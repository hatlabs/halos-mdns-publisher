//! HaLOS mDNS Publisher
//!
//! Native systemd service that advertises container subdomains via mDNS.
//! Monitors Docker containers for the `halos.subdomain` label and uses
//! avahi-publish to advertise the corresponding subdomains.

mod avahi_manager;
mod config;
mod container_watcher;
mod error;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use futures_util::StreamExt;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use crate::avahi_manager::AvahiManager;
use crate::config::Config;
use crate::container_watcher::{ContainerEvent, ContainerWatcher};
use crate::error::Result;

#[derive(Parser)]
#[command(name = "halos-mdns-publisher")]
#[command(about = "Advertises container subdomains via mDNS")]
#[command(version)]
struct Cli {
    /// Docker socket path
    #[arg(short, long, default_value = "/var/run/docker.sock")]
    socket: String,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    /// Health check interval in seconds
    #[arg(long, default_value = "60")]
    health_interval: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Set up logging
    let level = if cli.debug { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("HaLOS mDNS Publisher starting...");

    // Load configuration
    let config = Config::new(Some(cli.socket))?;
    info!("Domain: {}", config.domain);
    info!("Host IP: {}", config.host_ip);

    // Run the main service loop
    run_service(config, cli.health_interval).await
}

async fn run_service(config: Config, health_interval: u64) -> anyhow::Result<()> {
    // Wait for Docker to be available with retry
    let watcher = wait_for_docker(&config).await?;

    // Create Avahi manager
    let mut avahi = AvahiManager::new(&config.domain, &config.host_ip);

    // Capture timestamp BEFORE scanning to avoid missing events during the scan.
    // Any container that starts after this timestamp will be caught by the event stream.
    let scan_start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .ok();

    // Initial scan of running containers
    info!("Scanning existing containers...");
    match watcher.scan_containers().await {
        Ok(containers) => {
            info!(
                "Found {} container(s) with subdomain labels",
                containers.len()
            );
            for container in containers {
                if let Err(e) = avahi.publish(&container.id, &container.subdomain).await {
                    error!(
                        "Failed to publish subdomain for container {}: {}",
                        container.name, e
                    );
                }
            }
        }
        Err(e) => {
            warn!("Failed to scan containers: {}", e);
        }
    }
    info!(
        "Initial scan complete, {} active publications",
        avahi.active_count()
    );

    // Start watching for events (from scan_start_time to catch any we might have missed)
    info!("Watching for Docker events...");
    watch_loop(&watcher, &mut avahi, health_interval, scan_start_time).await
}

/// Wait for Docker to become available with exponential backoff
async fn wait_for_docker(config: &Config) -> Result<ContainerWatcher> {
    let mut retry_delay = Duration::from_secs(1);
    let max_delay = Duration::from_secs(30);

    loop {
        match ContainerWatcher::new(&config.docker_socket, &config.label_key) {
            Ok(watcher) => match watcher.ping().await {
                Ok(_) => {
                    info!("Connected to Docker daemon");
                    return Ok(watcher);
                }
                Err(e) => {
                    warn!("Docker not ready: {}. Retrying in {:?}...", e, retry_delay);
                }
            },
            Err(e) => {
                warn!(
                    "Failed to connect to Docker: {}. Retrying in {:?}...",
                    e, retry_delay
                );
            }
        }

        sleep(retry_delay).await;
        retry_delay = (retry_delay * 2).min(max_delay);
    }
}

/// Main watch loop handling Docker events and health checks
async fn watch_loop(
    watcher: &ContainerWatcher,
    avahi: &mut AvahiManager,
    health_interval: u64,
    since: Option<i64>,
) -> anyhow::Result<()> {
    // Set up signal handlers
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    // Health check timer
    let mut health_timer = interval(Duration::from_secs(health_interval));
    health_timer.tick().await; // Skip first immediate tick

    // Get event stream starting from the timestamp captured before scanning.
    // This ensures we don't miss any container start events that occurred during the scan.
    let mut events = watcher.watch_events(since).await.boxed();

    loop {
        tokio::select! {
            // Handle shutdown signals
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down...");
                break;
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down...");
                break;
            }

            // Handle Docker events
            Some(event_result) = events.next() => {
                match event_result {
                    Ok(Some(event)) => {
                        handle_event(avahi, event).await;
                    }
                    Ok(None) => {
                        // Container without subdomain label, nothing to do
                    }
                    Err(e) => {
                        error!("Docker event stream error: {}. Reconnecting...", e);
                        sleep(Duration::from_secs(5)).await;
                        // Get new event stream (None = from now, no replay needed)
                        events = watcher.watch_events(None).await.boxed();
                    }
                }
            }

            // Health check
            _ = health_timer.tick() => {
                debug!("Running health check...");
                if let Err(e) = avahi.check_health().await {
                    error!("Health check failed: {}", e);
                }
            }
        }
    }

    // Clean shutdown
    info!("Cleaning up...");
    avahi.shutdown().await;
    info!("Shutdown complete");

    Ok(())
}

/// Handle a container event
async fn handle_event(avahi: &mut AvahiManager, event: ContainerEvent) {
    match event {
        ContainerEvent::Started(info) => {
            info!(
                "Container '{}' started with subdomain '{}'",
                info.name, info.subdomain
            );
            if let Err(e) = avahi.publish(&info.id, &info.subdomain).await {
                error!(
                    "Failed to publish subdomain for container {}: {}",
                    info.name, e
                );
            }
        }
        ContainerEvent::Stopped(container_id) => {
            debug!(
                "Container stopped: {}",
                &container_id[..12.min(container_id.len())]
            );
            avahi.unpublish(&container_id).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_defaults() {
        let cli = Cli::parse_from(["halos-mdns-publisher"]);
        assert_eq!(cli.socket, "/var/run/docker.sock");
        assert!(!cli.debug);
        assert_eq!(cli.health_interval, 60);
    }

    #[test]
    fn test_cli_custom_socket() {
        let cli = Cli::parse_from([
            "halos-mdns-publisher",
            "--socket",
            "/custom/docker.sock",
            "--debug",
        ]);
        assert_eq!(cli.socket, "/custom/docker.sock");
        assert!(cli.debug);
    }
}

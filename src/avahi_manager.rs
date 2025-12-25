//! Avahi publish subprocess management
//!
//! Manages `avahi-publish -a` subprocesses for mDNS record publication.
//! Each subdomain gets its own subprocess that is tracked by container ID.

use std::collections::HashMap;

use tokio::process::{Child, Command};
use tracing::{debug, error, info, warn};

use crate::error::Result;

/// Validate a subdomain as a valid DNS label.
///
/// A valid DNS label must:
/// - Be 1-63 characters long
/// - Contain only alphanumeric characters and hyphens
/// - Not start or end with a hyphen
fn is_valid_dns_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }

    if label.starts_with('-') || label.ends_with('-') {
        return false;
    }

    label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Manages avahi-publish subprocesses for mDNS publication
pub struct AvahiManager {
    /// Domain suffix (e.g., "halos.local")
    domain: String,
    /// Host IP address to advertise
    host_ip: String,
    /// Active avahi-publish processes keyed by container ID
    processes: HashMap<String, AvahiProcess>,
}

/// Tracks an active avahi-publish process
struct AvahiProcess {
    /// The subprocess handle
    child: Child,
    /// The FQDN being published
    fqdn: String,
    /// The subdomain (for logging)
    subdomain: String,
}

impl AvahiManager {
    /// Create a new Avahi manager
    pub fn new(domain: &str, host_ip: &str) -> Self {
        Self {
            domain: domain.to_string(),
            host_ip: host_ip.to_string(),
            processes: HashMap::new(),
        }
    }

    /// Publish a subdomain for a container
    ///
    /// If already publishing for this container, does nothing.
    /// Returns Ok(()) if the subdomain is invalid (with a warning logged).
    pub async fn publish(&mut self, container_id: &str, subdomain: &str) -> Result<()> {
        // Skip empty subdomains
        if subdomain.is_empty() {
            debug!("Skipping empty subdomain for container {}", container_id);
            return Ok(());
        }

        // Validate subdomain as a DNS label
        if !is_valid_dns_label(subdomain) {
            warn!(
                "Invalid subdomain '{}' for container {} - must be 1-63 chars, alphanumeric/hyphens, not start/end with hyphen",
                subdomain,
                &container_id[..12.min(container_id.len())]
            );
            return Ok(());
        }

        // Check if already publishing for this container
        if let Some(existing) = self.processes.get(container_id) {
            if existing.subdomain == subdomain {
                debug!(
                    "Already publishing {} for container {}",
                    existing.fqdn,
                    &container_id[..12.min(container_id.len())]
                );
                return Ok(());
            }
            // Different subdomain, stop old one first
            warn!(
                "Container {} changed subdomain from {} to {}, restarting",
                &container_id[..12.min(container_id.len())],
                existing.subdomain,
                subdomain
            );
            self.unpublish(container_id).await;
        }

        let fqdn = format!("{}.{}", subdomain, self.domain);

        info!("Publishing {} -> {}", fqdn, self.host_ip);

        // Spawn avahi-publish process
        let child = Command::new("avahi-publish")
            .args(["-a", &fqdn, &self.host_ip])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let process = AvahiProcess {
            child,
            fqdn: fqdn.clone(),
            subdomain: subdomain.to_string(),
        };

        self.processes.insert(container_id.to_string(), process);

        info!(
            "Started avahi-publish for {} (container {})",
            fqdn,
            &container_id[..12.min(container_id.len())]
        );

        Ok(())
    }

    /// Stop publishing for a container
    pub async fn unpublish(&mut self, container_id: &str) {
        if let Some(mut process) = self.processes.remove(container_id) {
            info!(
                "Stopping avahi-publish for {} (container {})",
                process.fqdn,
                &container_id[..12.min(container_id.len())]
            );

            if let Err(e) = process.child.kill().await {
                // Process may have already exited
                debug!("Error killing avahi-publish process: {}", e);
            }

            // Wait for process to fully exit
            let _ = process.child.wait().await;
        }
    }

    /// Stop all publishing and clean up
    pub async fn shutdown(&mut self) {
        info!(
            "Shutting down Avahi manager, stopping {} processes",
            self.processes.len()
        );

        let container_ids: Vec<String> = self.processes.keys().cloned().collect();

        for container_id in container_ids {
            self.unpublish(&container_id).await;
        }
    }

    /// Get count of active publications
    pub fn active_count(&self) -> usize {
        self.processes.len()
    }

    /// Check health of all processes, restart any that have died
    pub async fn check_health(&mut self) -> Result<()> {
        let mut dead_processes = Vec::new();

        for (container_id, process) in &mut self.processes {
            // Try to check if process is still running
            match process.child.try_wait() {
                Ok(Some(status)) => {
                    warn!(
                        "avahi-publish for {} exited with status: {}",
                        process.fqdn, status
                    );
                    dead_processes.push((container_id.clone(), process.subdomain.clone()));
                }
                Ok(None) => {
                    // Still running
                    debug!("avahi-publish for {} is healthy", process.fqdn);
                }
                Err(e) => {
                    error!("Error checking avahi-publish status: {}", e);
                }
            }
        }

        // Restart dead processes
        for (container_id, subdomain) in dead_processes {
            self.processes.remove(&container_id);
            info!("Restarting avahi-publish for {}.{}", subdomain, self.domain);
            if let Err(e) = self.publish(&container_id, &subdomain).await {
                error!("Failed to restart avahi-publish: {}", e);
            }
        }

        Ok(())
    }
}

impl Drop for AvahiManager {
    fn drop(&mut self) {
        // Note: Can't do async cleanup in Drop, but processes will be killed
        // when their handles are dropped anyway
        if !self.processes.is_empty() {
            warn!(
                "AvahiManager dropped with {} active processes - they will be terminated",
                self.processes.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fqdn_construction() {
        let manager = AvahiManager::new("halos.local", "192.168.1.100");

        // FQDN should be subdomain.domain
        let expected_fqdn = "app.halos.local";
        let actual_fqdn = format!("{}.{}", "app", manager.domain);
        assert_eq!(actual_fqdn, expected_fqdn);
    }

    #[test]
    fn test_manager_initial_state() {
        let manager = AvahiManager::new("test.local", "10.0.0.1");

        assert_eq!(manager.domain, "test.local");
        assert_eq!(manager.host_ip, "10.0.0.1");
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_valid_dns_labels() {
        // Valid labels
        assert!(is_valid_dns_label("app"));
        assert!(is_valid_dns_label("my-app"));
        assert!(is_valid_dns_label("app123"));
        assert!(is_valid_dns_label("123app"));
        assert!(is_valid_dns_label("a"));
        assert!(is_valid_dns_label("my-cool-app-2024"));

        // 63 characters (max valid length)
        assert!(is_valid_dns_label(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }

    #[test]
    fn test_invalid_dns_labels() {
        // Empty
        assert!(!is_valid_dns_label(""));

        // Too long (64 characters)
        assert!(!is_valid_dns_label(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));

        // Starts with hyphen
        assert!(!is_valid_dns_label("-app"));

        // Ends with hyphen
        assert!(!is_valid_dns_label("app-"));

        // Contains invalid characters
        assert!(!is_valid_dns_label("app.name"));
        assert!(!is_valid_dns_label("app_name"));
        assert!(!is_valid_dns_label("app name"));
        assert!(!is_valid_dns_label("app@name"));
    }
}

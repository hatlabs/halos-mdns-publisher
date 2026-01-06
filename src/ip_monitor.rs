//! IP address change monitoring via netlink
//!
//! Monitors the system's network interfaces for IP address changes using
//! the Linux netlink protocol. This allows detecting DHCP renewals,
//! network reconfigurations, and other IP changes without polling.

use std::time::Duration;

use futures_util::StreamExt;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::constants::RTMGRP_IPV4_IFADDR;
use rtnetlink::new_connection;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::config::{get_host_ip, HostIp};
use crate::error::Result;

/// Debounce duration for IP changes (handles rapid changes during DHCP negotiation)
const IP_CHANGE_DEBOUNCE_MS: u64 = 2000;

/// Event indicating the host IP has changed
#[derive(Debug, Clone)]
pub struct IpChangeEvent {
    /// The previous IP address
    pub old_ip: String,
    /// The new IP address
    pub new_ip: String,
}

/// Event indicating the set of host IPs has changed
#[allow(dead_code)] // TODO: remove when integrated into main.rs
#[derive(Debug, Clone)]
pub struct IpSetChangeEvent {
    /// The previous set of IP addresses
    pub old_ips: Vec<HostIp>,
    /// The new set of IP addresses
    pub new_ips: Vec<HostIp>,
}

/// Start monitoring for IP address changes (multi-IP version)
///
/// Returns a receiver that yields `IpSetChangeEvent` when the host's IP set changes.
/// The monitor runs as a background task and handles debouncing internally.
#[allow(dead_code)] // TODO: remove when integrated into main.rs
pub async fn start_ip_set_monitor(
    initial_ips: Vec<HostIp>,
) -> Result<mpsc::UnboundedReceiver<IpSetChangeEvent>> {
    // TODO: implement
    let (tx, rx) = mpsc::unbounded_channel();
    let _ = (initial_ips, tx);
    Ok(rx)
}

/// Start monitoring for IP address changes
///
/// Returns a receiver that yields `IpChangeEvent` when the host's primary IP changes.
/// The monitor runs as a background task and handles debouncing internally.
pub async fn start_ip_monitor(
    initial_ip: String,
) -> Result<mpsc::UnboundedReceiver<IpChangeEvent>> {
    let (tx, rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        if let Err(e) = run_ip_monitor(initial_ip, tx).await {
            error!("IP monitor task failed: {}", e);
        }
    });

    Ok(rx)
}

/// Main loop with reconnection logic
async fn run_ip_monitor(
    initial_ip: String,
    tx: mpsc::UnboundedSender<IpChangeEvent>,
) -> Result<()> {
    let mut current_ip = initial_ip;

    loop {
        match monitor_netlink_events(&mut current_ip, &tx).await {
            Ok(()) => {
                // Stream ended cleanly (shouldn't happen normally)
                warn!("Netlink event stream ended, reconnecting...");
            }
            Err(e) => {
                error!("Netlink monitor error: {}. Reconnecting in 5s...", e);
            }
        }

        // Backoff before reconnecting
        sleep(Duration::from_secs(5)).await;
    }
}

/// Monitor netlink events for address changes
async fn monitor_netlink_events(
    current_ip: &mut String,
    tx: &mpsc::UnboundedSender<IpChangeEvent>,
) -> Result<()> {
    // Create connection to receive address change notifications
    let (mut conn, _handle, mut messages) = new_connection()?;

    // Subscribe to IPv4 address change multicast group
    let addr = SocketAddr::new(0, RTMGRP_IPV4_IFADDR);
    conn.socket_mut().socket_mut().bind(&addr)?;

    // Spawn the connection handler (required for messages to flow)
    tokio::spawn(conn);

    info!("IP address monitor started, current IP: {}", current_ip);

    let mut last_event_time = std::time::Instant::now();
    let mut pending_check = false;

    loop {
        // Use a timeout to periodically check if we should process pending events
        let timeout = if pending_check {
            Duration::from_millis(IP_CHANGE_DEBOUNCE_MS)
        } else {
            Duration::from_secs(60) // Long timeout when not waiting for debounce
        };

        tokio::select! {
            result = messages.next() => {
                match result {
                    Some((message, _addr)) => {
                        // Filter for address-related messages
                        if let NetlinkPayload::InnerMessage(
                            RouteNetlinkMessage::NewAddress(_)
                            | RouteNetlinkMessage::DelAddress(_),
                        ) = message.payload
                        {
                            debug!("Received address change notification");
                            pending_check = true;
                            last_event_time = std::time::Instant::now();
                        }
                    }
                    None => {
                        // Stream ended
                        return Ok(());
                    }
                }
            }
            _ = sleep(timeout) => {
                // Timeout - check if we should process pending events
            }
        }

        // Check if debounce period has passed and we have a pending check
        if pending_check
            && last_event_time.elapsed() >= Duration::from_millis(IP_CHANGE_DEBOUNCE_MS)
        {
            pending_check = false;

            // Get the new primary IP
            match get_host_ip() {
                Ok(new_ip) => {
                    // Always send an event on any address change, even if primary IP unchanged.
                    // This ensures multi-IP mode can detect secondary interface changes.
                    let primary_changed = new_ip != *current_ip;
                    if primary_changed {
                        info!("Primary IP changed: {} -> {}", current_ip, new_ip);
                    } else {
                        info!(
                            "Network change detected (primary IP unchanged: {})",
                            current_ip
                        );
                    }

                    let event = IpChangeEvent {
                        old_ip: current_ip.clone(),
                        new_ip: new_ip.clone(),
                    };

                    if primary_changed {
                        *current_ip = new_ip;
                    }

                    if tx.send(event).is_err() {
                        // Receiver dropped, exit monitor
                        info!("IP monitor receiver dropped, exiting");
                        return Ok(());
                    }
                }
                Err(e) => {
                    warn!("Failed to get new IP after address change: {}", e);
                    // Don't update current_ip, keep advertising old one
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_change_event_fields() {
        let event = IpChangeEvent {
            old_ip: "10.0.0.1".to_string(),
            new_ip: "10.0.0.2".to_string(),
        };
        assert_eq!(event.old_ip, "10.0.0.1");
        assert_eq!(event.new_ip, "10.0.0.2");
    }

    #[test]
    fn test_ip_change_event_clone() {
        let event = IpChangeEvent {
            old_ip: "10.0.0.1".to_string(),
            new_ip: "10.0.0.2".to_string(),
        };
        let cloned = event.clone();
        assert_eq!(event.old_ip, cloned.old_ip);
        assert_eq!(event.new_ip, cloned.new_ip);
    }

    #[test]
    fn test_ip_change_event_debug() {
        let event = IpChangeEvent {
            old_ip: "192.168.1.1".to_string(),
            new_ip: "192.168.1.2".to_string(),
        };
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("192.168.1.1"));
        assert!(debug_str.contains("192.168.1.2"));
    }

    // === Tests for IpSetChangeEvent ===

    fn make_host_ips(ips: &[(&str, &str)]) -> Vec<HostIp> {
        ips.iter()
            .map(|(ip, iface)| HostIp {
                ip: ip.to_string(),
                interface: iface.to_string(),
            })
            .collect()
    }

    #[test]
    fn test_ip_set_change_event_fields() {
        let old_ips = make_host_ips(&[("10.0.0.1", "eth0")]);
        let new_ips = make_host_ips(&[("10.0.0.1", "eth0"), ("192.168.4.1", "wlan0ap")]);

        let event = IpSetChangeEvent {
            old_ips: old_ips.clone(),
            new_ips: new_ips.clone(),
        };

        assert_eq!(event.old_ips.len(), 1);
        assert_eq!(event.new_ips.len(), 2);
        assert_eq!(event.old_ips[0].ip, "10.0.0.1");
        assert_eq!(event.new_ips[1].ip, "192.168.4.1");
    }

    #[test]
    fn test_ip_set_change_event_clone() {
        let event = IpSetChangeEvent {
            old_ips: make_host_ips(&[("10.0.0.1", "eth0")]),
            new_ips: make_host_ips(&[("10.0.0.2", "eth0")]),
        };
        let cloned = event.clone();

        assert_eq!(event.old_ips.len(), cloned.old_ips.len());
        assert_eq!(event.new_ips.len(), cloned.new_ips.len());
        assert_eq!(event.old_ips[0].ip, cloned.old_ips[0].ip);
    }

    #[test]
    fn test_ip_set_change_event_debug() {
        let event = IpSetChangeEvent {
            old_ips: make_host_ips(&[("192.168.1.1", "eth0")]),
            new_ips: make_host_ips(&[("192.168.1.2", "eth0")]),
        };
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("192.168.1.1"));
        assert!(debug_str.contains("192.168.1.2"));
    }

    #[test]
    fn test_ip_set_change_event_empty_to_populated() {
        let event = IpSetChangeEvent {
            old_ips: vec![],
            new_ips: make_host_ips(&[("10.0.0.1", "eth0")]),
        };

        assert!(event.old_ips.is_empty());
        assert_eq!(event.new_ips.len(), 1);
    }

    #[test]
    fn test_ip_set_change_event_populated_to_empty() {
        let event = IpSetChangeEvent {
            old_ips: make_host_ips(&[("10.0.0.1", "eth0")]),
            new_ips: vec![],
        };

        assert_eq!(event.old_ips.len(), 1);
        assert!(event.new_ips.is_empty());
    }

    #[test]
    fn test_ip_set_change_event_multiple_changes() {
        let event = IpSetChangeEvent {
            old_ips: make_host_ips(&[("10.84.77.20", "eth0"), ("10.84.77.22", "wlan0")]),
            new_ips: make_host_ips(&[("10.84.77.20", "eth0"), ("192.168.4.1", "wlan0ap")]),
        };

        assert_eq!(event.old_ips.len(), 2);
        assert_eq!(event.new_ips.len(), 2);
        // eth0 IP unchanged, wlan0 removed, wlan0ap added
        assert!(event.old_ips.iter().any(|ip| ip.interface == "wlan0"));
        assert!(event.new_ips.iter().any(|ip| ip.interface == "wlan0ap"));
    }
}

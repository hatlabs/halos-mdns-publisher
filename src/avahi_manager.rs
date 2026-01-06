//! Avahi publish subprocess management
//!
//! Manages `avahi-publish-address` subprocesses for mDNS record publication.
//! Each subdomain gets its own subprocess that is tracked by container ID.

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStderr, Command};
use tracing::{debug, error, info, warn};

use crate::config::HostIp;
use crate::error::Result;

/// Compute the difference between two IP sets
///
/// Returns (added, removed) where:
/// - added: IPs in new but not in old
/// - removed: IPs in old but not in new
#[allow(dead_code)] // TODO: remove when integrated into main.rs
pub fn compute_ip_diff(old: &[HostIp], new: &[HostIp]) -> (Vec<HostIp>, Vec<HostIp>) {
    use std::collections::HashSet;

    let old_set: HashSet<_> = old.iter().collect();
    let new_set: HashSet<_> = new.iter().collect();

    let added: Vec<HostIp> = new
        .iter()
        .filter(|ip| !old_set.contains(ip))
        .cloned()
        .collect();

    let removed: Vec<HostIp> = old
        .iter()
        .filter(|ip| !new_set.contains(ip))
        .cloned()
        .collect();

    (added, removed)
}

/// Time to wait after spawning avahi-publish before verifying resolution.
/// mDNS probing takes ~750ms (3 probes at 250ms intervals), plus some buffer.
const VERIFICATION_DELAY_MS: u64 = 1500;

/// Timeout for resolution verification.
const VERIFICATION_TIMEOUT_MS: u64 = 2000;

/// Maximum number of retry attempts when verification fails.
#[allow(dead_code)] // TODO: integrate verification into publish flow
const MAX_VERIFICATION_RETRIES: u32 = 3;

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
    /// Domain suffix (e.g., "myhostname.local")
    domain: String,
    /// Host IP address to advertise (single IP, legacy)
    host_ip: String,
    /// Host IP addresses to advertise (multi-IP support)
    host_ips_vec: Vec<HostIp>,
    /// Active avahi-publish processes keyed by container ID
    /// Each container can have multiple processes (one per IP)
    processes: HashMap<String, Vec<AvahiProcess>>,
}

/// Tracks an active avahi-publish process
struct AvahiProcess {
    /// The subprocess handle
    child: Child,
    /// Stderr handle for capturing error output
    stderr: Option<ChildStderr>,
    /// The FQDN being published
    fqdn: String,
    /// The subdomain (for logging)
    subdomain: String,
    /// The IP address this process publishes
    ip: String,
}

impl AvahiManager {
    /// Create a new Avahi manager
    pub fn new(domain: &str, host_ip: &str) -> Self {
        Self {
            domain: domain.to_string(),
            host_ip: host_ip.to_string(),
            host_ips_vec: vec![HostIp {
                ip: host_ip.to_string(),
                interface: "default".to_string(),
            }],
            processes: HashMap::new(),
        }
    }

    /// Create a new Avahi manager with multiple IP addresses
    ///
    /// For each container subdomain, one avahi-publish process will be
    /// spawned per IP address.
    #[allow(dead_code)] // TODO: remove when integrated into main.rs
    pub fn new_with_ips(domain: &str, host_ips: Vec<HostIp>) -> Self {
        let host_ip = host_ips.first().map(|ip| ip.ip.clone()).unwrap_or_default();
        Self {
            domain: domain.to_string(),
            host_ip,
            host_ips_vec: host_ips,
            processes: HashMap::new(),
        }
    }

    /// Get all host IP addresses being advertised
    #[allow(dead_code)] // TODO: remove when integrated into main.rs
    pub fn host_ips(&self) -> &[HostIp] {
        &self.host_ips_vec
    }

    /// Publish a subdomain for a container
    ///
    /// Spawns one avahi-publish process per configured IP address.
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

        // Check if already publishing for this container with the same subdomain
        if let Some(existing_processes) = self.processes.get(container_id) {
            if let Some(first) = existing_processes.first() {
                if first.subdomain == subdomain {
                    debug!(
                        "Already publishing {} for container {}",
                        first.fqdn,
                        &container_id[..12.min(container_id.len())]
                    );
                    return Ok(());
                }
                // Different subdomain, stop old ones first
                warn!(
                    "Container {} changed subdomain from {} to {}, restarting",
                    &container_id[..12.min(container_id.len())],
                    first.subdomain,
                    subdomain
                );
            }
            self.unpublish(container_id).await;
        }

        let fqdn = format!("{}.{}", subdomain, self.domain);
        let ips_to_publish: Vec<String> = self.host_ips_vec.iter().map(|h| h.ip.clone()).collect();

        if ips_to_publish.is_empty() {
            warn!("No IP addresses configured, skipping publish for {}", fqdn);
            return Ok(());
        }

        info!(
            "Publishing {} -> {} IP(s): {:?}",
            fqdn,
            ips_to_publish.len(),
            ips_to_publish
        );

        let mut spawned_processes = Vec::new();
        let mut any_succeeded = false;

        // Spawn one avahi-publish process per IP
        for ip in &ips_to_publish {
            match self.spawn_avahi_publish(&fqdn, subdomain, ip).await {
                Ok(process) => {
                    spawned_processes.push(process);
                    any_succeeded = true;
                }
                Err(e) => {
                    error!(
                        "Failed to spawn avahi-publish for {} -> {}: {}",
                        fqdn, ip, e
                    );
                }
            }
        }

        if spawned_processes.is_empty() {
            error!("Failed to spawn any avahi-publish processes for {}", fqdn);
            return Ok(());
        }

        // Store all spawned processes
        self.processes
            .insert(container_id.to_string(), spawned_processes);

        info!(
            "Started {} avahi-publish process(es) for {} (container {})",
            self.processes
                .get(container_id)
                .map(|p| p.len())
                .unwrap_or(0),
            fqdn,
            &container_id[..12.min(container_id.len())]
        );

        // Verify that at least one record is resolvable (after a delay for mDNS probing)
        if any_succeeded {
            tokio::time::sleep(Duration::from_millis(VERIFICATION_DELAY_MS)).await;
            match Self::test_resolution(&fqdn).await {
                Ok(resolved_ip) => {
                    info!("Verified: {} resolves to {}", fqdn, resolved_ip);
                }
                Err(e) => {
                    warn!(
                        "Resolution verification failed for {} (may still work): {}",
                        fqdn, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Spawn a single avahi-publish-address process
    async fn spawn_avahi_publish(
        &self,
        fqdn: &str,
        subdomain: &str,
        ip: &str,
    ) -> Result<AvahiProcess> {
        debug!("Spawning avahi-publish for {} -> {}", fqdn, ip);

        let mut child = Command::new("avahi-publish-address")
            .args(["--no-reverse", fqdn, ip])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let stderr = child.stderr.take();

        Ok(AvahiProcess {
            child,
            stderr,
            fqdn: fqdn.to_string(),
            subdomain: subdomain.to_string(),
            ip: ip.to_string(),
        })
    }

    /// Stop publishing for a container
    pub async fn unpublish(&mut self, container_id: &str) {
        if let Some(processes) = self.processes.remove(container_id) {
            let count = processes.len();
            let fqdn = processes
                .first()
                .map(|p| p.fqdn.clone())
                .unwrap_or_default();

            info!(
                "Stopping {} avahi-publish process(es) for {} (container {})",
                count,
                fqdn,
                &container_id[..12.min(container_id.len())]
            );

            for mut process in processes {
                if let Err(e) = process.child.kill().await {
                    // Process may have already exited
                    debug!("Error killing avahi-publish process: {}", e);
                }
                // Wait for process to fully exit
                let _ = process.child.wait().await;
            }
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

    /// Get count of active publications (containers being published)
    pub fn active_count(&self) -> usize {
        self.processes.len()
    }

    /// Get total count of avahi-publish processes
    #[allow(dead_code)]
    pub fn process_count(&self) -> usize {
        self.processes.values().map(|v| v.len()).sum()
    }

    /// Get the current host IP being advertised
    pub fn host_ip(&self) -> &str {
        &self.host_ip
    }

    /// Update the host IP address and restart all active publications
    ///
    /// This should be called when the host's IP address changes.
    /// All avahi-publish processes will be restarted with the new IP.
    pub async fn update_ip(&mut self, new_ip: &str) {
        if self.host_ip == new_ip {
            debug!("IP unchanged ({}), skipping update", new_ip);
            return;
        }

        info!(
            "Updating host IP from {} to {}, restarting {} publication(s)",
            self.host_ip,
            new_ip,
            self.processes.len()
        );

        let old_ip = std::mem::replace(&mut self.host_ip, new_ip.to_string());

        // Also update the host_ips_vec with the new single IP
        self.host_ips_vec = vec![HostIp {
            ip: new_ip.to_string(),
            interface: "default".to_string(),
        }];

        // Collect container IDs and subdomains to republish
        let to_republish: Vec<(String, String)> = self
            .processes
            .iter()
            .filter_map(|(id, processes)| {
                processes.first().map(|p| (id.clone(), p.subdomain.clone()))
            })
            .collect();

        // Stop all existing processes
        for (container_id, _) in &to_republish {
            self.unpublish(container_id).await;
        }

        // Restart all with new IP
        for (container_id, subdomain) in &to_republish {
            if let Err(e) = self.publish(container_id, subdomain).await {
                error!("Failed to republish {} after IP change: {}", subdomain, e);
            }
        }

        info!(
            "IP update complete: {} -> {}, {} publication(s) restarted",
            old_ip,
            self.host_ip,
            self.processes.len()
        );
    }

    /// Update the set of host IP addresses and restart affected publications
    ///
    /// This should be called when the host's IP set changes (interface up/down).
    #[allow(dead_code)] // TODO: remove when integrated into main.rs
    pub async fn update_ips(&mut self, new_ips: Vec<HostIp>) {
        let (added, removed) = compute_ip_diff(&self.host_ips_vec, &new_ips);

        if added.is_empty() && removed.is_empty() {
            debug!("IP set unchanged, skipping update");
            return;
        }

        info!(
            "Updating IP set: {} added, {} removed, restarting {} publication(s)",
            added.len(),
            removed.len(),
            self.processes.len()
        );

        // Update stored IPs
        self.host_ips_vec = new_ips;
        if let Some(first) = self.host_ips_vec.first() {
            self.host_ip = first.ip.clone();
        }

        // Collect container IDs and subdomains to republish
        let to_republish: Vec<(String, String)> = self
            .processes
            .iter()
            .filter_map(|(id, processes)| {
                processes.first().map(|p| (id.clone(), p.subdomain.clone()))
            })
            .collect();

        // Stop all existing processes
        for (container_id, _) in &to_republish {
            self.unpublish(container_id).await;
        }

        // Restart all with new IP set
        for (container_id, subdomain) in &to_republish {
            if let Err(e) = self.publish(container_id, subdomain).await {
                error!(
                    "Failed to republish {} after IP set change: {}",
                    subdomain, e
                );
            }
        }

        info!(
            "IP set update complete, {} publication(s) active",
            self.processes.len()
        );
    }

    /// Verify that a published record is resolvable.
    ///
    /// Waits for mDNS probing to complete, then tests resolution.
    /// Returns true if verification succeeded, false otherwise.
    /// On failure, processes are killed and removed to allow retry.
    #[allow(dead_code)] // TODO: integrate verification into publish flow
    async fn verify_publication(&mut self, container_id: &str, fqdn: &str) -> bool {
        // Wait for mDNS probing to complete
        tokio::time::sleep(Duration::from_millis(VERIFICATION_DELAY_MS)).await;

        // Check if any process has died
        let any_process_died = if let Some(processes) = self.processes.get_mut(container_id) {
            let mut any_died = false;
            for process in processes.iter_mut() {
                match process.child.try_wait() {
                    Ok(Some(status)) => {
                        let stderr_output = Self::read_stderr(&mut process.stderr).await;
                        error!(
                            "avahi-publish for {} -> {} exited immediately with status: {}{}",
                            fqdn,
                            process.ip,
                            status,
                            if stderr_output.is_empty() {
                                String::new()
                            } else {
                                format!("\nstderr: {}", stderr_output)
                            }
                        );
                        any_died = true;
                    }
                    Ok(None) => {
                        // Still running
                    }
                    Err(e) => {
                        error!(
                            "Error checking avahi-publish status for {} -> {}: {}",
                            fqdn, process.ip, e
                        );
                        any_died = true;
                    }
                }
            }
            any_died
        } else {
            // Processes were removed (container stopped?)
            return false;
        };

        // If any process exited early, remove all and fail verification
        if any_process_died {
            self.processes.remove(container_id);
            return false;
        }

        // Try to resolve the name using avahi-resolve
        match Self::test_resolution(fqdn).await {
            Ok(resolved_ip) => {
                info!("Verified: {} resolves to {}", fqdn, resolved_ip);
                true
            }
            Err(e) => {
                warn!("Resolution verification failed for {}: {}", fqdn, e);

                // Check if any process died while we were testing
                let any_process_died = if let Some(processes) = self.processes.get_mut(container_id)
                {
                    processes
                        .iter_mut()
                        .any(|p| matches!(p.child.try_wait(), Ok(Some(_))))
                } else {
                    true // Processes already removed
                };

                if any_process_died {
                    // Log and remove dead processes
                    if let Some(mut processes) = self.processes.remove(container_id) {
                        for process in processes.iter_mut() {
                            let status = process.child.try_wait().ok().flatten();
                            if let Some(status) = status {
                                let stderr_output = Self::read_stderr(&mut process.stderr).await;
                                error!(
                                    "avahi-publish for {} -> {} exited with status: {}{}",
                                    fqdn,
                                    process.ip,
                                    status,
                                    if stderr_output.is_empty() {
                                        String::new()
                                    } else {
                                        format!("\nstderr: {}", stderr_output)
                                    }
                                );
                            }
                        }
                    }
                } else {
                    // Processes are running but not resolving - kill them to allow retry
                    warn!(
                        "avahi-publish for {} is running but not resolving, killing for retry",
                        fqdn
                    );
                    self.unpublish(container_id).await;
                }
                false
            }
        }
    }

    /// Test if a hostname resolves via mDNS using avahi-resolve.
    async fn test_resolution(fqdn: &str) -> std::result::Result<String, String> {
        let result = tokio::time::timeout(
            Duration::from_millis(VERIFICATION_TIMEOUT_MS),
            Command::new("avahi-resolve").args(["-n", fqdn]).output(),
        )
        .await;

        match result {
            Ok(Ok(output)) => {
                if output.status.success() {
                    // Output format: "hostname\tIP"
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if let Some(ip) = stdout.split_whitespace().nth(1) {
                        Ok(ip.to_string())
                    } else {
                        Err(format!(
                            "Unexpected avahi-resolve output: {}",
                            stdout.trim()
                        ))
                    }
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(stderr.trim().to_string())
                }
            }
            Ok(Err(e)) => Err(format!("Failed to run avahi-resolve: {}", e)),
            Err(_) => Err("Resolution timed out".to_string()),
        }
    }

    /// Read stderr from a process, returning empty string if unavailable.
    async fn read_stderr(stderr: &mut Option<ChildStderr>) -> String {
        if let Some(mut stderr_handle) = stderr.take() {
            let mut output = String::new();
            match stderr_handle.read_to_string(&mut output).await {
                Ok(_) => output.trim().to_string(),
                Err(e) => {
                    debug!("Failed to read stderr: {}", e);
                    String::new()
                }
            }
        } else {
            String::new()
        }
    }

    /// Check health of all processes, restart any that have died
    pub async fn check_health(&mut self) -> Result<()> {
        // Collect containers that need restarting (any process died)
        let mut containers_to_restart = Vec::new();

        for (container_id, processes) in &mut self.processes {
            let mut any_dead = false;
            let subdomain = processes.first().map(|p| p.subdomain.clone());

            for process in processes.iter_mut() {
                match process.child.try_wait() {
                    Ok(Some(status)) => {
                        // Read stderr to understand why the process died
                        let stderr_output = Self::read_stderr(&mut process.stderr).await;
                        warn!(
                            "avahi-publish for {} -> {} exited with status: {}{}",
                            process.fqdn,
                            process.ip,
                            status,
                            if stderr_output.is_empty() {
                                String::new()
                            } else {
                                format!("\nstderr: {}", stderr_output)
                            }
                        );
                        any_dead = true;
                    }
                    Ok(None) => {
                        // Still running
                        debug!(
                            "avahi-publish for {} -> {} is healthy",
                            process.fqdn, process.ip
                        );
                    }
                    Err(e) => {
                        error!("Error checking avahi-publish status: {}", e);
                    }
                }
            }

            if any_dead {
                if let Some(subdomain) = subdomain {
                    containers_to_restart.push((container_id.clone(), subdomain));
                }
            }
        }

        // Restart containers with dead processes
        for (container_id, subdomain) in containers_to_restart {
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
    use crate::config::HostIp;

    #[test]
    fn test_fqdn_construction() {
        let manager = AvahiManager::new("test.local", "192.168.1.100");

        // FQDN should be subdomain.domain
        let expected_fqdn = "app.test.local";
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

    #[test]
    fn test_host_ip_getter() {
        let manager = AvahiManager::new("test.local", "192.168.1.100");
        assert_eq!(manager.host_ip(), "192.168.1.100");
    }

    #[test]
    fn test_host_ip_getter_different_values() {
        let manager1 = AvahiManager::new("test.local", "10.0.0.1");
        let manager2 = AvahiManager::new("test.local", "172.16.0.1");

        assert_eq!(manager1.host_ip(), "10.0.0.1");
        assert_eq!(manager2.host_ip(), "172.16.0.1");
    }

    // === Tests for multi-IP support ===

    fn make_host_ips(ips: &[(&str, &str)]) -> Vec<HostIp> {
        ips.iter()
            .map(|(ip, iface)| HostIp {
                ip: ip.to_string(),
                interface: iface.to_string(),
            })
            .collect()
    }

    #[test]
    fn test_new_with_ips_single() {
        let ips = make_host_ips(&[("192.168.1.100", "eth0")]);
        let manager = AvahiManager::new_with_ips("test.local", ips.clone());

        assert_eq!(manager.domain, "test.local");
        assert_eq!(manager.host_ips().len(), 1);
        assert_eq!(manager.host_ips()[0].ip, "192.168.1.100");
        assert_eq!(manager.host_ips()[0].interface, "eth0");
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_new_with_ips_multiple() {
        let ips = make_host_ips(&[
            ("192.168.1.100", "eth0"),
            ("10.0.0.1", "wlan0"),
            ("192.168.4.1", "wlan0ap"),
        ]);
        let manager = AvahiManager::new_with_ips("test.local", ips);

        assert_eq!(manager.host_ips().len(), 3);
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_new_with_ips_empty() {
        let ips: Vec<HostIp> = vec![];
        let manager = AvahiManager::new_with_ips("test.local", ips);

        assert_eq!(manager.host_ips().len(), 0);
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_host_ips_getter() {
        let ips = make_host_ips(&[("10.84.77.20", "eth0"), ("10.84.77.22", "wlan0")]);
        let manager = AvahiManager::new_with_ips("test.local", ips);

        let retrieved = manager.host_ips();
        assert_eq!(retrieved.len(), 2);
        assert!(retrieved.iter().any(|ip| ip.ip == "10.84.77.20"));
        assert!(retrieved.iter().any(|ip| ip.ip == "10.84.77.22"));
    }

    #[test]
    fn test_compute_ip_diff_added() {
        let old = make_host_ips(&[("192.168.1.1", "eth0")]);
        let new = make_host_ips(&[("192.168.1.1", "eth0"), ("10.0.0.1", "wlan0")]);

        let (added, removed) = compute_ip_diff(&old, &new);

        assert_eq!(added.len(), 1);
        assert_eq!(removed.len(), 0);
        assert_eq!(added[0].ip, "10.0.0.1");
    }

    #[test]
    fn test_compute_ip_diff_removed() {
        let old = make_host_ips(&[("192.168.1.1", "eth0"), ("10.0.0.1", "wlan0")]);
        let new = make_host_ips(&[("192.168.1.1", "eth0")]);

        let (added, removed) = compute_ip_diff(&old, &new);

        assert_eq!(added.len(), 0);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].ip, "10.0.0.1");
    }

    #[test]
    fn test_compute_ip_diff_changed() {
        let old = make_host_ips(&[("192.168.1.1", "eth0"), ("10.0.0.1", "wlan0")]);
        let new = make_host_ips(&[("10.0.0.1", "wlan0"), ("192.168.4.1", "wlan0ap")]);

        let (added, removed) = compute_ip_diff(&old, &new);

        assert_eq!(added.len(), 1);
        assert_eq!(removed.len(), 1);
        assert!(added.iter().any(|ip| ip.ip == "192.168.4.1"));
        assert!(removed.iter().any(|ip| ip.ip == "192.168.1.1"));
    }

    #[test]
    fn test_compute_ip_diff_unchanged() {
        let old = make_host_ips(&[("192.168.1.1", "eth0"), ("10.0.0.1", "wlan0")]);
        let new = make_host_ips(&[("192.168.1.1", "eth0"), ("10.0.0.1", "wlan0")]);

        let (added, removed) = compute_ip_diff(&old, &new);

        assert_eq!(added.len(), 0);
        assert_eq!(removed.len(), 0);
    }
}

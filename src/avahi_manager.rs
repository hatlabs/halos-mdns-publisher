//! Avahi publish subprocess management
//!
//! Manages `avahi-publish-address` subprocesses for mDNS record publication.
//! Each subdomain gets its own subprocess that is tracked by container ID.

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStderr, Command};
use tracing::{debug, error, info, warn};

use crate::error::Result;

/// Time to wait after spawning avahi-publish before verifying resolution.
/// mDNS probing takes ~750ms (3 probes at 250ms intervals), plus some buffer.
const VERIFICATION_DELAY_MS: u64 = 1500;

/// Timeout for resolution verification.
const VERIFICATION_TIMEOUT_MS: u64 = 2000;

/// Maximum number of retry attempts when verification fails.
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
    /// Host IP address to advertise
    host_ip: String,
    /// Active avahi-publish processes keyed by container ID
    processes: HashMap<String, AvahiProcess>,
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

        // Retry loop for verification failures
        for retry_count in 0..=MAX_VERIFICATION_RETRIES {
            if retry_count > 0 {
                info!(
                    "Publishing {} -> {} (retry {}/{})",
                    fqdn, self.host_ip, retry_count, MAX_VERIFICATION_RETRIES
                );
            } else {
                info!("Publishing {} -> {}", fqdn, self.host_ip);
            }

            // Spawn avahi-publish-address process with --no-reverse to avoid
            // "Local name collision" errors when publishing subdomains of the host's domain
            let mut child = Command::new("avahi-publish-address")
                .args(["--no-reverse", &fqdn, &self.host_ip])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()?;

            // Take stderr handle so we can read it later if the process fails
            let stderr = child.stderr.take();

            let process = AvahiProcess {
                child,
                stderr,
                fqdn: fqdn.clone(),
                subdomain: subdomain.to_string(),
            };

            self.processes.insert(container_id.to_string(), process);

            info!(
                "Started avahi-publish for {} (container {})",
                fqdn,
                &container_id[..12.min(container_id.len())]
            );

            // Verify that the record is actually resolvable
            let verified = self.verify_publication(container_id, &fqdn).await;

            if verified {
                return Ok(());
            }

            // If verification failed and we have retries left, loop will continue
            // (verify_publication already called unpublish on failure)
            if retry_count < MAX_VERIFICATION_RETRIES {
                warn!(
                    "Verification failed for {}, retrying ({}/{})",
                    fqdn,
                    retry_count + 1,
                    MAX_VERIFICATION_RETRIES
                );
            }
        }

        error!(
            "Failed to publish {} after {} retries, giving up",
            fqdn, MAX_VERIFICATION_RETRIES
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

        // Collect container IDs and subdomains to republish
        let to_republish: Vec<(String, String)> = self
            .processes
            .iter()
            .map(|(id, process)| (id.clone(), process.subdomain.clone()))
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

    /// Verify that a published record is resolvable.
    ///
    /// Waits for mDNS probing to complete, then tests resolution.
    /// Returns true if verification succeeded, false otherwise.
    /// On failure, the process is killed and removed to allow retry.
    async fn verify_publication(&mut self, container_id: &str, fqdn: &str) -> bool {
        // Wait for mDNS probing to complete
        tokio::time::sleep(Duration::from_millis(VERIFICATION_DELAY_MS)).await;

        // Check if process is still running
        let process_status = if let Some(process) = self.processes.get_mut(container_id) {
            match process.child.try_wait() {
                Ok(Some(status)) => Some(status),
                Ok(None) => None, // Still running
                Err(e) => {
                    error!("Error checking avahi-publish status for {}: {}", fqdn, e);
                    return false;
                }
            }
        } else {
            // Process was removed (container stopped?)
            return false;
        };

        // If process exited early, remove it and log the error
        if let Some(status) = process_status {
            // Remove the dead process to prevent duplicate logging in check_health
            if let Some(mut process) = self.processes.remove(container_id) {
                let stderr_output = Self::read_stderr(&mut process.stderr).await;
                error!(
                    "avahi-publish for {} exited immediately with status: {}{}",
                    fqdn,
                    status,
                    if stderr_output.is_empty() {
                        String::new()
                    } else {
                        format!("\nstderr: {}", stderr_output)
                    }
                );
            }
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

                // Check if the process is still running
                let process_died = if let Some(process) = self.processes.get_mut(container_id) {
                    matches!(process.child.try_wait(), Ok(Some(_)))
                } else {
                    true // Process already removed
                };

                // If process died, remove it and log with stderr
                if process_died {
                    if let Some(mut process) = self.processes.remove(container_id) {
                        let status = process.child.try_wait().ok().flatten();
                        let stderr_output = Self::read_stderr(&mut process.stderr).await;
                        error!(
                            "avahi-publish for {} exited with status: {}{}",
                            fqdn,
                            status
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "unknown".to_string()),
                            if stderr_output.is_empty() {
                                String::new()
                            } else {
                                format!("\nstderr: {}", stderr_output)
                            }
                        );
                    }
                } else {
                    // Process is running but not resolving - kill it to allow retry
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
        let mut dead_processes = Vec::new();

        for (container_id, process) in &mut self.processes {
            // Try to check if process is still running
            match process.child.try_wait() {
                Ok(Some(status)) => {
                    // Read stderr to understand why the process died
                    let stderr_output = Self::read_stderr(&mut process.stderr).await;
                    warn!(
                        "avahi-publish for {} exited with status: {}{}",
                        process.fqdn,
                        status,
                        if stderr_output.is_empty() {
                            String::new()
                        } else {
                            format!("\nstderr: {}", stderr_output)
                        }
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
}

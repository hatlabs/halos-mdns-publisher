//! Configuration for halos-mdns-publisher

use std::process::Command;

use crate::error::{PublisherError, Result};

/// Runtime configuration for the mDNS publisher
#[derive(Debug, Clone)]
pub struct Config {
    /// Docker socket path
    pub docker_socket: String,

    /// mDNS domain suffix (e.g., "halos.local")
    pub domain: String,

    /// Host IP address to advertise
    pub host_ip: String,

    /// Container label to look for
    pub label_key: String,
}

impl Config {
    /// Create a new configuration with auto-detected values
    pub fn new(docker_socket: Option<String>) -> Result<Self> {
        let domain = get_domain()?;
        let host_ip = get_host_ip()?;

        Ok(Self {
            docker_socket: docker_socket.unwrap_or_else(|| "/var/run/docker.sock".to_string()),
            domain,
            host_ip,
            label_key: "halos.subdomain".to_string(),
        })
    }
}

/// Get the mDNS domain based on hostname
fn get_domain() -> Result<String> {
    let hostname = gethostname::gethostname()
        .into_string()
        .map_err(|_| PublisherError::Hostname("Invalid UTF-8 in hostname".to_string()))?;

    // Get short hostname (before first dot)
    let short_hostname = hostname.split('.').next().unwrap_or(&hostname);

    Ok(format!("{}.local", short_hostname))
}

/// Get the host IP address from the default route
fn get_host_ip() -> Result<String> {
    // Use `ip route get 1.1.1.1` to find the source IP for the default route
    let output = Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .output()
        .map_err(|e| PublisherError::HostIp(format!("Failed to run ip route: {}", e)))?;

    if !output.status.success() {
        return Err(PublisherError::HostIp(
            "ip route command failed".to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output like: "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 1000"
    // We want the IP after "src"
    let ip = stdout
        .split_whitespace()
        .skip_while(|&s| s != "src")
        .nth(1)
        .ok_or_else(|| PublisherError::HostIp("Could not find src IP in route output".to_string()))?
        .to_string();

    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_format() {
        // Domain should end with .local
        let domain = get_domain().unwrap();
        assert!(domain.ends_with(".local"), "Domain should end with .local");
        assert!(!domain.starts_with('.'), "Domain should not start with dot");
    }

    #[test]
    fn test_host_ip_format() {
        // This test will only pass if the system has network connectivity
        if let Ok(ip) = get_host_ip() {
            // Basic IP format validation
            let parts: Vec<&str> = ip.split('.').collect();
            assert_eq!(parts.len(), 4, "IP should have 4 parts");
            for part in parts {
                // Verify each part is a valid u8 (0-255)
                let _num: u8 = part
                    .parse()
                    .expect("IP part should be a valid octet (0-255)");
            }
        }
    }
}

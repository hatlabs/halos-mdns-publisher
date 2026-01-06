//! Configuration for halos-mdns-publisher

use std::net::Ipv4Addr;
use std::process::Command;

use crate::error::{PublisherError, Result};

/// A host IP address with its interface name
#[allow(dead_code)] // TODO: remove when integrated into main.rs
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostIp {
    /// The IP address
    pub ip: String,
    /// The network interface name
    pub interface: String,
}

/// Check if an interface should have its IP published via mDNS
///
/// Excludes loopback, Docker bridges, and virtual ethernet interfaces.
#[allow(dead_code)] // TODO: remove when integrated
pub fn is_publishable_interface(name: &str) -> bool {
    // Exclude loopback
    if name == "lo" {
        return false;
    }
    // Exclude Docker default bridge
    if name == "docker0" {
        return false;
    }
    // Exclude Docker bridge networks (br-<id>)
    if name.starts_with("br-") {
        return false;
    }
    // Exclude Docker virtual ethernet pairs
    if name.starts_with("veth") {
        return false;
    }
    true
}

/// Check if an IP address should be published via mDNS
///
/// Excludes loopback and link-local addresses.
#[allow(dead_code)] // TODO: remove when integrated
pub fn is_publishable_ip(ip: &Ipv4Addr) -> bool {
    // Exclude loopback (127.x.x.x)
    if ip.is_loopback() {
        return false;
    }
    // Exclude link-local (169.254.x.x)
    if ip.is_link_local() {
        return false;
    }
    true
}

/// Get all routable host IP addresses from non-Docker interfaces
///
/// Filters out loopback, link-local, and Docker bridge interfaces.
#[allow(dead_code)] // TODO: remove when integrated into main.rs
pub fn get_host_ips() -> Result<Vec<HostIp>> {
    // Use `ip -j addr show` to get JSON output of all interfaces
    let output = Command::new("ip")
        .args(["-j", "addr", "show"])
        .output()
        .map_err(|e| PublisherError::HostIp(format!("Failed to run ip addr: {}", e)))?;

    if !output.status.success() {
        return Err(PublisherError::HostIp("ip addr command failed".to_string()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON output
    // Format: [{"ifname": "eth0", "addr_info": [{"local": "192.168.1.1", "family": "inet", ...}]}]
    let interfaces: Vec<serde_json::Value> = serde_json::from_str(&stdout)
        .map_err(|e| PublisherError::HostIp(format!("Failed to parse ip addr output: {}", e)))?;

    let mut host_ips = Vec::new();

    for iface in interfaces {
        let ifname = iface["ifname"].as_str().unwrap_or("");

        // Skip non-publishable interfaces
        if !is_publishable_interface(ifname) {
            continue;
        }

        // Get IPv4 addresses from addr_info
        if let Some(addr_info) = iface["addr_info"].as_array() {
            for addr in addr_info {
                // Only process IPv4 addresses
                if addr["family"].as_str() != Some("inet") {
                    continue;
                }

                if let Some(ip_str) = addr["local"].as_str() {
                    // Parse and validate IP
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        if is_publishable_ip(&ip) {
                            host_ips.push(HostIp {
                                ip: ip_str.to_string(),
                                interface: ifname.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    if host_ips.is_empty() {
        return Err(PublisherError::HostIp(
            "No publishable IP addresses found".to_string(),
        ));
    }

    Ok(host_ips)
}

/// Runtime configuration for the mDNS publisher
#[derive(Debug, Clone)]
pub struct Config {
    /// Docker socket path
    pub docker_socket: String,

    /// mDNS domain suffix (e.g., "myhostname.local")
    pub domain: String,

    /// Host IP address to advertise (legacy single-IP mode)
    #[allow(dead_code)] // Kept for backward compatibility; use get_host_ips() for multi-IP
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
///
/// Uses `ip route get 1.1.1.1` to determine the source IP for the default route.
/// This is more reliable than listing interfaces as it handles multiple interfaces
/// and complex routing configurations.
pub fn get_host_ip() -> Result<String> {
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

    // === Tests for HostIp type ===

    #[test]
    fn test_host_ip_equality() {
        let ip1 = HostIp {
            ip: "192.168.1.1".to_string(),
            interface: "eth0".to_string(),
        };
        let ip2 = HostIp {
            ip: "192.168.1.1".to_string(),
            interface: "eth0".to_string(),
        };
        let ip3 = HostIp {
            ip: "192.168.1.2".to_string(),
            interface: "eth0".to_string(),
        };

        assert_eq!(ip1, ip2);
        assert_ne!(ip1, ip3);
    }

    #[test]
    fn test_host_ip_clone() {
        let ip = HostIp {
            ip: "10.0.0.1".to_string(),
            interface: "wlan0".to_string(),
        };
        let cloned = ip.clone();
        assert_eq!(ip.ip, cloned.ip);
        assert_eq!(ip.interface, cloned.interface);
    }

    #[test]
    fn test_host_ip_debug() {
        let ip = HostIp {
            ip: "192.168.1.100".to_string(),
            interface: "eth0".to_string(),
        };
        let debug_str = format!("{:?}", ip);
        assert!(debug_str.contains("192.168.1.100"));
        assert!(debug_str.contains("eth0"));
    }

    // === Tests for is_publishable_interface ===

    #[test]
    fn test_publishable_interface_physical() {
        // Physical interfaces should be publishable
        assert!(
            is_publishable_interface("eth0"),
            "eth0 should be publishable"
        );
        assert!(
            is_publishable_interface("wlan0"),
            "wlan0 should be publishable"
        );
        assert!(
            is_publishable_interface("wlan0ap"),
            "wlan0ap should be publishable"
        );
        assert!(
            is_publishable_interface("enp0s3"),
            "enp0s3 should be publishable"
        );
        assert!(
            is_publishable_interface("wlp2s0"),
            "wlp2s0 should be publishable"
        );
    }

    #[test]
    fn test_publishable_interface_loopback() {
        // Loopback should not be publishable
        assert!(
            !is_publishable_interface("lo"),
            "lo should not be publishable"
        );
    }

    #[test]
    fn test_publishable_interface_docker() {
        // Docker interfaces should not be publishable
        assert!(
            !is_publishable_interface("docker0"),
            "docker0 should not be publishable"
        );
        assert!(
            !is_publishable_interface("br-abc123def"),
            "br-* should not be publishable"
        );
        assert!(
            !is_publishable_interface("br-1af60236a10c"),
            "br-* should not be publishable"
        );
        assert!(
            !is_publishable_interface("veth12345"),
            "veth* should not be publishable"
        );
        assert!(
            !is_publishable_interface("vethc0ffee"),
            "veth* should not be publishable"
        );
    }

    // === Tests for is_publishable_ip ===

    #[test]
    fn test_publishable_ip_normal() {
        // Normal IPs should be publishable
        assert!(
            is_publishable_ip(&Ipv4Addr::new(192, 168, 1, 100)),
            "192.168.1.100 should be publishable"
        );
        assert!(
            is_publishable_ip(&Ipv4Addr::new(10, 0, 0, 1)),
            "10.0.0.1 should be publishable"
        );
        assert!(
            is_publishable_ip(&Ipv4Addr::new(172, 16, 0, 1)),
            "172.16.0.1 should be publishable"
        );
    }

    #[test]
    fn test_publishable_ip_loopback() {
        // Loopback IPs should not be publishable
        assert!(
            !is_publishable_ip(&Ipv4Addr::new(127, 0, 0, 1)),
            "127.0.0.1 should not be publishable"
        );
        assert!(
            !is_publishable_ip(&Ipv4Addr::new(127, 0, 0, 2)),
            "127.0.0.2 should not be publishable"
        );
    }

    #[test]
    fn test_publishable_ip_link_local() {
        // Link-local IPs should not be publishable
        assert!(
            !is_publishable_ip(&Ipv4Addr::new(169, 254, 1, 1)),
            "169.254.1.1 should not be publishable"
        );
        assert!(
            !is_publishable_ip(&Ipv4Addr::new(169, 254, 255, 255)),
            "169.254.255.255 should not be publishable"
        );
    }
}

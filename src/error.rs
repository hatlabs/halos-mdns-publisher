//! Error types for halos-mdns-publisher

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PublisherError {
    #[error("Docker error: {0}")]
    Docker(#[from] bollard::errors::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to get hostname: {0}")]
    Hostname(String),

    #[error("Failed to get host IP: {0}")]
    HostIp(String),

    #[cfg(target_os = "linux")]
    #[error("Netlink error: {0}")]
    Netlink(#[from] rtnetlink::Error),
}

pub type Result<T> = std::result::Result<T, PublisherError>;

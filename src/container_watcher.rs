//! Docker container watching via bollard
//!
//! Monitors Docker for container start/stop events and extracts
//! the `halos.subdomain` label for mDNS publishing.

use std::collections::HashMap;

use bollard::container::{InspectContainerOptions, ListContainersOptions};
use bollard::system::EventsOptions;
use bollard::Docker;
use futures_util::StreamExt;
use tracing::{debug, info, warn};

use crate::error::Result;

/// Information about a container with an mDNS subdomain
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    /// Full container ID
    pub id: String,
    /// Container name (without leading /)
    pub name: String,
    /// Subdomain from halos.subdomain label
    pub subdomain: String,
}

/// Events from the container watcher
#[derive(Debug)]
pub enum ContainerEvent {
    /// Container with subdomain label started
    Started(ContainerInfo),
    /// Container stopped (by ID)
    Stopped(String),
}

/// Watches Docker containers for mDNS-relevant events
pub struct ContainerWatcher {
    docker: Docker,
    label_key: String,
}

impl ContainerWatcher {
    /// Create a new container watcher
    pub fn new(docker_socket: &str, label_key: &str) -> Result<Self> {
        let docker = Docker::connect_with_socket(
            docker_socket,
            120, // timeout in seconds
            bollard::API_DEFAULT_VERSION,
        )?;

        Ok(Self {
            docker,
            label_key: label_key.to_string(),
        })
    }

    /// Check if Docker is available
    pub async fn ping(&self) -> Result<()> {
        self.docker.ping().await?;
        Ok(())
    }

    /// Scan all running containers for those with the subdomain label
    pub async fn scan_containers(&self) -> Result<Vec<ContainerInfo>> {
        let mut filters = HashMap::new();
        filters.insert("status", vec!["running"]);

        let options = ListContainersOptions {
            all: false,
            filters,
            ..Default::default()
        };

        let containers = self.docker.list_containers(Some(options)).await?;
        let mut results = Vec::new();

        for container in containers {
            let id = match &container.id {
                Some(id) => id,
                None => continue,
            };

            if let Some(info) = self.inspect_container(id).await? {
                results.push(info);
            }
        }

        Ok(results)
    }

    /// Inspect a container and extract subdomain info if present
    pub async fn inspect_container(&self, container_id: &str) -> Result<Option<ContainerInfo>> {
        let options = InspectContainerOptions { size: false };

        let inspect = match self
            .docker
            .inspect_container(container_id, Some(options))
            .await
        {
            Ok(i) => i,
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {
                debug!("Container {} not found", container_id);
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        // Get container ID
        let id = inspect.id.unwrap_or_else(|| container_id.to_string());

        // Get container name (remove leading /)
        let name = inspect
            .name
            .map(|n| n.trim_start_matches('/').to_string())
            .unwrap_or_else(|| id.chars().take(12).collect());

        // Check for subdomain label
        let subdomain = inspect
            .config
            .and_then(|c| c.labels)
            .and_then(|labels| labels.get(&self.label_key).cloned());

        match subdomain {
            Some(subdomain) if !subdomain.is_empty() => {
                debug!(
                    "Container {} ({}) has subdomain: {}",
                    name,
                    &id[..12.min(id.len())],
                    subdomain
                );
                Ok(Some(ContainerInfo {
                    id,
                    name,
                    subdomain,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Watch for container events (start/stop)
    ///
    /// Returns an async stream of optional ContainerEvents.
    /// Returns None for containers that don't have the subdomain label on start.
    pub async fn watch_events(
        &self,
    ) -> impl futures_util::Stream<Item = Result<Option<ContainerEvent>>> + '_ {
        let mut filters = HashMap::new();
        filters.insert("type".to_string(), vec!["container".to_string()]);
        filters.insert(
            "event".to_string(),
            vec![
                "start".to_string(),
                "stop".to_string(),
                "die".to_string(),
                "destroy".to_string(),
            ],
        );

        let options = EventsOptions {
            since: None,
            until: None,
            filters,
        };

        let events = self.docker.events(Some(options));

        events.then(move |event_result| async move {
            match event_result {
                Ok(event) => {
                    let action = event.action.as_deref().unwrap_or("unknown");
                    let actor = event.actor.as_ref();
                    let container_id = actor
                        .and_then(|a| a.id.clone())
                        .unwrap_or_else(|| "unknown".to_string());

                    let container_name = actor
                        .and_then(|a| a.attributes.as_ref())
                        .and_then(|attrs| attrs.get("name"))
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");

                    info!("Docker event: {} container '{}'", action, container_name);

                    match action {
                        "start" => {
                            // Inspect to get subdomain
                            match self.inspect_container(&container_id).await {
                                Ok(Some(info)) => Ok(Some(ContainerEvent::Started(info))),
                                Ok(None) => {
                                    // Container doesn't have subdomain label, no event needed
                                    debug!(
                                        "Container '{}' has no subdomain label, ignoring",
                                        container_name
                                    );
                                    Ok(None)
                                }
                                Err(e) => {
                                    warn!("Failed to inspect container {}: {}", container_id, e);
                                    Err(e)
                                }
                            }
                        }
                        "stop" | "die" | "destroy" => {
                            Ok(Some(ContainerEvent::Stopped(container_id)))
                        }
                        _ => {
                            // Unknown event, treat as stop to clean up any stale state
                            Ok(Some(ContainerEvent::Stopped(container_id)))
                        }
                    }
                }
                Err(e) => Err(e.into()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_info_fields() {
        let info = ContainerInfo {
            id: "abc123def456".to_string(),
            name: "my-container".to_string(),
            subdomain: "app".to_string(),
        };

        assert_eq!(info.id, "abc123def456");
        assert_eq!(info.name, "my-container");
        assert_eq!(info.subdomain, "app");
    }

    #[test]
    fn test_container_event_variants() {
        let start_event = ContainerEvent::Started(ContainerInfo {
            id: "abc123".to_string(),
            name: "test".to_string(),
            subdomain: "web".to_string(),
        });

        let stop_event = ContainerEvent::Stopped("abc123".to_string());

        match start_event {
            ContainerEvent::Started(info) => assert_eq!(info.subdomain, "web"),
            _ => panic!("Expected Started event"),
        }

        match stop_event {
            ContainerEvent::Stopped(id) => assert_eq!(id, "abc123"),
            _ => panic!("Expected Stopped event"),
        }
    }
}

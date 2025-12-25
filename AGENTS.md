# HaLOS mDNS Publisher - Agent Instructions

## Repository Purpose

Native systemd service (Rust) that advertises container subdomains via Avahi/mDNS. Monitors Docker containers for the `halos.subdomain` label and dynamically publishes/removes mDNS records.

## Key Files

- `src/main.rs` - Entry point, CLI, signal handling, main service loop
- `src/container_watcher.rs` - Docker event monitoring via bollard
- `src/avahi_manager.rs` - avahi-publish subprocess management
- `src/config.rs` - Configuration and hostname/IP detection
- `src/error.rs` - Error types
- `debian/` - Debian packaging files
- `VERSION` - Package version for CI/CD

## Technical Notes

### How It Works

1. Waits for Docker daemon to be available (graceful degradation)
2. Scans running containers for `halos.subdomain` label
3. Spawns `avahi-publish -a` subprocesses for each subdomain
4. Monitors Docker events via bollard async stream
5. Starts/stops avahi-publish processes as containers start/stop
6. Periodic health checks to restart failed avahi-publish processes

### Container Labels

Containers can set `halos.subdomain=auth` to advertise `auth.<hostname>.local`.

### Domain

The domain is automatically derived from the system hostname: `<hostname>.local`

### Rust Crates

- `bollard` - Docker API client (async)
- `tokio` - Async runtime with process and signal support
- `tracing` - Structured logging
- `clap` - CLI argument parsing
- `anyhow`/`thiserror` - Error handling

## Development Commands

```bash
./run help              # Show all commands
./run build             # Build debug binary
./run build-release     # Build release binary
./run test              # Run tests
./run lint              # Run clippy and format check
./run hooks-install     # Install pre-commit hooks
```

## CI/CD

Uses shared-workflows for Debian package building:
- **main.yml**: Builds and publishes to apt.hatlabs.fi unstable on push to main
- **pr.yml**: Runs tests and linting on PRs
- **release.yml**: Publishes to apt.hatlabs.fi stable when release is published

## Debian Package

- Package name: `halos-mdns-publisher`
- Conflicts/Replaces: `halos-mdns-publisher-container` (old container-based package)
- Dependencies: `avahi-daemon`, `avahi-utils`
- Recommends: `docker.io` or `docker-ce`

## Related Repos

- `halos-core-containers` - Previously contained container-based mdns-publisher
- `halos-distro` - Parent workspace
- `homarr-container-adapter` - Similar Rust service pattern

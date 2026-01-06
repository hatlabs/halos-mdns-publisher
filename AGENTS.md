# HaLOS mDNS Publisher - Agent Instructions

## Repository Purpose

Native systemd service (Rust) that advertises container subdomains via Avahi/mDNS. Monitors Docker containers for the `halos.subdomain` label and dynamically publishes/removes mDNS records.

## ⚠️ Linux-Only Project

**IMPORTANT**: This is a Linux-only project. It uses Linux-specific APIs (netlink) that do not exist on macOS or Windows.

**All builds and tests MUST be performed in Docker containers.** The `./run` script commands automatically use Docker for compilation and testing. Never attempt native builds on macOS - they will fail.

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
3. Spawns `avahi-publish-address --no-reverse` subprocesses for each subdomain
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

## Versioning

**IMPORTANT**: Always use `./run bumpversion` to change versions. Never edit version files manually.

```bash
./run bumpversion patch    # Bump patch version (0.2.3 -> 0.2.4)
./run bumpversion minor    # Bump minor version (0.2.3 -> 0.3.0)
./run bumpversion major    # Bump major version (0.2.3 -> 1.0.0)
```

The command automatically commits the version change. Just push afterwards:
```bash
git push
```

**Note:** The working directory must be clean before bumping. This ensures atomic, isolated version commits.

**Version files kept in sync by bumpversion:**
- `VERSION` - Canonical source, read by CI
- `Cargo.toml` - Rust package version

**Note:** `debian/changelog` is generated dynamically by CI from the VERSION file.

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

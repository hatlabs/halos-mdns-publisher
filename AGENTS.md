# HaLOS mDNS Publisher - Agent Instructions

## Repository Purpose

Docker image that advertises `*.halos.local` subdomains via Avahi/mDNS. Monitors Docker containers for the `halos.subdomain` label and dynamically publishes/removes mDNS records.

## Key Files

- `Dockerfile` - Alpine-based image with bash, docker-cli, avahi-tools, jq
- `publish-subdomains.sh` - Main script monitoring Docker events and managing avahi-publish
- `VERSION` - Image version for tagging

## Technical Notes

### How It Works

1. Runs on host network to access Avahi daemon
2. Monitors Docker socket for container events
3. Scans containers for `halos.subdomain` label
4. Uses `avahi-publish -a` to advertise subdomains
5. Tracks PIDs in `/tmp/mdns-publisher/` for cleanup

### Container Labels

Containers can set `halos.subdomain=auth` to advertise `auth.<hostname>.local`.

### Domain

The domain is automatically derived from the system hostname: `<hostname>.local`

## Development Commands

```bash
./run help              # Show all commands
./run build             # Build Docker image locally
./run build-multiarch   # Build multi-arch image
./run bump-version patch|minor|major  # Bump version
./run install-hooks     # Install pre-commit hooks
```

## Version Management

Uses bump2version for version management:
- `VERSION` file is the source of truth
- `.bumpversion.cfg` configures bump2version
- `./run bump-version patch` bumps and commits automatically

## CI/CD

- **main.yml**: Builds and pushes to ghcr.io on push to main
- **pr.yml**: Builds (no push) on PRs for validation
- **release.yml**: Tags stable releases when GitHub releases are published

## Related Repos

- `halos-core-containers` - Contains `apps/mdns-publisher/` package that uses this image
- `halos-distro` - Parent workspace

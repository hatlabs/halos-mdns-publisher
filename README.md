# HaLOS mDNS Publisher

Native systemd service that advertises container subdomains via mDNS for HaLOS, and configures the system to resolve multi-label mDNS hostnames.

## Overview

This package provides two key mDNS capabilities:

1. **Publishing**: Monitors Docker containers for the `halos.subdomain` label and uses `avahi-publish` to advertise the corresponding mDNS records. This enables automatic subdomain resolution for HaLOS services on the local network.

2. **Resolution**: Configures the system to resolve multi-label mDNS hostnames (e.g., `auth.hostname.local`). By default, Debian only resolves single-label `.local` names; this package enables full subdomain resolution.

## Installation

The package is available from the Hat Labs APT repository:

```bash
# Add Hat Labs repository (if not already added)
curl -fsSL https://apt.hatlabs.fi/hat-labs-apt-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/hatlabs-apt-key.gpg
echo "deb [signed-by=/usr/share/keyrings/hatlabs-apt-key.gpg] https://apt.hatlabs.fi stable main" | sudo tee /etc/apt/sources.list.d/hatlabs.list

# Install the package
sudo apt update
sudo apt install halos-mdns-publisher
```

The service starts automatically after installation.

## Container Labels

Add the `halos.subdomain` label to containers you want to advertise:

```yaml
services:
  authelia:
    image: authelia/authelia:4.39
    labels:
      - "halos.subdomain=auth"  # Advertises auth.<hostname>.local
```

## How It Works

1. On startup, scans all running Docker containers for `halos.subdomain` labels
2. Monitors Docker events for container start/stop
3. Uses `avahi-publish` to advertise subdomains pointing to the host IP
4. Cleans up mDNS records when containers stop
5. Graceful degradation: waits for Docker if not immediately available

## Service Management

```bash
# Check status
sudo systemctl status halos-mdns-publisher

# View logs
sudo journalctl -u halos-mdns-publisher -f

# Restart service
sudo systemctl restart halos-mdns-publisher
```

## Command Line Options

```
Usage: halos-mdns-publisher [OPTIONS]

Options:
  -s, --socket <SOCKET>  Docker socket path [default: /var/run/docker.sock]
  -d, --debug            Enable debug logging
      --health-interval  Health check interval in seconds [default: 60]
  -h, --help             Print help
  -V, --version          Print version
```

## mDNS Resolution Configuration

This package configures the system to resolve multi-label mDNS hostnames by:

1. Installing `/etc/mdns.allow` to permit resolution of all `.local` domain names
2. Updating `/etc/nsswitch.conf` to use `mdns4` instead of `mdns4_minimal`

The `mdns4_minimal` resolver (Debian default) only resolves 2-label hostnames like `hostname.local`. The `mdns4` resolver with `mdns.allow` enables resolution of multi-label names like `auth.hostname.local`.

These changes are reverted when the package is purged (`apt purge halos-mdns-publisher`).

## Requirements

- Avahi daemon (`avahi-daemon` package)
- Avahi utilities (`avahi-utils` package)
- libnss-mdns (`libnss-mdns` package) - for mDNS name resolution
- Docker (recommended but not required at startup)

## Development

```bash
# Build
./run build

# Run tests
./run test

# Run linting
./run lint

# Install pre-commit hooks
./run hooks-install
```

## Migration from Container Version

This native package replaces the container-based `halos-mdns-publisher-container` package. The migration is automatic - installing this package will remove the container version.

## License

MIT License - see [LICENSE](LICENSE)

## Related

- [HaLOS Distro](https://github.com/hatlabs/halos-distro) - HaLOS workspace
- [HaLOS Core Containers](https://github.com/hatlabs/halos-core-containers) - Core container definitions

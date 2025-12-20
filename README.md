# HaLOS mDNS Publisher

Advertises `*.halos.local` subdomains via Avahi/mDNS for HaLOS containers.

## Overview

This Docker image monitors running containers for the `halos.subdomain` label and uses `avahi-publish` to advertise the corresponding mDNS records. This enables automatic subdomain resolution for HaLOS services on the local network.

## Usage

The container must run with host networking to access the Avahi daemon:

```yaml
services:
  mdns-publisher:
    image: ghcr.io/hatlabs/halos-mdns-publisher:latest
    container_name: mdns-publisher
    restart: unless-stopped
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /var/run/dbus:/var/run/dbus
```

The domain is automatically derived from the system hostname: `<hostname>.local`

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

1. On startup, scans all running containers for `halos.subdomain` labels
2. Monitors Docker events for container start/stop
3. Uses `avahi-publish` to advertise subdomains pointing to the host IP
4. Cleans up mDNS records when containers stop

## Requirements

- Host must have Avahi daemon running
- Container needs access to Docker socket
- Must run with `network_mode: host`

## Building

```bash
docker build -t halos-mdns-publisher .
```

## License

MIT License - see [LICENSE](LICENSE)

## Related

- [HaLOS Distro](https://github.com/hatlabs/halos-distro) - HaLOS workspace
- [HaLOS Core Containers](https://github.com/hatlabs/halos-core-containers) - Core container definitions

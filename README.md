# VPN

A personal, lightweight self-hostable VPN (server + client) implemented in Go.

## Key points
- Functional end-to-end VPN with TUN interface, NAT, routing and client authentication.
- Uses DTLS for secure transport between client and server.
- Low latency in tests (responsive), but current throughput is limited — observed ~200 KB/s in typical tests. Bandwidth is a known issue and under active investigation.
- Originally started as fun learning side project — now a functional lightweight VPN suited for low‑bandwidth needs.

## Features
- TUN interface creation and configuration
- NAT masquerading and IP forwarding for client internet access
- DTLS-secured transport
- Simple client/server protocol with keep-alive and authentication
- Dockerfile and docker-compose for quick deployment
- Config file support (place config in `./config/ServerConfig.json` or mount into container)

## Current limitations
- Bandwidth: throughput is currently limited (see Status). Suitable for low-bandwidth tasks.
- Not hardened for large-scale production by default (TLS/DTLS cert management optional).
- Verbose debug logging can impact performance — disable in production.
- Currently only supports linux (can be easily ported to windows by few changes needed in network interface and routing)

## Quick start (development)
1. Build and run:
    ```bash
    docker-compose up --build
    ```
2. Place server config at `./config/ServerConfig.json` or mount it into `/app/ServerConfig.json` in the container.
3. Use the included client (container or native) — requires root to create TUN device.


## Roadmap
- Investigate and fix bandwidth bottlenecks (MTU tuning, buffering, logging, routing)
- Improve DTLS certificate management and optional automated provisioning
- Add config-driven runtime tuning and better defaults
- Add tests and CI


# VPN Server

## Files & config
- Server code: `src/server/*`
- Default server config expected at: `./config/ServerConfig.json` or `/app/ServerConfig.json` (when running in container)
- Example config provided in `config/ServerConfig.json` (update and mount into container if needed)

## Quick start (Docker)
1. Ensure `config/ServerConfig.json` exists or mount your config:
   - docker-compose mounts: `./config:/app/config:ro` (recommended)
2. Build & run:
```bash
docker-compose up --build
```
3. To run only server:
```bash
docker-compose up --build vpn-server
```

## Quick start (local)
Requires root to create TUN device:
```bash
# from repo root
cd src/server
go build -o vpn-server ./cmd/Server/Server.go
sudo ./vpn-server
```


## Troubleshooting
- `exec format error` → architecture mismatch; ensure build/runtime platform match.
- `Permission denied` → binary lacks +x or container not running privileged (needs /dev/net/tun and NET_ADMIN).
- No internet from client:
  - Ensure ip_forward enabled and iptables MASQUERADE rule present.
  - Check TUN MTU (recommended 1400) to avoid fragmentation.
  - Disable verbose packet logging during performance tests.
- Config not found: mount `./config/ServerConfig.json` into `/app/ServerConfig.json` or place config in `/app/config/ServerConfig.json`.

## Performance notes
- Current throughput is limited; known areas to improve:
  - MTU tuning (default set to 1400)
  - Reduce logging overhead
  - Buffer sizing and goroutine scheduling
  - Consider using host networking or optimized Docker network mode 

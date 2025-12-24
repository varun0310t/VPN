# VPN Client

Simple VPN client that connects to the VPN server and routes all traffic through the VPN tunnel.

## Features

- ✅ **Automatic network config backup** - Saves your original routing and restores it on disconnect
- ✅ **TUN interface management** - Creates and configures virtual network interface
- ✅ **Secure authentication** - Authenticates with VPN server
- ✅ **Automatic routing** - Routes all traffic through VPN (except VPN server connection)
- ✅ **Keep-alive** - Maintains connection with periodic pings
- ✅ **Graceful shutdown** - Restores original network config on exit (Ctrl+C)

## Requirements

- Linux (TUN interface support)
- Root/sudo privileges (required for TUN and routing)

## Usage

### Build
```bash
go build -o vpn-client ./src/client.go
```

### Run
```bash
# Connect to VPN server
sudo ./vpn-client -server 192.168.1.100 -port 8080
```

### Parameters
- `-server` - VPN server IP address (default: 127.0.0.1)
- `-port` - VPN server port (default: 8080)

### Disconnect
Press `Ctrl+C` to disconnect. The client will automatically:
1. Restore original default gateway
2. Remove VPN routes
3. Close TUN interface
4. Notify server of disconnection

## Docker

### Build Docker image
```bash
docker build -t vpn-client -f src/client/dockerfile .
```

### Run in Docker
```bash
docker run -it --rm \
  --privileged \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --device=/dev/net/tun \
  -e SERVER_IP=192.168.1.100 \
  -e SERVER_PORT=8080 \
  vpn-client
```

## How It Works

1. **Initialize**
   - Save current network configuration (routes, gateway)
   - Connect to VPN server via UDP

2. **Authenticate**
   - Send authentication request
   - Receive assigned VPN IP (e.g., 10.8.0.2)

3. **Setup TUN**
   - Create TUN interface (tun1)
   - Configure with assigned IP
   - Bring interface up

4. **Setup Routing**
   - Add route for VPN server through original gateway (avoid routing loop)
   - Change default route to go through VPN tunnel
   - All traffic now flows through VPN

5. **Forward Traffic**
   - Packets from local apps → TUN → wrapped in VPN protocol → UDP → server
   - Server responses → UDP → unwrapped → TUN → local apps

6. **Disconnect**
   - Restore original default gateway
   - Remove VPN routes
   - Close TUN interface
   - Your original network config is back!

## Network Flow

```
Local App
   ↓
TUN Interface (10.8.0.2)
   ↓
VPN Client
   ↓ (UDP packet)
VPN Server (10.8.0.1)
   ↓
Internet
```

## Troubleshooting

### "Permission denied" when creating TUN
Run with sudo/root:
```bash
sudo ./vpn-client -server 192.168.1.100
```

### "Failed to restore network config"
Manually restore:
```bash
# Check current routes
ip route show

# Restore default gateway (replace with your gateway)
sudo ip route add default via 192.168.1.1 dev eth0
```

### Check if VPN is active
```bash
# Should show tun1 interface
ip addr show tun1

# Should show default route through tun1
ip route show default
```

### DNS not working
The client doesn't modify DNS yet. You can manually set DNS:
```bash
# Edit resolv.conf
sudo nano /etc/resolv.conf
# Add: nameserver 8.8.8.8
```

## Files

- `main.go` - Entry point and initialization
- `Connection.go` - VPN connection, authentication, packet handling
- `TunManager.go` - TUN interface creation and management
- `NetworkConfig.go` - Save/restore network configuration
- `dockerfile` - Docker build configuration

## Safety Features

- **Original config backup** - Network config saved before any changes
- **Graceful shutdown** - Ctrl+C triggers full cleanup
- **No permanent changes** - Everything restored on exit
- **Route protection** - VPN server always reachable via original gateway

## Example Session

```bash
$ sudo ./vpn-client -server 192.168.1.100 -port 8080

🔌 VPN Client Starting...
Server: 192.168.1.100:8080
💾 Saving current network configuration...
✅ Saved 5 routes
✅ VPN Client initialized
Server: 192.168.1.100:8080
🔐 Authenticating with server...
✅ Authenticated! Assigned IP: 10.8.0.2
✅ TUN interface tun1 created (fd: 6)
Configuring TUN interface tun1 with IP 10.8.0.2...
✅ TUN interface configured: tun1 (10.8.0.2/24)
✅ TUN interface created and configured
📡 Setting up VPN routes...
✅ Default gateway: 192.168.1.1 via eth0
✅ Route to VPN server via original gateway
✅ Default route now goes through tun1
✅ Routes configured
🚀 VPN connection established!
📤 Sending to VPN: dest=8.8.8.8 (84 bytes)
📥 Received from VPN: src=8.8.8.8 (84 bytes)
^C
🛑 Shutting down VPN client...
Disconnecting from VPN...
📡 Restoring original network configuration...
✅ Default gateway restored: 192.168.1.1 via eth0
✅ Network configuration restored
✅ TUN interface closed
✅ Connection closed
✅ VPN disconnected successfully
```

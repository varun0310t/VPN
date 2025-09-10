package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	SERVER_PORT = "8080"
	BUFFER_SIZE = 1500
)

type VPNServer struct {
	clients    map[string]*ClientConnection
	clientsMux sync.RWMutex
}

type ClientConnection struct {
	conn       net.Conn
	clientID   string
	lastSeen   time.Time
	packetChan chan []byte
}

func main() {
	fmt.Println("🚀 Starting VPN Server...")

	server := &VPNServer{
		clients: make(map[string]*ClientConnection),
	}

	// Start the server
	listener, err := net.Listen("tcp", ":"+SERVER_PORT)
	if err != nil {
		fmt.Printf("❌ Failed to start server: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("✅ VPN Server listening on port %s\n", SERVER_PORT)
	fmt.Println("📡 Waiting for VPN clients...")

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("❌ Failed to accept connection: %v\n", err)
			continue
		}

		clientID := conn.RemoteAddr().String()
		fmt.Printf("🔗 New VPN client connected: %s\n", clientID)

		// Handle each client in a separate goroutine
		go server.handleClient(conn, clientID)
	}
}

func (s *VPNServer) handleClient(conn net.Conn, clientID string) {
	defer conn.Close()

	// Register client
	client := &ClientConnection{
		conn:       conn,
		clientID:   clientID,
		lastSeen:   time.Now(),
		packetChan: make(chan []byte, 100),
	}
	s.clientsMux.Lock()
	s.clients[clientID] = client
	s.clientsMux.Unlock()

	// Cleanup on disconnect
	defer func() {
		s.clientsMux.Lock()
		delete(s.clients, clientID)
		s.clientsMux.Unlock()
		fmt.Printf("🔌 Client disconnected: %s\n", clientID)
	}()
	packetCount := 0
	totalBytes := 0

	fmt.Printf("📦 Processing packets from %s...\n", clientID)

	for {
		// Read packet length (4 bytes)
		lengthBytes := make([]byte, 4)
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err := io.ReadFull(conn, lengthBytes)
		if err != nil {
			if err == io.EOF {
				fmt.Printf("📊 Client %s disconnected gracefully after %d packets (%d bytes)\n",
					clientID, packetCount, totalBytes)
			} else {
				fmt.Printf("❌ Error reading packet length from %s: %v\n", clientID, err)
			}
			break
		}

		// Parse packet length (by combining 4 bytes into a single 32 bit int)
		packetLen := int(lengthBytes[0])<<24 |
			int(lengthBytes[1])<<16 |
			int(lengthBytes[2])<<8 |
			int(lengthBytes[3])

		// Validate packet length
		if packetLen <= 0 || packetLen > BUFFER_SIZE {
			fmt.Printf("❌ Invalid packet length from %s: %d\n", clientID, packetLen)
			break
		}

		// Read packet data
		packet := make([]byte, packetLen)
		_, err = io.ReadFull(conn, packet)
		if err != nil {
			fmt.Printf("❌ Error reading packet data from %s: %v\n", clientID, err)
			break
		}

		packetCount++
		totalBytes += packetLen
		client.lastSeen = time.Now()

		// Process the packet
		s.processPacket(client, packet, packetCount)

		// Show progress every 100 packets
		if packetCount%100 == 0 {
			fmt.Printf("📈 %s: %d packets processed (%d bytes total)\n",
				clientID, packetCount, totalBytes)
		}
	}

	fmt.Printf("📊 Final stats for %s: %d packets, %d bytes\n",
		clientID, packetCount, totalBytes)
}

func (s *VPNServer) processPacket(client *ClientConnection, packet []byte, packetNum int) {
	// Analyze the IP packet
	if len(packet) < 20 {
		return // Invalid IP packet
	}

	// Parse IP header
	version := packet[0] >> 4
	if version != 4 {
		return // Only handle IPv4
	}

	// Extract IPs
	sourceIP := net.IPv4(packet[12], packet[13], packet[14], packet[15])
	destIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])
	protocol := packet[9]

	// Get protocol name
	var protocolName string
	switch protocol {
	case 1:
		protocolName = "ICMP"
	case 6:
		protocolName = "TCP"
	case 17:
		protocolName = "UDP"
	default:
		protocolName = fmt.Sprintf("Proto-%d", protocol)
	}

	// Log interesting packets
	if packetNum <= 10 || packetNum%200 == 0 {
		fmt.Printf("🌐 Packet #%d: %s %s → %s (%d bytes)\n",
			packetNum, protocolName, sourceIP, destIP, len(packet))
	}

	// TODO: Forward packet to real internet

	s.forwardToInternet(packet, destIP.String(), protocolName)

	// TODO: Send response back to client

	if packetNum%50 == 0 {
		s.sendMockResponse(client, packet)
	}
}

func (s *VPNServer) forwardToInternet(packet []byte, destIP string, protocol string) {
	//todo

}

func (s *VPNServer) sendMockResponse(client *ClientConnection, originalPacket []byte) {
	//todo

	fmt.Printf("📤 [SIM] Would send response back to %s\n", client.clientID)
}

// Helper function to get server statistics
func (s *VPNServer) getStats() {
	s.clientsMux.RLock()
	defer s.clientsMux.RUnlock()

	fmt.Printf("📊 Server Stats: %d active clients\n", len(s.clients))
	for id, client := range s.clients {
		fmt.Printf("   - %s (last seen: %v ago)\n",
			id, time.Since(client.lastSeen))
	}
}

// TODO:
// - Real internet packet forwarding using raw sockets or tun
// - Response packet handling and routing back to clients
// - Client authentication and encryption
// - Bandwidth limiting and monitoring
// - Configuration management
// - Logging and metrics

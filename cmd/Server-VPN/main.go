package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	SERVER_PORT = "8080"
	BUFFER_SIZE = 1500
)

type VPNServer struct {
	clients       map[string]*ClientConnection
	clientsMux    sync.RWMutex
	tunDevice     tun.Device
	responsesChan chan ResponsePacket // Add this for response handling
}

type ClientConnection struct {
	conn       net.Conn
	clientID   string
	lastSeen   time.Time
	packetChan chan []byte
}

// Add this new struct for responses
type ResponsePacket struct {
	packet   []byte
	clientID string
}

func main() {
	fmt.Println("🚀 Starting VPN Server...")

	server := &VPNServer{
		clients:       make(map[string]*ClientConnection),
		responsesChan: make(chan ResponsePacket, 1000), // Buffer for responses
	}

	// Create TUN interface for internet forwarding
	err := server.initTunInterface()
	if err != nil {
		fmt.Printf("❌ Failed to create TUN interface: %v\n", err)
		fmt.Println("💡 Run as Administrator for TUN interface access")
		os.Exit(1)
	}
	defer server.tunDevice.Close()

	// Start global response listener (reads from TUN)
	go server.listenForInternetResponses()

	// Start response dispatcher (sends to clients)
	go server.dispatchResponsesToClients()

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

func (s *VPNServer) initTunInterface() error {
	// Create TUN interface on server (different name than client)
	device, err := tun.CreateTUN("VPN-Server", 1420)
	if err != nil {
		return fmt.Errorf("failed to create server TUN: %v", err)
	}

	s.tunDevice = device

	name, err := device.Name()
	if err != nil {
		device.Close()
		return fmt.Errorf("failed to get TUN name: %v", err)
	}

	// Configure server TUN with different IP range
	err = s.configureTunInterface(name)
	if err != nil {
		device.Close()
		return fmt.Errorf("failed to configure TUN: %v", err)
	}

	time.Sleep(5 * time.Second)

	fmt.Printf("✅ Server TUN interface '%s' created successfully\n", name)
	return nil
}

func (s *VPNServer) configureTunInterface(interfaceName string) error {
	// CHANGE THIS LINE:
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+interfaceName, "static", "10.0.0.1", "255.255.255.0") // ← Changed from 10.0.1.1 to 10.0.0.1
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set server IP: %v", err)
	}

	// CHANGE THIS LINE TOO:
	cmd = exec.Command("route", "add", "10.0.0.0", "mask", "255.255.255.0", "10.0.0.1") // ← Changed from 10.0.1.1
	cmd.Run()

	fmt.Printf("Server TUN configured with IP 10.0.0.1\n") // ← Updated message
	return nil
}

// Replace forwardToInternet with TUN-based forwarding
func (s *VPNServer) forwardToInternet(packet []byte, destIP string, protocol string) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too small")
	}

	// Skip problematic packets
	destBytes := packet[16:20]
	if destBytes[0] >= 224 && destBytes[0] <= 239 {
		return nil
	}
	if destBytes[3] == 255 {
		return nil
	}
	if packet[9] == 2 {
		return nil
	}

	// ✅ FIX: Change source IP to server's TUN IP for NAT
	originalSource := make([]byte, 4)
	copy(originalSource, packet[12:16]) // Save original source

	// Set source IP to server TUN IP (10.0.0.1) so responses come back to server
	packet[12] = 10 // Source IP: 10.0.0.1
	packet[13] = 0
	packet[14] = 0
	packet[15] = 1

	// Recalculate IP header checksum after changing source IP
	packet[10] = 0 // Clear existing checksum
	packet[11] = 0
	checksum := calculateIPChecksum(packet[:20])
	packet[10] = byte(checksum >> 8)
	packet[11] = byte(checksum & 0xFF)

	// Forward packet via TUN interface
	_, err := s.tunDevice.Write([][]byte{packet}, 0)
	if err != nil {
		return fmt.Errorf("failed to write to TUN: %v", err)
	}

	// Log successful forwarding
	if protocol == "ICMP" || protocol == "UDP" || protocol == "TCP" {
		fmt.Printf("🌍 Forwarded %s packet to %s via TUN (NAT: %d.%d.%d.%d→10.0.0.1, %d bytes)\n",
			protocol, destIP, originalSource[0], originalSource[1], originalSource[2], originalSource[3], len(packet))
	}

	return nil
}

// Helper function to calculate IP checksum
func calculateIPChecksum(header []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words in header
	for i := 0; i < len(header); i += 2 {
		if i+1 < len(header) {
			sum += uint32(header[i])<<8 + uint32(header[i+1])
		}
	}

	// Add carry bits
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// Return one's complement
	return uint16(^sum)
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

	// Forward packet to real internet
	err := s.forwardToInternet(packet, destIP.String(), protocolName)
	if err != nil {
		fmt.Printf("❌ Failed to forward packet: %v\n", err)
	}
}

// NEW: Global response listener - reads packets FROM internet
func (s *VPNServer) listenForInternetResponses() {
	fmt.Println("🔄 Starting internet response listener...")

	buffer := make([][]byte, 1)
	buffer[0] = make([]byte, 1500)
	lengths := make([]int, 1)
	responseCount := 0
	errorCount := 0
	realResponseCount := 0

	for {
		n, err := s.tunDevice.Read(buffer, lengths, 0)
		if err != nil {
			errorCount++
			if errorCount%1000 == 0 {
				fmt.Printf("🔍 TUN read errors: %d (latest: %v)\n", errorCount, err)
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if n > 0 && lengths[0] > 0 {
			responseCount++
			responsePacket := make([]byte, lengths[0])
			copy(responsePacket, buffer[0][:lengths[0]])

			// ✅ BETTER DEBUGGING
			if len(responsePacket) >= 20 {
				sourceIP := net.IPv4(responsePacket[12], responsePacket[13], responsePacket[14], responsePacket[15])
				destIP := net.IPv4(responsePacket[16], responsePacket[17], responsePacket[18], responsePacket[19])
				protocol := responsePacket[9]
				protocolName := "Unknown"
				switch protocol {
				case 1:
					protocolName = "ICMP"
				case 6:
					protocolName = "TCP"
				case 17:
					protocolName = "UDP"
				}

				// Check if this looks like a real internet response
				isRealResponse := (sourceIP.String() == "8.8.8.8" ||
					sourceIP.String() == "8.8.4.4" ||
					strings.Contains(sourceIP.String(), "142.251")) &&
					destIP.String() != "0.0.0.0"

				if isRealResponse {
					realResponseCount++
					fmt.Printf("🎉 REAL Response #%d: %s %s → %s (%d bytes)\n",
						realResponseCount, protocolName, sourceIP, destIP, len(responsePacket))
				} else if responseCount <= 10 {
					fmt.Printf("🔍 Response #%d: %s %s → %s (%d bytes)\n",
						responseCount, protocolName, sourceIP, destIP, len(responsePacket))
				}
			}

			clientID := s.findClientForResponse(responsePacket)
			if clientID != "" {
				select {
				case s.responsesChan <- ResponsePacket{
					packet:   responsePacket,
					clientID: clientID,
				}:
					if responseCount <= 5 {
						fmt.Printf("✅ Queued response #%d for client %s\n", responseCount, clientID)
					}
				default:
					fmt.Printf("⚠️ Response channel full, dropping packet\n")
				}

				if responseCount%50 == 0 {
					fmt.Printf("📥 Processed %d internet responses\n", responseCount)
				}
			} else {
				if responseCount <= 10 && len(responsePacket) >= 20 {
					destIP := net.IPv4(responsePacket[16], responsePacket[17], responsePacket[18], responsePacket[19])
					fmt.Printf("🤔 No client found for response to %s\n", destIP)
				}
			}
		}
	}
}

// NEW: Find which client a response packet belongs to
func (s *VPNServer) findClientForResponse(packet []byte) string {
	if len(packet) < 20 {
		return ""
	}

	destIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])

	// Check if this is destined for a VPN client
	if destIP.String() == "10.0.0.2" { // This should now work!
		s.clientsMux.RLock()
		defer s.clientsMux.RUnlock()

		for clientID := range s.clients {
			return clientID
		}
	}

	return ""
}

// NEW: Dispatch responses to appropriate clients
func (s *VPNServer) dispatchResponsesToClients() {
	fmt.Println("📤 Starting response dispatcher...")

	for responsePacket := range s.responsesChan {
		s.clientsMux.RLock()
		client, exists := s.clients[responsePacket.clientID]
		s.clientsMux.RUnlock()

		if exists {
			err := s.sendResponseToClient(client, responsePacket.packet)
			if err != nil {
				fmt.Printf("❌ Failed to send response to %s: %v\n",
					responsePacket.clientID, err)
			} else {
				// Log successful response
				if len(responsePacket.packet) >= 20 {
					protocol := responsePacket.packet[9]
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

					sourceIP := net.IPv4(responsePacket.packet[12], responsePacket.packet[13],
						responsePacket.packet[14], responsePacket.packet[15])

					fmt.Printf("📩 Sent %s response from %s to client (%d bytes)\n",
						protocolName, sourceIP, len(responsePacket.packet))
				}
			}
		}
	}
}

// Update the existing sendResponseToClient function
func (s *VPNServer) sendResponseToClient(client *ClientConnection, responsePacket []byte) error {
	// Send packet length first (same format as client sends to server)
	packetLen := len(responsePacket)
	lengthBytes := []byte{
		byte(packetLen >> 24),
		byte(packetLen >> 16),
		byte(packetLen >> 8),
		byte(packetLen),
	}

	// Set write deadline to prevent hanging
	client.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	// Send length
	_, err := client.conn.Write(lengthBytes)
	if err != nil {
		return fmt.Errorf("failed to send response length: %v", err)
	}

	// Send packet
	_, err = client.conn.Write(responsePacket)
	if err != nil {
		return fmt.Errorf("failed to send response packet: %v", err)
	}

	return nil
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

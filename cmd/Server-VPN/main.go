//go:build linux
// +build linux

package main

import (
	"fmt"
	"net"
	"syscall"
)

var Socket int
var CaptureSocket int
var UDPConn *net.UDPConn
var ClientAddr *net.UDPAddr

func main() {
	// Create raw socket
	Socket = CreateRawSocket()
	if Socket == -1 {
		panic("Failed to create raw socket")
	}
	defer syscall.Close(Socket)

	CaptureSocket = CreateCaptureSocket()
	if CaptureSocket == -1 {
		panic("Failed to create capture socket")
	}
	defer syscall.Close(CaptureSocket)

	// ✅ Create UDP listener instead of TCP
	var err error
	UDPConn, err = net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 8080,
	})
	if err != nil {
		panic(fmt.Sprintf("Could not create UDP listener: %v", err))
	}
	defer UDPConn.Close()

	fmt.Println("✅ Server ready - UDP listening on port 8080")

	// ✅ Run both goroutines
	go func() {
		err := ListenForPackets(UDPConn)
		if err != nil {
			fmt.Printf("❌ ListenForPackets error: %v\n", err)
		}
	}()

	go func() {
		err := ListenForResponse()
		if err != nil {
			fmt.Printf("❌ ListenForResponse error: %v\n", err)
		}
	}()

	fmt.Println("🚀 VPN Server running... Press Ctrl+C to stop")
	select {} // Block forever
}

func CreateRawSocket() int {
	fmt.Printf(" Trying to Creating Raw Socket ")
	Socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)

	if err != nil {
		fmt.Printf("Error creating Raw socket %v", err)
		return -1
	}

	// Enable IP_HDRINCL so we manage our own ip headers instead of kernel managing it
	err = syscall.SetsockoptInt(Socket, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		fmt.Printf("Error Enabling IP_HDRINCL %v", err)
		return -1
	}
	fmt.Printf("Raw socket created (fd: %d)\n", Socket)
	return Socket
}

func CreateTCPSocket() int {
	fmt.Printf(" Trying to Creating TCP Socket ")
	Socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		fmt.Printf("Error creating TCP socket %v", err)
		return -1
	}
	fmt.Printf("TCP socket created (fd: %d)\n", Socket)
	return Socket
}

func BindAndListenTCP(Socket int, Port uint16) error {
	addr := &syscall.SockaddrInet4{
		Port: int(Port),
		Addr: [4]byte{0, 0, 0, 0},
	}
	err := syscall.Bind(Socket, addr)
	if err != nil {
		return fmt.Errorf("bind failed: %v", err)
	}

	// Start listening for connections
	err = syscall.Listen(Socket, 128) // backlog of 128 connections
	if err != nil {
		return fmt.Errorf("listen failed: %v", err)
	}
	fmt.Printf("✅ TCP socket listening on port %d\n", Port)
	return nil
}

func ListenForConnection(Port string) (net.Conn, error) {
	listener, err := net.Listen("tcp", ":"+Port)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on port %s: %v", Port, err)
	}
	defer listener.Close()

	fmt.Printf("Listening for connections on port %s\n", Port)
	conn, err := listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("failed to accept connection: %v", err)
	}

	fmt.Printf("Connection accepted from %s\n", conn.RemoteAddr())
	return conn, nil
}
func ListenForPackets(conn *net.UDPConn) error {
	fmt.Printf("Listening for UDP packets from client\n")

	buffer := make([]byte, 65535) // Max UDP packet size

	for {
		// Read UDP packet
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Printf("❌ Error reading UDP packet: %v\n", err)
			continue
		}

		// Store client address for responses
		ClientAddr = addr

		if n > 0 {
			packet := buffer[:n]

			// Forward packet to internet
			err = ForwardPacketToInternet(packet)
			if err != nil {
				fmt.Printf("❌ Error forwarding packet: %v\n", err)
			}
		}
	}
}

// Forward packet to internet
func ForwardPacketToInternet(Packet []byte) error {
	if len(Packet) < 20 {
		return fmt.Errorf("packet too short for IP header")
	}

	// Extract destination IP from the packet
	destIP := net.IPv4(Packet[16], Packet[17], Packet[18], Packet[19])
	fmt.Printf("🌍 Forwarding packet to internet: %s\n", destIP)

	// // Modify source IP to VPN server's public IP (NAT)
	// Packet[12] = 172 // VPN server's IP
	// Packet[13] = 30
	// Packet[14] = 66
	// Packet[15] = 2

	// // Recalculate IP checksum after modifying source IP
	// Packet[10] = 0 // Clear existing checksum
	// Packet[11] = 0
	// checksum := calculateIPChecksum(Packet[:20])
	// Packet[10] = byte(checksum >> 8)
	// Packet[11] = byte(checksum & 0xFF)

	// Send packet to internet using raw socket
	return SendPacket(Socket, Packet, destIP.String())
}

// Send packet using raw socket
func SendPacket(socket int, packet []byte, destIP string) error {
	fmt.Printf("📤 Sending %d bytes to %s\n", len(packet), destIP)

	// Parse destination IP
	ip := net.ParseIP(destIP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", destIP)
	}
	ip = ip.To4()
	if ip == nil {
		return fmt.Errorf("not IPv4 address: %s", destIP)
	}

	// Create sockaddr for destination
	addr := &syscall.SockaddrInet4{
		Port: 0, // This Network layer socket so no port
		Addr: [4]byte{ip[0], ip[1], ip[2], ip[3]},
	}

	// Send packet using raw socket
	err := syscall.Sendto(socket, packet, 0, addr)
	if err != nil {
		return fmt.Errorf("sendto failed: %v", err)
	}

	fmt.Printf("✅ Packet sent successfully to %s (%d bytes)\n", destIP, len(packet))
	return nil
}

// Calculate IP header checksum
func calculateIPChecksum(header []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words in header
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(header[i])<<8 + uint32(header[i+1])
	}

	// Add odd byte if present
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}

	// Add carry bits
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// Return one's complement
	return uint16(^sum)
}

func ListenForResponse() error {
	fmt.Printf("Listening for Response\n")
	buffer := make([]byte, 4096)

	for {
		n, _, err := syscall.Recvfrom(CaptureSocket, buffer, 0)
		if err != nil {
			fmt.Printf("⚠️ Receive error: %v\n", err)
			continue
		}

		// ✅ FIX: AF_PACKET socket includes Ethernet header (14 bytes)
		// Ethernet header: [6 bytes dest MAC][6 bytes src MAC][2 bytes EtherType]
		if n < 34 { // 14 (Ethernet) + 20 (IP header minimum)
			continue
		}

		// Skip Ethernet header (14 bytes) to get to IP packet
		packet := buffer[14:n]

		if len(packet) < 20 {
			continue // Skip packets too short for IP header
		}

		// Extract destination IP (bytes 16-19 of IP header)
		destIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])
		// Extract source IP (bytes 12-15 of IP header)
		sourceIP := net.IPv4(packet[12], packet[13], packet[14], packet[15])

		fmt.Printf("📦 Captured packet - Source: %s -> Dest: %s\n", sourceIP.String(), destIP.String())

		// Skip packet if source IP is from client (avoid loops)
		if sourceIP.String() == "172.25.0.3" {
			fmt.Printf("⏩ Skipping packet from client\n")
			continue
		}

		// Check if this packet is meant for our VPN server (responses to forwarded packets)
		if destIP.String() == "172.25.0.2" {
			fmt.Printf("📥 Received response packet for client: %s -> %s\n", sourceIP, destIP)

			// Modify destination IP back to client's virtual IP
			packet[16] = 10 // Client's virtual IP: 10.8.0.2
			packet[17] = 8
			packet[18] = 0
			packet[19] = 2

			// Recalculate IP checksum
			packet[10] = 0
			packet[11] = 0
			checksum := calculateIPChecksum(packet[:20])
			packet[10] = byte(checksum >> 8)
			packet[11] = byte(checksum & 0xFF)

			// Send via UDP
			err = SendPacketToClient(packet)
			if err != nil {
				fmt.Printf("❌ Error sending packet to client: %v\n", err)
			}
		}
	}
}

func SendPacketToClient(packet []byte) error {
	if ClientAddr == nil {
		return fmt.Errorf("no client address available")
	}

	// ✅ UDP: Send packet directly (no length prefix needed)
	_, err := UDPConn.WriteToUDP(packet, ClientAddr)
	if err != nil {
		return fmt.Errorf("failed to send UDP packet: %v", err)
	}

	fmt.Printf("✅ Sent packet to client (%d bytes)\n", len(packet))
	return nil
}

func CreateCaptureSocket() int {
	fmt.Printf(" Trying to Creating Capture Raw Socket ")
	captureSocket, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))

	if err != nil {
		fmt.Printf("Error creating Raw socket %v", err)
		return -1
	}

	fmt.Printf("Capture socket created (fd: %d)\n", Socket)
	return captureSocket
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

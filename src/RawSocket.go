//go:build linux
// +build linux

package src

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

// RawSocket handles raw IP packet transmission/reception for Linux
type RawSocket struct {
	sendSocket    int
	captureSocket int
	closed        bool
}

// NewRawSocket creates a new raw socket for Linux
func NewRawSocket() (*RawSocket, error) {
	// Create raw socket for sending (IPPROTO_RAW)
	sendSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("failed to create send socket: %w (requires root)", err)
	}

	// Enable IP_HDRINCL so we manage our own IP headers
	err = syscall.SetsockoptInt(sendSocket, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		syscall.Close(sendSocket)
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %w", err)
	}

	// Create capture socket for receiving (AF_PACKET)
	captureSocket, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		syscall.Close(sendSocket)
		return nil, fmt.Errorf("failed to create capture socket: %w", err)
	}

	fmt.Printf("✅ Raw sockets created - Send: %d, Capture: %d\n", sendSocket, captureSocket)

	return &RawSocket{
		sendSocket:    sendSocket,
		captureSocket: captureSocket,
		closed:        false,
	}, nil
}

// SendPacket sends a raw IP packet (destination IP already in packet header)
func (rs *RawSocket) SendPacket(packet []byte) error {
	if rs.closed {
		return fmt.Errorf("socket is closed")
	}

	if len(packet) < 20 {
		return fmt.Errorf("packet too small: %d bytes", len(packet))
	}

	// Extract destination IP from packet header (bytes 16-19)
	destIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])

	// Create sockaddr structure
	addr := &syscall.SockaddrInet4{
		Port: 0, // Network layer socket, no port
		Addr: [4]byte{packet[16], packet[17], packet[18], packet[19]},
	}

	// Send packet
	err := syscall.Sendto(rs.sendSocket, packet, 0, addr)
	if err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	fmt.Printf("📤 Sent packet to %s (%d bytes)\n", destIP.String(), len(packet))
	return nil
}

// ReceivePacket receives a raw IP packet from the capture socket
func (rs *RawSocket) ReceivePacket(buffer []byte) (int, net.IP, error) {
	if rs.closed {
		return 0, nil, fmt.Errorf("socket is closed")
	}

	// Receive packet (includes Ethernet header)
	n, _, err := syscall.Recvfrom(rs.captureSocket, buffer, 0)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to receive packet: %w", err)
	}

	// AF_PACKET socket includes Ethernet header (14 bytes)
	if n < 34 { // 14 (Ethernet) + 20 (IP header minimum)
		return 0, nil, fmt.Errorf("packet too short: %d bytes", n)
	}

	// Skip Ethernet header to get IP packet
	ipPacket := buffer[14:n]

	if len(ipPacket) < 20 {
		return 0, nil, fmt.Errorf("IP packet too short")
	}

	// Extract source IP (bytes 12-15 of IP header)
	srcIP := net.IPv4(ipPacket[12], ipPacket[13], ipPacket[14], ipPacket[15])

	// Copy IP packet to start of buffer (remove Ethernet header)
	copy(buffer, ipPacket)

	return len(ipPacket), srcIP, nil
}

// Close closes the raw sockets
func (rs *RawSocket) Close() error {
	if rs.closed {
		return nil
	}
	rs.closed = true

	err1 := syscall.Close(rs.sendSocket)
	err2 := syscall.Close(rs.captureSocket)

	if err1 != nil {
		return err1
	}
	return err2
}

// htons converts host byte order to network byte order
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// ParseIPHeader parses IP header from packet
func ParseIPHeader(packet []byte) *IPHeader {
	if len(packet) < 20 {
		return nil
	}

	header := &IPHeader{
		Version:  packet[0] >> 4,
		IHL:      packet[0] & 0x0F,
		TOS:      packet[1],
		Length:   binary.BigEndian.Uint16(packet[2:4]),
		ID:       binary.BigEndian.Uint16(packet[4:6]),
		Flags:    packet[6] >> 5,
		FragOff:  binary.BigEndian.Uint16(packet[6:8]) & 0x1FFF,
		TTL:      packet[8],
		Protocol: packet[9],
		Checksum: binary.BigEndian.Uint16(packet[10:12]),
		SrcIP:    net.IPv4(packet[12], packet[13], packet[14], packet[15]),
		DstIP:    net.IPv4(packet[16], packet[17], packet[18], packet[19]),
	}

	return header
}

// IPHeader represents an IPv4 header
type IPHeader struct {
	Version  uint8
	IHL      uint8
	TOS      uint8
	Length   uint16
	ID       uint16
	Flags    uint8
	FragOff  uint16
	TTL      uint8
	Protocol uint8
	Checksum uint16
	SrcIP    net.IP
	DstIP    net.IP
}

// CalculateIPChecksum calculates IP header checksum
func CalculateIPChecksum(header []byte) uint16 {
	sum := uint32(0)

	// Sum all 16-bit words
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

// CalculateTCPChecksum calculates TCP/UDP checksum with pseudo-header
func CalculateTCPChecksum(packet []byte, srcIP, dstIP net.IP) uint16 {
	// Get protocol and length
	protocol := packet[9]
	ipHeaderLen := int((packet[0] & 0x0F) * 4)
	totalLen := binary.BigEndian.Uint16(packet[2:4])
	tcpLen := totalLen - uint16(ipHeaderLen)

	// Build pseudo-header
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], tcpLen)

	// Combine pseudo-header + TCP/UDP segment
	data := append(pseudoHeader, packet[ipHeaderLen:]...)

	sum := uint32(0)
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 + uint32(data[i+1])
	}

	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return uint16(^sum)
}

// RawSocketManager handles routing between VPN clients and raw socket
type RawSocketManager struct {
	socket   *RawSocket
	serverIP net.IP
	portMap  map[int]*net.UDPAddr // NAT port -> client address
}

// NewRawSocketManager creates a new raw socket manager
func NewRawSocketManager(serverIP string) (*RawSocketManager, error) {
	socket, err := NewRawSocket()
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(serverIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid server IP: %s", serverIP)
	}

	return &RawSocketManager{
		socket:   socket,
		serverIP: ip.To4(),
		portMap:  make(map[int]*net.UDPAddr),
	}, nil
}

// Start starts the raw socket receiver loop
func (rsm *RawSocketManager) Start() {
	go rsm.receiveLoop()
}

// receiveLoop receives packets from internet and routes to VPN clients
func (rsm *RawSocketManager) receiveLoop() {
	buffer := make([]byte, 65535)

	fmt.Println(" Listening for response packets from internet...")

	for {
		n, srcIP, err := rsm.socket.ReceivePacket(buffer)
		_ = srcIP
		if err != nil {
			continue
		}

		packet := buffer[:n]

		// Parse IP header
		ipHeader := ParseIPHeader(packet)
		if ipHeader == nil {
			continue
		}

		// Check if this is a response to our VPN server
		if ipHeader.DstIP.Equal(rsm.serverIP) {
			fmt.Printf("📥 Response packet: %s -> %s (%d bytes)\n",
				ipHeader.SrcIP.String(), ipHeader.DstIP.String(), n)

			// Route packet back to client based on destination port
			rsm.routeToClient(packet)
		}
	}
}

// routeToClient routes response packet back to VPN client
func (rsm *RawSocketManager) routeToClient(packet []byte) {
	ipHeader := ParseIPHeader(packet)
	if ipHeader == nil {
		return
	}

	// Get IP header length
	ipHeaderLen := int((packet[0] & 0x0F) * 4)

	// Extract destination port based on protocol
	var destPort int
	if ipHeader.Protocol == 6 || ipHeader.Protocol == 17 { // TCP or UDP
		if len(packet) >= ipHeaderLen+4 {
			destPort = int(binary.BigEndian.Uint16(packet[ipHeaderLen+2 : ipHeaderLen+4]))
		}
	}

	// Lookup client by NAT port
	clientAddr, exists := rsm.portMap[destPort]
	_ = clientAddr
	if !exists {
		fmt.Printf("No client found for port %d\n", destPort)
		return
	}

	// Send packet back to client via VPN
	//sendDataPacket(clientAddr, packet)
}

// ForwardFromClient forwards packet from VPN client to internet with NAT
func (rsm *RawSocketManager) ForwardFromClient(packet []byte, natPort int) error {
	// Parse IP header
	ipHeader := ParseIPHeader(packet)
	if ipHeader == nil {
		return fmt.Errorf("invalid IP packet")
	}

	// Modify source IP to server's public IP (NAT)
	packet[12] = rsm.serverIP[0]
	packet[13] = rsm.serverIP[1]
	packet[14] = rsm.serverIP[2]
	packet[15] = rsm.serverIP[3]

	// Get IP header length
	ipHeaderLen := int((packet[0] & 0x0F) * 4)

	// Update source port to NAT port based on protocol
	if ipHeader.Protocol == 6 || ipHeader.Protocol == 17 { // TCP or UDP
		if len(packet) >= ipHeaderLen+4 {
			// Update source port
			binary.BigEndian.PutUint16(packet[ipHeaderLen:ipHeaderLen+2], uint16(natPort))

			// Recalculate TCP/UDP checksum
			packet[ipHeaderLen+16] = 0 // Clear checksum
			packet[ipHeaderLen+17] = 0
			checksum := CalculateTCPChecksum(packet, rsm.serverIP, ipHeader.DstIP)
			binary.BigEndian.PutUint16(packet[ipHeaderLen+16:ipHeaderLen+18], checksum)
		}
	}

	// Recalculate IP checksum
	packet[10] = 0
	packet[11] = 0
	checksum := CalculateIPChecksum(packet[:ipHeaderLen])
	binary.BigEndian.PutUint16(packet[10:12], checksum)

	fmt.Printf("🌍 Forwarding: %s:%d -> %s (NAT Port: %d)\n",
		rsm.serverIP.String(), natPort, ipHeader.DstIP.String(), natPort)

	// Send via raw socket
	return rsm.socket.SendPacket(packet)
}

// Close closes the raw socket manager
func (rsm *RawSocketManager) Close() error {
	return rsm.socket.Close()
}

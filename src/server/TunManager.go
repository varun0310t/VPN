//go:build linux
// +build linux

package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	TUNSETIFF = 0x400454ca
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
)

type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

// TunInterface handles TUN interface for packet routing
type TunInterface struct {
	fd     int
	name   string
	closed bool
}

// NewTunInterface creates a new TUN interface
func NewTunInterface(name string) (*TunInterface, error) {
	fd, err := syscall.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w (requires root)", err)
	}

	var ifr ifreq
	copy(ifr.name[:], name)
	ifr.flags = IFF_TUN | IFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %v", errno)
	}

	fmt.Printf("✅ TUN interface %s created (fd: %d)\n", name, fd)

	return &TunInterface{
		fd:     fd,
		name:   name,
		closed: false,
	}, nil
}

// Configure sets up the TUN interface with IP and routes
func (tun *TunInterface) Configure(ipAddr string, subnet string) error {
	fmt.Printf("Configuring TUN interface %s...\n", tun.name)

	// Flush any existing IP addresses first
	cmd := exec.Command("ip", "addr", "flush", "dev", tun.name)
	_ = cmd.Run() // Ignore errors if no IPs exist

	// Set IP address
	cmd = exec.Command("ip", "addr", "add", ipAddr+"/24", "dev", tun.name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP: %w", err)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", tun.name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	fmt.Printf(" TUN interface configured with IP %s/24\n", ipAddr)
	return nil
}

// SetupNATAndForwarding configures NAT masquerading and IP forwarding
func (tun *TunInterface) SetupNATAndForwarding(subnet string, outInterface string) error {
	fmt.Println("Setting up NAT and packet forwarding...")

	// Enable IP forwarding
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Setup NAT masquerading
	cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", outInterface, "-j", "MASQUERADE")
	if err := cmd.Run(); err != nil {
		fmt.Printf("⚠️ Warning: iptables NAT rule may already exist: %v\n", err)
	}

	// Allow forwarding
	cmd = exec.Command("iptables", "-A", "FORWARD", "-i", tun.name, "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		fmt.Printf("⚠️ Warning: iptables forward rule may already exist: %v\n", err)
	}

	cmd = exec.Command("iptables", "-A", "FORWARD", "-o", tun.name, "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		fmt.Printf("⚠️ Warning: iptables forward rule may already exist: %v\n", err)
	}

	fmt.Println("✅ NAT and forwarding configured")
	return nil
}

// WritePacket writes an IP packet to the TUN interface
func (tun *TunInterface) WritePacket(packet []byte) error {
	if tun.closed {
		return fmt.Errorf("TUN interface is closed")
	}

	if len(packet) < 20 {
		return fmt.Errorf("packet too small: %d bytes", len(packet))
	}

	n, err := syscall.Write(tun.fd, packet)
	if err != nil {
		return fmt.Errorf("failed to write to TUN: %w", err)
	}

	fmt.Printf("✅ Wrote %d bytes to TUN interface\n", n)
	return nil
}

// ReadPacket reads an IP packet from the TUN interface
func (tun *TunInterface) ReadPacket(buffer []byte) (int, error) {
	if tun.closed {
		return 0, fmt.Errorf("TUN interface is closed")
	}

	n, err := syscall.Read(tun.fd, buffer)
	if err != nil {
		return 0, fmt.Errorf("failed to read from TUN: %w", err)
	}

	return n, nil
}

// Close closes the TUN interface
func (tun *TunInterface) Close() error {
	if tun.closed {
		return nil
	}
	tun.closed = true

	return syscall.Close(tun.fd)
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

// TunManager handles routing between VPN clients and TUN interface
type TunManager struct {
	tun *TunInterface
}

// NewTunManager creates a new TUN manager
func NewTunManager(tunName string, serverIP string, subnet string, outInterface string) (*TunManager, error) {
	tun, err := NewTunInterface(tunName)
	if err != nil {
		return nil, err
	}

	// Configure TUN interface
	err = tun.Configure(serverIP, subnet)
	if err != nil {
		tun.Close()
		return nil, err
	}

	// Setup NAT and forwarding
	err = tun.SetupNATAndForwarding(subnet, outInterface)
	if err != nil {
		tun.Close()
		return nil, err
	}

	return &TunManager{
		tun: tun,
	}, nil
}

// Start starts the TUN receiver loop
func (tm *TunManager) Start() {
	go tm.receiveLoop()
}

// receiveLoop receives packets from TUN and routes to VPN clients
func (tm *TunManager) receiveLoop() {
	buffer := make([]byte, 65535)

	fmt.Println("📡 Listening for packets from TUN interface...")

	for {
		n, err := tm.tun.ReadPacket(buffer)
		if err != nil {
			continue
		}

		packet := buffer[:n]

		// Parse IP header
		ipHeader := ParseIPHeader(packet)
		if ipHeader == nil {
			continue
		}

		fmt.Printf("📥 TUN packet: %s -> %s (%d bytes)\n",
			ipHeader.SrcIP.String(), ipHeader.DstIP.String(), n)

		// Route packet back to client
		tm.routeToClient(packet)
	}
}

// routeToClient routes packet back to VPN client based on destination IP
func (tm *TunManager) routeToClient(packet []byte) {
	ipHeader := ParseIPHeader(packet)
	if ipHeader == nil {
		return
	}

	// Extract destination IP last octet (10.8.0.X -> X)
	destIPOctet := int(ipHeader.DstIP.To4()[3])

	// Lookup client by IP using ClientManager
	session, exists := ClientManager.GetClientByIP(destIPOctet)
	if !exists {
		fmt.Printf("No client found for IP 10.8.0.%d\n", destIPOctet)
		return
	}

	// Send packet back to client via UDP
	_, err := udpConn.WriteToUDP(packet, session.Addr)
	if err != nil {
		fmt.Printf("❌ Error sending to client: %v\n", err)
	} else {
		fmt.Printf("✅ Sent %d bytes to client %s\n", len(packet), session.Addr.String())
	}
}

// ForwardFromClient forwards packet from VPN client to TUN interface
func (tm *TunManager) ForwardFromClient(packet []byte, assignedIP int) error {
	// Parse IP header
	ipHeader := ParseIPHeader(packet)
	if ipHeader == nil {
		return fmt.Errorf("invalid IP packet")
	}

	// **SWAP SOURCE IP**: Replace client's source IP with their assigned VPN IP
	vpnIP := net.IPv4(10, 8, 0, byte(assignedIP))

	// Modify source IP in packet
	packet[12] = vpnIP[0]
	packet[13] = vpnIP[1]
	packet[14] = vpnIP[2]
	packet[15] = vpnIP[3]

	// Recalculate IP checksum
	packet[10] = 0 // Clear old checksum
	packet[11] = 0
	checksum := CalculateIPChecksum(packet[:20])
	packet[10] = byte(checksum >> 8)
	packet[11] = byte(checksum)

	// Recalculate TCP/UDP checksum if needed
	protocol := packet[9]
	if protocol == 6 || protocol == 17 { // TCP or UDP
		ipHeaderLen := int((packet[0] & 0x0F) * 4)
		// Clear transport layer checksum
		if protocol == 6 { // TCP
			packet[ipHeaderLen+16] = 0
			packet[ipHeaderLen+17] = 0
		} else { // UDP
			packet[ipHeaderLen+6] = 0
			packet[ipHeaderLen+7] = 0
		}

		tcpChecksum := CalculateTCPChecksum(packet, vpnIP, ipHeader.DstIP)
		if protocol == 6 {
			packet[ipHeaderLen+16] = byte(tcpChecksum >> 8)
			packet[ipHeaderLen+17] = byte(tcpChecksum)
		} else {
			packet[ipHeaderLen+6] = byte(tcpChecksum >> 8)
			packet[ipHeaderLen+7] = byte(tcpChecksum)
		}
	}

	fmt.Printf("🌍 Forwarding from client: 10.8.0.%d -> %s\n",
		assignedIP, ipHeader.DstIP.String())

	// Write to TUN - kernel handles NAT and routing
	return tm.tun.WritePacket(packet)
}

// Close closes the TUN manager
func (tm *TunManager) Close() error {
	return tm.tun.Close()
}

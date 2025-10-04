//go:build linux
// +build linux

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	VPN_SERVER_HOST = "192.168.1.15"
	VPN_SERVER_PORT = "8080"
	TUN_INTERFACE   = "tun0"
	VPN_CLIENT_IP   = "10.8.0.2"
)

const (
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
	TUNSETIFF = 0x400454ca
)

type TunInterface struct {
	fd   int
	name string
}

func main() {
	fmt.Println("🚀 Starting Linux VPN client...")

	// ✅ CLEAR ALL LOGS FIRST
	clearAllLogs()

	// Check if running as root
	if os.Geteuid() != 0 {
		fmt.Println("❌ This program must be run as root (sudo)")
		os.Exit(1)
	}

	// Create TUN interface
	tunIface, err := createTunInterface(TUN_INTERFACE)
	if err != nil {
		fmt.Printf("❌ Failed to create TUN interface: %v\n", err)
		return
	}
	defer tunIface.Close()

	// Configure TUN interface
	err = configureTunInterface(TUN_INTERFACE, VPN_CLIENT_IP)
	if err != nil {
		fmt.Printf("❌ Failed to configure TUN interface: %v\n", err)
		return
	}

	// Set up signal handling
	signChan := make(chan os.Signal, 1)
	signal.Notify(signChan, syscall.SIGINT, syscall.SIGTERM)

	defer func() {
		fmt.Println("\n🧹 Cleaning up...")
		restoreOriginalRoutes()
		tunIface.Close()
		fmt.Println("✅ Cleanup complete - internet should work now")
	}()

	// Set default route through VPN
	err = setDefaultRoute()
	if err != nil {
		fmt.Printf("❌ Failed to set default route: %v\n", err)
		return
	}

	// Connect to VPN server
	fmt.Printf("🔗 Connecting to VPN server at %s:%s...\n", VPN_SERVER_HOST, VPN_SERVER_PORT)
	serverConn, err := connectToVPNServer()
	if err != nil {
		fmt.Printf("❌ Failed to connect to the server: %v\n", err)
		return
	}
	defer serverConn.Close()
	fmt.Println("✅ Connected to VPN server successfully!")

	// Start response reader
	go readResponsesFromServer(serverConn, tunIface)

	// Main packet forwarding loop
	buffer := make([]byte, 1500)
	count := 0

	fmt.Println("🔄 VPN active - forwarding packets...")

	for {
		select {
		case <-signChan:
			fmt.Printf("\n📊 Processed %d packets. Shutting down...\n", count)
			return

		default:
			// Read packet from TUN interface
			n, err := tunIface.Read(buffer)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
					time.Sleep(1 * time.Millisecond)
					continue
				}
				fmt.Printf("❌ Error reading from TUN: %v\n", err)
				continue
			}

			if n > 0 {
				count++
				packet := buffer[:n]

				// ✅ LOG SENT PACKET BEFORE FORWARDING
				logSentPacketToFile(packet, count)

				// Analyze the packet
				if len(packet) >= 20 { // Minimum IP header
					version := packet[0] >> 4
					if version == 4 {
						// Extract destination IP and protocol
						destIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])
						protocol := packet[9]

						protocolName := getProtocolName(protocol)

						// Show progress occasionally
						if count%100 == 0 {
							fmt.Printf("📤 Forwarded %d packets (latest: %s to %s)\n",
								count, protocolName, destIP)
						}

						// ✅ ENHANCED LOGGING FOR SPECIFIC IPs
						if destIP.String() == "142.250.76.174" || destIP.String() == "8.8.8.8" || destIP.String() == "8.8.4.4" {
							fmt.Printf("🎯 SENT PACKET #%d: %s to %s | Protocol: %s\n",
								count,
								net.IPv4(packet[12], packet[13], packet[14], packet[15]), // source IP
								destIP,
								protocolName)
						}

						// Forward packet to server
						err = forwardPacketToServer(serverConn, packet)
						if err != nil {
							fmt.Printf("❌ Failed to forward packet %d: %v\n", count, err)
							continue
						}
					}
				}
			}
		}
	}
}

func createTunInterface(name string) (*TunInterface, error) {
	fmt.Printf("🔧 Creating TUN interface: %s\n", name)

	// Open /dev/net/tun
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	// Prepare interface request structure
	type ifreq struct {
		name  [16]byte
		flags uint16
		_     [22]byte // padding
	}

	var ifr ifreq
	copy(ifr.name[:], name)
	ifr.flags = IFF_TUN | IFF_NO_PI

	// Create TUN interface
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		TUNSETIFF,
		uintptr(unsafe.Pointer(&ifr)),
	)

	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF ioctl failed: %v", errno)
	}

	fmt.Printf("✅ TUN interface %s created successfully (fd: %d)\n", name, fd)

	return &TunInterface{
		fd:   fd,
		name: name,
	}, nil
}

func configureTunInterface(name, ip string) error {
	fmt.Printf("⚙️  Configuring TUN interface %s with IP %s\n", name, ip)

	commands := [][]string{
		{"ip", "addr", "add", ip + "/24", "dev", name},
		{"ip", "link", "set", name, "up"},

		// ✅ FIX: REPLACE resolv.conf, don't append
		{"sh", "-c", "echo 'nameserver 8.8.8.8' > /etc/resolv.conf"},
		{"sh", "-c", "echo 'nameserver 8.8.4.4' >> /etc/resolv.conf"},
		{"sh", "-c", "echo 'nameserver 1.1.1.1' >> /etc/resolv.conf"},
	}

	for _, cmd := range commands {
		if err := runCommand(cmd...); err != nil {
			return fmt.Errorf("failed to run %v: %v", cmd, err)
		}
	}

	fmt.Printf("✅ TUN interface %s configured successfully\n", name)
	return nil
}

func setDefaultRoute() error {
	fmt.Println("🛣️  Setting default route through VPN...")

	// Save current default route
	err := runCommand("ip", "route", "save", "table", "main", ">", "/tmp/vpn_backup_routes")
	if err != nil {
		fmt.Printf("⚠️  Warning: Could not backup routes: %v\n", err)
	}

	// Add route for VPN server via current default gateway
	err = runCommand("ip", "route", "add", VPN_SERVER_HOST, "via", getDefaultGateway())
	if err != nil {
		fmt.Printf("⚠️  Warning: Could not add server route: %v\n", err)
	}

	// Set new default route through TUN
	err = runCommand("ip", "route", "replace", "default", "dev", TUN_INTERFACE)
	if err != nil {
		return fmt.Errorf("failed to set default route: %v", err)
	}

	fmt.Println("✅ Default route set through VPN")
	return nil
}

func restoreOriginalRoutes() error {
	fmt.Println("🔄 Restoring original routes...")

	// Remove VPN default route
	runCommand("ip", "route", "del", "default", "dev", TUN_INTERFACE)

	// Remove server-specific route
	runCommand("ip", "route", "del", VPN_SERVER_HOST)

	// Restore original routes (simplified)
	gateway := getDefaultGateway()
	if gateway != "" {
		runCommand("ip", "route", "add", "default", "via", gateway)
	} else {
		runCommand("ip", "route", "add", "default", "via", "172.30.64.1", "dev", "eth0")
	}

	return nil
}

func getDefaultGateway() string {
	// Simple implementation - get first default gateway
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "172.30.64.1 " // fallback
	}

	fields := string(output)
	if len(fields) > 12 {
		// Extract IP after "via "
		start := 12 // length of "default via "
		end := start
		for end < len(fields) && fields[end] != ' ' {
			end++
		}
		if end > start {
			return fields[start:end]
		}
	}
	return "172.30.64.1 " // fallback
}

func (tun *TunInterface) Read(buffer []byte) (int, error) {
	return syscall.Read(tun.fd, buffer)
}

func (tun *TunInterface) Write(packet []byte) (int, error) {
	return syscall.Write(tun.fd, packet)
}

func (tun *TunInterface) Close() error {
	if tun.fd != -1 {
		err := syscall.Close(tun.fd)
		tun.fd = -1
		return err
	}
	return nil
}

func connectToVPNServer() (net.Conn, error) {
	serverAddr := VPN_SERVER_HOST + ":" + VPN_SERVER_PORT
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", serverAddr, err)
	}
	return conn, nil
}

func forwardPacketToServer(conn net.Conn, packet []byte) error {
	packetLen := len(packet)
	lengthBytes := []byte{
		byte(packetLen >> 24),
		byte(packetLen >> 16),
		byte(packetLen >> 8),
		byte(packetLen),
	}

	// Send length prefix
	_, err := conn.Write(lengthBytes)
	if err != nil {
		return fmt.Errorf("failed to send packet length: %v", err)
	}

	// Send actual packet
	_, err = conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to send packet data: %v", err)
	}

	return nil
}

func readResponsesFromServer(serverConn net.Conn, tunIface *TunInterface) {
	fmt.Println("📥 Starting response reader...")
	responseCount := 0

	for {
		// Read length prefix
		lengthBytes := make([]byte, 4)
		serverConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err := io.ReadFull(serverConn, lengthBytes)
		if err != nil {
			if err == io.EOF {
				fmt.Println("📡 Server disconnected")
			} else {
				fmt.Printf("❌ Error reading response length: %v\n", err)
			}
			break
		}

		// Parse length
		responseLen := int(lengthBytes[0])<<24 | int(lengthBytes[1])<<16 |
			int(lengthBytes[2])<<8 | int(lengthBytes[3])

		// Read packet data
		responsePacket := make([]byte, responseLen)
		_, err = io.ReadFull(serverConn, responsePacket)
		if err != nil {
			fmt.Printf("❌ Error reading response packet: %v\n", err)
			break
		}
		// Rewrite destination IP to actual eth0 IP and recalculate checksum
		if len(responsePacket) >= 20 {

			// Parse eth0 IP
			eth0IPBytes := net.ParseIP("10.8.0.2").To4()
			if eth0IPBytes == nil {
				fmt.Printf("❌ Invalid eth0 IP format: %s\n", " 10.8.0.2")
				continue
			}

			// Rewrite destination IP (bytes 16-19)
			copy(responsePacket[16:20], eth0IPBytes)

			// Recalculate IP header checksum
			// Clear existing checksum
			responsePacket[10] = 0
			responsePacket[11] = 0

			// ✅ FIRST: Recalculate UDP/TCP checksum (if needed) with ENTIRE packet
			protocol := responsePacket[9]
			if protocol == 6 { // TCP
				err := recalculateTCPChecksum(responsePacket)
				if err != nil {
					fmt.Printf("❌ TCP checksum error: %v\n", err)
					continue
				}
			} else if protocol == 17 { // UDP (DNS uses this!)
				err := recalculateUDPChecksum(responsePacket)
				if err != nil {
					fmt.Printf("❌ UDP checksum error: %v\n", err)
					continue
				}
			}

			// ✅ THEN: Calculate IP checksum (only IP header)
			checksum := calculateIPChecksum(responsePacket[:20])
			responsePacket[10] = byte(checksum >> 8)
			responsePacket[11] = byte(checksum & 0xFF)

			// Log packet to file for validation

			logPacketToFile(responsePacket, responseCount, "response")
			// Write response back to TUN interface
			_, err = tunIface.Write(responsePacket)
			if err != nil {
				fmt.Printf("❌ Error writing response to TUN: %v\n", err)
				continue
			}

			responseCount++
			if responseCount%25 == 0 {
				fmt.Printf("📨 Received %d responses from server\n", responseCount)
			}

			// Debug: Log first few responses

			sourceIP := net.IPv4(responsePacket[12], responsePacket[13], responsePacket[14], responsePacket[15])
			destIP := net.IPv4(responsePacket[16], responsePacket[17], responsePacket[18], responsePacket[19])
			protocol = responsePacket[9]
			protocolName := getProtocolName(protocol)

			fmt.Printf("📩 Response #%d: %s → %s (%s, %d bytes)\n",
				responseCount, sourceIP, destIP, protocolName, len(responsePacket))

		}
	}
}

func getProtocolName(protocol byte) string {
	switch protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("Proto-%d", protocol)
	}
}

func runCommand(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

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

func logPacketToFile(packet []byte, count int, packetType string) {
	// Create logs directory if it doesn't exist
	if err := os.MkdirAll("logs", 0755); err != nil {
		fmt.Printf("⚠️  Warning: Could not create logs directory: %v\n", err)
		return
	}

	// Open log file (append mode)
	filename := fmt.Sprintf("logs/packets_%s.log", time.Now().Format("2006-01-02"))
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("⚠️  Warning: Could not open log file: %v\n", err)
		return
	}
	defer file.Close()

	// Parse packet information
	timestamp := time.Now().Format("15:04:05.000")

	// Write log entry header
	logEntry := fmt.Sprintf("\n[%s] %s #%d:s\n",
		timestamp, packetType, count)

	if _, err := file.WriteString(logEntry); err != nil {
		fmt.Printf("⚠️  Warning: Could not write to log file: %v\n", err)
		return
	}

	// ✅ LOG ENTIRE PACKET - Complete hex dump
	hexDump := createFullHexDump(packet, count, packetType)
	file.WriteString(hexDump)

	// ✅ Also log as raw hex string for easy copy/paste
	rawHex := createRawHexString(packet)
	file.WriteString(fmt.Sprintf("Raw Hex: %s\n", rawHex))

	// Add separator
	file.WriteString("=" + strings.Repeat("=", 80) + "\n")
}

func createFullHexDump(packet []byte, count int, packetType string) string {
	var result strings.Builder

	result.WriteString(fmt.Sprintf("--- Complete Hex Dump for %s #%d (%d bytes) ---\n",
		packetType, count, len(packet)))

	// ✅ NO LIMIT - dump entire packet
	for i := 0; i < len(packet); i += 16 {
		// Offset
		result.WriteString(fmt.Sprintf("%04x: ", i))

		// Hex bytes
		for j := 0; j < 16; j++ {
			if i+j < len(packet) {
				result.WriteString(fmt.Sprintf("%02x ", packet[i+j]))
			} else {
				result.WriteString("   ")
			}

			// Add extra space in the middle
			if j == 7 {
				result.WriteString(" ")
			}
		}

		// ASCII representation
		result.WriteString(" |")
		for j := 0; j < 16 && i+j < len(packet); j++ {
			b := packet[i+j]
			if b >= 32 && b <= 126 {
				result.WriteString(string(b))
			} else {
				result.WriteString(".")
			}
		}
		result.WriteString("|\n")
	}

	return result.String()
}

func createRawHexString(packet []byte) string {
	var result strings.Builder

	for i, b := range packet {
		result.WriteString(fmt.Sprintf("%02x", b))
		// Add space every 16 bytes for readability
		if (i+1)%16 == 0 && i+1 < len(packet) {
			result.WriteString(" ")
		}
	}

	return result.String()
}

func logSentPacketToFile(packet []byte, count int) {
	// Create sent_logs directory if it doesn't exist
	if err := os.MkdirAll("sent_logs", 0755); err != nil {
		fmt.Printf("⚠️  Warning: Could not create sent_logs directory: %v\n", err)
		return
	}

	// Open log file (append mode) in sent_logs directory
	filename := fmt.Sprintf("sent_logs/sent_packets_%s.log", time.Now().Format("2006-01-02"))
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("⚠️  Warning: Could not open sent log file: %v\n", err)
		return
	}
	defer file.Close()

	// Parse packet information
	timestamp := time.Now().Format("15:04:05.000")

	// Write log entry header
	logEntry := fmt.Sprintf("\n[%s] sent #%d\n",
		timestamp, count)

	if _, err := file.WriteString(logEntry); err != nil {
		fmt.Printf("⚠️  Warning: Could not write to sent log file: %v\n", err)
		return
	}

	// ✅ LOG ENTIRE SENT PACKET - Complete hex dump
	hexDump := createFullHexDump(packet, count, "sent")
	file.WriteString(hexDump)

	// ✅ Also log as raw hex string for easy copy/paste
	rawHex := createRawHexString(packet)
	file.WriteString(fmt.Sprintf("Raw Hex: %s\n", rawHex))

	// Add separator
	file.WriteString("=" + strings.Repeat("=", 80) + "\n")
}

// Add this function to your main.go file

func clearAllLogs() {
	fmt.Println("🧹 Clearing previous logs...")

	// List of log directories to clear
	logDirs := []string{
		"logs",
		"sent_logs",
		"received_logs",
	}

	for _, dir := range logDirs {
		// Check if directory exists
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue // Directory doesn't exist, skip
		}

		// Read directory contents
		files, err := os.ReadDir(dir)
		if err != nil {
			fmt.Printf("⚠️  Warning: Could not read %s directory: %v\n", dir, err)
			continue
		}

		// Delete all files in the directory
		deletedCount := 0
		for _, file := range files {
			if !file.IsDir() { // Only delete files, not subdirectories
				filePath := fmt.Sprintf("%s/%s", dir, file.Name())
				err := os.Remove(filePath)
				if err != nil {
					fmt.Printf("⚠️  Warning: Could not delete %s: %v\n", filePath, err)
				} else {
					deletedCount++
				}
			}
		}

		if deletedCount > 0 {
			fmt.Printf("🗑️  Deleted %d log files from %s/\n", deletedCount, dir)
		}
	}

	fmt.Println("✅ Log cleanup complete - starting fresh!")
}

// Add this function to recalculate TCP checksum
func recalculateTCPChecksum(packet []byte) error {
	if len(packet) < 40 { // IP header (20) + TCP header (20)
		return fmt.Errorf("packet too short for TCP")
	}

	protocol := packet[9]
	if protocol != 6 { // Not TCP
		return nil
	}

	// Extract IPs
	srcIP := packet[12:16]
	destIP := packet[16:20]

	// Get TCP header start
	ipHeaderLen := int(packet[0]&0x0F) * 4
	tcpHeader := packet[ipHeaderLen:]

	if len(tcpHeader) < 20 {
		return fmt.Errorf("TCP header too short")
	}

	// Clear existing TCP checksum
	tcpHeader[16] = 0
	tcpHeader[17] = 0

	// Calculate TCP checksum with pseudo-header
	checksum := calculateTCPChecksum(srcIP, destIP, tcpHeader)

	// Set new checksum
	tcpHeader[16] = byte(checksum >> 8)
	tcpHeader[17] = byte(checksum & 0xFF)

	return nil
}

// Calculate TCP checksum including pseudo-header
func calculateTCPChecksum(srcIP, destIP, tcpData []byte) uint16 {
	var sum uint32

	// Pseudo-header: src IP (4) + dest IP (4) + zero (1) + protocol (1) + TCP length (2)
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP)
	copy(pseudoHeader[4:8], destIP)
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6 // TCP protocol
	tcpLen := uint16(len(tcpData))
	pseudoHeader[10] = byte(tcpLen >> 8)
	pseudoHeader[11] = byte(tcpLen & 0xFF)

	// Sum pseudo-header
	for i := 0; i < 12; i += 2 {
		sum += uint32(pseudoHeader[i])<<8 + uint32(pseudoHeader[i+1])
	}

	// Sum TCP header and data
	for i := 0; i < len(tcpData)-1; i += 2 {
		sum += uint32(tcpData[i])<<8 + uint32(tcpData[i+1])
	}

	// ✅ FIX: Handle odd-length TCP data correctly
	if len(tcpData)%2 == 1 {
		sum += uint32(tcpData[len(tcpData)-1]) << 8
	}

	// ✅ FIX: Proper carry handling
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return uint16(^sum)
}

// Add this function for UDP checksum recalculation
func recalculateUDPChecksum(packet []byte) error {
	if len(packet) < 28 { // IP header (20) + UDP header (8)
		return fmt.Errorf("packet too short for UDP")
	}

	protocol := packet[9]
	if protocol != 17 { // Not UDP
		return nil
	}

	// Extract IPs
	srcIP := packet[12:16]
	destIP := packet[16:20]

	// Get UDP header start
	ipHeaderLen := int(packet[0]&0x0F) * 4
	udpHeader := packet[ipHeaderLen:]

	if len(udpHeader) < 8 {
		return fmt.Errorf("UDP header too short")
	}

	// Clear existing UDP checksum
	udpHeader[6] = 0
	udpHeader[7] = 0

	// Calculate UDP checksum with pseudo-header
	checksum := calculateUDPChecksum(srcIP, destIP, udpHeader)

	// Set new checksum (0 means no checksum in UDP)
	if checksum == 0 {
		checksum = 0xFFFF // UDP uses 0xFFFF instead of 0
	}

	udpHeader[6] = byte(checksum >> 8)
	udpHeader[7] = byte(checksum & 0xFF)

	return nil
}

// Calculate UDP checksum including pseudo-header
func calculateUDPChecksum(srcIP, destIP, udpData []byte) uint16 {
	var sum uint32

	// Pseudo-header: src IP (4) + dest IP (4) + zero (1) + protocol (1) + UDP length (2)
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP)
	copy(pseudoHeader[4:8], destIP)
	pseudoHeader[8] = 0
	pseudoHeader[9] = 17 // UDP protocol
	udpLen := uint16(len(udpData))
	pseudoHeader[10] = byte(udpLen >> 8)
	pseudoHeader[11] = byte(udpLen & 0xFF)

	// Sum pseudo-header
	for i := 0; i < 12; i += 2 {
		sum += uint32(pseudoHeader[i])<<8 + uint32(pseudoHeader[i+1])
	}

	// Sum UDP header and data
	for i := 0; i < len(udpData)-1; i += 2 {
		sum += uint32(udpData[i])<<8 + uint32(udpData[i+1])
	}

	// Add odd byte if present
	if len(udpData)%2 == 1 {
		sum += uint32(udpData[len(udpData)-1]) << 8
	}

	// Add carry bits
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return uint16(^sum)
}

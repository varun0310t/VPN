//go:build windows
// +build windows

package main

import (
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

func main() {
	fmt.Println("🧪 Windows VPN Packet Injection Test")

	// Create TUN interface (same as your VPN client)
	tunDevice, err := createTunInterface()
	if err != nil {
		fmt.Printf("❌ Failed to create TUN interface: %v\n", err)
		return
	}
	defer tunDevice.Close()

	fmt.Println("✅ TUN interface created")

	// Test different types of packet injection
	fmt.Println("\n🔍 Testing packet injection...")

	// Test 1: ICMP Echo Reply (should reach ping command)
	testICMPResponse(tunDevice)

	// Test 2: HTTP Response (should reach browser/curl)
	testHTTPResponse(tunDevice)

	// Test 3: DNS Response (should reach DNS resolver)
	testDNSResponse(tunDevice)

	// Monitor for a while
	fmt.Println("\n👂 Monitoring TUN interface for 30 seconds...")
	fmt.Println("💡 Try running: ping 8.8.8.8 in another terminal")
	fmt.Println("💡 Or browse to: http://httpbin.org/ip")

	monitorTunInterface(tunDevice, 30*time.Second)
}

func createTunInterface() (tun.Device, error) {
	// Create TUN interface with same config as your VPN client
	tunDevice, err := tun.CreateTUN("VPN-Test", 1500)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %v", err)
	}

	// Configure IP (you might need to run as administrator)
	fmt.Println("⚙️  Configuring TUN interface...")
	fmt.Println("💡 You may need to manually set IP: netsh interface ip set address \"VPN-Test\" static 10.8.0.2 255.255.255.0")

	return tunDevice, nil
}

func testICMPResponse(tunDevice tun.Device) {
	fmt.Println("\n🏓 Test 1: Injecting ICMP Echo Reply")

	// Create fake ping response from 8.8.8.8 to 10.8.0.2
	packet := createICMPReply("8.8.8.8", "10.8.0.2", 1234, 1)

	_, err := tunDevice.Write([][]byte{packet}, 0)
	if err != nil {
		fmt.Printf("❌ Failed to write ICMP packet: %v\n", err)
		return
	}

	fmt.Printf("✅ Injected ICMP reply: 8.8.8.8 → 10.8.0.2 (%d bytes)\n", len(packet))
	fmt.Println("💡 If you have 'ping 8.8.8.8' running, it should receive this reply!")

	time.Sleep(2 * time.Second)
}

func testHTTPResponse(tunDevice tun.Device) {
	fmt.Println("\n🌐 Test 2: Injecting HTTP Response")

	// Create fake HTTP response
	httpData := "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello from VPN"
	packet := createTCPPacket("142.250.191.14", "10.8.0.2", 80, 12345, []byte(httpData))

	_, err := tunDevice.Write([][]byte{packet}, 0)
	if err != nil {
		fmt.Printf("❌ Failed to write HTTP packet: %v\n", err)
		return
	}

	fmt.Printf("✅ Injected HTTP response: 142.250.191.14:80 → 10.8.0.2:12345 (%d bytes)\n", len(packet))
	fmt.Println("💡 If you have an HTTP request to port 12345, it should receive this!")

	time.Sleep(2 * time.Second)
}

func testDNSResponse(tunDevice tun.Device) {
	fmt.Println("\n🔍 Test 3: Injecting DNS Response")

	// Create fake DNS response for google.com
	dnsResponse := createDNSResponse()
	packet := createUDPPacket("8.8.8.8", "10.8.0.2", 53, 54321, dnsResponse)

	_, err := tunDevice.Write([][]byte{packet}, 0)
	if err != nil {
		fmt.Printf("❌ Failed to write DNS packet: %v\n", err)
		return
	}

	fmt.Printf("✅ Injected DNS response: 8.8.8.8:53 → 10.8.0.2:54321 (%d bytes)\n", len(packet))
	fmt.Println("💡 If you have a DNS query from port 54321, it should receive this!")

	time.Sleep(2 * time.Second)
}

func monitorTunInterface(tunDevice tun.Device, duration time.Duration) {
	fmt.Printf("📡 Reading packets from TUN interface...\n")

	deadline := time.Now().Add(duration)
	packetCount := 0

	for time.Now().Before(deadline) {
		// Set read timeout
		packets := make([][]byte, 1)
		packets[0] = make([]byte, 1500)
		sizes := make([]int, 1)

		// Note: Windows TUN interface Read might block
		// In a real implementation, you'd use goroutines or non-blocking reads

		n, err := tunDevice.Read(packets, sizes, 0)
		if err != nil {
			fmt.Printf("Read error: %v\n", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if n > 0 && len(packets[0]) >= 20 {
			packetCount++
			analyzeOutgoingPacket(packets[0], packetCount)
		}

		// Check periodically
		time.Sleep(10 * time.Millisecond)
	}

	fmt.Printf("📊 Monitored %d outgoing packets\n", packetCount)
}

func analyzeOutgoingPacket(packet []byte, count int) {
	if len(packet) < 20 {
		return
	}

	version := packet[0] >> 4
	if version != 4 {
		return // Not IPv4
	}

	protocol := packet[9]
	srcIP := net.IPv4(packet[12], packet[13], packet[14], packet[15])
	dstIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])

	protocolName := getProtocolName(protocol)

	fmt.Printf("📤 Outgoing #%d: %s → %s (%s, %d bytes)\n",
		count, srcIP, dstIP, protocolName, len(packet))

	// Protocol-specific analysis
	switch protocol {
	case 1: // ICMP
		if len(packet) >= 24 {
			icmpType := packet[20]
			icmpCode := packet[21]
			fmt.Printf("   ICMP Type: %d, Code: %d", icmpType, icmpCode)
			if icmpType == 8 {
				fmt.Printf(" (Echo Request - ping)")
			}
			fmt.Println()
		}
	case 6: // TCP
		if len(packet) >= 40 {
			srcPort := uint16(packet[20])<<8 | uint16(packet[21])
			dstPort := uint16(packet[22])<<8 | uint16(packet[23])
			fmt.Printf("   TCP: %s:%d → %s:%d\n", srcIP, srcPort, dstIP, dstPort)
		}
	case 17: // UDP
		if len(packet) >= 28 {
			srcPort := uint16(packet[20])<<8 | uint16(packet[21])
			dstPort := uint16(packet[22])<<8 | uint16(packet[23])
			fmt.Printf("   UDP: %s:%d → %s:%d", srcIP, srcPort, dstIP, dstPort)
			if dstPort == 53 {
				fmt.Printf(" (DNS Query)")
			}
			fmt.Println()
		}
	}
}

// Create ICMP Echo Reply packet
func createICMPReply(srcIP, dstIP string, id, seq uint16) []byte {
	packet := make([]byte, 84) // 20 IP + 8 ICMP + 56 data

	// IP Header
	packet[0] = 0x45 // Version 4, IHL 5
	packet[1] = 0x00 // TOS
	packet[2] = 0x00 // Total Length high
	packet[3] = 0x54 // Total Length low (84)
	packet[4] = 0x12 // ID high
	packet[5] = 0x34 // ID low
	packet[6] = 0x40 // Don't Fragment
	packet[7] = 0x00 // Fragment offset
	packet[8] = 0x40 // TTL
	packet[9] = 0x01 // Protocol (ICMP)

	// Source and destination IPs
	copy(packet[12:16], net.ParseIP(srcIP).To4())
	copy(packet[16:20], net.ParseIP(dstIP).To4())

	// Calculate IP checksum
	packet[10] = 0
	packet[11] = 0
	checksum := calculateChecksum(packet[:20])
	packet[10] = byte(checksum >> 8)
	packet[11] = byte(checksum & 0xFF)

	// ICMP Header
	packet[20] = 0x00             // Type: Echo Reply
	packet[21] = 0x00             // Code
	packet[24] = byte(id >> 8)    // ID high
	packet[25] = byte(id & 0xFF)  // ID low
	packet[26] = byte(seq >> 8)   // Sequence high
	packet[27] = byte(seq & 0xFF) // Sequence low

	// ICMP Data
	for i := 28; i < 84; i++ {
		packet[i] = byte(i - 28)
	}

	// Calculate ICMP checksum
	packet[22] = 0
	packet[23] = 0
	icmpChecksum := calculateChecksum(packet[20:])
	packet[22] = byte(icmpChecksum >> 8)
	packet[23] = byte(icmpChecksum & 0xFF)

	return packet
}

// Create TCP packet with data
func createTCPPacket(srcIP, dstIP string, srcPort, dstPort uint16, data []byte) []byte {
	ipHeaderLen := 20
	tcpHeaderLen := 20
	totalLen := ipHeaderLen + tcpHeaderLen + len(data)

	packet := make([]byte, totalLen)

	// IP Header
	packet[0] = 0x45                  // Version 4, IHL 5
	packet[1] = 0x00                  // TOS
	packet[2] = byte(totalLen >> 8)   // Total Length high
	packet[3] = byte(totalLen & 0xFF) // Total Length low
	packet[4] = 0x12                  // ID high
	packet[5] = 0x34                  // ID low
	packet[6] = 0x40                  // Don't Fragment
	packet[7] = 0x00                  // Fragment offset
	packet[8] = 0x40                  // TTL
	packet[9] = 0x06                  // Protocol (TCP)

	// IPs
	copy(packet[12:16], net.ParseIP(srcIP).To4())
	copy(packet[16:20], net.ParseIP(dstIP).To4())

	// IP Checksum
	packet[10] = 0
	packet[11] = 0
	checksum := calculateChecksum(packet[:20])
	packet[10] = byte(checksum >> 8)
	packet[11] = byte(checksum & 0xFF)

	// TCP Header
	packet[20] = byte(srcPort >> 8)   // Source port high
	packet[21] = byte(srcPort & 0xFF) // Source port low
	packet[22] = byte(dstPort >> 8)   // Dest port high
	packet[23] = byte(dstPort & 0xFF) // Dest port low

	// TCP fields (simplified)
	packet[32] = 0x50 // Data offset (5 * 4 = 20 bytes)
	packet[33] = 0x18 // Flags (PSH + ACK)
	packet[34] = 0xFF // Window high
	packet[35] = 0xFF // Window low

	// Copy data
	copy(packet[40:], data)

	return packet
}

// Create UDP packet
func createUDPPacket(srcIP, dstIP string, srcPort, dstPort uint16, data []byte) []byte {
	ipHeaderLen := 20
	udpHeaderLen := 8
	totalLen := ipHeaderLen + udpHeaderLen + len(data)

	packet := make([]byte, totalLen)

	// IP Header (similar to TCP)
	packet[0] = 0x45
	packet[1] = 0x00
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen & 0xFF)
	packet[4] = 0x12
	packet[5] = 0x34
	packet[6] = 0x40
	packet[7] = 0x00
	packet[8] = 0x40
	packet[9] = 0x11 // Protocol (UDP)

	copy(packet[12:16], net.ParseIP(srcIP).To4())
	copy(packet[16:20], net.ParseIP(dstIP).To4())

	// IP Checksum
	packet[10] = 0
	packet[11] = 0
	checksum := calculateChecksum(packet[:20])
	packet[10] = byte(checksum >> 8)
	packet[11] = byte(checksum & 0xFF)

	// UDP Header
	udpLen := udpHeaderLen + len(data)
	packet[20] = byte(srcPort >> 8)
	packet[21] = byte(srcPort & 0xFF)
	packet[22] = byte(dstPort >> 8)
	packet[23] = byte(dstPort & 0xFF)
	packet[24] = byte(udpLen >> 8)
	packet[25] = byte(udpLen & 0xFF)
	packet[26] = 0x00 // Checksum (simplified - set to 0)
	packet[27] = 0x00

	// Copy data
	copy(packet[28:], data)

	return packet
}

// Create simple DNS response
func createDNSResponse() []byte {
	// Simplified DNS response for google.com → 8.8.8.8
	return []byte{
		0x12, 0x34, // Transaction ID
		0x81, 0x80, // Flags (response)
		0x00, 0x01, // Questions: 1
		0x00, 0x01, // Answer RRs: 1
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		// Question section (simplified)
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // End of name
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		// Answer section
		0xc0, 0x0c, // Name (pointer to question)
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x00, 0x3c, // TTL: 60 seconds
		0x00, 0x04, // Data length: 4
		8, 8, 8, 8, // IP address: 8.8.8.8
	}
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32

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

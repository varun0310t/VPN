package main

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/songgao/water"
)

var MTU = 1500
var tun_peer net.IP
var Interface *water.Interface
var Conn net.Conn

func main() {
	Interface, err := newTun("tun0")
	if err != nil {
		fmt.Println("could not create tun")
		return
	}
	ip := net.ParseIP("10.0.0.1")
	_, subnet, err := net.ParseCIDR("10.0.0.0/30")
	if err != nil {
		fmt.Println("bad CIDR:", err)
		return
	}
	if err := setTunIP(Interface, ip, subnet); err != nil {
		fmt.Println("setTunIP:", err)
		return
	}

	Conn, err := ListenForConnection("8080")
	if err != nil {
		fmt.Printf("Could not connect to client: %v\n", err)
		return
	}
	defer Conn.Close()

	fmt.Println("✅ Server ready - starting packet processing...")

	go func() {
		err := ListenForPackets(Conn)
		if err != nil {
			fmt.Printf("Error Listening Packets: %v\n", err)
		}
	}()

	go func() {
		err := ListenForResponse()
		if err != nil {
			fmt.Printf("Error Listening Response: %v\n", err)
		}
	}()

	// Keep server running
	fmt.Println("🚀 VPN Server running... Press Ctrl+C to stop")
	select {} // Block forever

}
func ListenForPackets(Conn net.Conn) error {
	fmt.Printf("Listening for Packets from client")

	for {
		lengthBytes := make([]byte, 4)
		Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err := io.ReadFull(Conn, lengthBytes)
		if err != nil {
			if err == io.EOF {
				fmt.Println(" Client disconnected")
			} else {
				fmt.Printf(" Error reading response length: %v\n", err)
			}
			break
		}
		packetLen := int(uint32(lengthBytes[0])<<24 | uint32(lengthBytes[1])<<16 | uint32(lengthBytes[2])<<8 | uint32(lengthBytes[3]))
		PacketByte := make([]byte, packetLen)
		Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err = io.ReadFull(Conn, PacketByte)
		if err != nil {
			if err == io.EOF {
				fmt.Println(" Client disconnected")
			} else {
				fmt.Printf(" Error reading response length: %v\n", err)
			}
			break
		}
		err = ForwardPacketToInternet(PacketByte)
		if err != nil {
			fmt.Printf("Error on Forwarding Packet to Internet")
		}

	}

	return nil
}

// Forward packet to internet
func ForwardPacketToInternet(Packet []byte) error {
	if len(Packet) < 20 {
		return fmt.Errorf("packet too short for IP header")
	}

	// Extract destination IP from the packet
	destIP := net.IPv4(Packet[16], Packet[17], Packet[18], Packet[19])
	fmt.Printf("🌍 Forwarding packet to internet: %s\n", destIP)

	// Modify source IP to VPN server's public IP (NAT)
	Packet[12] = 172 // VPN server's IP
	Packet[13] = 30
	Packet[14] = 66
	Packet[15] = 2

	// Recalculate IP checksum after modifying source IP
	Packet[10] = 0 // Clear existing checksum
	Packet[11] = 0
	checksum := calculateIPChecksum(Packet[:20])
	Packet[10] = byte(checksum >> 8)
	Packet[11] = byte(checksum & 0xFF)

	// Send packet to internet using raw socket
	return SendPacket(Packet, destIP.String())
}

func SendPacket(packet []byte, destIP string) error {
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

	// Send packet using raw socket
	n, err := Interface.Write(packet)
	if err != nil {
		return fmt.Errorf("sendto failed: %v", err)
	}

	_ = n

	fmt.Printf("✅ Packet sent successfully to %s (%d bytes)\n", destIP, len(packet))
	return nil
}

func newTun(name string) (iface *water.Interface, err error) {

	iface, err = water.New(water.Config{DeviceType: 0})
	if err != nil {
		return nil, err
	}
	fmt.Printf("interface %v created\n", iface.Name())

	sargs := fmt.Sprintf("link set dev %s up mtu %d qlen 100", iface.Name(), MTU)
	args := strings.Split(sargs, " ")
	cmd := exec.Command("ip", args...)
	fmt.Printf("ip %s\n", sargs)
	err = cmd.Run()
	if err != nil {
		return nil, err
	}

	return iface, nil
}

func setTunIP(iface *water.Interface, ip net.IP, subnet *net.IPNet) (err error) {
	ip = ip.To4()
	fmt.Println("%v", ip)
	if ip[3]%2 == 0 {
		return nil
	}

	peer := net.IP(make([]byte, 4))
	copy([]byte(peer), []byte(ip))
	peer[3]++
	tun_peer = peer

	sargs := fmt.Sprintf("addr add dev %s local %s peer %s", iface.Name(), ip, peer)
	args := strings.Split(sargs, " ")
	cmd := exec.Command("ip", args...)
	fmt.Println("ip %s", sargs)
	err = cmd.Run()
	if err != nil {
		return err
	}

	sargs = fmt.Sprintf("route add %s via %s dev %s", subnet, peer, iface.Name())
	args = strings.Split(sargs, " ")
	cmd = exec.Command("ip", args...)
	println("ip %s", sargs)
	err = cmd.Run()
	return err
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
	fmt.Printf("Listening for Reponse")
	buffer := make([]byte, 4096)
	for {
		n, err := Interface.Read(buffer)
		if err != nil {
			// Check if it's timeout
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.EAGAIN {
				continue
			}
			fmt.Printf("⚠️ Receive error: %v\n", err)
			continue
		}

		if n < 20 {
			continue // Skip packets too short for IP header
		}

		packet := buffer[:n]

		// Extract destination IP (should be our VPN client's virtual IP)
		destIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])
		// Extract source IP to check if it's from client
		sourceIP := net.IPv4(packet[12], packet[13], packet[14], packet[15])
		fmt.Printf("source ip %s destip %s \n", sourceIP.String(), destIP.String())
		// Skip packet if source IP is from client (192.168.1.12)
		if sourceIP.String() == "192.168.1.12" {
			continue
		}
		// Check if this packet is meant for our VPN client
		if destIP.String() == "172.30.60.2" { // Assuming client virtual IP
			fmt.Printf("📥 Received response packet for client: %s\n", destIP)

			// Modify destination IP back to client's virtual IP
			packet[16] = 192 // Client's virtual IP
			packet[17] = 168
			packet[18] = 1
			packet[19] = 12

			// Recalculate IP checksum
			packet[10] = 0
			packet[11] = 0
			checksum := calculateIPChecksum(packet[:20])
			packet[10] = byte(checksum >> 8)
			packet[11] = byte(checksum & 0xFF)

			// Send packet back to client through TCP connection
			err = SendPacketToClient(packet)
			if err != nil {
				fmt.Printf("Error sending packet to client: %v\n", err)
			}
		}
	}
}

func SendPacketToClient(packet []byte) error {
	// Create packet length header (4 bytes, big-endian)
	lengthBytes := make([]byte, 4)
	packetLen := uint32(len(packet))
	lengthBytes[0] = byte(packetLen >> 24)
	lengthBytes[1] = byte(packetLen >> 16)
	lengthBytes[2] = byte(packetLen >> 8)
	lengthBytes[3] = byte(packetLen)

	// Send length header first
	_, err := Conn.Write(lengthBytes)
	if err != nil {
		return fmt.Errorf("failed to send packet length: %v", err)
	}

	// Send the actual packet
	_, err = Conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to send packet: %v", err)
	}

	fmt.Printf("✅ Sent packet to client (%d bytes)\n", len(packet))
	return nil
}

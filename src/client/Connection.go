//go:build linux
// +build linux

package client

import (
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pion/dtls/v2"
)

// PacketType identifies the type of VPN packet
type PacketType byte

const (
	PacketTypeAuthReq      PacketType = 0x01 // Authentication request
	PacketTypeAuthRespPass PacketType = 0x02 // Authentication response - success
	PacketTypeData         PacketType = 0x03 // VPN data packet
	PacketTypePing         PacketType = 0x04 // Keep-alive ping
	PacketTypePong         PacketType = 0x05 // Keep-alive pong
	PacketTypeDisc         PacketType = 0x06 // Disconnect
	PacketTypeAuthRespFail PacketType = 0x07 // Authentication response - failure
	PacketTypeAskForIP     PacketType = 0x08 // Request for IP address
	PacketTypeIPRes        PacketType = 0x09 // IP address response
)

type VPNClient struct {
	serverAddr    *net.UDPAddr
	conn          net.Conn
	tunManager    *TunManager
	assignedIP    string
	authenticated bool
	netConfig     *NetworkConfig
	running       bool
}

func NewVPNClient(serverIP string, serverPort int) (*VPNClient, error) {
	// Resolve server address
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", serverIP, serverPort))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server address: %w", err)
	}

	// Load server certificate for verification
	certPool := x509.NewCertPool()
	serverCert, err := os.ReadFile("/etc/vpn/server-cert.pem")
	if err != nil {
		fmt.Printf(" Warning: Could not load server cert, using insecure mode: %v\n", err)
		certPool = nil
	} else {
		certPool.AppendCertsFromPEM(serverCert)
	}

	// Configure DTLS
	config := &dtls.Config{
		InsecureSkipVerify:   certPool == nil,
		RootCAs:              certPool,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	// Create UDP connection
	udpConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %w", err)
	}

	udpConn.SetReadBuffer(4 * 1024 * 1024)
	udpConn.SetWriteBuffer(4 * 1024 * 1024)
	// Wrap with DTLS
	fmt.Println(" Establishing encrypted DTLS connection...")
	dtlsConn, err := dtls.Client(udpConn, config)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("failed to establish DTLS connection: %w", err)
	}

	fmt.Println(" Encrypted connection established!")

	return &VPNClient{
		serverAddr: serverAddr,
		conn:       dtlsConn,
		netConfig:  NewNetworkConfig(),
	}, nil
}

func (vc *VPNClient) SaveNetworkConfig() error {
	return vc.netConfig.Save()
}

func (vc *VPNClient) Connect() error {
	fmt.Println(" Authenticating with server...")

	// Send authentication request
	err := vc.sendAuthRequest()
	if err != nil {
		return fmt.Errorf("failed to send auth request: %w", err)
	}

	// Wait for authentication response
	err = vc.waitForAuthResponse()
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	fmt.Printf(" Authenticated! Assigned IP: %s\n", vc.assignedIP)

	// Create TUN interface
	vc.tunManager, err = NewTunManager("tun1", vc.assignedIP)
	if err != nil {
		return fmt.Errorf("failed to create TUN interface: %w", err)
	}

	fmt.Println(" TUN interface created and configured")

	// Setup routes to route traffic through VPN
	err = vc.setupRoutes()
	if err != nil {
		return fmt.Errorf("failed to setup routes: %w", err)
	}

	vc.running = true

	// Start packet forwarding
	go vc.forwardFromTUN()
	go vc.receiveFromServer()

	// Start keep-alive
	go vc.keepAlive()

	fmt.Println(" VPN connection established!")
	return nil
}

func (vc *VPNClient) sendAuthRequest() error {
	payload := []byte(ClientCfg.PASSWORD)
	if Password == "" {
		fmt.Printf("no password provided for authentication using ClientCfg")
	} else {
		fmt.Println(" Using provided password for authentication")
		payload = []byte(Password)
	}
	packet := make([]byte, len(payload)+1)
	packet[0] = byte(PacketTypeAuthReq)
	copy(packet[1:], payload)
	_, err := vc.conn.Write(packet)
	return err
}

func (vc *VPNClient) waitForAuthResponse() error {
	buffer := make([]byte, 1024)
	vc.conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	n, err := vc.conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("timeout waiting for auth response: %w", err)
	}

	vc.conn.SetReadDeadline(time.Time{}) // Clear deadline

	if n < 1 {
		return fmt.Errorf("invalid auth response")
	}

	packetType := PacketType(buffer[0])
	if packetType == PacketTypeAuthRespPass {
		// Extract assigned IP from response (last octet)
		if n >= 5 {
			lastOctet := int(buffer[4])
			vc.assignedIP = fmt.Sprintf("10.8.0.%d", lastOctet)
			vc.authenticated = true
			return nil
		}
		return fmt.Errorf("invalid auth response format")
	} else if packetType == PacketTypeAuthRespFail {
		return fmt.Errorf("authentication rejected by server")
	}

	return fmt.Errorf("unexpected response type: 0x%02x", packetType)
}

func (vc *VPNClient) forwardFromTUN() {
	buffer := make([]byte, 65535)
	PacketSendCounter := 0
	PrevTime := time.Now().UnixMilli()
	for vc.running {
		n, err := vc.tunManager.ReadPacket(buffer)
		if err != nil {
			if vc.running {
				fmt.Printf(" Error reading from TUN: %v\n", err)
			}
			continue
		}

		packet := buffer[:n]

		if len(packet) >= 20 {
			//	destIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])
			//fmt.Printf("Sending to VPN: dest=%s (%d bytes)\n", destIP.String(), n)
		}

		// Wrap in VPN data packet and send to server
		vc.sendDataPacket(packet)
		PacketSendCounter++
		CurrentTime := time.Now().UnixMilli()
		if CurrentTime-PrevTime >= 1000 {
			fmt.Printf(" Sent %d packets in the last second\n", PacketSendCounter)
			PacketSendCounter = 0
			PrevTime = CurrentTime
		}

	}
}

func (vc *VPNClient) receiveFromServer() {
	buffer := make([]byte, 65535)
	PacketRecvCounter := 0
	PrevTime := time.Now().UnixMilli()
	for vc.running {
		n, err := vc.conn.Read(buffer)
		if err != nil {
			if vc.running {
				fmt.Printf(" Error receiving from server: %v\n", err)
			}
			continue
		}

		if n < 1 {
			continue
		}

		packetType := PacketType(buffer[0])
		payload := buffer[1:n]

		switch packetType {
		case PacketTypeData:
			vc.handleDataPacket(payload)
		case PacketTypePong:
			// Keep-alive response received
		default:
			fmt.Printf("Unknown packet type: 0x%02x\n", packetType)
		}

		PacketRecvCounter++
		CurrentTime := time.Now().UnixMilli()
		if CurrentTime-PrevTime >= 1000 {
			fmt.Printf(" Received %d packets in the last second\n", PacketRecvCounter)
			PacketRecvCounter = 0
			PrevTime = CurrentTime
		}
	}
}

func (vc *VPNClient) handleDataPacket(payload []byte) {

	if len(payload) >= 20 {
		//	srcIP := net.IPv4(payload[12], payload[13], payload[14], payload[15])
		//	fmt.Printf(" Received from VPN: src=%s (%d bytes)\n", srcIP.String(), len(payload))
	}

	// Write packet to TUN interface
	err := vc.tunManager.WritePacket(payload)
	if err != nil {
		fmt.Printf(" Error writing to TUN: %v\n", err)
	}
}

func (vc *VPNClient) sendDataPacket(data []byte) error {
	// Prepend packet type
	packet := make([]byte, len(data)+1)
	packet[0] = byte(PacketTypeData)
	copy(packet[1:], data)

	_, err := vc.conn.Write(packet)
	return err
}

func (vc *VPNClient) keepAlive() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for vc.running {
		<-ticker.C
		packet := []byte{byte(PacketTypePing)}
		_, err := vc.conn.Write(packet)
		if err != nil {
			fmt.Printf(" Warning: Keep-alive failed: %v\n", err)
		}
	}
}

func (vc *VPNClient) setupRoutes() error {
	fmt.Println("📡 Setting up VPN routes...")

	// Save current default gateway before modifying routes
	err := vc.netConfig.SaveDefaultGateway()
	if err != nil {
		return fmt.Errorf("failed to save default gateway: %w", err)
	}

	// Route all traffic through VPN (except server connection)
	err = vc.netConfig.AddVPNRoutes(vc.serverAddr.IP.String(), "tun1")
	if err != nil {
		return fmt.Errorf("failed to add VPN routes: %w", err)
	}

	fmt.Println(" Routes configured")
	return nil
}

func (vc *VPNClient) Disconnect() error {
	vc.running = false

	fmt.Println(" Restoring original network configuration...")

	// Restore original network config
	if vc.netConfig != nil {
		err := vc.netConfig.Restore()
		if err != nil {
			fmt.Printf(" Warning: failed to restore network config: %v\n", err)
		} else {
			fmt.Println("Network configuration restored")
		}
	}

	// Send disconnect packet
	if vc.conn != nil {
		packet := []byte{byte(PacketTypeDisc)}
		vc.conn.Write(packet)
	}
	// Restore DNS settings
	vc.tunManager.RestoreDNS()

	// Close TUN interface
	if vc.tunManager != nil {
		vc.tunManager.Close()
		fmt.Println(" TUN interface closed")
	}

	// Close UDP connection
	if vc.conn != nil {
		vc.conn.Close()
		fmt.Println(" Connection closed")
	}

	fmt.Println(" VPN disconnected successfully")
	return nil
}

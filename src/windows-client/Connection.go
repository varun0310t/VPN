//go:build windows
// +build windows

package windowsclient

import (
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/pion/dtls/v2"
	"golang.org/x/sys/windows"
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
	running       bool
	SecretKey     string
}

func NewVPNClient(serverIP string, serverPort int, SecretKEY string) (*VPNClient, error) {
	// Resolve server address
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", serverIP, serverPort))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server address: %w", err)
	}
	// Load server certificate for verification
	certPool := x509.NewCertPool()

	// Configure DTLS
	config := &dtls.Config{
		InsecureSkipVerify:   true,
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
		SecretKey:  SecretKEY,
	}, nil
}
func (client *VPNClient) Connect() error {
	fmt.Println(" Authenticating with server...")

	// Send authentication request
	err := client.sendAuthRequest()
	if err != nil {
		return fmt.Errorf("failed to send auth request: %w", err)
	}

	// Wait for authentication response
	err = client.waitForAuthResponse()
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	fmt.Printf(" Authenticated! Assigned IP: %s\n", client.assignedIP)
	// Create TUN interface
	client.tunManager, err = NewTunManager("tun1", client.assignedIP)
	if err != nil {
		return fmt.Errorf("failed to create TUN interface: %w", err)
	}

	fmt.Println(" TUN interface created and configured")
	client.running = true

	// // this is a test read to avoid deadlock
	// buffer := make([]byte, 65535)
	// n, err := client.tunManager.ReadPacket(buffer)
	// if err != nil {
	// 	return fmt.Errorf("failed to read from TUN interface: %w", err)
	// }
	// fmt.Printf(" Test read %d bytes from TUN interface\n", n)

	go client.forwardFromTUN()
	go client.receiveFromServer()

	// Start keep-alive routine
	go client.keepAlive()

	fmt.Println(" VPN connection established!")
	return nil
}

func (client *VPNClient) Disconnect() {
	client.running = false
	// Send disconnect packet
	if client.conn != nil {
		packet := []byte{byte(PacketTypeDisc)}
		client.conn.Write(packet)
	}

	// Close TUN interface
	if client.tunManager != nil {
		client.tunManager.Close()
		fmt.Println(" TUN interface closed")
	}

	// Close UDP connection
	if client.conn != nil {
		client.conn.Close()
		fmt.Println(" Connection closed")
	}

	fmt.Println(" VPN disconnected successfully")

}
func (client *VPNClient) keepAlive() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for client.running {
		<-ticker.C
		packet := []byte{byte(PacketTypePing)}
		_, err := client.conn.Write(packet)
		if err != nil {
			fmt.Printf(" Warning: Keep-alive failed: %v\n", err)
		}
	}
}
func (client *VPNClient) sendAuthRequest() error {
	if client.conn == nil {
		return fmt.Errorf("connection is not established")
	}
	payload := []byte(ClientCfg.PASSWORD)
	if client.SecretKey == "" {
		fmt.Printf("secret key is empty using Config file ")
	} else {
		payload = []byte(client.SecretKey)
	}
	packet := append([]byte{byte(PacketTypeAuthReq)}, payload...)
	_, err := client.conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to send authentication request: %w", err)
	}

	return nil
}

func (client *VPNClient) waitForAuthResponse() error {
	buffer := make([]byte, 1024)
	client.conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	n, err := client.conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("timeout waiting for auth response: %w", err)
	}

	client.conn.SetReadDeadline(time.Time{}) // Clear deadline

	if n < 1 {
		return fmt.Errorf("invalid auth response")
	}

	packetType := PacketType(buffer[0])
	if packetType == PacketTypeAuthRespPass {
		// Extract assigned IP from response (last octet)
		if n >= 5 {
			lastOctet := int(buffer[4])
			client.assignedIP = fmt.Sprintf("10.8.0.%d", lastOctet)
			client.authenticated = true
			return nil
		}
		return fmt.Errorf("invalid auth response format")
	} else if packetType == PacketTypeAuthRespFail {
		return fmt.Errorf("authentication rejected by server")
	}

	return fmt.Errorf("unexpected response type: 0x%02x", packetType)
}

func (client *VPNClient) forwardFromTUN() {
	buffer := make([]byte, 65535)
	PacketSendCounter := 0
	PrevTime := time.Now().UnixMilli()

	for client.running {

		n, err := client.tunManager.ReadPacket(buffer)
		if err != nil {
			if client.running {
				//fmt.Printf("error reading from TUN: %v\n", err)

			}
			waitHandle := client.tunManager.Session.ReadWaitEvent()
			windows.WaitForSingleObject(waitHandle, windows.INFINITE)
			continue
		}
		packet := buffer[:n]
		err = client.sendDataPacket(packet)
		if err != nil {
			fmt.Printf("error sending data packet: %v\n", err)
			continue
		}
		PacketSendCounter++
		CurrentTime := time.Now().UnixMilli()

		if CurrentTime-PrevTime >= 1000 {
			fmt.Printf(" Sent %d packets in the last second\n", PacketSendCounter)
			PacketSendCounter = 0
			PrevTime = CurrentTime
		}
		//time.Sleep(50 * time.Second)

	}
}

func (client *VPNClient) receiveFromServer() {
	buffer := make([]byte, 65535)
	PacketRecvCounter := 0
	PrevTime := time.Now().UnixMilli()
	for client.running {
		n, err := client.conn.Read(buffer)
		fmt.Printf(" Read %d bytes from server\n", n)
		if err != nil {
			if client.running {
				fmt.Printf(" Error reading from server: %v\n", err)
			}
			continue
		}
		packet := buffer[1:n]
		// Write packet to TUN interface
		err = client.tunManager.WritePacket(packet)
		if err != nil {
			fmt.Printf(" Error writing to TUN: %v\n", err)
			continue
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

func (vc *VPNClient) sendDataPacket(packet []byte) error {
	dataPacket := make([]byte, len(packet)+1)
	dataPacket[0] = byte(PacketTypeData)
	copy(dataPacket[1:], packet)
	_, err := vc.conn.Write(dataPacket)
	return err
}

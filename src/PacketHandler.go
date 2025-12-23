package src

import (
	"fmt"
	"net"
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
)

// VPNPacket represents a VPN protocol packet
type VPNPacket struct {
	Type    PacketType
	Payload []byte
}

// HandlePacket processes incoming packets from clients
func HandlePacket(data []byte, clientAddr *net.UDPAddr) {
	// Minimum packet size check
	if len(data) < 1 {
		fmt.Printf("Received invalid packet from %s: too small\n", clientAddr.String())
		return
	}

	packetType := PacketType(data[0])
	payload := data[1:]

	switch packetType {
	case PacketTypeAuthReq:
		handleAuthPacket(payload, clientAddr)
	case PacketTypeData:
		handleDataPacket(payload, clientAddr)
	case PacketTypePing:
		handlePingPacket(payload, clientAddr)
	case PacketTypeDisc:
		handleDisconnectPacket(payload, clientAddr)
	default:
		fmt.Printf("Unknown packet type 0x%02x from %s\n", packetType, clientAddr.String())
	}
}

// handleAuthPacket processes authentication requests
func handleAuthPacket(payload []byte, clientAddr *net.UDPAddr) {
	fmt.Printf("Auth request from %s\n", clientAddr.String())

	session, err := ClientManager.GetOrAddClient(clientAddr)
	if err != nil {
		fmt.Printf("Failed to create session for %s: %v\n", clientAddr.String(), err)
		sendAuthResponse(clientAddr, false, 0)
		return
	}

	// Mark session as authenticated
	ClientManager.SetAuthenticated(clientAddr, true)

	sendAuthResponse(clientAddr, true, session.NATPort)
}

// handleDataPacket processes VPN data packets
func handleDataPacket(payload []byte, clientAddr *net.UDPAddr) {
	// Check if client is authenticated
	session, exists := ClientManager.GetClient(clientAddr)
	if !exists {
		fmt.Printf("Data packet from unknown client %s - ignored\n", clientAddr.String())
		return
	}

	if !session.Authenticated {
		fmt.Printf("Data packet from unauthenticated client %s - ignored\n", clientAddr.String())
		return
	}

	// Update stats
	ClientManager.UpdateLastSeen(clientAddr)
	ClientManager.AddBytesRecv(clientAddr, uint64(len(payload)))

	fmt.Printf("Data packet from %s (NAT Port: %d): %d bytes\n",
		clientAddr.String(), session.NATPort, len(payload))

	// Forward packet to the raw Socket or TUN interface
}

// handlePingPacket processes keep-alive pings
func handlePingPacket(payload []byte, clientAddr *net.UDPAddr) {
	// Check if client is authenticated
	session, exists := ClientManager.GetClient(clientAddr)
	if !exists || !session.Authenticated {
		fmt.Printf("Ping from unauthenticated client %s - ignored\n", clientAddr.String())
		return
	}

	ClientManager.UpdateLastSeen(clientAddr)
	sendPongPacket(clientAddr)
}

// handleDisconnectPacket processes disconnect requests
func handleDisconnectPacket(payload []byte, clientAddr *net.UDPAddr) {
	fmt.Printf("Disconnect request from %s\n", clientAddr.String())
	ClientManager.RemoveClient(clientAddr)
}

// sendAuthResponse sends authentication response to client
func sendAuthResponse(addr *net.UDPAddr, success bool, natPort int) {
	var response []byte

	if success {
		// Success response with NAT port
		response = make([]byte, 5)
		response[0] = byte(PacketTypeAuthRespPass)
		// Pack NAT port (4 bytes, big endian)
		response[1] = byte(natPort >> 24)
		response[2] = byte(natPort >> 16)
		response[3] = byte(natPort >> 8)
		response[4] = byte(natPort)
	} else {
		// Failure response
		response = []byte{byte(PacketTypeAuthRespFail)}
	}

	_, err := udpConn.WriteToUDP(response, addr)
	if err != nil {
		fmt.Printf("Failed to send auth response to %s: %v\n", addr.String(), err)
	} else {
		if success {
			fmt.Printf("Auth success sent to %s (NAT Port: %d)\n", addr.String(), natPort)
		} else {
			fmt.Printf("Auth failure sent to %s\n", addr.String())
		}
	}
}

// sendPongPacket sends pong response to client
func sendPongPacket(addr *net.UDPAddr) {
	packet := []byte{byte(PacketTypePong)}
	_, err := udpConn.WriteToUDP(packet, addr)
	if err != nil {
		fmt.Printf("Failed to send pong to %s: %v\n", addr.String(), err)
	}
}

// SendToClient sends raw data to a client (utility function)
func SendToClient(addr *net.UDPAddr, data []byte) error {
	_, err := udpConn.WriteToUDP(data, addr)
	if err != nil {
		return fmt.Errorf("failed to send to client %s: %w", addr.String(), err)
	}
	return nil
}

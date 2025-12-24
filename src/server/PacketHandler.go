//go:build linux
// +build linux

package server

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
	PacketTypeAskForIP     PacketType = 0x08 // Request for IP address
	PacketTypeIPRes        PacketType = 0x09 // IP address response
)

// VPNPacket represents a VPN protocol packet
type VPNPacket struct {
	Type    PacketType
	Payload []byte
}

// HandlePacket processes incoming packets from clients
func HandlePacket(data []byte, clientAddr net.Addr) {
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
	case PacketTypeAskForIP:
		handleAskForIPPacket(payload, clientAddr)
	default:
		fmt.Printf("Unknown packet type 0x%02x from %s\n", packetType, clientAddr.String())
	}
}

// handleAuthPacket processes authentication requests
func handleAuthPacket(payload []byte, clientAddr net.Addr) {
	fmt.Printf("Auth request from %s\n", clientAddr.String())

	session, exists := ClientManager.GetClient(clientAddr)
	if !exists {
		fmt.Printf("Session not found for %s\n", clientAddr.String())
		sendAuthResponse(clientAddr, false, nil)
		return
	}

	// Convert payload to string
	receivedPassword := string(payload)
	if receivedPassword != ServerCfg.Password {
		fmt.Printf("Authentication failed for %s: incorrect password\n", clientAddr.String())
		sendAuthResponse(clientAddr, false, nil)
		return
	}

	// Mark session as authenticated
	ClientManager.SetAuthenticated(clientAddr, true)

	sendAuthResponse(clientAddr, true, session.AssignedIP)
}

// handleDataPacket processes VPN data packets
func handleDataPacket(payload []byte, clientAddr net.Addr) {
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

	fmt.Printf("Data packet from %s (Assigned IP: %s): %d bytes\n",
		clientAddr.String(), session.AssignedIP.String(), len(payload))

	// Forward packet to the TUN interface
	err := tunManager.ForwardFromClient(payload, session.AssignedIP)
	if err != nil {
		fmt.Printf("Failed to forward packet from %s: %v\n", clientAddr.String(), err)
	}
}

// handlePingPacket processes keep-alive pings
func handlePingPacket(payload []byte, clientAddr net.Addr) {
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
func handleDisconnectPacket(payload []byte, clientAddr net.Addr) {
	fmt.Printf("Disconnect request from %s\n", clientAddr.String())
	ClientManager.RemoveClient(clientAddr)
}

// handleAskForIPPacket processes IP address requests
func handleAskForIPPacket(payload []byte, clientAddr net.Addr) {
	// Check if client is authenticated
	session, exists := ClientManager.GetClient(clientAddr)
	if !exists || !session.Authenticated {
		fmt.Printf("IP request from unauthenticated client %s - ignored\n", clientAddr.String())
		return
	}

	fmt.Printf("IP request from %s\n", clientAddr.String())

	sendIPResponse(clientAddr, session.AssignedIP)
}

// sendAuthResponse sends authentication response to client
func sendAuthResponse(addr net.Addr, success bool, assignedIP net.IP) {
	var response []byte

	if success {
		// Convert IP to 4-byte format
		ip4 := assignedIP.To4()
		if ip4 == nil {
			fmt.Printf("Invalid IP address format\n")
			return
		}

		// Success response with assigned IP (5 bytes total)
		response = make([]byte, 5)
		response[0] = byte(PacketTypeAuthRespPass)
		response[1] = ip4[0] // First octet (10)
		response[2] = ip4[1] // Second octet (8)
		response[3] = ip4[2] // Third octet (0)
		response[4] = ip4[3] // Fourth octet (e.g., 2, 3, 4...)
	} else {
		// Failure response
		response = []byte{byte(PacketTypeAuthRespFail)}
	}

	// Use ClientManager to write to client
	err := ClientManager.WriteToClient(addr, response)
	if err != nil {
		fmt.Printf("Failed to send auth response to %s: %v\n", addr.String(), err)
	} else {
		if success {
			fmt.Printf("Auth success sent to %s (Assigned IP: %s)\n", addr.String(), assignedIP.String())
		} else {
			fmt.Printf("Auth failure sent to %s\n", addr.String())
		}
	}
}

// sendPongPacket sends pong response to client
func sendPongPacket(addr net.Addr) {
	packet := []byte{byte(PacketTypePong)}

	err := ClientManager.WriteToClient(addr, packet)
	if err != nil {
		fmt.Printf("Failed to send pong to %s: %v\n", addr.String(), err)
	}
}

// sendIPResponse sends IP address response to client
func sendIPResponse(addr net.Addr, assignedIP net.IP) {
	// Convert to 4-byte format
	ip4 := assignedIP.To4()
	if ip4 == nil {
		fmt.Printf("Invalid IP address format\n")
		return
	}

	// Response: [PacketType][IP byte 1][IP byte 2][IP byte 3][IP byte 4]
	response := make([]byte, 5)
	response[0] = byte(PacketTypeIPRes)
	response[1] = ip4[0]
	response[2] = ip4[1]
	response[3] = ip4[2]
	response[4] = ip4[3]

	err := ClientManager.WriteToClient(addr, response)
	if err != nil {
		fmt.Printf("Failed to send IP response to %s: %v\n", addr.String(), err)
	} else {
		fmt.Printf("IP response sent to %s: %s\n", addr.String(), assignedIP.String())
	}
}

// SendToClient sends raw data to a client (utility function)
func SendToClient(addr net.Addr, data []byte) error {
	return ClientManager.WriteToClient(addr, data)
}

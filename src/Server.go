package src

import (
	"fmt"
	"net"

	"github.com/varun0310t/VPN/internal/config"
)

var (
	ServerCfg     *config.ServerConfig
	udpConn       *net.UDPConn
	ClientManager *Manager
)

func InitServer() error {
	var err error
	ServerCfg, err = config.LoadServerConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Start UDP listener
	addr := fmt.Sprintf("%s:%d", ServerCfg.ListenAddress, ServerCfg.ListenPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %w", err)
	}

	ClientManager, err = NewManager()
	if err != nil {
		return fmt.Errorf("failed to create client manager: %w", err)
	}

	fmt.Printf("VPN Server started on %s\n", addr)
	fmt.Printf("Max clients: %d\n", ServerCfg.MaxClients)

	// TODO: Initialize TUN interface
	// TODO: Setup routing

	return nil
}

// Run starts the main server loop (call this to start accepting connections)
func Run() error {
	if udpConn == nil {
		return fmt.Errorf("server not initialized, call InitServer() first")
	}

	buffer := make([]byte, 65535)

	for {
		n, clientAddr, err := udpConn.ReadFromUDP(buffer)
		_ = clientAddr
		if err != nil {
			fmt.Printf("Error reading UDP packet: %v\n", err)
			continue
		}

		// Copy data for goroutine
		dataCopy := make([]byte, n)
		copy(dataCopy, buffer[:n])

		ClientManager.GetOrAddClient(clientAddr)

		// Handle each client packet in separate goroutine
		//go handleClientPacket(dataCopy, clientAddr)
	}
}

func StopServer() error {
	if udpConn != nil {
		fmt.Println("Shutting down VPN server...")
		return udpConn.Close()
	}
	return nil
}

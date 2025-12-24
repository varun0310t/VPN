//go:build linux
// +build linux

package server

import (
	"fmt"
	"net"

	"github.com/pion/dtls/v2"
	"github.com/varun0310t/VPN/internal/config"
)

var (
	ServerCfg     *config.ServerConfig
	udpConn       *net.UDPConn
	dtlsConn      net.Listener
	ClientManager *Manager
	tunManager    *TunManager
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

	// udpConn, err = net.ListenUDP("udp", udpAddr)
	// if err != nil {
	// 	return fmt.Errorf("failed to start UDP listener: %w", err)
	// }

	//wrap with dtls

	dtlsConfig, err := LoadDtlsConfig(ServerCfg)
	if err != nil {
		return fmt.Errorf("failed to load DTLS config: %w", err)
	}

	dtlsConn, err = dtls.Listen("udp", udpAddr, dtlsConfig)

	if err != nil {
		return fmt.Errorf("failed to start DTLS listener: %w", err)
	}

	ClientManager, err = NewManager()
	if err != nil {
		return fmt.Errorf("failed to create client manager: %w", err)
	}
	tunManager, err = NewTunManager(ServerCfg.TunDevice, ServerCfg.TunIP, ServerCfg.TunSubnet, ServerCfg.OutgoingInterface)
	if err != nil {
		return fmt.Errorf("failed to create TUN manager: %w", err)
	}
	fmt.Printf("VPN Server started on %s\n", addr)
	fmt.Printf("Max clients: %d\n", ServerCfg.MaxClients)

	// TODO: Initialize TUN interface
	// TODO: Setup routing

	return nil
}

// Run starts the main server loop (call this to start accepting connections)
func Run() error {
	if dtlsConn == nil {
		return fmt.Errorf("server not initialized, call InitServer() first")
	}
	tunManager.Start()

	// Accept DTLS connections in a loop
	for {
		// Accept a new encrypted connection
		conn, err := dtlsConn.Accept()
		if err != nil {
			fmt.Printf("Error accepting DTLS connection: %v\n", err)
			continue
		}

		// each client in a separate goroutine
		go handleDTLSClient(conn)
	}
}

func handleDTLSClient(conn net.Conn) {
	defer conn.Close()

	// Get client address
	clientAddr := conn.RemoteAddr()
	fmt.Printf("New encrypted connection from: %s\n", clientAddr)

	ClientManager.AddClient(clientAddr.(*net.UDPAddr), conn)

	buffer := make([]byte, 65535)

	// Read packets from this specific client connection
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Printf("Client %s disconnected: %v\n", clientAddr, err)
			return
		}

		// Copy data for handling
		dataCopy := make([]byte, n)
		copy(dataCopy, buffer[:n])

		// Handle packet (you'll need to adapt this to work with net.Conn)
		go HandlePacket(dataCopy, clientAddr)
	}
}

func StopServer() error {
	if udpConn != nil {
		fmt.Println("Shutting down VPN server...")
		return udpConn.Close()
	}
	return nil
}

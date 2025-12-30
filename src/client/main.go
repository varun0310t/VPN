//go:build linux
// +build linux

package client

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var (
	vpnClient *VPNClient
	ClientCfg *ClientConfig
	Password  string
)

func InitClient(serverAddr string, serverPort int, password string) error {
	var err error
	Password = password
	vpnClient, err = NewVPNClient(serverAddr, serverPort)
	if err != nil {
		return fmt.Errorf("failed to create VPN client: %w", err)
	}

	ClientCfg, err = loadClientConfig()
	if err != nil {
		return fmt.Errorf("failed to load client config: %w", err)
	}

	// Save original network configuration
	err = vpnClient.SaveNetworkConfig()
	if err != nil {
		return fmt.Errorf("failed to save network config: %w", err)
	}

	fmt.Printf(" VPN Client initialized\n")
	fmt.Printf("Server: %s:%d\n", serverAddr, serverPort)
	return nil
}

func Connect() error {
	if vpnClient == nil {
		return fmt.Errorf("client not initialized, call InitClient() first")
	}

	err := vpnClient.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	signal.Ignore(syscall.SIGPIPE)
	// Setup signal handlers for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n Shutting down VPN client")
		Disconnect()
		os.Exit(0)
	}()

	return nil
}

func Disconnect() error {
	if vpnClient == nil {
		return nil
	}

	fmt.Println("Disconnecting from VPN...")
	return vpnClient.Disconnect()
}

//go:build windows
// +build windows

// build windows
package windowsclient

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var (
	vpnClient *VPNClient
	ClientCfg *ClientConfig
)

func InitClient(serverAddr string, serverPort int, password string) error {
	var err error

	ClientCfg, err = loadClientConfig()
	if err != nil {
		return fmt.Errorf("failed to load client config: %w", err)
	}

	vpnClient, err = NewVPNClient(serverAddr, serverPort, password)
	if err != nil {
		return fmt.Errorf("failed to create VPN client: %w", err)
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

func Disconnect() {
	if vpnClient == nil {
		return
	}

	fmt.Println("Disconnecting from VPN...")
	vpnClient.Disconnect()
}

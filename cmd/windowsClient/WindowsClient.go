//go:build windows
// +build windows

// go:build windows
package main

import (
	"flag"
	"fmt"
	"os"

	windowsclient "github.com/varun0310t/VPN/src/windows-client"
)

func main() {
	// Parse command line flags
	serverAddr := flag.String("server", "127.0.0.1", "VPN server IP address")
	serverPort := flag.Int("port", 8080, "VPN server port")
	password := flag.String("password", "", "VPN password")
	flag.Parse()

	fmt.Println("🔌 VPN Client Starting...")
	fmt.Printf("Server: %s:%d\n", *serverAddr, *serverPort)

	// Initialize client
	err := windowsclient.InitClient(*serverAddr, *serverPort, *password)
	if err != nil {
		fmt.Printf("Failed to initialize client: %v\n", err)
		os.Exit(1)
	}

	// Connect to VPN
	err = windowsclient.Connect()
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		windowsclient.Disconnect()
		os.Exit(1)
	}

	// Keep running
	select {}
}

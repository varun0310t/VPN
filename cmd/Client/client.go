//go:build linux
// +build linux

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/varun0310t/VPN/src/client"
)

func main() {
	// Parse command line flags
	serverAddr := flag.String("server", "127.0.0.1", "VPN server IP address")
	serverPort := flag.Int("port", 8080, "VPN server port")
	flag.Parse()

	fmt.Println("🔌 VPN Client Starting...")
	fmt.Printf("Server: %s:%d\n", *serverAddr, *serverPort)

	// Initialize client
	err := client.InitClient(*serverAddr, *serverPort)
	if err != nil {
		fmt.Printf("❌ Failed to initialize client: %v\n", err)
		os.Exit(1)
	}

	// Connect to VPN
	err = client.Connect()
	if err != nil {
		fmt.Printf("❌ Failed to connect: %v\n", err)
		client.Disconnect()
		os.Exit(1)
	}

	// Keep running
	select {}
}

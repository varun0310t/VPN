package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/varun0310t/VPN/internal/tunnel"
)

var (
	VPN_SERVER_HOST = "127.0.0.1"
	VPN_SERVER_PORT = "8080"
)

func main() {
	fmt.Print("Starting the VPN client...")
	ifce := tunnel.CreateTUN()

	signChan := make(chan os.Signal, 1)
	signal.Notify(signChan, syscall.SIGINT, syscall.SIGTERM)

	defer func() {
		fmt.Printf("\nCleaning up the mess...")
		tunnel.RestoreOriginalRoute()
		ifce.Close()
		fmt.Print("Routes restored - internet should work now")
	}()

	tunnel.SetDefaultRoute()

	// Connect to VPN server
	fmt.Printf("Connecting to VPN server at %s:%s...\n", VPN_SERVER_HOST, VPN_SERVER_PORT)
	serverConn, err := connectToVPNServer()
	if err != nil {
		fmt.Printf("Failed to connect to the server: %v\n", err)
		return
	}
	defer serverConn.Close()
	fmt.Println("Connected to VPN server successfully!")

	buffer := make([][]byte, 1)
	buffer[0] = make([]byte, 1500)
	count := 0
	lengths := make([]int, 1)

	fmt.Println("VPN active - forwarding packets...")

	for {
		select {
		case <-signChan:
			fmt.Printf("\nProcessed %d packets. Shutting down...\n", count)
			return

		default:
			n, err := ifce.Read(buffer, lengths, 0)
			if err != nil {
				continue
			}

			if n > 0 {
				count++
				packet := buffer[0][:lengths[0]]

				// Analyze the packet
				if len(packet) >= 20 { // Minimum IP header
					version := packet[0] >> 4
					if version == 4 {
						// Extract destination IP
						destIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])
						protocol := packet[9]

						protocolName := "Unknown"
						switch protocol {
						case 1:
							protocolName = "ICMP"
						case 6:
							protocolName = "TCP"
						case 17:
							protocolName = "UDP"
						}

						// Show progress occasionally (not every packet)
						if count%200 == 0 {
							fmt.Printf("Forwarded %d packets (latest: %s to %s)\n",
								count, protocolName, destIP)
						}

						// Forward packet to server with error handling
						err = forwardPacketToServer(serverConn, packet)
						if err != nil {
							fmt.Printf("Failed to forward packet %d: %v\n", count, err)
							// Could implement reconnection logic here
							continue
						}
					}
				}
			}
		}
	}
}

func connectToVPNServer() (net.Conn, error) {
	serverAddr := VPN_SERVER_HOST + ":" + VPN_SERVER_PORT
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", serverAddr, err)
	}
	return conn, nil
}

func forwardPacketToServer(conn net.Conn, packet []byte) error {
	packetLen := len(packet)
	lengthBytes := []byte{
		byte(packetLen >> 24),
		byte(packetLen >> 16),
		byte(packetLen >> 8),
		byte(packetLen),
	}
	//first we send length
	_, err := conn.Write(lengthBytes)
	if err != nil {
		return fmt.Errorf("failed to send packet length: %v", err)
	}

	//Send actual packet
	_, err = conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to send packet data: %v", err)
	}

	return nil
}

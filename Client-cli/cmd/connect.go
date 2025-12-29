//go:build linux
// +build linux

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	serverIP   string
	serverPort int
	secretKey  string
)

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Start the VPN tunnel",
	Run: func(cmd *cobra.Command, args []string) {

		if serverIP == "" {
			fmt.Println("No server IP provided. Using the Ip provided in the configFile.")
			// load from config file logic
		}
		if serverPort == 0 {
			fmt.Println("No server port provided. Using the Port provided in the configFile.")
			// load from config file logic
		}
		if secretKey == "" {
			fmt.Println("No secret key provided. Using the Key provided in the configFile.")
			// load from config file logic
		}
		fmt.Printf("Connecting to %s...\n", serverIP)
		fmt.Println("[Mycelium] Roots extending...")

		// Build the path to the core binary
		exe, _ := os.Executable()
		clientBin := filepath.Join(filepath.Dir(exe), "mycelium-client")

		//execute the client vpn connection here

		proc := exec.Command(clientBin, "--server", serverIP, "--port", fmt.Sprintf("%d", serverPort))
		proc.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true, //  CRITICAL. It creates a new session ID.
			// If don't do this, closing the terminal kills the VPN.
		}
		err := proc.Start()
		if err != nil {
			fmt.Printf("Failed to start VPN client: %v\n", err)
			return
		}
		//save the process id to a file
		pid := proc.Process.Pid
		err = os.WriteFile("vpn_client.pid", []byte(fmt.Sprintf("%d", pid)), 0644)
		if err != nil {
			fmt.Printf("Failed to write PID file: %v\n", err)
			return
		}

	},
}

func init() {
	rootCmd.AddCommand(connectCmd)
	connectCmd.Flags().StringVarP(&serverIP, "server", "s", "", "Server IP Address")
	connectCmd.Flags().IntVarP(&serverPort, "port", "p", 8080, "Server Port")
	connectCmd.Flags().StringVarP(&secretKey, "key", "k", "", "Secret Key")
	connectCmd.MarkFlagRequired("server")
}

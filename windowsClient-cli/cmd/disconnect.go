package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
)

var disconnectCmd = &cobra.Command{
	Use:   "disconnect",
	Short: "Disconnect from the VPN",
	Run: func(cmd *cobra.Command, args []string) {
		// Get binary directory
		exe, err := os.Executable()
		if err != nil {
			fmt.Printf("Failed to get executable path: %v\n", err)
			return
		}
		binaryDir := filepath.Dir(exe)
		pidFile := filepath.Join(binaryDir, "vpn_client.pid")

		// Read PID File
		data, err := os.ReadFile(pidFile)
		if os.IsNotExist(err) {
			fmt.Println("Mycelium is not running (PID file not found).")
			return
		} else if err != nil {
			fmt.Printf("Error reading PID file: %v\n", err)
			return
		}

		// Parse PID
		pid, err := strconv.Atoi(string(data))
		if err != nil {
			fmt.Println("Invalid PID found. Cleaning up...")
			os.Remove(pidFile)
			return
		}

		// Find Process
		process, err := os.FindProcess(pid)
		if err != nil {
			fmt.Println("Process not found. Cleaning up stale PID file.")
			os.Remove(pidFile)
			return
		}

		// Kill the Process
		err = process.Kill()
		if err != nil {

			fmt.Println("Process was already dead or could not be stopped.")
			os.Remove(pidFile)
			return
		}

		//. Cleanup
		os.Remove(pidFile)
		fmt.Println("Mycelium VPN disconnected successfully.")
	},
}

func init() {
	rootCmd.AddCommand(disconnectCmd)
}

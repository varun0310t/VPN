package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"
)

var disconnectCmd = &cobra.Command{
	Use:   "disconnect",
	Short: "Disconnect from the VPN",
	Run: func(cmd *cobra.Command, args []string) {
		// Get the directory of the currently running binary
		exe, err := os.Executable()
		if err != nil {
			fmt.Printf("Failed to get executable path: %v\n", err)
			return
		}
		binaryDir := filepath.Dir(exe)
		pidFile := filepath.Join(binaryDir, "vpn_client.pid")

		// Check if the PID file exists
		data, err := os.ReadFile(pidFile)
		if os.IsNotExist(err) {
			fmt.Println("Mycelium is not running (PID file not found).")
			return
		} else if err != nil {
			fmt.Printf("Error reading PID file: %v\n", err)
			return
		}

		// Parse the PID from the file
		pid, err := strconv.Atoi(string(data))
		if err != nil {
			fmt.Println("Invalid PID found in file. Cleaning up...")
			os.Remove(pidFile)
			return
		}

		// Find the process
		process, err := os.FindProcess(pid)
		if err != nil {
			fmt.Printf("Error finding process: %v\n", err)
			return
		}

		// Check if the process is actually alive (Signal 0 trick)
		if err := process.Signal(syscall.Signal(0)); err != nil {
			fmt.Println("Process was already dead. Cleaning up stale PID file.")
			os.Remove(pidFile)
			return
		}

		// Send the Kill Signal (SIGTERM)
		err = process.Signal(syscall.SIGTERM)
		if err != nil {
			fmt.Printf("Failed to stop process: %v\n", err)
			return
		}

		// Cleanup
		os.Remove(pidFile)
		fmt.Println("Mycelium VPN disconnected successfully.")
	},
}

func init() {
	rootCmd.AddCommand(disconnectCmd)
}

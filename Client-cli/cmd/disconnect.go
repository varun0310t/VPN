package cmd

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"
)

var disconnectCmd = &cobra.Command{
	Use:   "disconnect",
	Short: "Disconnect from the VPN",
	Run: func(cmd *cobra.Command, args []string) {
		pidFile := "vpn_client.pid"

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

		//  Find the process
		// Note On Unix, FindProcess always succeeds, it doesn't check if the process actually exists yet.
		process, err := os.FindProcess(pid)
		if err != nil {
			fmt.Printf("Error finding process: %v\n", err)
			return
		}

		// Check if the process is actually alive (Signal 0 trick)
		// Sending signal 0 doesn't kill it, but returns an error if the process is gone.
		if err := process.Signal(syscall.Signal(0)); err != nil {
			fmt.Println("Process was already dead. Cleaning up stale PID file.")
			os.Remove(pidFile)
			return
		}

		// Send the Kill Signal (SIGTERM)
		// SIGTERM is the polite way to ask a program to stop (allows it to close connections/files).
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

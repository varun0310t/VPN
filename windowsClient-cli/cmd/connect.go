//go:build windows
// +build windows

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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

		// --- Config Loading Logic (Simplified) ---
		if serverIP == "" {

			fmt.Println("No server IP provided. Using config file...")
		}
		if serverPort == 0 {

			fmt.Println("No server port provided. Using config file...")
		}
		if secretKey == "" {

			fmt.Println("No secret key provided. Using config file...")
		}

		fmt.Printf("Connecting to %s...\n", serverIP)
		fmt.Println("[Mycelium] Roots extending...")

		// Locate the Binary
		exe, _ := os.Executable()
		clientBin := filepath.Join(filepath.Dir(exe), "mycelium-client.exe")

		// first check if process is already running by checking for pid file
		pidFilePath := filepath.Join(filepath.Dir(exe), "vpn_client.pid")

		if _, err := os.Stat(pidFilePath); err == nil {
			fmt.Println("VPN client is already running. Please disconnect first.")
			return
		}

		// Prepare the Command
		proc := exec.Command(clientBin, "--server", serverIP, "--port", fmt.Sprintf("%d", serverPort), "--password", secretKey)

		// Critical: CreationFlags allows the child to survive after this CLI tool exits
		proc.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x08000000,
		}
		//  Setup Pipes to listen for the "Success" message
		stdout, err := proc.StdoutPipe()
		if err != nil {
			fmt.Printf("Failed to capture stdout: %v\n", err)
			return
		}
		stderr, err := proc.StderrPipe()
		if err != nil {
			fmt.Printf("Failed to capture stderr: %v\n", err)
			return
		}

		// Start the Process
		if err := proc.Start(); err != nil {
			fmt.Printf("Failed to start VPN client: %v\n", err)
			return
		}

		// Create a Channel to listen for the specific success signal
		// We make it buffered (size 1) so the goroutine doesn't block if we exit early
		successChan := make(chan bool, 1)

		// Scanner for STDOUT
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				rawLine := scanner.Text()

				// Trim invisible whitespace (spaces, tabs, newlines)
				line := strings.TrimSpace(rawLine)
				fmt.Printf(" %s\n", line)
				// Check for your specific success message

				if line == "VPN connection established!" {
					successChan <- true
					return
				}
			}
		}()

		// Scanner for STDERR (Just for logging)
		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				// logs in the file in the future
				fmt.Printf("error: %s\n", scanner.Text())
			}
		}()

		// Wait for Success OR Timeout
		// This blocks the CLI until we know it worked
		select {
		case <-successChan:
			// Success! We received the signal.
			fmt.Println("VPN connection established successfully!")

		case <-time.After(10 * time.Second):
			// Timeout! It took too long.
			// Note: The process might still be trying to connect, or it might have failed silently.
			// You can choose to kill it here, or just warn the user.
			fmt.Println("Warning: Connection timed out waiting for confirmation.")
			fmt.Println("The background process is still running. Check logs.")
			// Check if the process is actually alive (Signal 0 trick)
			proc.Process.Kill()
			time.Sleep(10 * time.Second)
			return
		}

		// Save PID and Exit

		pid := proc.Process.Pid
		binaryDir := filepath.Dir(exe)
		pidFilePath = filepath.Join(binaryDir, "vpn_client.pid")

		if err := os.WriteFile(pidFilePath, []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
			fmt.Printf("Failed to write PID file: %v\n", err)
			return
		}

		fmt.Printf("VPN is running in background (PID: %d)\n", pid)
		// Function returns here, CLI exits, but VPN Process (Setsid) stays alive.
	},
}

func init() {
	rootCmd.AddCommand(connectCmd)
	connectCmd.Flags().StringVarP(&serverIP, "server", "s", "", "Server IP Address")
	connectCmd.Flags().IntVarP(&serverPort, "port", "p", 8080, "Server Port")
	connectCmd.Flags().StringVarP(&secretKey, "key", "k", "", "Secret Key")

	// I commented this out because you have logic to load from config if flags are missing.
	// If you require flags, uncomment it.
	// connectCmd.MarkFlagRequired("server")
}

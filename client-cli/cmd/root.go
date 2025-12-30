package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "mycelium",
	Short: "lightweight VPN client",
	Long: `Mycelium is a high-performance VPN for secure, private connections.
Use 'mycelium connect' to start a tunnel.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

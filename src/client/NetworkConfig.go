//go:build linux
// +build linux

package client

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

// NetworkConfig stores original network configuration to restore on disconnect
type NetworkConfig struct {
	DefaultGateway string
	DefaultIface   string
	OriginalRoutes []string
	VPNRoutes      []string
}

func NewNetworkConfig() *NetworkConfig {
	return &NetworkConfig{
		OriginalRoutes: make([]string, 0),
		VPNRoutes:      make([]string, 0),
	}
}

// Save captures current network configuration
func (nc *NetworkConfig) Save() error {
	fmt.Println("💾 Saving current network configuration...")

	// Save current routes
	cmd := exec.Command("ip", "route", "show")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get routes: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		nc.OriginalRoutes = append(nc.OriginalRoutes, scanner.Text())
	}

	fmt.Printf("✅ Saved %d routes\n", len(nc.OriginalRoutes))
	return nil
}

// SaveDefaultGateway captures the default gateway before modifying routes
func (nc *NetworkConfig) SaveDefaultGateway() error {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get default gateway: %w", err)
	}

	routeLine := strings.TrimSpace(string(output))
	if routeLine == "" {
		return fmt.Errorf("no default gateway found")
	}

	// Parse: "default via 192.168.1.1 dev eth0"
	parts := strings.Fields(routeLine)
	for i, part := range parts {
		if part == "via" && i+1 < len(parts) {
			nc.DefaultGateway = parts[i+1]
		}
		if part == "dev" && i+1 < len(parts) {
			nc.DefaultIface = parts[i+1]
		}
	}

	if nc.DefaultGateway == "" {
		return fmt.Errorf("failed to parse default gateway")
	}

	fmt.Printf("✅ Default gateway: %s via %s\n", nc.DefaultGateway, nc.DefaultIface)
	return nil
}

// AddVPNRoutes sets up routing to send traffic through VPN
func (nc *NetworkConfig) AddVPNRoutes(serverIP string, tunIface string) error {
	// 1. Add specific route for VPN server through original gateway
	//    (so VPN traffic itself doesn't go through VPN)
	if nc.DefaultGateway != "" && nc.DefaultIface != "" {
		cmd := exec.Command("ip", "route", "add", serverIP, "via", nc.DefaultGateway, "dev", nc.DefaultIface)
		output, err := cmd.CombinedOutput()
		if err != nil && !strings.Contains(string(output), "File exists") {
			return fmt.Errorf("failed to add server route: %w (output: %s)", err, string(output))
		}
		nc.VPNRoutes = append(nc.VPNRoutes, fmt.Sprintf("%s via %s dev %s", serverIP, nc.DefaultGateway, nc.DefaultIface))
		fmt.Printf("✅ Route to VPN server via original gateway\n")
	}

	// 2. Change default route to go through VPN
	// First, delete old default route
	cmd := exec.Command("ip", "route", "del", "default")
	_ = cmd.Run() // Ignore errors

	// Add new default route through VPN
	cmd = exec.Command("ip", "route", "add", "default", "dev", tunIface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add default VPN route: %w (output: %s)", err, string(output))
	}
	nc.VPNRoutes = append(nc.VPNRoutes, fmt.Sprintf("default dev %s", tunIface))
	fmt.Printf("✅ Default route now goes through %s\n", tunIface)

	return nil
}

// Restore returns network configuration to original state
func (nc *NetworkConfig) Restore() error {
	fmt.Println("🔄 Restoring original network configuration...")

	// Delete VPN routes
	for _, route := range nc.VPNRoutes {
		parts := strings.Fields(route)
		if len(parts) >= 2 {
			cmd := exec.Command("ip", "route", "del", parts[0])
			_ = cmd.Run() // Ignore errors
		}
	}

	// Restore default gateway if we have it
	if nc.DefaultGateway != "" && nc.DefaultIface != "" {
		// Delete any existing default route
		cmd := exec.Command("ip", "route", "del", "default")
		_ = cmd.Run()

		// Add back original default route
		cmd = exec.Command("ip", "route", "add", "default", "via", nc.DefaultGateway, "dev", nc.DefaultIface)
		output, err := cmd.CombinedOutput()
		if err != nil && !strings.Contains(string(output), "File exists") {
			return fmt.Errorf("failed to restore default gateway: %w (output: %s)", err, string(output))
		}
		fmt.Printf("✅ Default gateway restored: %s via %s\n", nc.DefaultGateway, nc.DefaultIface)
	}

	return nil
}

// GetCurrentRoutes returns current routing table (for debugging)
func (nc *NetworkConfig) GetCurrentRoutes() ([]string, error) {
	cmd := exec.Command("ip", "route", "show")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	routes := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		routes = append(routes, scanner.Text())
	}

	return routes, nil
}

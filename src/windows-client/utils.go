package windowsclient

import (
	"fmt"
	"os/exec"
	"strings"
)

func getDefaultGateway() (string, error) {
	// PowerShell Command Explanation:
	// 1. Get-NetRoute: Fetch all routing table entries
	// 2. -DestinationPrefix "0.0.0.0/0": Filter for the "Default Gateway"
	// 3. Sort-Object RouteMetric: Put the "best" connection (lowest cost) first
	// 4. Select-Object -First 1: Pick only the best one
	// 5. -ExpandProperty NextHop: Print only the IP address

	psCommand := `Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop`

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCommand)

	// Windows hides the console window for this command automatically
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get gateway: %v", err)
	}

	// Clean up the output (remove newlines/spaces)
	gatewayIP := strings.TrimSpace(string(output))

	if gatewayIP == "" {
		return "", fmt.Errorf("no default gateway found")
	}

	return gatewayIP, nil
}

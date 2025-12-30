//go:build windows
// +build windows

package windowsclient

import (
	"fmt"
	"log"
	"os/exec"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

type TunManager struct {
	iface          *wintun.Adapter
	Name           string
	ip             string
	DefaultGateway string
	closed         bool
}

func NewTunManager(Name string, ip string) *TunManager {
	guid, err := windows.GUIDFromString("0d38140cf6584aa292bd65bf20000619")

	//Create Adapter
	iface, err := wintun.CreateAdapter(Name, "Wintun", &guid)
	if err != nil {
		panic(err)
	}
	gateway, err := getDefaultGateway()
	if err != nil {
		panic(err)
	}
	tm := &TunManager{
		iface:          iface,
		Name:           Name,
		ip:             ip,
		closed:         false,
		DefaultGateway: gateway,
	}
	err = tm.ConfigureIP()
	if err != nil {
		panic(err)
	}
	err = tm.SetMTU(1420)
	if err != nil {
		panic(err)
	}
	err = tm.SetMetric(5)
	if err != nil {
		panic(err)
	}
	return tm
}

func (tm *TunManager) ConfigureIP() error {
	fmt.Printf("Configuring TUN interface %s with IP %s...\n", tm.Name, tm.ip)

	cmd := exec.Command("netsh", "interface", "ip", "set", "address", fmt.Sprintf("name=%s", tm.Name),
		"source=static", fmt.Sprintf("addr=%s", tm.ip), "mask=255.255.255.0", fmt.Sprintf("gateway=%s", tm.DefaultGateway))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set IP address: %w, output: %s", err, string(output))
	}
	return nil
}

// set MTU for the interface
func (tm *TunManager) SetMTU(mtu int) error {
	log.Printf("Setting MTU to %d for adapter '%s'", mtu, tm.Name)

	cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		fmt.Sprintf("name=\"%s\"", tm.Name),
		fmt.Sprintf("mtu=%d", mtu),
		"store=active",
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set MTU: %s (err: %v)", string(output), err)
	}

	return nil
}

// set Interface Metric(priority) for the interface
func (tm *TunManager) SetMetric(metric int) error {
	log.Printf("Setting Interface Metric to %d for '%s'", metric, tm.Name)

	// Command: netsh interface ipv4 set interface "Mycelium" metric=5
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "interface",
		fmt.Sprintf("name=\"%s\"", tm.Name),
		fmt.Sprintf("metric=%d", metric),
	)

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set metric: %s", string(out))
	}
	return nil
}

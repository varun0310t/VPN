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
	Session        wintun.Session
}

func NewTunManager(Name string, ip string) (*TunManager, error) {
	guid, err := windows.GUIDFromString("{c6dcde62-7346-45e9-88cd-3c8cbce94454}")
	if err != nil {
		return nil, fmt.Errorf("invalid GUID format: %w", err)
	}

	//Create Adapter
	iface, err := wintun.CreateAdapter(Name, "Wintun", &guid)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN adapter: %w", err)
	}
	gateway, err := getDefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("failed to get default gateway: %w", err)
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
		return nil, err
	}
	err = tm.SetMTU(1420)
	if err != nil {
		return nil, err
	}
	err = tm.SetMetric(5)
	if err != nil {
		return nil, err
	}
	tm.Session, err = tm.iface.StartSession(0x800000)
	if err != nil {
		return nil, err
	}
	tm.Session.ReadWaitEvent()

	return tm, nil
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

// write packet to the TUN interface
func (tm *TunManager) WritePacket(packet []byte) error {
	if tm.closed {
		return fmt.Errorf("TUN interface is closed")
	}

	if len(packet) < 20 {
		return fmt.Errorf("packet too small: %d bytes", len(packet))
	}

	packetBuffer, err := tm.Session.AllocateSendPacket(int(len(packet)))
	if err != nil {
		return fmt.Errorf("failed to allocate send packet: %w", err)
	}

	copy(packetBuffer, packet)

	tm.Session.SendPacket(packetBuffer)

	return nil
}

// read packet from the TUN interface
func (tm *TunManager) ReadPacket(buffer []byte) (int, error) {
	if tm.closed {
		return 0, fmt.Errorf("TUN interface is closed")
	}
	packet, err := tm.Session.ReceivePacket()
	if err != nil {
		return 0, fmt.Errorf("failed to read from TUN: %w", err)
	}
	copy(buffer, packet)
	tm.Session.ReleaseReceivePacket(packet)

	return len(packet), nil
}

func (tm *TunManager) Close() error {
	if tm.closed {
		return nil
	}
	tm.closed = true
	tm.Session.End()
	return tm.iface.Close()
}

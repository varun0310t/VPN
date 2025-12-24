//go:build linux
// +build linux

package client

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	TUNSETIFF = 0x400454ca
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
)

type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

type TunManager struct {
	fd     int
	name   string
	ip     string
	closed bool
}

func NewTunManager(tunName string, assignedIP string) (*TunManager, error) {
	// Create TUN interface
	fd, err := syscall.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w (requires root)", err)
	}

	var ifr ifreq
	copy(ifr.name[:], tunName)
	ifr.flags = IFF_TUN | IFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %v", errno)
	}

	fmt.Printf("✅ TUN interface %s created (fd: %d)\n", tunName, fd)

	tm := &TunManager{
		fd:     fd,
		name:   tunName,
		ip:     assignedIP,
		closed: false,
	}

	// Configure the interface
	err = tm.Configure()
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}

	return tm, nil
}

func (tm *TunManager) Configure() error {
	fmt.Printf("Configuring TUN interface %s with IP %s...\n", tm.name, tm.ip)

	// Flush any existing IPs
	cmd := exec.Command("ip", "addr", "flush", "dev", tm.name)
	_ = cmd.Run()

	// Set IP address
	cmd = exec.Command("ip", "addr", "add", tm.ip+"/24", "dev", tm.name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set IP: %w (output: %s)", err, string(output))
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", tm.name, "up")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to bring interface up: %w (output: %s)", err, string(output))
	}

	fmt.Printf("✅ TUN interface configured: %s (%s/24)\n", tm.name, tm.ip)
	return nil
}

func (tm *TunManager) ReadPacket(buffer []byte) (int, error) {
	if tm.closed {
		return 0, fmt.Errorf("TUN interface is closed")
	}

	n, err := syscall.Read(tm.fd, buffer)
	if err != nil {
		return 0, fmt.Errorf("failed to read from TUN: %w", err)
	}

	return n, nil
}

func (tm *TunManager) WritePacket(packet []byte) error {
	if tm.closed {
		return fmt.Errorf("TUN interface is closed")
	}

	if len(packet) < 20 {
		return fmt.Errorf("packet too small: %d bytes", len(packet))
	}

	n, err := syscall.Write(tm.fd, packet)
	if err != nil {
		return fmt.Errorf("failed to write to TUN: %w", err)
	}

	if n != len(packet) {
		return fmt.Errorf("partial write: wrote %d of %d bytes", n, len(packet))
	}

	return nil
}

func (tm *TunManager) Close() error {
	if tm.closed {
		return nil
	}
	tm.closed = true

	// Bring interface down
	cmd := exec.Command("ip", "link", "set", "dev", tm.name, "down")
	_ = cmd.Run()

	// Close file descriptor
	return syscall.Close(tm.fd)
}

// Helper function to parse IP header for debugging
func ParseIPHeader(packet []byte) *IPHeader {
	if len(packet) < 20 {
		return nil
	}

	return &IPHeader{
		SrcIP: net.IPv4(packet[12], packet[13], packet[14], packet[15]),
		DstIP: net.IPv4(packet[16], packet[17], packet[18], packet[19]),
	}
}

type IPHeader struct {
	SrcIP net.IP
	DstIP net.IP
}

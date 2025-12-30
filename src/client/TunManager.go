//go:build linux
// +build linux

package client

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
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
	fd               int
	name             string
	ip               string
	closed           bool
	resolvBackup     string
	resolvWasSymlink bool
	resolvLinkTarget string
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

	fmt.Printf(" TUN interface %s created (fd: %d)\n", tunName, fd)

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

	err = tm.ConfigureDNS()
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}

	return tm, nil
}

func (tm *TunManager) Configure() error {
	fmt.Printf("Configuring TUN interface %s with IP %s...\n", tm.name, tm.ip)

	// Set MTU first
	cmd := exec.Command("ip", "link", "set", "dev", tm.name, "mtu", "1400")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set MTU: %w, output: %s", err, string(output))
	}

	// Flush any existing IPs
	cmd = exec.Command("ip", "addr", "flush", "dev", tm.name)
	_ = cmd.Run()

	// Set IP address
	cmd = exec.Command("ip", "addr", "add", tm.ip+"/24", "dev", tm.name)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set IP: %w (output: %s)", err, string(output))
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", tm.name, "up")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to bring interface up: %w (output: %s)", err, string(output))
	}

	fmt.Printf(" TUN interface configured: %s (%s/24)\n", tm.name, tm.ip)
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

func (tm *TunManager) ConfigureDNS() error {

	dnsServers := []string{"8.8.8.8", "1.1.1.1"}

	// If systemd-resolved's resolvectl is available, use it to set DNS for the interface
	if _, err := exec.LookPath("resolvectl"); err == nil {
		// still back up /etc/resolv.conf so we can restore original state on disconnect
		dst := "/etc/resolv.conf"
		backup := fmt.Sprintf("%s.vpn.bak.%d", dst, time.Now().Unix())
		tm.resolvBackup = backup

		// capture symlink target if any
		if st, err := os.Lstat(dst); err == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				if target, err := os.Readlink(dst); err == nil {
					tm.resolvWasSymlink = true
					tm.resolvLinkTarget = target
				}
			}
		}

		// backup existing file content (follows symlink)
		if data, err := os.ReadFile(dst); err == nil {
			_ = os.WriteFile(backup, data, 0644)
		}

		args := append([]string{"dns", tm.name}, dnsServers...)
		if out, err := exec.Command("resolvectl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("resolvectl dns failed: %w - %s", err, string(out))
		}
		fmt.Printf(" DNS configured via resolvectl for %s\n", tm.name)
		return nil
	}

	// Fallback: update /etc/resolv.conf (backup existing)
	dst := "/etc/resolv.conf"
	backup := fmt.Sprintf("%s.vpn.bak.%d", dst, time.Now().Unix())
	tm.resolvBackup = backup

	// capture symlink target if any
	if st, err := os.Lstat(dst); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			if target, err := os.Readlink(dst); err == nil {
				tm.resolvWasSymlink = true
				tm.resolvLinkTarget = target
			}
		}
	}

	// Read existing file (works even if it's a symlink) and back it up if present
	if data, err := os.ReadFile(dst); err == nil {
		if err := os.WriteFile(backup, data, 0644); err != nil {
			return fmt.Errorf("failed to create backup of %s: %w", dst, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", dst, err)
	}

	// If /etc/resolv.conf is a symlink, remove it so we can write a regular file
	if st, err := os.Lstat(dst); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(dst); err != nil {
				return fmt.Errorf("resolv.conf is a symlink and could not be removed: %w", err)
			}
		}
	}

	// Write new resolv.conf
	content := ""
	for _, s := range dnsServers {
		content += "nameserver " + s + "\n"
	}
	if err := os.WriteFile(dst, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", dst, err)
	}
	fmt.Printf(" DNS configured via /etc/resolv.conf for %s\n", tm.name)
	return nil
}

func (tm *TunManager) RestoreDNS() error {
	dst := "/etc/resolv.conf"

	// If we recorded a backup path, try to restore it
	if tm.resolvBackup != "" {
		// If original was a symlink, restore symlink target
		if tm.resolvWasSymlink && tm.resolvLinkTarget != "" {
			// remove current file/symlink
			_ = os.Remove(dst)
			if err := os.Symlink(tm.resolvLinkTarget, dst); err != nil {
				return fmt.Errorf("failed to recreate symlink %s -> %s: %w", dst, tm.resolvLinkTarget, err)
			}
			_ = os.Remove(tm.resolvBackup)
			tm.resolvBackup = ""
			tm.resolvWasSymlink = false
			tm.resolvLinkTarget = ""
			fmt.Println(" DNS settings restored")
			return nil
		}

		// otherwise restore file contents from backup
		data, err := os.ReadFile(tm.resolvBackup)
		if err != nil {
			return fmt.Errorf("failed to read backup %s: %w", tm.resolvBackup, err)
		}
		_ = os.Remove(dst) // remove current file/symlink if present
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return fmt.Errorf("failed to restore %s from %s: %w", dst, tm.resolvBackup, err)
		}
		_ = os.Remove(tm.resolvBackup)
		tm.resolvBackup = ""
		fmt.Println(" DNS settings restored")
		return nil
	}

	// No recorded backup to restore
	return fmt.Errorf("no resolv.conf backup recorded to restore")
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

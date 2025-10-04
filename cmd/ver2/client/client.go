package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

var MTU = 1500
var tun_peer net.IP
var Interface *water.Interface

func main() {
	Interface, err := newTun("tun0")
	if err != nil {
		fmt.Println("could not create tun")
		return
	}
	ip := net.ParseIP("10.0.0.1")
	_, subnet, err := net.ParseCIDR("10.0.0.0/30")
	if err != nil {
		fmt.Println("bad CIDR:", err)
		return
	}
	if err := setTunIP(Interface, ip, subnet); err != nil {
		fmt.Println("setTunIP:", err)
		return
	}

}

func newTun(name string) (iface *water.Interface, err error) {

	iface, err = water.New(water.Config{DeviceType: 0})
	if err != nil {
		return nil, err
	}
	fmt.Printf("interface %v created\n", iface.Name())

	sargs := fmt.Sprintf("link set dev %s up mtu %d qlen 100", iface.Name(), MTU)
	args := strings.Split(sargs, " ")
	cmd := exec.Command("ip", args...)
	fmt.Printf("ip %s\n", sargs)
	err = cmd.Run()
	if err != nil {
		return nil, err
	}

	return iface, nil
}

func setTunIP(iface *water.Interface, ip net.IP, subnet *net.IPNet) (err error) {
	ip = ip.To4()
	fmt.Println("%v", ip)
	if ip[3]%2 == 0 {
		return nil
	}

	peer := net.IP(make([]byte, 4))
	copy([]byte(peer), []byte(ip))
	peer[3]++
	tun_peer = peer

	sargs := fmt.Sprintf("addr add dev %s local %s peer %s", iface.Name(), ip, peer)
	args := strings.Split(sargs, " ")
	cmd := exec.Command("ip", args...)
	fmt.Println("ip %s", sargs)
	err = cmd.Run()
	if err != nil {
		return err
	}

	sargs = fmt.Sprintf("route add %s via %s dev %s", subnet, peer, iface.Name())
	args = strings.Split(sargs, " ")
	cmd = exec.Command("ip", args...)
	println("ip %s", sargs)
	err = cmd.Run()
	return err
}

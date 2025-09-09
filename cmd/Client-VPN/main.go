package main

import (
	"fmt"

	"github.com/varun0310t/VPN/internal/tunnel"
)

func main() {
	fmt.Print("Starting the vpn server")
	ifce := tunnel.CreateTUN()

	defer func() {
		fmt.Printf("Cleaning up the mess...")
		tunnel.RestoreOriginalRoute()
		ifce.Close()
		fmt.Print("Routes restored - internet should work now")
	}()

	tunnel.SetDefaultRoute()

	// buffer := make([][]byte, 1)
	// buffer[0] = make([]byte, 14000)
	// count := 0
	// len := make([]int, 1)
	// for {
	// 	n, err := ifce.Read(buffer, len, 0)
	// 	if err != nil {
	// 		fmt.Print("something went wrong")
	// 	}
	// 	if n > 0 {
	// 		count++
	// 		fmt.Println(count)
	// 	}
	// }

}

//go:build linux
// +build linux

package main

import (
	"github.com/varun0310t/VPN/src/server"
)

func main() {
	err := server.InitServer()
	if err != nil {
		panic(err)
	}
	err = server.Run()
	if err != nil {
		panic(err)
	}
	select {}
}

package server

import (
	"crypto/tls"

	"github.com/pion/dtls/v2"
	"github.com/varun0310t/VPN/internal/config"
)

func LoadDtlsConfig(ServerCfg *config.ServerConfig) (*dtls.Config, error) {

	cert, err := tls.LoadX509KeyPair("/etc/vpn/server-cert.pem", "/etc/vpn/server-key.pem")

	if err != nil {
		return nil, err
	}

	// Configure DTLS
	config := &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	return config, nil

}

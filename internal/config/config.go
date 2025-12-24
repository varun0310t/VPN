package config

import (
	"encoding/json"
	"os"
)

type ServerConfig struct {
	ListenAddress     string   `json:"listen_address"`
	ListenPort        int      `json:"listen_port"`
	TunIP             string   `json:"tun_ip"`
	TunSubnet         string   `json:"tun_subnet"`
	DNS               []string `json:"dns_servers"`
	MaxClients        int      `json:"max_clients"`
	LogLevel          string   `json:"log_level"`
	TLSEnabled        bool     `json:"tls_enabled"`
	CertFile          string   `json:"cert_file"`
	KeyFile           string   `json:"key_file"`
	IPPoolMin         int      `json:"ip_pool_min"`
	IPPoolMax         int      `json:"ip_pool_max"`
	TunDevice         string   `json:"tun_device"`
	OutgoingInterface string   `json:"outgoing_interface"`
	Password          string   `json:"password"`
}

func LoadServerConfig() (*ServerConfig, error) {
	path := "config/server_config.json"

	data, err := os.ReadFile(path)
	if err != nil {
		// Return default config if file doesn't exist
		if os.IsNotExist(err) {
			return &ServerConfig{
				ListenAddress:     "0.0.0.0",
				ListenPort:        8080,
				TunIP:             "10.8.0.0",
				TunSubnet:         "10.8.0.0/24",
				DNS:               []string{"8.8.8.8", "8.8.4.4"},
				MaxClients:        10,
				LogLevel:          "info",
				TLSEnabled:        true,
				CertFile:          "certs/server.crt",
				KeyFile:           "certs/server.key",
				IPPoolMin:         10,
				IPPoolMax:         255,
				TunDevice:         "tun0",
				OutgoingInterface: "eth0",
				Password:          "VPN1234",
			}, nil
		}
		return nil, err
	}

	var config ServerConfig
	err = json.Unmarshal(data, &config)
	return &config, err
}

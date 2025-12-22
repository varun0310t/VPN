package config

import (
	"encoding/json"
	"os"
)

type ServerConfig struct {
	ListenAddress string   `json:"listen_address"`
	ListenPort    int      `json:"listen_port"`
	TunIP         string   `json:"tun_ip"`
	TunSubnet     string   `json:"tun_subnet"`
	DNS           []string `json:"dns_servers"`
	MaxClients    int      `json:"max_clients"`
	LogLevel      string   `json:"log_level"`
	TLSEnabled    bool     `json:"tls_enabled"`
	CertFile      string   `json:"cert_file"`
	KeyFile       string   `json:"key_file"`
}

type ClientConfig struct {
	ServerAddress string   `json:"server_address"`
	ServerPort    int      `json:"server_port"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	TunIP         string   `json:"tun_ip"`
	DNS           []string `json:"dns_servers"`
	AutoReconnect bool     `json:"auto_reconnect"`
	LogLevel      string   `json:"log_level"`
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config ServerConfig
	err = json.Unmarshal(data, &config)
	return &config, err
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config ClientConfig
	err = json.Unmarshal(data, &config)
	return &config, err
}

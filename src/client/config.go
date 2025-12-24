package client

import (
	"encoding/json"
	"os"
)

type ClientConfig struct {
	Password string `json:"password"`
}

func loadClientConfig() (*ClientConfig, error) {
	path := "config/server_config.json"

	data, err := os.ReadFile(path)
	if err != nil {
		// Return default config if file doesn't exist
		if os.IsNotExist(err) {
			return &ClientConfig{
				Password: "VPN1234",
			}, nil
		}
		return nil, err
	}

	var config ClientConfig
	err = json.Unmarshal(data, &config)
	return &config, err
}

package client

import (
	"encoding/json"
	"fmt"
	"os"
)

type ClientConfig struct {
	PASSWORD   string `json:"PASSWORD"`
	SERVERIP   string `json:"SERVERIP,omitempty"`
	SERVERPORT int    `json:"SERVERPORT,omitempty"`
}

func loadClientConfig() (*ClientConfig, error) {
	// Define multiple paths to search for the config file
	paths := []string{
		"./src/config/ClientConfig.json",    // Relative to the project root
		"/etc/mycelium/ClientConfig.json",   // System-wide config
		"$HOME/.mycelium/ClientConfig.json", // User-specific config
	}

	var data []byte
	var err error

	// Iterate through the paths to find the config file
	for _, path := range paths {
		// Expand environment variables (e.g., $HOME)
		path = os.ExpandEnv(path)

		data, err = os.ReadFile(path)
		if err == nil {
			fmt.Printf("Config file loaded from %s\n", path)
			break
		} else if os.IsNotExist(err) {
			continue // Try the next path if the file doesn't exist
		} else {
			// Return error if it's not a "file not found" error
			return nil, fmt.Errorf("error reading config file at %s: %w", path, err)
		}
	}

	// If no config file was found, return the default config
	if os.IsNotExist(err) {
		fmt.Println("Config file not found in any path, using default config")
		return &ClientConfig{
			PASSWORD:   "VPN1234",
			SERVERIP:   "127.0.0.1",
			SERVERPORT: 8080,
		}, nil
	}

	// Parse the config file
	var config ClientConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	return &config, nil
}

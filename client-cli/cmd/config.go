package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// configCmd represents the base config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration settings",
	Long:  `View or modify the Mycelium client configuration.`,
}

// setCmd represents the "config set" command
var setCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Update a configuration value",
	Example: `  mycelium config set password "MySecretPass"
  mycelium config set server_ip "1.2.3.4"`,
	Args: cobra.ExactArgs(2), // Requires exactly 2 arguments
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		value := args[1]

		if err := updateConfig(key, value); err != nil {
			fmt.Printf("Error updating config: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully updated '%s' to '%s'\n", key, value)
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(setCmd)
}

// Helper function to handle the JSON logic
func updateConfig(key, value string) error {
	//first find the binary locaion the config file is same place
	key = strings.ToUpper(key)
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	configPath := filepath.Dir(exe) + "/ClientConfig.json"

	//Create the file if it doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		emptyJSON := []byte("{}")
		if err := os.WriteFile(configPath, emptyJSON, 0644); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}
	}

	//Read existing file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	//Unmarshal into a generic map
	var config map[string]interface{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("invalid JSON in config file: %w", err)
		}
	} else {
		config = make(map[string]interface{})
	}

	//Update the specific key
	config[key] = value

	//Marshal back to JSON
	updatedData, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	//Write back to disk
	if err := os.WriteFile(configPath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}

package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config represents the application configuration
type Config struct {
	// Logging configuration
	Logging struct {
		// Level is the minimum log level to output (debug, info, warn, error)
		Level string `json:"level"`
		// File is the path to the log file. If empty, logs to stdout only
		File string `json:"file"`
		// MaxSizeMB is the maximum size of log file before rotation
		MaxSizeMB int64 `json:"max_size_mb"`
		// LogRetentionDays is the number of days to keep log files
		LogRetentionDays int `json:"log_retention_days"`
	} `json:"logging"`

	// Capture configuration
	Capture struct {
		// OutputDir is where capture files are stored
		OutputDir string `json:"output_dir"`
		// WindowSeconds is how long each capture runs
		WindowSeconds int `json:"window_seconds"`
		// Loop determines if the agent should run in a continuous loop
		Loop bool `json:"loop"`
		// Interface specifies which network interface to capture from. "any" captures on every interface
		Interface string `json:"interface"`
	} `json:"capture"`

	// Enigma API configuration
	EnigmaAPI struct {
		// Server is the Enigma API server address
		Server string `json:"server"`
		// APIKey is the Enigma API key
		APIKey string `json:"api_key"`
		// Upload is whether to upload captured data to the Enigma API
		Upload bool `json:"upload"`
	} `json:"enigma_api"`

	// Zeek configuration
	Zeek struct {
		// Path is the Zeek executable path
		Path string `json:"path"`
	} `json:"zeek"`
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(configPath string) (*Config, error) {
	// Set default config path if not provided
	if configPath == "" {
		configPath = "config.json"
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse config
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Set defaults if not specified
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}
	if config.Logging.MaxSizeMB == 0 {
		config.Logging.MaxSizeMB = 100 // 100MB default
	}
	if config.Logging.LogRetentionDays == 0 {
		config.Logging.LogRetentionDays = 1 // 1 day default
	}
	if config.EnigmaAPI.Server == "" {
		config.EnigmaAPI.Server = "api.enigmaai.net:443"
	}
	if config.EnigmaAPI.Upload == false {
		config.EnigmaAPI.Upload = false
	}
	if config.Capture.Loop != true {
		config.Capture.Loop = false
	}
	if config.Capture.Interface == "" {
		config.Capture.Interface = "any"
	}
	// Zeek path can be empty by default

	return &config, nil
}

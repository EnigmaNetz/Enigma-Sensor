package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"EnigmaNetz/Enigma-Go-Agent/internal/logger"
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
	} `json:"logging"`

	// Capture configuration
	Capture struct {
		// OutputDir is where capture files are stored
		OutputDir string `json:"output_dir"`
		// IntervalSeconds is how often to run captures
		IntervalSeconds int `json:"interval_seconds"`
		// WindowSeconds is how long each capture runs
		WindowSeconds int `json:"window_seconds"`
	} `json:"capture"`
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
	if config.Capture.IntervalSeconds == 0 {
		config.Capture.IntervalSeconds = 300 // 5 minutes default
	}
	if config.Capture.WindowSeconds == 0 {
		config.Capture.WindowSeconds = 60 // 1 minute default
	}

	return &config, nil
}

// InitializeLogging sets up logging based on config
func (c *Config) InitializeLogging() error {
	// Parse log level
	level, err := logger.ParseLogLevel(c.Logging.Level)
	if err != nil {
		return fmt.Errorf("invalid log level: %v", err)
	}

	// Create log directory if file logging is enabled
	if c.Logging.File != "" {
		logDir := filepath.Dir(c.Logging.File)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %v", err)
		}
	}

	// Initialize logger
	logConfig := logger.Config{
		LogLevel: level,
		LogFile:  c.Logging.File,
		MaxSize:  c.Logging.MaxSizeMB * 1024 * 1024, // Convert MB to bytes
	}

	if err := logger.Initialize(logConfig); err != nil {
		return fmt.Errorf("failed to initialize logger: %v", err)
	}

	return nil
}

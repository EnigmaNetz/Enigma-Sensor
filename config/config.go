package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Config represents the application configuration
type Config struct {
	// SensorID is a user-defined identifier for this sensor (required)
	SensorID string `json:"sensor_id"`

	// Logging configuration
	Logging struct {
		// Level is the minimum log level to output (debug, info, warn, error)
		Level string `json:"level"`
		// File is the path to the log file. If empty, logs to stdout only
		File string `json:"file"`
		// MaxSizeMB is the maximum size of log file before rotation (min 10MB, max 500MB)
		MaxSizeMB int64 `json:"max_size_mb"`
		// LogRetentionDays is the number of days to keep log files (min 1, max 30)
		LogRetentionDays int `json:"log_retention_days"`
		// MaxBackups is the maximum number of old log files to retain (min 1, max 10)
		MaxBackups int `json:"max_backups"`
	} `json:"logging"`

	// Capture configuration
	Capture struct {
		// OutputDir is where capture files are stored
		OutputDir string `json:"output_dir"`
		// WindowSeconds is how long each capture runs
		WindowSeconds int `json:"window_seconds"`
		// Loop determines if the sensor should run in a continuous loop
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
		// MaxPayloadSizeMB is the maximum size of payload before chunking (default: 25MB)
		MaxPayloadSizeMB int64 `json:"max_payload_size_mb"`
	} `json:"enigma_api"`

	// Buffering configuration for local retries during publisher outages
	Buffering struct {
		// Dir is the directory to store buffered payloads
		Dir string `json:"dir"`
		// MaxAgeHours is the maximum age of buffered items before purge
		MaxAgeHours int `json:"max_age_hours"`
	} `json:"buffering"`

	// Zeek configuration
	Zeek struct {
		// Path is the Zeek executable path
		Path string `json:"path"`
		// SamplingPercentage is the percentage of traffic to process (0-100)
		SamplingPercentage float64 `json:"sampling_percentage"`
	} `json:"zeek"`
}

// validateSensorID validates the sensor_id format
// Rules: 1-64 chars, alphanumeric + spaces/hyphens/underscores, must start/end with alphanumeric
func validateSensorID(sensorID string) error {
	sensorID = strings.TrimSpace(sensorID)

	if sensorID == "" {
		return fmt.Errorf("sensor_id is required in config.json")
	}

	if sensorID == "REPLACE_WITH_YOUR_SENSOR_ID" {
		return fmt.Errorf("sensor_id must be set to a real value (not the placeholder from config.example.json)")
	}

	if len(sensorID) > 64 {
		return fmt.Errorf("sensor_id must be 64 characters or less, got %d", len(sensorID))
	}

	// Must start and end with alphanumeric, can contain letters, numbers, spaces, hyphens, underscores
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-_ ]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$`)
	if !validPattern.MatchString(sensorID) {
		return fmt.Errorf("sensor_id must start and end with a letter or number, and can only contain letters, numbers, spaces, hyphens, and underscores")
	}

	return nil
}

// ValidateAndSetDefaults normalizes the configuration and sets defaults
// Returns an error if any explicit values are out of bounds (0/missing values get defaults)
func (config *Config) ValidateAndSetDefaults() error {
	// Validate sensor_id (required, no default)
	if err := validateSensorID(config.SensorID); err != nil {
		return err
	}
	config.SensorID = strings.TrimSpace(config.SensorID)

	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}
	// Validate and set MaxSizeMB with bounds: min 10MB, max 500MB, default 50MB
	if config.Logging.MaxSizeMB == 0 {
		config.Logging.MaxSizeMB = 50 // 50MB default
	} else if config.Logging.MaxSizeMB < 10 {
		return fmt.Errorf("logging.max_size_mb must be at least 10MB, got %d", config.Logging.MaxSizeMB)
	} else if config.Logging.MaxSizeMB > 500 {
		return fmt.Errorf("logging.max_size_mb must be at most 500MB, got %d", config.Logging.MaxSizeMB)
	}
	// Validate and set LogRetentionDays with bounds: min 1, max 30, default 7
	if config.Logging.LogRetentionDays == 0 {
		config.Logging.LogRetentionDays = 7 // 7 days default
	} else if config.Logging.LogRetentionDays < 1 {
		return fmt.Errorf("logging.log_retention_days must be at least 1, got %d", config.Logging.LogRetentionDays)
	} else if config.Logging.LogRetentionDays > 30 {
		return fmt.Errorf("logging.log_retention_days must be at most 30, got %d", config.Logging.LogRetentionDays)
	}
	// Validate and set MaxBackups with bounds: min 1, max 10, default 5
	if config.Logging.MaxBackups == 0 {
		config.Logging.MaxBackups = 5 // 5 backups default
	} else if config.Logging.MaxBackups < 1 {
		return fmt.Errorf("logging.max_backups must be at least 1, got %d", config.Logging.MaxBackups)
	} else if config.Logging.MaxBackups > 10 {
		return fmt.Errorf("logging.max_backups must be at most 10, got %d", config.Logging.MaxBackups)
	}
	if config.EnigmaAPI.Server == "" {
		config.EnigmaAPI.Server = "api.enigmaai.net:443"
	}
	if config.EnigmaAPI.Upload == false {
		config.EnigmaAPI.Upload = false
	}
	if config.EnigmaAPI.MaxPayloadSizeMB == 0 {
		config.EnigmaAPI.MaxPayloadSizeMB = 25 // 25MB default
	}
	if config.Capture.Loop != true {
		config.Capture.Loop = false
	}
	if config.Capture.Interface == "" {
		config.Capture.Interface = "any"
	}
	// Zeek path can be empty by default
	if config.Zeek.SamplingPercentage == 0 {
		config.Zeek.SamplingPercentage = 100 // Default to 100% (process all traffic)
	}
	// Defaults for buffering
	if config.Buffering.Dir == "" {
		config.Buffering.Dir = "logs/buffer"
	}
	if config.Buffering.MaxAgeHours == 0 {
		config.Buffering.MaxAgeHours = 2 // Default to 2 hours retention
	}
	return nil
}

// validateInterfaceName validates that an interface name contains only safe characters
// to prevent command injection attacks when the interface name is passed to system commands
func validateInterfaceName(name string) error {
	// Allow only alphanumeric, dash, underscore, and dot characters
	// This pattern matches common interface naming conventions (eth0, wlan0, en0, etc.)
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9\-_.]+$`)

	if len(name) == 0 {
		return fmt.Errorf("interface name cannot be empty")
	}

	if len(name) > 255 {
		return fmt.Errorf("interface name too long: %d characters (max 255)", len(name))
	}

	if !validPattern.MatchString(name) {
		return fmt.Errorf("interface name contains invalid characters: must contain only letters, numbers, hyphens, underscores, and dots")
	}

	// Additional check for potentially dangerous sequences
	forbidden := []string{"..", "/", "\\", "|", "&", ";", "$", "`", "(", ")", "{", "}", "[", "]", "<", ">", "\"", "'", " ", "\t", "\n", "\r"}
	for _, f := range forbidden {
		if strings.Contains(name, f) {
			return fmt.Errorf("interface name contains forbidden sequence: %s", f)
		}
	}

	return nil
}

// GetFirstInterface returns the first valid interface from comma-separated list, or "any" if empty
func (c *Config) GetFirstInterface() (string, error) {
	if c.Capture.Interface == "" {
		return "any", nil
	}

	// Split by comma and find first non-empty interface
	interfaces := strings.Split(c.Capture.Interface, ",")
	for _, iface := range interfaces {
		trimmed := strings.TrimSpace(iface)
		if trimmed == "" {
			continue
		}

		// Special cases that don't need validation
		if trimmed == "any" || trimmed == "all" {
			return trimmed, nil
		}

		// Validate the interface name for security
		if err := validateInterfaceName(trimmed); err != nil {
			return "", fmt.Errorf("invalid interface '%s': %w", trimmed, err)
		}

		return trimmed, nil
	}

	// If all interfaces are empty, default to "any"
	return "any", nil
}

// GetAllInterfaces returns all valid interfaces from comma-separated list, or ["any"] if empty
func (c *Config) GetAllInterfaces() ([]string, error) {
	if c.Capture.Interface == "" {
		return []string{"any"}, nil
	}

	// Split by comma and collect all valid interfaces
	interfaces := strings.Split(c.Capture.Interface, ",")
	var validInterfaces []string

	for _, iface := range interfaces {
		trimmed := strings.TrimSpace(iface)
		if trimmed == "" {
			continue
		}

		// Special cases that don't need validation
		if trimmed == "any" || trimmed == "all" {
			validInterfaces = append(validInterfaces, trimmed)
			continue
		}

		// Validate the interface name for security
		if err := validateInterfaceName(trimmed); err != nil {
			return nil, fmt.Errorf("invalid interface '%s': %w", trimmed, err)
		}

		validInterfaces = append(validInterfaces, trimmed)
	}

	// If no valid interfaces found, default to "any"
	if len(validInterfaces) == 0 {
		return []string{"any"}, nil
	}

	return validInterfaces, nil
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

	// Normalize and apply defaults in one place
	if err := config.ValidateAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

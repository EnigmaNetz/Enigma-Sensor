package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// newBaseConfig returns a fully populated Config for use in tests.
// Each field has a recognizable non-zero value so we can detect unwanted changes.
func newBaseConfig() Config {
	cfg := Config{}
	cfg.NetworkID = "original-network"
	cfg.Logging.Level = "info"
	cfg.Logging.File = "/var/log/sensor.log"
	cfg.Logging.MaxSizeMB = 50
	cfg.Logging.LogRetentionDays = 7
	cfg.Logging.MaxBackups = 5
	cfg.Capture.OutputDir = "/tmp/capture"
	cfg.Capture.WindowSeconds = 60
	cfg.Capture.Loop = false
	cfg.Capture.Interface = "eth0"
	cfg.EnigmaAPI.Server = "api.enigmaai.net:443"
	cfg.EnigmaAPI.APIKey = "original-key"
	cfg.EnigmaAPI.Upload = true
	cfg.EnigmaAPI.MaxPayloadSizeMB = 25
	cfg.Buffering.Dir = "logs/buffer"
	cfg.Buffering.MaxAgeHours = 2
	cfg.Zeek.Path = "/usr/bin/zeek"
	cfg.Zeek.SamplingPercentage = 100.0
	cfg.PcapIngest.Enabled = false
	cfg.PcapIngest.WatchDir = "/tmp/pcap"
	cfg.PcapIngest.PollIntervalSeconds = 10
	cfg.PcapIngest.FileStableSeconds = 5
	return cfg
}

func TestApplyEnvOverrides_StringTopLevel(t *testing.T) {
	cfg := newBaseConfig()
	t.Setenv("SENSOR_NETWORK_ID", "overridden-network")

	err := ApplyEnvOverrides(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.NetworkID != "overridden-network" {
		t.Errorf("expected NetworkID to be %q, got %q", "overridden-network", cfg.NetworkID)
	}
}

func TestApplyEnvOverrides_StringNested(t *testing.T) {
	cfg := newBaseConfig()
	t.Setenv("SENSOR_LOGGING_LEVEL", "debug")

	err := ApplyEnvOverrides(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected Logging.Level to be %q, got %q", "debug", cfg.Logging.Level)
	}
}

func TestApplyEnvOverrides_IntOverride(t *testing.T) {
	cfg := newBaseConfig()
	t.Setenv("SENSOR_CAPTURE_WINDOW_SECONDS", "120")

	err := ApplyEnvOverrides(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Capture.WindowSeconds != 120 {
		t.Errorf("expected Capture.WindowSeconds to be 120, got %d", cfg.Capture.WindowSeconds)
	}
}

func TestApplyEnvOverrides_Int64Override(t *testing.T) {
	cfg := newBaseConfig()
	t.Setenv("SENSOR_LOGGING_MAX_SIZE_MB", "200")

	err := ApplyEnvOverrides(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Logging.MaxSizeMB != 200 {
		t.Errorf("expected Logging.MaxSizeMB to be 200, got %d", cfg.Logging.MaxSizeMB)
	}
}

func TestApplyEnvOverrides_Float64Override(t *testing.T) {
	cfg := newBaseConfig()
	t.Setenv("SENSOR_ZEEK_SAMPLING_PERCENTAGE", "42.5")

	err := ApplyEnvOverrides(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Zeek.SamplingPercentage != 42.5 {
		t.Errorf("expected Zeek.SamplingPercentage to be 42.5, got %f", cfg.Zeek.SamplingPercentage)
	}
}

func TestApplyEnvOverrides_BoolTrue(t *testing.T) {
	cfg := newBaseConfig()
	cfg.Capture.Loop = false
	t.Setenv("SENSOR_CAPTURE_LOOP", "true")

	err := ApplyEnvOverrides(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Capture.Loop != true {
		t.Errorf("expected Capture.Loop to be true, got %v", cfg.Capture.Loop)
	}
}

func TestApplyEnvOverrides_BoolFalse(t *testing.T) {
	cfg := newBaseConfig()
	cfg.EnigmaAPI.Upload = true
	t.Setenv("SENSOR_ENIGMA_API_UPLOAD", "false")

	err := ApplyEnvOverrides(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.EnigmaAPI.Upload != false {
		t.Errorf("expected EnigmaAPI.Upload to be false, got %v", cfg.EnigmaAPI.Upload)
	}
}

func TestApplyEnvOverrides_NestedWithUnderscoresInBothNames(t *testing.T) {
	tests := []struct {
		name     string
		envVar   string
		envValue string
		check    func(cfg *Config) error
	}{
		{
			name:     "enigma_api section with api_key field",
			envVar:   "SENSOR_ENIGMA_API_API_KEY",
			envValue: "new-secret-key",
			check: func(cfg *Config) error {
				if cfg.EnigmaAPI.APIKey != "new-secret-key" {
					return fmt.Errorf("expected EnigmaAPI.APIKey to be %q, got %q", "new-secret-key", cfg.EnigmaAPI.APIKey)
				}
				return nil
			},
		},
		{
			name:     "pcap_ingest section with watch_dir field",
			envVar:   "SENSOR_PCAP_INGEST_WATCH_DIR",
			envValue: "/new/watch/path",
			check: func(cfg *Config) error {
				if cfg.PcapIngest.WatchDir != "/new/watch/path" {
					return fmt.Errorf("expected PcapIngest.WatchDir to be %q, got %q", "/new/watch/path", cfg.PcapIngest.WatchDir)
				}
				return nil
			},
		},
		{
			name:     "enigma_api section with max_payload_size_mb field",
			envVar:   "SENSOR_ENIGMA_API_MAX_PAYLOAD_SIZE_MB",
			envValue: "100",
			check: func(cfg *Config) error {
				if cfg.EnigmaAPI.MaxPayloadSizeMB != 100 {
					return fmt.Errorf("expected EnigmaAPI.MaxPayloadSizeMB to be 100, got %d", cfg.EnigmaAPI.MaxPayloadSizeMB)
				}
				return nil
			},
		},
		{
			name:     "pcap_ingest section with poll_interval_seconds field",
			envVar:   "SENSOR_PCAP_INGEST_POLL_INTERVAL_SECONDS",
			envValue: "30",
			check: func(cfg *Config) error {
				if cfg.PcapIngest.PollIntervalSeconds != 30 {
					return fmt.Errorf("expected PcapIngest.PollIntervalSeconds to be 30, got %d", cfg.PcapIngest.PollIntervalSeconds)
				}
				return nil
			},
		},
		{
			name:     "pcap_ingest section with file_stable_seconds field",
			envVar:   "SENSOR_PCAP_INGEST_FILE_STABLE_SECONDS",
			envValue: "15",
			check: func(cfg *Config) error {
				if cfg.PcapIngest.FileStableSeconds != 15 {
					return fmt.Errorf("expected PcapIngest.FileStableSeconds to be 15, got %d", cfg.PcapIngest.FileStableSeconds)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newBaseConfig()
			t.Setenv(tt.envVar, tt.envValue)

			err := ApplyEnvOverrides(&cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if checkErr := tt.check(&cfg); checkErr != nil {
				t.Error(checkErr)
			}
		})
	}
}

func TestApplyEnvOverrides_UnsetEnvDoesNotOverride(t *testing.T) {
	cfg := newBaseConfig()
	original := newBaseConfig()

	// Do not set any env vars at all
	err := ApplyEnvOverrides(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify every field matches the original
	if cfg.NetworkID != original.NetworkID {
		t.Errorf("NetworkID changed: expected %q, got %q", original.NetworkID, cfg.NetworkID)
	}
	if cfg.Logging.Level != original.Logging.Level {
		t.Errorf("Logging.Level changed: expected %q, got %q", original.Logging.Level, cfg.Logging.Level)
	}
	if cfg.Logging.File != original.Logging.File {
		t.Errorf("Logging.File changed: expected %q, got %q", original.Logging.File, cfg.Logging.File)
	}
	if cfg.Logging.MaxSizeMB != original.Logging.MaxSizeMB {
		t.Errorf("Logging.MaxSizeMB changed: expected %d, got %d", original.Logging.MaxSizeMB, cfg.Logging.MaxSizeMB)
	}
	if cfg.Capture.WindowSeconds != original.Capture.WindowSeconds {
		t.Errorf("Capture.WindowSeconds changed: expected %d, got %d", original.Capture.WindowSeconds, cfg.Capture.WindowSeconds)
	}
	if cfg.Capture.Loop != original.Capture.Loop {
		t.Errorf("Capture.Loop changed: expected %v, got %v", original.Capture.Loop, cfg.Capture.Loop)
	}
	if cfg.EnigmaAPI.APIKey != original.EnigmaAPI.APIKey {
		t.Errorf("EnigmaAPI.APIKey changed: expected %q, got %q", original.EnigmaAPI.APIKey, cfg.EnigmaAPI.APIKey)
	}
	if cfg.EnigmaAPI.Upload != original.EnigmaAPI.Upload {
		t.Errorf("EnigmaAPI.Upload changed: expected %v, got %v", original.EnigmaAPI.Upload, cfg.EnigmaAPI.Upload)
	}
	if cfg.Zeek.SamplingPercentage != original.Zeek.SamplingPercentage {
		t.Errorf("Zeek.SamplingPercentage changed: expected %f, got %f", original.Zeek.SamplingPercentage, cfg.Zeek.SamplingPercentage)
	}
	if cfg.PcapIngest.WatchDir != original.PcapIngest.WatchDir {
		t.Errorf("PcapIngest.WatchDir changed: expected %q, got %q", original.PcapIngest.WatchDir, cfg.PcapIngest.WatchDir)
	}
}

func TestApplyEnvOverrides_InvalidInt(t *testing.T) {
	cfg := newBaseConfig()
	t.Setenv("SENSOR_CAPTURE_WINDOW_SECONDS", "not-a-number")

	err := ApplyEnvOverrides(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid int value, got nil")
	}
	if !strings.Contains(err.Error(), "SENSOR_CAPTURE_WINDOW_SECONDS") {
		t.Errorf("expected error to mention the env var name, got: %v", err)
	}
}

func TestApplyEnvOverrides_InvalidBool(t *testing.T) {
	cfg := newBaseConfig()
	t.Setenv("SENSOR_CAPTURE_LOOP", "not-a-bool")

	err := ApplyEnvOverrides(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid bool value, got nil")
	}
	if !strings.Contains(err.Error(), "SENSOR_CAPTURE_LOOP") {
		t.Errorf("expected error to mention the env var name, got: %v", err)
	}
}

func TestApplyEnvOverrides_InvalidFloat(t *testing.T) {
	cfg := newBaseConfig()
	t.Setenv("SENSOR_ZEEK_SAMPLING_PERCENTAGE", "not-a-float")

	err := ApplyEnvOverrides(&cfg)
	if err == nil {
		t.Fatal("expected error for invalid float value, got nil")
	}
	if !strings.Contains(err.Error(), "SENSOR_ZEEK_SAMPLING_PERCENTAGE") {
		t.Errorf("expected error to mention the env var name, got: %v", err)
	}
}

func TestApplyEnvOverrides_MultipleOverridesAtOnce(t *testing.T) {
	cfg := newBaseConfig()
	t.Setenv("SENSOR_NETWORK_ID", "multi-test-network")
	t.Setenv("SENSOR_LOGGING_LEVEL", "error")
	t.Setenv("SENSOR_CAPTURE_WINDOW_SECONDS", "300")
	t.Setenv("SENSOR_ENIGMA_API_API_KEY", "multi-key-123")
	t.Setenv("SENSOR_ZEEK_SAMPLING_PERCENTAGE", "75.5")
	t.Setenv("SENSOR_CAPTURE_LOOP", "true")
	t.Setenv("SENSOR_PCAP_INGEST_ENABLED", "true")

	err := ApplyEnvOverrides(&cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.NetworkID != "multi-test-network" {
		t.Errorf("NetworkID: expected %q, got %q", "multi-test-network", cfg.NetworkID)
	}
	if cfg.Logging.Level != "error" {
		t.Errorf("Logging.Level: expected %q, got %q", "error", cfg.Logging.Level)
	}
	if cfg.Capture.WindowSeconds != 300 {
		t.Errorf("Capture.WindowSeconds: expected 300, got %d", cfg.Capture.WindowSeconds)
	}
	if cfg.EnigmaAPI.APIKey != "multi-key-123" {
		t.Errorf("EnigmaAPI.APIKey: expected %q, got %q", "multi-key-123", cfg.EnigmaAPI.APIKey)
	}
	if cfg.Zeek.SamplingPercentage != 75.5 {
		t.Errorf("Zeek.SamplingPercentage: expected 75.5, got %f", cfg.Zeek.SamplingPercentage)
	}
	if cfg.Capture.Loop != true {
		t.Errorf("Capture.Loop: expected true, got %v", cfg.Capture.Loop)
	}
	if cfg.PcapIngest.Enabled != true {
		t.Errorf("PcapIngest.Enabled: expected true, got %v", cfg.PcapIngest.Enabled)
	}

	// Verify fields that were NOT set via env are still at their original values
	if cfg.Logging.File != "/var/log/sensor.log" {
		t.Errorf("Logging.File should not have changed: expected %q, got %q", "/var/log/sensor.log", cfg.Logging.File)
	}
	if cfg.Buffering.MaxAgeHours != 2 {
		t.Errorf("Buffering.MaxAgeHours should not have changed: expected 2, got %d", cfg.Buffering.MaxAgeHours)
	}
}

// expectedEnvVarName computes the expected SENSOR_ env var name from JSON tags.
// For top level fields: SENSOR_<UPPER(json_tag)>
// For nested fields: SENSOR_<UPPER(section_json_tag)>_<UPPER(field_json_tag)>
func expectedEnvVarName(sectionTag, fieldTag string) string {
	if sectionTag == "" {
		return "SENSOR_" + strings.ToUpper(fieldTag)
	}
	return "SENSOR_" + strings.ToUpper(sectionTag) + "_" + strings.ToUpper(fieldTag)
}

// TestApplyEnvOverrides_AllFieldEnvVarNames is a regression guard that verifies
// the env var naming convention for every field in Config. If a new field is
// added to Config, this test will fail until the mapping is updated.
func TestApplyEnvOverrides_AllFieldEnvVarNames(t *testing.T) {
	// Build expected mapping from the Config struct using reflection.
	// Each entry is envVarName -> description for human readability.
	type fieldSpec struct {
		envVar      string
		description string // e.g. "NetworkID" or "Logging.Level"
	}

	var expected []fieldSpec

	cfgType := reflect.TypeOf(Config{})
	for i := 0; i < cfgType.NumField(); i++ {
		topField := cfgType.Field(i)
		topTag := topField.Tag.Get("json")
		if topTag == "" || topTag == "-" {
			continue
		}
		// Strip options like ",omitempty"
		topTag = strings.Split(topTag, ",")[0]

		if topField.Type.Kind() == reflect.Struct {
			// Nested struct: iterate inner fields
			for j := 0; j < topField.Type.NumField(); j++ {
				innerField := topField.Type.Field(j)
				innerTag := innerField.Tag.Get("json")
				if innerTag == "" || innerTag == "-" {
					continue
				}
				innerTag = strings.Split(innerTag, ",")[0]
				expected = append(expected, fieldSpec{
					envVar:      expectedEnvVarName(topTag, innerTag),
					description: topField.Name + "." + innerField.Name,
				})
			}
		} else {
			// Top level field
			expected = append(expected, fieldSpec{
				envVar:      expectedEnvVarName("", topTag),
				description: topField.Name,
			})
		}
	}

	if len(expected) == 0 {
		t.Fatal("reflection found zero fields in Config; this is a bug in the test")
	}

	// Verify each expected env var by setting it and confirming ApplyEnvOverrides reads it.
	// We set a sentinel value appropriate for each type and check the field changed.
	for _, spec := range expected {
		t.Run(spec.envVar, func(t *testing.T) {
			cfg := newBaseConfig()

			// Determine the field type so we can set a valid sentinel value
			fieldVal := fieldByDescription(cfg, spec.description)
			var sentinel string
			switch fieldVal.Kind() {
			case reflect.String:
				sentinel = "sentinel_" + spec.envVar
			case reflect.Int, reflect.Int64:
				sentinel = "99999"
			case reflect.Float64:
				sentinel = "99.999"
			case reflect.Bool:
				// Flip the current value so we can detect the change
				if fieldVal.Bool() {
					sentinel = "false"
				} else {
					sentinel = "true"
				}
			default:
				t.Fatalf("unsupported field type %v for %s", fieldVal.Kind(), spec.description)
			}

			t.Setenv(spec.envVar, sentinel)

			err := ApplyEnvOverrides(&cfg)
			if err != nil {
				t.Fatalf("unexpected error applying env var %s=%s: %v", spec.envVar, sentinel, err)
			}

			// Re-read the field and verify it changed from the base config
			baseVal := fieldByDescription(newBaseConfig(), spec.description)
			newVal := fieldByDescription(cfg, spec.description)

			if reflect.DeepEqual(newVal.Interface(), baseVal.Interface()) {
				t.Errorf("env var %s did not override field %s (value still %v)", spec.envVar, spec.description, newVal.Interface())
			}
		})
	}
}

// fieldByDescription returns the reflect.Value for a field described as
// "FieldName" (top level) or "Section.FieldName" (nested).
func fieldByDescription(cfg Config, desc string) reflect.Value {
	v := reflect.ValueOf(cfg)
	parts := strings.Split(desc, ".")
	for _, p := range parts {
		v = v.FieldByName(p)
	}
	return v
}

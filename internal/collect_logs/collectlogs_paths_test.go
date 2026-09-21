package collect_logs

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testAPIKey    = "live-key-7f3a9c2e"
	testOldAPIKey = "rotated-key-41b8d0"
)

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("failed to create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func writeGzipFile(t *testing.T, path, content string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(content)); err != nil {
		t.Fatalf("failed to gzip %s: %v", path, err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("failed to gzip %s: %v", path, err)
	}
	writeTestFile(t, path, buf.String())
}

func testConfigJSON(t *testing.T, logFile, captureDir string) string {
	t.Helper()
	cfg := map[string]any{
		"network_id": "HQ-Firewall-01",
		"logging":    map[string]any{"file": logFile},
		"capture":    map[string]any{"output_dir": captureDir},
		"enigma_api": map[string]any{"api_key": testAPIKey, "server": "api.enigmaai.net:443", "upload": true},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	return string(data)
}

// oldSensorLog is what sensors before B1CF-2020 wrote on start, plus a line
// holding the current key.
func oldSensorLog() string {
	return strings.Repeat("capture window complete\n", 20) +
		"2026/09/01 12:00:00 Loaded config: &{NetworkID:HQ-Firewall-01 EnigmaAPI:{Server:api.enigmaai.net:443 APIKey:" + testOldAPIKey + " CACertFile: Upload:true MaxPayloadSizeMB:25}}\n" +
		"2026/09/02 12:00:00 debug " + testAPIKey + "\n"
}

func assertNoAPIKey(t *testing.T, members map[string][]byte) {
	t.Helper()
	for name, content := range members {
		for _, key := range []string{testAPIKey, testOldAPIKey} {
			if bytes.Contains(content, []byte(key)) {
				t.Errorf("archive member %s contains API key %q", name, key)
			}
		}
	}
}

func memberNames(members map[string][]byte) []string {
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	return names
}

// TestCollect_InstalledLayout_FindsFilesAndRedactsKey mirrors a Linux package
// install: absolute config, log, and capture paths, run from an unrelated
// working directory.
func TestCollect_InstalledLayout_FindsFilesAndRedactsKey(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc", "enigma-sensor")
	logDir := filepath.Join(root, "var", "log", "enigma-sensor")
	captureDir := filepath.Join(root, "var", "lib", "enigma-sensor", "captures")
	serviceLogDir := filepath.Join(root, "ProgramData", "logs")

	configPath := filepath.Join(etc, "config.json")
	writeTestFile(t, configPath, testConfigJSON(t, filepath.Join(logDir, "enigma-sensor.log"), captureDir))
	writeTestFile(t, filepath.Join(logDir, "enigma-sensor.log"), oldSensorLog())
	writeGzipFile(t, filepath.Join(logDir, "enigma-sensor-2026-09-01T00-00-00.000.log.gz"), oldSensorLog())
	writeTestFile(t, filepath.Join(logDir, "unrelated.log"), "not ours")
	writeTestFile(t, filepath.Join(captureDir, "zeek_out_1", "conn.xlsx"), "conn data")
	writeTestFile(t, filepath.Join(serviceLogDir, "enigma-sensor.log"), oldSensorLog())

	t.Chdir(t.TempDir())
	wd, _ := os.Getwd()
	outName := "bundle" + ArchiveExt
	_, err := collect(outName, sources{
		configPaths:   []string{configPath, "config.json"},
		baseDirs:      []string{wd},
		serviceLogDir: serviceLogDir,
	})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}

	members := readArchiveMembers(t, outName)
	for _, want := range []string{
		"config.json",
		"logs/enigma-sensor.log",
		"logs/enigma-sensor-2026-09-01T00-00-00.000.log",
		"service-logs/enigma-sensor.log",
		"captures/zeek_out_1/conn.xlsx",
		"version.txt",
		"system-info.txt",
		"collect-logs.txt",
	} {
		if _, ok := members[want]; !ok {
			t.Errorf("expected %s in archive (members: %v)", want, memberNames(members))
		}
	}
	if _, ok := members["logs/unrelated.log"]; ok {
		t.Error("archive picked up a file that is not the sensor's log")
	}
	assertNoAPIKey(t, members)

	// The redacted config is still valid JSON with everything but the key intact.
	var cfg struct {
		NetworkID string `json:"network_id"`
		EnigmaAPI struct {
			APIKey string `json:"api_key"`
		} `json:"enigma_api"`
	}
	if err := json.Unmarshal(members["config.json"], &cfg); err != nil {
		t.Fatalf("redacted config.json is not valid JSON: %v", err)
	}
	if cfg.NetworkID != "HQ-Firewall-01" {
		t.Errorf("network_id = %q, want it kept", cfg.NetworkID)
	}
	if cfg.EnigmaAPI.APIKey != strings.Repeat("*", len(testAPIKey)) {
		t.Errorf("api_key = %q, want it masked", cfg.EnigmaAPI.APIKey)
	}
	if got, want := string(members["logs/enigma-sensor-2026-09-01T00-00-00.000.log"]), len(oldSensorLog()); len(got) != want {
		t.Errorf("rotated log decompressed to %d bytes, want %d", len(got), want)
	}
	if !strings.Contains(string(members["collect-logs.txt"]), configPath) {
		t.Errorf("collect-logs.txt does not name the config used: %q", members["collect-logs.txt"])
	}
}

// TestCollect_RelativePathsResolveAgainstExecutableDir mirrors the Windows
// service, whose working directory is the install directory: relative config
// paths resolve there even when collect-logs runs from somewhere else.
func TestCollect_RelativePathsResolveAgainstExecutableDir(t *testing.T) {
	installDir := t.TempDir()
	writeTestFile(t, filepath.Join(installDir, "config.json"), testConfigJSON(t, "logs/enigma-sensor.log", "./captures"))
	writeTestFile(t, filepath.Join(installDir, "logs", "enigma-sensor.log"), oldSensorLog())
	writeTestFile(t, filepath.Join(installDir, "captures", "cap.pcap"), strings.Repeat("p", 300))

	t.Chdir(t.TempDir())
	wd, _ := os.Getwd()
	outName := "bundle" + ArchiveExt
	if _, err := collect(outName, sources{
		configPaths: []string{filepath.Join(t.TempDir(), "missing", "config.json"), "config.json"},
		baseDirs:    []string{wd, installDir},
	}); err != nil {
		t.Fatalf("collect failed: %v", err)
	}

	members := readArchiveMembers(t, outName)
	for _, want := range []string{"config.json", "logs/enigma-sensor.log", "captures/cap.pcap"} {
		if _, ok := members[want]; !ok {
			t.Errorf("expected %s in archive (members: %v)", want, memberNames(members))
		}
	}
	assertNoAPIKey(t, members)
}

// TestCollect_InvalidConfig_StillArchivedRedacted covers the case support most
// needs a bundle for: a config the sensor refuses to load. The key must never
// reach the bundle, and paths the config names must still be followed. A config
// that is not valid JSON is left out, because its key cannot be located.
func TestCollect_InvalidConfig_StillArchivedRedacted(t *testing.T) {
	root := t.TempDir()
	logFile := filepath.ToSlash(filepath.Join(root, "var", "log", "enigma-sensor.log"))
	captureDir := filepath.ToSlash(filepath.Join(root, "var", "lib", "captures"))

	tests := []struct {
		name   string
		config string
		// parses is true when the config is valid JSON: it is archived masked,
		// and its absolute log and capture paths are followed.
		parses bool
		// keyInLog is true when the key can be read from the config, so a log
		// line holding only the literal key is masked too.
		keyInLog bool
	}{
		{
			name:     "fails validation",
			config:   `{"network_id": "", "logging": {"file": "` + logFile + `"}, "capture": {"output_dir": "` + captureDir + `"}, "enigma_api": {"api_key": "` + testAPIKey + `"}}`,
			parses:   true,
			keyInLog: true,
		},
		{name: "misspelled key name apikey", config: `{"enigma_api": {"apikey": "` + testAPIKey + `"}}`, parses: true},
		{name: "misspelled key name api-key", config: `{"enigma_api": {"api-key": "` + testAPIKey + `"}}`, parses: true},
		{name: "syntax error with an uppercase key name", config: `{"enigma_api": {"API_KEY": "` + testAPIKey + `",}}`, keyInLog: true},
		{name: "syntax error with the value on the next line", config: "{\"enigma_api\": {\"api_key\":\n    \"" + testAPIKey + "\"},", keyInLog: true},
		{name: "single-quoted value", config: `{"enigma_api": {"api_key": '` + testAPIKey + `'}}`},
		{name: "single-quoted name", config: `{"enigma_api": {'api_key': "` + testAPIKey + `"}}`},
		{name: "unquoted name", config: `{"enigma_api": {api_key: "` + testAPIKey + `"}}`},
		{name: "raw newline inside the value", config: "{\"enigma_api\": {\"api_key\": \"live-key-\n7f3a9c2e\"}}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			writeTestFile(t, "config.json", tt.config)
			logContent := oldSensorLog()
			if !tt.keyInLog {
				// Without a readable key, only the shapes sensors log it in
				// can be masked.
				logContent = strings.ReplaceAll(logContent, "2026/09/02 12:00:00 debug "+testAPIKey+"\n", "")
			}
			wantLog, wantCapture := filepath.Join("logs", "enigma-sensor.log"), filepath.Join("captures", "cap.pcap")
			if tt.parses && strings.Contains(tt.config, logFile) {
				wantLog, wantCapture = filepath.FromSlash(logFile), filepath.Join(filepath.FromSlash(captureDir), "cap.pcap")
			}
			writeTestFile(t, wantLog, logContent)
			writeTestFile(t, wantCapture, "pcap data")

			outName := "bundle" + ArchiveExt
			if _, err := collectInCwd(t, outName); err != nil {
				t.Fatalf("collect failed: %v", err)
			}

			members := readArchiveMembers(t, outName)
			for _, want := range []string{"logs/enigma-sensor.log", "captures/cap.pcap"} {
				if _, ok := members[want]; !ok {
					t.Errorf("expected %s in archive (members: %v)", want, memberNames(members))
				}
			}
			assertNoAPIKey(t, members)
			for _, fragment := range []string{"live-key-", "7f3a9c2e"} {
				if bytes.Contains(members["config.json"], []byte(fragment)) {
					t.Errorf("config.json contains key fragment %q", fragment)
				}
			}
			notes := string(members["collect-logs.txt"])
			_, archived := members["config.json"]
			if tt.parses {
				if !archived {
					t.Errorf("expected the valid JSON config in the archive (members: %v)", memberNames(members))
				} else if !json.Valid(members["config.json"]) {
					t.Errorf("masked config.json is not valid JSON: %s", members["config.json"])
				}
			} else {
				if archived {
					t.Errorf("config.json that is not valid JSON was archived: %s", members["config.json"])
				}
				if !strings.Contains(notes, "not valid JSON") {
					t.Errorf("collect-logs.txt does not say why the config was left out: %q", notes)
				}
			}
			if !strings.Contains(notes, "config load error") {
				t.Errorf("collect-logs.txt does not record the load error: %q", notes)
			}
		})
	}
}

// TestCollect_EnvOverrideKeyIsRedacted covers Docker, where the key comes from
// SENSOR_ENIGMA_API_API_KEY rather than the config file.
func TestCollect_EnvOverrideKeyIsRedacted(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("SENSOR_ENIGMA_API_API_KEY", testAPIKey)
	fileConfig := strings.ReplaceAll(testConfigJSON(t, "logs/enigma-sensor.log", "captures"), testAPIKey, "file-key-93c1e5")
	writeTestFile(t, "config.json", fileConfig)
	writeTestFile(t, filepath.Join("logs", "enigma-sensor.log"), "upload with "+testAPIKey+"\n"+strings.Repeat("x", 300))

	outName := "bundle" + ArchiveExt
	if _, err := collectInCwd(t, outName); err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	members := readArchiveMembers(t, outName)
	assertNoAPIKey(t, members)
	if bytes.Contains(members["config.json"], []byte("file-key-93c1e5")) {
		t.Error("config.json contains the key from the file")
	}
}

// TestCollect_SkipsSymlinksInsideLogAndCaptureDirs keeps a link planted in a
// capture or log directory from pulling another file into the archive
// unmasked.
func TestCollect_SkipsSymlinksInsideLogAndCaptureDirs(t *testing.T) {
	t.Chdir(t.TempDir())
	outside := filepath.Join(t.TempDir(), "secret.json")
	writeTestFile(t, outside, `{"token": "`+testAPIKey+`"}`)
	writeTestFile(t, filepath.Join("logs", "enigma-sensor.log"), strings.Repeat("x", 300))
	writeTestFile(t, filepath.Join("captures", "cap.pcap"), "pcap data")
	for _, link := range []string{filepath.Join("captures", "link.json"), filepath.Join("logs", "enigma-sensor-link.log")} {
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}

	outName := "bundle" + ArchiveExt
	if _, err := collectInCwd(t, outName); err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	members := readArchiveMembers(t, outName)
	for _, name := range []string{"captures/link.json", "logs/enigma-sensor-link.log"} {
		if _, ok := members[name]; ok {
			t.Errorf("archive followed symlink %s", name)
		}
	}
	assertNoAPIKey(t, members)
}

// TestCollect_ExistingOutputIsLeftAlone checks the archive is never written
// over, or through, a file that already exists.
func TestCollect_ExistingOutputIsLeftAlone(t *testing.T) {
	t.Chdir(t.TempDir())
	writeTestFile(t, filepath.Join("logs", "enigma-sensor.log"), strings.Repeat("x", 300))
	outName := "bundle" + ArchiveExt
	writeTestFile(t, outName, "existing")

	if _, err := collectInCwd(t, outName); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected an already exists error, got %v", err)
	}
	if got, err := os.ReadFile(outName); err != nil || string(got) != "existing" {
		t.Errorf("existing file was changed or removed: %q, %v", got, err)
	}
}

// TestCollect_UnparseableConfig_FallsBackToInstallDirs covers an installed
// Linux sensor whose config has a syntax error, so it names no paths: logs and
// captures come from the installer's folders.
func TestCollect_UnparseableConfig_FallsBackToInstallDirs(t *testing.T) {
	root := t.TempDir()
	installLogDir := filepath.Join(root, "var", "log", "enigma-sensor")
	installCaptureDir := filepath.Join(root, "var", "lib", "enigma-sensor", "captures")
	writeTestFile(t, filepath.Join(installLogDir, "enigma-sensor.log"), oldSensorLog())
	writeTestFile(t, filepath.Join(installCaptureDir, "zeek_out_1", "conn.xlsx"), "conn data")
	configPath := filepath.Join(root, "etc", "enigma-sensor", "config.json")
	writeTestFile(t, configPath, `{"enigma_api": {"api_key": "`+testAPIKey+`",}}`)

	t.Chdir(t.TempDir())
	wd, _ := os.Getwd()
	outName := "bundle" + ArchiveExt
	if _, err := collect(outName, sources{
		configPaths:       []string{configPath, "config.json"},
		baseDirs:          []string{wd},
		installLogDir:     installLogDir,
		installCaptureDir: installCaptureDir,
	}); err != nil {
		t.Fatalf("collect failed: %v", err)
	}

	members := readArchiveMembers(t, outName)
	for _, want := range []string{"logs/enigma-sensor.log", "captures/zeek_out_1/conn.xlsx"} {
		if _, ok := members[want]; !ok {
			t.Errorf("expected %s in archive (members: %v)", want, memberNames(members))
		}
	}
	assertNoAPIKey(t, members)
}

// TestCollect_ConfigPathsWinOverInstallDirs checks the fallback never replaces
// a path the config names, even one that does not exist.
func TestCollect_ConfigPathsWinOverInstallDirs(t *testing.T) {
	installLogDir := t.TempDir()
	writeTestFile(t, filepath.Join(installLogDir, "enigma-sensor.log"), "install dir log")

	t.Chdir(t.TempDir())
	wd, _ := os.Getwd()
	writeTestFile(t, "config.json", testConfigJSON(t, filepath.Join(wd, "elsewhere", "enigma-sensor.log"), "captures"))
	outName := "bundle" + ArchiveExt
	if _, err := collect(outName, sources{
		configPaths:   []string{"config.json"},
		baseDirs:      []string{wd},
		installLogDir: installLogDir,
	}); err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if _, ok := readArchiveMembers(t, outName)["logs/enigma-sensor.log"]; ok {
		t.Error("archive used the install log folder although the config names another")
	}
}

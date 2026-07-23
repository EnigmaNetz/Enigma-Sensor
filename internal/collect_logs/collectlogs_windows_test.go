//go:build windows

package collect_logs

import (
	"archive/zip"
	"os"
	"strings"
	"testing"
)

// TestCollectLogs_Windows_CreatesZipWithExpectedFiles ports the original
// zip-based coverage: CollectLogs on Windows still produces a .zip archive
// with the expected members.
func TestCollectLogs_Windows_CreatesZipWithExpectedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	useCwdSources(t)

	// Setup: create logs/, captures/, config.json
	if err := os.Mkdir("logs", 0755); err != nil {
		t.Fatalf("failed to create logs dir: %v", err)
	}
	if err := os.WriteFile("logs/test.log", []byte("logdata-"+strings.Repeat("a", 300)), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}
	if err := os.MkdirAll("captures/session1", 0755); err != nil {
		t.Fatalf("failed to create captures dir: %v", err)
	}
	if err := os.WriteFile("captures/session1/cap.pcap", []byte("pcapdata-"+strings.Repeat("p", 300)), 0644); err != nil {
		t.Fatalf("failed to write pcap file: %v", err)
	}
	if err := os.WriteFile("config.json", []byte(`{"foo": "`+strings.Repeat("b", 300)+`"}`), 0644); err != nil {
		t.Fatalf("failed to write config.json: %v", err)
	}

	zipName := "test-logs.zip"
	_, err := CollectLogs(zipName)
	if err != nil {
		t.Fatalf("CollectLogs failed: %v", err)
	}

	// Check zip file exists
	if _, err := os.Stat(zipName); err != nil {
		t.Fatalf("Zip file not created: %v", err)
	}

	// Open and check contents
	r, err := zip.OpenReader(zipName)
	if err != nil {
		t.Fatalf("Failed to open zip: %v", err)
	}
	defer r.Close()

	files := map[string]bool{}
	for _, f := range r.File {
		normalized := strings.ReplaceAll(f.Name, "\\", "/")
		files[normalized] = true
	}

	// Should include these files
	for _, want := range []string{
		"logs/test.log", "captures/session1/cap.pcap", "config.json", "version.txt", "system-info.txt",
	} {
		if !files[want] {
			t.Errorf("Expected %s in zip, not found", want)
		}
	}
}

// TestCollectLogs_Windows_MissingDirsAreHandled verifies that a missing
// captures/ dir is tolerated: with a log file and config.json present (runtime
// content exists, so the bundle is not degraded), CollectLogs still succeeds
// and includes logs, config.json, version.txt, and system-info.txt.
func TestCollectLogs_Windows_MissingDirsAreHandled(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	useCwdSources(t)

	// Create logs/ (runtime content) and config.json; captures/ stays absent.
	if err := os.Mkdir("logs", 0755); err != nil {
		t.Fatalf("failed to create logs dir: %v", err)
	}
	if err := os.WriteFile("logs/test.log", []byte(strings.Repeat("l", 300)), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}
	if err := os.WriteFile("config.json", []byte(`{"foo": "`+strings.Repeat("c", 300)+`"}`), 0644); err != nil {
		t.Fatalf("failed to write config.json: %v", err)
	}

	zipName := "test-logs-missing.zip"
	_, err := CollectLogs(zipName)
	if err != nil {
		t.Fatalf("CollectLogs failed: %v", err)
	}

	// Check zip file exists
	if _, err := os.Stat(zipName); err != nil {
		t.Fatalf("Zip file not created: %v", err)
	}

	// Open and check contents
	r, err := zip.OpenReader(zipName)
	if err != nil {
		t.Fatalf("Failed to open zip: %v", err)
	}
	defer r.Close()

	var foundLog, foundConfig, foundVersion, foundSysinfo bool
	for _, f := range r.File {
		normalized := strings.ReplaceAll(f.Name, "\\", "/")
		if normalized == "logs/test.log" {
			foundLog = true
		}
		if normalized == "config.json" {
			foundConfig = true
		}
		if normalized == "version.txt" {
			foundVersion = true
		}
		if normalized == "system-info.txt" {
			foundSysinfo = true
		}
	}
	if !foundLog || !foundConfig || !foundVersion || !foundSysinfo {
		t.Errorf("Expected logs/test.log, config.json, version.txt, and system-info.txt in zip (got: %v)", r.File)
	}
}

// TestCollectLogs_Windows_EmptyDirs_ReturnsError verifies that the
// no-diagnostic-content check applies on Windows too: empty logs/ and
// captures/ with no config.json must fail rather than emit a hollow zip
// holding only the generated version.txt and system-info.txt blobs.
func TestCollectLogs_Windows_EmptyDirs_ReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	useCwdSources(t)

	if err := os.Mkdir("logs", 0755); err != nil {
		t.Fatalf("failed to create logs dir: %v", err)
	}
	if err := os.Mkdir("captures", 0755); err != nil {
		t.Fatalf("failed to create captures dir: %v", err)
	}

	zipName := "test-logs-empty.zip"
	_, err := CollectLogs(zipName)
	if err == nil {
		t.Fatal("expected CollectLogs to return an error when no diagnostic content exists, got nil")
	}
	if !strings.Contains(err.Error(), "no diagnostic content found") {
		t.Errorf("expected error to mention missing diagnostic content, got: %v", err)
	}
}

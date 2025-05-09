package collect_logs

import (
	"archive/zip"
	"os"
	"strings"
	"testing"
)

func TestCollectLogs_CreatesZipWithExpectedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	os.Chdir(tmpDir)

	// Setup: create logs/, captures/, config.json
	os.Mkdir("logs", 0755)
	os.WriteFile("logs/test.log", []byte("logdata"), 0644)
	os.MkdirAll("captures/session1", 0755)
	os.WriteFile("captures/session1/cap.pcap", []byte("pcapdata"), 0644)
	os.WriteFile("config.json", []byte(`{"foo": "bar"}`), 0644)

	zipName := "test-logs.zip"
	err := CollectLogs(zipName)
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

func TestCollectLogs_MissingDirsAreHandled(t *testing.T) {
	tmpDir := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	os.Chdir(tmpDir)

	// Only create config.json
	os.WriteFile("config.json", []byte(`{"foo": "bar"}`), 0644)

	zipName := "test-logs-missing.zip"
	err := CollectLogs(zipName)
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

	var foundConfig, foundVersion, foundSysinfo bool
	for _, f := range r.File {
		normalized := strings.ReplaceAll(f.Name, "\\", "/")
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
	if !foundConfig || !foundVersion || !foundSysinfo {
		t.Errorf("Expected config.json, version.txt, and system-info.txt in zip (got: %v)", r.File)
	}
}

func TestCollectLogs_EmptyDirs(t *testing.T) {
	tmpDir := t.TempDir()
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	os.Chdir(tmpDir)

	os.Mkdir("logs", 0755)
	os.Mkdir("captures", 0755)

	zipName := "test-logs-empty.zip"
	err := CollectLogs(zipName)
	if err != nil {
		t.Fatalf("CollectLogs failed: %v", err)
	}

	// Open and check contents
	r, err := zip.OpenReader(zipName)
	if err != nil {
		t.Fatalf("Failed to open zip: %v", err)
	}
	defer r.Close()

	var foundVersion, foundSysinfo bool
	for _, f := range r.File {
		normalized := strings.ReplaceAll(f.Name, "\\", "/")
		if normalized == "version.txt" {
			foundVersion = true
		}
		if normalized == "system-info.txt" {
			foundSysinfo = true
		}
	}
	if !foundVersion || !foundSysinfo {
		t.Errorf("Expected version.txt and system-info.txt in zip (got: %v)", r.File)
	}
}

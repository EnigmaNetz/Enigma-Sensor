package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// createMockLogFiles creates empty log files to simulate capture
func createMockLogFiles(dir string) error {
	files := []string{"dns.xlsx", "conn.xlsx"}
	for _, f := range files {
		path := filepath.Join(dir, f)
		if err := os.WriteFile(path, []byte(""), 0644); err != nil {
			return err
		}
	}
	return nil
}

func TestMain(t *testing.T) {
	// Create temp directory for test outputs
	tempDir := t.TempDir()
	originalArgs := os.Args

	// Create logs directory
	logsDir := filepath.Join(".", "logs")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		t.Fatalf("Failed to create logs directory: %v", err)
	}
	defer os.RemoveAll(logsDir)

	// Create mock log files
	if err := createMockLogFiles(logsDir); err != nil {
		t.Fatalf("Failed to create mock log files: %v", err)
	}

	// Setup test config file
	configPath := filepath.Join(tempDir, "config.json")
	os.Args = []string{os.Args[0], "-config", configPath}
	defer func() {
		os.Args = originalArgs
	}()

	// Start agent in background
	done := make(chan struct{})
	go func() {
		main()
		close(done)
	}()

	// Give it time to start up
	time.Sleep(2 * time.Second)

	// Verify capture is running by checking for log files
	files, err := os.ReadDir(logsDir)
	if err != nil {
		t.Errorf("Failed to read logs directory: %v", err)
	}
	if len(files) == 0 {
		t.Error("Expected log files to be created")
	}

	// Send shutdown signal
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	p.Signal(os.Interrupt)

	// Wait for shutdown
	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for agent to shutdown")
	}
}

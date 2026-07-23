//go:build !windows

package collect_logs

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCollectLogs_Unix_ArchiveContainsExpectedFiles verifies that on
// non-Windows platforms CollectLogs produces a .tar.gz archive containing
// all expected members, and that file content round-trips byte-for-byte.
func TestCollectLogs_Unix_ArchiveContainsExpectedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)

	if err := os.Mkdir("logs", 0755); err != nil {
		t.Fatalf("failed to create logs dir: %v", err)
	}
	logContent := "logdata-" + strings.Repeat("a", 300)
	if err := os.WriteFile("logs/test.log", []byte(logContent), 0644); err != nil {
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

	outName := "test-logs.tar.gz"
	if _, err := CollectLogs(outName); err != nil {
		t.Fatalf("CollectLogs failed: %v", err)
	}

	info, err := os.Stat(outName)
	if err != nil {
		t.Fatalf("archive not created: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("expected archive to be non-empty")
	}
	if info.Size() <= 256 {
		t.Errorf("expected archive larger than 256 bytes, got %d", info.Size())
	}

	f, err := os.Open(outName)
	if err != nil {
		t.Fatalf("failed to open archive: %v", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("failed to open gzip reader: %v", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	members := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("failed to read tar entry: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		buf := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, buf); err != nil {
			t.Fatalf("failed to read member %s: %v", hdr.Name, err)
		}
		members[hdr.Name] = buf
	}

	for _, want := range []string{
		"logs/test.log", "captures/session1/cap.pcap", "config.json", "version.txt", "system-info.txt",
	} {
		if _, ok := members[want]; !ok {
			names := make([]string, 0, len(members))
			for k := range members {
				names = append(names, k)
			}
			t.Errorf("expected %s in archive, not found (members: %v)", want, names)
		}
	}

	if got := string(members["logs/test.log"]); got != logContent {
		t.Errorf("logs/test.log content mismatch: got %q, want %q", got, logContent)
	}
}

// TestCollectLogs_Unix_MissingDirsAreHandled verifies that when logs/ and
// captures/ are absent, CollectLogs still succeeds and includes config.json,
// version.txt, and system-info.txt.
func TestCollectLogs_Unix_MissingDirsAreHandled(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)

	if err := os.WriteFile("config.json", []byte(`{"foo": "`+strings.Repeat("c", 300)+`"}`), 0644); err != nil {
		t.Fatalf("failed to write config.json: %v", err)
	}

	outName := "test-logs-missing.tar.gz"
	if _, err := CollectLogs(outName); err != nil {
		t.Fatalf("CollectLogs failed: %v", err)
	}

	f, err := os.Open(outName)
	if err != nil {
		t.Fatalf("failed to open archive: %v", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("failed to open gzip reader: %v", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	found := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("failed to read tar entry: %v", err)
		}
		found[hdr.Name] = true
	}

	for _, want := range []string{"config.json", "version.txt", "system-info.txt"} {
		if !found[want] {
			t.Errorf("expected %s in archive, not found", want)
		}
	}
}

// TestCollectLogs_Unix_NonRegularCaptureEntry_DoesNotCorruptArchive verifies
// that a non-regular entry under captures/ (here a symlink pointing at a
// directory) is skipped without poisoning the tar stream. Declaring a header
// size and then writing fewer bytes latches a sticky "missed writing N bytes"
// error on tar.Writer, which would fail every later entry and the whole run.
func TestCollectLogs_Unix_NonRegularCaptureEntry_DoesNotCorruptArchive(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)

	if err := os.Mkdir("logs", 0755); err != nil {
		t.Fatalf("failed to create logs dir: %v", err)
	}
	logContent := "logdata-" + strings.Repeat("a", 300)
	if err := os.WriteFile("logs/enigma.log", []byte(logContent), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}
	if err := os.MkdirAll("captures/session1", 0755); err != nil {
		t.Fatalf("failed to create captures dir: %v", err)
	}
	// A symlink to a directory: filepath.Walk does not follow it, so it is
	// enumerated as a file, but os.Open plus Stat resolve it to a directory.
	if err := os.Symlink(filepath.Join(tmpDir, "captures", "session1"), filepath.Join("captures", "link")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	outName := "test-logs.tar.gz"
	if _, err := CollectLogs(outName); err != nil {
		t.Fatalf("CollectLogs failed on a non-regular captures entry: %v", err)
	}

	f, err := os.Open(outName)
	if err != nil {
		t.Fatalf("failed to open archive: %v", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("failed to open gzip reader: %v", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	members := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("archive is corrupt, failed to read tar entry: %v", err)
		}
		buf := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, buf); err != nil {
			t.Fatalf("failed to read member %s: %v", hdr.Name, err)
		}
		members[hdr.Name] = buf
	}

	for _, want := range []string{"logs/enigma.log", "version.txt", "system-info.txt"} {
		if _, ok := members[want]; !ok {
			names := make([]string, 0, len(members))
			for k := range members {
				names = append(names, k)
			}
			t.Errorf("expected %s in archive, not found (members: %v)", want, names)
		}
	}
	if got := string(members["logs/enigma.log"]); got != logContent {
		t.Errorf("logs/enigma.log content mismatch: got %q, want %q", got, logContent)
	}
}

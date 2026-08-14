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

// readTarGzMembers opens a .tar.gz archive and returns a map of member name to
// its byte content, restricted to regular file entries.
func readTarGzMembers(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
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
	return members
}

// TestCollectLogs_Unix_PackagedPaths_GatheredRegardlessOfCwd verifies the core
// fix for issue #71: when the sensor is installed to packaged absolute paths,
// collect-logs must gather logs, captures (including nested files), and config
// from those install paths regardless of the current working directory. The
// in-archive member names stay stable (logs/<basename>,
// captures/<relative-path>, config.json) even though the on-disk sources live
// outside the cwd.
func TestCollectLogs_Unix_PackagedPaths_GatheredRegardlessOfCwd(t *testing.T) {
	installLog := t.TempDir()
	installCapture := t.TempDir()
	configDir := t.TempDir()

	logContent := "installlog-" + strings.Repeat("a", 300)
	if err := os.WriteFile(filepath.Join(installLog, "enigma.log"), []byte(logContent), 0644); err != nil {
		t.Fatalf("failed to write install log file: %v", err)
	}

	captureContent := "installpcap-" + strings.Repeat("p", 300)
	if err := os.MkdirAll(filepath.Join(installCapture, "session1"), 0755); err != nil {
		t.Fatalf("failed to create install capture dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(installCapture, "session1", "cap.pcap"), []byte(captureContent), 0644); err != nil {
		t.Fatalf("failed to write install capture file: %v", err)
	}

	configContent := `{"foo": "` + strings.Repeat("b", 300) + `"}`
	configPath := filepath.Join(configDir, "config.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write install config: %v", err)
	}

	useInstallSources(t, installLog, installCapture, configPath)

	// Run from a DIFFERENT empty cwd with no logs/, captures/, or config.json:
	// the content must still come from the install paths.
	t.Chdir(t.TempDir())

	outName := "test-logs.tar.gz"
	if _, err := CollectLogs(outName); err != nil {
		t.Fatalf("CollectLogs failed: %v", err)
	}

	members := readTarGzMembers(t, outName)

	if got := string(members["logs/enigma.log"]); got != logContent {
		t.Errorf("logs/enigma.log content mismatch: got %q, want %q", got, logContent)
	}
	if got := string(members["captures/session1/cap.pcap"]); got != captureContent {
		t.Errorf("captures/session1/cap.pcap content mismatch: got %q, want %q", got, captureContent)
	}
	if got := string(members["config.json"]); got != configContent {
		t.Errorf("config.json content mismatch: got %q, want %q", got, configContent)
	}
}

// TestCollectLogs_Unix_InstallPathPreferredOverCwd verifies that when BOTH the
// install log dir and a cwd-relative logs/ exist, the install path wins. The
// install file carries content A and the cwd file carries a different content
// B under the same basename; the archived logs/<name> must be A.
func TestCollectLogs_Unix_InstallPathPreferredOverCwd(t *testing.T) {
	installLog := t.TempDir()
	contentA := "install-wins-" + strings.Repeat("a", 300)
	if err := os.WriteFile(filepath.Join(installLog, "enigma.log"), []byte(contentA), 0644); err != nil {
		t.Fatalf("failed to write install log file: %v", err)
	}

	// captures/config install sources are absent, so they fall back to cwd
	// (also absent). logs comes from the install path.
	base := t.TempDir()
	useInstallSources(t,
		installLog,
		filepath.Join(base, "absent-captures"),
		filepath.Join(base, "absent-config.json"),
	)

	t.Chdir(t.TempDir())
	if err := os.Mkdir("logs", 0755); err != nil {
		t.Fatalf("failed to create cwd logs dir: %v", err)
	}
	contentB := "cwd-loses-" + strings.Repeat("z", 300)
	if err := os.WriteFile("logs/enigma.log", []byte(contentB), 0644); err != nil {
		t.Fatalf("failed to write cwd log file: %v", err)
	}

	outName := "test-logs.tar.gz"
	if _, err := CollectLogs(outName); err != nil {
		t.Fatalf("CollectLogs failed: %v", err)
	}

	members := readTarGzMembers(t, outName)
	if got := string(members["logs/enigma.log"]); got != contentA {
		t.Errorf("expected install log content to win: got %q, want %q", got, contentA)
	}
}

// TestCollectLogs_Unix_CwdFallbackWhenInstallAbsent verifies the dev/source-run
// path: when the packaged install paths do not exist, collect-logs falls back
// to gathering logs/, captures/, and config.json from the current working
// directory.
func TestCollectLogs_Unix_CwdFallbackWhenInstallAbsent(t *testing.T) {
	t.Chdir(t.TempDir())
	useCwdSources(t) // install paths point at guaranteed-absent temp paths

	if err := os.Mkdir("logs", 0755); err != nil {
		t.Fatalf("failed to create logs dir: %v", err)
	}
	logContent := "cwdlog-" + strings.Repeat("a", 300)
	if err := os.WriteFile("logs/test.log", []byte(logContent), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}
	if err := os.MkdirAll("captures/session1", 0755); err != nil {
		t.Fatalf("failed to create captures dir: %v", err)
	}
	captureContent := "cwdpcap-" + strings.Repeat("p", 300)
	if err := os.WriteFile("captures/session1/cap.pcap", []byte(captureContent), 0644); err != nil {
		t.Fatalf("failed to write pcap file: %v", err)
	}
	configContent := `{"foo": "` + strings.Repeat("b", 300) + `"}`
	if err := os.WriteFile("config.json", []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config.json: %v", err)
	}

	outName := "test-logs.tar.gz"
	if _, err := CollectLogs(outName); err != nil {
		t.Fatalf("CollectLogs failed: %v", err)
	}

	members := readTarGzMembers(t, outName)
	if got := string(members["logs/test.log"]); got != logContent {
		t.Errorf("logs/test.log content mismatch: got %q, want %q", got, logContent)
	}
	if got := string(members["captures/session1/cap.pcap"]); got != captureContent {
		t.Errorf("captures/session1/cap.pcap content mismatch: got %q, want %q", got, captureContent)
	}
	if got := string(members["config.json"]); got != configContent {
		t.Errorf("config.json content mismatch: got %q, want %q", got, configContent)
	}
}

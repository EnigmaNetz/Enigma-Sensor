package collect_logs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// useCwdSources points the packaged-install source vars at guaranteed-absent
// paths under a temp dir and restores them in cleanup. Every test MUST control
// these vars: they default to REAL absolute system paths (e.g.
// /var/log/enigma-sensor), so a test that leaves them unset could read real
// host state and become nondeterministic. Calling this forces CollectLogs onto
// the cwd-relative fallback (logs/, captures/, config.json), which is what the
// existing tests seed.
func useCwdSources(t *testing.T) {
	t.Helper()
	origLog, origCap, origCfg := installLogDir, installCaptureDir, installConfigPath
	base := t.TempDir()
	installLogDir = filepath.Join(base, "absent-install-logs")
	installCaptureDir = filepath.Join(base, "absent-install-captures")
	installConfigPath = filepath.Join(base, "absent-install-config.json")
	t.Cleanup(func() {
		installLogDir, installCaptureDir, installConfigPath = origLog, origCap, origCfg
	})
}

// useInstallSources points the packaged-install source vars at the given
// (populated) paths and restores them in cleanup, for tests that exercise the
// absolute install-path resolution.
func useInstallSources(t *testing.T, logDir, captureDir, configPath string) {
	t.Helper()
	origLog, origCap, origCfg := installLogDir, installCaptureDir, installConfigPath
	installLogDir = logDir
	installCaptureDir = captureDir
	installConfigPath = configPath
	t.Cleanup(func() {
		installLogDir, installCaptureDir, installConfigPath = origLog, origCap, origCfg
	})
}

// seedDiagnosticContent writes a real log file into the current working
// directory so CollectLogs has actual diagnostic content to gather.
func seedDiagnosticContent(t *testing.T) {
	t.Helper()
	if err := os.Mkdir("logs", 0755); err != nil {
		t.Fatalf("failed to create logs dir: %v", err)
	}
	if err := os.WriteFile("logs/test.log", []byte(strings.Repeat("x", 300)), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}
}

// TestCollectLogs_NoDiagnosticContent_ReturnsError verifies that running
// CollectLogs from a directory with no logs/, no captures/, and no
// config.json fails loudly instead of emitting a hollow archive that contains
// only the generated version.txt and system-info.txt blobs.
func TestCollectLogs_NoDiagnosticContent_ReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	useCwdSources(t)

	_, err := CollectLogs("test-logs" + ArchiveExt)
	if err == nil {
		t.Fatal("expected CollectLogs to return an error when no diagnostic content exists, got nil")
	}
	if !strings.Contains(err.Error(), "no diagnostic content found") {
		t.Errorf("expected error to mention missing diagnostic content, got: %v", err)
	}
	for _, want := range []string{"logs/", "captures/", "config.json"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected error to name %q, got: %v", want, err)
		}
	}
}

// TestCollectLogs_ConfigOnly_Degraded_ReturnsError verifies the degraded-bundle
// guard: when config.json is present but there are no logs and no captures, the
// bundle would carry only configuration and no diagnostic runtime content.
// CollectLogs must reject that condition rather than ship a config-only bundle
// that looks complete to support, and must not leave an archive on disk.
func TestCollectLogs_ConfigOnly_Degraded_ReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	useCwdSources(t)

	// Only a config source, no logs and no captures.
	if err := os.WriteFile("config.json", []byte(`{"foo": "`+strings.Repeat("c", 300)+`"}`), 0644); err != nil {
		t.Fatalf("failed to write config.json: %v", err)
	}

	outName := "test-logs" + ArchiveExt
	_, err := CollectLogs(outName)
	if err == nil {
		t.Fatal("expected CollectLogs to return an error for a config-only (degraded) bundle, got nil")
	}
	// The message must convey BOTH that logs and captures were empty AND that
	// config alone is not enough (the bundle would contain only config).
	for _, want := range []string{"only", "config", "logs", "captures"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected degraded-bundle error to mention %q, got: %v", want, err)
		}
	}
	if _, statErr := os.Stat(outName); !os.IsNotExist(statErr) {
		t.Errorf("expected no archive to be left on disk for a degraded bundle, stat err: %v", statErr)
	}
}

// TestCollectLogs_ArchiveStepFailure_ReturnsError verifies that CollectLogs
// surfaces an error (rather than silently succeeding) when the underlying
// archive-writing step fails.
func TestCollectLogs_ArchiveStepFailure_ReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	useCwdSources(t)
	seedDiagnosticContent(t)

	original := writeArchive
	t.Cleanup(func() { writeArchive = original })
	writeArchive = func(outName string, files []archiveFile, blobs []archiveBlob) (int, error) {
		return 0, fmt.Errorf("simulated archive write failure")
	}

	_, err := CollectLogs("test-logs" + ArchiveExt)
	if err == nil {
		t.Fatal("expected CollectLogs to return an error when writeArchive fails, got nil")
	}
	if !strings.Contains(err.Error(), "simulated archive write failure") {
		t.Errorf("expected error to surface the underlying failure, got: %v", err)
	}
}

// TestCollectLogs_ImplausiblySmallArchive_ReturnsError verifies that
// CollectLogs rejects an archive that is suspiciously small even though the
// write step reported success.
func TestCollectLogs_ImplausiblySmallArchive_ReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	useCwdSources(t)
	seedDiagnosticContent(t)

	original := writeArchive
	t.Cleanup(func() { writeArchive = original })
	writeArchive = func(outName string, files []archiveFile, blobs []archiveBlob) (int, error) {
		// Simulate a writer that "succeeds" but produces an implausibly
		// small file (10 bytes).
		return len(files), os.WriteFile(outName, []byte("tinydata!!"), 0644)
	}

	outName := "test-logs" + ArchiveExt
	_, err := CollectLogs(outName)
	if err == nil {
		t.Fatal("expected CollectLogs to return an error for an implausibly small archive, got nil")
	}
	if !strings.Contains(err.Error(), "small") {
		t.Errorf("expected error to mention 'small', got: %v", err)
	}
}

// TestCollectLogs_MissingArchive_ReturnsError verifies that CollectLogs
// returns an error when the archive step reports success but never actually
// wrote the output file.
func TestCollectLogs_MissingArchive_ReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	useCwdSources(t)
	seedDiagnosticContent(t)

	original := writeArchive
	t.Cleanup(func() { writeArchive = original })
	writeArchive = func(outName string, files []archiveFile, blobs []archiveBlob) (int, error) {
		return len(files), nil // reports success but writes nothing
	}

	outName := "test-logs" + ArchiveExt
	_, err := CollectLogs(outName)
	if err == nil {
		t.Fatal("expected CollectLogs to return an error when the archive file is missing, got nil")
	}
}

// TestCollectLogs_Success_ReturnsArchiveSize verifies that a successful run
// returns the byte size of the archive it wrote, so the caller can report it.
func TestCollectLogs_Success_ReturnsArchiveSize(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	useCwdSources(t)

	if err := os.Mkdir("logs", 0755); err != nil {
		t.Fatalf("failed to create logs dir: %v", err)
	}
	// Pad well past the minimum-size floor so the real archiver produces a
	// plausible archive.
	filler := strings.Repeat("x", 300)
	if err := os.WriteFile("logs/test.log", []byte(filler), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}

	outName := "test-logs" + ArchiveExt

	size, err := CollectLogs(outName)
	if err != nil {
		t.Fatalf("CollectLogs failed: %v", err)
	}

	if size == 0 {
		t.Error("expected CollectLogs to return a non-zero archive size, got 0")
	}

	info, err := os.Stat(outName)
	if err != nil {
		t.Fatalf("expected archive to exist: %v", err)
	}
	if size != info.Size() {
		t.Errorf("expected returned size %d to match the archive on disk (%d bytes)", size, info.Size())
	}
}

// TestCollectLogs_NoFilesArchived_ReturnsError verifies that a bundle holding
// only the generated blobs fails even when the written file clears the
// minimum-size floor. Files are gathered per stat but none can be archived
// (the root-owned logs/ collected as a non-root user case), so the entry count
// reported by the archive writer is the only guard that can fire.
func TestCollectLogs_NoFilesArchived_ReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	useCwdSources(t)
	seedDiagnosticContent(t)

	original := writeArchive
	t.Cleanup(func() { writeArchive = original })
	writeArchive = func(outName string, files []archiveFile, blobs []archiveBlob) (int, error) {
		// Writes a plausibly sized file, but archived none of the gathered
		// source files.
		return 0, os.WriteFile(outName, []byte(strings.Repeat("h", 512)), 0644)
	}

	outName := "test-logs" + ArchiveExt
	_, err := CollectLogs(outName)
	if err == nil {
		t.Fatal("expected CollectLogs to return an error when no gathered file was archived, got nil")
	}
	if !strings.Contains(err.Error(), "no diagnostic files") {
		t.Errorf("expected error to mention that no diagnostic files were archived, got: %v", err)
	}
}

// TestCollectLogs_FailedRun_RemovesArchive verifies that a run that fails after
// the output file was created does not leave a misleading archive on disk.
func TestCollectLogs_FailedRun_RemovesArchive(t *testing.T) {
	tmpDir := t.TempDir()
	t.Chdir(tmpDir)
	useCwdSources(t)
	seedDiagnosticContent(t)

	original := writeArchive
	t.Cleanup(func() { writeArchive = original })
	writeArchive = func(outName string, files []archiveFile, blobs []archiveBlob) (int, error) {
		if err := os.WriteFile(outName, []byte(strings.Repeat("h", 512)), 0644); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("simulated archive write failure")
	}

	outName := "test-logs" + ArchiveExt
	if _, err := CollectLogs(outName); err == nil {
		t.Fatal("expected CollectLogs to return an error, got nil")
	}

	if _, err := os.Stat(outName); !os.IsNotExist(err) {
		t.Errorf("expected the partial archive %s to be removed, stat err: %v", outName, err)
	}
}

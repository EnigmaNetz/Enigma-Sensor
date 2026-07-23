package selfmetrics

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// sink retains allocations so the compiler cannot elide them.
var sink [][]byte

func TestSampleNoOutputDir(t *testing.T) {
	s := Sample("")

	if s.Goroutines <= 0 {
		t.Errorf("Goroutines = %d, want > 0", s.Goroutines)
	}
	if s.HeapAllocBytes == 0 {
		t.Error("HeapAllocBytes = 0, want > 0")
	}
	if s.ZeekOutDirs != -1 {
		t.Errorf("ZeekOutDirs = %d, want -1 when outputDir is empty", s.ZeekOutDirs)
	}

	if runtime.GOOS == "linux" {
		if s.RSSBytes == 0 {
			t.Error("RSSBytes = 0 on linux, want > 0")
		}
		if s.OpenFDs <= 0 {
			t.Errorf("OpenFDs = %d on linux, want > 0", s.OpenFDs)
		}
		if s.ThreadsOS <= 0 {
			t.Errorf("ThreadsOS = %d on linux, want > 0", s.ThreadsOS)
		}
	}
}

func TestSampleCountsZeekOutDirsOnly(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"zeek_out_A", "zeek_out_B", "zeek_out_C", "other"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}
	// decoy: matching prefix but a regular file, not a directory
	if err := os.WriteFile(filepath.Join(dir, "zeek_out_notadir"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write decoy file: %v", err)
	}

	if got := Sample(dir).ZeekOutDirs; got != 3 {
		t.Errorf("ZeekOutDirs = %d, want 3", got)
	}
}

func TestSampleMissingOutputDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does", "not", "exist")

	if got := Sample(missing).ZeekOutDirs; got != -1 {
		t.Errorf("ZeekOutDirs = %d for missing dir, want -1", got)
	}
}

func TestLogLinePopulated(t *testing.T) {
	s := Stats{
		RSSBytes:       123456789,
		OpenFDs:        42,
		ThreadsOS:      7,
		Goroutines:     19,
		HeapAllocBytes: 987654321,
		ZeekOutDirs:    3,
	}

	line := s.LogLine()
	if !strings.Contains(line, "[selfmetrics] ") {
		t.Errorf("LogLine() = %q, want it to contain the %q prefix", line, "[selfmetrics] ")
	}
	for _, want := range []string{"123456789", "42", "7", "19", "987654321", "3"} {
		if !strings.Contains(line, want) {
			t.Errorf("LogLine() = %q, missing value %q", line, want)
		}
	}
	if strings.Contains(line, "n/a") {
		t.Errorf("LogLine() = %q, should not render n/a when all values are available", line)
	}
}

func TestLogLineUnavailableValues(t *testing.T) {
	s := Stats{
		RSSBytes:       0,
		OpenFDs:        -1,
		ThreadsOS:      -1,
		Goroutines:     11,
		HeapAllocBytes: 2048,
		ZeekOutDirs:    -1,
	}

	line := s.LogLine()
	if !strings.Contains(line, "[selfmetrics] ") {
		t.Errorf("LogLine() = %q, want it to contain the %q prefix", line, "[selfmetrics] ")
	}
	if strings.Count(line, "n/a") != 4 {
		t.Errorf("LogLine() = %q, want 4 n/a renderings (rss, fds, threads, zeek dirs)", line)
	}
	if strings.Contains(line, "-1") {
		t.Errorf("LogLine() = %q, should render n/a rather than the -1 sentinel", line)
	}
	for _, want := range []string{"11", "2048"} {
		if !strings.Contains(line, want) {
			t.Errorf("LogLine() = %q, missing available value %q", line, want)
		}
	}
}

func TestSampleObservesHeapGrowth(t *testing.T) {
	sink = nil
	before := Sample("")

	sink = make([][]byte, 0, 20000)
	for i := 0; i < 20000; i++ {
		sink = append(sink, make([]byte, 512))
	}

	after := Sample("")
	if after.HeapAllocBytes <= before.HeapAllocBytes {
		t.Errorf("HeapAllocBytes did not grow: before=%d after=%d", before.HeapAllocBytes, after.HeapAllocBytes)
	}

	runtime.KeepAlive(sink)
	sink = nil
}

// lockedBuffer serializes writes from the logger goroutine against test reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestStartLoggerLogsPeriodicallyAndReturnsOnCancel(t *testing.T) {
	var buf lockedBuffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		StartLogger(ctx, 10*time.Millisecond, "")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartLogger did not return within 2s of context cancellation")
	}

	if n := strings.Count(buf.String(), "[selfmetrics] "); n < 2 {
		t.Errorf("logged %d [selfmetrics] lines, want at least 2", n)
	}
}

func TestStartLoggerLogsImmediatelyWhenContextAlreadyCancelled(t *testing.T) {
	var buf lockedBuffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		StartLogger(ctx, time.Hour, "")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartLogger did not return promptly for an already-cancelled context")
	}

	if n := strings.Count(buf.String(), "[selfmetrics] "); n < 1 {
		t.Errorf("logged %d [selfmetrics] lines, want at least 1 immediate sample", n)
	}
}

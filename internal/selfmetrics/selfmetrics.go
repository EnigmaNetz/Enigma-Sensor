// Package selfmetrics samples the sensor's own resource usage so growth in
// memory, file descriptors or on-disk Zeek output is visible in the log.
package selfmetrics

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

// Stats is a point-in-time sample of the sensor process's own resource usage.
type Stats struct {
	RSSBytes       uint64 // 0 when unavailable
	OpenFDs        int    // -1 when unavailable
	ThreadsOS      int    // -1 when unavailable
	Goroutines     int
	HeapAllocBytes uint64
	ZeekOutDirs    int // -1 when not measured
}

// Sample collects a Stats snapshot. outputDir may be empty, in which case the
// Zeek output directory count is not measured.
func Sample(outputDir string) Stats {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	rss, threads := readRSSAndThreads()

	return Stats{
		RSSBytes:       rss,
		OpenFDs:        countOpenFDs(),
		ThreadsOS:      threads,
		Goroutines:     runtime.NumGoroutine(),
		HeapAllocBytes: mem.HeapAlloc,
		ZeekOutDirs:    countZeekOutDirs(outputDir),
	}
}

// countZeekOutDirs counts directories named zeek_out_* directly under dir.
// Returns -1 when dir is empty or cannot be read.
func countZeekOutDirs(dir string) int {
	if dir == "" {
		return -1
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return -1
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "zeek_out_") {
			count++
		}
	}
	return count
}

// LogLine renders the sample as a single log line, showing "n/a" for any value
// that could not be measured on this platform.
func (s Stats) LogLine() string {
	rss := "n/a"
	if s.RSSBytes > 0 {
		rss = fmt.Sprintf("%d", s.RSSBytes)
	}
	return fmt.Sprintf("[selfmetrics] rss_bytes=%s open_fds=%s os_threads=%s goroutines=%d heap_alloc_bytes=%d zeek_out_dirs=%s",
		rss,
		renderCount(s.OpenFDs),
		renderCount(s.ThreadsOS),
		s.Goroutines,
		s.HeapAllocBytes,
		renderCount(s.ZeekOutDirs),
	)
}

// renderCount renders a count, mapping the -1 unavailable sentinel to "n/a".
func renderCount(v int) string {
	if v < 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d", v)
}

// StartLogger logs a sample immediately and then once per interval until ctx is
// done. It is a pure observer and returns as soon as ctx is cancelled.
func StartLogger(ctx context.Context, interval time.Duration, outputDir string) {
	log.Print(Sample(outputDir).LogLine())

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Print(Sample(outputDir).LogLine())
		}
	}
}

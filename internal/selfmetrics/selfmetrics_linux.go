//go:build linux

package selfmetrics

import (
	"os"
	"strconv"
	"strings"
)

// readRSSAndThreads reads resident set size (bytes) and OS thread count from
// /proc/self/status. Unavailable values come back as 0 and -1 respectively.
func readRSSAndThreads() (uint64, int) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, -1
	}
	return parseProcStatus(data)
}

// parseProcStatus extracts the resident set size in BYTES (VmRSS, reported in kB)
// and the OS thread count (Threads) from /proc/<pid>/status content. Whichever
// field is absent or unparseable comes back as its unavailable sentinel:
// rssBytes is 0 when unknown, threads is -1 when unknown.
func parseProcStatus(data []byte) (rssBytes uint64, threads int) {
	rssBytes = 0
	threads = -1

	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "VmRSS:"):
			// VmRSS is reported in kB, e.g. "VmRSS:      12345 kB".
			fields := strings.Fields(strings.TrimPrefix(line, "VmRSS:"))
			if len(fields) > 0 {
				if kb, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
					rssBytes = kb * 1024
				}
			}
		case strings.HasPrefix(line, "Threads:"):
			if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Threads:"))); err == nil {
				threads = n
			}
		}
	}

	return rssBytes, threads
}

// countOpenFDs counts entries in /proc/self/fd. The count includes the fd held
// open by this read itself; that is consistent run to run, so it is not
// corrected for. Returns -1 when unavailable.
func countOpenFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

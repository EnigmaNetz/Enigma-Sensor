//go:build linux

package config

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	// kbPerMB converts /proc/meminfo values, which are reported in kB.
	kbPerMB = 1024
	// bytesPerMB converts cgroup limit files, which are reported in bytes.
	bytesPerMB = 1024 * 1024
	// cgroupUnlimited is the threshold above which a cgroup byte limit is
	// treated as "no limit". cgroup v1 writes a huge sentinel (commonly
	// 9223372036854771712) rather than an explicit "max".
	cgroupUnlimited = uint64(1) << 62

	cgroupV2LimitPath = "/sys/fs/cgroup/memory.max"
	cgroupV1LimitPath = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
)

// hostAvailableMemoryMB returns the memory budget this process should size itself
// against: the minimum of the host's available memory and any cgroup memory limit
// applied to it. Inside a container /proc/meminfo still reports the host's memory,
// so the cgroup limit is what actually gets the process OOM-killed.
// Returns (0, false) when it cannot be determined.
func hostAvailableMemoryMB() (uint64, bool) {
	hostMB, hostKnown := readMeminfoMB()
	limitMB, limitKnown := readCgroupLimitMB()

	switch {
	case hostKnown && limitKnown:
		if limitMB < hostMB {
			return limitMB, true
		}
		return hostMB, true
	case hostKnown:
		return hostMB, true
	case limitKnown:
		return limitMB, true
	default:
		return 0, false
	}
}

// readMeminfoMB reads /proc/meminfo, degrading to unknown on any read failure.
func readMeminfoMB() (uint64, bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	defer f.Close()
	return parseMeminfoMB(f)
}

// readCgroupLimitMB reads the cgroup v2 memory limit, falling back to the v1 path
// when v2 is absent. Any read failure degrades to unknown.
func readCgroupLimitMB() (uint64, bool) {
	if b, err := os.ReadFile(cgroupV2LimitPath); err == nil {
		return parseCgroupLimitMB(string(b))
	}
	if b, err := os.ReadFile(cgroupV1LimitPath); err == nil {
		return parseCgroupLimitMB(string(b))
	}
	return 0, false
}

// parseMeminfoMB parses /proc/meminfo content, preferring MemAvailable and falling
// back to MemTotal. Values in /proc/meminfo are in kB. Returns (0, false) if
// neither is present or parseable.
func parseMeminfoMB(r io.Reader) (uint64, bool) {
	var totalKB uint64
	var totalKnown bool

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "MemAvailable:":
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				continue
			}
			return kb / kbPerMB, true
		case "MemTotal:":
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				continue
			}
			totalKB, totalKnown = kb, true
		}
	}
	if scanner.Err() != nil || !totalKnown {
		return 0, false
	}
	return totalKB / kbPerMB, true
}

// parseCgroupLimitMB parses the content of a cgroup memory limit file
// (v2 /sys/fs/cgroup/memory.max or v1 /sys/fs/cgroup/memory/memory.limit_in_bytes).
// The content is a byte count, or the literal "max" (v2) / a huge sentinel (v1)
// meaning unlimited. Returns (0, false) for unlimited, empty, or unparseable input.
func parseCgroupLimitMB(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0, false
	}
	bytes, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	if bytes >= cgroupUnlimited {
		return 0, false
	}
	return bytes / bytesPerMB, true
}

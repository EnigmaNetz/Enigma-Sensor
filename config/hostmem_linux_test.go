//go:build linux

package config

import (
	"strings"
	"testing"
)

// TestParseMeminfoMB checks the kB-to-MB conversion with exact expected values.
// The conversion is the whole point: returning the raw kB figure would overstate
// available memory by 1024x and defeat the memory-scaled worker default.
func TestParseMeminfoMB(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantMB    uint64
		wantKnown bool
	}{
		{
			name:      "MemAvailable is preferred and converted from kB to MB",
			input:     "MemTotal:       8388608 kB\nMemAvailable:   2097152 kB\n",
			wantMB:    2048,
			wantKnown: true,
		},
		{
			name:      "MemAvailable alone",
			input:     "MemAvailable:   1048576 kB\n",
			wantMB:    1024,
			wantKnown: true,
		},
		{
			name:      "falls back to MemTotal when MemAvailable is absent",
			input:     "MemTotal:       4194304 kB\nMemFree:         524288 kB\n",
			wantMB:    4096,
			wantKnown: true,
		},
		{
			name:      "MemAvailable wins even when it appears after MemTotal",
			input:     "MemTotal:      16777216 kB\nMemFree:        1048576 kB\nMemAvailable:   8388608 kB\n",
			wantMB:    8192,
			wantKnown: true,
		},
		{
			name:      "neither field present is unknown",
			input:     "MemFree:         524288 kB\nBuffers:          16384 kB\n",
			wantKnown: false,
		},
		{
			name:      "non-numeric MemAvailable with no MemTotal is unknown",
			input:     "MemAvailable:   notanumber kB\n",
			wantKnown: false,
		},
		{
			name:      "non-numeric MemAvailable falls back to a valid MemTotal",
			input:     "MemTotal:       2097152 kB\nMemAvailable:   notanumber kB\n",
			wantMB:    2048,
			wantKnown: true,
		},
		{
			name:      "non-numeric MemTotal is unknown",
			input:     "MemTotal:       garbage kB\n",
			wantKnown: false,
		},
		{
			name:      "empty input is unknown",
			input:     "",
			wantKnown: false,
		},
		{
			name:      "realistic /proc/meminfo excerpt",
			wantMB:    3072,
			wantKnown: true,
			input: `MemTotal:        8127792 kB
MemFree:          204936 kB
MemAvailable:    3145728 kB
Buffers:           64712 kB
Cached:          4102340 kB
SwapCached:            0 kB
Active:          2318476 kB
Inactive:        4809912 kB
SwapTotal:       2097152 kB
SwapFree:        2097152 kB
Dirty:               612 kB
`,
		},
		{
			name:      "sub-MB value floors to zero but is still known",
			input:     "MemAvailable:        512 kB\n",
			wantMB:    0,
			wantKnown: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMB, gotKnown := parseMeminfoMB(strings.NewReader(tt.input))
			if gotKnown != tt.wantKnown {
				t.Fatalf("parseMeminfoMB() known = %v, want %v (value %d)", gotKnown, tt.wantKnown, gotMB)
			}
			if gotMB != tt.wantMB {
				t.Errorf("parseMeminfoMB() = %d MB, want %d MB", gotMB, tt.wantMB)
			}
		})
	}
}

// TestParseCgroupLimitMB checks the bytes-to-MB conversion and the unlimited
// sentinels. cgroup limit files are in BYTES, not kB: treating them as kB would
// report a 1GB container as having 1TB of headroom.
func TestParseCgroupLimitMB(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantMB    uint64
		wantKnown bool
	}{
		{
			name:      "1GiB in bytes converts to 1024 MB",
			input:     "1073741824",
			wantMB:    1024,
			wantKnown: true,
		},
		{
			name:      "512MiB in bytes converts to 512 MB",
			input:     "536870912",
			wantMB:    512,
			wantKnown: true,
		},
		{
			name:      "trailing newline is tolerated",
			input:     "2147483648\n",
			wantMB:    2048,
			wantKnown: true,
		},
		{
			name:      "surrounding whitespace is tolerated",
			input:     "  1073741824  \n",
			wantMB:    1024,
			wantKnown: true,
		},
		{
			name:      "cgroup v2 literal max is unlimited",
			input:     "max\n",
			wantKnown: false,
		},
		{
			name:      "cgroup v1 huge sentinel is unlimited",
			input:     "9223372036854771712\n",
			wantKnown: false,
		},
		{
			name:      "empty input is unknown",
			input:     "",
			wantKnown: false,
		},
		{
			name:      "whitespace-only input is unknown",
			input:     "   \n",
			wantKnown: false,
		},
		{
			name:      "garbage is unknown",
			input:     "not-a-number\n",
			wantKnown: false,
		},
		{
			name:      "negative value is unknown",
			input:     "-1\n",
			wantKnown: false,
		},
		{
			name:      "sub-MB limit floors to zero but is still known",
			input:     "1024",
			wantMB:    0,
			wantKnown: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMB, gotKnown := parseCgroupLimitMB(tt.input)
			if gotKnown != tt.wantKnown {
				t.Fatalf("parseCgroupLimitMB(%q) known = %v, want %v (value %d)", tt.input, gotKnown, tt.wantKnown, gotMB)
			}
			if gotMB != tt.wantMB {
				t.Errorf("parseCgroupLimitMB(%q) = %d MB, want %d MB", tt.input, gotMB, tt.wantMB)
			}
		})
	}
}

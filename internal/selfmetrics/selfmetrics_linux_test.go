//go:build linux

package selfmetrics

import "testing"

// TestParseProcStatus pins the kB-to-bytes conversion of VmRSS with exact
// expected byte counts. Dropping the * 1024 would under-report resident memory
// by 1024x, which is exactly the kind of units bug a "greater than zero"
// assertion would sail straight past.
func TestParseProcStatus(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantRSS     uint64
		wantThreads int
	}{
		{
			name: "realistic /proc/self/status excerpt",
			input: `Name:	sensor
Umask:	0022
State:	S (sleeping)
Tgid:	1234
Pid:	1234
PPid:	1
VmPeak:	  1234567 kB
VmSize:	  1234000 kB
VmRSS:	    12345 kB
RssAnon:	     9000 kB
Threads:	7
SigQ:	0/31234
`,
			wantRSS:     12345 * 1024,
			wantThreads: 7,
		},
		{
			name:        "minimal pair",
			input:       "VmRSS:\t2048 kB\nThreads:\t1\n",
			wantRSS:     2048 * 1024,
			wantThreads: 1,
		},
		{
			name:        "VmRSS missing leaves the zero sentinel",
			input:       "Name:\tsensor\nThreads:\t4\n",
			wantRSS:     0,
			wantThreads: 4,
		},
		{
			name:        "Threads missing leaves the -1 sentinel",
			input:       "VmRSS:\t512 kB\n",
			wantRSS:     512 * 1024,
			wantThreads: -1,
		},
		{
			name:        "malformed VmRSS value falls back to the sentinel",
			input:       "VmRSS:\tnotanumber kB\nThreads:\t3\n",
			wantRSS:     0,
			wantThreads: 3,
		},
		{
			name:        "malformed Threads value falls back to the sentinel",
			input:       "VmRSS:\t4096 kB\nThreads:\tmany\n",
			wantRSS:     4096 * 1024,
			wantThreads: -1,
		},
		{
			name:        "both malformed falls back to both sentinels",
			input:       "VmRSS:\t\nThreads:\t\n",
			wantRSS:     0,
			wantThreads: -1,
		},
		{
			name:        "empty input yields both sentinels",
			input:       "",
			wantRSS:     0,
			wantThreads: -1,
		},
		{
			name:        "zero RSS is reported as zero bytes",
			input:       "VmRSS:\t0 kB\nThreads:\t2\n",
			wantRSS:     0,
			wantThreads: 2,
		},
		{
			name:        "large RSS does not overflow",
			input:       "VmRSS:\t8388608 kB\nThreads:\t12\n",
			wantRSS:     8388608 * 1024,
			wantThreads: 12,
		},
		{
			name:        "no trailing newline on the final field",
			input:       "VmRSS:\t1000 kB\nThreads:\t9",
			wantRSS:     1000 * 1024,
			wantThreads: 9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRSS, gotThreads := parseProcStatus([]byte(tt.input))
			if gotRSS != tt.wantRSS {
				t.Errorf("parseProcStatus() rssBytes = %d, want %d", gotRSS, tt.wantRSS)
			}
			if gotThreads != tt.wantThreads {
				t.Errorf("parseProcStatus() threads = %d, want %d", gotThreads, tt.wantThreads)
			}
		})
	}
}

// TestParseProcStatus_RSSIsBytesNotKB states the units contract on its own so a
// regression to kB fails with an unambiguous message rather than hiding inside
// a table row.
func TestParseProcStatus_RSSIsBytesNotKB(t *testing.T) {
	const kB = 65432
	rss, _ := parseProcStatus([]byte("VmRSS:\t65432 kB\nThreads:\t1\n"))

	if rss == kB {
		t.Fatalf("parseProcStatus() returned %d, which is the raw kB value; it must return bytes", rss)
	}
	if want := uint64(kB) * 1024; rss != want {
		t.Errorf("parseProcStatus() rssBytes = %d, want %d", rss, want)
	}
}

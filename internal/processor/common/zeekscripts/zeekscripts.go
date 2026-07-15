// Package zeekscripts embeds the bundled Zeek scripts into the sensor binary and
// materializes them to a run directory at processing time.
//
// Embedding removes the previous dependency on locating zeek-scripts/ relative to
// the process's current working directory, which silently failed on packaged
// (.deb/RPM systemd) installs where CWD is / and the scripts were not shipped.
// The binary now always carries the scripts regardless of how it is launched.
package zeekscripts

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

// Script filenames embedded in the binary. These are the canonical names Zeek
// writes logs for (e.g. ja3-ja4-fingerprinting.zeek -> ja3_ja4.log / ja4s.log).
const (
	JA3JA4   = "ja3-ja4-fingerprinting.zeek"
	DHCP     = "dhcp-fingerprint.zeek"
	Sampling = "sampling.zeek"
)

//go:embed *.zeek
var scripts embed.FS

// Materialize writes the embedded script `name` into dir and returns the path to
// the written file, so callers can pass an absolute path to Zeek. The file is
// overwritten if it already exists (run directories are per-PCAP and ephemeral).
func Materialize(dir, name string) (string, error) {
	data, err := scripts.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("read embedded zeek script %q: %w", name, err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create script dir %s: %w", dir, err)
	}
	dest := filepath.Join(dir, name)
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		return "", fmt.Errorf("write zeek script %q to %s: %w", name, dir, err)
	}
	return dest, nil
}

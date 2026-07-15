package types

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"EnigmaNetz/Enigma-Go-Sensor/internal/processor/common/zeekscripts"
)

// Processor defines the interface for platform-agnostic PCAP processing using Zeek.
// Implementations should process the given PCAP file and return XLSX file paths for both con.log and dns.log.
type Processor interface {
	ProcessPCAP(pcapPath string, opts ProcessOptions) (ProcessedData, error)
}

// ProcessOptions carries the per-run knobs for ProcessPCAP. Bundling them keeps
// the ProcessPCAP signature stable as new knobs are added.
type ProcessOptions struct {
	// SamplingPercentage is the percentage of traffic to process (0-100).
	SamplingPercentage float64
	// ExcludedSubnets is the list of CIDRs whose flows/records must be dropped
	// from the produced logs before upload. Empty = no filtering.
	ExcludedSubnets []string
}

// ZeekLogFiles is the single source of truth for the Zeek logs the sensor
// uploads. Both FilterExcludedSubnets and RenameZeekLogsToXLSX key off this
// list so "what we filter" and "what we upload" can never drift apart — adding
// a sixth uploaded log here automatically brings it under subnet filtering on
// every platform.
var ZeekLogFiles = []string{"conn.log", "dns.log", "dhcp.log", "ja3_ja4.log", "ja4s.log"}

// ProcessedData represents the output of PCAP processing.
type ProcessedData struct {
	ConnPath   string                 // XLSX file path for conn.xlsx
	DNSPath    string                 // XLSX file path for dns.xlsx
	DHCPPath   string                 // XLSX file path for dhcp.xlsx
	JA3JA4Path string                 // XLSX file path for ja3_ja4.xlsx
	JA4SPath   string                 // XLSX file path for ja4s.xlsx
	Metadata   map[string]interface{} // Additional processing metadata
}

// FS abstracts file system operations for testability (matches Linux, used by Windows with os).
type FS interface {
	Stat(name string) (os.FileInfo, error)
	Rename(oldpath, newpath string) error
}

// OSFS is a real FS implementation using the os package.
type OSFS struct{}

func (OSFS) Stat(name string) (os.FileInfo, error) { return os.Stat(name) }
func (OSFS) Rename(oldpath, newpath string) error  { return os.Rename(oldpath, newpath) }

// RenameZeekLogsToXLSX renames Zeek log files to .xlsx and returns a map of original log names to new paths.
// Returns error if any rename fails. Missing files are skipped.
func RenameZeekLogsToXLSX(fs FS, runDir string, logFiles []string) (map[string]string, error) {
	paths := make(map[string]string)
	for _, logName := range logFiles {
		logPath := filepath.Join(runDir, logName)
		if _, err := fs.Stat(logPath); err == nil {
			xlsxPath := filepath.Join(runDir, logName[:len(logName)-len(filepath.Ext(logName))]+".xlsx")
			if err := fs.Rename(logPath, xlsxPath); err != nil {
				return nil, fmt.Errorf("failed to rename %s to xlsx: %w", logName, err)
			}
			paths[logName] = xlsxPath
		}
	}
	return paths, nil
}

// PrepareZeekArgsWithSampling prepares Zeek command arguments including sampling
// configuration. Primarily used by Linux; Windows handles sampling via main.zeek.
func PrepareZeekArgsWithSampling(runDir string, samplingPercentage float64, baseArgs []string) []string {
	args := make([]string, len(baseArgs))
	copy(args, baseArgs)

	// Add sampling script if sampling percentage is less than 100. The embedded
	// sampling.zeek is materialized into runDir and the Sampling::sampling_percentage
	// arg is prepended before its path.
	if samplingPercentage < 100 {
		if path, err := zeekscripts.Materialize(runDir, zeekscripts.Sampling); err != nil {
			log.Printf("[processor] Warning: could not materialize sampling script (%v); processing all traffic", err)
		} else {
			args = append(args, fmt.Sprintf("Sampling::sampling_percentage=%.1f", samplingPercentage))
			args = append(args, path)
			log.Printf("[processor] Added sampling script at %.1f%% from %s", samplingPercentage, path)
		}
	}

	return args
}

// AppendZeekScript materializes the embedded Zeek script `script` into runDir and
// appends its path to args. Returns the updated args, or the original args and an
// error if the script could not be written. Scripts are sourced from the binary
// (see the zeekscripts package), not from a CWD-relative filesystem lookup, so
// discovery no longer depends on the process's working directory.
func AppendZeekScript(args []string, runDir, script string) ([]string, error) {
	path, err := zeekscripts.Materialize(runDir, script)
	if err != nil {
		return args, err
	}
	log.Printf("[processor] Added Zeek script %s from %s", script, path)
	return append(args, path), nil
}

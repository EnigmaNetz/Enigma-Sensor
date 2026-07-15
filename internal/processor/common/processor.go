package types

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
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

// PrepareZeekArgsWithSampling prepares Zeek command arguments including sampling configuration
// This is primarily used by Linux; Windows handles sampling via main.zeek
func PrepareZeekArgsWithSampling(pcapPath, runDir string, samplingPercentage float64, baseArgs []string) []string {
	args := make([]string, len(baseArgs))
	copy(args, baseArgs)

	// Add sampling script if sampling percentage is less than 100. Sampling is a
	// special case of script discovery: the same candidate-path lookup, but it
	// prepends a Sampling::sampling_percentage arg before the script path.
	if samplingPercentage < 100 {
		if samplingScriptPath := findZeekScript(OSFS{}, pcapPath, "sampling.zeek"); samplingScriptPath != "" {
			args = append(args, fmt.Sprintf("Sampling::sampling_percentage=%.1f", samplingPercentage))
			args = append(args, samplingScriptPath)
			log.Printf("[processor] Added sampling script at %.1f%% from %s", samplingPercentage, samplingScriptPath)
		} else {
			log.Printf("[processor] Warning: sampling script not found, processing all traffic")
		}
	}

	return args
}

// zeekScriptCandidates returns the standard locations a bundled Zeek script named
// `script` may live in, relative to the current working directory and to the pcap
// directory. This is the single source of truth for where the sensor looks for
// its zeek-scripts/ assets across sampling, DHCP, and JA3/JA4 discovery.
func zeekScriptCandidates(pcapPath, script string) []string {
	return []string{
		filepath.Join("zeek-scripts", script),
		filepath.Join("..", "..", "zeek-scripts", script),
		filepath.Join(filepath.Dir(pcapPath), "..", "..", "zeek-scripts", script),
	}
}

// findZeekScript returns the first candidate path for `script` that exists per fs,
// or "" if none resolve.
func findZeekScript(fs FS, pcapPath, script string) string {
	for _, path := range zeekScriptCandidates(pcapPath, script) {
		if _, err := fs.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// AppendZeekScriptIfFound locates the bundled Zeek script `script` and, if found,
// appends its path to args and returns (args, true). If no candidate resolves it
// returns (args, false) so the caller can decide how to report the miss (the
// upload path tolerates missing logs, so a silent miss is easy to overlook).
// Stat goes through the injected FS so the discovery loop stays unit-testable.
func AppendZeekScriptIfFound(fs FS, args []string, pcapPath, script string) ([]string, bool) {
	path := findZeekScript(fs, pcapPath, script)
	if path == "" {
		return args, false
	}
	log.Printf("[processor] Added Zeek script %s from %s", script, path)
	return append(args, path), true
}

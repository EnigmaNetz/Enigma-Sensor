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
	ProcessPCAP(pcapPath string, samplingPercentage float64) (ProcessedData, error)
}

// ProcessedData represents the output of PCAP processing.
type ProcessedData struct {
	ConnPath string                 // XLSX file path for conn.xlsx
	DNSPath  string                 // XLSX file path for dns.xlsx
	Metadata map[string]interface{} // Additional processing metadata
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

	// Add sampling script if sampling percentage is less than 100
	if samplingPercentage < 100 {
		// Try to find the sampling script in various locations
		possiblePaths := []string{
			"zeek-scripts/sampling.zeek",
			filepath.Join("..", "..", "zeek-scripts", "sampling.zeek"),
			filepath.Join(filepath.Dir(pcapPath), "..", "..", "zeek-scripts", "sampling.zeek"),
		}

		var samplingScriptPath string
		for _, path := range possiblePaths {
			if _, err := os.Stat(path); err == nil {
				samplingScriptPath = path
				break
			}
		}

		if samplingScriptPath != "" {
			args = append(args, fmt.Sprintf("Sampling::sampling_percentage=%.1f", samplingPercentage))
			args = append(args, samplingScriptPath)
			log.Printf("[processor] Added sampling script at %.1f%% from %s", samplingPercentage, samplingScriptPath)
		} else {
			log.Printf("[processor] Warning: sampling script not found, processing all traffic")
		}
	}

	return args
}

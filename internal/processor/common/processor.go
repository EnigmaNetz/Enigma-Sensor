package types

import (
	"fmt"
	"os"
	"path/filepath"
)

// Processor defines the interface for platform-agnostic PCAP processing using Zeek.
// Implementations should process the given PCAP file and return XLSX file paths for both con.log and dns.log.
type Processor interface {
	ProcessPCAP(pcapPath string) (ProcessedData, error)
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

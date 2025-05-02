//go:build linux || darwin

package linux

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	types "EnigmaNetz/Enigma-Go-Agent/internal/processor/common"
)

// zeekBinary is the path to the Zeek executable
const zeekBinary = "/opt/zeek/bin/zeek"

// zeekLogFiles are the Zeek logs we care about
var zeekLogFiles = []string{"conn.log", "dns.log"}

// Processor implements the Processor interface for Linux
type Processor struct{}

func NewProcessor() *Processor {
	return &Processor{}
}

// ProcessPCAP runs Zeek on the given PCAP, converts logs to XLSX, and returns their paths
func (p *Processor) ProcessPCAP(pcapPath string) (types.ProcessedData, error) {
	// Use CAPTURE_OUTPUT_DIR from environment, fallback to ./captures if not set
	outDir := os.Getenv("CAPTURE_OUTPUT_DIR")
	if outDir == "" {
		outDir = "./captures"
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Printf("[processor] Failed to create output dir: %v", err)
		return types.ProcessedData{}, fmt.Errorf("failed to create output dir: %w", err)
	}
	log.Printf("[processor] Output directory: %s", outDir)

	// Create a unique subdirectory for this processing run
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	runDir := filepath.Join(outDir, "zeek_out_"+timestamp)
	if err := os.MkdirAll(runDir, 0755); err != nil {
		log.Printf("[processor] Failed to create run dir: %v", err)
		return types.ProcessedData{}, fmt.Errorf("failed to create run dir: %w", err)
	}
	log.Printf("[processor] Run directory created: %s", runDir)

	// Copy the PCAP file to the runDir if not already there
	pcapBase := filepath.Base(pcapPath)
	pcapDest := filepath.Join(runDir, pcapBase)
	if absSrc, _ := filepath.Abs(pcapPath); absSrc != pcapDest {
		srcFile, err := os.Open(pcapPath)
		if err != nil {
			log.Printf("[processor] Failed to open source PCAP: %v", err)
			return types.ProcessedData{}, fmt.Errorf("failed to open source PCAP: %w", err)
		}
		defer srcFile.Close()
		dstFile, err := os.Create(pcapDest)
		if err != nil {
			log.Printf("[processor] Failed to create destination PCAP: %v", err)
			return types.ProcessedData{}, fmt.Errorf("failed to create destination PCAP: %w", err)
		}
		defer dstFile.Close()
		if _, err := io.Copy(dstFile, srcFile); err != nil {
			log.Printf("[processor] Failed to copy PCAP: %v", err)
			return types.ProcessedData{}, fmt.Errorf("failed to copy PCAP: %w", err)
		}
		log.Printf("[processor] Copied PCAP to %s", pcapDest)
	} else {
		log.Printf("[processor] PCAP already in run directory: %s", pcapDest)
	}

	// Run Zeek
	log.Printf("[processor] Running Zeek: %s -r %s Log::default_logdir=%s -C", zeekBinary, pcapDest, runDir)
	cmd := exec.Command(zeekBinary, "-r", pcapDest, fmt.Sprintf("Log::default_logdir=%s", runDir), "-C")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("[processor] Zeek execution failed: %v", err)
		return types.ProcessedData{}, fmt.Errorf("zeek failed: %w", err)
	}
	log.Printf("[processor] Zeek execution completed successfully.")

	// Convert Zeek logs to XLSX (now: just rename to .xlsx)
	paths := make(map[string]string)
	for _, logName := range zeekLogFiles {
		logPath := filepath.Join(runDir, logName)
		log.Printf("[processor] Checking for Zeek log: %s", logPath)
		if _, err := os.Stat(logPath); err == nil {
			xlsxPath := filepath.Join(runDir, logName[:len(logName)-len(filepath.Ext(logName))]+".xlsx")
			log.Printf("[processor] Renaming %s to %s...", logPath, xlsxPath)
			if err := os.Rename(logPath, xlsxPath); err != nil {
				log.Printf("[processor] Failed to rename %s to xlsx: %v", logName, err)
				return types.ProcessedData{}, fmt.Errorf("failed to rename %s to xlsx: %w", logName, err)
			}
			log.Printf("[processor] Successfully renamed %s to %s", logPath, xlsxPath)
			paths[logName] = xlsxPath
		} else {
			log.Printf("[processor] Zeek log not found: %s", logPath)
		}
	}

	metadata := map[string]interface{}{
		"zeek_out_dir": runDir,
		"timestamp":    timestamp,
		"pcap_path":    pcapDest,
	}
	log.Printf("[processor] Returning results: conn.xlsx=%s, dns.xlsx=%s, metadata=%v", paths["conn.log"], paths["dns.log"], metadata)

	return types.ProcessedData{
		ConnPath: paths["conn.log"],
		DNSPath:  paths["dns.log"],
		Metadata: metadata,
	}, nil
}

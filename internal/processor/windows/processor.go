//go:build windows

package windows

import (
	types "EnigmaNetz/Enigma-Go-Sensor/internal/processor/common"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type execCmdFunc func(name string, arg ...string) *exec.Cmd

type Processor struct {
	execCmd execCmdFunc
	fs      types.FS
}

func NewProcessor() *Processor {
	return &Processor{
		execCmd: exec.Command,
		fs:      types.OSFS{},
	}
}

// Exported for testing
func NewTestProcessor(execCmd execCmdFunc, fs types.FS) *Processor {
	return &Processor{
		execCmd: execCmd,
		fs:      fs,
	}
}

func toZeekPath(path string) string {
	return strings.ReplaceAll(path, string(os.PathSeparator), "/")
}

// prepareWindowsZeekArgsWithSampling prepares Zeek arguments for Windows using the copied sampling script
func prepareWindowsZeekArgsWithSampling(runDir string, samplingPercentage float64, baseArgs []string) []string {
	args := make([]string, len(baseArgs))
	copy(args, baseArgs)

	// Add sampling percentage parameter if sampling is enabled
	// The sampling script is already loaded via main.zeek
	if samplingPercentage < 100 {
		args = append(args, fmt.Sprintf("Sampling::sampling_percentage=%.1f", samplingPercentage))
		log.Printf("[processor] Added sampling configuration at %.1f%% (script loaded via main.zeek)", samplingPercentage)
	}

	return args
}

func (p *Processor) ProcessPCAP(pcapPath string, samplingPercentage float64) (types.ProcessedData, error) {
	runDir := filepath.Dir(pcapPath)
	zeekBaseDir := filepath.Join("zeek-windows", "zeek-runtime-win64")
	zeekPath := filepath.Join(zeekBaseDir, "bin", "zeek.exe")
	if _, err := p.fs.Stat(zeekPath); err != nil {
		log.Printf("[processor] Zeek executable not found at %s: %v", zeekPath, err)
		return types.ProcessedData{}, fmt.Errorf("zeek executable not found: %w", err)
	}
	log.Printf("[processor] Run directory: %s", runDir)

	zeekShareAbs, err := filepath.Abs(filepath.Join(zeekBaseDir, "share", "zeek"))
	if err != nil {
		log.Printf("[processor] Failed to get absolute path for ZEEKPATH: %v", err)
		return types.ProcessedData{}, err
	}

	// Normalize paths for Zeek
	zeekRunDir := toZeekPath(runDir)
	zeekPcapPath := toZeekPath(pcapPath)
	zeekScript := toZeekPath(filepath.Join(zeekShareAbs, "site", "custom-scripts", "main.zeek"))

	// Prepare Zeek command arguments with sampling
	baseArgs := []string{"-r", zeekPcapPath, zeekScript, fmt.Sprintf("Log::default_logdir=%s", zeekRunDir), "-C"}

	// For Windows, we handle sampling by modifying the search paths to use absolute paths
	zeekArgs := prepareWindowsZeekArgsWithSampling(runDir, samplingPercentage, baseArgs)

	log.Printf("[processor] Running Zeek: %s %v", zeekPath, zeekArgs)

	cmd := p.execCmd("bin/zeek.exe", zeekArgs...)
	cmd.Dir = zeekBaseDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "ZEEKPATH="+zeekShareAbs)
	if err := cmd.Run(); err != nil {
		log.Printf("[processor] Zeek execution failed: %v", err)
		return types.ProcessedData{}, fmt.Errorf("zeek failed: %w", err)
	}
	log.Printf("[processor] Zeek execution completed successfully.")

	logFiles := []string{"conn.log", "dns.log", "dhcp.log", "ja3_ja4.log", "ja4s.log"}
	paths, err := types.RenameZeekLogsToXLSX(p.fs, runDir, logFiles)
	if err != nil {
		log.Printf("[processor] Failed to rename Zeek logs: %v", err)
		return types.ProcessedData{}, err
	}

	metadata := map[string]interface{}{
		"zeek_out_dir":        runDir,
		"timestamp":           time.Now().UTC().Format("20060102T150405Z"),
		"pcap_path":           pcapPath,
		"sampling_percentage": samplingPercentage,
	}
	log.Printf("[processor] Returning results: conn.xlsx=%s, dns.xlsx=%s, dhcp.xlsx=%s, ja3_ja4.xlsx=%s, ja4s.xlsx=%s, metadata=%v", paths["conn.log"], paths["dns.log"], paths["dhcp.log"], paths["ja3_ja4.log"], paths["ja4s.log"], metadata)

	return types.ProcessedData{
		ConnPath:   paths["conn.log"],
		DNSPath:    paths["dns.log"],
		DHCPPath:   paths["dhcp.log"],
		JA3JA4Path: paths["ja3_ja4.log"],
		JA4SPath:   paths["ja4s.log"],
		Metadata:   metadata,
	}, nil
}

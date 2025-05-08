//go:build windows

package windows

import (
	types "EnigmaNetz/Enigma-Go-Agent/internal/processor/common"
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

func (p *Processor) ProcessPCAP(pcapPath string) (types.ProcessedData, error) {
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

	log.Printf("[processor] Running Zeek: %s -r %s %s Log::default_logdir=%s -C", zeekPath, zeekPcapPath, zeekScript, zeekRunDir)

	cmd := p.execCmd("bin/zeek.exe", "-r", zeekPcapPath, zeekScript, fmt.Sprintf("Log::default_logdir=%s", zeekRunDir), "-C")
	cmd.Dir = zeekBaseDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "ZEEKPATH="+zeekShareAbs)
	if err := cmd.Run(); err != nil {
		log.Printf("[processor] Zeek execution failed: %v", err)
		return types.ProcessedData{}, fmt.Errorf("zeek failed: %w", err)
	}
	log.Printf("[processor] Zeek execution completed successfully.")

	logFiles := []string{"conn.log", "dns.log"}
	paths, err := types.RenameZeekLogsToXLSX(p.fs, runDir, logFiles)
	if err != nil {
		log.Printf("[processor] Failed to rename Zeek logs: %v", err)
		return types.ProcessedData{}, err
	}

	metadata := map[string]interface{}{
		"zeek_out_dir": runDir,
		"timestamp":    time.Now().UTC().Format("20060102T150405Z"),
		"pcap_path":    pcapPath,
	}
	log.Printf("[processor] Returning results: conn.xlsx=%s, dns.xlsx=%s, metadata=%v", paths["conn.log"], paths["dns.log"], metadata)

	return types.ProcessedData{
		ConnPath: paths["conn.log"],
		DNSPath:  paths["dns.log"],
		Metadata: metadata,
	}, nil
}

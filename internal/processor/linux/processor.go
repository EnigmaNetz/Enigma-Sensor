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

// Dependency interfaces for testability
// FS abstracts file system operations
//go:generate mockgen -destination=fs_mock.go -package=linux . FS
//go:generate mockgen -destination=exec_mock.go -package=linux . CmdRunner

type FS interface {
	MkdirAll(path string, perm os.FileMode) error
	Stat(name string) (os.FileInfo, error)
	Open(name string) (*os.File, error)
	Create(name string) (*os.File, error)
	Rename(oldpath, newpath string) error
}

type Cmd interface {
	Run() error
}

type CmdRunner interface {
	Command(name string, arg ...string) Cmd
}

// Real implementations

type realFS struct{}

func (realFS) MkdirAll(path string, perm os.FileMode) error { return os.MkdirAll(path, perm) }
func (realFS) Stat(name string) (os.FileInfo, error)        { return os.Stat(name) }
func (realFS) Open(name string) (*os.File, error)           { return os.Open(name) }
func (realFS) Create(name string) (*os.File, error)         { return os.Create(name) }
func (realFS) Rename(oldpath, newpath string) error         { return os.Rename(oldpath, newpath) }

type realCmd struct{ cmd *exec.Cmd }

func (r *realCmd) Run() error { return r.cmd.Run() }

type realCmdRunner struct{}

func (realCmdRunner) Command(name string, arg ...string) Cmd {
	return &realCmd{cmd: exec.Command(name, arg...)}
}

// Processor implements the Processor interface for Linux
// Now supports dependency injection for testability

type Processor struct {
	fs        FS
	cmdRunner CmdRunner
	zeekPath  string
}

func NewProcessor() *Processor {
	return &Processor{
		fs:        realFS{},
		cmdRunner: realCmdRunner{},
		zeekPath:  zeekBinary,
	}
}

// For tests
func NewProcessorWithDeps(fs FS, cmdRunner CmdRunner, zeekPath string) *Processor {
	return &Processor{fs: fs, cmdRunner: cmdRunner, zeekPath: zeekPath}
}

// ProcessPCAP runs Zeek on the given PCAP, converts logs to XLSX, and returns their paths
func (p *Processor) ProcessPCAP(pcapPath string) (types.ProcessedData, error) {
	outDir := os.Getenv("CAPTURE_OUTPUT_DIR")
	if outDir == "" {
		outDir = "./captures"
	}
	if err := p.fs.MkdirAll(outDir, 0755); err != nil {
		log.Printf("[processor] Failed to create output dir: %v", err)
		return types.ProcessedData{}, fmt.Errorf("failed to create output dir: %w", err)
	}
	log.Printf("[processor] Output directory: %s", outDir)

	timestamp := time.Now().UTC().Format("20060102T150405Z")
	runDir := filepath.Join(outDir, "zeek_out_"+timestamp)
	if err := p.fs.MkdirAll(runDir, 0755); err != nil {
		log.Printf("[processor] Failed to create run dir: %v", err)
		return types.ProcessedData{}, fmt.Errorf("failed to create run dir: %w", err)
	}
	log.Printf("[processor] Run directory created: %s", runDir)

	pcapBase := filepath.Base(pcapPath)
	pcapDest := filepath.Join(runDir, pcapBase)
	if absSrc, _ := filepath.Abs(pcapPath); absSrc != pcapDest {
		srcFile, err := p.fs.Open(pcapPath)
		if err != nil {
			log.Printf("[processor] Failed to open source PCAP: %v", err)
			return types.ProcessedData{}, fmt.Errorf("failed to open source PCAP: %w", err)
		}
		defer srcFile.Close()
		dstFile, err := p.fs.Create(pcapDest)
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

	log.Printf("[processor] Running Zeek: %s -r %s Log::default_logdir=%s -C", p.zeekPath, pcapDest, runDir)
	cmd := p.cmdRunner.Command(p.zeekPath, "-r", pcapDest, fmt.Sprintf("Log::default_logdir=%s", runDir), "-C")
	cmdStdout, ok := cmd.(*realCmd)
	if ok {
		cmdStdout.cmd.Stdout = os.Stdout
		cmdStdout.cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		log.Printf("[processor] Zeek execution failed: %v", err)
		return types.ProcessedData{}, fmt.Errorf("zeek failed: %w", err)
	}
	log.Printf("[processor] Zeek execution completed successfully.")

	paths := make(map[string]string)
	for _, logName := range zeekLogFiles {
		logPath := filepath.Join(runDir, logName)
		log.Printf("[processor] Checking for Zeek log: %s", logPath)
		if _, err := p.fs.Stat(logPath); err == nil {
			xlsxPath := filepath.Join(runDir, logName[:len(logName)-len(filepath.Ext(logName))]+".xlsx")
			log.Printf("[processor] Renaming %s to %s...", logPath, xlsxPath)
			if err := p.fs.Rename(logPath, xlsxPath); err != nil {
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

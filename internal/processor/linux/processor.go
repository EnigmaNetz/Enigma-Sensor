//go:build linux || darwin

package linux

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	types "EnigmaNetz/Enigma-Go-Sensor/internal/processor/common"
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
func (p *Processor) ProcessPCAP(pcapPath string, samplingPercentage float64) (types.ProcessedData, error) {
	// Use the directory containing the PCAP as the run directory
	runDir := filepath.Dir(pcapPath)
	log.Printf("[processor] Run directory: %s", runDir)

	// Prepare Zeek command with sampling if needed
	baseArgs := []string{"-r", pcapPath, fmt.Sprintf("Log::default_logdir=%s", runDir), "-C"}
	zeekArgs := types.PrepareZeekArgsWithSampling(pcapPath, runDir, samplingPercentage, baseArgs)

	log.Printf("[processor] Running Zeek: %s %v", p.zeekPath, zeekArgs)
	cmd := p.cmdRunner.Command(p.zeekPath, zeekArgs...)
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

	paths, err := types.RenameZeekLogsToXLSX(p.fs, runDir, zeekLogFiles)
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
	log.Printf("[processor] Returning results: conn.xlsx=%s, dns.xlsx=%s, metadata=%v", paths["conn.log"], paths["dns.log"], metadata)

	return types.ProcessedData{
		ConnPath: paths["conn.log"],
		DNSPath:  paths["dns.log"],
		Metadata: metadata,
	}, nil
}

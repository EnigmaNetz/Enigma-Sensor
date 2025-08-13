//go:build windows

package windows

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
)

type WindowsCapturer struct {
	cmd       *exec.Cmd
	outputDir string
}

var commandContext = exec.Command

func NewWindowsCapturer() *WindowsCapturer {
	return &WindowsCapturer{}
}

// Capture runs a single pktmon capture and returns the output file path or error
func (c *WindowsCapturer) Capture(ctx context.Context, config common.CaptureConfig) (string, error) {
	c.outputDir = config.OutputDir
	// Clean output directory of .etl files before capture
	entries, err := os.ReadDir(c.outputDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".etl" {
				os.Remove(c.outputDir + "/" + entry.Name())
			}
		}
	}
	return c.runCapture(ctx, config)
}

// runCapture executes pktmon and returns the output file path or error
func (c *WindowsCapturer) runCapture(ctx context.Context, config common.CaptureConfig) (string, error) {
	// Generate output filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	etlFile := filepath.Join(c.outputDir, fmt.Sprintf("capture_%s.etl", timestamp))

	if config.Interface != "" && config.Interface != "any" && config.Interface != "all" {
		log.Printf("[capture] Adding pktmon filter for interface: %s", config.Interface)
		addCmd := commandContext("pktmon", "filter", "add", "-i", config.Interface)
		if err := addCmd.Run(); err != nil {
			return "", fmt.Errorf("failed to add pktmon filter for interface %s: %v", config.Interface, err)
		}
		defer func() {
			log.Printf("[capture] Removing pktmon filter")
			if err := commandContext("pktmon", "filter", "remove").Run(); err != nil {
				log.Printf("[capture] Warning: failed to remove pktmon filter: %v", err)
			}
		}()
	}

	// Start pktmon capture
	log.Printf("[capture] Starting pktmon capture with command: pktmon start --capture --file %s", etlFile)
	c.cmd = commandContext("pktmon", "start", "--capture", "--file", etlFile)

	if err := c.cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start pktmon capture: %v", err)
	}
	log.Printf("[capture] pktmon capture started successfully")

	// Wait for capture duration
	log.Printf("[capture] Capturing for %v...", config.CaptureWindow)
	time.Sleep(config.CaptureWindow)

	// Stop capture
	log.Printf("[capture] Stopping pktmon capture")
	stopCmd := commandContext("pktmon", "stop")
	if err := stopCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to stop pktmon capture: %v", err)
	}
	log.Printf("[capture] pktmon capture stopped successfully")

	// Verify ETL file exists before attempting conversion
	// Add retry logic to handle timing race conditions
	log.Printf("[capture] Verifying ETL file exists: %s", etlFile)
	if err := waitForETLFile(etlFile, 5*time.Second); err != nil {
		return "", fmt.Errorf("ETL file verification failed after pktmon stop: %v", err)
	}

	// Detect available pktmon conversion subcommand
	subcommand, err := detectPktmonConversionSubcommand()
	if err != nil {
		return "", err
	}

	// Convert ETL to PCAPNG
	pcapngFile := filepath.Join(c.outputDir, fmt.Sprintf("capture_%s.pcapng", timestamp))
	log.Printf("[capture] Running conversion: pktmon %s %s -o %s", subcommand, etlFile, pcapngFile)
	convertCmd := commandContext("pktmon", subcommand, etlFile, "-o", pcapngFile)
	var outBuf, errBuf bytes.Buffer
	convertCmd.Stdout = &outBuf
	convertCmd.Stderr = &errBuf
	if err := convertCmd.Run(); err != nil {
		log.Printf("[capture] pktmon %s stdout: %s", subcommand, outBuf.String())
		log.Printf("[capture] pktmon %s stderr: %s", subcommand, errBuf.String())
		return "", fmt.Errorf("failed to convert ETL to PCAPNG: %v", err)
	}

	return pcapngFile, nil
}

// waitForETLFile waits for the ETL file to exist and be non-empty, with retry logic
func waitForETLFile(etlFile string, timeout time.Duration) error {
	start := time.Now()
	checkInterval := 100 * time.Millisecond

	for time.Since(start) < timeout {
		if info, err := os.Stat(etlFile); err == nil {
			// File exists, check if it has content
			if info.Size() > 0 {
				log.Printf("[capture] ETL file verified: %s (size: %d bytes)", etlFile, info.Size())
				return nil
			}
			log.Printf("[capture] ETL file exists but is empty, waiting... (size: %d)", info.Size())
		} else {
			log.Printf("[capture] ETL file does not exist yet, waiting: %s", etlFile)
		}

		time.Sleep(checkInterval)
	}

	// Final check to provide detailed error information
	if info, err := os.Stat(etlFile); err != nil {
		return fmt.Errorf("ETL file '%s' does not exist after %v timeout: %v", etlFile, timeout, err)
	} else if info.Size() == 0 {
		return fmt.Errorf("ETL file '%s' exists but is empty after %v timeout (possible pktmon capture failure)", etlFile, timeout)
	} else {
		// This shouldn't happen, but just in case
		return fmt.Errorf("ETL file '%s' verification failed after %v timeout", etlFile, timeout)
	}
}

// detectPktmonConversionSubcommand checks which pktmon conversion subcommand is available.
func detectPktmonConversionSubcommand() (string, error) {
	// Try etl2pcapng first
	cmd := exec.Command("pktmon", "etl2pcapng", "/?")
	if err := cmd.Run(); err == nil {
		return "etl2pcapng", nil
	}
	// Fallback to etl2pcap
	cmd = exec.Command("pktmon", "etl2pcap", "/?")
	if err := cmd.Run(); err == nil {
		return "etl2pcap", nil
	}
	return "", fmt.Errorf("neither 'etl2pcapng' nor 'etl2pcap' subcommands are available in pktmon; please update Windows or pktmon")
}

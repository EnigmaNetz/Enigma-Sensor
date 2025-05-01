// Package main provides a cross-platform packet capture command
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/capture"
)

func main() {
	// Parse command line flags
	outputDir := flag.String("output", ".", "Directory for output files")
	duration := flag.Int("duration", 60, "Duration to capture in seconds")
	flag.Parse()

	// Create absolute path for output directory
	absOutputDir, err := filepath.Abs(*outputDir)
	if err != nil {
		log.Fatalf("Failed to resolve output directory path: %v", err)
	}

	// Ensure output directory exists
	if err := os.MkdirAll(absOutputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Create config
	cfg := capture.Config{
		OutputDir:     absOutputDir,
		CaptureWindow: *duration,
	}

	// Create platform-specific capturer
	capturer := capture.NewCapturer(cfg)

	// Start capture
	log.Printf("Starting packet capture for %d seconds...", cfg.CaptureWindow)
	log.Printf("Output directory: %s", absOutputDir)

	if err := capturer.StartCapture(); err != nil {
		log.Fatalf("Capture failed: %v", err)
	}

	// Wait for capture to complete
	time.Sleep(time.Duration(*duration) * time.Second)

	// Get output files
	dnsLog, connLog, err := capturer.OutputFiles()
	if err != nil {
		log.Fatalf("Failed to get output files: %v", err)
	}

	log.Printf("Capture complete. Output files:")
	log.Printf("  DNS Log: %s", dnsLog)
	log.Printf("  Conn Log: %s", connLog)
}

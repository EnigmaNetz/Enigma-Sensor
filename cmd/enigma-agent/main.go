package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/config"
	"EnigmaNetz/Enigma-Go-Agent/internal/api"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
	"EnigmaNetz/Enigma-Go-Agent/internal/processor"
	"EnigmaNetz/Enigma-Go-Agent/internal/version"
)

func printHelp() {
	fmt.Print(`Enigma Agent - Network Capture & Processing Tool

Usage: enigma-agent [--version|-v] [--help|-h]

Runs a network capture and processing session using config.json.

Options:
  --version, -v   Print version and exit
  --help, -h      Show this help message and exit

Configuration:
  The agent loads its configuration from config.json in the working directory by default.
  You can customize logging, capture, and Enigma API settings in this file.
  See config.example.json for a template and documentation of all options.

Example:
  enigma-agent
    Runs a single capture and processing session using config.json.

  enigma-agent --help
    Shows this help message.

  enigma-agent --version
    Prints the agent version.
`)
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
		printHelp()
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Println(version.Version)
		return
	}
	// Load config from config.json
	cfg, err := config.LoadConfig("")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set up standard logger to log to file if specified
	if cfg.Logging.File != "" {
		logDir := filepath.Dir(cfg.Logging.File)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			log.Fatalf("Failed to create log directory: %v", err)
		}
		f, err := os.OpenFile(cfg.Logging.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		log.SetOutput(io.MultiWriter(os.Stdout, f))
	}

	log.Printf("Loaded config: %+v", cfg)

	// Prepare capture config
	outputDir := cfg.Capture.OutputDir
	window := time.Duration(cfg.Capture.WindowSeconds) * time.Second
	// interval := time.Duration(cfg.Capture.IntervalSeconds) * time.Second // Removed

	ctx := context.Background()

	processor := processor.NewProcessor()
	var uploader *api.LogUploader
	if cfg.EnigmaAPI.Upload {
		server := cfg.EnigmaAPI.Server
		apiKey := cfg.EnigmaAPI.APIKey
		if server == "" || apiKey == "" {
			log.Printf("enigma_api.server and enigma_api.api_key must be set to upload logs; skipping upload.")
		} else {
			u, err := api.NewLogUploader(server, apiKey, false)
			if err != nil {
				log.Printf("Failed to initialize LogUploader: %v", err)
			} else {
				uploader = u
			}
		}
	}

	loop := cfg.Capture.Loop
	log.Printf("Agent loop mode: %v", loop)

	for {
		// Create a unique zeek_out_<timestamp> directory for this capture
		timestamp := time.Now().UTC().Format("20060102T150405Z")
		zeekOutDir := filepath.Join(outputDir, "zeek_out_"+timestamp)
		if err := os.MkdirAll(zeekOutDir, 0755); err != nil {
			log.Fatalf("Failed to create zeek_out dir: %v", err)
		}

		capCfg := common.CaptureConfig{
			CaptureWindow: window,
			OutputDir:     zeekOutDir,
		}

		capturer := capture.NewCapturer(capCfg)
		log.Printf("Starting capture iteration at %s", timestamp)
		pcapPath, err := capturer.Capture(ctx, capCfg)
		if err != nil {
			log.Fatalf("Failed to capture: %v", err)
		}
		log.Printf("Captured file: %s", pcapPath)

		absPCAPPath, err := filepath.Abs(pcapPath)
		if err != nil {
			log.Fatalf("Failed to get absolute path for PCAP: %v", err)
		}
		if _, err := os.Stat(absPCAPPath); err != nil {
			log.Fatalf("PCAP file does not exist or is not accessible: %v", err)
		}
		log.Printf("Processing PCAP file at absolute path: %s", absPCAPPath)

		result, err := processor.ProcessPCAP(absPCAPPath)
		if err != nil {
			log.Fatalf("Processing failed: %v", err)
		}
		log.Printf("Processing complete. Conn XLSX: %s, DNS XLSX: %s, Metadata: %+v", result.ConnPath, result.DNSPath, result.Metadata)

		if uploader != nil {
			uploadErr := uploader.UploadLogs(ctx, api.LogFiles{
				DNSPath:  result.DNSPath,
				ConnPath: result.ConnPath,
			})
			if uploadErr != nil {
				log.Printf("Log upload failed: %v", uploadErr)
			} else {
				log.Printf("Log upload successful.")
			}
		}

		if !loop {
			break
		}
		// Immediately start next capture (no sleep)
	}
}

// findLatestFile returns the most recently modified file with the given extension in dir
func findLatestFile(dir, ext string) (string, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var matches []string
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ext {
			matches = append(matches, filepath.Join(dir, f.Name()))
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no %s files found in %s", ext, dir)
	}
	sort.Slice(matches, func(i, j int) bool {
		fi, _ := os.Stat(matches[i])
		fj, _ := os.Stat(matches[j])
		return fi.ModTime().After(fj.ModTime())
	})
	return matches[0], nil
}

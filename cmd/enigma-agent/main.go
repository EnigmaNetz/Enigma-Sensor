package main

import (
	"context"
	"fmt"
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
)

func main() {
	// Load config from config.json
	cfg, err := config.LoadConfig("")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Loaded config: %+v", cfg)

	if err := cfg.InitializeLogging(); err != nil {
		log.Fatalf("Failed to initialize logging: %v", err)
	}

	// Prepare capture config
	outputDir := cfg.Capture.OutputDir
	window := time.Duration(cfg.Capture.WindowSeconds) * time.Second
	// interval := time.Duration(cfg.Capture.IntervalSeconds) * time.Second // Removed

	// Create a unique zeek_out_<timestamp> directory for this capture
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	zeekOutDir := filepath.Join(outputDir, "zeek_out_"+timestamp)
	if err := os.MkdirAll(zeekOutDir, 0755); err != nil {
		log.Fatalf("Failed to create zeek_out dir: %v", err)
	}

	capCfg := common.CaptureConfig{
		CaptureWindow: window,
		// Add Interface if/when supported in CaptureConfig
		OutputDir: zeekOutDir,
	}

	ctx := context.Background()

	capturer := capture.NewCapturer(capCfg)
	pcapPath, err := capturer.Capture(ctx, capCfg)
	if err != nil {
		log.Fatalf("Failed to capture: %v", err)
	}
	log.Printf("Captured file: %s", pcapPath)

	// Ensure the PCAP file exists and use absolute path
	absPCAPPath, err := filepath.Abs(pcapPath)
	if err != nil {
		log.Fatalf("Failed to get absolute path for PCAP: %v", err)
	}
	if _, err := os.Stat(absPCAPPath); err != nil {
		log.Fatalf("PCAP file does not exist or is not accessible: %v", err)
	}
	log.Printf("Processing PCAP file at absolute path: %s", absPCAPPath)

	// Process the capture file
	processor := processor.NewProcessor()
	result, err := processor.ProcessPCAP(absPCAPPath)
	if err != nil {
		log.Fatalf("Processing failed: %v", err)
	}
	log.Printf("Processing complete. Conn XLSX: %s, DNS XLSX: %s, Metadata: %+v", result.ConnPath, result.DNSPath, result.Metadata)

	// Optionally upload processed logs to Enigma API if enabled
	if cfg.EnigmaAPI.Upload {
		server := cfg.EnigmaAPI.Server
		apiKey := cfg.EnigmaAPI.APIKey
		// insecure := cfg.EnigmaAPI.DisableTLS // Removed
		if server == "" || apiKey == "" {
			log.Printf("enigma_api.server and enigma_api.api_key must be set to upload logs; skipping upload.")
			return
		}

		uploader, err := api.NewLogUploader(server, apiKey, false)
		if err != nil {
			log.Printf("Failed to initialize LogUploader: %v", err)
			return
		}
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

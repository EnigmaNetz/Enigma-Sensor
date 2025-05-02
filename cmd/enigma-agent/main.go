package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/joho/godotenv"

	"EnigmaNetz/Enigma-Go-Agent/internal/api"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
	"EnigmaNetz/Enigma-Go-Agent/internal/processor"
)

func main() {
	// Load environment variables from .env if present
	_ = godotenv.Load()

	// Parse required config from environment
	outputDir := os.Getenv("CAPTURE_OUTPUT_DIR")
	if outputDir == "" {
		outputDir = "./captures"
	}
	windowStr := os.Getenv("CAPTURE_DURATION")
	if windowStr == "" {
		windowStr = "60s"
	}
	window, err := time.ParseDuration(windowStr)
	if err != nil {
		log.Fatalf("Invalid CAPTURE_DURATION: %v", err)
	}
	interval := window // Default: run once
	if intervalStr := os.Getenv("CAPTURE_INTERVAL"); intervalStr != "" {
		if iv, err := time.ParseDuration(intervalStr); err == nil {
			interval = iv
		}
	}

	// Create a unique zeek_out_<timestamp> directory for this capture
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	zeekOutDir := filepath.Join(outputDir, "zeek_out_"+timestamp)
	if err := os.MkdirAll(zeekOutDir, 0755); err != nil {
		log.Fatalf("Failed to create zeek_out dir: %v", err)
	}

	cfg := common.CaptureConfig{
		CaptureWindow:   window,
		CaptureInterval: interval,
		OutputDir:       zeekOutDir,
	}

	// Remove context.WithTimeout and time.Sleep; let capture logic control duration
	ctx := context.Background()

	capturer := capture.NewCapturer(cfg)
	pcapPath, err := capturer.Capture(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to capture: %v", err)
	}
	log.Printf("Captured file: %s", pcapPath)

	// Process the capture file
	processor := processor.NewProcessor()
	result, err := processor.ProcessPCAP(pcapPath)
	if err != nil {
		log.Fatalf("Processing failed: %v", err)
	}
	log.Printf("Processing complete. Conn XLSX: %s, DNS XLSX: %s, Metadata: %+v", result.ConnPath, result.DNSPath, result.Metadata)

	// Optionally upload processed logs to Enigma API if enabled
	uploadEnabled := os.Getenv("ENIGMA_UPLOAD")
	if uploadEnabled == "true" {
		server := os.Getenv("ENIGMA_SERVER")
		apiKey := os.Getenv("ENIGMA_API_KEY")
		insecure := os.Getenv("DISABLE_TLS") == "true"
		if server == "" || apiKey == "" {
			log.Printf("ENIGMA_SERVER and ENIGMA_API_KEY must be set to upload logs; skipping upload.")
			return
		}

		// Import the LogUploader and LogFiles
		uploader, err := api.NewLogUploader(server, apiKey, insecure)
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

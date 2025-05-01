package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/api"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture"
)

var (
	serverAddr = flag.String("server", "localhost:50051", "API server address")
	apiKey     = flag.String("api-key", "", "API key for authentication")
	interface_ = flag.String("interface", "", "Network interface to capture")
	duration   = flag.Duration("duration", 60*time.Second, "Duration to capture")
	outputDir  = flag.String("output", "captures", "Directory to store capture files")
	noTLS      = flag.Bool("no-tls", false, "Disable TLS for API connection")
)

func main() {
	flag.Parse()

	if *apiKey == "" {
		log.Fatal("API key is required")
	}

	if *interface_ == "" {
		log.Fatal("Network interface is required")
	}

	// Ensure output directory exists
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Initialize API client
	uploader, err := api.NewLogUploader(*serverAddr, *apiKey, *noTLS)
	if err != nil {
		log.Fatalf("Failed to initialize API client: %v", err)
	}

	// Setup signal handling for graceful shutdown
	done := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create platform-specific capturer
	cfg := capture.Config{
		OutputDir: *outputDir,
	}

	var capturer capture.PacketCapturer
	switch runtime.GOOS {
	case "windows":
		capturer = capture.NewWindowsCapturer(cfg)
	case "linux":
		capturer = capture.NewLinuxCapturer(cfg)
	default:
		log.Fatalf("Unsupported platform: %s", runtime.GOOS)
	}

	// Start capture
	log.Printf("Starting capture on interface %s for %v", *interface_, *duration)
	if err := capturer.StartCapture(); err != nil {
		log.Fatalf("Capture failed: %v", err)
	}

	// Handle shutdown
	go func() {
		<-sigChan
		log.Println("Received shutdown signal")
		if err := capturer.StopCapture(); err != nil {
			log.Printf("Warning: Failed to stop capture gracefully: %v", err)
		}
		close(done)
	}()

	// Wait for duration or interrupt
	select {
	case <-time.After(*duration):
	case <-done:
		log.Println("Capture interrupted")
		return
	}

	// Stop capture
	if err := capturer.StopCapture(); err != nil {
		log.Printf("Warning: Failed to stop capture gracefully: %v", err)
	}

	// Get output files
	dnsPath := filepath.Join(*outputDir, "dns.log")
	connPath := filepath.Join(*outputDir, "conn.log")

	// Upload logs
	log.Println("Uploading logs to API server...")
	err = uploader.UploadLogs(context.Background(), api.LogFiles{
		DNSPath:  dnsPath,
		ConnPath: connPath,
	})
	if err != nil {
		log.Fatalf("Failed to upload logs: %v", err)
	}

	log.Println("Successfully captured and uploaded logs")
}

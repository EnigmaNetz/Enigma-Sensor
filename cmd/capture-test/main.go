package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/api"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"

	"github.com/joho/godotenv"
)

func parseDuration(s string, defaultDuration time.Duration) time.Duration {
	if s == "" {
		return defaultDuration
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultDuration
	}
	return d
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	// Load .env file first
	envFile := ".env"
	if err := godotenv.Load(envFile); err != nil {
		log.Printf("Warning: Error loading %s: %v", envFile, err)
		// Try loading from absolute path
		absPath, _ := filepath.Abs(envFile)
		log.Printf("Trying absolute path: %s", absPath)
		if err := godotenv.Load(absPath); err != nil {
			log.Printf("Warning: Error loading from absolute path: %v", err)
		}
	}

	// Debug: Print environment variables
	pwd, _ := os.Getwd()
	log.Printf("Current working directory: %s", pwd)
	log.Printf("ENIGMA_API_KEY set: %v", os.Getenv("ENIGMA_API_KEY") != "")
	log.Printf("ENIGMA_SERVER: %s", os.Getenv("ENIGMA_SERVER"))
	log.Printf("CAPTURE_INTERFACE: %s", os.Getenv("CAPTURE_INTERFACE"))

	// Define and parse flags after loading .env
	serverAddr := flag.String("server", os.Getenv("ENIGMA_SERVER"), "API server address (use dev.getenigma.ai:443 for staging)")
	apiKey := flag.String("api-key", os.Getenv("ENIGMA_API_KEY"), "API key for authentication")
	interface_ := flag.String("interface", os.Getenv("CAPTURE_INTERFACE"), "Network interface to capture")
	duration := flag.Duration("duration", parseDuration(os.Getenv("CAPTURE_DURATION"), 60*time.Second), "Duration to capture")
	outputDir := flag.String("output", getEnvOrDefault("CAPTURE_OUTPUT_DIR", "captures"), "Directory to store capture files")
	noTLS := flag.Bool("no-tls", os.Getenv("DISABLE_TLS") == "true", "Disable TLS for API connection (not recommended for production)")
	local := flag.Bool("local", false, "Save logs locally without uploading to API server")

	flag.Parse()

	// Set default server if not specified
	if *serverAddr == "" {
		*serverAddr = "api.enigmaai.net:443"
	}

	// Debug: Print flag values
	log.Printf("Using API key: %v", *apiKey != "")
	log.Printf("Using server: %s", *serverAddr)
	log.Printf("Using interface: %s", *interface_)

	if *apiKey == "" || strings.TrimSpace(*apiKey) == "" {
		if !*local {
			log.Fatal("API key is required unless --local flag is used. Set ENIGMA_API_KEY in .env file or use --api-key flag")
		}
	}

	if *interface_ == "" {
		log.Fatal("Network interface is required. Set CAPTURE_INTERFACE in .env file or use --interface flag")
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

	// Create capture configuration
	cfg := common.CaptureConfig{
		CaptureWindow:   *duration,
		CaptureInterval: *duration,
		OutputDir:       *outputDir,
	}

	// Create platform-specific capturer
	capturer := capture.NewCapturer(cfg)

	// Create context for capture
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start capture
	log.Printf("Starting capture on interface %s for %v", *interface_, *duration)
	if err := capturer.Start(ctx, cfg); err != nil {
		log.Fatalf("Capture failed: %v", err)
	}

	// Handle shutdown
	go func() {
		<-sigChan
		log.Println("Received shutdown signal")
		if err := capturer.Stop(); err != nil {
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
	if err := capturer.Stop(); err != nil {
		log.Printf("Warning: Failed to stop capture gracefully: %v", err)
	}

	// Get status
	if status, err := capturer.Status(); err == nil {
		log.Printf("Capture completed. Status: %+v", status)
	}

	// Get output files
	dnsPath := filepath.Join(*outputDir, "dns.xlsx")
	connPath := filepath.Join(*outputDir, "conn.xlsx")

	if *local {
		log.Printf("Logs saved locally at:\n  DNS Log: %s\n  Conn Log: %s", dnsPath, connPath)
		return
	}

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

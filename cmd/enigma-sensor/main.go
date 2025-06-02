package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/config"
	"EnigmaNetz/Enigma-Go-Sensor/internal/api"
	"EnigmaNetz/Enigma-Go-Sensor/internal/capture"
	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
	collect_logs "EnigmaNetz/Enigma-Go-Sensor/internal/collect_logs"
	"EnigmaNetz/Enigma-Go-Sensor/internal/processor"
	"EnigmaNetz/Enigma-Go-Sensor/internal/sensor"
	"EnigmaNetz/Enigma-Go-Sensor/internal/version"

	"gopkg.in/natefinch/lumberjack.v2"
)

func printHelp() {
	fmt.Print(`Enigma Sensor - Network Capture & Processing Tool

Usage: enigma-sensor [collect-logs] [--version|-v] [--help|-h]

Runs a network capture and processing session using config.json.

Options:
  collect-logs    Package logs, captures, config, and diagnostics into a zip archive for support
  --version, -v   Print version and exit
  --help, -h      Show this help message and exit

Configuration:
  The sensor loads its configuration from config.json in the working directory by default.
  You can customize logging, capture, and Enigma API settings in this file.
  See config.example.json for a template and documentation of all options.

Example:
  enigma-sensor
    Runs a single capture and processing session using config.json.

  enigma-sensor collect-logs
    Packages logs, captures, config, and diagnostics into a zip archive for support.

  enigma-sensor --help
    Shows this help message.

  enigma-sensor --version
    Prints the sensor version.
`)
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--help", "-h":
			printHelp()
			return
		case "--version", "-v":
			fmt.Println(version.Version)
			return
		case "collect-logs":
			zipName := fmt.Sprintf("enigma-logs-%s.zip", time.Now().Format("20060102-150405"))
			err := collect_logs.CollectLogs(zipName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to collect logs: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Created %s with logs, config, and diagnostics.\n", zipName)
			return
		}
	}
	// Load config from config.json
	var configPaths []string
	if runtime.GOOS == "windows" {
		configPaths = []string{
			`C:\\ProgramData\\EnigmaSensor\\config.json`,
			"config.json",
		}
	} else {
		configPaths = []string{
			"/etc/enigma-sensor/config.json",
			"config.json",
		}
	}
	var cfg *config.Config
	var err error
	for _, path := range configPaths {
		cfg, err = config.LoadConfig(path)
		if err == nil {
			break
		}
	}
	if cfg == nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set up standard logger to log to file if specified
	if cfg.Logging.File != "" {
		logDir := filepath.Dir(cfg.Logging.File)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			log.Fatalf("Failed to create log directory: %v", err)
		}
		// Use lumberjack for log rotation based on config
		logWriter := &lumberjack.Logger{
			Filename:   cfg.Logging.File,
			MaxSize:    int(cfg.Logging.MaxSizeMB),   // megabytes
			MaxAge:     cfg.Logging.LogRetentionDays, // days
			MaxBackups: 3,                            // keep up to 3 old log files
			Compress:   true,                         // compress rotated logs
		}
		log.SetOutput(io.MultiWriter(os.Stdout, logWriter))
	}

	log.Printf("Loaded config: %+v", cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Prepare capturer, processor, uploader for sensor.RunSensor
	window := time.Duration(cfg.Capture.WindowSeconds) * time.Second
	capCfg := common.CaptureConfig{
		CaptureWindow: window,
		OutputDir:     cfg.Capture.OutputDir, // Will be overridden per iteration
		Interface:     cfg.Capture.Interface,
	}
	capturer := capture.NewCapturer(capCfg)
	proc := processor.NewProcessor()

	var uploader sensor.Uploader
	if cfg.EnigmaAPI.Upload {
		server := cfg.EnigmaAPI.Server
		apiKey := cfg.EnigmaAPI.APIKey
		if server == "" || apiKey == "" {
			log.Printf("enigma_api.server and enigma_api.api_key must be set to upload logs; skipping upload.")
		} else {
			u, err := api.NewLogUploader(server, apiKey)
			if err != nil {
				log.Printf("Failed to initialize LogUploader: %v", err)
			} else {
				uploader = u
			}
		}
	}

	if err := sensor.RunSensor(ctx, cfg, capturer, proc, uploader); err != nil {
		if err == api.ErrAPIGone || err == sensor.ErrAPIGone {
			log.Printf("Sensor stopped due to 410 Gone from API because the API key is invalid. Exiting as instructed.")
			os.Exit(0)
		}
		log.Fatalf("Sensor exited with error: %v", err)
	}
}

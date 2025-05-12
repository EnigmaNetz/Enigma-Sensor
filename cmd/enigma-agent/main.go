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
	"EnigmaNetz/Enigma-Go-Agent/internal/agent"
	"EnigmaNetz/Enigma-Go-Agent/internal/api"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
	collect_logs "EnigmaNetz/Enigma-Go-Agent/internal/collect_logs"
	"EnigmaNetz/Enigma-Go-Agent/internal/processor"
	"EnigmaNetz/Enigma-Go-Agent/internal/version"

	"gopkg.in/natefinch/lumberjack.v2"
)

func printHelp() {
	fmt.Print(`Enigma Agent - Network Capture & Processing Tool

Usage: enigma-agent [collect-logs] [--version|-v] [--help|-h]

Runs a network capture and processing session using config.json.

Options:
  collect-logs    Package logs, captures, config, and diagnostics into a zip archive for support
  --version, -v   Print version and exit
  --help, -h      Show this help message and exit

Configuration:
  The agent loads its configuration from config.json in the working directory by default.
  You can customize logging, capture, and Enigma API settings in this file.
  See config.example.json for a template and documentation of all options.

Example:
  enigma-agent
    Runs a single capture and processing session using config.json.

  enigma-agent collect-logs
    Packages logs, captures, config, and diagnostics into a zip archive for support.

  enigma-agent --help
    Shows this help message.

  enigma-agent --version
    Prints the agent version.
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
	configPaths := []string{
		`C:\\ProgramData\\EnigmaAgent\\config.json`,
		"config.json",
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

	// Prepare capturer, processor, uploader for agent.RunAgent
	window := time.Duration(cfg.Capture.WindowSeconds) * time.Second
	capCfg := common.CaptureConfig{
		CaptureWindow: window,
		OutputDir:     cfg.Capture.OutputDir, // Will be overridden per iteration
	}
	capturer := capture.NewCapturer(capCfg)
	proc := processor.NewProcessor()

	var uploader agent.Uploader
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

	if err := agent.RunAgent(ctx, cfg, capturer, proc, uploader); err != nil {
		log.Fatalf("Agent exited with error: %v", err)
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

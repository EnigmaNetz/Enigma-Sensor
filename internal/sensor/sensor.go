package sensor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/config"
	"EnigmaNetz/Enigma-Go-Sensor/internal/api"
	"EnigmaNetz/Enigma-Go-Sensor/internal/capture/common"
	types "EnigmaNetz/Enigma-Go-Sensor/internal/processor/common"
	"archive/zip"
	"runtime"
)

var ErrAPIGone = errors.New("sensor received 410 Gone from API and should stop")

// Capturer abstracts the capture logic
// (You can use mockgen for tests)
//
//go:generate mockgen -destination=mock_capturer.go -package=sensor . Capturer
type Capturer interface {
	Capture(ctx context.Context, cfg common.CaptureConfig) (string, error)
}

type Processor interface {
	ProcessPCAP(pcapPath string, samplingPercentage float64) (types.ProcessedData, error)
}

type Uploader interface {
	UploadLogs(ctx context.Context, files api.LogFiles) error
}

// validateZipPath checks if a zip entry path is safe from directory traversal attacks
func validateZipPath(path string) error {
	// Check for ".." path traversal elements
	if strings.Contains(path, "..") {
		return fmt.Errorf("path contains '..' element: %s", path)
	}
	// Check for absolute paths (should be relative)
	// This needs to check for both OS-specific absolute paths and Unix-style paths
	// since zip files can contain Unix paths even on Windows
	if filepath.IsAbs(path) {
		return fmt.Errorf("path is absolute: %s", path)
	}
	// Also check for Unix-style absolute paths (starting with /)
	// which filepath.IsAbs may not catch on Windows
	if len(path) > 0 && path[0] == '/' {
		return fmt.Errorf("path is absolute: %s", path)
	}
	return nil
}

// ensureZeekWindows extracts Zeek for Windows, always overwriting the directory to ensure the latest version is used
func ensureZeekWindows() error {
	zeekDir := "zeek-windows"
	zipPaths := []string{"zeek-runtime-win64.zip", "installer/windows/zeek-runtime-win64.zip"}
	var zipFile *os.File
	var err error
	for _, path := range zipPaths {
		zipFile, err = os.Open(path)
		if err == nil {
			break
		}
	}
	if zipFile == nil {
		return err
	}
	defer zipFile.Close()
	stat, err := zipFile.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(zipFile, stat.Size())
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		// Prevent zip slip vulnerability: validate file path
		if err := validateZipPath(f.Name); err != nil {
			return fmt.Errorf("invalid file path in zip archive: %w", err)
		}

		fpath := filepath.Join(zeekDir, f.Name)

		// Additional security check: ensure the resolved path is within zeekDir
		cleanPath := filepath.Clean(fpath)
		absZeekDir, err := filepath.Abs(zeekDir)
		if err != nil {
			return fmt.Errorf("failed to resolve zeek directory: %w", err)
		}
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			return fmt.Errorf("failed to resolve file path: %w", err)
		}
		if !strings.HasPrefix(absPath, absZeekDir+string(filepath.Separator)) && absPath != absZeekDir {
			return fmt.Errorf("zip slip attempt detected: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, f.Mode()); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
			return err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			outFile.Close()
			return err
		}
		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}

	// Copy sampling script to the custom-scripts directory if it exists
	samplingScriptSrc := "zeek-scripts/sampling.zeek"
	samplingScriptDst := filepath.Join(zeekDir, "zeek-runtime-win64", "share", "zeek", "site", "custom-scripts", "sampling.zeek")

	if _, err := os.Stat(samplingScriptSrc); err == nil {
		srcFile, err := os.Open(samplingScriptSrc)
		if err != nil {
			log.Printf("[sensor] Warning: Failed to open sampling script source: %v", err)
		} else {
			defer srcFile.Close()

			// Ensure destination directory exists
			if err := os.MkdirAll(filepath.Dir(samplingScriptDst), 0755); err != nil {
				log.Printf("[sensor] Warning: Failed to create sampling script destination directory: %v", err)
			} else {
				dstFile, err := os.Create(samplingScriptDst)
				if err != nil {
					log.Printf("[sensor] Warning: Failed to create sampling script destination: %v", err)
				} else {
					defer dstFile.Close()
					if _, err := io.Copy(dstFile, srcFile); err != nil {
						log.Printf("[sensor] Warning: Failed to copy sampling script: %v", err)
					} else {
						log.Printf("[sensor] Successfully copied sampling script to Windows Zeek runtime")

						// Update main.zeek to load the sampling script
						mainZeekPath := filepath.Join(zeekDir, "zeek-runtime-win64", "share", "zeek", "site", "custom-scripts", "main.zeek")
						if err := addSamplingScriptToMainZeek(mainZeekPath); err != nil {
							log.Printf("[sensor] Warning: Failed to update main.zeek: %v", err)
						}
					}
				}
			}
		}
	} else {
		log.Printf("[sensor] Warning: Sampling script not found at %s", samplingScriptSrc)
	}

	return nil
}

// addSamplingScriptToMainZeek adds the sampling script load directive to main.zeek if not already present
func addSamplingScriptToMainZeek(mainZeekPath string) error {
	// Read the current main.zeek file
	content, err := os.ReadFile(mainZeekPath)
	if err != nil {
		return fmt.Errorf("failed to read main.zeek: %w", err)
	}

	contentStr := string(content)
	samplingLoadDirective := "@load ./sampling.zeek"

	// Check if the sampling script is already loaded
	if strings.Contains(contentStr, samplingLoadDirective) {
		log.Printf("[sensor] Sampling script already loaded in main.zeek")
		return nil
	}

	// Add the sampling script load directive
	updatedContent := contentStr + "\n" + samplingLoadDirective + "\n"

	// Write the updated content back
	if err := os.WriteFile(mainZeekPath, []byte(updatedContent), 0644); err != nil {
		return fmt.Errorf("failed to write updated main.zeek: %w", err)
	}

	log.Printf("[sensor] Added sampling script load directive to main.zeek")
	return nil
}

// deletePCAPFile deletes the given PCAP file and logs the result.
func deletePCAPFile(pcapPath string) {
	if err := os.Remove(pcapPath); err != nil {
		log.Printf("[worker] Failed to delete processed PCAP file %s: %v", pcapPath, err)
	} else {
		log.Printf("[worker] Deleted processed PCAP file: %s", pcapPath)
	}

	// Also try to delete a corresponding .etl file if it exists (Windows)
	etlPath := pcapPath[:len(pcapPath)-len(filepath.Ext(pcapPath))] + ".etl"
	if _, err := os.Stat(etlPath); err == nil {
		if err := os.Remove(etlPath); err != nil {
			log.Printf("[worker] Failed to delete corresponding ETL file %s: %v", etlPath, err)
		} else {
			log.Printf("[worker] Deleted corresponding ETL file: %s", etlPath)
		}
	}
}

// RunSensor orchestrates capture, processing, and upload with graceful shutdown
// If disableSignals is true, signal handling is skipped (for tests)
// If skipEnsureZeek is true, ensureZeekWindows is not called (for tests)
func RunSensor(ctx context.Context, cfg *config.Config, capturer Capturer, processor Processor, uploader Uploader, disableSignalsAndSkipZeek ...bool) error {
	skipEnsureZeek := false
	disableSignals := false
	if len(disableSignalsAndSkipZeek) > 0 {
		disableSignals = disableSignalsAndSkipZeek[0]
	}
	if len(disableSignalsAndSkipZeek) > 1 {
		skipEnsureZeek = disableSignalsAndSkipZeek[1]
	}
	// Ensure Zeek for Windows is available
	if !skipEnsureZeek && runtime.GOOS == "windows" {
		if err := ensureZeekWindows(); err != nil {
			return err
		}
	}

	outputDir := cfg.Capture.OutputDir
	window := time.Duration(cfg.Capture.WindowSeconds) * time.Second
	loop := cfg.Capture.Loop

	pcapQueue := make(chan string, 4)
	var wg sync.WaitGroup

	// Processing worker
	shutdownCh := make(chan struct{}, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for pcapPath := range pcapQueue {
			absPCAPPath, err := filepath.Abs(pcapPath)
			if err != nil {
				log.Printf("[worker] Failed to get absolute path for PCAP: %v", err)
				continue
			}
			if _, err := os.Stat(absPCAPPath); err != nil {
				log.Printf("[worker] PCAP file does not exist or is not accessible: %v", err)
				continue
			}
			log.Printf("[worker] Processing PCAP file at absolute path: %s", absPCAPPath)

			result, err := processor.ProcessPCAP(absPCAPPath, cfg.Zeek.SamplingPercentage)
			if err != nil {
				log.Printf("[worker] Processing failed: %v", err)
				// Do not delete the PCAP file on processing error
				continue
			}
			log.Printf("[worker] Processing complete. Conn XLSX: %s, DNS XLSX: %s, DHCP XLSX: %s, JA3JA4 XLSX: %s, JA4S XLSX: %s, Metadata: %+v", result.ConnPath, result.DNSPath, result.DHCPPath, result.JA3JA4Path, result.JA4SPath, result.Metadata)

			if uploader != nil {
				uploadErr := uploader.UploadLogs(ctx, api.LogFiles{
					DNSPath:    result.DNSPath,
					ConnPath:   result.ConnPath,
					DHCPPath:   result.DHCPPath,
					JA3JA4Path: result.JA3JA4Path,
					JA4SPath:   result.JA4SPath,
				})
				if uploadErr != nil {
					if uploadErr == api.ErrAPIGone {
						log.Printf("[sensor] Received 410 Gone from API because the API key is invalid. Stopping sensor and service as instructed.")
						// Signal main loop to shutdown
						shutdownCh <- struct{}{}
						return
					}
					log.Printf("[worker] Log upload failed: %v", uploadErr)
				} else {
					log.Printf("[worker] Log upload successful.")
				}
			}
			// Only delete the capture file after successful processing and upload attempt
			deletePCAPFile(absPCAPPath)
			// Clean up any other .pcap and .etl files in the output directory
			dir := filepath.Dir(absPCAPPath)
			entries, err := os.ReadDir(dir)
			if err == nil {
				for _, entry := range entries {
					if !entry.IsDir() {
						ext := filepath.Ext(entry.Name())
						if (ext == ".pcap" || ext == ".etl") && entry.Name() != filepath.Base(absPCAPPath) {
							orphanPath := filepath.Join(dir, entry.Name())
							if err := os.Remove(orphanPath); err != nil {
								log.Printf("[worker] Failed to delete orphaned file %s: %v", orphanPath, err)
							} else {
								log.Printf("[worker] Deleted orphaned file: %s", orphanPath)
							}
						}
					}
				}
			} else {
				log.Printf("[worker] Failed to scan directory for orphaned files: %v", err)
			}
		}
		log.Printf("[worker] Exiting worker goroutine")
	}()

	// Optionally handle Ctrl+C for graceful shutdown
	doSignals := true
	if disableSignals {
		doSignals = false
	}
	var sigCh chan os.Signal
	if doSignals {
		sigCh = make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	}

	var once sync.Once
	closeQueue := func() { once.Do(func() { close(pcapQueue) }) }

	defer func() {
		closeQueue()
		wg.Wait()
	}()

	// cleanOldZeekOutFolders deletes zeek_out_* folders older than retentionDays in the given outputDir.
	cleanOldZeekOutFolders := func(outputDir string, retentionDays int) {
		if outputDir == "" {
			return
		}
		entries, err := os.ReadDir(outputDir)
		if err == nil {
			cutoff := time.Now().AddDate(0, 0, -retentionDays)
			for _, entry := range entries {
				if entry.IsDir() && len(entry.Name()) > 9 && entry.Name()[:9] == "zeek_out_" {
					fullPath := filepath.Join(outputDir, entry.Name())
					info, err := os.Stat(fullPath)
					if err == nil && info.ModTime().Before(cutoff) {
						_ = os.RemoveAll(fullPath)
					}
				}
			}
		}
	}

	for {
		// Clean up old zeek_out_* folders every iteration
		cleanOldZeekOutFolders(cfg.Capture.OutputDir, cfg.Logging.LogRetentionDays)
		select {
		case <-ctx.Done():
			log.Printf("Context canceled, shutting down after current capture...")
			closeQueue()
			return nil
		case <-shutdownCh:
			// Received shutdown signal from worker
			return ErrAPIGone
		default:
			if doSignals {
				select {
				case sig := <-sigCh:
					log.Printf("Received signal %v, shutting down after current capture...", sig)
					closeQueue()
					return nil
				default:
				}
			}
		}
		timestamp := time.Now().UTC().Format("20060102T150405Z")
		zeekOutDir := filepath.Join(outputDir, "zeek_out_"+timestamp)
		if err := os.MkdirAll(zeekOutDir, 0755); err != nil {
			closeQueue()
			return err
		}
		capCfg := common.CaptureConfig{
			CaptureWindow: window,
			OutputDir:     zeekOutDir,
			Interface:     cfg.Capture.Interface,
		}
		log.Printf("Starting capture iteration at %s", timestamp)
		pcapPath, err := capturer.Capture(ctx, capCfg)
		if err != nil {
			closeQueue()
			return err
		}
		log.Printf("Captured file: %s", pcapPath)
		select {
		case pcapQueue <- pcapPath:
			log.Printf("Enqueued PCAP for processing: %s", pcapPath)
		case <-ctx.Done():
			log.Printf("Context canceled while enqueueing, exiting loop")
			closeQueue()
			return nil
		default:
			log.Printf("[warning] PCAP queue full, dropping capture: %s", pcapPath)
		}
		if !loop {
			break
		}
	}
	log.Printf("Waiting for processing worker to finish...")
	// Wait handled by defer
	log.Printf("Shutdown complete.")
	return nil
}

package agent

import (
	"context"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/config"
	"EnigmaNetz/Enigma-Go-Agent/internal/api"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
	types "EnigmaNetz/Enigma-Go-Agent/internal/processor/common"
	"archive/zip"
)

// Capturer abstracts the capture logic
// (You can use mockgen for tests)
//
//go:generate mockgen -destination=mock_capturer.go -package=agent . Capturer
type Capturer interface {
	Capture(ctx context.Context, cfg common.CaptureConfig) (string, error)
}

type Processor interface {
	ProcessPCAP(pcapPath string) (types.ProcessedData, error)
}

type Uploader interface {
	UploadLogs(ctx context.Context, files api.LogFiles) error
}

// ensureZeekWindows extracts Zeek for Windows, always overwriting the directory to ensure the latest version is used
func ensureZeekWindows() error {
	zeekDir := "zeek-windows"
	zipPath := "internal/processor/windows/zeek-runtime-win64.zip"
	// Remove the existing directory if it exists
	if _, err := os.Stat(zeekDir); err == nil {
		if err := os.RemoveAll(zeekDir); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(zeekDir, 0755); err != nil {
		return err
	}
	zipFile, err := os.Open(zipPath)
	if err != nil {
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
		fpath := filepath.Join(zeekDir, f.Name)
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
	return nil
}

// deletePCAPFile deletes the given PCAP file and logs the result.
func deletePCAPFile(pcapPath string) {
	if err := os.Remove(pcapPath); err != nil {
		log.Printf("[worker] Failed to delete processed PCAP file %s: %v", pcapPath, err)
	} else {
		log.Printf("[worker] Deleted processed PCAP file: %s", pcapPath)
	}
}

// RunAgent orchestrates capture, processing, and upload with graceful shutdown
// If disableSignals is true, signal handling is skipped (for tests)
func RunAgent(ctx context.Context, cfg *config.Config, capturer Capturer, processor Processor, uploader Uploader, disableSignals ...bool) error {
	// Ensure Zeek for Windows is available
	if err := ensureZeekWindows(); err != nil {
		return err
	}

	outputDir := cfg.Capture.OutputDir
	window := time.Duration(cfg.Capture.WindowSeconds) * time.Second
	loop := cfg.Capture.Loop

	pcapQueue := make(chan string, 4)
	var wg sync.WaitGroup

	// Processing worker
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

			result, err := processor.ProcessPCAP(absPCAPPath)
			if err != nil {
				log.Printf("[worker] Processing failed: %v", err)
				// Do not delete the PCAP file on processing error
				continue
			}
			log.Printf("[worker] Processing complete. Conn XLSX: %s, DNS XLSX: %s, Metadata: %+v", result.ConnPath, result.DNSPath, result.Metadata)

			if uploader != nil {
				uploadErr := uploader.UploadLogs(ctx, api.LogFiles{
					DNSPath:  result.DNSPath,
					ConnPath: result.ConnPath,
				})
				if uploadErr != nil {
					log.Printf("[worker] Log upload failed: %v", uploadErr)
				} else {
					log.Printf("[worker] Log upload successful.")
				}
			}
			// Only delete the capture file after successful processing and upload attempt
			deletePCAPFile(absPCAPPath)
			// Clean up any other .pcap files in the output directory
			dir := filepath.Dir(absPCAPPath)
			entries, err := os.ReadDir(dir)
			if err == nil {
				for _, entry := range entries {
					if !entry.IsDir() && filepath.Ext(entry.Name()) == ".pcap" && entry.Name() != filepath.Base(absPCAPPath) {
						orphanPath := filepath.Join(dir, entry.Name())
						if err := os.Remove(orphanPath); err != nil {
							log.Printf("[worker] Failed to delete orphaned PCAP file %s: %v", orphanPath, err)
						} else {
							log.Printf("[worker] Deleted orphaned PCAP file: %s", orphanPath)
						}
					}
				}
			} else {
				log.Printf("[worker] Failed to scan directory for orphaned PCAPs: %v", err)
			}
		}
		log.Printf("[worker] Exiting worker goroutine")
	}()

	// Optionally handle Ctrl+C for graceful shutdown
	doSignals := true
	if len(disableSignals) > 0 && disableSignals[0] {
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

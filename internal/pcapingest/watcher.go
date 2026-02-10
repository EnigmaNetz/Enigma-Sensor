package pcapingest

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/internal/api"
	types "EnigmaNetz/Enigma-Go-Sensor/internal/processor/common"
)

// Processor processes a PCAP file and returns structured log data.
type Processor interface {
	ProcessPCAP(pcapPath string, samplingPercentage float64) (types.ProcessedData, error)
}

// Uploader uploads processed log files to the API.
type Uploader interface {
	UploadLogs(ctx context.Context, files api.LogFiles) error
}

// WatcherConfig holds configuration for the PCAP directory watcher.
type WatcherConfig struct {
	WatchDir          string
	PollInterval      time.Duration
	FileStableSeconds int
	SamplingPct       float64
}

// Watcher polls a directory for incoming PCAP files and feeds them through
// the existing process and upload pipeline.
type Watcher struct {
	watchDir          string
	pollInterval      time.Duration
	fileStableSeconds int
	processor         Processor
	uploader          Uploader
	samplingPct       float64
}

// NewWatcher creates a new PCAP directory watcher.
func NewWatcher(cfg WatcherConfig, proc Processor, uploader Uploader) *Watcher {
	return &Watcher{
		watchDir:          cfg.WatchDir,
		pollInterval:      cfg.PollInterval,
		fileStableSeconds: cfg.FileStableSeconds,
		processor:         proc,
		uploader:          uploader,
		samplingPct:       cfg.SamplingPct,
	}
}

// Run starts the watcher loop. It creates subdirectories, then polls for new
// PCAP files until the context is canceled. Returns api.ErrAPIGone if a 410
// response is received during upload.
func (w *Watcher) Run(ctx context.Context) error {
	incomingDir := filepath.Join(w.watchDir, "incoming")
	processingDir := filepath.Join(w.watchDir, "processing")
	processedDir := filepath.Join(w.watchDir, "processed")
	failedDir := filepath.Join(w.watchDir, "failed")

	for _, dir := range []string{incomingDir, processingDir, processedDir, failedDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// TODO: Implement retention cleanup for the processed/ directory to avoid unbounded disk growth.

	log.Printf("[pcap-ingest] Watching %s for PCAP files (poll every %s)", incomingDir, w.pollInterval)

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[pcap-ingest] Context canceled, stopping watcher")
			return nil
		case <-ticker.C:
			if err := w.pollOnce(ctx, incomingDir, processingDir, processedDir, failedDir); err != nil {
				if errors.Is(err, api.ErrAPIGone) {
					return api.ErrAPIGone
				}
				log.Printf("[pcap-ingest] Poll error: %v", err)
			}
		}
	}
}

// pollOnce scans the incoming directory and processes any PCAP files found.
func (w *Watcher) pollOnce(ctx context.Context, incomingDir, processingDir, processedDir, failedDir string) error {
	entries, err := os.ReadDir(incomingDir)
	if err != nil {
		return fmt.Errorf("failed to read incoming directory: %w", err)
	}

	// Filter for PCAP files and collect them with their modification times
	type pcapEntry struct {
		entry   os.DirEntry
		modTime time.Time
	}
	var pcapFiles []pcapEntry

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !isPCAPFile(entry.Name()) {
			continue
		}

		// Get modification time for sorting
		info, err := entry.Info()
		if err != nil {
			log.Printf("[pcap-ingest] Failed to stat %s: %v, skipping", entry.Name(), err)
			continue
		}

		pcapFiles = append(pcapFiles, pcapEntry{
			entry:   entry,
			modTime: info.ModTime(),
		})
	}

	// Sort by modification time (oldest first)
	sort.Slice(pcapFiles, func(i, j int) bool {
		return pcapFiles[i].modTime.Before(pcapFiles[j].modTime)
	})

	// Process files in order of modification time
	for _, pf := range pcapFiles {
		if ctx.Err() != nil {
			return nil
		}

		srcPath := filepath.Join(incomingDir, pf.entry.Name())

		if !w.isFileStable(srcPath) {
			log.Printf("[pcap-ingest] File %s not yet stable, skipping", pf.entry.Name())
			continue
		}

		if err := w.processFile(ctx, srcPath, processingDir, processedDir, failedDir); err != nil {
			if errors.Is(err, api.ErrAPIGone) {
				return api.ErrAPIGone
			}
			log.Printf("[pcap-ingest] Failed to process %s: %v", pf.entry.Name(), err)
		}
	}

	return nil
}

// processFile moves a PCAP from incoming to processing, runs the processor
// and uploader, then moves to processed or failed.
func (w *Watcher) processFile(ctx context.Context, srcPath, processingDir, processedDir, failedDir string) error {
	fileName := filepath.Base(srcPath)
	procPath := filepath.Join(processingDir, fileName)

	// Move to processing
	if err := os.Rename(srcPath, procPath); err != nil {
		return fmt.Errorf("failed to move %s to processing: %w", fileName, err)
	}

	log.Printf("[pcap-ingest] Processing %s", fileName)

	result, err := w.processor.ProcessPCAP(procPath, w.samplingPct)
	if err != nil {
		log.Printf("[pcap-ingest] Processing failed for %s: %v", fileName, err)
		// Move to failed
		failPath := filepath.Join(failedDir, fileName)
		if moveErr := os.Rename(procPath, failPath); moveErr != nil {
			log.Printf("[pcap-ingest] Failed to move %s to failed dir: %v", fileName, moveErr)
		}
		return nil
	}

	if w.uploader != nil {
		uploadErr := w.uploader.UploadLogs(ctx, api.LogFiles{
			DNSPath:    result.DNSPath,
			ConnPath:   result.ConnPath,
			DHCPPath:   result.DHCPPath,
			JA3JA4Path: result.JA3JA4Path,
			JA4SPath:   result.JA4SPath,
		})
		if uploadErr != nil {
			if uploadErr == api.ErrAPIGone {
				// Move to processed before returning the error
				dstPath := filepath.Join(processedDir, fileName)
				_ = os.Rename(procPath, dstPath)
				return api.ErrAPIGone
			}
			log.Printf("[pcap-ingest] Upload failed for %s: %v", fileName, uploadErr)
		}
	}

	// Move to processed
	dstPath := filepath.Join(processedDir, fileName)
	if err := os.Rename(procPath, dstPath); err != nil {
		log.Printf("[pcap-ingest] Failed to move %s to processed dir: %v", fileName, err)
	} else {
		log.Printf("[pcap-ingest] Successfully processed %s", fileName)
	}

	return nil
}

// isFileStable checks if a file's size has not changed over the configured
// stability period.
func (w *Watcher) isFileStable(path string) bool {
	info1, err := os.Stat(path)
	if err != nil {
		return false
	}
	time.Sleep(time.Duration(w.fileStableSeconds) * time.Second)
	info2, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info1.Size() == info2.Size()
}

// isPCAPFile returns true if the filename has a .pcap or .pcapng extension.
func isPCAPFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".pcap") || strings.HasSuffix(lower, ".pcapng")
}

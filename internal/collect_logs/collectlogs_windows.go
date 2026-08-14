//go:build windows

package collect_logs

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
)

// ArchiveExt is the archive extension used on Windows.
const ArchiveExt = ".zip"

// Packaged-install source paths on Windows.
//
// Only config.json has a fixed absolute home: the installer
// (installer/windows/enigma-sensor-installer.iss) copies config.example.json
// verbatim to C:\ProgramData\EnigmaSensor\config.json, changing only
// api_key/network_id. That config keeps relative paths for everything else
// (capture.output_dir = "./captures", logging.file = "logs/enigma-sensor.log").
// The service runs via NSSM with AppDirectory set to the install dir
// (C:\Program Files\EnigmaSensor), so at runtime the process cwd is the
// install dir, not ProgramData. Leaving the log and capture dirs empty here
// means resolveDir falls through to its cwd-relative fallback ("logs",
// "captures"), which resolves against that install-dir cwd and matches
// where the running service actually writes.
const (
	defaultInstallLogDir     = ``
	defaultInstallCaptureDir = ``
	defaultInstallConfigPath = `C:\ProgramData\EnigmaSensor\config.json`
)

// writeArchiveDefault writes a zip archive containing the given on-disk files
// and generated blobs. It returns the number of on-disk source files actually
// written into the archive; the generated blobs are not counted.
func writeArchiveDefault(outName string, files []archiveFile, blobs []archiveBlob) (int, error) {
	out, err := os.Create(outName)
	if err != nil {
		return 0, fmt.Errorf("failed to create archive file %s: %w", outName, err)
	}

	zipWriter := zip.NewWriter(out)

	written := 0
	writeErr := func() error {
		for _, f := range files {
			if err := addFileToZip(zipWriter, f); err != nil {
				// Non-fatal: a source file that cannot be archived is skipped.
				fmt.Fprintf(os.Stderr, "warning: skipped %s: %v\n", f.Source, err)
				continue
			}
			written++
		}
		for _, blob := range blobs {
			if err := addBlobToZip(zipWriter, blob); err != nil {
				return fmt.Errorf("failed to add %s to archive: %w", blob.Name, err)
			}
		}
		return nil
	}()

	if writeErr != nil {
		_ = zipWriter.Close()
		_ = out.Close()
		return written, writeErr
	}

	if err := zipWriter.Close(); err != nil {
		_ = out.Close()
		return written, fmt.Errorf("failed to close zip writer for %s: %w", outName, err)
	}
	if err := out.Close(); err != nil {
		return written, fmt.Errorf("failed to close archive file %s: %w", outName, err)
	}
	return written, nil
}

func addFileToZip(zipWriter *zip.Writer, af archiveFile) error {
	f, err := os.Open(af.Source)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", af.Source)
	}

	w, err := zipWriter.Create(af.Name)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}

func addBlobToZip(zipWriter *zip.Writer, blob archiveBlob) error {
	w, err := zipWriter.Create(blob.Name)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(blob.Content))
	return err
}

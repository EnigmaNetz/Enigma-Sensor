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

// writeArchiveDefault writes a zip archive containing the given on-disk entries
// and generated blobs. It returns the number of on-disk source files actually
// written into the archive; the generated blobs are not counted.
func writeArchiveDefault(outName string, entries []archiveEntry, blobs []archiveBlob) (int, error) {
	// Never overwrite an existing file. The mode has no effect on Windows: the
	// archive takes its permissions from the folder it is written to.
	out, err := os.OpenFile(outName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return 0, fmt.Errorf("failed to create archive file %s: %w", outName, err)
	}

	zipWriter := zip.NewWriter(out)

	written := 0
	writeErr := func() error {
		for _, entry := range entries {
			if err := addFileToZip(zipWriter, entry); err != nil {
				// Non-fatal: a source file that cannot be archived is skipped.
				fmt.Fprintf(os.Stderr, "warning: skipped %s: %v\n", entry.Path, err)
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

func addFileToZip(zipWriter *zip.Writer, entry archiveEntry) error {
	f, _, _, err := openEntry(entry)
	if err != nil {
		return err
	}
	defer f.Close()

	w, err := zipWriter.Create(entry.Name)
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

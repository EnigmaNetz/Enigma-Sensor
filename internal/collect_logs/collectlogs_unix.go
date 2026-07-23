//go:build !windows

package collect_logs

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
)

// ArchiveExt is the archive extension used on non-Windows platforms.
const ArchiveExt = ".tar.gz"

// writeArchiveDefault writes a gzip-compressed tar archive containing the
// given on-disk files and generated blobs. It returns the number of on-disk
// source files actually written into the archive; the generated blobs are not
// counted.
func writeArchiveDefault(outName string, files []string, blobs []archiveBlob) (int, error) {
	out, err := os.Create(outName)
	if err != nil {
		return 0, fmt.Errorf("failed to create archive file %s: %w", outName, err)
	}

	gzWriter := gzip.NewWriter(out)
	tarWriter := tar.NewWriter(gzWriter)

	written := 0
	writeErr := func() error {
		for _, path := range files {
			if err := addFileToTar(tarWriter, path); err != nil {
				// Non-fatal: a source file that cannot be archived is skipped.
				// addFileToTar leaves the tar stream well-formed in that case.
				fmt.Fprintf(os.Stderr, "warning: skipped %s: %v\n", path, err)
				continue
			}
			written++
		}
		for _, blob := range blobs {
			if err := addBlobToTar(tarWriter, blob); err != nil {
				return fmt.Errorf("failed to add %s to archive: %w", blob.Name, err)
			}
		}
		return nil
	}()

	if writeErr != nil {
		_ = tarWriter.Close()
		_ = gzWriter.Close()
		_ = out.Close()
		return written, writeErr
	}

	if err := tarWriter.Close(); err != nil {
		_ = gzWriter.Close()
		_ = out.Close()
		return written, fmt.Errorf("failed to close tar writer for %s: %w", outName, err)
	}
	if err := gzWriter.Close(); err != nil {
		_ = out.Close()
		return written, fmt.Errorf("failed to close gzip writer for %s: %w", outName, err)
	}
	if err := out.Close(); err != nil {
		return written, fmt.Errorf("failed to close archive file %s: %w", outName, err)
	}
	return written, nil
}

// addFileToTar writes one on-disk file into the tar stream. The tar writer
// pre-declares the entry size, so exactly hdr.Size bytes must be written or the
// writer latches a sticky error that would poison every later entry. Anything
// that could produce a short or long copy is therefore handled here: non-regular
// files are rejected before the header is written, a file that shrank mid-copy
// is zero-padded, and a file that grew is truncated to the declared size.
func addFileToTar(tarWriter *tar.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", path)
	}

	hdr := &tar.Header{
		Name:     path,
		Mode:     0644,
		Size:     info.Size(),
		ModTime:  info.ModTime(),
		Typeflag: tar.TypeReg,
	}
	if err := tarWriter.WriteHeader(hdr); err != nil {
		return err
	}

	n, copyErr := io.CopyN(tarWriter, f, hdr.Size)
	if copyErr != nil && copyErr != io.EOF {
		// The entry is already open in the stream. Pad it out so the archive
		// stays well-formed, then report the failure so the caller can skip it.
		if padErr := padTarEntry(tarWriter, hdr.Size-n); padErr != nil {
			return fmt.Errorf("failed to pad truncated entry %s: %w", path, padErr)
		}
		return copyErr
	}
	if n < hdr.Size {
		// The file shrank between stat and copy. Pad the remainder with zeros
		// so the declared size is honoured.
		if err := padTarEntry(tarWriter, hdr.Size-n); err != nil {
			return fmt.Errorf("failed to pad shrunken entry %s: %w", path, err)
		}
	}
	return nil
}

// padTarEntry writes n zero bytes into the current tar entry.
func padTarEntry(tarWriter *tar.Writer, n int64) error {
	if n <= 0 {
		return nil
	}
	if _, err := io.CopyN(tarWriter, zeroReader{}, n); err != nil {
		return err
	}
	return nil
}

// zeroReader is an infinite source of zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func addBlobToTar(tarWriter *tar.Writer, blob archiveBlob) error {
	hdr := &tar.Header{
		Name:     blob.Name,
		Mode:     0644,
		Size:     int64(len(blob.Content)),
		Typeflag: tar.TypeReg,
	}
	if err := tarWriter.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tarWriter.Write([]byte(blob.Content)); err != nil {
		return err
	}
	return nil
}

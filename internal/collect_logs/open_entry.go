package collect_logs

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// readCloser pairs a reader with the closers of everything underneath it.
type readCloser struct {
	io.Reader
	closers []io.Closer
}

func (rc readCloser) Close() error {
	var first error
	for i := len(rc.closers) - 1; i >= 0; i-- {
		if err := rc.closers[i].Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// openEntry opens an entry's content for archiving and returns it with its
// exact size and modification time. A redacted .gz file is decompressed, so
// its size is measured with a first full read.
func openEntry(e archiveEntry) (io.ReadCloser, int64, time.Time, error) {
	f, info, err := openRegular(e.Path)
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	if e.Redact == nil {
		return f, info.Size(), info.ModTime(), nil
	}
	if !isGzip(e.Path) {
		rr := &redactingReader{src: bufio.NewReader(f), r: e.Redact}
		return readCloser{Reader: rr, closers: []io.Closer{f}}, info.Size(), info.ModTime(), nil
	}

	size, err := gunzippedSize(f)
	_ = f.Close()
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	f, _, err = openRegular(e.Path)
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		_ = f.Close()
		return nil, 0, time.Time{}, err
	}
	rr := &redactingReader{src: bufio.NewReader(gz), r: e.Redact}
	return readCloser{Reader: rr, closers: []io.Closer{f, gz}}, size, info.ModTime(), nil
}

func openRegular(path string) (*os.File, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("not a regular file: %s", path)
	}
	return f, info, nil
}

func gunzippedSize(r io.Reader) (int64, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, err
	}
	defer gz.Close()
	return io.Copy(io.Discard, gz)
}

func isGzip(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".gz")
}

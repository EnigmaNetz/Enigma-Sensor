package api

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// bufferedFile is one buffered payload on disk.
type bufferedFile struct {
	path string
	size int64
}

// bufferedPayloads lists the buffered payloads (.rec and legacy .bin) in the buffer directory,
// oldest first, with their total size. Names lead with their write time and os.ReadDir sorts by
// name, so this is age order, as in flushBuffer.
func (u *LogUploader) bufferedPayloads() ([]bufferedFile, int64, error) {
	entries, err := os.ReadDir(u.bufferDir)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read buffer dir: %w", err)
	}
	var files []bufferedFile
	var total int64
	for _, e := range entries {
		if e.IsDir() || !isBufferedPayload(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, bufferedFile{path: filepath.Join(u.bufferDir, e.Name()), size: info.Size()})
		total += info.Size()
	}
	return files, total, nil
}

// makeBufferRoom drops the oldest buffered payloads until a new payload of size bytes fits
// under bufferMaxBytes and leaves bufferMinFree bytes free on the disk. When the payload could
// not fit even with the whole buffer emptied, it returns an error before dropping anything, and
// the caller writes nothing.
func (u *LogUploader) makeBufferRoom(size int64) error {
	if u.bufferMaxBytes <= 0 && u.bufferMinFree <= 0 {
		return nil
	}
	if u.bufferMaxBytes > 0 && size > u.bufferMaxBytes {
		return fmt.Errorf("payload of %d bytes is larger than the whole buffer cap (%d bytes)", size, u.bufferMaxBytes)
	}
	files, total, err := u.bufferedPayloads()
	if err != nil {
		return err
	}

	checkFree := u.bufferMinFree > 0
	var free int64
	if checkFree {
		diskFree := u.diskFree
		if diskFree == nil {
			diskFree = freeDiskBytes
		}
		f, err := diskFree(u.bufferDir)
		if err != nil {
			// The size cap still applies; without a reading the floor cannot be checked
			log.Printf("[upload] Could not read free disk space for %s, buffering under the size cap only: %v", u.bufferDir, err)
			checkFree = false
		} else {
			free = int64(min(f, uint64(1<<62))) //nolint:gosec // G115: clamped to fit int64
		}
	}
	// Emptying the buffer would not free enough: something else filled the disk, and deleting
	// buffered data cannot help
	if checkFree && free+total-size < u.bufferMinFree {
		return fmt.Errorf("not enough free disk space to buffer %d bytes and keep buffering.min_free_mb (%d bytes) free: %d bytes free", size, u.bufferMinFree, free)
	}

	overCap := func() bool { return u.bufferMaxBytes > 0 && total+size > u.bufferMaxBytes }
	lowDisk := func() bool { return checkFree && free-size < u.bufferMinFree }

	// Which limit forced the drops, for the log line
	reason := ""
	switch {
	case overCap() && lowDisk():
		reason = fmt.Sprintf("to stay under buffering.max_size_mb (%d bytes, %d buffered) and keep buffering.min_free_mb (%d bytes, %d free)", u.bufferMaxBytes, total, u.bufferMinFree, free)
	case overCap():
		reason = fmt.Sprintf("to stay under buffering.max_size_mb (%d bytes, %d buffered)", u.bufferMaxBytes, total)
	case lowDisk():
		reason = fmt.Sprintf("to keep buffering.min_free_mb (%d bytes, %d free)", u.bufferMinFree, free)
	}

	dropped := 0
	var droppedBytes int64
	for _, f := range files {
		if !overCap() && !lowDisk() {
			break
		}
		err := os.Remove(f.path)
		switch {
		case err == nil:
			dropped++
			droppedBytes += f.size
		case os.IsNotExist(err):
			// A flush already uploaded it; it no longer takes space but was not lost
		default:
			log.Printf("[upload] Could not drop buffered payload %s: %v", filepath.Base(f.path), err)
			continue
		}
		total -= f.size
		free += f.size
	}
	if dropped > 0 {
		log.Printf("[upload] Buffer full: dropped the %d oldest buffered payload(s) (%d bytes) %s", dropped, droppedBytes, reason)
	}
	if overCap() || lowDisk() {
		return fmt.Errorf("could not make room to buffer %d bytes: buffered payloads could not be removed", size)
	}
	return nil
}

package api

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeBuffered writes a buffered payload of size bytes under name in dir.
func writeBuffered(t *testing.T, dir, name string, size int) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte("x"), size), 0o600))
}

// bufferNames lists the files in dir, sorted.
func bufferNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// bufferBytes is the total size of the buffered payloads in dir.
func bufferBytes(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		info, err := e.Info()
		require.NoError(t, err)
		total += info.Size()
	}
	return total
}

// captureLog sends the standard logger to a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// simulatedFree reports free disk space that grows as buffered payloads are removed from dir, the
// way a real volume does.
func simulatedFree(t *testing.T, dir string, freeWithEmptyBuffer int64) func(string) (uint64, error) {
	return func(string) (uint64, error) {
		return uint64(freeWithEmptyBuffer - bufferBytes(t, dir)), nil //nolint:gosec // G115: test values are small
	}
}

func TestBufferSave_CapDropsOldestFirst(t *testing.T) {
	dir := t.TempDir()
	writeBuffered(t, dir, "buf_20260101T000000Z_1.rec", 40)
	writeBuffered(t, dir, "buf_20260101T000001Z_2.rec", 40)
	writeBuffered(t, dir, "buf_20260101T000002Z_3.rec", 40)
	logs := captureLog(t)

	u := &LogUploader{bufferDir: dir, bufferMaxBytes: 150}
	require.NoError(t, u.bufferSave(bytes.Repeat([]byte("y"), 60), bufferRecordsExt))

	names := bufferNames(t, dir)
	assert.NotContains(t, names, "buf_20260101T000000Z_1.rec", "the oldest payload is dropped")
	assert.Contains(t, names, "buf_20260101T000001Z_2.rec")
	assert.Contains(t, names, "buf_20260101T000002Z_3.rec")
	assert.Len(t, names, 3)
	assert.LessOrEqual(t, bufferBytes(t, dir), int64(150))
	assert.Contains(t, logs.String(), "dropped the 1 oldest buffered payload(s) (40 bytes) to stay under buffering.max_size_mb")
	assert.NotContains(t, logs.String(), "min_free_mb", "the log names only the limit that forced the drop")
}

func TestBufferSave_UnderCapDropsNothing(t *testing.T) {
	dir := t.TempDir()
	writeBuffered(t, dir, "buf_20260101T000000Z_1.rec", 40)
	logs := captureLog(t)

	u := &LogUploader{bufferDir: dir, bufferMaxBytes: 150}
	require.NoError(t, u.bufferSave(bytes.Repeat([]byte("y"), 60), bufferRecordsExt))

	assert.Len(t, bufferNames(t, dir), 2)
	assert.NotContains(t, logs.String(), "dropped")
}

func TestBufferSave_PayloadLargerThanCapIsNotWritten(t *testing.T) {
	dir := t.TempDir()
	writeBuffered(t, dir, "buf_20260101T000000Z_1.rec", 40)

	u := &LogUploader{bufferDir: dir, bufferMaxBytes: 50}
	err := u.bufferSave(bytes.Repeat([]byte("y"), 60), bufferRecordsExt)
	require.Error(t, err)

	assert.Equal(t, []string{"buf_20260101T000000Z_1.rec"}, bufferNames(t, dir), "nothing is dropped for a payload that can never fit")
}

func TestBufferSave_LegacyBinCountsAndIsDroppedInAgeOrder(t *testing.T) {
	dir := t.TempDir()
	writeBuffered(t, dir, "buf_20260101T000000Z_1.bin", 40)
	writeBuffered(t, dir, "buf_20260101T000001Z_2.rec", 40)
	writeBuffered(t, dir, "buf_20260101T000002Z_3.bin", 40)
	writeBuffered(t, dir, "notes.txt", 500)

	u := &LogUploader{bufferDir: dir, bufferMaxBytes: 100}
	require.NoError(t, u.bufferSave(bytes.Repeat([]byte("y"), 40), bufferRecordsExt))

	names := bufferNames(t, dir)
	assert.NotContains(t, names, "buf_20260101T000000Z_1.bin", "a legacy .bin payload counts toward the cap and goes first when oldest")
	assert.NotContains(t, names, "buf_20260101T000001Z_2.rec")
	assert.Contains(t, names, "buf_20260101T000002Z_3.bin")
	assert.Contains(t, names, "notes.txt", "a file that is not a buffered payload is never dropped or counted")
	assert.Len(t, names, 3)
}

func TestBufferSave_LowDiskDropsOldestFirst(t *testing.T) {
	dir := t.TempDir()
	writeBuffered(t, dir, "buf_20260101T000000Z_1.rec", 40)
	writeBuffered(t, dir, "buf_20260101T000001Z_2.bin", 40)
	logs := captureLog(t)

	// 100 bytes free with the buffer empty leaves 20 free now. Dropping the oldest frees 40, so
	// the 30 byte write leaves exactly the 30 byte floor.
	u := &LogUploader{bufferDir: dir, bufferMaxBytes: 1000, bufferMinFree: 30, diskFree: simulatedFree(t, dir, 100)}
	require.NoError(t, u.bufferSave(bytes.Repeat([]byte("y"), 30), bufferRecordsExt))

	names := bufferNames(t, dir)
	assert.NotContains(t, names, "buf_20260101T000000Z_1.rec")
	assert.Contains(t, names, "buf_20260101T000001Z_2.bin")
	assert.Len(t, names, 2)
	assert.Contains(t, logs.String(), "dropped the 1 oldest buffered payload(s) (40 bytes) to keep buffering.min_free_mb")
	assert.NotContains(t, logs.String(), "max_size_mb", "the log names only the limit that forced the drop")
}

func TestBufferSave_DiskTooFullEvenWhenEmptyIsNotWritten(t *testing.T) {
	dir := t.TempDir()
	writeBuffered(t, dir, "buf_20260101T000000Z_1.rec", 40)

	u := &LogUploader{bufferDir: dir, bufferMinFree: 100, diskFree: simulatedFree(t, dir, 80)}
	err := u.bufferSave(bytes.Repeat([]byte("y"), 10), bufferRecordsExt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enough free disk space")

	assert.Equal(t, []string{"buf_20260101T000000Z_1.rec"}, bufferNames(t, dir),
		"emptying the buffer could not free enough, so nothing is dropped and the new payload is not written")
}

func TestBufferSave_DiskFreeErrorFallsBackToSizeCap(t *testing.T) {
	dir := t.TempDir()
	logs := captureLog(t)

	u := &LogUploader{bufferDir: dir, bufferMaxBytes: 100, bufferMinFree: 1 << 40,
		diskFree: func(string) (uint64, error) { return 0, errors.New("statfs failed") }}
	require.NoError(t, u.bufferSave(bytes.Repeat([]byte("y"), 10), bufferRecordsExt))

	assert.Len(t, bufferNames(t, dir), 1)
	assert.Contains(t, logs.String(), "Could not read free disk space")
}

func TestBufferSave_NoLimitsSkipsChecks(t *testing.T) {
	dir := t.TempDir()
	called := false
	u := &LogUploader{bufferDir: dir, diskFree: func(string) (uint64, error) { called = true; return 0, nil }}
	require.NoError(t, u.bufferSave(bytes.Repeat([]byte("y"), 10), bufferRecordsExt))

	assert.Len(t, bufferNames(t, dir), 1)
	assert.False(t, called, "no free-space floor means no free-space reading")
}

func TestBufferSave_PayloadAlreadyFlushedIsNotCountedAsDropped(t *testing.T) {
	dir := t.TempDir()
	writeBuffered(t, dir, "buf_20260101T000000Z_1.rec", 40)
	writeBuffered(t, dir, "buf_20260101T000001Z_2.rec", 40)
	logs := captureLog(t)

	// A flush uploads and removes the oldest payload after it was listed but before it is dropped
	flushed := filepath.Join(dir, "buf_20260101T000000Z_1.rec")
	u := &LogUploader{bufferDir: dir, bufferMaxBytes: 45, bufferMinFree: 1,
		diskFree: func(string) (uint64, error) {
			require.NoError(t, os.Remove(flushed))
			return 1 << 30, nil
		}}
	require.NoError(t, u.bufferSave(bytes.Repeat([]byte("y"), 10), bufferRecordsExt))

	assert.Len(t, bufferNames(t, dir), 1)
	assert.Contains(t, logs.String(), "dropped the 1 oldest buffered payload(s) (40 bytes)",
		"the payload a flush uploaded is not reported as lost")
}

func TestBufferSave_PayloadThatCannotBeRemovedIsNotWritten(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory this user cannot delete from")
	}
	dir := t.TempDir()
	writeBuffered(t, dir, "buf_20260101T000000Z_1.rec", 40)
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	logs := captureLog(t)

	u := &LogUploader{bufferDir: dir, bufferMaxBytes: 50}
	err := u.bufferSave(bytes.Repeat([]byte("y"), 20), bufferRecordsExt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not make room")
	assert.Contains(t, logs.String(), "Could not drop buffered payload")
	assert.NotContains(t, logs.String(), "Buffer full")
}

func TestFreeDiskBytes_ReadsTheRealVolume(t *testing.T) {
	free, err := freeDiskBytes(t.TempDir())
	require.NoError(t, err)
	assert.Positive(t, free)
}

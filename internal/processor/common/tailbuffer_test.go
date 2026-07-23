package types

import (
	"io"
	"strings"
	"sync"
	"testing"
)

// TestTailBuffer_UnderCapacity verifies that everything written is retained when
// the total written is smaller than the buffer capacity, and Truncated stays false.
func TestTailBuffer_UnderCapacity(t *testing.T) {
	tb := NewTailBuffer(64)
	n, err := tb.Write([]byte("hello world"))
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != len("hello world") {
		t.Errorf("Write returned n=%d, want %d", n, len("hello world"))
	}
	if got := tb.String(); got != "hello world" {
		t.Errorf("String() = %q, want %q", got, "hello world")
	}
	if tb.Truncated() {
		t.Error("Truncated() = true, want false for under-capacity writes")
	}
}

// TestTailBuffer_ExactlyAtCapacity verifies that a write filling the buffer
// exactly is retained in full and is not reported as truncated.
func TestTailBuffer_ExactlyAtCapacity(t *testing.T) {
	tb := NewTailBuffer(5)
	if _, err := tb.Write([]byte("abcde")); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if got := tb.String(); got != "abcde" {
		t.Errorf("String() = %q, want %q", got, "abcde")
	}
	if tb.Truncated() {
		t.Error("Truncated() = true, want false when exactly at capacity")
	}
}

// TestTailBuffer_OverCapacityKeepsLastBytes verifies that once more than max
// bytes have been written the buffer retains the LAST max bytes and reports
// itself as truncated.
func TestTailBuffer_OverCapacityKeepsLastBytes(t *testing.T) {
	tb := NewTailBuffer(5)
	if _, err := tb.Write([]byte("abc")); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if _, err := tb.Write([]byte("defgh")); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if got := tb.String(); got != "defgh" {
		t.Errorf("String() = %q, want last 5 bytes %q", got, "defgh")
	}
	if !tb.Truncated() {
		t.Error("Truncated() = false, want true after dropping bytes")
	}
}

// TestTailBuffer_SingleOversizedWrite verifies that a single Write larger than
// the capacity keeps only the tail of that write.
func TestTailBuffer_SingleOversizedWrite(t *testing.T) {
	tb := NewTailBuffer(4)
	payload := "0123456789"
	n, err := tb.Write([]byte(payload))
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Write returned n=%d, want %d (full length of p)", n, len(payload))
	}
	if got := tb.String(); got != "6789" {
		t.Errorf("String() = %q, want %q", got, "6789")
	}
	if !tb.Truncated() {
		t.Error("Truncated() = false, want true after an oversized write")
	}
}

// TestTailBuffer_ManySmallWritesAcrossBoundary verifies the sliding-window
// behaviour when the capacity boundary is crossed by an accumulation of small
// writes rather than one big one.
func TestTailBuffer_ManySmallWritesAcrossBoundary(t *testing.T) {
	tb := NewTailBuffer(10)
	for i := 0; i < 26; i++ {
		b := []byte{byte('a' + i)}
		if _, err := tb.Write(b); err != nil {
			t.Fatalf("Write %d returned error: %v", i, err)
		}
	}
	if got := tb.String(); got != "qrstuvwxyz" {
		t.Errorf("String() = %q, want last 10 bytes %q", got, "qrstuvwxyz")
	}
	if !tb.Truncated() {
		t.Error("Truncated() = false, want true")
	}
}

// TestTailBuffer_WriteContractIsMultiWriterSafe verifies the io.Writer contract
// that makes TailBuffer safe as a member of an io.MultiWriter: Write must always
// report len(p) bytes written with a nil error, even when it discards bytes.
// io.MultiWriter aborts with io.ErrShortWrite if any writer under-reports.
func TestTailBuffer_WriteContractIsMultiWriterSafe(t *testing.T) {
	tb := NewTailBuffer(4)
	var sink strings.Builder
	mw := io.MultiWriter(&sink, tb)

	payload := "the quick brown fox"
	n, err := mw.Write([]byte(payload))
	if err != nil {
		t.Fatalf("MultiWriter Write returned error: %v", err)
	}
	if n != len(payload) {
		t.Errorf("MultiWriter Write returned n=%d, want %d", n, len(payload))
	}
	if sink.String() != payload {
		t.Errorf("passthrough writer got %q, want %q", sink.String(), payload)
	}
	if got := tb.String(); got != " fox" {
		t.Errorf("tail String() = %q, want %q", got, " fox")
	}
}

// TestTailBuffer_ZeroAndNegativeCapacity verifies that a non-positive capacity
// is safe: it retains nothing, never panics, and still honours the io.Writer
// contract of reporting len(p).
func TestTailBuffer_ZeroAndNegativeCapacity(t *testing.T) {
	for _, max := range []int{0, -1, -100} {
		tb := NewTailBuffer(max)
		n, err := tb.Write([]byte("some zeek stderr"))
		if err != nil {
			t.Errorf("max=%d: Write returned error: %v", max, err)
		}
		if n != len("some zeek stderr") {
			t.Errorf("max=%d: Write returned n=%d, want %d", max, n, len("some zeek stderr"))
		}
		if got := tb.String(); got != "" {
			t.Errorf("max=%d: String() = %q, want empty", max, got)
		}
	}
}

// TestTailBuffer_EmptyWrite verifies a zero-length write is a no-op that does
// not mark the buffer truncated.
func TestTailBuffer_EmptyWrite(t *testing.T) {
	tb := NewTailBuffer(8)
	n, err := tb.Write(nil)
	if err != nil {
		t.Fatalf("Write(nil) returned error: %v", err)
	}
	if n != 0 {
		t.Errorf("Write(nil) returned n=%d, want 0", n)
	}
	if tb.Truncated() {
		t.Error("Truncated() = true after empty write, want false")
	}
	if got := tb.String(); got != "" {
		t.Errorf("String() = %q, want empty", got)
	}
}

// TestTailBuffer_ConcurrentWrites exercises TailBuffer from multiple goroutines
// so that `go test -race` flags any missing synchronization. Zeek's stdout and
// stderr are written from separate goroutines by os/exec, so this is the real
// usage pattern, not a hypothetical.
func TestTailBuffer_ConcurrentWrites(t *testing.T) {
	tb := NewTailBuffer(32)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 64; j++ {
				if _, err := tb.Write([]byte("zeek stderr line\n")); err != nil {
					t.Errorf("concurrent Write returned error: %v", err)
					return
				}
				_ = tb.String()
				_ = tb.Truncated()
			}
		}()
	}
	wg.Wait()

	if got := len(tb.String()); got > 32 {
		t.Errorf("String() length = %d, want <= 32", got)
	}
	if !tb.Truncated() {
		t.Error("Truncated() = false after far more than 32 bytes written, want true")
	}
}

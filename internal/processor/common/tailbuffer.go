package types

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ZeekStderrTailBytes bounds how much of Zeek's stderr is retained for the
// failure log line.
const ZeekStderrTailBytes = 64 * 1024

// ZeekWaitDelay bounds how long Wait blocks after Zeek exits. Stderr is an
// io.MultiWriter rather than an *os.File, so os/exec pipes it through a copier
// goroutine; without a delay Wait would block forever whenever a grandchild
// inherited the write end of that pipe and outlived Zeek, permanently parking
// the worker goroutine. After the delay os/exec force-closes the pipes and Wait
// returns exec.ErrWaitDelay.
const ZeekWaitDelay = 30 * time.Second

// TailBuffer is an io.Writer that retains only the last max bytes written to it.
// It is safe for concurrent use and never reports a short write, so it can be
// dropped into an io.MultiWriter without breaking the chain.
type TailBuffer struct {
	mu        sync.Mutex
	buf       []byte
	max       int
	truncated bool
}

// NewTailBuffer returns a TailBuffer retaining at most max bytes. A non-positive
// max retains nothing.
func NewTailBuffer(max int) *TailBuffer {
	// The backing array is allocated lazily on the first Write so a run where
	// Zeek writes nothing to stderr costs no memory.
	return &TailBuffer{max: max}
}

// Write records the tail of p, always reporting len(p) bytes written with a nil
// error so io.MultiWriter does not abort with io.ErrShortWrite.
func (t *TailBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if n == 0 {
		return 0, nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.max <= 0 {
		t.truncated = true
		return n, nil
	}

	if t.buf == nil {
		t.buf = make([]byte, 0, t.max)
	}

	if n >= t.max {
		if n > t.max || len(t.buf) > 0 {
			t.truncated = true
		}
		t.buf = append(t.buf[:0], p[n-t.max:]...)
		return n, nil
	}

	if len(t.buf)+n > t.max {
		t.truncated = true
		drop := len(t.buf) + n - t.max
		kept := copy(t.buf, t.buf[drop:])
		t.buf = t.buf[:kept]
	}
	t.buf = append(t.buf, p...)
	return n, nil
}

// String returns the retained tail.
func (t *TailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// Truncated reports whether any bytes have been discarded.
func (t *TailBuffer) Truncated() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.truncated
}

// FormatZeekFailure builds the detail portion of the Zeek failure log line: the
// underlying error, the decoded exit status when available, and the captured
// stderr tail so a field engineer can read why Zeek died.
func FormatZeekFailure(err error, tail *TailBuffer) string {
	parts := []string{fmt.Sprintf("%v", err)}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ProcessState != nil {
		if code := exitErr.ExitCode(); code >= 0 {
			parts = append(parts, fmt.Sprintf("exit code %d", code))
		} else {
			parts = append(parts, fmt.Sprintf("terminated by %s", exitErr.ProcessState.String()))
		}
	}

	detail := "zeek stderr: <empty>"
	if tail != nil {
		if s := tail.String(); s != "" {
			if tail.Truncated() {
				detail = fmt.Sprintf("zeek stderr (truncated, last %d bytes):\n%s", len(s), s)
			} else {
				detail = fmt.Sprintf("zeek stderr:\n%s", s)
			}
		}
	}
	parts = append(parts, detail)

	return strings.Join(parts, " | ")
}

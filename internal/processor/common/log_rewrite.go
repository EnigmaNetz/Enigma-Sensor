package types

import (
	"bufio"
	"bytes"
	"fmt"
	"os"

	"EnigmaNetz/Enigma-Go-Sensor/internal/records"
)

// rewriteLog streams a Zeek JSON log through edit one line at a time and replaces the file only
// if edit dropped or changed a line, so memory stays at one line however large the log is. The
// replacement is a temporary file renamed over the log, so a failure leaves the log as it was.
//
// edit returns the line to keep (nil to drop it) or an error, which stops the rewrite and is
// returned with its line number. Blank lines are kept without calling edit. A missing file
// returns 0 and no error. The result is the number of lines dropped or changed.
func rewriteLog(path string, edit func(line []byte) ([]byte, error)) (int, error) {
	in, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read: %w", err)
	}
	defer in.Close()

	tmpPath := path + ".rewrite"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("create temporary file: %w", err)
	}
	replaced := false
	defer func() {
		if !replaced {
			_ = os.Remove(tmpPath)
		}
	}()

	changed, err := copyEdited(in, out, edit)
	if closeErr := out.Close(); err == nil && closeErr != nil {
		err = fmt.Errorf("write: %w", closeErr)
	}
	if err != nil || changed == 0 {
		return 0, err
	}
	// Close the log before replacing it: Windows cannot rename over an open file.
	in.Close()
	if err := os.Rename(tmpPath, path); err != nil {
		return 0, fmt.Errorf("replace log: %w", err)
	}
	replaced = true
	return changed, nil
}

func copyEdited(in *os.File, out *os.File, edit func([]byte) ([]byte, error)) (int, error) {
	w := bufio.NewWriter(out)
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), records.MaxLineBytes)
	changed, lineNo := 0, 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		kept := line
		if len(bytes.TrimSpace(line)) > 0 {
			var err error
			if kept, err = edit(line); err != nil {
				return 0, fmt.Errorf("line %d: %w", lineNo, err)
			}
			if kept == nil || !bytes.Equal(kept, line) {
				changed++
			}
			if kept == nil {
				continue
			}
		}
		if _, err := w.Write(kept); err != nil {
			return 0, fmt.Errorf("write: %w", err)
		}
		if err := w.WriteByte('\n'); err != nil {
			return 0, fmt.Errorf("write: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("line %d: read: %w", lineNo+1, err)
	}
	if err := w.Flush(); err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}
	return changed, nil
}

package flowlogs

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// output writes a poll's conn records, creating its directory only when there is a record.
type output struct {
	dir     string
	f       *os.File
	w       *bufio.Writer
	enc     *json.Encoder
	err     error
	records int
}

func (o *output) write(rec ConnRecord) {
	if o.err != nil {
		return
	}
	if o.f == nil {
		if o.err = os.MkdirAll(o.dir, 0o755); o.err != nil {
			return
		}
		if o.f, o.err = os.Create(filepath.Join(o.dir, connLog)); o.err != nil {
			return
		}
		o.w = bufio.NewWriter(o.f)
		o.enc = json.NewEncoder(o.w)
		o.enc.SetEscapeHTML(false)
	}
	if o.err = o.enc.Encode(rec); o.err == nil {
		o.records++
	}
}

func (o *output) close() error {
	if o.f != nil {
		if err := o.w.Flush(); err != nil && o.err == nil {
			o.err = err
		}
		if err := o.f.Close(); err != nil && o.err == nil {
			o.err = err
		}
	}
	if o.err != nil {
		return fmt.Errorf("write %s: %w", filepath.Join(o.dir, connLog), o.err)
	}
	return nil
}

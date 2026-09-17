package collect_logs

import (
	"EnigmaNetz/Enigma-Go-Sensor/config"
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// maskByte overwrites redacted bytes. Masking keeps every file the same length,
// so a tar header can declare the size before the redacted content is streamed.
const maskByte = '*'

var (
	// configKeyPattern matches the api_key value in config.json. Go's JSON
	// decoder matches field names case-insensitively, so this does too.
	configKeyPattern = regexp.MustCompile(`(?i)("api_key"\s*:\s*")((?:[^"\\]|\\.)*)"`)
	// configDumpKeyPattern matches the APIKey field of a config printed with %+v,
	// which sensor versions before B1CF-2020 logged on every start.
	configDumpKeyPattern = regexp.MustCompile(`(APIKey:)([^\s}]*)`)
)

// redactor masks API keys in text files. It masks each literal key it is
// given, and any key in the two shapes the key has been written in, so a key
// that has since been rotated is masked in old logs too.
type redactor struct {
	keys [][]byte
}

// newRedactor returns a redactor for keys, ignoring blank and duplicate ones.
func newRedactor(keys ...string) *redactor {
	r := &redactor{}
	seen := map[string]bool{}
	for _, key := range keys {
		if strings.TrimSpace(key) == "" || seen[key] {
			continue
		}
		seen[key] = true
		r.keys = append(r.keys, []byte(key))
	}
	return r
}

// apiKeysIn returns every api_key value in a config file's raw content. It
// works on content that is not valid JSON and on a value on a later line than
// its name, which a line-by-line match misses.
func apiKeysIn(data []byte) []string {
	var keys []string
	for _, m := range configKeyPattern.FindAllSubmatch(data, -1) {
		keys = append(keys, string(m[2]))
	}
	return keys
}

// redactLine masks secrets in line in place and returns it. Every key is
// found in the unmasked line before any is masked, so keys that overlap, or
// one that contains another, are masked whole.
func (r *redactor) redactLine(line []byte) []byte {
	var found [][2]int
	for _, key := range r.keys {
		for start := 0; ; start++ {
			i := bytes.Index(line[start:], key)
			if i < 0 {
				break
			}
			start += i
			found = append(found, [2]int{start, start + len(key)})
		}
	}
	for _, f := range found {
		mask(line[f[0]:f[1]])
	}
	for _, pattern := range []*regexp.Regexp{configKeyPattern, configDumpKeyPattern} {
		for _, m := range pattern.FindAllSubmatchIndex(line, -1) {
			value := line[m[4]:m[5]]
			if string(value) == config.RedactedValue {
				continue
			}
			mask(value)
		}
	}
	return line
}

func mask(b []byte) {
	for i := range b {
		b[i] = maskByte
	}
}

// redactingReader streams src line by line through a redactor.
type redactingReader struct {
	src     *bufio.Reader
	r       *redactor
	pending []byte
	err     error
}

func (rr *redactingReader) Read(p []byte) (int, error) {
	for len(rr.pending) == 0 {
		if rr.err != nil {
			return 0, rr.err
		}
		line, err := rr.src.ReadBytes('\n')
		rr.pending = rr.r.redactLine(line)
		rr.err = err
	}
	n := copy(p, rr.pending)
	rr.pending = rr.pending[n:]
	return n, nil
}

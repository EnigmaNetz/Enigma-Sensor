package collect_logs

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// apiSettingsKey is the config section holding the key. Go's JSON decoder
// matches it case-insensitively, so this does too.
const apiSettingsKey = "enigma_api"

// publicAPISettings are the enigma_api fields left readable in a bundle.
// Support needs them to diagnose connection and certificate problems, and
// neither holds a secret. Every other string under enigma_api is masked, so a
// misspelled key name such as "apikey" is masked rather than missed.
var publicAPISettings = []string{"server", "ca_cert_file"}

// redactConfig masks secrets in a config file by its JSON structure and
// reports whether it could. It masks every string under enigma_api except
// publicAPISettings, and every string in a field whose name looks like a
// secret, wherever it is. Content that is not valid JSON has no structure to
// follow, so it returns false and the caller must leave the file out.
// Masking replaces the characters inside the quotes, so the result is still
// valid JSON with the original layout.
func redactConfig(data []byte) ([]byte, bool) {
	if !json.Valid(data) {
		return nil, false
	}

	type frame struct {
		object  bool   // an object, not an array
		wantKey bool   // the next token in an object is a field name
		key     string // the current field name in an object
		maskAll bool   // every string inside is a secret
		api     bool   // this object is the top-level enigma_api section
	}

	out := bytes.Clone(data)
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []*frame
	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err == io.EOF {
			return out, true
		}
		if err != nil {
			return nil, false
		}

		var parent *frame
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		if parent != nil && parent.object && parent.wantKey {
			if name, ok := tok.(string); ok {
				parent.key = name
				parent.wantKey = false
				continue
			}
		}

		// tok is a value (or a closing delimiter). Decide whether a value in
		// this position is a secret.
		secret := false
		if parent != nil {
			secret = parent.maskAll
			if parent.object {
				secret = secret || secretName(parent.key) || (parent.api && !publicAPISetting(parent.key))
			}
		}

		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				child := &frame{object: t == '{', wantKey: t == '{', maskAll: secret}
				child.api = t == '{' && len(stack) == 1 && parent.object && strings.EqualFold(parent.key, apiSettingsKey)
				stack = append(stack, child)
				continue
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
		case string:
			if secret {
				maskStringToken(out, int(start), int(dec.InputOffset()))
			}
		}
		// A value in an object is complete, so a field name comes next.
		if len(stack) > 0 && stack[len(stack)-1].object {
			stack[len(stack)-1].wantKey = true
		}
	}
}

// maskStringToken masks the characters inside the quotes of the JSON string
// that ends at end. The token starts after any whitespace, colon or comma
// following from.
func maskStringToken(b []byte, from, end int) {
	start := from
	for start < end && b[start] != '"' {
		start++
	}
	if end-start >= 2 {
		mask(b[start+1 : end-1])
	}
}

// secretName reports whether a field name looks like it holds a secret.
func secretName(name string) bool {
	n := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(name))
	for _, word := range []string{"key", "secret", "token", "password"} {
		if strings.Contains(n, word) {
			return true
		}
	}
	return false
}

func publicAPISetting(name string) bool {
	for _, public := range publicAPISettings {
		if strings.EqualFold(name, public) {
			return true
		}
	}
	return false
}

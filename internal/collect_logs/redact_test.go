package collect_logs

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestRedactLine(t *testing.T) {
	const key = "live-key-7f3a9c2e"
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "literal key anywhere in a line",
			in:   "upload failed for key live-key-7f3a9c2e, retrying live-key-7f3a9c2e",
			want: "upload failed for key *****************, retrying *****************",
		},
		{
			name: "config json value",
			in:   `    "api_key": "rotated-old-key",`,
			want: `    "api_key": "***************",`,
		},
		{
			name: "config json value with escaped quote",
			in:   `{"api_key":"ab\"cd"}`,
			want: `{"api_key":"******"}`,
		},
		{
			name: "config dumped with %+v by older sensors",
			in:   "2026/09/01 Loaded config: &{NetworkID:HQ EnigmaAPI:{Server:api.enigmaai.net:443 APIKey:rotated-old-key CACertFile: Upload:true}}",
			want: "2026/09/01 Loaded config: &{NetworkID:HQ EnigmaAPI:{Server:api.enigmaai.net:443 APIKey:*************** CACertFile: Upload:true}}",
		},
		{
			name: "config dump with the key at the end of its struct",
			in:   "EnigmaAPI:{APIKey:rotated-old-key}",
			want: "EnigmaAPI:{APIKey:***************}",
		},
		{
			name: "already redacted dump is left readable",
			in:   "Loaded config from /etc/enigma-sensor/config.json: {EnigmaAPI:{APIKey:[REDACTED] Upload:true}}",
			want: "Loaded config from /etc/enigma-sensor/config.json: {EnigmaAPI:{APIKey:[REDACTED] Upload:true}}",
		},
		{
			name: "line without secrets is unchanged",
			in:   "[upload] Sending metadata to API: map[network_id:HQ]",
			want: "[upload] Sending metadata to API: map[network_id:HQ]",
		},
	}
	r := newRedactor(key)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(r.redactLine([]byte(tt.in)))
			if got != tt.want {
				t.Errorf("redactLine:\n got  %q\n want %q", got, tt.want)
			}
			if len(got) != len(tt.in) {
				t.Errorf("redaction changed the length from %d to %d", len(tt.in), len(got))
			}
		})
	}
}

func TestRedactLine_EmptyKeyMasksNothingExtra(t *testing.T) {
	for _, key := range []string{"", "   "} {
		in := "plain line with spaces"
		if got := string(newRedactor(key).redactLine([]byte(in))); got != in {
			t.Errorf("key %q: got %q, want the line unchanged", key, got)
		}
	}
}

func TestRedactingReader_StreamsLinesAndKeepsLength(t *testing.T) {
	const key = "live-key-7f3a9c2e"
	in := "first live-key-7f3a9c2e\n\nsecond line\nlast without newline live-key-7f3a9c2e"
	rr := &redactingReader{src: bufio.NewReader(strings.NewReader(in)), r: newRedactor(key)}

	// A tiny read buffer forces lines to be returned across several reads.
	var out strings.Builder
	buf := make([]byte, 3)
	for {
		n, err := rr.Read(buf)
		out.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}

	want := "first *****************\n\nsecond line\nlast without newline *****************"
	if out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}

func TestRedactLine_OverlappingKeysAreMaskedWhole(t *testing.T) {
	tests := []struct {
		name string
		keys []string
		in   string
	}{
		{"one key contains another", []string{"FAKE-SEC", "FAKE-SECRET-18"}, "key FAKE-SECRET-18 end"},
		{"same keys in the other order", []string{"FAKE-SECRET-18", "FAKE-SEC"}, "key FAKE-SECRET-18 end"},
		{"keys that partly overlap", []string{"abcXYZ", "XYZdef"}, "key abcXYZdef end"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(newRedactor(tt.keys...).redactLine([]byte(tt.in)))
			if want := "key " + strings.Repeat("*", len(tt.in)-len("key  end")) + " end"; got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

func TestRedactConfig(t *testing.T) {
	in := `{
  "network_id": "HQ-Firewall-01",
  "logging": {"file": "/var/log/enigma-sensor/enigma-sensor.log"},
  "Enigma_API": {
    "server": "enigma.acme.internal:443",
    "CA_Cert_File": "/etc/enigma-sensor/enigma-ca.crt",
    "api_key": "k1-secret",
    "apikey": "k2-secret",
    "api-key": "k3-\"quoted\"-secret",
    "notes": ["k4-secret", {"x": "k5-secret"}],
    "upload": true,
    "max_payload_size_mb": 25
  },
  "zeek": {"auth_token": "k6-secret", "excluded_subnets": "10.0.0.0/8"}
}`
	got, ok := redactConfig([]byte(in))
	if !ok {
		t.Fatal("redactConfig rejected valid JSON")
	}
	if len(got) != len(in) || !json.Valid(got) {
		t.Fatalf("masked config changed length or is not valid JSON:\n%s", got)
	}
	if strings.Contains(string(got), "secret") {
		t.Errorf("masked config still holds a secret:\n%s", got)
	}
	for _, kept := range []string{"HQ-Firewall-01", "/var/log/enigma-sensor/enigma-sensor.log", "enigma.acme.internal:443", "/etc/enigma-sensor/enigma-ca.crt", "10.0.0.0/8", "\"api_key\"", "\"upload\": true"} {
		if !strings.Contains(string(got), kept) {
			t.Errorf("masked config lost %q:\n%s", kept, got)
		}
	}

	for _, bad := range []string{`{"enigma_api": {"api_key": "x",}}`, `{'api_key': "x"}`, ``, `{"a": 1} {"b": 2}`} {
		if _, ok := redactConfig([]byte(bad)); ok {
			t.Errorf("redactConfig accepted invalid JSON %q", bad)
		}
	}
}

package records

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"EnigmaNetz/Enigma-Go-Sensor/internal/api/ingest"
)

// readTSV parses a tab-separated Zeek log the way Enigma-Subscriber's streaming_zeek_parser.ts
// does: "-" is null, "(empty)" is "", time, interval and double are floats, count and port are
// numbers, bool is T, and the "id." prefix is dropped from column names.
func readTSV(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var fields, types []string
	var rows []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "#fields\t"):
			fields = strings.Split(line, "\t")[1:]
		case strings.HasPrefix(line, "#types\t"):
			types = strings.Split(line, "\t")[1:]
		case line == "" || strings.HasPrefix(line, "#"):
		default:
			row := map[string]any{}
			for i, v := range strings.Split(line, "\t") {
				name := strings.TrimPrefix(fields[i], "id.")
				switch {
				case v == "-":
					row[name] = nil
				case v == "(empty)":
					row[name] = ""
				case types[i] == "time" || types[i] == "interval" || types[i] == "double":
					row[name] = mustFloat(t, v)
				case types[i] == "count" || types[i] == "port":
					row[name] = mustFloat(t, v)
				case types[i] == "bool":
					row[name] = v == "T"
				default:
					row[name] = v
				}
			}
			rows = append(rows, row)
		}
	}
	return rows
}

func mustFloat(t *testing.T, s string) float64 {
	t.Helper()
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// asRow reads a record the way the Subscriber's decoder does: an unset optional field is null.
func asRow(m proto.Message) map[string]any {
	row := map[string]any{}
	msg := m.ProtoReflect()
	fields := msg.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if fd.HasPresence() && !msg.Has(fd) {
			row[string(fd.Name())] = nil
			continue
		}
		v := msg.Get(fd)
		switch fd.Kind() {
		case protoreflect.StringKind:
			row[string(fd.Name())] = v.String()
		case protoreflect.BoolKind:
			row[string(fd.Name())] = v.Bool()
		case protoreflect.DoubleKind:
			row[string(fd.Name())] = v.Float()
		default:
			row[string(fd.Name())] = float64(v.Uint())
		}
	}
	return row
}

func fixturePaths(format string) LogPaths {
	dir := filepath.Join("testdata", format)
	return LogPaths{
		Conn:   filepath.Join(dir, "conn.log"),
		DNS:    filepath.Join(dir, "dns.log"),
		DHCP:   filepath.Join(dir, "dhcp.log"),
		JA3JA4: filepath.Join(dir, "ja3_ja4.log"),
		JA4S:   filepath.Join(dir, "ja4s.log"),
	}
}

var unlimited = Limits{MaxBytes: 1 << 30, MaxRecords: 1 << 30}

// decodeBatch inflates and decodes a batch the way the Subscriber does, and checks its counts
// against the records it holds.
func decodeBatch(t *testing.T, b Batch) *ingest.RecordBatch {
	t.Helper()
	r, err := zlib.NewReader(bytes.NewReader(b.Records))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	var rb ingest.RecordBatch
	if err := proto.Unmarshal(raw, &rb); err != nil {
		t.Fatal(err)
	}
	want := &ingest.RecordCounts{
		Conn: uint32(len(rb.Conn)), Dns: uint32(len(rb.Dns)), Dhcp: uint32(len(rb.Dhcp)),
		Ja3Ja4: uint32(len(rb.Ja3Ja4)), Ja4S: uint32(len(rb.Ja4S)),
	}
	if !proto.Equal(b.Counts, want) {
		t.Fatalf("counts %v, batch holds %v", b.Counts, want)
	}
	return &rb
}

func readBatches(t *testing.T, paths LogPaths, limits Limits) []*ingest.RecordBatch {
	t.Helper()
	var out []*ingest.RecordBatch
	if err := Read(paths, limits, func(b Batch) error {
		out = append(out, decodeBatch(t, b))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func readAll(t *testing.T, paths LogPaths) *ingest.RecordBatch {
	t.Helper()
	batches := readBatches(t, paths, unlimited)
	if len(batches) != 1 {
		t.Fatalf("got %d batches, want 1", len(batches))
	}
	return batches[0]
}

func total(rb *ingest.RecordBatch) int {
	return len(rb.Conn) + len(rb.Dns) + len(rb.Dhcp) + len(rb.Ja3Ja4) + len(rb.Ja4S)
}

// TestParityWithTabSeparatedLogs is the ticket's parity proof: one capture written by Zeek in
// both formats gives the same values through the Subscriber's tab-separated parser and through
// this package.
func TestParityWithTabSeparatedLogs(t *testing.T) {
	batch := readAll(t, fixturePaths("json"))
	tsv := fixturePaths("tsv")

	byField := func(name string) func(map[string]any) string {
		return func(row map[string]any) string { return row[name].(string) }
	}
	// The JA3/JA4 script writes a connection's fingerprint, then writes it again with ja4 and
	// user_agent once it sees that client's HTTP User-Agent, so uid alone is not unique.
	byUIDAndAgent := func(row map[string]any) string {
		agent, _ := row["user_agent"].(string)
		return row["uid"].(string) + "|" + agent
	}
	cases := []struct {
		name    string
		tsvPath string
		records []proto.Message
		key     func(map[string]any) string
	}{
		{"conn", tsv.Conn, toMessages(batch.Conn), byField("uid")},
		{"dns", tsv.DNS, toMessages(batch.Dns), byField("uid")},
		{"dhcp", tsv.DHCP, toMessages(batch.Dhcp), byField("uids")},
		{"ja3_ja4", tsv.JA3JA4, toMessages(batch.Ja3Ja4), byUIDAndAgent},
		{"ja4s", tsv.JA4S, toMessages(batch.Ja4S), byField("uid")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := readTSV(t, c.tsvPath)
			if len(want) == 0 {
				t.Fatal("fixture has no records")
			}
			if len(c.records) != len(want) {
				t.Fatalf("got %d records, want %d", len(c.records), len(want))
			}
			// The two Zeek runs write rows in different orders, so match them by uid.
			got := map[string]map[string]any{}
			for _, r := range c.records {
				row := asRow(r)
				got[c.key(row)] = row
			}
			for _, w := range want {
				k := c.key(w)
				g, ok := got[k]
				if !ok {
					t.Fatalf("no record for %s", k)
				}
				for col, wv := range w {
					gv, has := g[col]
					if !has {
						t.Errorf("column %s has no field in the schema", col)
						continue
					}
					if gv != wv {
						t.Errorf("%s: %s = %#v, want %#v", k, col, gv, wv)
					}
				}
				// Fields the tab-separated log does not have must be unset.
				for col, gv := range g {
					if _, has := w[col]; !has && gv != nil {
						t.Errorf("%s: %s = %#v, not in the tab-separated log", k, col, gv)
					}
				}
			}
		})
	}
}

func toMessages[T proto.Message](in []T) []proto.Message {
	out := make([]proto.Message, len(in))
	for i, m := range in {
		out[i] = m
	}
	return out
}

func TestDecode(t *testing.T) {
	t.Run("rounds doubles to six places", func(t *testing.T) {
		var r ingest.ConnRecord
		if err := Decode([]byte(`{"ts":1.0,"duration":0.007250070571899414}`), &r); err != nil {
			t.Fatal(err)
		}
		if r.GetDuration() != 0.00725 {
			t.Fatalf("duration = %v", r.GetDuration())
		}
	})
	t.Run("leaves an absent optional field unset", func(t *testing.T) {
		var r ingest.ConnRecord
		if err := Decode([]byte(`{"ts":1.0,"uid":"C1"}`), &r); err != nil {
			t.Fatal(err)
		}
		if r.Service != nil || r.OrigBytes != nil {
			t.Fatalf("unset fields were set: %v", &r)
		}
	})
	t.Run("joins vectors and writes empty ones as empty strings", func(t *testing.T) {
		var r ingest.DnsRecord
		if err := Decode([]byte(`{"answers":["a.example","10.0.0.1"],"TTLs":[3600.0,60.5],"opcode_name":[]}`), &r); err == nil {
			// opcode_name is a string in the schema; an empty JSON array becomes "".
			if r.GetAnswers() != "a.example,10.0.0.1" || r.GetTTLs() != "3600.000000,60.500000" {
				t.Fatalf("answers=%q TTLs=%q", r.GetAnswers(), r.GetTTLs())
			}
			if r.OpcodeName == nil || *r.OpcodeName != "" {
				t.Fatalf("opcode_name = %v", r.OpcodeName)
			}
		} else {
			t.Fatal(err)
		}
	})
	t.Run("escapes a comma inside a list element as the tab-separated log does", func(t *testing.T) {
		var r ingest.DnsRecord
		if err := Decode([]byte(`{"answers":["TXT 9 a, b","plain"]}`), &r); err != nil {
			t.Fatal(err)
		}
		if r.GetAnswers() != `TXT 9 a\x2c b,plain` {
			t.Fatalf("answers = %q", r.GetAnswers())
		}
	})
	t.Run("reads addresses only from the id. columns the filter checks", func(t *testing.T) {
		var r ingest.ConnRecord
		if err := Decode([]byte(`{"ts":1.0,"orig_h":"10.0.0.1","resp_h":"10.0.0.2","id.orig_p":5}`), &r); err != nil {
			t.Fatal(err)
		}
		if r.OrigH != "" || r.RespH != "" || r.OrigP != 5 {
			t.Fatalf("orig_h=%q resp_h=%q orig_p=%d", r.OrigH, r.RespH, r.OrigP)
		}
	})
	t.Run("escapes control characters as the tab-separated log does", func(t *testing.T) {
		var r ingest.DnsRecord
		if err := Decode([]byte(`{"query":"a\tb\nc\u007fd"}`), &r); err != nil {
			t.Fatal(err)
		}
		if r.GetQuery() != `a\x09b\x0ac\x7fd` {
			t.Fatalf("query = %q", r.GetQuery())
		}
	})
	t.Run("ignores a column the schema does not have", func(t *testing.T) {
		var r ingest.ConnRecord
		if err := Decode([]byte(`{"ts":1.0,"a_new_zeek_column":"x"}`), &r); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("refuses a line that is not JSON", func(t *testing.T) {
		var r ingest.ConnRecord
		if err := Decode([]byte("1.0\tC1\t10.0.0.1"), &r); err == nil {
			t.Fatal("want an error")
		}
	})
}

func TestRead(t *testing.T) {
	t.Run("emits nothing when there are no records", func(t *testing.T) {
		if got := readBatches(t, LogPaths{Conn: filepath.Join(t.TempDir(), "missing.log")}, unlimited); len(got) != 0 {
			t.Fatalf("got %d batches", len(got))
		}
	})
	t.Run("splits by record count and keeps every record", func(t *testing.T) {
		all := readAll(t, fixturePaths("json"))
		sum := 0
		for _, b := range readBatches(t, fixturePaths("json"), Limits{MaxBytes: 1 << 30, MaxRecords: 3}) {
			if total(b) > 3 {
				t.Fatalf("batch of %d records", total(b))
			}
			sum += total(b)
		}
		if sum != total(all) {
			t.Fatalf("got %d records across batches, want %d", sum, total(all))
		}
	})
	t.Run("splits by size and stays under it", func(t *testing.T) {
		const maxBytes = 600
		batches := readBatches(t, fixturePaths("json"), Limits{MaxBytes: maxBytes, MaxRecords: 1 << 30})
		if len(batches) < 2 {
			t.Fatalf("got %d batches, want several", len(batches))
		}
		for _, b := range batches {
			if total(b) > 1 && proto.Size(b) > maxBytes {
				t.Fatalf("batch of %d bytes", proto.Size(b))
			}
		}
	})
	t.Run("fails a log in which no record can be read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "conn.log")
		if err := os.WriteFile(path, []byte("#separator \\x09\n#fields\tts\tuid\n1.0\tC1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := Read(LogPaths{Conn: path}, unlimited, func(Batch) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "none of its 3 record(s)") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("skips an unreadable record and keeps the rest", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "conn.log")
		content := "{\"ts\":1.0,\"uid\":\"C1\"}\nnot json\n{\"ts\":2.0,\"uid\":\"C2\",\"orig_bytes\":\"many\"}\n{\"ts\":3.0,\"uid\":\"C3\"}\n"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		batches := readBatches(t, LogPaths{Conn: path}, unlimited)
		if len(batches) != 1 || len(batches[0].Conn) != 2 {
			t.Fatalf("got %v", batches)
		}
		if batches[0].Conn[0].Uid != "C1" || batches[0].Conn[1].Uid != "C3" {
			t.Fatalf("kept %s and %s", batches[0].Conn[0].Uid, batches[0].Conn[1].Uid)
		}
	})
	t.Run("returns an emit error", func(t *testing.T) {
		want := errors.New("upload failed")
		if err := Read(fixturePaths("json"), unlimited, func(Batch) error { return want }); !errors.Is(err, want) {
			t.Fatalf("err = %v", err)
		}
	})
}

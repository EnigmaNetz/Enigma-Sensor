// Package records maps Zeek's JSON logs into the typed records of sensor_records.proto
// (B1CF-2107), the payload of the Publisher's uploadRecords method.
//
// The values must match what the Subscriber stores for the same traffic sent as tab-separated
// logs, so each value is converted the way Zeek writes it in that format and the Subscriber
// reads it back:
//
//   - An unset field (left out of the JSON) stays unset in the record.
//   - Doubles are rounded to six decimal places, which is all the tab-separated log carries.
//   - Control characters in text (a tab or newline in a DNS query, for example) are written as
//     \x09, \x0a and so on, as the tab-separated log escapes them; JSON carries them raw.
//   - Sets and vectors are joined with commas; an empty one becomes "". A comma inside an
//     element is written as \x2c, as the tab-separated log escapes it. Interval vectors (dns
//     TTLs) are written with six decimal places, as the tab-separated log writes them.
//   - orig_h, orig_p, resp_h and resp_p come only from the id.orig_h, id.orig_p, id.resp_h and
//     id.resp_p columns, the ones the excluded-subnet filter checks.
//
// A column with no field in the record is dropped, so a column a newer Zeek adds is ignored
// until it is added to the schema. A record that cannot be read is skipped and counted, not
// fatal: the excluded-subnet filter has already run, so failing the window would protect nothing
// and would drop every record once a newer Zeek writes a value this mapping does not expect. A
// log in which no record can be read is an error, though: that is a Zeek writing another format
// (tab-separated logs, for example), and uploading nothing would look like success.
// testdata holds one capture written in both formats, and the parity test requires both to give
// the same values.
package records

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"EnigmaNetz/Enigma-Go-Sensor/internal/api/ingest"
)

// SchemaVersion is the RecordBatch layout this package writes.
const SchemaVersion = 1

// MaxLineBytes bounds one JSON log line, here and in the processor's in-place log rewrites.
// Zeek's records are far smaller; the bound only stops a corrupt file from being read into
// memory as a single line.
const MaxLineBytes = 16 * 1024 * 1024

// intervalVectors names the vector-of-interval fields, which the tab-separated log writes with
// six decimal places ("300.000000") where JSON writes 300.0.
var intervalVectors = map[string]bool{"TTLs": true}

// idFields are the conn_id fields, which Zeek's JSON writes as id.orig_h and so on.
var idFields = map[string]bool{"orig_h": true, "orig_p": true, "resp_h": true, "resp_p": true}

// LogPaths holds the path of each JSON log. An empty path or a missing file contributes no
// records.
type LogPaths struct {
	Conn   string
	DNS    string
	DHCP   string
	JA3JA4 string
	JA4S   string
}

// Limits bound each batch Read emits.
type Limits struct {
	// MaxBytes is the most serialized (uncompressed) bytes in one batch.
	MaxBytes int
	// MaxRecords is the most records in one batch.
	MaxRecords int
}

// Batch is one upload's worth of records: a zlib-compressed, serialized RecordBatch and its
// per-type counts for the request envelope.
type Batch struct {
	Records []byte
	Counts  *ingest.RecordCounts
}

// Total returns the number of records in the batch.
func (b Batch) Total() int {
	c := b.Counts
	return int(c.GetConn() + c.GetDns() + c.GetDhcp() + c.GetJa3Ja4() + c.GetJa4S())
}

// Read streams the logs in paths, one line at a time, and calls emit with consecutive batches
// that each stay within limits. Each record is encoded and compressed as it is read, so memory
// holds one compressed batch, not the logs or the decoded records. Logs with no records emit
// nothing. An emit error stops reading and is returned.
func Read(paths LogPaths, limits Limits, emit func(Batch) error) error {
	if limits.MaxBytes <= 0 || limits.MaxRecords <= 0 {
		return errors.New("records: limits must be positive")
	}
	b := &batcher{limits: limits, emit: emit}
	defer b.discard()

	logs := []struct {
		path   string
		name   string
		field  protowire.Number
		newRec func() proto.Message
		count  func(*ingest.RecordCounts) *uint32
	}{
		{paths.Conn, "conn", 1, func() proto.Message { return &ingest.ConnRecord{} },
			func(c *ingest.RecordCounts) *uint32 { return &c.Conn }},
		{paths.DNS, "dns", 2, func() proto.Message { return &ingest.DnsRecord{} },
			func(c *ingest.RecordCounts) *uint32 { return &c.Dns }},
		{paths.DHCP, "dhcp", 3, func() proto.Message { return &ingest.DhcpRecord{} },
			func(c *ingest.RecordCounts) *uint32 { return &c.Dhcp }},
		{paths.JA3JA4, "ja3_ja4", 4, func() proto.Message { return &ingest.Ja3Ja4Record{} },
			func(c *ingest.RecordCounts) *uint32 { return &c.Ja3Ja4 }},
		{paths.JA4S, "ja4s", 5, func() proto.Message { return &ingest.Ja4SRecord{} },
			func(c *ingest.RecordCounts) *uint32 { return &c.Ja4S }},
	}
	for _, l := range logs {
		if err := readLog(l.path, l.name, l.newRec, func(m proto.Message) error {
			return b.add(l.field, m, l.count)
		}); err != nil {
			return fmt.Errorf("%s log: %w", l.name, err)
		}
	}
	return b.flush()
}

// readLog decodes each line of one JSON log into a fresh record and passes it to add. Records
// that cannot be decoded are skipped, and logged once with their count and the first error. If
// no record decodes at all, that is an error.
func readLog(path, name string, newRec func() proto.Message, add func(proto.Message) error) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxLineBytes)
	lineNo, skipped, decoded := 0, 0, 0
	var firstErr error
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		rec := newRec()
		if err := Decode(line, rec); err != nil {
			if skipped == 0 {
				firstErr = fmt.Errorf("line %d: %w", lineNo, err)
			}
			skipped++
			continue
		}
		decoded++
		if err := add(rec); err != nil {
			return err
		}
	}
	if skipped > 0 && decoded == 0 {
		return fmt.Errorf("none of its %d record(s) could be read; first: %w", skipped, firstErr)
	}
	if skipped > 0 {
		log.Printf("[records] Skipped %d unreadable record(s) in %s.log; first: %v", skipped, name, firstErr)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	return nil
}

// batcher writes records into a compressed RecordBatch and emits it whenever the next record
// would break a limit. A RecordBatch on the wire is its records, each as a field tag, a length
// and the encoded record, in any order, so records are appended as they arrive.
type batcher struct {
	limits Limits
	emit   func(Batch) error

	buf     *bytes.Buffer
	zw      *zlib.Writer
	counts  *ingest.RecordCounts
	bytes   int
	count   int
	scratch []byte
}

func (b *batcher) add(field protowire.Number, m proto.Message, count func(*ingest.RecordCounts) *uint32) error {
	encoded, err := proto.MarshalOptions{}.MarshalAppend(b.scratch[:0], m)
	if err != nil {
		return fmt.Errorf("encode record: %w", err)
	}
	b.scratch = encoded
	cost := protowire.SizeTag(field) + protowire.SizeBytes(len(encoded))
	if b.count > 0 && (b.bytes+cost > b.limits.MaxBytes || b.count+1 > b.limits.MaxRecords) {
		if err := b.flush(); err != nil {
			return err
		}
	}
	if b.zw == nil {
		b.buf = &bytes.Buffer{}
		b.zw = zlib.NewWriter(b.buf)
		b.counts = &ingest.RecordCounts{}
	}
	head := protowire.AppendTag(nil, field, protowire.BytesType)
	head = protowire.AppendVarint(head, uint64(len(encoded)))
	if _, err := b.zw.Write(head); err != nil {
		return fmt.Errorf("compress: %w", err)
	}
	if _, err := b.zw.Write(encoded); err != nil {
		return fmt.Errorf("compress: %w", err)
	}
	*count(b.counts)++
	b.bytes += cost
	b.count++
	return nil
}

// flush emits the current batch, if it has any records.
func (b *batcher) flush() error {
	if b.count == 0 {
		return nil
	}
	if err := b.zw.Close(); err != nil {
		return fmt.Errorf("compress: %w", err)
	}
	batch := Batch{Records: b.buf.Bytes(), Counts: b.counts}
	b.buf, b.zw, b.counts, b.bytes, b.count = nil, nil, nil, 0, 0
	return b.emit(batch)
}

// discard drops a batch left unfinished by an error.
func (b *batcher) discard() {
	if b.zw != nil {
		_ = b.zw.Close()
	}
	b.buf, b.zw = nil, nil
}

// Decode fills rec from one JSON log line. Columns with no field in rec are ignored.
func Decode(line []byte, rec proto.Message) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(line, &obj); err != nil {
		return fmt.Errorf("not a JSON log record: %w", err)
	}
	msg := rec.ProtoReflect()
	fields := msg.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		name := string(fd.Name())
		key := name
		if idFields[name] {
			key = "id." + name
		}
		raw, ok := obj[key]
		if !ok || string(raw) == "null" {
			continue
		}
		v, err := convert(fd, raw)
		if err != nil {
			return fmt.Errorf("field %s: %w", name, err)
		}
		msg.Set(fd, v)
	}
	return nil
}

func convert(fd protoreflect.FieldDescriptor, raw json.RawMessage) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.StringKind:
		s, err := toText(raw, intervalVectors[string(fd.Name())])
		return protoreflect.ValueOfString(s), err
	case protoreflect.DoubleKind:
		f, err := strconv.ParseFloat(string(raw), 64)
		if err != nil {
			return protoreflect.Value{}, err
		}
		return protoreflect.ValueOfFloat64(round6(f)), nil
	case protoreflect.Uint32Kind:
		n, err := toUint(raw, 32)
		return protoreflect.ValueOfUint32(uint32(n)), err
	case protoreflect.Uint64Kind:
		n, err := toUint(raw, 64)
		return protoreflect.ValueOfUint64(n), err
	case protoreflect.BoolKind:
		var b bool
		err := json.Unmarshal(raw, &b)
		return protoreflect.ValueOfBool(b), err
	default:
		return protoreflect.Value{}, fmt.Errorf("unsupported field kind %s", fd.Kind())
	}
}

// escapeControl writes control characters as \xNN, as Zeek's tab-separated log does.
func escapeControl(s string) string {
	if !strings.ContainsFunc(s, isControl) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if isControl(r) {
			fmt.Fprintf(&b, `\x%02x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// round6 rounds to the six decimal places the tab-separated log writes, so the value equals what
// the Subscriber parses from that text.
func round6(f float64) float64 {
	r, _ := strconv.ParseFloat(strconv.FormatFloat(f, 'f', 6, 64), 64)
	return r
}

func toUint(raw json.RawMessage, bits int) (uint64, error) {
	n, err := strconv.ParseUint(string(raw), 10, bits)
	if err == nil {
		return n, nil
	}
	// Zeek writes counts as integers; accept an integral float in case a writer does not.
	f, ferr := strconv.ParseFloat(string(raw), 64)
	if ferr != nil || f < 0 || f != float64(uint64(f)) {
		return 0, err
	}
	return uint64(f), nil
}

// toText renders a JSON value as the text the tab-separated log carries for it.
func toText(raw json.RawMessage, intervals bool) (string, error) {
	switch raw[0] {
	case '"':
		var s string
		err := json.Unmarshal(raw, &s)
		return escapeControl(s), err
	case '[':
		var elems []json.RawMessage
		if err := json.Unmarshal(raw, &elems); err != nil {
			return "", err
		}
		parts := make([]string, len(elems))
		for i, e := range elems {
			if intervals {
				f, err := strconv.ParseFloat(string(e), 64)
				if err != nil {
					return "", err
				}
				parts[i] = strconv.FormatFloat(f, 'f', 6, 64)
				continue
			}
			s, err := toText(e, false)
			if err != nil {
				return "", err
			}
			parts[i] = strings.ReplaceAll(s, ",", `\x2c`)
		}
		return strings.Join(parts, ","), nil
	case 't':
		return "T", nil
	case 'f':
		return "F", nil
	default:
		// A number where the schema has a string: keep Zeek's text for it.
		return string(raw), nil
	}
}

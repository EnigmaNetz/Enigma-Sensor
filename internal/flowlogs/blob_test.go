package flowlogs

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"EnigmaNetz/Enigma-Go-Sensor/internal/api/ingest"
	"EnigmaNetz/Enigma-Go-Sensor/internal/records"
)

// readSample returns the sample record from Microsoft's VNet flow log documentation, with its
// two real public source addresses replaced by documentation addresses (RFC 5737).
func readSample(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "microsoft-sample.json"))
	require.NoError(t, err)
	return data
}

// convertBlob scans a whole blob and converts it, returning the conn.log lines and what the
// converter dropped.
func convertBlob(t *testing.T, data []byte) ([]ConnRecord, Stats) {
	t.Helper()
	recs, next, err := scanRecords("sample", data, 0)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(strings.TrimSpace(string(data[next:])), "]"),
		"the offset stops just after the last record, before the closing ]}")
	var out []ConnRecord
	conv := NewConverter(Options{}, NewConverterState(), func(r ConnRecord) { out = append(out, r) })
	for _, r := range recs {
		ok, err := parseRecord(r.data, r.pos, conv.Add)
		require.NoError(t, err)
		require.True(t, ok)
	}
	conv.Flush(nil)
	return out, conv.Stats
}

func TestMicrosoftSample(t *testing.T) {
	out, stats := convertBlob(t, readSample(t))
	states := map[string]int{}
	for _, r := range out {
		states[r.ConnState]++
	}
	// Five begin and end pairs, all answered. The nine denied inbound attempts come from
	// outside the network, so they are dropped and counted
	require.Equal(t, map[string]int{"SF": 5}, states)
	require.Equal(t, 9, stats.Denied)
	var last ConnRecord
	for _, r := range out {
		if r.OrigP == 36776 {
			last = r
		}
	}
	require.Equal(t, "198.51.100.84", last.RespH)
	require.Equal(t, uint64(22), last.OrigPkts)
	require.Equal(t, uint64(32466), last.RespIPBytes)
	require.InDelta(t, 5.45, last.Duration, 0.0001)
	require.Equal(t, 1663146017.343, last.TS)
}

// The converter's conn.log must go through the sensor's own record mapper, the one UploadLogs
// uses, without a single record skipped.
func TestOutputMapsToTypedRecords(t *testing.T) {
	out, _ := convertBlob(t, readSample(t))
	// An S0 too, which has no history; the sample's denied attempts come from outside and are dropped
	h := newHarness(t, Options{})
	h.add(macA, at(0, "10.0.3.7,"+vmA+",55188,22,6,I,D,NX,0,0,0,0"))
	require.Len(t, h.recs, 1)
	out = append(out, h.recs...)
	path := filepath.Join(t.TempDir(), "conn.log")
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range out {
		require.NoError(t, enc.Encode(r))
	}
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))

	for i, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var rec ingest.ConnRecord
		require.NoError(t, records.Decode(line, &rec), "line %d", i+1)
		require.NotEmpty(t, rec.Uid)
		require.NotEmpty(t, rec.OrigH)
		require.Equal(t, "tcp", rec.Proto)
		require.NotNil(t, rec.IpProto)
	}
	total := 0
	err := records.Read(records.LogPaths{Conn: path}, records.Limits{MaxBytes: 1 << 20, MaxRecords: 1000},
		func(b records.Batch) error {
			total += int(b.Counts.GetConn())
			return nil
		})
	require.NoError(t, err)
	require.Equal(t, len(out), total)
}

func TestScanRecordsIncrementally(t *testing.T) {
	header := `{"records":[`
	rec1 := `{"flowLogVersion":4,"macAddress":"AA","flowRecords":{"flows":[]}}`
	rec2 := `{"flowLogVersion":4,"macAddress":"BB","flowRecords":{"flows":[]}}`

	// A blob part way through its first record
	blob := header + "\n" + rec1[:20]
	recs, next, err := scanRecords("b", []byte(blob), 0)
	require.NoError(t, err)
	require.Empty(t, recs)
	require.Equal(t, int64(len(header)), next, "the header is consumed, the partial record is not")

	// The record completes and the array is closed
	blob = header + "\n" + rec1 + "]}"
	recs, next, err = scanRecords("b", []byte(blob[next:]), next)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	require.Equal(t, rec1, string(recs[0].data))
	require.Equal(t, int64(len(header)+1+len(rec1)), next)

	// Azure adds the next record before the closing ]}
	blob = header + "\n" + rec1 + "," + rec2 + "]}"
	recs, next2, err := scanRecords("b", []byte(blob[next:]), next)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	require.Equal(t, rec2, string(recs[0].data))
	require.Equal(t, "b@"+itoa(next+1), recs[0].pos, "the position is the record's byte in the blob")
	require.Equal(t, int64(len(blob)-2), next2)

	// Nothing new
	recs, next3, err := scanRecords("b", []byte(blob[next2:]), next2)
	require.NoError(t, err)
	require.Empty(t, recs)
	require.Equal(t, next2, next3)
}

func TestScanRecordsErrors(t *testing.T) {
	_, _, err := scanRecords("b", []byte(`{"value":[`), 0)
	require.Error(t, err, "not a flow log blob")

	_, next, err := scanRecords("b", []byte(`{"rec`), 0)
	require.NoError(t, err, "a header still being written is not an error")
	require.Zero(t, next)

	recs, next, err := scanRecords("b", []byte(`{"records":[{"a":1},{"a":}]}`), 0)
	require.Error(t, err)
	require.Len(t, recs, 1, "the records before the bad one are kept")
	require.Equal(t, int64(len(`{"records":[{"a":1}`)), next)

	_, _, err = scanRecords("b", []byte(`, 42]`), 100)
	require.Error(t, err)
}

func TestParseRecordSkipsOtherVersions(t *testing.T) {
	ok, err := parseRecord([]byte(`{"flowLogVersion":2,"flowRecords":{"flows":[{"flowGroups":[{"flowTuples":["x"]}]}]}}`), "p", func(Tuple) {
		t.Fatal("no tuple of another version is converted")
	})
	require.NoError(t, err)
	require.False(t, ok)

	_, err = parseRecord([]byte(`{"flowLogVersion":4,"flowRecords":{"flows":[{"flowGroups":[{"flowTuples":["1,2,3"]}]}]}}`), "p", func(Tuple) {})
	require.Error(t, err)
}

func TestParseTupleRejectsBadFields(t *testing.T) {
	good := "1663146003606,10.0.0.6,192.0.2.180,23956,443,6,O,E,NX,3,767,2,1580"
	_, err := parseTuple(good)
	require.NoError(t, err)
	for i, bad := range []string{"x", "1663146003606,10.0.0.6,192.0.2.180,23956,443,6,X,E,NX,3,767,2,1580",
		"1663146003606,10.0.0.6,192.0.2.180,23956,443,6,O,Q,NX,3,767,2,1580",
		"1663146003606,10.0.0.6,192.0.2.180,99999,443,6,O,E,NX,3,767,2,1580",
		"1663146003606,10.0.0.6,not-an-ip,23956,443,6,O,E,NX,3,767,2,1580",
		"1663146003606,10.0.0.6,192.0.2.180,23956,443,6,O,E,NX,-3,767,2,1580"} {
		_, err := parseTuple(bad)
		require.Error(t, err, "case %d", i)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

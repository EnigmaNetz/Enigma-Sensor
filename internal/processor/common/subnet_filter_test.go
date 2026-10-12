package types

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeLog writes JSON log records, one per line with a trailing newline, as Zeek does with
// LogAscii::use_json=T.
func writeLog(t *testing.T, runDir, name string, records ...string) string {
	t.Helper()
	p := filepath.Join(runDir, name)
	if err := os.WriteFile(p, []byte(strings.Join(records, "\n")+"\n"), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// readUIDs returns the uid (or the joined uids) of each record in a JSON log, in order.
func readUIDs(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			UID  string   `json:"uid"`
			UIDs []string `json:"uids"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("record %q: %v", line, err)
		}
		if rec.UID != "" {
			out = append(out, rec.UID)
		} else {
			out = append(out, strings.Join(rec.UIDs, ","))
		}
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFilterExcludedSubnets_ConnDropsBySrcOrDst(t *testing.T) {
	dir := t.TempDir()
	path := writeLog(t, dir, "conn.log",
		`{"ts":1.0,"uid":"CA","id.orig_h":"10.1.2.3","id.resp_h":"8.8.8.8"}`,
		`{"ts":2.0,"uid":"CB","id.orig_h":"192.168.1.5","id.resp_h":"10.9.9.9"}`,
		`{"ts":3.0,"uid":"CC","id.orig_h":"192.168.1.5","id.resp_h":"8.8.8.8"}`,
	)
	if err := FilterExcludedSubnets(dir, []string{"conn.log"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("FilterExcludedSubnets: %v", err)
	}
	if got := readUIDs(t, path); !equal(got, []string{"CC"}) {
		t.Fatalf("kept %v, want [CC]", got)
	}
}

func TestFilterExcludedSubnets_DHCPAddressFields(t *testing.T) {
	dir := t.TempDir()
	path := writeLog(t, dir, "dhcp.log",
		`{"ts":1.0,"uids":["D1"],"client_addr":"192.168.1.20","server_addr":"192.168.1.1"}`,
		`{"ts":2.0,"uids":["D2"],"client_addr":"192.168.1.21","assigned_addr":"10.0.0.21"}`,
		`{"ts":3.0,"uids":["D3"],"requested_addr":"10.0.0.22"}`,
		`{"ts":4.0,"uids":["D4"],"server_addr":"10.0.0.1"}`,
	)
	if err := FilterExcludedSubnets(dir, []string{"dhcp.log"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("FilterExcludedSubnets: %v", err)
	}
	if got := readUIDs(t, path); !equal(got, []string{"D1"}) {
		t.Fatalf("kept %v, want [D1]", got)
	}
}

func TestFilterExcludedSubnets_FeatureOffLeavesFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := writeLog(t, dir, "conn.log", `{"ts":1.0,"uid":"CA","id.orig_h":"10.1.2.3","id.resp_h":"8.8.8.8"}`)
	before, _ := os.ReadFile(path)
	for _, cidrs := range [][]string{nil, {}, {"", "  "}} {
		if err := FilterExcludedSubnets(dir, []string{"conn.log"}, cidrs); err != nil {
			t.Fatalf("FilterExcludedSubnets(%q): %v", cidrs, err)
		}
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("file changed with filtering off")
	}
}

func TestFilterExcludedSubnets_NothingDroppedLeavesFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := writeLog(t, dir, "conn.log", `{"ts":1.0,"uid":"CA","id.orig_h":"192.168.1.5","id.resp_h":"8.8.8.8"}`)
	before, _ := os.ReadFile(path)
	if err := FilterExcludedSubnets(dir, []string{"conn.log"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("file changed although no record was dropped")
	}
	if _, err := os.Stat(path + ".rewrite"); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}
}

// dhcp.log has no conn_id, so a lease record with only some address fields is checked on those.
func TestFilterExcludedSubnets_DHCPNeedsNoConnID(t *testing.T) {
	dir := t.TempDir()
	path := writeLog(t, dir, "dhcp.log", `{"ts":1.0,"uids":["D1"],"mac":"aa:bb:cc:dd:ee:ff"}`)
	if err := FilterExcludedSubnets(dir, []string{"dhcp.log"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if got := readUIDs(t, path); !equal(got, []string{"D1"}) {
		t.Fatalf("kept %v, want [D1]", got)
	}
}

func TestFilterExcludedSubnets_MissingFileIsNoOp(t *testing.T) {
	if err := FilterExcludedSubnets(t.TempDir(), []string{"ja3_ja4.log"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("missing file should be a no-op, got %v", err)
	}
}

func TestFilterExcludedSubnets_DNSAnswers(t *testing.T) {
	dir := t.TempDir()
	path := writeLog(t, dir, "dns.log",
		`{"ts":1.0,"uid":"N1","id.orig_h":"192.168.1.5","id.resp_h":"8.8.8.8","answers":["host.example","10.2.3.4"]}`,
		`{"ts":2.0,"uid":"N2","id.orig_h":"192.168.1.5","id.resp_h":"8.8.8.8","answers":["93.184.216.34"]}`,
		`{"ts":3.0,"uid":"N3","id.orig_h":"192.168.1.5","id.resp_h":"8.8.8.8","answers":[]}`,
		`{"ts":4.0,"uid":"N4","id.orig_h":"192.168.1.5","id.resp_h":"8.8.8.8"}`,
	)
	if err := FilterExcludedSubnets(dir, []string{"dns.log"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("FilterExcludedSubnets: %v", err)
	}
	if got := readUIDs(t, path); !equal(got, []string{"N2", "N3", "N4"}) {
		t.Fatalf("kept %v, want [N2 N3 N4]", got)
	}
}

func TestFilterExcludedSubnets_IPv6(t *testing.T) {
	dir := t.TempDir()
	path := writeLog(t, dir, "conn.log",
		`{"ts":1.0,"uid":"V1","id.orig_h":"fd00::5","id.resp_h":"2001:db8::1"}`,
		`{"ts":2.0,"uid":"V2","id.orig_h":"fe80::1","id.resp_h":"2001:db8::1"}`,
	)
	if err := FilterExcludedSubnets(dir, []string{"conn.log"}, []string{"fd00::/8"}); err != nil {
		t.Fatalf("FilterExcludedSubnets: %v", err)
	}
	if got := readUIDs(t, path); !equal(got, []string{"V2"}) {
		t.Fatalf("kept %v, want [V2]", got)
	}
}

// When a present log cannot be read, filtering must return an error so the caller aborts the
// window rather than uploading unfiltered data. A directory in place of the log forces a read
// error independent of the test user's privileges.
func TestFilterExcludedSubnets_ReadErrorAborts(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "conn.log"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := FilterExcludedSubnets(dir, []string{"conn.log"}, []string{"10.0.0.0/8"}); err == nil {
		t.Fatal("expected an error when a log cannot be read (fail-closed), got nil")
	}
}

// A line the filter cannot read as a JSON record could hide an excluded address, so it stops the
// upload and leaves the log as it was. A tab-separated log (Zeek not writing JSON) is refused the
// same way.
func TestFilterExcludedSubnets_UnreadableRecordAborts(t *testing.T) {
	for name, line := range map[string]string{
		"not JSON":        "1.0\tCA\t10.1.2.3\t8.8.8.8",
		"truncated":       `{"ts":1.0,"uid":"CB","id.orig_h":"10.1.`,
		"address not str": `{"ts":1.0,"uid":"CC","id.orig_h":42}`,
		"no conn_id":      `{"ts":1.0,"uid":"CD","orig_h":"10.1.2.3"}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeLog(t, dir, "conn.log", `{"ts":0.5,"uid":"C0","id.orig_h":"10.0.0.1","id.resp_h":"8.8.8.8"}`, line)
			before, _ := os.ReadFile(path)
			err := FilterExcludedSubnets(dir, []string{"conn.log"}, []string{"10.0.0.0/8"})
			if err == nil || !strings.Contains(err.Error(), "line 2") {
				t.Fatalf("err = %v, want a line 2 error", err)
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("log changed although filtering failed")
			}
		})
	}
}

func TestFilterExcludedSubnets_MultipleCIDRsAndTLSLog(t *testing.T) {
	dir := t.TempDir()
	path := writeLog(t, dir, "ja3_ja4.log",
		`{"ts":1.0,"uid":"JA","id.orig_h":"172.20.10.5","id.resp_h":"1.1.1.1","ja3":"abc"}`,
		`{"ts":2.0,"uid":"JB","id.orig_h":"203.0.113.7","id.resp_h":"1.1.1.1","ja3":"abc"}`,
	)
	if err := FilterExcludedSubnets(dir, []string{"ja3_ja4.log"}, []string{"10.0.0.0/8", "172.20.10.0/24"}); err != nil {
		t.Fatalf("FilterExcludedSubnets: %v", err)
	}
	if got := readUIDs(t, path); !equal(got, []string{"JB"}) {
		t.Fatalf("kept %v, want [JB]", got)
	}
}

// The real Zeek output in the records package's fixtures: excluding the web server's subnet
// drops its connections, the DNS answers that resolve to it and the TLS fingerprints, and keeps
// everything else.
func TestFilterExcludedSubnets_ZeekFixture(t *testing.T) {
	src := filepath.Join("..", "..", "records", "testdata", "json")
	dir := t.TempDir()
	for _, name := range ZeekLogFiles {
		copyFile(t, filepath.Join(src, name), filepath.Join(dir, name))
	}
	if err := FilterExcludedSubnets(dir, ZeekLogFiles, []string{"203.0.113.0/24"}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]int{"conn.log": 13, "dns.log": 4, "dhcp.log": 1, "ja3_ja4.log": 0, "ja4s.log": 0} {
		if got := len(readUIDs(t, filepath.Join(dir, name))); got != want {
			t.Errorf("%s kept %d records, want %d", name, got, want)
		}
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	in, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
}

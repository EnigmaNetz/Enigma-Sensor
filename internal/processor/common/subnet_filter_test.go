package types

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// zeekHeader builds the standard Zeek TSV header for a log with the given path
// name and #fields columns. The #separator line uses the literal "\x09" escape
// exactly as Zeek writes it, so the filter's separator decoding is exercised.
func zeekHeader(path string, fields ...string) []string {
	return []string{
		`#separator \x09`,
		"#set_separator\t,",
		"#empty_field\t(empty)",
		"#unset_field\t-",
		"#path\t" + path,
		"#open\t2024-01-01-00-00-00",
		"#fields\t" + strings.Join(fields, "\t"),
		"#types\t" + strings.Repeat("string\t", len(fields)-1) + "string",
	}
}

// writeLog joins header + data rows + a #close footer with a trailing newline
// (matching real Zeek output) and writes it to runDir/name.
func writeLog(t *testing.T, runDir, name string, header []string, rows ...string) string {
	t.Helper()
	lines := append([]string{}, header...)
	lines = append(lines, rows...)
	lines = append(lines, "#close\t2024-01-01-00-01-00", "")
	p := filepath.Join(runDir, name)
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func row(cols ...string) string { return strings.Join(cols, "\t") }

// readDataRows returns the non-comment, non-empty rows of a log file.
func readDataRows(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func TestFilterExcludedSubnets_ConnDropsBySrcOrDst(t *testing.T) {
	dir := t.TempDir()
	hdr := zeekHeader("conn", "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto")
	path := writeLog(t, dir, "conn.log", hdr,
		row("1", "CA", "10.1.2.3", "1234", "8.8.8.8", "53", "udp"),      // orig in 10/8 -> drop
		row("2", "CB", "192.168.1.5", "5555", "10.5.5.5", "443", "tcp"), // resp in 10/8 -> drop
		row("3", "CC", "192.168.1.5", "5555", "8.8.8.8", "443", "tcp"),  // neither -> keep
	)

	if err := FilterExcludedSubnets(dir, []string{"conn.log"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("FilterExcludedSubnets: %v", err)
	}

	rows := readDataRows(t, path)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row kept, got %d: %v", len(rows), rows)
	}
	if !strings.Contains(rows[0], "CC") {
		t.Errorf("expected only row CC kept, got %q", rows[0])
	}
}

func TestFilterExcludedSubnets_DHCPAddressColumns(t *testing.T) {
	dir := t.TempDir()
	// DHCP log with the dhcp-specific address columns and no id.orig_h/resp_h.
	hdr := zeekHeader("dhcp", "ts", "uid", "mac", "client_addr", "server_addr", "requested_addr", "assigned_addr", "lease_time")
	path := writeLog(t, dir, "dhcp.log", hdr,
		// assigned_addr in 10/8 -> drop (client_addr unset)
		row("1", "DA", "aa:bb:cc:dd:ee:01", "-", "192.168.1.1", "-", "10.0.0.50", "3600"),
		// all address fields unset or out-of-range -> keep (unset markers skipped)
		row("2", "DB", "aa:bb:cc:dd:ee:02", "-", "192.168.1.1", "(empty)", "-", "3600"),
		// requested_addr in 10/8 -> drop
		row("3", "DC", "aa:bb:cc:dd:ee:03", "192.168.1.9", "192.168.1.1", "10.9.9.9", "-", "3600"),
	)

	if err := FilterExcludedSubnets(dir, []string{"dhcp.log"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("FilterExcludedSubnets: %v", err)
	}

	rows := readDataRows(t, path)
	if len(rows) != 1 || !strings.Contains(rows[0], "DB") {
		t.Fatalf("expected only row DB kept, got %v", rows)
	}
}

func TestFilterExcludedSubnets_PreservesHeadersAndFooter(t *testing.T) {
	dir := t.TempDir()
	hdr := zeekHeader("conn", "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto")
	path := writeLog(t, dir, "conn.log", hdr,
		row("1", "CA", "10.1.2.3", "1234", "8.8.8.8", "53", "udp"), // dropped
	)
	before, _ := os.ReadFile(path)

	if err := FilterExcludedSubnets(dir, []string{"conn.log"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("FilterExcludedSubnets: %v", err)
	}

	after, _ := os.ReadFile(path)
	afterStr := string(after)
	// Every header/footer line must survive verbatim.
	for _, want := range append(hdr, "#close\t2024-01-01-00-01-00") {
		if !strings.Contains(afterStr, want) {
			t.Errorf("header/footer line missing after filter: %q", want)
		}
	}
	// Trailing newline preserved.
	if !strings.HasSuffix(afterStr, "\n") {
		t.Errorf("trailing newline not preserved")
	}
	// The data row must be gone.
	if strings.Contains(afterStr, "\tCA\t") {
		t.Errorf("dropped row still present")
	}
	if len(after) >= len(before) {
		t.Errorf("expected file to shrink after dropping a row")
	}
}

func TestFilterExcludedSubnets_FeatureOffLeavesFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	hdr := zeekHeader("conn", "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto")
	path := writeLog(t, dir, "conn.log", hdr,
		row("1", "CA", "10.1.2.3", "1234", "8.8.8.8", "53", "udp"),
	)
	before, _ := os.ReadFile(path)

	// Empty CIDR list = feature off: no rows should be dropped.
	if err := FilterExcludedSubnets(dir, []string{"conn.log"}, nil); err != nil {
		t.Fatalf("FilterExcludedSubnets: %v", err)
	}

	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Errorf("file changed with feature off")
	}
}

func TestFilterExcludedSubnets_MissingFileIsNoOp(t *testing.T) {
	dir := t.TempDir()
	// ja3_ja4.log / ja4s.log frequently absent (e.g. on Linux). Must not error.
	if err := FilterExcludedSubnets(dir, []string{"ja3_ja4.log", "ja4s.log"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("expected no-op for missing files, got %v", err)
	}
}

func TestFilterExcludedSubnets_DNSAnswers(t *testing.T) {
	dir := t.TempDir()
	// Client and resolver are NOT in the excluded range; only an answer is.
	// This is the leak the answers coverage closes.
	hdr := zeekHeader("dns", "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "query", "qtype_name", "answers")
	path := writeLog(t, dir, "dns.log", hdr,
		// answers set contains an excluded IP among a public one -> drop
		row("1", "DNSA", "192.168.1.10", "5300", "192.168.1.1", "53", "udp", "db.corp", "A", "93.184.216.34,10.50.1.5"),
		// answers has a CNAME hostname + an out-of-range IP -> keep
		row("2", "DNSB", "192.168.1.10", "5300", "192.168.1.1", "53", "udp", "www.example.com", "A", "cname.example.com,93.184.216.34"),
		// answers unset -> keep
		row("3", "DNSC", "192.168.1.10", "5300", "192.168.1.1", "53", "udp", "x.corp", "A", "-"),
	)

	if err := FilterExcludedSubnets(dir, []string{"dns.log"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("FilterExcludedSubnets: %v", err)
	}

	rows := readDataRows(t, path)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows kept (DNSB, DNSC), got %d: %v", len(rows), rows)
	}
	for _, r := range rows {
		if strings.Contains(r, "DNSA") {
			t.Errorf("DNSA should have been dropped (answer 10.50.1.5 in excluded subnet): %q", r)
		}
	}
}

func TestFilterExcludedSubnets_DNSAnswersCustomSetSeparator(t *testing.T) {
	dir := t.TempDir()
	// A log declaring a non-comma #set_separator must still split answers correctly.
	hdr := []string{
		`#separator \x09`,
		"#set_separator\t;",
		"#empty_field\t(empty)",
		"#unset_field\t-",
		"#path\tdns",
		"#open\t2024-01-01-00-00-00",
		"#fields\tts\tuid\tid.orig_h\tid.resp_h\tanswers",
		"#types\ttime\tstring\taddr\taddr\tset[string]",
	}
	path := writeLog(t, dir, "dns.log", hdr,
		row("1", "S1", "192.168.1.10", "192.168.1.1", "8.8.8.8;10.0.0.9"), // second answer excluded -> drop
		row("2", "S2", "192.168.1.10", "192.168.1.1", "8.8.8.8;1.1.1.1"),  // both public -> keep
	)

	if err := FilterExcludedSubnets(dir, []string{"dns.log"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("FilterExcludedSubnets: %v", err)
	}

	rows := readDataRows(t, path)
	if len(rows) != 1 || !strings.Contains(rows[0], "S2") {
		t.Fatalf("expected only row S2 kept, got %v", rows)
	}
}

func TestFilterExcludedSubnets_IPv6(t *testing.T) {
	dir := t.TempDir()
	hdr := zeekHeader("conn", "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto")
	path := writeLog(t, dir, "conn.log", hdr,
		row("1", "V6A", "fd00::1", "1234", "2001:4860:4860::8888", "53", "udp"),      // orig in fd00::/8 -> drop
		row("2", "V6B", "2606:4700::1", "1234", "2001:4860:4860::8888", "53", "udp"), // out of range -> keep
	)

	if err := FilterExcludedSubnets(dir, []string{"conn.log"}, []string{"fd00::/8"}); err != nil {
		t.Fatalf("FilterExcludedSubnets: %v", err)
	}

	rows := readDataRows(t, path)
	if len(rows) != 1 || !strings.Contains(rows[0], "V6B") {
		t.Fatalf("expected only row V6B kept, got %v", rows)
	}
}

// TestFilterExcludedSubnets_ReadErrorAborts pins the fail-closed contract: if a
// present log cannot be read/parsed, filtering must return an error so the
// caller aborts the window rather than uploading unfiltered data. Using a
// directory in place of the log forces a non-NotExist read error deterministically,
// independent of the test user's privileges.
func TestFilterExcludedSubnets_ReadErrorAborts(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "conn.log"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := FilterExcludedSubnets(dir, []string{"conn.log"}, []string{"10.0.0.0/8"}); err == nil {
		t.Fatal("expected an error when a log cannot be read (fail-closed), got nil")
	}
}

func TestFilterExcludedSubnets_MultipleCIDRsAndTLSLog(t *testing.T) {
	dir := t.TempDir()
	hdr := zeekHeader("ja3_ja4", "ts", "uid", "id.orig_h", "id.resp_h", "ja3", "ja4")
	path := writeLog(t, dir, "ja3_ja4.log", hdr,
		row("1", "JA", "172.20.10.5", "1.1.1.1", "abc", "def"), // orig in 172.20.10.0/24 -> drop
		row("2", "JB", "203.0.113.7", "1.1.1.1", "abc", "def"), // out of range -> keep
	)

	if err := FilterExcludedSubnets(dir, []string{"ja3_ja4.log"}, []string{"10.0.0.0/8", "172.20.10.0/24"}); err != nil {
		t.Fatalf("FilterExcludedSubnets: %v", err)
	}

	rows := readDataRows(t, path)
	if len(rows) != 1 || !strings.Contains(rows[0], "JB") {
		t.Fatalf("expected only row JB kept, got %v", rows)
	}
}

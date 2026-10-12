package types

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleDHCPLog = `{"ts":1746000000.0,"uids":["Cabc123"],"client_addr":"192.168.1.10","server_addr":"192.168.1.1","mac":"aa:bb:cc:dd:ee:ff","host_name":"mylaptop","lease_time":86400.0}
{"ts":1746000010.0,"uids":["Cdef456"],"client_addr":"192.168.1.20","server_addr":"192.168.1.1","mac":"11:22:33:44:55:66","host_name":"phone","lease_time":86400.0}
`

func writeDHCPLog(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dhcp.log")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// paramReqLists returns each record's param_req_list ("" when unset), in order.
func paramReqLists(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var rec struct {
			ParamReqList string `json:"param_req_list"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("record %q: %v", line, err)
		}
		out = append(out, rec.ParamReqList)
	}
	return out
}

func TestPatchDHCPLog_FillsFingerprints(t *testing.T) {
	path := writeDHCPLog(t, sampleDHCPLog)
	fingerprints := map[string]string{
		"aa:bb:cc:dd:ee:ff": "1,3,6,15,119,252",
		"11:22:33:44:55:66": "1,3,6,15,28,43",
	}
	if err := PatchDHCPLog(path, fingerprints); err != nil {
		t.Fatalf("PatchDHCPLog error: %v", err)
	}
	got := paramReqLists(t, path)
	if len(got) != 2 || got[0] != "1,3,6,15,119,252" || got[1] != "1,3,6,15,28,43" {
		t.Fatalf("param_req_list = %v", got)
	}
}

func TestPatchDHCPLog_KeepsOtherFields(t *testing.T) {
	path := writeDHCPLog(t, sampleDHCPLog)
	if err := PatchDHCPLog(path, map[string]string{"aa:bb:cc:dd:ee:ff": "1,3,6"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	first := strings.SplitN(string(data), "\n", 2)[0]
	for _, want := range []string{`"ts":1746000000.0`, `"uids":["Cabc123"]`, `"host_name":"mylaptop"`, `"lease_time":86400.0`} {
		if !strings.Contains(first, want) {
			t.Errorf("patched record lost %s: %s", want, first)
		}
	}
}

func TestPatchDHCPLog_Idempotent(t *testing.T) {
	path := writeDHCPLog(t, strings.Replace(sampleDHCPLog, `"host_name":"mylaptop"`, `"host_name":"mylaptop","param_req_list":"1,3,6,15"`, 1))
	if err := PatchDHCPLog(path, map[string]string{"aa:bb:cc:dd:ee:ff": "9,9,9,9"}); err != nil {
		t.Fatalf("PatchDHCPLog error: %v", err)
	}
	if got := paramReqLists(t, path); got[0] != "1,3,6,15" {
		t.Errorf("overwrote an already-set param_req_list: %v", got)
	}
}

func TestPatchDHCPLog_NoMatchLeavesFileUnchanged(t *testing.T) {
	path := writeDHCPLog(t, sampleDHCPLog)
	if err := PatchDHCPLog(path, map[string]string{"00:00:00:00:00:01": "1,3,6"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != sampleDHCPLog {
		t.Error("file changed although no record matched")
	}
	if _, err := os.Stat(path + ".rewrite"); !os.IsNotExist(err) {
		t.Error("temporary file left behind")
	}
}

func TestPatchDHCPLog_CopiesUnreadableLines(t *testing.T) {
	path := writeDHCPLog(t, "not a record\n"+sampleDHCPLog)
	if err := PatchDHCPLog(path, map[string]string{"aa:bb:cc:dd:ee:ff": "1,3,6"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), "not a record\n") {
		t.Error("unreadable line was not copied unchanged")
	}
}

func TestPatchDHCPLog_MissingFile(t *testing.T) {
	err := PatchDHCPLog("/nonexistent/dhcp.log", map[string]string{"aa:bb:cc:dd:ee:ff": "1,3,6"})
	if err != nil {
		t.Errorf("expected nil for missing file, got: %v", err)
	}
}

func TestExtractDHCPFingerprints_MissingFile(t *testing.T) {
	result, err := ExtractDHCPFingerprints("/nonexistent/capture.pcapng")
	if err == nil {
		t.Error("expected error for missing file")
	}
	if result != nil {
		t.Error("expected nil result for missing file")
	}
}

// End to end on the records package's fixtures: option 55 read from the synthetic capture lands
// in the dhcp.log Zeek wrote from it.
func TestEnrichDHCPLog_ZeekFixture(t *testing.T) {
	testdata := filepath.Join("..", "..", "records", "testdata")
	path := filepath.Join(t.TempDir(), "dhcp.log")
	copyFile(t, filepath.Join(testdata, "json", "dhcp.log"), path)

	if err := EnrichDHCPLog(filepath.Join(testdata, "synthetic.pcap"), path); err != nil {
		t.Fatal(err)
	}
	if got := paramReqLists(t, path); len(got) != 1 || got[0] != "1,3,6,15,31,33,43,44,46,47,119,121,249,252" {
		t.Fatalf("param_req_list = %v", got)
	}
}

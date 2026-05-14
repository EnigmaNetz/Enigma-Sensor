package types

import (
	"os"
	"strings"
	"testing"
)

const sampleDHCPLog = "#separator \\x09\n" +
	"#set_separator\t,\n" +
	"#empty_field\t(empty)\n" +
	"#unset_field\t-\n" +
	"#path\tdhcp\n" +
	"#fields\tts\tuids\tclient_addr\tserver_addr\tmac\thost_name\tparam_req_list\tlease_time\n" +
	"#types\ttime\tset[string]\taddr\taddr\tstring\tstring\tstring\tinterval\n" +
	"1746000000.0\tCabc123\t192.168.1.10\t192.168.1.1\taa:bb:cc:dd:ee:ff\tmylaptop\t-\t86400.0\n" +
	"1746000010.0\tCdef456\t192.168.1.20\t192.168.1.1\t11:22:33:44:55:66\tphone\t-\t86400.0\n"

func TestPatchDHCPLog_FillsFingerprints(t *testing.T) {
	f, err := os.CreateTemp("", "dhcp-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(sampleDHCPLog)
	f.Close()

	fingerprints := map[string]string{
		"aa:bb:cc:dd:ee:ff": "1,3,6,15,119,252",
		"11:22:33:44:55:66": "1,3,6,15,28,43",
	}

	if err := PatchDHCPLog(f.Name(), fingerprints); err != nil {
		t.Fatalf("PatchDHCPLog error: %v", err)
	}

	content, _ := os.ReadFile(f.Name())
	if !strings.Contains(string(content), "1,3,6,15,119,252") {
		t.Error("expected first fingerprint in patched log")
	}
	if !strings.Contains(string(content), "1,3,6,15,28,43") {
		t.Error("expected second fingerprint in patched log")
	}
}

func TestPatchDHCPLog_Idempotent(t *testing.T) {
	f, err := os.CreateTemp("", "dhcp-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	content := sampleDHCPLog
	content = strings.Replace(content,
		"aa:bb:cc:dd:ee:ff\tmylaptop\t-\t",
		"aa:bb:cc:dd:ee:ff\tmylaptop\t1,3,6,15\t", 1)
	f.WriteString(content)
	f.Close()

	fingerprints := map[string]string{
		"aa:bb:cc:dd:ee:ff": "9,9,9,9",
	}
	if err := PatchDHCPLog(f.Name(), fingerprints); err != nil {
		t.Fatalf("PatchDHCPLog error: %v", err)
	}

	out, _ := os.ReadFile(f.Name())
	if strings.Contains(string(out), "9,9,9,9") {
		t.Error("should not overwrite an already-set param_req_list value")
	}
}

func TestPatchDHCPLog_MissingFile(t *testing.T) {
	err := PatchDHCPLog("/nonexistent/dhcp.log", map[string]string{"aa:bb:cc:dd:ee:ff": "1,3,6"})
	if err != nil {
		t.Errorf("expected nil for missing file, got: %v", err)
	}
}

func TestPatchDHCPLog_NoParamReqListColumn(t *testing.T) {
	f, err := os.CreateTemp("", "dhcp-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("#fields\tts\tmac\tlease_time\n1746000000.0\taa:bb:cc:dd:ee:ff\t86400.0\n")
	f.Close()

	err = PatchDHCPLog(f.Name(), map[string]string{"aa:bb:cc:dd:ee:ff": "1,3,6"})
	if err != nil {
		t.Errorf("expected nil when column absent, got: %v", err)
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

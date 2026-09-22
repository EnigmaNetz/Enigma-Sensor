//go:build linux || darwin

package linux

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// writeTestPcap writes one packet per timestamp; each payload is the tag plus its index.
func writeTestPcap(t *testing.T, path string, linkType layers.LinkType, tag byte, stamps []time.Time) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, linkType); err != nil {
		t.Fatalf("write header: %v", err)
	}
	for i, ts := range stamps {
		data := []byte{tag, byte(i)}
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(data), Length: len(data)}, data); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}
}

func readTestPcap(t *testing.T, path string) [][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	var packets [][]byte
	for {
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			return packets
		}
		if err != nil {
			t.Fatalf("read packet: %v", err)
		}
		packets = append(packets, data)
	}
}

func TestMergePcapFiles_KeepsEveryInterfaceInTimeOrder(t *testing.T) {
	dir := t.TempDir()
	base := time.Unix(1700000000, 0)
	a := filepath.Join(dir, "a.pcap")
	b := filepath.Join(dir, "b.pcap")
	writeTestPcap(t, a, layers.LinkTypeEthernet, 'a', []time.Time{base, base.Add(2 * time.Second), base.Add(4 * time.Second)})
	writeTestPcap(t, b, layers.LinkTypeEthernet, 'b', []time.Time{base.Add(1 * time.Second), base.Add(3 * time.Second)})

	out := filepath.Join(dir, "merged.pcap")
	if err := mergePcapFiles([]string{a, b}, out); err != nil {
		t.Fatalf("mergePcapFiles: %v", err)
	}

	var got []string
	for _, p := range readTestPcap(t, out) {
		got = append(got, string(p[0])+string('0'+p[1]))
	}
	want := "a0 b0 a1 b1 a2"
	if strings.Join(got, " ") != want {
		t.Errorf("merged order = %q, want %q", strings.Join(got, " "), want)
	}
}

func TestMergePcapFiles_LinkTypeMismatchFails(t *testing.T) {
	dir := t.TempDir()
	base := time.Unix(1700000000, 0)
	a := filepath.Join(dir, "a.pcap")
	b := filepath.Join(dir, "b.pcap")
	writeTestPcap(t, a, layers.LinkTypeEthernet, 'a', []time.Time{base})
	writeTestPcap(t, b, layers.LinkTypeRaw, 'b', []time.Time{base})

	out := filepath.Join(dir, "merged.pcap")
	err := mergePcapFiles([]string{a, b}, out)
	if err == nil || !strings.Contains(err.Error(), "link type") {
		t.Fatalf("expected a link type error, got: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("merged file should not exist after a failed merge")
	}
}

func TestMergePcapFiles_TruncatedInputKeepsCompletePackets(t *testing.T) {
	dir := t.TempDir()
	base := time.Unix(1700000000, 0)
	a := filepath.Join(dir, "a.pcap")
	b := filepath.Join(dir, "b.pcap")
	writeTestPcap(t, a, layers.LinkTypeEthernet, 'a', []time.Time{base, base.Add(2 * time.Second)})
	writeTestPcap(t, b, layers.LinkTypeEthernet, 'b', []time.Time{base.Add(1 * time.Second)})

	// Cut the last byte off a's final packet, as a killed tcpdump can leave it
	info, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(a, info.Size()-1); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "merged.pcap")
	if err := mergePcapFiles([]string{a, b}, out); err != nil {
		t.Fatalf("mergePcapFiles: %v", err)
	}
	if n := len(readTestPcap(t, out)); n != 2 {
		t.Errorf("expected 2 complete packets, got %d", n)
	}
}

func TestMergePcapFiles_MissingHeaderFails(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.pcap")
	b := filepath.Join(dir, "b.pcap")
	writeTestPcap(t, a, layers.LinkTypeEthernet, 'a', []time.Time{time.Unix(1700000000, 0)})
	if err := os.WriteFile(b, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := mergePcapFiles([]string{a, b}, filepath.Join(dir, "merged.pcap")); err == nil {
		t.Fatal("expected an error for an input with no pcap header")
	}
}

// An idle interface produces a pcap with a header and no packets
func TestMergePcapFiles_EmptyInterfaceCapture(t *testing.T) {
	dir := t.TempDir()
	base := time.Unix(1700000000, 0)
	a := filepath.Join(dir, "a.pcap")
	b := filepath.Join(dir, "b.pcap")
	writeTestPcap(t, a, layers.LinkTypeEthernet, 'a', []time.Time{base, base.Add(time.Second)})
	writeTestPcap(t, b, layers.LinkTypeEthernet, 'b', nil)

	out := filepath.Join(dir, "merged.pcap")
	if err := mergePcapFiles([]string{a, b}, out); err != nil {
		t.Fatalf("mergePcapFiles: %v", err)
	}
	if n := len(readTestPcap(t, out)); n != 2 {
		t.Errorf("expected 2 packets, got %d", n)
	}
}

func TestMergePcapFiles_NoInputsFails(t *testing.T) {
	if err := mergePcapFiles(nil, filepath.Join(t.TempDir(), "merged.pcap")); err == nil {
		t.Fatal("expected an error for no inputs")
	}
}

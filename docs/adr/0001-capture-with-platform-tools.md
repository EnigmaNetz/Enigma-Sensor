# 0001. Capture with the platform's packet tools

Status: Accepted

Date: 2026-11-17 (backfilled)

## Context

The sensor runs on customer Linux, macOS and Windows hosts and must write each capture window to a
PCAP (packet capture) file that Zeek can read. Each platform already has a capture tool:
`tcpdump` on Linux and macOS, `pktmon` on Windows. Windows has no `tcpdump`, and `pktmon` only sees
traffic the host itself sends or receives, which is not enough when the sensor watches a SPAN
(Switched Port Analyzer) port or a mirror.

## Decision

- `internal/capture/factory.go` picks one `Capturer` (interface in
  `internal/capture/common/capture.go`) per platform at start.
- Linux and macOS run the `tcpdump` binary as a subprocess (`internal/capture/linux/capture.go`).
  Several named interfaces get one `tcpdump` each, merged by timestamp with the pure-Go
  `gopacket/pcapgo` (`internal/capture/linux/merge.go`). The Linux build links no libpcap and
  needs no cgo, Go's C interface (see the note at the top of `Dockerfile`).
- Windows uses Npcap through `gopacket/pcap` when `wpcap.dll` is present
  (`internal/capture/windows/capture_npcap.go`, promiscuous mode). Otherwise it falls back to the
  `pktmon` command (`internal/capture/windows/capture.go`), converting its ETL (Event Trace Log)
  output with `pktmon etl2pcapng`.
- `capture.interface` takes `pktmon` component IDs on Windows on both paths;
  `internal/capture/windows/interface_mapper.go` maps them to Npcap devices.
- Platform code sits behind build tags with stubs (`capture_npcap_stub.go`, `linux/dummy.go`,
  `windows/dummy.go`).

## Consequences

- The installers must provide the tools: the Linux installer installs `tcpdump`, and the Windows
  installer offers Npcap. A host without them cannot capture.
- Windows without Npcap captures only host traffic; the README calls this out and recommends Npcap.
- Capture code is tested by injecting a fake command runner (`commandContext`), not by capturing.
- Any new capturer must implement `common.Capturer`, ship a stub for other platforms, and compile
  under `GOOS=windows`, `GOOS=darwin` and Linux `go vet`.
- Do not add a cgo capture dependency on Linux or macOS without superseding this ADR.

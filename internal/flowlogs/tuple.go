// Package flowlogs reads Azure VNet flow logs from a storage account and converts them into
// Zeek-shaped conn records (B1CF-2140), for VMs a packet capture cannot see, such as those
// behind a Standard public load balancer. The records go up through the same UploadLogs path
// as a capture's conn.log.
//
// A flow log tuple is not a connection: Azure logs a connection as B (begin), then C
// (continuing) every five minutes with that interval's counters, then E (end), or D for a
// denied flow. The Converter keeps a running total per connection and emits one record when
// the connection ends, like Zeek does. A denied flow from outside the network is dropped, as
// a capture would never see it. See convert.go for the state machine.
package flowlogs

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// SupportedVersion is the only flowLogVersion the converter reads. Version 4 tuples carry a
// millisecond timestamp; older NSG flow logs used seconds and different states.
const SupportedVersion = 4

// Protocol numbers in a tuple.
const (
	protoTCP = 6
	protoUDP = 17
)

// Tuple is one flow log tuple.
type Tuple struct {
	// TS is the tuple time in Unix milliseconds.
	TS       int64
	Src, Dst netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Proto    uint8
	// Inbound is true for direction I (into the NIC) and false for O (out of it).
	Inbound bool
	// State is 'B', 'C', 'E' or 'D'.
	State byte
	// Counters for this interval. Src is the side that started the flow, so the first pair is
	// what the originator sent.
	OrigPkts, OrigBytes, RespPkts, RespBytes uint64
	// MAC is the NIC that logged the tuple.
	MAC string
	// Pos identifies the tuple's place in the source blobs. It seeds the uid of a session the
	// tuple starts, so the same input always gives the same uid.
	Pos string
}

// record is one entry of a flow log blob's records array, keeping only what the converter
// reads.
type record struct {
	MAC         string `json:"macAddress"`
	Version     int    `json:"flowLogVersion"`
	FlowRecords struct {
		Flows []struct {
			Groups []struct {
				Tuples []string `json:"flowTuples"`
			} `json:"flowGroups"`
		} `json:"flows"`
	} `json:"flowRecords"`
}

// parseRecord decodes one record and calls add for each of its tuples, in order. pos
// identifies the record in its blob. A tuple that cannot be parsed fails the whole record, as
// a record of another format would. ok is false for a record of another flowLogVersion, which
// is skipped.
func parseRecord(data []byte, pos string, add func(Tuple)) (ok bool, err error) {
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		return false, fmt.Errorf("decode record: %w", err)
	}
	if rec.Version != SupportedVersion {
		return false, nil
	}
	mac := strings.ToUpper(rec.MAC)
	var tuples []Tuple
	n := 0
	for _, flow := range rec.FlowRecords.Flows {
		for _, group := range flow.Groups {
			for _, s := range group.Tuples {
				t, err := parseTuple(s)
				if err != nil {
					return false, fmt.Errorf("tuple %d: %w", n, err)
				}
				t.MAC = mac
				t.Pos = fmt.Sprintf("%s/%d", pos, n)
				tuples = append(tuples, t)
				n++
			}
		}
	}
	for _, t := range tuples {
		add(t)
	}
	return true, nil
}

// parseTuple parses one version 4 tuple:
//
//	time,src,dst,srcPort,dstPort,protocol,direction,state,encryption,origPkts,origBytes,respPkts,respBytes
//
// Counters are empty on a B tuple and read as zero.
func parseTuple(s string) (Tuple, error) {
	f := strings.Split(s, ",")
	if len(f) != 13 {
		return Tuple{}, fmt.Errorf("want 13 fields, got %d", len(f))
	}
	var t Tuple
	var err error
	if t.TS, err = strconv.ParseInt(f[0], 10, 64); err != nil {
		return Tuple{}, fmt.Errorf("time: %w", err)
	}
	if t.Src, err = netip.ParseAddr(f[1]); err != nil {
		return Tuple{}, fmt.Errorf("source: %w", err)
	}
	if t.Dst, err = netip.ParseAddr(f[2]); err != nil {
		return Tuple{}, fmt.Errorf("destination: %w", err)
	}
	if t.SrcPort, err = parsePort(f[3]); err != nil {
		return Tuple{}, fmt.Errorf("source port: %w", err)
	}
	if t.DstPort, err = parsePort(f[4]); err != nil {
		return Tuple{}, fmt.Errorf("destination port: %w", err)
	}
	proto, err := strconv.ParseUint(f[5], 10, 8)
	if err != nil {
		return Tuple{}, fmt.Errorf("protocol: %w", err)
	}
	t.Proto = uint8(proto)
	switch f[6] {
	case "I":
		t.Inbound = true
	case "O":
	default:
		return Tuple{}, fmt.Errorf("direction %q", f[6])
	}
	switch f[7] {
	case "B", "C", "E", "D":
		t.State = f[7][0]
	default:
		return Tuple{}, fmt.Errorf("state %q", f[7])
	}
	counters := []*uint64{&t.OrigPkts, &t.OrigBytes, &t.RespPkts, &t.RespBytes}
	for i, c := range counters {
		if f[9+i] == "" {
			continue
		}
		if *c, err = strconv.ParseUint(f[9+i], 10, 64); err != nil {
			return Tuple{}, fmt.Errorf("counter %d: %w", i+1, err)
		}
	}
	return t, nil
}

func parsePort(s string) (uint16, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	return uint16(p), err
}

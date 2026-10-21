package flowlogs

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"time"

	"EnigmaNetz/Enigma-Go-Sensor/internal/flowlogs/lbrules"
)

const (
	// DefaultMaxAge is how long a connection stays open before its counters so far are emitted
	// as a record and a new segment starts, so a long-lived connection shows up within the hour.
	DefaultMaxAge = time.Hour

	// idleTimeout closes a connection with no tuple for this long. Azure logs a C for every open
	// connection every five minutes, even with nothing sent, so three missed intervals mean its
	// E was lost (or fell outside the logs read so far).
	idleTimeout = 15 * time.Minute

	// staleTimeout closes a connection whose NIC has logged nothing for this long, measured
	// against the newest tuple from any NIC. idleTimeout cannot fire for a NIC that has stopped
	// logging. A NIC that still has blobs to read is not stale: it is only behind.
	staleTimeout = 2 * time.Hour

	// ownerTTL forgets an address no NIC has used for this long, so a reassigned address is
	// not deduplicated against a NIC that no longer has it.
	ownerTTL = 24 * time.Hour

	// healthProbeAddr is the Azure platform address load balancer health probes come from.
	healthProbeAddr = "168.63.129.16"

	// Header bytes per packet, subtracted from IP bytes to estimate payload bytes: IPv4 plus
	// TCP with the timestamp option, and IPv4 plus UDP. IPv6 tuples are dropped.
	tcpHeaderBytes = 52
	udpHeaderBytes = 28

	// msThreshold separates millisecond timestamps from second timestamps: 10^12 ms is 2001,
	// 10^12 s is far in the future. Version 4 uses milliseconds, but Microsoft's own example
	// shows seconds, so both are accepted.
	msThreshold = 1_000_000_000_000
)

var healthProbe = netip.MustParseAddr(healthProbeAddr)

// ConnRecord is one conn.log line, with Zeek's JSON field names. Pointer fields are left out
// when unset, as Zeek leaves out an unset field.
type ConnRecord struct {
	TS          float64 `json:"ts"`
	UID         string  `json:"uid"`
	OrigH       string  `json:"id.orig_h"`
	OrigP       uint16  `json:"id.orig_p"`
	RespH       string  `json:"id.resp_h"`
	RespP       uint16  `json:"id.resp_p"`
	Proto       string  `json:"proto"`
	Service     *string `json:"service,omitempty"`
	Duration    float64 `json:"duration"`
	OrigBytes   uint64  `json:"orig_bytes"`
	RespBytes   uint64  `json:"resp_bytes"`
	ConnState   string  `json:"conn_state"`
	LocalOrig   *bool   `json:"local_orig"`
	LocalResp   *bool   `json:"local_resp"`
	History     *string `json:"history,omitempty"`
	OrigPkts    uint64  `json:"orig_pkts"`
	OrigIPBytes uint64  `json:"orig_ip_bytes"`
	RespPkts    uint64  `json:"resp_pkts"`
	RespIPBytes uint64  `json:"resp_ip_bytes"`
	IPProto     uint8   `json:"ip_proto"`
}

// Session is one open connection as seen by its owning NIC. It is exported so the poller can
// save it in the state file.
type Session struct {
	MAC     string `json:"mac"`
	Proto   uint8  `json:"proto"`
	Src     string `json:"src"`
	SrcPort uint16 `json:"src_port"`
	Dst     string `json:"dst"`
	DstPort uint16 `json:"dst_port"`
	UID     string `json:"uid"`
	// Start is the start of the current segment and Last the newest tuple, in Unix ms.
	Start int64 `json:"start"`
	Last  int64 `json:"last"`
	// Begun is true when this segment started with a B.
	Begun bool `json:"begun"`
	// Replied is true once the responder has sent anything, in any segment.
	Replied   bool   `json:"replied"`
	OrigPkts  uint64 `json:"orig_pkts"`
	OrigBytes uint64 `json:"orig_bytes"`
	RespPkts  uint64 `json:"resp_pkts"`
	RespBytes uint64 `json:"resp_bytes"`
}

// Seen records which NIC uses an address, and when it last did, in Unix ms.
type Seen struct {
	MAC  string `json:"mac"`
	Last int64  `json:"last"`
}

// Address records a NIC's private address, and when it was last seen, in Unix ms.
type Address struct {
	IP   string `json:"ip"`
	Last int64  `json:"last"`
}

// ConverterState is everything the converter must remember between polls.
type ConverterState struct {
	Sessions map[string]*Session `json:"sessions"`
	// Owners maps a NIC's own address to the NIC, learned from its outbound tuples' sources and
	// its inbound tuples' local destinations.
	Owners map[string]Seen `json:"owners"`
	// PrivateIP maps a NIC to its most recent local address, so traffic to the NIC's
	// instance public IP is attributed to the VM.
	PrivateIP map[string]Address `json:"private_ip"`
	// Watermarks holds the newest tuple time per NIC, in Unix ms.
	Watermarks map[string]int64 `json:"watermarks"`
}

// NewConverterState returns an empty state.
func NewConverterState() *ConverterState {
	s := &ConverterState{}
	s.init()
	return s
}

func (s *ConverterState) init() {
	if s.Sessions == nil {
		s.Sessions = map[string]*Session{}
	}
	if s.Owners == nil {
		s.Owners = map[string]Seen{}
	}
	if s.PrivateIP == nil {
		s.PrivateIP = map[string]Address{}
	}
	if s.Watermarks == nil {
		s.Watermarks = map[string]int64{}
	}
}

// Options configure a Converter.
type Options struct {
	// VNetCIDRs are the virtual network's address spaces, used for local_orig, local_resp, to
	// tell a NIC's private address from its public one, and to tell a denied flow from outside
	// the network from one inside it. Empty means the private ranges (RFC 1918 for IPv4).
	VNetCIDRs []netip.Prefix
	// Rules set service for flows to a load balancer's backends.
	Rules []lbrules.Rule
	// MaxAge is the longest a segment stays open; zero means DefaultMaxAge.
	MaxAge time.Duration
}

// Stats counts what the converter dropped, for the poll log.
type Stats struct {
	Records, Duplicates, HealthProbes, IPv6, OtherProtocols, Denied int
}

// Converter folds tuples into connections and emits a ConnRecord when one ends. It owns a
// ConverterState and changes it in place; it is not safe for concurrent use.
//
// Two NICs log a flow between two monitored VMs, each from its own side and with its own
// five-minute phase, so their counters cannot be merged. The converter keeps only the source
// NIC's view: a tuple is dropped when it is inbound and its source address belongs to another
// monitored NIC. A NIC's addresses are learned from its own tuples.
type Converter struct {
	opts  Options
	state *ConverterState
	emit  func(ConnRecord)
	Stats Stats
}

// NewConverter returns a converter over state that calls emit for each finished record.
func NewConverter(opts Options, state *ConverterState, emit func(ConnRecord)) *Converter {
	if opts.MaxAge <= 0 {
		opts.MaxAge = DefaultMaxAge
	}
	state.init()
	return &Converter{opts: opts, state: state, emit: emit}
}

// Learn records which NIC owns the addresses in t, without converting it. Calling it for
// every tuple of a poll before Add lets the first poll deduplicate flows whose source NIC's
// tuples come later in the poll.
func (c *Converter) Learn(t Tuple) {
	if !t.Src.Is4() || !t.Dst.Is4() {
		return
	}
	ts := normalizeTS(t.TS)
	if !t.Inbound {
		c.own(t.Src, t.MAC, ts)
	} else if c.local(t.Dst) {
		c.own(t.Dst, t.MAC, ts)
	}
}

func (c *Converter) own(addr netip.Addr, mac string, ts int64) {
	key := addr.String()
	// The newest tuple wins when an address moves to another NIC
	if cur, ok := c.state.Owners[key]; !ok || cur.MAC == mac || ts >= cur.Last {
		c.state.Owners[key] = Seen{MAC: mac, Last: max(ts, cur.Last)}
	}
	if c.local(addr) {
		if cur, ok := c.state.PrivateIP[mac]; !ok || ts >= cur.Last {
			c.state.PrivateIP[mac] = Address{IP: key, Last: ts}
		}
	}
}

// Add converts one tuple. Tuples from one NIC must be added in the order the NIC logged them:
// two tuples with the same timestamp can be an E and the B of the next connection on the same
// ports, and only their order tells which is which.
func (c *Converter) Add(t Tuple) {
	if !t.Src.Is4() || !t.Dst.Is4() {
		c.Stats.IPv6++
		return
	}
	if t.Proto != protoTCP && t.Proto != protoUDP {
		c.Stats.OtherProtocols++
		return
	}
	if t.Src == healthProbe {
		c.Stats.HealthProbes++
		return
	}
	t.TS = normalizeTS(t.TS)
	c.Learn(t)
	if t.TS > c.state.Watermarks[t.MAC] {
		c.state.Watermarks[t.MAC] = t.TS
	}
	if t.Inbound {
		// Traffic to the NIC's instance public IP belongs to the VM's private address
		if !c.local(t.Dst) {
			if priv, ok := c.state.PrivateIP[t.MAC]; ok {
				if addr, err := netip.ParseAddr(priv.IP); err == nil {
					t.Dst = addr
				}
			}
		}
		if owner, ok := c.state.Owners[t.Src.String()]; ok && owner.MAC != t.MAC {
			// The source NIC logs this flow. If this NIC opened a session for it before the
			// source's address was known, drop it unsent: emitting it would count the flow twice
			delete(c.state.Sessions, sessionKey(t))
			c.Stats.Duplicates++
			return
		}
	}

	if t.State == 'D' {
		if !c.local(t.Src) {
			// Blocked before it reached the VM, so a capture would never see it: on an
			// internet-facing VM this is scanner noise, not connections
			c.Stats.Denied++
			return
		}
		// A blocked attempt from inside the network: a capture of the sender sees its SYN
		// go unanswered, so it is an S0 as Zeek would log it
		s := c.newSession(t)
		s.add(t)
		c.emitRecord(s, "S0", false)
		return
	}

	key := sessionKey(t)
	s := c.state.Sessions[key]
	if s != nil && t.TS-s.Last > idleTimeout.Milliseconds() {
		c.close(key, s, false)
		s = nil
	}
	switch t.State {
	case 'B':
		// A B on ports that are still open means the earlier connection's E was lost
		if s != nil {
			c.close(key, s, false)
		}
		s = c.newSession(t)
		s.Begun = true
		c.state.Sessions[key] = s
		return
	case 'C', 'E':
		if s == nil {
			// Its B is outside the logs read so far: start here, so the duration is a lower bound
			s = c.newSession(t)
			c.state.Sessions[key] = s
		} else if t.TS-s.Start >= c.opts.MaxAge.Milliseconds() {
			c.emitRecord(s, stateFor(s, false), false)
			s.restart()
		}
		s.add(t)
		if t.State == 'E' {
			c.close(key, s, true)
		}
	}
}

// Flush closes every connection that has gone idle by its NIC's newest tuple, or whose NIC has
// gone quiet. Call it after each poll's tuples have been added. reading holds the NICs that
// still have blobs to read: while a backlog is read over several polls, one NIC's newer tuples
// can be read before another's, so a NIC in reading is not quiet, and neither its connections
// nor its learned addresses are dropped for it. Connections are closed in key order so the
// output does not depend on map order.
func (c *Converter) Flush(reading map[string]bool) {
	var newest int64
	for _, w := range c.state.Watermarks {
		newest = max(newest, w)
	}
	keys := make([]string, 0, len(c.state.Sessions))
	for k := range c.state.Sessions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := c.state.Sessions[k]
		if c.state.Watermarks[s.MAC]-s.Last > idleTimeout.Milliseconds() ||
			(!reading[s.MAC] && newest-s.Last > staleTimeout.Milliseconds()) {
			c.close(k, s, false)
		}
	}
	for addr, seen := range c.state.Owners {
		if !reading[seen.MAC] && newest-seen.Last > ownerTTL.Milliseconds() {
			delete(c.state.Owners, addr)
		}
	}
	for mac, addr := range c.state.PrivateIP {
		if !reading[mac] && newest-addr.Last > ownerTTL.Milliseconds() {
			delete(c.state.PrivateIP, mac)
		}
	}
	for mac, w := range c.state.Watermarks {
		if !reading[mac] && newest-w > ownerTTL.Milliseconds() {
			delete(c.state.Watermarks, mac)
		}
	}
}

// newSession starts a session at t with no counters; the caller adds t's counters.
func (c *Converter) newSession(t Tuple) *Session {
	return &Session{
		MAC: t.MAC, Proto: t.Proto,
		Src: t.Src.String(), SrcPort: t.SrcPort,
		Dst: t.Dst.String(), DstPort: t.DstPort,
		UID:   newUID(t),
		Start: t.TS, Last: t.TS,
	}
}

// add sums one interval's counters into the session. C and E counters cover only the interval
// since the previous tuple, so they are summed, never subtracted.
func (s *Session) add(t Tuple) {
	s.OrigPkts += t.OrigPkts
	s.OrigBytes += t.OrigBytes
	s.RespPkts += t.RespPkts
	s.RespBytes += t.RespBytes
	if t.RespPkts > 0 {
		s.Replied = true
	}
	s.Last = max(s.Last, t.TS)
}

// restart begins a new segment of a connection whose counters so far were emitted. The next
// segment starts where this one ended and keeps the uid and whether the responder replied.
func (s *Session) restart() {
	s.Start = s.Last
	s.Begun = false
	s.OrigPkts, s.OrigBytes, s.RespPkts, s.RespBytes = 0, 0, 0, 0
}

// close emits a session and forgets it. ended is true when Azure logged its E.
func (c *Converter) close(key string, s *Session, ended bool) {
	c.emitRecord(s, stateFor(s, ended), ended)
	delete(c.state.Sessions, key)
}

// stateFor is the conn_state for a session: SF once it ended with a reply seen at any point,
// S1 for one still open (or whose E was lost) with a reply, S0 with no reply at all. Azure
// does not say how a connection ended, so there is no REJ or reset state.
func stateFor(s *Session, ended bool) string {
	switch {
	case !s.Replied:
		return "S0"
	case ended:
		return "SF"
	default:
		return "S1"
	}
}

func (c *Converter) emitRecord(s *Session, state string, ended bool) {
	// The addresses came from parsed tuples, through the state file; a damaged file must not
	// panic the sensor, and an unparsable address only loses the local flags and service
	src, _ := netip.ParseAddr(s.Src)
	dst, _ := netip.ParseAddr(s.Dst)
	hdr := uint64(tcpHeaderBytes)
	proto := "tcp"
	if s.Proto == protoUDP {
		hdr, proto = udpHeaderBytes, "udp"
	}
	rec := ConnRecord{
		TS:          float64(s.Start) / 1000,
		UID:         s.UID,
		OrigH:       s.Src,
		OrigP:       s.SrcPort,
		RespH:       s.Dst,
		RespP:       s.DstPort,
		Proto:       proto,
		Duration:    float64(s.Last-s.Start) / 1000,
		OrigBytes:   payload(s.OrigBytes, s.OrigPkts, hdr),
		RespBytes:   payload(s.RespBytes, s.RespPkts, hdr),
		ConnState:   state,
		OrigPkts:    s.OrigPkts,
		OrigIPBytes: s.OrigBytes,
		RespPkts:    s.RespPkts,
		RespIPBytes: s.RespBytes,
		IPProto:     s.Proto,
	}
	if svc, ok := lbrules.Match(c.opts.Rules, dst, s.DstPort, s.Proto); ok {
		rec.Service = &svc
	}
	lo, lr := c.local(src), c.local(dst)
	rec.LocalOrig, rec.LocalResp = &lo, &lr
	// Synthetic, not packet history: S when Azure logged the begin, F when it logged the end
	history := ""
	if s.Begun {
		history += "S"
	}
	if ended {
		history += "F"
	}
	if history != "" {
		rec.History = &history
	}
	c.Stats.Records++
	c.emit(rec)
}

// local reports whether addr is in the virtual network: the configured address spaces, or any
// private address when none are configured.
func (c *Converter) local(addr netip.Addr) bool {
	if len(c.opts.VNetCIDRs) == 0 {
		return addr.IsPrivate()
	}
	for _, p := range c.opts.VNetCIDRs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// payload estimates payload bytes from IP bytes, clamped at zero: Azure's counters include
// headers, Zeek's orig_bytes and resp_bytes do not.
func payload(ipBytes, pkts, hdr uint64) uint64 {
	if ipBytes <= pkts*hdr {
		return 0
	}
	return ipBytes - pkts*hdr
}

func normalizeTS(ts int64) int64 {
	if ts < msThreshold {
		return ts * 1000
	}
	return ts
}

func sessionKey(t Tuple) string {
	return fmt.Sprintf("%s|%d|%s|%d|%s|%d", t.MAC, t.Proto, t.Src, t.SrcPort, t.Dst, t.DstPort)
}

// newUID derives a Zeek-style uid from the tuple's place in the source logs, so converting the
// same logs again gives the same uids. It is not an idempotency key: the platform does not
// deduplicate on uid, and every segment of a long connection shares it.
func newUID(t Tuple) string {
	sum := sha256.Sum256([]byte(t.MAC + "|" + t.Pos))
	n := new(big.Int).SetBytes(sum[:12])
	s := n.Text(62)
	for len(s) < 17 {
		s = "0" + s
	}
	return "C" + s[:17]
}

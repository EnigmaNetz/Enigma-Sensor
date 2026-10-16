package flowlogs

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"EnigmaNetz/Enigma-Go-Sensor/internal/flowlogs/lbrules"
)

// Test addresses are documentation and private ranges: two monitored VMs, a client on the
// internet, and an instance public IP.
const (
	macA     = "00224800AAAA"
	macB     = "00224800BBBB"
	vmA      = "10.0.1.4"
	vmB      = "10.0.2.5"
	client   = "203.0.113.9"
	publicIP = "198.51.100.20"
	t0       = int64(1790856000000) // ms
)

type harness struct {
	t    *testing.T
	conv *Converter
	recs []ConnRecord
	n    int
}

func newHarness(t *testing.T, opts Options) *harness {
	h := &harness{t: t}
	h.conv = NewConverter(opts, NewConverterState(), func(r ConnRecord) { h.recs = append(h.recs, r) })
	return h
}

// tuple builds a tuple from its CSV form, as it appears in a blob.
func (h *harness) tuple(mac, csv string) Tuple {
	h.t.Helper()
	tp, err := parseTuple(csv)
	require.NoError(h.t, err)
	tp.MAC = mac
	tp.Pos = fmt.Sprintf("test@%d", h.n)
	h.n++
	return tp
}

func (h *harness) add(mac string, csvs ...string) {
	h.t.Helper()
	for _, c := range csvs {
		h.conv.Add(h.tuple(mac, c))
	}
}

// at formats a tuple at t0 plus offset.
func at(offset time.Duration, rest string) string {
	return fmt.Sprintf("%d,%s", t0+offset.Milliseconds(), rest)
}

func strp(s string) *string { return &s }

func TestLifecycleSumsIntervals(t *testing.T) {
	h := newHarness(t, Options{})
	h.add(macA,
		at(0, vmA+","+client+",50000,443,6,O,B,NX,,,,"),
		at(300*time.Second, vmA+","+client+",50000,443,6,O,C,NX,10,1000,8,4000"),
		at(400*time.Second, vmA+","+client+",50000,443,6,O,E,NX,2,200,1,100"),
	)
	require.Len(t, h.recs, 1)
	r := h.recs[0]
	require.Equal(t, float64(t0)/1000, r.TS)
	require.Equal(t, 400.0, r.Duration)
	require.Equal(t, "SF", r.ConnState)
	require.Equal(t, strp("SF"), r.History)
	require.Equal(t, uint64(12), r.OrigPkts)
	require.Equal(t, uint64(1200), r.OrigIPBytes)
	require.Equal(t, uint64(9), r.RespPkts)
	require.Equal(t, uint64(4100), r.RespIPBytes)
	require.Equal(t, uint64(1200-12*52), r.OrigBytes)
	require.Equal(t, uint64(4100-9*52), r.RespBytes)
	require.Equal(t, "tcp", r.Proto)
	require.Equal(t, uint8(6), r.IPProto)
	require.Equal(t, vmA, r.OrigH)
	require.Equal(t, client, r.RespH)
	require.Nil(t, r.Service)
	require.Len(t, r.UID, 18)
	require.Empty(t, h.conv.state.Sessions)
}

func TestEndWithoutBegin(t *testing.T) {
	h := newHarness(t, Options{})
	h.add(macA, at(0, vmA+","+client+",50000,443,6,O,E,NX,4,400,3,300"))
	require.Len(t, h.recs, 1)
	r := h.recs[0]
	require.Equal(t, "SF", r.ConnState)
	require.Equal(t, strp("F"), r.History)
	require.Equal(t, 0.0, r.Duration)
	require.Equal(t, uint64(4), r.OrigPkts)
}

func TestBeginWithoutEndClosesWhenIdle(t *testing.T) {
	h := newHarness(t, Options{})
	h.add(macA,
		at(0, vmA+","+client+",50001,443,6,O,B,NX,,,,"),
		at(60*time.Second, vmA+","+client+",50002,443,6,O,B,NX,,,,"),
		at(300*time.Second, vmA+","+client+",50002,443,6,O,C,NX,3,300,2,200"),
	)
	h.conv.Flush()
	require.Empty(t, h.recs, "nothing is idle yet")

	// The NIC's newest tuple moves 16 minutes past the second connection's last tuple
	h.add(macA, at(1260*time.Second, vmA+","+client+",50003,443,6,O,B,NX,,,,"))
	h.conv.Flush()
	require.Len(t, h.recs, 2)
	byPort := map[uint16]ConnRecord{}
	for _, r := range h.recs {
		byPort[r.OrigP] = r
	}
	require.Equal(t, "S0", byPort[50001].ConnState, "no reply ever seen")
	require.Equal(t, strp("S"), byPort[50001].History)
	require.Equal(t, "S1", byPort[50002].ConnState, "replied, but its E was never logged")
	require.Equal(t, strp("S"), byPort[50002].History)
	require.Equal(t, 240.0, byPort[50002].Duration, "from its B to its last C")
}

func TestIdleGapOnArrivalStartsNewConnection(t *testing.T) {
	h := newHarness(t, Options{})
	h.add(macA,
		at(0, vmA+","+client+",50000,443,6,O,C,NX,1,100,1,100"),
		at(20*time.Minute, vmA+","+client+",50000,443,6,O,E,NX,1,100,1,100"),
	)
	require.Len(t, h.recs, 2)
	require.Equal(t, "S1", h.recs[0].ConnState)
	require.Equal(t, "SF", h.recs[1].ConnState)
	require.NotEqual(t, h.recs[0].UID, h.recs[1].UID)
}

func TestMaxAgeFlushesAndKeepsUID(t *testing.T) {
	h := newHarness(t, Options{})
	key := vmA + "," + vmB + ",52114,1433,6,O,"
	h.add(macA, at(0, key+"B,NX,,,,"))
	var orig uint64
	for i := 1; i <= 13; i++ {
		h.add(macA, at(time.Duration(i)*300*time.Second, key+"C,NX,10,1000,5,500"))
		orig += 10
	}
	h.add(macA, at(4000*time.Second, key+"E,NX,1,100,1,100"))
	orig++

	require.Len(t, h.recs, 2)
	first, second := h.recs[0], h.recs[1]
	require.Equal(t, "S1", first.ConnState)
	require.Equal(t, strp("S"), first.History)
	require.Equal(t, 3300.0, first.Duration, "the segment ends at the last tuple before the hour")
	require.Equal(t, "SF", second.ConnState)
	require.Equal(t, strp("F"), second.History)
	require.Equal(t, first.TS+first.Duration, second.TS, "the next segment starts where the first ended")
	require.Equal(t, first.UID, second.UID)
	require.Equal(t, orig, first.OrigPkts+second.OrigPkts, "no interval is lost or counted twice")
}

func TestReplyInEarlierIntervalStillEstablished(t *testing.T) {
	h := newHarness(t, Options{})
	k := vmA + "," + client + ",50000,443,6,O,"
	h.add(macA, at(0, k+"B,NX,,,,"), at(300*time.Second, k+"C,NX,5,500,4,400"),
		at(600*time.Second, k+"C,NX,1,52,0,0"), at(700*time.Second, k+"E,NX,1,52,0,0"))
	require.Len(t, h.recs, 1)
	require.Equal(t, "SF", h.recs[0].ConnState)
}

func TestNoReplyIsS0(t *testing.T) {
	h := newHarness(t, Options{})
	k := vmA + "," + client + ",50000,443,6,O,"
	h.add(macA, at(0, k+"B,NX,,,,"), at(30*time.Second, k+"E,NX,3,156,0,0"))
	require.Equal(t, "S0", h.recs[0].ConnState)
	require.Equal(t, uint64(0), h.recs[0].OrigBytes, "payload estimate clamps at zero")
}

func TestTwoNICsKeepTheSourceNIC(t *testing.T) {
	for _, order := range []string{"source NIC first", "destination NIC first"} {
		t.Run(order, func(t *testing.T) {
			h := newHarness(t, Options{})
			k := vmA + "," + vmB + ",52114,1433,6,"
			// Each NIC logs the flow from its own side, five-minute intervals out of phase
			a := []Tuple{
				h.tuple(macA, at(0, k+"O,B,NX,,,,")),
				h.tuple(macA, at(300*time.Second, k+"O,C,NX,10,1000,8,800")),
				h.tuple(macA, at(450*time.Second, k+"O,E,NX,2,200,1,100")),
			}
			b := []Tuple{
				h.tuple(macB, at(5*time.Millisecond, k+"I,B,NX,,,,")),
				h.tuple(macB, at(250*time.Second, k+"I,C,NX,9,900,7,700")),
				h.tuple(macB, at(451*time.Second, k+"I,E,NX,3,300,2,200")),
			}
			first, second := a, b
			if order == "destination NIC first" {
				first, second = b, a
			}
			// The poller learns every NIC's addresses before converting
			for _, tp := range append(append([]Tuple{}, first...), second...) {
				h.conv.Learn(tp)
			}
			for _, tp := range append(first, second...) {
				h.conv.Add(tp)
			}
			require.Len(t, h.recs, 1)
			require.Equal(t, uint64(12), h.recs[0].OrigPkts, "only the source NIC's counters")
			require.Equal(t, 3, h.conv.Stats.Duplicates)
		})
	}
}

func TestInboundFromUnmonitoredSourceIsKept(t *testing.T) {
	h := newHarness(t, Options{})
	h.add(macA, at(0, vmA+","+client+",50000,443,6,O,B,NX,,,,"))
	h.add(macB, at(time.Second, client+","+vmB+",61000,443,6,I,E,NX,5,500,5,5000"))
	require.Len(t, h.recs, 1)
	require.Equal(t, client, h.recs[0].OrigH)
	require.Equal(t, 0, h.conv.Stats.Duplicates)
}

func TestSameTimestampEndThenBegin(t *testing.T) {
	h := newHarness(t, Options{})
	k := vmA + "," + client + ",50000,443,6,O,"
	h.add(macA,
		at(0, k+"B,NX,,,,"),
		at(10*time.Second, k+"E,NX,2,200,2,200"),
		at(10*time.Second, k+"B,NX,,,,"),
		at(20*time.Second, k+"E,NX,4,400,4,400"),
	)
	require.Len(t, h.recs, 2)
	require.Equal(t, uint64(2), h.recs[0].OrigPkts)
	require.Equal(t, uint64(4), h.recs[1].OrigPkts)
	require.Equal(t, strp("SF"), h.recs[1].History)
	require.NotEqual(t, h.recs[0].UID, h.recs[1].UID)
}

func TestDeniedFlow(t *testing.T) {
	h := newHarness(t, Options{})
	h.add(macA, at(0, client+","+vmA+",55188,22,6,I,D,NX,0,0,0,0"))
	require.Len(t, h.recs, 1)
	r := h.recs[0]
	require.Equal(t, "S0", r.ConnState)
	require.Nil(t, r.History)
	require.Empty(t, h.conv.state.Sessions)
}

func TestLoadBalancerRules(t *testing.T) {
	rules, err := lbrules.Parse("10.0.2.0/24:443=ssl, 10.0.2.5:53/udp=dns")
	require.NoError(t, err)
	h := newHarness(t, Options{Rules: rules})
	h.add(macB,
		at(0, client+","+vmB+",61000,443,6,I,E,NX,5,500,5,5000"),
		at(0, client+","+vmB+",61001,8443,6,I,E,NX,5,500,5,5000"),
		at(0, client+","+vmB+",61002,53,17,I,E,NX,1,60,1,90"),
		at(0, client+","+vmB+",61003,53,6,I,E,NX,1,60,1,90"),
	)
	require.Len(t, h.recs, 4)
	require.Equal(t, strp("ssl"), h.recs[0].Service)
	require.Nil(t, h.recs[1].Service, "no rule for the port")
	require.Equal(t, strp("dns"), h.recs[2].Service)
	require.Equal(t, "udp", h.recs[2].Proto)
	require.Equal(t, uint64(60-28), h.recs[2].OrigBytes)
	require.Nil(t, h.recs[3].Service, "the rule is for udp")
}

func TestInstancePublicIPAttributedToVM(t *testing.T) {
	h := newHarness(t, Options{})
	h.add(macA, at(0, vmA+","+client+",50000,443,6,O,E,NX,1,100,1,100"))
	h.add(macA, at(time.Second, client+","+publicIP+",61000,1433,6,I,E,NX,3,300,3,300"))
	require.Len(t, h.recs, 2)
	require.Equal(t, vmA, h.recs[1].RespH)
}

func TestDroppedTuples(t *testing.T) {
	h := newHarness(t, Options{})
	h.add(macA,
		at(0, "168.63.129.16,"+vmA+",60000,80,6,I,E,NX,1,60,1,60"),
		at(0, "2001:db8::1,2001:db8::2,60000,80,6,O,E,NX,1,60,1,60"),
		at(0, vmA+","+client+",0,0,1,O,E,NX,1,60,1,60"),
	)
	require.Empty(t, h.recs)
	require.Equal(t, 1, h.conv.Stats.HealthProbes)
	require.Equal(t, 1, h.conv.Stats.IPv6)
	require.Equal(t, 1, h.conv.Stats.OtherProtocols)
}

func TestLocalFlagsFromVNetCIDRs(t *testing.T) {
	h := newHarness(t, Options{VNetCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}})
	h.add(macA, at(0, vmA+","+client+",50000,443,6,O,E,NX,1,100,1,100"))
	r := h.recs[0]
	require.NotNil(t, r.LocalOrig)
	require.True(t, *r.LocalOrig)
	require.False(t, *r.LocalResp)

	h = newHarness(t, Options{})
	h.add(macA, at(0, vmA+","+client+",50000,443,6,O,E,NX,1,100,1,100"))
	require.True(t, *h.recs[0].LocalOrig, "without address spaces, private addresses are local")
	require.False(t, *h.recs[0].LocalResp)
}

// A destination NIC's tuples read before the source NIC's address is known open a session;
// once the address is known, that session is dropped unsent, not emitted alongside the source
// NIC's record.
func TestLateOwnershipDropsTheDuplicateSession(t *testing.T) {
	h := newHarness(t, Options{})
	k := vmA + "," + vmB + ",52114,1433,6,"
	h.add(macB, at(0, k+"I,B,NX,,,,"), at(300*time.Second, k+"I,C,NX,9,900,7,700"))
	require.Len(t, h.conv.state.Sessions, 1)
	h.add(macA, at(0, k+"O,B,NX,,,,"), at(300*time.Second, k+"O,C,NX,10,1000,8,800"))
	h.add(macB, at(600*time.Second, k+"I,E,NX,3,300,2,200"))
	h.add(macA, at(600*time.Second, k+"O,E,NX,2,200,1,100"))
	// macB's clock moves well past the idle timeout, which would flush a leftover session
	h.add(macB, at(time.Hour, vmB+","+client+",50000,443,6,O,B,NX,,,,"))
	h.conv.Flush()
	require.Len(t, h.recs, 1)
	require.Equal(t, uint64(12), h.recs[0].OrigPkts, "only the source NIC's counters")
}

func TestSecondTimestampsAccepted(t *testing.T) {
	h := newHarness(t, Options{})
	h.add(macA, fmt.Sprintf("%d,%s,%s,50000,443,6,O,E,NX,1,100,1,100", t0/1000, vmA, client))
	require.Equal(t, float64(t0/1000), h.recs[0].TS)
}

func TestStaleNICClosed(t *testing.T) {
	h := newHarness(t, Options{})
	h.add(macA, at(0, vmA+","+client+",50000,443,6,O,B,NX,,,,"))
	h.add(macB, at(3*time.Hour, vmB+","+client+",50000,443,6,O,B,NX,,,,"))
	h.conv.Flush()
	require.Len(t, h.recs, 1)
	require.Equal(t, vmA, h.recs[0].OrigH)
}

// stream is a mixed input exercising every path, for the determinism and restart tests.
func stream() []struct{ mac, csv string } {
	k := vmA + "," + vmB + ",52114,1433,6,"
	var s []struct{ mac, csv string }
	add := func(mac, csv string) { s = append(s, struct{ mac, csv string }{mac, csv}) }
	add(macA, at(0, k+"O,B,NX,,,,"))
	add(macB, at(0, k+"I,B,NX,,,,"))
	for i := 1; i <= 15; i++ {
		add(macA, at(time.Duration(i)*300*time.Second, k+"O,C,NX,10,1000,5,500"))
		add(macB, at(time.Duration(i)*300*time.Second-time.Minute, k+"I,C,NX,9,900,4,400"))
		add(macB, at(time.Duration(i)*300*time.Second, fmt.Sprintf("%s,%s,%d,443,6,I,E,NX,4,400,4,4000", client, vmB, 40000+i)))
		add(macA, at(time.Duration(i)*300*time.Second, fmt.Sprintf("%s,%s,50000,%d,6,I,D,NX,0,0,0,0", client, vmA, i)))
	}
	add(macA, at(4600*time.Second, k+"O,E,NX,1,100,1,100"))
	add(macA, at(4600*time.Second, vmA+","+client+",50001,443,6,O,B,NX,,,,"))
	return s
}

func runStream(t *testing.T, split int) []byte {
	var out []byte
	emit := func(r ConnRecord) {
		b, err := json.Marshal(r)
		require.NoError(t, err)
		out = append(append(out, b...), '\n')
	}
	in := stream()
	state := NewConverterState()
	for i, part := range [][]struct{ mac, csv string }{in[:split], in[split:]} {
		// Each part is a poll: the state goes through JSON between polls, as through the file
		data, err := json.Marshal(state)
		require.NoError(t, err)
		state = &ConverterState{}
		require.NoError(t, json.Unmarshal(data, state))
		conv := NewConverter(Options{}, state, emit)
		for j, e := range part {
			tp, err := parseTuple(e.csv)
			require.NoError(t, err)
			tp.MAC, tp.Pos = e.mac, fmt.Sprintf("blob@%d", j+i*split)
			conv.Add(tp)
		}
		conv.Flush()
	}
	return out
}

func TestOutputIsDeterministic(t *testing.T) {
	a := runStream(t, len(stream()))
	b := runStream(t, len(stream()))
	require.NotEmpty(t, a)
	require.Equal(t, string(a), string(b))
}

func TestStateSurvivesRestart(t *testing.T) {
	whole := runStream(t, len(stream()))
	for _, split := range []int{1, 7, 30, len(stream()) - 1} {
		require.Equal(t, string(whole), string(runStream(t, split)), "split at %d", split)
	}
}

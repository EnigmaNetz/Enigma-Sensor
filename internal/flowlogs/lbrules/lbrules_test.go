package lbrules

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRejectsBadEntries(t *testing.T) {
	for _, bad := range []string{"10.0.0.1:443", "10.0.0.1=ssl", "10.0.0.1:0=ssl", "10.0.0.1:443/icmp=ssl",
		"10.0.0.1:443=SSL", "nope:443=ssl", "[2001:db8::1]:443=ssl", "10.0.0.0/33:443=ssl"} {
		_, err := Parse(bad)
		require.Error(t, err, bad)
	}
	rules, err := Parse("")
	require.NoError(t, err)
	require.Empty(t, rules)
}

func TestMatch(t *testing.T) {
	rules, err := Parse("10.0.2.0/24:443=ssl,10.0.2.5:53/udp=dns")
	require.NoError(t, err)
	svc, ok := Match(rules, netip.MustParseAddr("10.0.2.9"), 443, TCP)
	require.True(t, ok)
	require.Equal(t, "ssl", svc)
	_, ok = Match(rules, netip.MustParseAddr("10.0.3.9"), 443, TCP)
	require.False(t, ok)
	svc, ok = Match(rules, netip.MustParseAddr("10.0.2.5"), 53, UDP)
	require.True(t, ok)
	require.Equal(t, "dns", svc)
}

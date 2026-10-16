// Package lbrules parses the azure_flow_logs.lb_rules setting. It has no dependencies, so the
// config package can validate the setting without pulling in the Azure SDK.
package lbrules

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Protocol numbers a rule can name.
const (
	TCP = 6
	UDP = 17
)

// Rule sets service for flows to a load balancer backend: flow logs carry no protocol
// detection, so service comes only from rules the operator lists, never from the port alone.
type Rule struct {
	Backend netip.Prefix
	Port    uint16
	Proto   uint8
	Service string
}

var serviceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// Parse parses a comma-separated list of rules, each
//
//	<backend address or CIDR>:<port>[/tcp|/udp]=<service>
//
// for example "10.1.2.0/24:443=ssl,10.1.2.0/24:80/tcp=http". The protocol defaults to tcp.
// An empty list returns no rules.
func Parse(list string) ([]Rule, error) {
	var rules []Rule
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		r, err := parseLBRule(entry)
		if err != nil {
			return nil, fmt.Errorf("load balancer rule %q: %w", entry, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func parseLBRule(entry string) (Rule, error) {
	target, service, ok := strings.Cut(entry, "=")
	if !ok {
		return Rule{}, fmt.Errorf("want <backend>:<port>[/tcp|/udp]=<service>")
	}
	service = strings.TrimSpace(service)
	if !serviceName.MatchString(service) {
		return Rule{}, fmt.Errorf("service %q must be lowercase letters, digits, - or _", service)
	}
	r := Rule{Service: service, Proto: TCP}
	target = strings.TrimSpace(target)
	if before, proto, ok := strings.Cut(target, "/tcp"); ok && proto == "" {
		target = before
	} else if before, proto, ok := strings.Cut(target, "/udp"); ok && proto == "" {
		target, r.Proto = before, UDP
	}
	i := strings.LastIndex(target, ":")
	if i < 0 {
		return Rule{}, fmt.Errorf("missing :<port>")
	}
	port, err := strconv.ParseUint(target[i+1:], 10, 16)
	if err != nil || port == 0 {
		return Rule{}, fmt.Errorf("port %q must be 1 to 65535", target[i+1:])
	}
	r.Port = uint16(port)
	backend := target[:i]
	if strings.Contains(backend, "/") {
		r.Backend, err = netip.ParsePrefix(backend)
	} else {
		var addr netip.Addr
		if addr, err = netip.ParseAddr(backend); err == nil {
			r.Backend = netip.PrefixFrom(addr, addr.BitLen())
		}
	}
	if err != nil {
		return Rule{}, fmt.Errorf("backend %q: %w", backend, err)
	}
	if !r.Backend.Addr().Is4() {
		return Rule{}, fmt.Errorf("backend %q must be IPv4", backend)
	}
	r.Backend = r.Backend.Masked()
	return r, nil
}

// Match returns the service of the first rule matching a flow to dst:port.
func Match(rules []Rule, dst netip.Addr, port uint16, proto uint8) (string, bool) {
	for _, r := range rules {
		if r.Port == port && r.Proto == proto && r.Backend.Contains(dst) {
			return r.Service, true
		}
	}
	return "", false
}

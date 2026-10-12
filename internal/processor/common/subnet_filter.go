package types

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strings"
)

// addressFields is the set of Zeek log fields that hold a single IP address we filter on. The
// same names cover every uploaded log:
//   - conn, dns, ja3_ja4, ja4s: id.orig_h, id.resp_h
//   - dhcp: client_addr, server_addr, requested_addr, assigned_addr
//
// A field name only appears here where it is genuinely an address, so keying off the name alone
// is safe across all five logs.
var addressFields = []string{
	"id.orig_h",
	"id.resp_h",
	"client_addr",
	"server_addr",
	"requested_addr",
	"assigned_addr",
}

// addressSetFields names Zeek fields that hold a list of values which may include IP addresses.
// dns.log "answers" is the case that matters: a DNS reply resolving to an excluded-subnet IP
// would otherwise leak that internal address even when the client and resolver are not in an
// excluded subnet. Each element is checked; non-IP members (CNAMEs, MX targets, TXT data, ...)
// are ignored.
var addressSetFields = []string{"answers"}

// FilterExcludedSubnets rewrites each of the given Zeek JSON logs in runDir in place, dropping
// any record that references an excluded-subnet address: either a single address field (see
// addressFields) or an IP in a list field such as dns.log "answers" (see addressSetFields).
// Missing log files are a no-op (JA3/JA4 may be absent). An empty or whitespace CIDR list turns
// the feature off.
//
// Filtering is a "do not upload it" guarantee, so any read, parse or write failure on a present
// log, including a line that is not a JSON record, is returned as an error rather than
// swallowed. The caller aborts the capture window rather than risk uploading unfiltered data.
//
// The logs are filtered in place, not only in the upload, because support bundles archive the
// capture directories (internal/collect_logs).
func FilterExcludedSubnets(runDir string, logFiles []string, excludedCIDRs []string) error {
	nets := parseCIDRs(excludedCIDRs)
	if len(nets) == 0 {
		return nil
	}
	for _, name := range logFiles {
		if err := filterLogFile(filepath.Join(runDir, name), nets); err != nil {
			return fmt.Errorf("filter %s: %w", name, err)
		}
	}
	return nil
}

// parseCIDRs converts CIDR strings to *net.IPNet. Malformed entries are skipped
// with a warning; config validation is the authoritative gate, this keeps the
// filter robust when called directly (e.g. in tests).
func parseCIDRs(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			log.Printf("[processor] Warning: skipping invalid excluded subnet %q: %v", c, err)
			continue
		}
		nets = append(nets, n)
	}
	return nets
}

// filterLogFile drops excluded records from a single Zeek JSON log, in place.
func filterLogFile(logPath string, nets []*net.IPNet) error {
	// dhcp.log has no conn_id; every other uploaded log must carry one, so a record without it
	// is refused rather than passed through unchecked.
	requireConnID := filepath.Base(logPath) != "dhcp.log"
	dropped, err := rewriteLog(logPath, func(line []byte) ([]byte, error) {
		excluded, err := recordExcluded(line, nets, requireConnID)
		if err != nil || excluded {
			return nil, err
		}
		return line, nil
	})
	if err != nil {
		return err
	}
	if dropped > 0 {
		log.Printf("[processor] Subnet filter dropped %d record(s) from %s", dropped, filepath.Base(logPath))
	}
	return nil
}

// recordExcluded reports whether a JSON log record references an excluded-subnet IP in any
// single address field or any element of a list field. With requireConnID, a record that has
// neither id.orig_h nor id.resp_h is an error.
func recordExcluded(line []byte, nets []*net.IPNet, requireConnID bool) (bool, error) {
	var rec map[string]json.RawMessage
	if err := json.Unmarshal(line, &rec); err != nil {
		return false, fmt.Errorf("not a JSON log record: %w", err)
	}
	if requireConnID {
		_, orig := rec["id.orig_h"]
		_, resp := rec["id.resp_h"]
		if !orig && !resp {
			return false, fmt.Errorf("record has no id.orig_h or id.resp_h to check")
		}
	}
	for _, name := range addressFields {
		raw, ok := rec[name]
		if !ok {
			continue
		}
		var addr string
		if err := json.Unmarshal(raw, &addr); err != nil {
			return false, fmt.Errorf("field %s: %w", name, err)
		}
		if ipInNets(addr, nets) {
			return true, nil
		}
	}
	for _, name := range addressSetFields {
		raw, ok := rec[name]
		if !ok {
			continue
		}
		var values []string
		if err := json.Unmarshal(raw, &values); err != nil {
			return false, fmt.Errorf("field %s: %w", name, err)
		}
		for _, v := range values {
			if ipInNets(v, nets) {
				return true, nil
			}
		}
	}
	return false, nil
}

// ipInNets reports whether val is a valid IP inside one of the excluded subnets. Non-IP values
// (e.g. hostnames in a dns answers list) return false.
func ipInNets(val string, nets []*net.IPNet) bool {
	ip := net.ParseIP(val)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

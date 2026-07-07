package types

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// addressFields is the set of Zeek log column names that hold a single IP
// address we filter on. Located by name via the log's #fields header (never by
// hardcoded index) so the same code path covers every uploaded log:
//   - conn, dns, ja3_ja4, ja4s: id.orig_h, id.resp_h
//   - dhcp: client_addr, server_addr, requested_addr, assigned_addr
//
// A column name only appears here where it is genuinely an address, so keying
// off the name alone is safe across all five logs.
var addressFields = map[string]bool{
	"id.orig_h":      true,
	"id.resp_h":      true,
	"client_addr":    true,
	"server_addr":    true,
	"requested_addr": true,
	"assigned_addr":  true,
}

// addressSetFields names Zeek columns that hold a set/vector of values (joined
// by the log's #set_separator) which may include IP addresses. dns.log "answers"
// is the case that matters: a DNS reply resolving to an excluded-subnet IP would
// otherwise leak that internal address even when the client/resolver are not in
// an excluded subnet. Each element is checked individually; non-IP members
// (CNAMEs, MX targets, TXT data, ...) are ignored.
var addressSetFields = map[string]bool{
	"answers": true,
}

// zeekUnsetMarkers are the placeholder tokens Zeek writes for an absent value.
// They are not addresses and must be skipped, not parsed.
var zeekUnsetMarkers = map[string]bool{
	"-":       true,
	"(empty)": true,
}

// FilterExcludedSubnets rewrites each of the given Zeek TSV logs in runDir in
// place, dropping any data row that references an excluded-subnet address —
// either a source/destination address column (see addressFields) or an IP in a
// set-valued column such as dns.log "answers" (see addressSetFields). Header/
// footer lines (#separator, #fields, #types, #open, #close, ...) are preserved
// verbatim. Missing log files are a no-op (JA3/JA4 may be absent, e.g. on
// Linux). An empty/whitespace CIDR list turns the feature off.
//
// Filtering is a "do not upload it" guarantee, so any read/parse/write failure
// on a present log is returned as an error rather than swallowed — the caller
// aborts the capture window rather than risk uploading unfiltered data.
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

// filterLogFile drops excluded rows from a single Zeek TSV log, in place.
func filterLogFile(logPath string, nets []*net.IPNet) error {
	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read: %w", err)
	}

	lines := strings.Split(string(data), "\n")

	sep := "\t"
	setSep := ","
	var addrIdx []int // single-IP columns
	var setIdx []int  // set-of-values columns (e.g. dns answers)
	for _, line := range lines {
		if strings.HasPrefix(line, "#separator") {
			sep = parseSeparator(line)
			continue
		}
		if strings.HasPrefix(line, "#set_separator") {
			// Delimited by the main separator, which is already known by now.
			if parts := strings.Split(line, sep); len(parts) >= 2 && parts[1] != "" {
				setSep = parts[1]
			}
			continue
		}
		if strings.HasPrefix(line, "#fields") {
			// Drop the "#fields" token so the remaining indices align with data columns.
			fields := strings.Split(line, sep)[1:]
			for i, f := range fields {
				switch {
				case addressFields[f]:
					addrIdx = append(addrIdx, i)
				case addressSetFields[f]:
					setIdx = append(setIdx, i)
				}
			}
			break
		}
	}
	// No #fields header, or no address columns in this log: nothing to filter.
	if len(addrIdx) == 0 && len(setIdx) == 0 {
		return nil
	}

	out := make([]string, 0, len(lines))
	dropped := 0
	for _, line := range lines {
		// Preserve every header/footer line and the trailing empty element
		// (which round-trips a final newline) exactly as-is.
		if line == "" || strings.HasPrefix(line, "#") {
			out = append(out, line)
			continue
		}
		if rowExcluded(strings.Split(line, sep), addrIdx, setIdx, setSep, nets) {
			dropped++
			continue
		}
		out = append(out, line)
	}

	if dropped == 0 {
		return nil
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(out, "\n")), 0644); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	log.Printf("[processor] Subnet filter dropped %d row(s) from %s", dropped, filepath.Base(logPath))
	return nil
}

// rowExcluded reports whether the row references an excluded-subnet IP in any
// single-IP column (addrIdx) or any set-valued column (setIdx, split on setSep).
func rowExcluded(cols []string, addrIdx, setIdx []int, setSep string, nets []*net.IPNet) bool {
	for _, idx := range addrIdx {
		if idx < len(cols) && ipInNets(cols[idx], nets) {
			return true
		}
	}
	for _, idx := range setIdx {
		if idx >= len(cols) {
			continue
		}
		cell := cols[idx]
		if cell == "" || zeekUnsetMarkers[cell] {
			continue
		}
		for _, v := range strings.Split(cell, setSep) {
			if ipInNets(v, nets) {
				return true
			}
		}
	}
	return false
}

// ipInNets reports whether val is a valid IP inside one of the excluded subnets.
// Zeek unset markers and non-IP values (e.g. hostnames in a dns answers set)
// return false.
func ipInNets(val string, nets []*net.IPNet) bool {
	if val == "" || zeekUnsetMarkers[val] {
		return false
	}
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

// parseSeparator decodes a Zeek "#separator" header line. Zeek writes the
// separator as an escape (e.g. "#separator \x09" for tab) using a literal space
// delimiter, since the separator cannot delimit its own definition. Defaults to
// tab if the line is malformed.
func parseSeparator(line string) string {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return "\t"
	}
	sep := strings.TrimSpace(parts[1])
	if strings.HasPrefix(sep, `\x`) {
		if b, err := strconv.ParseUint(sep[2:], 16, 8); err == nil {
			return string(rune(b))
		}
	}
	if sep == "" {
		return "\t"
	}
	return sep
}

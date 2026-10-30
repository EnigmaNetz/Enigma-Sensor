package flowlogs

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

const (
	// rootRefresh is how often the whole container is listed to find the flow log roots (one
	// per flow log resource). Between those listings each poll lists only the days in its
	// lookback under each root. The full listing also catches any recent blob a daily listing
	// missed.
	rootRefresh = time.Hour

	// blobSuffix ends every flow log blob's name; anything else in the container is ignored.
	blobSuffix = "/PT1H.json"

	// learnReadBytes is the first read of a NIC's newest blob made to learn its addresses before
	// any blob is converted. A busy NIC's first record can be larger, so the read doubles up to
	// maxLearnRead.
	learnReadBytes = 256 << 10
	maxLearnRead   = 4 << 20

	// giveUpAfter is how long a blob may keep failing with an error about that blob alone (not
	// permissions, throttling, the service or the network) before it is given up on, so it does
	// not hold its NIC's later blobs for good. A blob that is gone (404) is given up on at once.
	giveUpAfter = 2 * time.Hour
)

// Read limits, variables so tests can lower them. pollReadBudget bounds the bytes downloaded
// in one poll, and so the memory a poll holds; a poll that hits it runs again straight away.
// maxBlobRead bounds one blob's read, except that a record larger than that is read whole, up
// to maxRecordRead.
var (
	pollReadBudget int64 = 16 << 20
	maxBlobRead    int64 = 16 << 20
	maxRecordRead  int64 = 256 << 20
)

// list returns the flow log blobs worth reading this poll, from every account, sorted by key:
// every tracked blob, and every other blob changed since trackWindow before the last committed
// poll that listed its account (or before now, on a first start), back to maxLookback at most.
// Blobs are named by their key (see account). Every blob it returns is tracked in st from then
// on, so a poll that reads none of them (it ran out of budget, say) cannot let them fall out of
// the next poll's lookback. The date in the path sorts each NIC's hourly blobs into order, and
// the converter needs each NIC's tuples in order.
//
// An account that cannot be listed is left out of this poll and returned in down with its
// error; err is set only when no account could be listed.
func (p *Poller) list(ctx context.Context, st *State, now time.Time) (out []BlobInfo, down map[*account]error, err error) {
	down = map[*account]error{}
	for _, a := range p.accounts {
		// While the others are read through a backlog, polls run back to back; an account that
		// failed is tried again once per interval, not every poll
		if len(p.accounts) > 1 && a.listErr != nil && now.Sub(a.listFailedAt) < p.cfg.Interval {
			down[a] = a.listErr
			continue
		}
		blobs, err := p.listAccount(ctx, a, st, now)
		if err != nil {
			a.listErr, a.listFailedAt = p.wrap(a, err), now
			down[a] = a.listErr
			continue
		}
		a.listErr = nil
		out = append(out, blobs...)
	}
	if len(down) == len(p.accounts) {
		if len(down) == 1 {
			return nil, nil, down[p.accounts[0]]
		}
		errs := make([]error, len(p.accounts))
		for i, a := range p.accounts {
			errs[i] = down[a]
		}
		return nil, nil, errors.Join(errs...)
	}
	// Keys sort by account (every other account's start with @, before the first account's) and
	// then by blob name. Only the order within a NIC matters, and a NIC's blobs are all in one
	// account
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, down, nil
}

// listAccount lists one account's blobs for list.
func (p *Poller) listAccount(ctx context.Context, a *account, st *State, now time.Time) ([]BlobInfo, error) {
	base := now
	if last := st.lastPoll(a); !last.IsZero() && last.Before(now) {
		base = last
	}
	wanted := base.Add(-trackWindow)
	cutoff := wanted
	if floor := now.Add(-maxLookback); cutoff.Before(floor) {
		cutoff = floor
	}

	var found []BlobInfo
	if a.roots == nil || now.Sub(a.rootsAt) >= rootRefresh {
		all, err := a.Store.List(ctx, "")
		if err != nil {
			return nil, err
		}
		a.roots, a.rootsAt = roots(all), now
		found = all
	} else {
		for _, prefix := range dayPrefixes(a.roots, cutoff, now) {
			blobs, err := a.Store.List(ctx, prefix)
			if err != nil {
				return nil, err
			}
			found = append(found, blobs...)
		}
	}
	var out []BlobInfo
	skipped := 0
	for _, b := range found {
		if !strings.HasSuffix(b.Name, blobSuffix) {
			continue
		}
		b.Name = a.key(b.Name)
		bs, tracked := st.Blobs[b.Name]
		switch {
		case tracked:
		case !b.LastModified.Before(cutoff):
			bs = &BlobState{}
			st.Blobs[b.Name] = bs
		case !b.LastModified.Before(wanted):
			skipped++
			continue
		default:
			continue
		}
		bs.Size, bs.LastModified = b.Size, b.LastModified
		out = append(out, b)
	}
	if skipped > 0 {
		log.Printf("[flowlogs] Skipping %d flow log blob(s)%s last changed more than %v ago, while the sensor was stopped or failing", skipped, p.in(a), maxLookback)
	}
	return out, nil
}

// in names the account in a log line, when there is more than one to tell apart.
func (p *Poller) in(a *account) string {
	if len(p.accounts) == 1 {
		return ""
	}
	return " in storage account " + a.Name
}

// roots returns the distinct flow log roots (the path before /y=) in a listing.
func roots(blobs []BlobInfo) []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range blobs {
		i := strings.Index(b.Name, "/y=")
		if i < 0 || !strings.HasSuffix(b.Name, blobSuffix) {
			continue
		}
		if root := b.Name[:i]; !seen[root] {
			seen[root] = true
			out = append(out, root)
		}
	}
	sort.Strings(out)
	return out
}

// dayPrefixes returns the listing prefixes for every UTC day from from to to.
func dayPrefixes(roots []string, from, to time.Time) []string {
	var days []time.Time
	for d := from.UTC().Truncate(24 * time.Hour); !d.After(to); d = d.Add(24 * time.Hour) {
		days = append(days, d)
	}
	var out []string
	for _, root := range roots {
		for _, d := range days {
			out = append(out, fmt.Sprintf("%s/y=%04d/m=%02d/d=%02d/", root, d.Year(), int(d.Month()), d.Day()))
		}
	}
	return out
}

// blobMAC returns the NIC a blob belongs to, from the macAddress= part of its name, or "".
func blobMAC(name string) string {
	_, rest, ok := strings.Cut(name, "/macAddress=")
	if !ok {
		return ""
	}
	mac, _, _ := strings.Cut(rest, "/")
	return strings.ToUpper(mac)
}

// learnNewNICs reads the start of the newest blob of each NIC whose addresses are not known
// yet, and teaches conv its addresses. When a backlog takes several polls to read, a
// destination NIC's older blobs can be converted before the source NIC's are read; knowing every
// NIC's addresses first keeps those flows deduplicated. The reads count against budget, and it
// returns false when the budget ran out before every NIC was tried. A NIC whose blob fails to
// download is skipped: its own blobs fail too, and read reports the error.
func (p *Poller) learnNewNICs(ctx context.Context, st *State, blobs []BlobInfo, conv *Converter, budget *readBudget) bool {
	newest := map[string]BlobInfo{}
	for _, b := range blobs {
		if mac := blobMAC(b.Name); mac != "" {
			newest[mac] = b // blobs are sorted, so the last one is the newest
		}
	}
	// Forget blobs that are no longer a NIC's newest, so the set does not grow for good
	for name := range p.noAddress {
		if newest[blobMAC(name)].Name != name {
			delete(p.noAddress, name)
		}
	}
	macs := make([]string, 0, len(newest))
	for mac, b := range newest {
		if _, known := st.Converter.PrivateIP[mac]; !known && !p.noAddress[b.Name] {
			macs = append(macs, mac)
		}
	}
	sort.Strings(macs)
	for _, mac := range macs {
		if budget.left <= 0 {
			return false
		}
		b := newest[mac]
		c, err := p.readChunk(ctx, b.Name, 0, b.Size, learnReadBytes, maxLearnRead, budget)
		if err != nil {
			continue
		}
		if c.outOfBudget {
			return false
		}
		for _, r := range c.recs {
			_, _ = parseRecord(r.data, r.pos, conv.Learn)
		}
		if _, known := st.Converter.PrivateIP[mac]; !known {
			// Nothing to learn in this blob; try the NIC again when it has a newer one
			p.noAddress[b.Name] = true
		}
	}
	return true
}

// read downloads the new part of each blob and returns its complete records, advancing each
// blob's offset in st past them. readErrs holds each account's first download failure, for Run
// to report.
//
// A NIC's tuples must be converted in order, so once one of its blobs is not read to the end
// (a failed download, or a read limit), its later blobs wait for the next poll. more is true
// only when a read limit stopped a blob after making progress, so an immediate next poll has
// something to do; a failed download waits for the next interval.
func (p *Poller) read(ctx context.Context, st *State, blobs []BlobInfo, now time.Time, budget *readBudget) (recs []rawRecord, read int, more bool, readErrs map[*account]error) {
	readErrs = map[*account]error{}
	held := map[string]bool{}
	for _, b := range blobs {
		nic := blobMAC(b.Name)
		if nic == "" {
			nic = b.Name
		}
		bs := st.Blobs[b.Name]
		if bs.Abandoned || b.Size == bs.Scanned || held[nic] {
			continue
		}
		if b.Size < bs.Offset {
			log.Printf("[flowlogs] %s shrank from %d to %d bytes; skipping to its end", b.Name, bs.Offset, b.Size)
			bs.Offset, bs.Scanned = b.Size, b.Size
			continue
		}
		if budget.left <= 0 {
			held[nic], more = true, true
			continue
		}
		remaining := b.Size - bs.Offset
		c, err := p.readChunk(ctx, b.Name, bs.Offset, remaining, maxBlobRead, maxRecordRead, budget)
		if err != nil {
			if a, _ := p.owner(b.Name); readErrs[a] == nil {
				readErrs[a] = p.wrap(a, err)
			}
			held[nic] = true
			p.blobFailed(b.Name, bs, err, now)
			continue
		}
		bs.FailingSince = nil
		if c.outOfBudget {
			held[nic], more = true, true
			continue
		}
		recs = append(recs, c.recs...)
		if len(c.recs) > 0 {
			read++
		}
		bs.Offset = c.next
		switch {
		case c.bad != nil:
			// The records before it are kept; the rest of this blob is lost, not the NIC
			log.Printf("[flowlogs] Skipping the rest of %s from byte %d: %v", b.Name, c.next, c.bad)
			bs.Abandoned = true
		case c.size < remaining:
			held[nic], more = true, true
		default:
			bs.Scanned = b.Size
		}
	}
	return recs, read, more, readErrs
}

// blobFailed records a failed download. Only an error about this blob gives it up: at once if
// the blob is gone, after giveUpAfter of failing otherwise. A missing permission, throttling,
// an outage or a network failure affects every blob and passes, so it never loses data.
func (p *Poller) blobFailed(name string, bs *BlobState, err error, now time.Time) {
	gone, aboutBlob := blobFault(err)
	if !aboutBlob {
		bs.FailingSince = nil
		return
	}
	if bs.FailingSince == nil {
		bs.FailingSince = &now
	}
	if gone || now.Sub(*bs.FailingSince) >= giveUpAfter {
		log.Printf("[flowlogs] Giving up on %s from byte %d, failing since %s: %v", name, bs.Offset, bs.FailingSince.Format(time.RFC3339), err)
		bs.Abandoned = true
	}
}

// readBudget is what one poll may still download: left bytes, and whether a read has already
// gone past the budget to finish a record (see readChunk).
type readBudget struct {
	left     int64
	overshot bool
}

// chunk is what readChunk read from one blob.
type chunk struct {
	// recs are the complete records read, and next the offset just past the last of them.
	recs []rawRecord
	next int64
	// size is how many bytes were read from the offset.
	size int64
	// bad is set when the scan stopped at a record that cannot be read, or one larger than
	// the read may grow; the blob is given up on from next.
	bad error
	// outOfBudget is set when no whole record fit in what the poll's budget allowed; the blob
	// is read again next poll.
	outOfBudget bool
}

// readChunk reads a blob from offset, first up to first bytes, and scans it for records. When
// no whole record fits, it reads further, doubling the size up to most, until one does or the
// blob ends. Every byte downloaded is charged to budget and downloaded once. It stops at the
// budget, except that once per poll (budget.overshot) it may go past it to finish one record, so a
// record larger than the whole budget is still read. Doubling can read up to twice the record's
// size, and never more than most.
// err is set only when a download failed.
func (p *Poller) readChunk(ctx context.Context, name string, offset, remaining, first, most int64, budget *readBudget) (chunk, error) {
	var data []byte
	limit := min(remaining, first, budget.left) // callers only read with budget left
	overshooting := false
	a, blob := p.owner(name)
	for {
		part, err := a.Store.Read(ctx, blob, offset+int64(len(data)), limit-int64(len(data)))
		if err != nil {
			return chunk{}, err
		}
		budget.left -= int64(len(part))
		data = append(data, part...)
		recs, next, scanErr := scanRecords(name, data, offset)
		c := chunk{recs: recs, next: next, size: int64(len(data)), bad: scanErr}
		if len(recs) > 0 || scanErr != nil || c.size >= remaining {
			return c, nil
		}
		// No whole record in what was read
		if limit >= most {
			c.bad = fmt.Errorf("a record at byte %d is larger than %d bytes", offset, most)
			return c, nil
		}
		grow := min(limit*2, remaining, most) - limit
		if grow > budget.left && !overshooting {
			if budget.overshot {
				c.outOfBudget = true
				return c, nil
			}
			budget.overshot, overshooting = true, true
		}
		limit += grow
	}
}

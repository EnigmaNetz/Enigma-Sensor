package flowlogs

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// stateVersion is the layout of the state file. A file of another version is set aside and
// the poller starts fresh.
const stateVersion = 1

// State is what the poller saves between polls and restarts: how far each blob has been read,
// and the converter's open connections. It is saved only after the records it produced are
// uploaded or buffered, so a crash or a lost upload rereads the same input instead of losing
// it.
type State struct {
	Version int `json:"version"`
	// LastPoll is when a poll was last committed, within ten minutes. After the sensor has been
	// stopped or failing, the next poll looks back to it, so the blobs written meanwhile are read.
	// It is the first storage account's; AccountPolls holds every other account's, by name, so
	// an account that cannot be listed keeps its lookback while the others are read.
	LastPoll     time.Time             `json:"last_poll"`
	AccountPolls map[string]time.Time  `json:"account_polls,omitempty"`
	Blobs        map[string]*BlobState `json:"blobs"`
	Converter    *ConverterState       `json:"converter"`
}

// lastPoll returns when a poll that listed a was last committed.
func (s *State) lastPoll(a *account) time.Time {
	if a.prefix == "" {
		return s.LastPoll
	}
	return s.AccountPolls[a.Name]
}

func (s *State) setLastPoll(a *account, t time.Time) {
	if a.prefix == "" {
		s.LastPoll = t
		return
	}
	if s.AccountPolls == nil {
		s.AccountPolls = map[string]time.Time{}
	}
	s.AccountPolls[a.Name] = t
}

// BlobState records how far one blob has been read.
type BlobState struct {
	// Offset is the byte just past the last record read. The blob's closing ]} and any record
	// still being written lie past it.
	Offset int64 `json:"offset"`
	// Scanned is the blob size whose records have all been read; while the listed size equals
	// it there is nothing new.
	Scanned int64 `json:"scanned"`
	// Size and LastModified are from the latest listing.
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
	// FailingSince is when downloads of this blob started failing with an error about the blob
	// itself, if they are failing.
	FailingSince *time.Time `json:"failing_since,omitempty"`
	// Abandoned is set when a blob holds a record that cannot be read, is gone, or keeps failing
	// to download; the rest of it is skipped so the NIC's later blobs are not held up behind it.
	Abandoned bool `json:"abandoned,omitempty"`
}

// done reports whether everything in the blob has been read or given up on.
func (b *BlobState) done() bool {
	return b.Abandoned || b.Scanned == b.Size
}

func newState() *State {
	return &State{Version: stateVersion, Blobs: map[string]*BlobState{}, Converter: NewConverterState()}
}

// decodeState parses a saved state.
func decodeState(data []byte) (*State, error) {
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("state version %d, want %d", s.Version, stateVersion)
	}
	if s.Blobs == nil {
		s.Blobs = map[string]*BlobState{}
	}
	if s.Converter == nil {
		s.Converter = NewConverterState()
	}
	s.Converter.init()
	// A damaged file can hold null entries; dropping them costs at most a reread
	for name, bs := range s.Blobs {
		if bs == nil {
			delete(s.Blobs, name)
		}
	}
	for key, sess := range s.Converter.Sessions {
		if sess == nil {
			delete(s.Converter.Sessions, key)
		}
	}
	return &s, nil
}

// loadState reads the state file, returning it encoded. A missing file is an empty state. A
// file that cannot be read as state is renamed to <path>.corrupt and an empty state returned,
// so the sensor keeps running; the cost is rereading the blobs still in the tracking window.
func loadState(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return json.Marshal(newState())
	}
	if err != nil {
		return nil, fmt.Errorf("read flow log state: %w", err)
	}
	if _, err := decodeState(data); err != nil {
		aside := path + ".corrupt"
		log.Printf("[flowlogs] State file %s is unreadable (%v); moving it to %s and starting fresh", path, err, aside)
		if err := os.Rename(path, aside); err != nil {
			return nil, fmt.Errorf("set aside unreadable flow log state: %w", err)
		}
		return json.Marshal(newState())
	}
	return data, nil
}

// saveState writes the state under a temporary name, syncs it and renames it over the old one,
// so a crash leaves either the old state or the new one, never part of one. It holds addresses
// seen on the customer's network, so only the sensor's user can read it.
func saveState(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create flow log state dir: %w", err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write flow log state: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write flow log state: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("sync flow log state: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close flow log state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("finalize flow log state: %w", err)
	}
	return nil
}

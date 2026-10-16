package flowlogs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// BlobInfo describes one blob in a listing.
type BlobInfo struct {
	Name         string
	Size         int64
	LastModified time.Time
}

// BlobStore is the part of Azure Blob Storage the poller uses, so tests can fake it.
type BlobStore interface {
	// List returns the blobs whose names start with prefix.
	List(ctx context.Context, prefix string) ([]BlobInfo, error)
	// Read returns count bytes of blob name starting at offset.
	Read(ctx context.Context, name string, offset, count int64) ([]byte, error)
}

// rawRecord is one record of a blob's records array, undecoded, with its position.
type rawRecord struct {
	data []byte
	pos  string
}

// scanRecords finds the complete records in data, which holds a flow log blob from byte offset
// onward. A blob is one JSON object, {"records":[...]}, that Azure grows once a minute by adding
// records to the array, so only the bytes after the last record already read need fetching.
//
// It returns the records and the offset just past the last complete one, which is where the
// next read starts. A record cut short at the end of data is left for the next read, so the
// scanner works whether or not the blob ends with the array's closing "]}" yet, and whatever
// size the read was limited to. At offset 0, data must start with the {"records":[ header.
func scanRecords(name string, data []byte, offset int64) ([]rawRecord, int64, error) {
	i := 0
	if offset == 0 {
		n, err := scanHeader(data)
		if err != nil || n == 0 {
			return nil, 0, err
		}
		i = n
	}
	var recs []rawRecord
	next := offset + int64(i)
	for {
		for i < len(data) && (isSpace(data[i]) || data[i] == ',') {
			i++
		}
		if i == len(data) || data[i] == ']' {
			return recs, next, nil
		}
		if data[i] != '{' {
			return recs, next, fmt.Errorf("%s at byte %d: want a record, got %q", name, offset+int64(i), data[i])
		}
		dec := json.NewDecoder(bytes.NewReader(data[i:]))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				// The rest of this record is not written (or not read) yet
				return recs, next, nil
			}
			return recs, next, fmt.Errorf("%s at byte %d: %w", name, offset+int64(i), err)
		}
		end := i + int(dec.InputOffset())
		recs = append(recs, rawRecord{data: data[i:end], pos: fmt.Sprintf("%s@%d", name, offset+int64(i))})
		i = end
		next = offset + int64(i)
	}
}

// scanHeader returns the length of the {"records":[ header at the start of data, or 0 when data
// ends before the header does.
func scanHeader(data []byte) (int, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	want := []json.Token{json.Delim('{'), "records", json.Delim('[')}
	for _, w := range want {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, nil
			}
			return 0, fmt.Errorf("not a flow log blob: %w", err)
		}
		if tok != w {
			return 0, fmt.Errorf("not a flow log blob: want %v, got %v", w, tok)
		}
	}
	return int(dec.InputOffset()), nil
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

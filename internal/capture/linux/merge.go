//go:build linux || darwin

package linux

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// pcapSource is one input file in a merge, holding its next unread packet.
type pcapSource struct {
	path   string
	file   *os.File
	reader *pcapgo.Reader
	data   []byte
	ci     gopacket.CaptureInfo
	done   bool
}

// next reads the source's next packet. A file cut short mid-packet (tcpdump
// killed on shutdown) ends the source instead of failing the merge.
func (s *pcapSource) next() error {
	data, ci, err := s.reader.ReadPacketData()
	if err == io.EOF {
		s.done = true
		return nil
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		log.Printf("[capture] %s ends in a truncated packet; keeping the packets before it", s.path)
		s.done = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read packet from %s: %w", s.path, err)
	}
	s.data, s.ci = data, ci
	return nil
}

// mergePcapFiles merges pcap files into outputFile in timestamp order, so a
// multi-interface capture keeps every interface's packets. All inputs must share
// a link type, since a pcap file can hold only one.
func mergePcapFiles(inputFiles []string, outputFile string) (err error) {
	if len(inputFiles) == 0 {
		return errors.New("no pcap files to merge")
	}
	sources := make([]*pcapSource, 0, len(inputFiles))
	defer func() {
		for _, s := range sources {
			s.file.Close()
		}
	}()

	for _, path := range inputFiles {
		f, openErr := os.Open(path)
		if openErr != nil {
			return fmt.Errorf("failed to open %s: %w", path, openErr)
		}
		r, readErr := pcapgo.NewReader(bufio.NewReader(f))
		if readErr != nil {
			f.Close()
			return fmt.Errorf("failed to read pcap header from %s: %w", path, readErr)
		}
		sources = append(sources, &pcapSource{path: path, file: f, reader: r})
	}

	linkType := sources[0].reader.LinkType()
	var snaplen uint32
	nanos := false
	for _, s := range sources {
		if s.reader.LinkType() != linkType {
			return fmt.Errorf("cannot merge %s (link type %s) with %s (link type %s): set capture.interface to \"any\", or list only interfaces with the same link type",
				sources[0].path, linkType, s.path, s.reader.LinkType())
		}
		if s.reader.Snaplen() > snaplen {
			snaplen = s.reader.Snaplen()
		}
		if s.reader.Resolution() == gopacket.TimestampResolutionNanosecond {
			nanos = true
		}
	}

	out, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", outputFile, err)
	}
	defer func() {
		if closeErr := out.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("failed to close %s: %w", outputFile, closeErr)
		}
		if err != nil {
			os.Remove(outputFile)
		}
	}()

	buf := bufio.NewWriter(out)
	w := pcapgo.NewWriter(buf)
	if nanos {
		w = pcapgo.NewWriterNanos(buf)
	}
	if err := w.WriteFileHeader(snaplen, linkType); err != nil {
		return fmt.Errorf("failed to write pcap header: %w", err)
	}

	for _, s := range sources {
		if err := s.next(); err != nil {
			return err
		}
	}

	// Few inputs (one per interface), so a linear scan for the earliest packet is enough
	for {
		var earliest *pcapSource
		for _, s := range sources {
			if !s.done && (earliest == nil || s.ci.Timestamp.Before(earliest.ci.Timestamp)) {
				earliest = s
			}
		}
		if earliest == nil {
			break
		}
		if err := w.WritePacket(earliest.ci, earliest.data); err != nil {
			return fmt.Errorf("failed to write packet to %s: %w", outputFile, err)
		}
		if err := earliest.next(); err != nil {
			return err
		}
	}

	if err := buf.Flush(); err != nil {
		return fmt.Errorf("failed to write %s: %w", outputFile, err)
	}
	return nil
}

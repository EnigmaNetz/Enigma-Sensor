package types

// Processor defines the interface for platform-agnostic PCAP processing using Zeek.
// Implementations should process the given PCAP file and return XLSX file paths for both con.log and dns.log.
type Processor interface {
	ProcessPCAP(pcapPath string) (ProcessedData, error)
}

// ProcessedData represents the output of PCAP processing.
type ProcessedData struct {
	ConnPath string                 // XLSX file path for conn.xlsx
	DNSPath  string                 // XLSX file path for dns.xlsx
	Metadata map[string]interface{} // Additional processing metadata
}

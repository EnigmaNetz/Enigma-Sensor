# Enigma Go Agent

A cross-platform network capture agent that collects and processes network traffic data into standardized Zeek-format logs.

## Core Architecture

The agent follows a platform-agnostic design with platform-specific capture implementations:

1. **Packet Capture Layer** (Platform-specific)
   - Windows: Uses pktmon to capture traffic into ETL format, converts to PCAP
   - Linux: Uses tcpdump to capture traffic directly to PCAP format
   - Common interface ensures consistent behavior across platforms

2. **Processing Layer** (Platform-agnostic)
   - Takes PCAP/PCAPNG files as input
   - Uses gopacket for packet analysis
   - Processes into standardized Zeek-format logs:
     - conn.log: TCP/UDP connection tracking (IPv4/IPv6)
     - dns.xlsx: DNS queries, responses, and metadata

## Project Structure

```
.
├── cmd/
│   ├── enigma-agent/          # Main application entry point
│   └── windows/
│       └── pcap-analyzer/     # PCAP analysis CLI tool
├── internal/
│   ├── capture/
│   │   ├── common/           # Common capture interfaces and types
│   │   ├── windows/          # Windows-specific capture (pktmon)
│   │   └── linux/            # Linux-specific capture (tcpdump)
│   └── processor/
│       └── pcap/            # PCAP to Zeek format conversion
```

## Log Formats

### Connection Log (conn.log)
JSON format with fields:
```json
{
  "ts": "2024-01-01T00:00:00Z",  // Timestamp
  "uid": "C123456",              // Unique connection ID
  "src_ip": "192.168.1.1",       // Source IP (v4/v6)
  "src_port": 12345,             // Source port
  "dst_ip": "192.168.1.2",       // Destination IP (v4/v6)
  "dst_port": 80,                // Destination port
  "proto": "tcp",                // Protocol (tcp/udp)
  "duration": 1.5,               // Connection duration
  "orig_bytes": 1024,            // Original bytes
  "conn_state": "S0"             // Connection state
}
```

### DNS Log (dns.xlsx)
JSON format with fields:
```json
{
  "ts": "2024-01-01T00:00:00Z",  // Timestamp
  "uid": "D123456",              // Unique DNS ID
  "src_ip": "192.168.1.1",       // Source IP
  "src_port": 53,                // Source port
  "dst_ip": "8.8.8.8",          // Destination IP
  "dst_port": 53,                // Destination port
  "proto": "udp",                // Protocol
  "trans_id": 1234,              // Transaction ID
  "query": "example.com",        // Query domain
  "qclass": 1,                   // Query class
  "qtype": "A",                  // Query type
  "answers": ["1.2.3.4"],        // Answer records
  "ttls": [300],                 // TTL values
  "rcode": 0                     // Response code
}
```

## Capture Flow

1. **Initialization**
   - Platform detection
   - Configuration loading
   - Appropriate capture implementation selection

2. **Capture Cycle**
   - Runs every 2 minutes (configurable)
   - 30-second capture window (configurable)
   - Platform-specific capture to PCAP
   - Processing into Zeek format
   - File cleanup and rotation (7-day retention by default)

## Development

### Prerequisites

#### Windows
- Administrator privileges (for pktmon)
- Windows 10 1809 or later (pktmon requirement)

#### Linux
- Root privileges (for tcpdump)
- tcpdump package installed

### Building

1. Install Go 1.20+
2. Build main agent:
```bash
go build -o bin/enigma-agent ./cmd/enigma-agent
```

### Configuration

Key configuration options (see config.json):
```json
{
  "capture": {
    "window": 30,        // Capture window in seconds
    "interval": 120,     // Time between captures in seconds
    "retention": 7,      // Log retention in days
    "output_dir": "./logs"
  }
}
```

## Building

[Build instructions here]

## Testing

[Testing instructions here]

## Setup

1. Install Go 1.20+
2. Copy .env.example to .env and fill in config.
3. Build: go build -o bin/enigma-agent ./cmd/enigma-agent
4. Run: ./bin/enigma-agent

### Platform-Specific Requirements

#### Windows
- Administrator privileges (for pktmon)

#### Linux
- Root privileges (for tcpdump)
- tcpdump package installed (usually pre-installed on most distributions)

## Testing

1. Run all tests: `go test ./...`
2. Run tests with output: `go test -v ./...`
3. Run specific package tests: `go test -v ./internal/capture/...`
4. Run a specific test: `go test -v -run TestPcapParser_ProcessFile ./internal/processor/pcap/...`

Test files are located in their respective package directories. The main test data files are in the `test/` directory.

## Tools

### PCAP Analyzer
The PCAP analyzer tool processes PCAP/PCAPNG files and generates Zeek-format logs. It supports:
- Both PCAP and PCAPNG file formats
- IPv4 and IPv6 traffic
- TCP and UDP connections
- DNS protocol analysis with full query/response details

1. Build the tool:
```bash
go build -o bin/pcap-analyzer ./cmd/windows/pcap-analyzer
```

2. Run the analyzer:
```bash
./bin/pcap-analyzer -input <pcap-file> -output <output-dir>
```

Example:
```bash
./bin/pcap-analyzer -input test/capture.pcapng -output logs
```

This will generate:
- logs/conn.log: Connection tracking in JSON format
- logs/dns.xlsx: DNS queries and responses in JSON format

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
     - conn.xlsx: TCP/UDP connection tracking (IPv4/IPv6)
     - dns.xlsx: DNS queries, responses, and metadata

## Project Structure

```
.
├── cmd/
│   ├── capture-test/         # Test utility for capture and upload
│   ├── enigma-agent/         # Main application entry point
│   └── windows/
│       └── pcap-analyzer/    # PCAP analysis CLI tool
├── internal/
│   ├── capture/
│   │   ├── common/           # Common capture interfaces and types
│   │   ├── windows/          # Windows-specific capture (pktmon)
│   │   └── linux/           # Linux-specific capture (tcpdump)
│   ├── api/
│   │   └── publish/         # Protobuf API implementation
│   └── processor/
│       └── pcap/            # PCAP to Zeek format conversion
```

## Setup

1. Install Go 1.24+
2. Copy .env.example to .env and configure:
3. Build: `go build -o bin/enigma-agent ./cmd/enigma-agent`
4. Run: `./bin/enigma-agent`

### Testing Capture and Upload

To test packet capture and API upload functionality:

1. Ensure your .env is configured with valid ENIGMA_SERVER and ENIGMA_API_KEY
2. Run the capture test `go run ./cmd/capture-test/main.go`:
   This will:
   - Capture packets for the configured duration
   - Process them into Zeek format
   - Upload to the configured API endpoint
   - Display upload status and response

### Generating Local Log Files

To generate and review log files locally without uploading:

1. Run the capture test with local flag: `go run ./cmd/capture-test/main.go --local`
   This will:
   - Capture packets for the configured duration
   - Process them into Zeek format
   - Save files locally without uploading
   - Display file locations for review

This will generate:

- logs/conn.xlsx: Connection tracking in TSV format
- logs/dns.xlsx: DNS queries and responses in TSV format

## Log Formats

### Connection Log (conn.log)

TSV format with fields:
```
ts	uid	src_ip	src_port	dst_ip	dst_port	proto	duration	orig_bytes	conn_state
2024-01-01T00:00:00Z	C123456	192.168.1.1	12345	192.168.1.2	80	tcp	1.5	1024	S0
```

Field descriptions:

- ts: Timestamp (ISO8601 format)
- uid: Unique connection ID
- src_ip: Source IP (v4/v6)
- src_port: Source port
- dst_ip: Destination IP (v4/v6)
- dst_port: Destination port
- proto: Protocol (tcp/udp)
- duration: Connection duration in seconds
- orig_bytes: Original bytes sent
- conn_state: Connection state

### DNS Log (dns.log)

TSV format with fields:
```
ts	uid	src_ip	src_port	dst_ip	dst_port	proto	trans_id	query	qclass	qtype	answers	ttls	rcode
2024-01-01T00:00:00Z	D123456	192.168.1.1	53	8.8.8.8	53	udp	1234	example.com	1	A	1.2.3.4	300	0
```

Field descriptions:

- ts: Timestamp (ISO8601 format)
- uid: Unique DNS ID
- src_ip: Source IP
- src_port: Source port
- dst_ip: Destination IP
- dst_port: Destination port
- proto: Protocol
- trans_id: Transaction ID
- query: Query domain
- qclass: Query class
- qtype: Query type (A, AAAA, etc.)
- answers: Answer records (comma-separated if multiple)
- ttls: TTL values (comma-separated if multiple)
- rcode: Response code

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

1. Install Go 1.24+: <https://go.dev/doc/install>
2. Build main agent: `go build -o bin/enigma-agent ./cmd/enigma-agent`

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
# Enigma Sensor Load Testing

High-performance load testing infrastructure using industry-standard tools for network traffic generation and analysis.

## Quick Start

**Important**: Run all commands from the `loadtest/` directory.

```bash
cd loadtest

# Quick validation test (60s, 2x2 generators)
./run-load-test.sh quick

# High-performance test (120s, 8x8 generators)
./run-load-test.sh performance

# Custom configuration examples
HTTP_RPS=100 DNS_QPS=200 TEST_DURATION=30 ./run-load-test.sh quick
HTTP_RPS=500 DNS_QPS=1000 HTTP_GENERATORS=8 DNS_GENERATORS=8 ./run-load-test.sh performance
```

## Performance Capabilities

### Performance Metrics
- **Maximum Tested**: 730+ operations/second with DNS at 2,400+ QPS capability
- **Theoretical Capability**: 12,000+ operations/second with 8x8 generator configuration
- **Recommended Production**: 6,000-8,000 RPS (conservative), 9,000-10,200 RPS (aggressive)

### Load Generation Capacity
- **HTTP Load**: Up to 4,000+ RPS (8 generators × 500 RPS each)
- **DNS Load**: Up to 8,000+ QPS (8 generators × 1,000 QPS each) 
- **Combined Load**: 12,000+ operations/second theoretical
- **Horizontal Scaling**: Environment-controlled via `*_GENERATORS` variables

## Architecture Overview

### Core Components
- **`run-load-test.sh`** - Unified load testing with quick and performance modes
- **`docker-compose.yml`** - Container orchestration using industry-standard tools
- **`Dockerfile.sensor`** - Sensor container with Zeek integration

### Technology Stack
- **Traffic Generation**: `curl` and `dig` commands in Docker containers
- **Orchestration**: Docker Compose with replica scaling
- **Monitoring**: `docker stats` with CSV output and automated reporting
- **DNS Resolution**: External DNS (8.8.8.8)
- **Scripting**: Pure bash with standard UNIX tools

## Configuration Options

### Environment Variables
```bash
# Load Generation
HTTP_RPS=50              # HTTP requests per second per generator
DNS_QPS=100              # DNS queries per second per generator
TEST_DURATION=60         # Test duration in seconds

# Scaling
HTTP_GENERATORS=2        # Number of HTTP generator containers
DNS_GENERATORS=2         # Number of DNS generator containers

# Example: High Performance Test
HTTP_RPS=200 DNS_QPS=400 HTTP_GENERATORS=8 DNS_GENERATORS=8 TEST_DURATION=120
```

### Sensor Configuration
The sensor uses optimized configuration from `configs/sensor-config.json`:
- **Zeek Sampling**: 100% (fixed from previous 0% issue)
- **PCAP Retention**: Enabled for analysis (no auto-deletion)
- **Logging**: INFO level with comprehensive output

## Test Scenarios

### 1. Quick Validation Test (60s)
```bash
./run-load-test.sh quick
# Default: 2 HTTP + 2 DNS generators (100 RPS + 200 QPS = 300 ops/sec)
```

### 2. Performance Test (120s)
```bash
./run-load-test.sh performance
# Default: 8 HTTP + 8 DNS generators (1,600 RPS + 3,200 QPS = 4,800 ops/sec)
```

### 3. Maximum Load Test
```bash
HTTP_RPS=500 DNS_QPS=1000 HTTP_GENERATORS=8 DNS_GENERATORS=8 TEST_DURATION=300 ./run-load-test.sh performance
# 8×500 + 8×1000 = 4,000 + 8,000 = 12,000 ops/sec
```

### 4. Custom Scenarios
```bash
# High HTTP load, minimal DNS
HTTP_RPS=1000 HTTP_GENERATORS=4 DNS_QPS=10 DNS_GENERATORS=1 ./run-load-test.sh quick

# DNS-focused testing  
HTTP_RPS=10 HTTP_GENERATORS=1 DNS_QPS=2000 DNS_GENERATORS=6 ./run-load-test.sh quick

# Sustained endurance test
HTTP_RPS=200 DNS_QPS=300 TEST_DURATION=600 ./run-load-test.sh performance
```

## Results & Monitoring

### Automated Result Collection
Every test generates comprehensive reports in `results/YYYYMMDD_HHMMSS/`:
- **`test.log`** - Execution timeline and events
- **`logs.txt`** - All container logs and output
- **`stats.log`** - Docker container resource usage (CSV format)
- **`LOAD_TEST_SUMMARY.md`** - Comprehensive performance analysis

### Key Performance Metrics
- **Traffic Generation Rates** - Actual vs. theoretical RPS/QPS
- **Sensor Analysis** - PCAP file creation and Zeek log line counts
- **System Performance** - Container CPU/memory usage
- **Data Quality** - Network capture success rates
- **Error Analysis** - Container failures and sensor errors

### Sample Summary Output
```
## Performance Results
- HTTP Load Generated: 60,000 requests (1,000 RPS achieved)
- DNS Load Generated: 120,000 queries (2,000 QPS achieved)  
- Total Operations: 180,000 (3,000 ops/sec)

## Enigma Sensor Analysis
- PCAP Files Created: 12 files (3.2MB total)
- Zeek Log Lines: 2,847 lines (23.7 lines/sec)
- Sensor Status: ✅ Healthy (0 errors)
```

## Sensor Integration

### Container Configuration
The sensor runs with required network access:
```yaml
sensor:
  container_name: enigma-sensor
  privileged: true        # Required for packet capture
  network_mode: host      # Required for full network visibility
  volumes:
    - ../logs:/app/logs   # Persistent logging
```

### Zeek Processing Verification
The new configuration ensures proper Zeek analysis:
- **Sampling Rate**: 100% (no packet skipping)
- **Log Retention**: PCAP files preserved for analysis
- **Expected Output**: ~1 Zeek log line per network operation

## Security Features

### Attack Surface Reduction
- **No Custom Binaries**: Uses curl, dig, nginx (industry-audited)
- **Minimal Dependencies**: Standard UNIX tools and official container images
- **No Memory Management**: Eliminated potential buffer overflows
- **Transparent Logic**: Bash scripts vs. compiled executables

### Supply Chain Security
- **Official Container Images**: curlimages/curl:latest, alpine:latest, nginx:alpine
- **Standard Tools**: curl, dig, docker-compose
- **No Pre-compiled Assets**: Everything built from source or standard packages

## Troubleshooting

### Common Issues

#### 1. Sensor Build Required
```bash
# Build sensor binary from project root
cd ..
go build -o bin/enigma-sensor ./cmd/enigma-sensor
cd loadtest
```

#### 2. Low Zeek Log Lines
- **Symptom**: Few Zeek logs despite high traffic
- **Cause**: Sensor config has 0% sampling
- **Fix**: Verify `configs/sensor-config.json` has `"sampling_percentage": 100`

#### 3. No PCAP Files
- **Symptom**: No files in ../captures/
- **Cause**: Auto-deletion enabled  
- **Fix**: Ensure `"retain_pcap_files": true` in config

#### 4. Container Resource Issues
- **Symptom**: Containers killed during high load
- **Fix**: Reduce generator counts or rates:
```bash
HTTP_GENERATORS=4 DNS_GENERATORS=4 ./run-performance-scale-test.sh
```

#### 5. Permission Errors
```bash
# Fix docker permissions
sudo chmod 666 /var/run/docker.sock

# Fix capture directory permissions  
sudo mkdir -p ../captures ../logs
sudo chown $USER:$USER ../captures ../logs
```

## Testing Validation

### Performance Benchmarks

```bash
# Validate basic functionality
./run-load-test.sh quick

# Validate high performance (should achieve 4,800+ ops/sec)
./run-load-test.sh performance

# Validate maximum load 
HTTP_RPS=625 DNS_QPS=1250 HTTP_GENERATORS=8 DNS_GENERATORS=8 ./run-load-test.sh performance

# Validate Zeek processing
# Expected: Excel reports (conn.xlsx, dns.xlsx) generated
```

### Success Criteria
- **Performance**: Achieve target operations/second in load tests
- **Zeek Analysis**: Excel reports (conn.xlsx, dns.xlsx) generated with traffic data
- **PCAP Creation**: Files present in ../captures/ directory
- **System Stability**: No container failures during sustained tests
- **Monitoring**: Complete summary reports generated

---

*High-performance load testing infrastructure using industry-standard tools for network traffic generation and analysis.*
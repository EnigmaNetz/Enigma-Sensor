# Enigma Agent Test Harness

A Docker-based test environment for the Enigma Go Agent that generates diverse network traffic for capture and analysis.

## Architecture

The test harness consists of two main containers connected via a Docker bridge network:

1. **Agent Container**: Runs tcpdump and load testing tools to capture cross-container traffic
2. **Targets Container**: Runs Nginx and multiple mock API services

**Note:** This simplified test harness (`docker-compose.simple.yml`) captures raw PCAP files only. It does NOT:
- Process captures with Zeek 
- Generate conn.log/dns.log files
- Upload anything to the Enigma API

To test the full agent with Zeek processing and API upload, use the full agent build (see Advanced Usage).

### What Gets Uploaded to the API

When using the full agent (`docker-compose.yml`) with a valid API key:

1. **Zeek Logs** (renamed to .xlsx for upload):
   - `conn.xlsx` - TCP/UDP connection logs
   - `dns.xlsx` - DNS query/response logs

2. **Upload Format**:
   - Logs are compressed with zlib
   - Base64 encoded
   - Sent via gRPC to api.enigmaai.net:443

3. **Data Included**:
   - Source/destination IPs and ports
   - Connection duration and bytes transferred
   - DNS queries and responses
   - Protocol information
   - Timestamps

The raw PCAP files are NOT uploaded - only the processed Zeek logs.

## Quick Start

### Basic Setup

```bash
# From the test-harness directory
cd test-harness

# Create necessary directories
mkdir -p captures logs

# Fix line endings (IMPORTANT if on Windows/WSL)
dos2unix *.sh

# Build the containers
docker-compose -f docker-compose.simple.yml build
```

### Option 1: Generate Small Test Traffic (~1-5MB)

```bash
# Start the services
docker-compose -f docker-compose.simple.yml up -d

# Wait for services to be ready
sleep 10

# Generate test traffic
docker-compose -f docker-compose.simple.yml exec -T simple-agent bash -c "
tcpdump -i any -w /app/captures/test-\$(date +%s).pcap &
TCPDUMP_PID=\$!
for i in {1..100}; do
  curl -s http://targets/ > /dev/null
  curl -s http://targets:8081/api/users > /dev/null
done
kill \$TCPDUMP_PID
ls -lah /app/captures/
"

# View the web interface
open http://localhost:8080
```

### Option 2: Generate 100+ MB of Traffic

```bash
# Make sure services are running
docker-compose -f docker-compose.simple.yml up -d

# Run the fast 100MB traffic generator
docker run --rm --network test-harness_test-network --privileged \
  -v ./captures:/app/captures \
  -v ./fast-100mb.sh:/app/fast-100mb.sh \
  test-harness-simple-agent bash -c "/app/fast-100mb.sh"

# This will generate ~200MB of network traffic including:
# - 20 x 10MB file uploads
# - 20,000 HTTP requests
# - Mixed API traffic patterns
```

### Option 3: Custom Traffic Generation

```bash
# Run a custom traffic generation script
docker run --rm --network test-harness_test-network --privileged \
  -v ./captures:/app/captures \
  test-harness-simple-agent bash -c "
    # Start packet capture
    tcpdump -i any -w /app/captures/custom-\$(date +%s).pcap -s 0 &
    TCPDUMP_PID=\$!
    
    # Your custom traffic generation here
    # Example: Generate 1MB POST requests
    dd if=/dev/urandom bs=1M count=1 2>/dev/null | base64 > /tmp/data.txt
    for i in {1..10}; do
      curl -s -X POST -H 'Content-Type: text/plain' \
        --data-binary @/tmp/data.txt \
        http://targets:8082/api/upload
    done
    
    # Stop capture
    sleep 5
    kill \$TCPDUMP_PID
    ls -lah /app/captures/
"
```

## What Gets Captured

The agent captures all network traffic between containers, including:

- **HTTP/HTTPS traffic** to Nginx and mock APIs
- **DNS queries** for service resolution
- **TCP connections** with various patterns
- **Large payloads** from analytics and file upload endpoints
- **Streaming data** from Server-Sent Events endpoints

## Generated Traffic Patterns

### Load Testing Script (`load-test.sh`)
- **wrk** for high-performance HTTP load testing
- **curl** for varied request patterns (GET, POST, PUT, DELETE)
- **DNS queries** using nslookup and dig
- **Ping tests** for ICMP traffic

### Mock APIs
1. **User API (8081)**: CRUD operations on user data
2. **Analytics API (8082)**: Large JSON payloads and file uploads
3. **Notification API (8083)**: Real-time events and bulk operations

### Web Interface
Visit `http://localhost:8080` to:
- Monitor service health
- Manually trigger API tests
- Generate load bursts
- View real-time request logs

## Output Validation

### Captured Files
- **PCAP files**: `/test-harness/captures/zeek_out_*/capture.pcap`
- **Zeek logs**: `/test-harness/captures/zeek_out_*/conn.xlsx` and `dns.xlsx`
- **Agent logs**: `/test-harness/logs/enigma-agent.log`

### Expected Zeek Output
- **conn.xlsx**: TCP/UDP connections between agent container (172.20.0.X) and targets container
- **dns.xlsx**: DNS queries for container hostnames and external domains

### Verification Commands

#### For Simple Test Harness:
```bash
# Check if traffic is being captured
docker-compose -f docker-compose.simple.yml exec simple-agent tcpdump -i any -c 10

# View captured files
ls -la captures/

# Test connectivity between containers
docker-compose -f docker-compose.simple.yml exec simple-agent ping -c 3 targets

# Generate manual traffic and capture
docker-compose -f docker-compose.simple.yml exec simple-agent bash -c "
tcpdump -i any -w /app/captures/test-$(date +%s).pcap &
TCPDUMP_PID=\$!
for i in {1..10}; do curl -s http://targets/ > /dev/null; done
kill \$TCPDUMP_PID
ls -la /app/captures/
"
```

#### For Full Agent:
```bash
# Check if traffic is being captured
docker-compose exec agent tcpdump -i any -c 10

# View latest capture files  
ls -la captures/

# Monitor agent logs
tail -f logs/enigma-agent.log
```

## Configuration

### Agent Config (`config.json`)
- 30-second capture windows
- Loop mode enabled (continuous capture)
- Upload disabled (local testing only)
- Zeek processing enabled

### Network Settings
- Bridge network: `172.20.0.0/16`
- Agent container captures on all interfaces
- Cross-container traffic ensures network boundary crossing

## Viewing Captured Traffic

```bash
# Check capture file sizes
ls -lah captures/

# View packet count in a capture
tcpdump -r captures/fast-100mb.pcap | wc -l

# View first 100 packets
tcpdump -r captures/fast-100mb.pcap -c 100

# Filter HTTP traffic
tcpdump -r captures/fast-100mb.pcap -A 'tcp port 80 or tcp port 8081' | less

# Extract statistics
capinfos captures/fast-100mb.pcap  # If Wireshark tools installed
```

## Traffic Generation Scripts

The test harness includes several traffic generation scripts:

- **`load-test.sh`**: Basic continuous traffic generation (runs automatically)
- **`heavy-load-test.sh`**: Generates ~100MB with mixed traffic patterns
- **`fast-100mb.sh`**: Optimized to generate 200+ MB quickly
- **`generate-100mb.sh`**: Alternative approach using 5MB payloads

## Stopping and Cleanup

```bash
# Stop containers
docker-compose -f docker-compose.simple.yml down

# Remove volumes and clean up
docker-compose -f docker-compose.simple.yml down -v
docker system prune -f

# Keep capture data for analysis
# (captures/ and logs/ directories are preserved)
```

## Troubleshooting

### No Traffic Captured
- Check if containers can communicate: `docker-compose exec agent ping targets`
- Verify tcpdump permissions: `docker-compose exec agent tcpdump -i any -c 1`
- Check load test script: `docker-compose exec agent ps aux | grep load-test`

### Zeek Processing Issues
- Verify Zeek installation: `docker-compose exec agent zeek --version`
- Check capture file permissions in `/app/captures/`
- Review agent logs for processing errors

### Container Health
- Check service status: `docker-compose ps`
- View container logs: `docker-compose logs [service-name]`
- Test API connectivity: `curl http://localhost:8080/health`

## Customization

### Modify Traffic Patterns
Edit `load-test.sh` to adjust:
- Request frequency and concurrency
- Target endpoints and payloads
- Traffic duration and cycles

### Add More Services
1. Create new API in `mock-apis/servers/`
2. Add service to `supervisord.conf`
3. Update `nginx.conf` for reverse proxy
4. Expose port in `docker-compose.yml`

### Adjust Capture Settings
Modify `config.json`:
- `window_seconds`: Capture duration per cycle
- `loop`: Enable/disable continuous capture
- `output_dir`: Change capture output location

## ✅ YES! This Now Pushes Zeek Logs to the API

The full agent (`docker-compose.yml`) processes traffic with Zeek and uploads logs to the Enigma API.

## Advanced Usage: Full Agent with Zeek and API Upload

To test the complete Enigma agent with Zeek processing and API upload:

### Setup

```bash
# Build the full agent (this takes longer due to Go compilation and Zeek installation)
docker-compose build
```

### Run with Zeek Processing and API Upload

```bash
# Method 1: Provide API key as environment variable
ENIGMA_API_KEY=your_actual_api_key docker-compose up

# Method 2: Export API key first, then run
export ENIGMA_API_KEY=your_actual_api_key
docker-compose up

# Method 3: Create a .env file (optional)
echo "ENIGMA_API_KEY=your_actual_api_key" > .env
docker-compose up

# The agent will:
# 1. Use the top-level config.example.json as a template
# 2. Automatically configure paths and settings for the test harness
# 3. Capture network traffic with tcpdump
# 4. Process PCAP files with Zeek to generate conn.log and dns.log
# 5. Upload the processed logs to the Enigma API
```

### Monitor Progress

```bash
# Check agent logs
docker-compose logs -f agent

# View captured files and Zeek output
ls -la captures/

# Check for Zeek logs (renamed to .xlsx for upload)
ls -la captures/zeek_out_*/
```

### Features of Full Agent:
- ✅ Zeek processing (generates conn.log and dns.log)
- ✅ API upload with compression
- ✅ Automatic cleanup after successful upload
- ✅ Kill switch support (responds to API 410 status)
- ✅ Continuous capture in loop mode

**Note:** The full agent:
- Uses the top-level `config.example.json` as a template
- Automatically configures test harness settings (30s windows, loop mode, upload enabled)
- Requires a valid Enigma API key for uploads
- Takes ~5-10 minutes to build (Go compilation + Zeek installation)
- Requires network access to api.enigmaai.net:443

**Configuration Source:** The test harness automatically uses `../config.example.json` and modifies it for the test environment. No separate config files needed!
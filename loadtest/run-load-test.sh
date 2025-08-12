#!/bin/bash

# Unified Load Test Runner
# Supports both quick validation and high-performance testing

set -euo pipefail

# Test mode selection
MODE=${1:-quick}

# Set configuration based on mode
case "$MODE" in
    "quick"|"validation")
        # Quick validation test (60s)
        export HTTP_RPS=${HTTP_RPS:-50}
        export DNS_QPS=${DNS_QPS:-100}
        export TEST_DURATION=${TEST_DURATION:-60}
        export HTTP_GENERATORS=${HTTP_GENERATORS:-2}
        export DNS_GENERATORS=${DNS_GENERATORS:-2}
        TEST_TYPE="Quick Validation"
        ;;
    "performance"|"scale"|"high")
        # High-performance test (120s)
        export HTTP_RPS=${HTTP_RPS:-200}
        export DNS_QPS=${DNS_QPS:-400}
        export TEST_DURATION=${TEST_DURATION:-120}
        export HTTP_GENERATORS=${HTTP_GENERATORS:-8}
        export DNS_GENERATORS=${DNS_GENERATORS:-8}
        TEST_TYPE="High Performance"
        ;;
    *)
        echo "Usage: $0 [quick|performance]"
        echo ""
        echo "Modes:"
        echo "  quick       - Quick validation test (60s, 2x2 generators)"
        echo "  performance - High-performance test (120s, 8x8 generators)"
        echo ""
        echo "Environment variables (override defaults):"
        echo "  HTTP_RPS=N           - HTTP requests per second per generator"
        echo "  DNS_QPS=N            - DNS queries per second per generator"
        echo "  TEST_DURATION=N      - Test duration in seconds"
        echo "  HTTP_GENERATORS=N    - Number of HTTP generator containers"
        echo "  DNS_GENERATORS=N     - Number of DNS generator containers"
        echo ""
        echo "Examples:"
        echo "  $0 quick                    # Quick test with defaults"
        echo "  $0 performance              # Performance test with defaults"
        echo "  HTTP_RPS=100 $0 quick       # Custom quick test"
        exit 1
        ;;
esac

RESULTS_DIR="results/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

# Calculate theoretical performance
THEORETICAL_HTTP_RPS=$((HTTP_RPS * HTTP_GENERATORS))
THEORETICAL_DNS_QPS=$((DNS_QPS * DNS_GENERATORS))
THEORETICAL_TOTAL=$((THEORETICAL_HTTP_RPS + THEORETICAL_DNS_QPS))

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$RESULTS_DIR/test.log"
}

cleanup() {
    log "Cleaning up..."
    docker-compose down --remove-orphans 2>/dev/null || true
    jobs -p | xargs -r kill 2>/dev/null || true
}

trap cleanup EXIT

start_monitoring() {
    if [ "$MODE" = "performance" ] || [ "$MODE" = "scale" ] || [ "$MODE" = "high" ]; then
        log "Starting comprehensive performance monitoring..."
        
        # Enhanced monitoring for performance tests
        {
            echo "timestamp,container,cpu_percent,mem_usage_mb,mem_percent,net_rx_mb,net_tx_mb,pids"
            while true; do
                docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.PIDs}}" | tail -n +2 | while IFS=$'\t' read -r container cpu mem_usage mem_percent net_io pids; do
                    # Parse memory usage (e.g., "123.4MiB / 2GiB")
                    mem_used_mb=$(echo "$mem_usage" | awk '{print $1}' | sed 's/[^0-9.]//g')
                    
                    # Parse network I/O (e.g., "1.2MB / 3.4MB") 
                    net_rx=$(echo "$net_io" | awk '{print $1}' | sed 's/[^0-9.]//g')
                    net_tx=$(echo "$net_io" | awk '{print $3}' | sed 's/[^0-9.]//g')
                    
                    # Clean CPU percentage
                    cpu_clean=$(echo "$cpu" | sed 's/%//')
                    mem_percent_clean=$(echo "$mem_percent" | sed 's/%//')
                    
                    echo "$(date -Iseconds),$container,$cpu_clean,$mem_used_mb,$mem_percent_clean,$net_rx,$net_tx,$pids"
                done
                sleep 5
            done
        } > "$RESULTS_DIR/docker_performance_stats.csv" &
        
        # System performance monitoring
        {
            echo "timestamp,cpu_usage_percent,memory_usage_percent,load_avg_1min"
            while true; do
                cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')
                mem_usage=$(free | awk 'NR==2{printf "%.1f", $3*100/$2}')
                load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
                
                echo "$(date -Iseconds),$cpu_usage,$mem_usage,$load_avg"
                sleep 5
            done
        } > "$RESULTS_DIR/system_performance.csv" &
    else
        log "Starting basic monitoring..."
        
        # Basic monitoring for quick tests
        {
            echo "timestamp,container,cpu_percent,mem_usage,mem_percent"
            while true; do
                docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}" 2>/dev/null | tail -n +2 | while IFS=$'\t' read -r container cpu mem_usage mem_percent; do
                    echo "$(date -Iseconds),$container,$cpu,$mem_usage,$mem_percent"
                done
                sleep 5
            done
        } > "$RESULTS_DIR/stats.log" &
    fi
}

generate_summary() {
    log "Generating test summary with sensor metrics..."

    # Count actual requests from logs
    local http_requests=0
    local dns_completions=0
    if [ -f "$RESULTS_DIR/logs.txt" ]; then
        http_requests=$(grep -c "GET / HTTP" "$RESULTS_DIR/logs.txt" 2>/dev/null || echo "0")
        dns_completions=$(grep -c "DNS load completed" "$RESULTS_DIR/logs.txt" 2>/dev/null || echo "0")
    fi

    # Calculate actual rates
    local actual_http_rps=$((http_requests / TEST_DURATION))
    local actual_dns_qps=$((dns_completions * DNS_QPS))
    local actual_total_rps=$((actual_http_rps + actual_dns_qps))

    # Check sensor metrics (PCAP and Zeek data)
    local pcap_size="Unknown"
    local pcap_files=0
    local zeek_lines=0
    local sensor_errors=0

    # Look for sensor logs and data
    if [ -d "../captures" ]; then
        if ls ../captures/*/capture_*.pcap >/dev/null 2>&1; then
            pcap_files=$(ls ../captures/*/capture_*.pcap 2>/dev/null | wc -l)
            pcap_size=$(du -sh ../captures/*/capture_*.pcap 2>/dev/null | awk '{total+=$1} END {print total"KB"}' || echo "Unknown")
        fi

        # Count Excel report files (Zeek generates conn.xlsx and dns.xlsx)
        if ls ../captures/*/conn.xlsx >/dev/null 2>&1 || ls ../captures/*/dns.xlsx >/dev/null 2>&1; then
            zeek_lines=$(ls ../captures/*/conn.xlsx ../captures/*/dns.xlsx 2>/dev/null | wc -l)
        fi
    fi

    # Check for sensor errors in logs
    if [ -f "../logs/enigma-sensor.log" ]; then
        sensor_errors=$(grep -c "Error\|Failed" ../logs/enigma-sensor.log 2>/dev/null || echo "0")
    fi

    # Check Docker logs for sensor info
    local sensor_log_lines=0
    if [ -f "$RESULTS_DIR/logs.txt" ]; then
        sensor_log_lines=$(grep "enigma-sensor" "$RESULTS_DIR/logs.txt" | wc -l)
    fi

    # System resource analysis (for performance mode)
    local max_cpu="N/A"
    local max_memory="N/A"
    if [ -f "$RESULTS_DIR/system_performance.csv" ]; then
        max_cpu=$(tail -n +2 "$RESULTS_DIR/system_performance.csv" | cut -d',' -f2 | sort -n | tail -1 2>/dev/null || echo "N/A")
        max_memory=$(tail -n +2 "$RESULTS_DIR/system_performance.csv" | cut -d',' -f3 | sort -n | tail -1 2>/dev/null || echo "N/A")
    fi

    # Performance assessment
    local performance_status="MODERATE PERFORMANCE"
    local target_comparison="Below target"
    if [ "$actual_total_rps" -ge 10000 ]; then
        performance_status="HIGH PERFORMANCE"
        target_comparison="Exceeds target"
    elif [ "$actual_total_rps" -ge 5000 ]; then
        performance_status="GOOD PERFORMANCE"
        target_comparison="Strong performance"
    fi

    # Generate comprehensive summary
    cat > "$RESULTS_DIR/LOAD_TEST_SUMMARY.md" << EOF
# Load Test Performance Summary

**Test Type:** $TEST_TYPE Test
**Test Date:** $(date)
**Duration:** ${TEST_DURATION} seconds
**Configuration:** $HTTP_GENERATORS HTTP generators @ $HTTP_RPS RPS + $DNS_GENERATORS DNS generators @ $DNS_QPS QPS

## Performance Results

### Traffic Generation
- **HTTP Load Generated:** $http_requests requests ($actual_http_rps RPS achieved)
- **DNS Load Generated:** $((dns_completions * DNS_QPS * TEST_DURATION)) queries ($actual_dns_qps QPS achieved)
- **Total Operations:** $((http_requests + dns_completions * DNS_QPS * TEST_DURATION)) ($actual_total_rps ops/sec)

### Target vs Achieved
- **Target Rate:** $THEORETICAL_TOTAL ops/sec
- **Achieved Rate:** $actual_total_rps ops/sec
- **Efficiency:** $(echo "scale=1; $actual_total_rps * 100 / $THEORETICAL_TOTAL" | bc -l 2>/dev/null || echo "N/A")%

## Enigma Sensor Analysis

### Packet Capture (PCAP)
- **PCAP Files Created:** $pcap_files files
- **Total PCAP Size:** $pcap_size
- **Capture Duration:** ${TEST_DURATION}s

### Zeek Analysis
- **Zeek Reports Generated:** $zeek_lines Excel files
- **Expected Output:** conn.xlsx and dns.xlsx files with network analysis

### Sensor Health
- **Sensor Log Entries:** $sensor_log_lines entries
- **Sensor Errors:** $sensor_errors errors
- **Sensor Status:** $(if [ "$sensor_errors" -lt 5 ]; then echo "Healthy"; else echo "Issues detected"; fi)

## System Performance

### Resource Usage
$(if [ "$max_cpu" != "N/A" ]; then
    echo "- **Peak CPU Usage:** ${max_cpu}%"
    echo "- **Peak Memory Usage:** ${max_memory}%"
fi)
$(if [ -f "$RESULTS_DIR/stats.log" ]; then
    echo "### Container Resource Usage"
    tail -n 3 "$RESULTS_DIR/stats.log" 2>/dev/null || echo "No container stats available"
fi)

### Load Generator Performance
- **HTTP Generators:** $HTTP_GENERATORS containers ($(echo "scale=1; $actual_http_rps / $HTTP_GENERATORS" | bc -l 2>/dev/null || echo "N/A") RPS each)
- **DNS Generators:** $DNS_GENERATORS containers ($(echo "scale=1; $actual_dns_qps / $DNS_GENERATORS" | bc -l 2>/dev/null || echo "N/A") QPS each)

## Test Quality Assessment

**$performance_status**: $target_comparison

### Data Quality
- **Network Traffic Captured:** $(if [ "$pcap_files" -gt 0 ]; then echo "PCAP files generated"; else echo "No PCAP capture"; fi)
- **Zeek Analysis:** $(if [ "$zeek_lines" -gt 0 ]; then echo "Excel reports generated"; else echo "No analysis reports"; fi)
- **Sensor Reliability:** $(if [ "$sensor_errors" -eq 0 ]; then echo "No errors"; else echo "$sensor_errors errors"; fi)

## Files Generated

- **Test Logs:** \`$RESULTS_DIR/test.log\`
- **Container Logs:** \`$RESULTS_DIR/logs.txt\`
$(if [ -f "$RESULTS_DIR/docker_performance_stats.csv" ]; then
    echo "- **Performance Stats:** \`$RESULTS_DIR/docker_performance_stats.csv\`"
    echo "- **System Metrics:** \`$RESULTS_DIR/system_performance.csv\`"
else
    echo "- **Basic Stats:** \`$RESULTS_DIR/stats.log\`"
fi)
- **PCAP Files:** \`../captures/\` ($pcap_files files, $pcap_size total)
- **Zeek Reports:** \`../captures/\` ($zeek_lines Excel files)

## Performance Analysis

| Metric | This Test | Status |
|--------|-----------|---------|
| Total ops/sec | $actual_total_rps | $target_comparison |
| PCAP Capture | $pcap_files files | $(if [ "$pcap_files" -gt 0 ]; then echo "Working"; else echo "Check sensor"; fi) |
| Zeek Analysis | $zeek_lines reports | $(if [ "$zeek_lines" -gt 0 ]; then echo "Working"; else echo "Check processing"; fi) |

## Recommendations

$(if [ "$actual_total_rps" -lt "$THEORETICAL_TOTAL" ]; then
echo "- **Performance Gap:** Actual rate below theoretical - check system resources"
fi)
$(if [ "$pcap_files" -eq 0 ]; then
echo "- **PCAP Issue:** No capture files generated - verify sensor configuration"
fi)
$(if [ "$sensor_errors" -gt 0 ]; then
echo "- **Sensor Errors:** $sensor_errors errors detected - check sensor logs"
fi)
$(if [ "$actual_total_rps" -ge 10000 ]; then
echo "- **Success:** High performance achieved"
else
echo "- **Scaling:** Consider increasing generators or rates for higher performance"
fi)

---

EOF

    log "Comprehensive summary generated: $RESULTS_DIR/LOAD_TEST_SUMMARY.md"
}

main() {
    log "Starting $TEST_TYPE load test: HTTP ${HTTP_RPS} rps, DNS ${DNS_QPS} qps for ${TEST_DURATION}s"
    log "Total theoretical performance: $THEORETICAL_TOTAL ops/sec"
    log "Configuration: $HTTP_GENERATORS HTTP + $DNS_GENERATORS DNS generators"

    # Pre-test system check for performance mode
    if [ "$MODE" = "performance" ] || [ "$MODE" = "scale" ] || [ "$MODE" = "high" ]; then
        log "Pre-test system status:"
        log "  Available memory: $(free -h | awk 'NR==2{print $7}')"
        log "  CPU cores: $(nproc)"
        log "  Load average: $(uptime | awk -F'load average:' '{print $2}')"
    fi

    # Start monitoring
    start_monitoring

    # Start load test
    docker-compose up -d

    # Wait for containers to initialize
    if [ "$MODE" = "performance" ] || [ "$MODE" = "scale" ] || [ "$MODE" = "high" ]; then
        log "Waiting for containers to initialize (30s)..."
        sleep 30
        
        # Monitor test progress for performance tests
        for ((i=1; i<=TEST_DURATION; i+=30)); do
            remaining=$((TEST_DURATION - i + 1))
            log "Test progress: ${i}s/${TEST_DURATION}s (${remaining}s remaining)"
            
            # Check container health
            running_containers=$(docker ps --format "{{.Names}}" | wc -l)
            expected_containers=$((HTTP_GENERATORS + DNS_GENERATORS + 2)) # +2 for target-server and sensor
            if [ "$running_containers" -lt "$expected_containers" ]; then
                log "WARNING: Only $running_containers containers running (expected ~$expected_containers)"
            fi
            
            sleep 30
        done
    else
        log "Test running... (duration: ${TEST_DURATION}s)"
        sleep $((TEST_DURATION + 10))
    fi

    log "Test completed, collecting results..."
    
    # Collect results
    docker-compose logs > "$RESULTS_DIR/logs.txt"

    # Wait for final monitoring data
    sleep 10

    # Generate comprehensive summary
    generate_summary

    log "Test completed. Results and summary available in: $RESULTS_DIR"
    log "View summary: cat $RESULTS_DIR/LOAD_TEST_SUMMARY.md"
    
    # Show quick summary for performance tests
    if [ "$MODE" = "performance" ] || [ "$MODE" = "scale" ] || [ "$MODE" = "high" ]; then
        echo ""
        echo "=== QUICK SUMMARY ==="
        if [ -f "$RESULTS_DIR/LOAD_TEST_SUMMARY.md" ]; then
            grep -A 5 "### Traffic Generation" "$RESULTS_DIR/LOAD_TEST_SUMMARY.md"
        fi
    fi
}

main "$@"
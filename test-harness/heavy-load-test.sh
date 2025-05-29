#!/bin/bash

# Heavy load testing script to generate 100+ MB of network traffic
echo "Starting HEAVY load test traffic generation..."

# Wait for targets to be ready
sleep 5

# Generate a large payload for POST requests
LARGE_PAYLOAD=$(python3 -c "print('x' * 10000)")

echo "=== Starting intensive traffic generation ==="

# Function to generate heavy HTTP traffic
generate_heavy_traffic() {
    echo "Generating 10,000 requests with large payloads..."
    
    # Use multiple concurrent processes for speed
    for batch in {1..10}; do
        (
            echo "Starting batch $batch (1000 requests)..."
            for i in {1..1000}; do
                # Mix of different request types and sizes
                
                # Large POST to analytics API (10KB each)
                curl -s -X POST -H "Content-Type: application/json" \
                     -d "{\"data\":\"$LARGE_PAYLOAD\",\"batch\":$batch,\"request\":$i}" \
                     http://targets:8082/api/upload > /dev/null &
                
                # GET request with response data
                curl -s http://targets:8082/api/analytics > /dev/null &
                
                # Multiple smaller requests
                curl -s http://targets:8081/api/users > /dev/null &
                curl -s http://targets:8083/api/notifications > /dev/null &
                
                # Limit concurrent connections
                if (( i % 20 == 0 )); then
                    wait
                    echo "Batch $batch: Completed $i requests..."
                fi
            done
            wait
            echo "Batch $batch completed!"
        ) &
    done
    
    # Wait for all batches to complete
    wait
    echo "All 10,000 requests completed!"
}

# Function to generate large file downloads
generate_large_downloads() {
    echo "Generating large file transfers..."
    
    # Create a large test file on the fly
    for i in {1..50}; do
        # Simulate downloading large content
        curl -s -X POST -H "Content-Type: application/octet-stream" \
             --data-binary "@/dev/urandom" \
             --max-filesize 2M \
             http://targets:8082/api/upload > /dev/null &
        
        if (( i % 10 == 0 )); then
            wait
            echo "Completed $i large transfers..."
        fi
    done
    wait
}

# Function to use apache bench for sustained load
generate_ab_traffic() {
    echo "Generating sustained load with Apache Bench..."
    
    # High concurrency, many requests
    ab -n 2000 -c 50 -p /tmp/post_data.txt -T application/json http://targets:8082/api/data 2>/dev/null &
    ab -n 2000 -c 50 http://targets:8081/api/users 2>/dev/null &
    ab -n 2000 -c 50 http://targets:8083/api/notifications 2>/dev/null &
    ab -n 2000 -c 50 http://targets/ 2>/dev/null &
    
    wait
    echo "Apache Bench load completed!"
}

# Create data for POST requests
echo "{\"test\":\"data\",\"payload\":\"$(python3 -c 'print("x" * 5000)')\"}" > /tmp/post_data.txt

# Start monitoring
echo "=== Traffic Generation Started ==="
START_TIME=$(date +%s)

# Run all traffic generation methods
generate_heavy_traffic &
HEAVY_PID=$!

generate_large_downloads &
DOWNLOAD_PID=$!

generate_ab_traffic &
AB_PID=$!

# Wait for all to complete
echo "Waiting for all traffic generation to complete..."
wait $HEAVY_PID
wait $DOWNLOAD_PID  
wait $AB_PID

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "=== Traffic Generation Completed ==="
echo "Total duration: ${DURATION} seconds"
echo "Estimated data transferred: 100+ MB"

# Cleanup
rm -f /tmp/post_data.txt
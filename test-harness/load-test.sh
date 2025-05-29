#!/bin/bash

# Load testing script to generate diverse network traffic
# Runs continuously to generate traffic for the agent to capture

echo "Starting load test traffic generation..."

# Wait for targets to be fully ready
sleep 10

# Function to generate HTTP traffic with ab (apache bench)
generate_http_traffic() {
    local url=$1
    local duration=$2
    local connections=${3:-10}
    
    # Calculate requests based on duration (rough approximation)
    local requests=$((duration * connections * 2))
    
    echo "Generating HTTP traffic to $url with $requests requests and $connections concurrent connections..."
    ab -n $requests -c $connections -t $duration $url > /dev/null 2>&1 &
}

# Function to generate curl-based traffic (more varied patterns)
generate_curl_traffic() {
    local base_url=$1
    local iterations=${2:-50}
    
    echo "Generating varied curl traffic to $base_url..."
    for i in $(seq 1 $iterations); do
        # GET requests
        curl -s "$base_url/" > /dev/null &
        curl -s "$base_url/api/users" > /dev/null &
        curl -s "$base_url/static/test.json" > /dev/null &
        
        # POST requests
        curl -s -X POST -H "Content-Type: application/json" \
             -d '{"test":"data","id":'$i'}' \
             "$base_url/api/data" > /dev/null &
        
        # PUT/DELETE requests
        curl -s -X PUT "$base_url/api/users/$i" > /dev/null &
        curl -s -X DELETE "$base_url/api/temp/$i" > /dev/null &
        
        # Add some delay between requests
        sleep 0.5
    done
}

# Function to generate DNS traffic
generate_dns_traffic() {
    echo "Generating DNS queries..."
    for domain in google.com github.com stackoverflow.com example.com; do
        nslookup $domain > /dev/null 2>&1 &
        dig $domain > /dev/null 2>&1 &
    done
}

# Main traffic generation loop
while true; do
    echo "=== Starting traffic generation cycle ==="
    
    # Generate traffic to different services
    generate_http_traffic "http://targets:80" 20 15 4
    generate_http_traffic "http://targets:8081" 15 8 2
    generate_http_traffic "http://targets:8082" 15 8 2
    generate_http_traffic "http://targets:8083" 15 8 2
    
    # Generate more varied traffic patterns
    generate_curl_traffic "http://targets:80" 30 &
    generate_curl_traffic "http://targets:8081" 20 &
    generate_curl_traffic "http://targets:8082" 20 &
    
    # Generate DNS traffic
    generate_dns_traffic
    
    # Ping tests for ICMP traffic
    ping -c 5 targets > /dev/null 2>&1 &
    ping -c 3 8.8.8.8 > /dev/null 2>&1 &
    
    echo "Traffic generation cycle started, waiting 60s before next cycle..."
    sleep 60
    
    # Kill any lingering background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
done
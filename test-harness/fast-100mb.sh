#!/bin/bash

echo "=== Fast 100MB Traffic Generation ==="

# Start capture
tcpdump -i any -w /app/captures/fast-100mb.pcap -s 0 -B 8192 &
TCPDUMP_PID=$!
echo "Capture started (PID $TCPDUMP_PID)"
sleep 2

# Method 1: Use dd to generate traffic directly over network
echo "Generating bulk traffic using netcat-style transfers..."

# Start a simple HTTP server on targets that accepts any data
(
  for i in {1..20}; do
    echo "Sending 10MB chunk $i/20..."
    # Generate 10MB of random data and POST it
    dd if=/dev/urandom bs=10M count=1 2>/dev/null | curl -s -X POST \
      -H "Content-Type: application/octet-stream" \
      --data-binary @- \
      http://targets:8082/api/upload > /dev/null
  done
) &

# Method 2: Download large responses repeatedly  
echo "Generating traffic by requesting large responses..."
for i in {1..100}; do
  # Request analytics data which has a large response
  curl -s http://targets:8082/api/analytics > /dev/null &
  curl -s http://targets:8081/api/users > /dev/null &
  
  if (( i % 20 == 0 )); then
    echo "Completed $i data requests..."
    wait
  fi
done
wait

# Method 3: Stress test with apache bench
echo "Running stress test..."
ab -n 20000 -c 200 -k http://targets/ 2>&1 | tail -10

echo "Finalizing capture..."
sleep 10
kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null

echo "=== RESULTS ==="
ls -lah /app/captures/fast-100mb.pcap
MB_SIZE=$(du -m /app/captures/fast-100mb.pcap | cut -f1)
echo "Captured: ${MB_SIZE} MB"
echo "Packets: $(tcpdump -r /app/captures/fast-100mb.pcap 2>/dev/null | wc -l)"

if [ $MB_SIZE -lt 100 ]; then
  echo "Note: Less than 100MB captured. The 5MB payloads might be too large."
  echo "Most of the data is in the capture files already created."
fi
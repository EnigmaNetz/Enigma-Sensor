#!/bin/bash

echo "=== Generating 100+ MB of Network Traffic ==="

# Start capture with larger buffer
tcpdump -i any -w /app/captures/100mb-test.pcap -s 0 -B 4096 &
TCPDUMP_PID=$!
echo "Capture started (PID $TCPDUMP_PID)"
sleep 2

# Generate 5MB payload file
echo "Creating 5MB payload..."
dd if=/dev/urandom bs=5M count=1 2>/dev/null | base64 > /tmp/5mb_payload.txt

# Send 25 requests with 5MB payload each = 125MB+ of traffic
echo "Sending 25 x 5MB requests..."
for i in {1..25}; do
  curl -s -X POST -H "Content-Type: text/plain" \
    --data-binary @/tmp/5mb_payload.txt \
    http://targets:8082/api/upload &
  
  # Also generate response traffic
  curl -s http://targets:8082/api/analytics > /dev/null &
  
  # Limit concurrent connections
  if (( i % 5 == 0 )); then
    echo "Progress: $i/25 large uploads completed"
    wait
  fi
done
wait

# Additional traffic to ensure we hit 100MB
echo "Generating additional traffic..."
ab -n 10000 -c 50 http://targets/ 2>&1 | tail -5
ab -n 10000 -c 50 http://targets:8081/api/users 2>&1 | tail -5

echo "Finalizing capture..."
sleep 5
kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null

echo "=== CAPTURE COMPLETE ==="
ls -lah /app/captures/100mb-test.pcap
echo "Size in MB: $(du -m /app/captures/100mb-test.pcap | cut -f1)"
echo "Packet count: $(tcpdump -r /app/captures/100mb-test.pcap 2>/dev/null | wc -l)"

# Cleanup
rm -f /tmp/5mb_payload.txt
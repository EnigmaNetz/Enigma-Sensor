#!/bin/bash
set -e

# Validate required environment variables
if [ -z "$ENIGMA_API_KEY" ]; then
    echo "ERROR: ENIGMA_API_KEY is required"
    echo ""
    echo "Usage: docker run -e ENIGMA_API_KEY=<your_api_key> ghcr.io/enigmanetz/enigma-sensor:latest"
    echo ""
    echo "Optional environment variables:"
    echo "  ENIGMA_NETWORK_ID   Network identifier (default: enigma-sensor-docker)"
    echo "  ENIGMA_API_URL      API server address (default: api.enigmaai.net:443)"
    exit 1
fi

# Set defaults for optional variables
ENIGMA_NETWORK_ID="${ENIGMA_NETWORK_ID:-enigma-sensor-docker}"
ENIGMA_API_URL="${ENIGMA_API_URL:-api.enigmaai.net:443}"

# Inject configuration from template
cp /etc/enigma-sensor/config.template.json /etc/enigma-sensor/config.json

# Replace placeholder values
sed -i "s|REPLACE_WITH_YOUR_NETWORK_ID|${ENIGMA_NETWORK_ID}|g" /etc/enigma-sensor/config.json
sed -i "s|REPLACE_WITH_YOUR_API_KEY|${ENIGMA_API_KEY}|g" /etc/enigma-sensor/config.json
sed -i "s|api.enigmaai.net:443|${ENIGMA_API_URL}|g" /etc/enigma-sensor/config.json

# Override paths for Docker runtime directories
sed -i "s|logs/enigma-sensor.log|/var/log/enigma-sensor/enigma-sensor.log|g" /etc/enigma-sensor/config.json
sed -i "s|./captures|/var/lib/enigma-sensor/captures|g" /etc/enigma-sensor/config.json
sed -i "s|logs/buffer|/var/log/enigma-sensor/buffer|g" /etc/enigma-sensor/config.json

echo "Starting Enigma Sensor"
echo "  Network ID: ${ENIGMA_NETWORK_ID}"
echo "  API server: ${ENIGMA_API_URL}"

exec "$@"

#!/bin/bash
set -e

# Copy the template config as a base for the binary to read.
# The Go binary applies SENSOR_* environment variable overrides on top of this.
cp /etc/enigma-sensor/config.template.json /etc/enigma-sensor/config.json

# --- Legacy environment variable mapping (backward compatibility) ---
# Map old env var names to new SENSOR_* convention, but only when the new
# variable has not already been set by the caller.

if [ -n "$ENIGMA_API_KEY" ] && [ -z "$SENSOR_ENIGMA_API_API_KEY" ]; then
    export SENSOR_ENIGMA_API_API_KEY="$ENIGMA_API_KEY"
fi

if [ -n "$ENIGMA_NETWORK_ID" ] && [ -z "$SENSOR_NETWORK_ID" ]; then
    export SENSOR_NETWORK_ID="$ENIGMA_NETWORK_ID"
fi

if [ -n "$ENIGMA_API_URL" ] && [ -z "$SENSOR_ENIGMA_API_SERVER" ]; then
    export SENSOR_ENIGMA_API_SERVER="$ENIGMA_API_URL"
fi

# --- Validate required configuration ---
if [ -z "$SENSOR_ENIGMA_API_API_KEY" ]; then
    echo "ERROR: An API key is required"
    echo ""
    echo "Usage: docker run -e ENIGMA_API_KEY=<your_api_key> ghcr.io/enigmanetz/enigma-sensor:latest"
    echo ""
    echo "Environment variables:"
    echo "  ENIGMA_API_KEY              API key (legacy, maps to SENSOR_ENIGMA_API_API_KEY)"
    echo "  SENSOR_ENIGMA_API_API_KEY   API key (preferred)"
    echo "  ENIGMA_NETWORK_ID           Network identifier (legacy, maps to SENSOR_NETWORK_ID)"
    echo "  SENSOR_NETWORK_ID           Network identifier (preferred, default: enigma-sensor-docker)"
    echo "  ENIGMA_API_URL              API server address (legacy, maps to SENSOR_ENIGMA_API_SERVER)"
    echo "  SENSOR_ENIGMA_API_SERVER    API server address (preferred)"
    echo ""
    echo "Any config field can be overridden with SENSOR_<SECTION>_<FIELD> variables."
    exit 1
fi

# --- Default for network_id ---
export SENSOR_NETWORK_ID="${SENSOR_NETWORK_ID:-enigma-sensor-docker}"

# --- Docker specific path defaults ---
export SENSOR_LOGGING_FILE="${SENSOR_LOGGING_FILE:-/var/log/enigma-sensor/enigma-sensor.log}"
export SENSOR_CAPTURE_OUTPUT_DIR="${SENSOR_CAPTURE_OUTPUT_DIR:-/var/lib/enigma-sensor/captures}"
export SENSOR_BUFFERING_DIR="${SENSOR_BUFFERING_DIR:-/var/log/enigma-sensor/buffer}"

# --- Startup info ---
echo "Starting Enigma Sensor"
echo "  Network ID: ${SENSOR_NETWORK_ID}"
echo "  API server: ${SENSOR_ENIGMA_API_SERVER:-<config default>}"

exec "$@"

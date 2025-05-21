#!/bin/bash
set -euo pipefail

# Start nginx in the background (runs as daemon by default)
nginx

# Run the agent in the foreground
exec /usr/local/bin/enigma-agent

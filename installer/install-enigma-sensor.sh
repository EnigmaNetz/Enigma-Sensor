#!/bin/bash
set -eu

# --- User-provided variables ---
ENIGMA_API_KEY="${ENIGMA_API_KEY:-}"
ENIGMA_API_URL="${ENIGMA_API_URL:-api.enigmaai.net:443}"
ENIGMA_NETWORK_ID="${ENIGMA_NETWORK_ID:-}"

# --- Validation function for network ID ---
validate_network_id() {
  local network_id="$1"
  local len=${#network_id}

  # Check length (1-64)
  if [ "$len" -lt 1 ] || [ "$len" -gt 64 ]; then
    return 1
  fi

  # Check format: alphanumeric start/end, allows letters, numbers, spaces, hyphens, underscores
  # Must start with alphanumeric
  if ! echo "$network_id" | grep -q '^[a-zA-Z0-9]'; then
    return 1
  fi

  # Must end with alphanumeric
  if ! echo "$network_id" | grep -q '[a-zA-Z0-9]$'; then
    return 1
  fi

  # Must contain only allowed characters (letters, numbers, spaces, hyphens, underscores)
  if echo "$network_id" | grep -q '[^a-zA-Z0-9 _-]'; then
    return 1
  fi

  return 0
}

# --- Prompt for API Key if not set ---
if [ -z "$ENIGMA_API_KEY" ]; then
  echo "ENIGMA_API_KEY environment variable not set."
  read -r -s -p "Enter your Enigma API Key: " ENIGMA_API_KEY
  echo
  if [ -z "$ENIGMA_API_KEY" ]; then
    echo "ERROR: API key is required."
    exit 1
  fi
fi

# --- Prompt for Network ID if not set ---
if [ -z "$ENIGMA_NETWORK_ID" ]; then
  echo "ENIGMA_NETWORK_ID environment variable not set."
  echo "Network ID requirements:"
  echo "  - 1 to 64 characters"
  echo "  - Letters, numbers, spaces, hyphens, and underscores only"
  echo "  - Must start and end with a letter or number"
  echo "  - Example: HQ-Firewall-01"
  read -r -p "Enter your Network ID: " ENIGMA_NETWORK_ID
  if [ -z "$ENIGMA_NETWORK_ID" ]; then
    echo "ERROR: Network ID is required."
    exit 1
  fi
fi

# --- Validate Network ID ---
if ! validate_network_id "$ENIGMA_NETWORK_ID"; then
  echo "ERROR: Invalid Network ID '$ENIGMA_NETWORK_ID'."
  echo "Requirements:"
  echo "  - 1 to 64 characters"
  echo "  - Letters, numbers, spaces, hyphens, and underscores only"
  echo "  - Must start and end with a letter or number"
  exit 1
fi

# --- Detect OS ---
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_ID=$ID
  VERSION_ID=$VERSION_ID
else
  echo "ERROR: Cannot detect OS type (missing /etc/os-release)."
  exit 1
fi

case "$OS_ID" in
  ubuntu|debian)
    # --- Ensure curl and gpg are installed ---
    apt update
    apt install -y curl gpg
    # --- Add Zeek repository and key if not present ---
    if ! grep -q 'security:/zeek' /etc/apt/sources.list.d/security:zeek.list 2>/dev/null; then
      case "$VERSION_ID" in
        "20.04")
          ZEEK_RELEASE="xUbuntu_20.04"
          ;;
        "22.04")
          ZEEK_RELEASE="xUbuntu_22.04"
          ;;
        "24.04")
          ZEEK_RELEASE="xUbuntu_24.04"
          ;;
        *)
          echo "ERROR: Unsupported Ubuntu version: $VERSION_ID for Zeek repo."
          exit 1
          ;;
      esac
      curl -fsSL https://download.opensuse.org/repositories/security:zeek/${ZEEK_RELEASE}/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg
      echo "deb http://download.opensuse.org/repositories/security:/zeek/${ZEEK_RELEASE}/ /" | tee /etc/apt/sources.list.d/security:zeek.list
      apt update
    fi
    # --- Install Zeek, tcpdump, and dependencies ---
    export DEBIAN_FRONTEND=noninteractive
    apt install -y zeek tcpdump
    # --- Find and install Enigma Sensor .deb package ---
    PKG=$(ls ./*.deb 2>/dev/null | head -n1)
    if [ -z "$PKG" ]; then
      echo "ERROR: No .deb package found in the current directory."
      exit 1
    fi
    dpkg -i "$PKG" || apt-get install -f -y
    ;;
  centos|rhel|fedora)
    # --- Install Zeek, tcpdump, and dependencies ---
    yum install -y epel-release || true
    yum install -y zeek tcpdump || dnf install -y zeek tcpdump
    # --- Find and install Enigma Sensor .rpm package ---
    PKG=$(ls ./*.rpm 2>/dev/null | head -n1)
    if [ -z "$PKG" ]; then
      echo "ERROR: No .rpm package found in the current directory."
      exit 1
    fi
    yum install -y "$PKG" || dnf install -y "$PKG"
    ;;
  *)
    echo "ERROR: Unsupported Linux distribution: $OS_ID"
    exit 1
    ;;
esac

# --- Write config file only if it doesn't exist ---
mkdir -p /etc/enigma-sensor
if [ ! -f /etc/enigma-sensor/config.json ]; then
  cat > /etc/enigma-sensor/config.json <<EOF
{
  "network_id": "$ENIGMA_NETWORK_ID",
  "logging": {
    "level": "info",
    "file": "/var/log/enigma-sensor/enigma-sensor.log",
    "max_size_mb": 100,
    "log_retention_days": 7
  },
  "capture": {
    "output_dir": "/var/lib/enigma-sensor/captures",
    "window_seconds": 60,
    "loop": true,
    "interface": "any"
  },
  "enigma_api": {
    "api_key": "$ENIGMA_API_KEY",
    "server": "$ENIGMA_API_URL",
    "upload": true,
    "max_payload_size_mb": 25
  },
  "zeek": {
    "sampling_percentage": 100
  }
}
EOF
fi

# --- Create necessary directories ---
mkdir -p /var/log/enigma-sensor
mkdir -p /var/lib/enigma-sensor/captures
chown -R root:root /var/log/enigma-sensor /var/lib/enigma-sensor
chmod 755 /var/log/enigma-sensor /var/lib/enigma-sensor
chmod 644 /var/lib/enigma-sensor/captures

# --- Restart service if systemd is present ---
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart enigma-sensor || true
fi

echo "Enigma Sensor installed and configured."

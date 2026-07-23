#!/bin/bash
set -eu

# Resolve the directory holding this script so the bundled Zeek packages and the
# sensor package are found regardless of the caller's working directory.
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)

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
    export DEBIAN_FRONTEND=noninteractive
    # --- Ensure base tooling is installed ---
    # tcpdump lives here, not with Zeek: the sensor package depends on it and the
    # Zeek step below is best effort, so it must not be skipped by a Zeek failure.
    apt update
    apt install -y curl gpg tcpdump

    # --- Install Zeek from the packages bundled in the release ---
    # The bundle is exactly Zeek 8.0.5-0, pinned to avoid breaking changes from
    # newer Zeek releases. apt, not dpkg, so Zeek's shared library dependencies
    # resolve from the distribution's own repositories.
    install_zeek_bundled() {
      [ -d "$SCRIPT_DIR/zeek" ] || return 1
      if [ ! -f "$SCRIPT_DIR/zeek/SHA256SUMS" ]; then
        echo "ERROR: the bundled Zeek packages carry no SHA256SUMS manifest."
        return 1
      fi
      if ! ( cd "$SCRIPT_DIR/zeek" && sha256sum -c SHA256SUMS ); then
        echo "ERROR: the bundled Zeek packages fail checksum verification."
        return 1
      fi
      # Install exactly the files the manifest lists. A glob installs whatever
      # .deb is present, so a local user who drops one into an unpacked release
      # directory gets its maintainer scripts run as root.
      zeek_debs=()
      while read -r _ zeek_deb_name; do
        [ -n "$zeek_deb_name" ] || continue
        [ -f "$SCRIPT_DIR/zeek/$zeek_deb_name" ] || return 1
        zeek_debs+=("$SCRIPT_DIR/zeek/$zeek_deb_name")
      done < "$SCRIPT_DIR/zeek/SHA256SUMS"
      [ "${#zeek_debs[@]}" -gt 0 ] || return 1
      # --no-install-recommends matches the Dockerfile so the published image and
      # a host install resolve the same package closure.
      apt-get install -y --no-install-recommends "${zeek_debs[@]}" || return 1
      # Retire the third-party repository a previous installer version configured.
      rm -f /etc/apt/trusted.gpg.d/security_zeek.gpg \
            /etc/apt/sources.list.d/security:zeek.list
      return 0
    }

    # --- Fall back to the OpenSUSE repository when the bundle is unavailable ---
    ZEEK_OBS_KEYRING=/usr/share/keyrings/security_zeek.gpg
    ZEEK_OBS_SOURCES=/etc/apt/sources.list.d/security:zeek.list

    # Remove the key and the apt source together so a failed fallback never
    # leaves a configured third-party repository behind.
    zeek_obs_cleanup() {
      rm -f "$ZEEK_OBS_KEYRING" "$ZEEK_OBS_SOURCES"
    }

    install_zeek_obs() {
      case "$VERSION_ID" in
        "22.04")
          ZEEK_RELEASE="xUbuntu_22.04"
          ;;
        "24.04")
          ZEEK_RELEASE="xUbuntu_24.04"
          ;;
        *)
          echo "ERROR: Unsupported Ubuntu version: $VERSION_ID for Zeek repo."
          return 1
          ;;
      esac
      if ! grep -q 'security:/zeek' "$ZEEK_OBS_SOURCES" 2>/dev/null; then
        # Fetch the key into a private temporary directory first. Piping curl
        # into gpg into tee hides a curl failure behind tee's exit status and
        # leaves an apt source backed by an empty key, and a derived .gpg name
        # in /tmp is a target a local process can pre-create as a symlink.
        ZEEK_KEY_DIR=$(mktemp -d) || return 1
        if ! curl -fsSL "https://download.opensuse.org/repositories/security:zeek/${ZEEK_RELEASE}/Release.key" -o "$ZEEK_KEY_DIR/key.asc"; then
          rm -rf "$ZEEK_KEY_DIR"
          echo "ERROR: Unable to download the OpenSUSE Zeek repository key."
          return 1
        fi
        if ! gpg --dearmor < "$ZEEK_KEY_DIR/key.asc" > "$ZEEK_KEY_DIR/key.gpg"; then
          rm -rf "$ZEEK_KEY_DIR"
          return 1
        fi
        # signed-by scopes the key to this repository; trusted.gpg.d would trust
        # it for every repository on the host.
        if ! mv "$ZEEK_KEY_DIR/key.gpg" "$ZEEK_OBS_KEYRING"; then
          rm -rf "$ZEEK_KEY_DIR"
          return 1
        fi
        rm -rf "$ZEEK_KEY_DIR"
        echo "deb [signed-by=$ZEEK_OBS_KEYRING] https://download.opensuse.org/repositories/security:/zeek/${ZEEK_RELEASE}/ /" > "$ZEEK_OBS_SOURCES" || { zeek_obs_cleanup; return 1; }
        apt update || { zeek_obs_cleanup; return 1; }
      fi
      # Constrain to the 8.0.x line: 8.1 and later carry breaking changes the
      # sensor cannot take.
      apt-get install -y 'zeek-core=8.0.*' || { zeek_obs_cleanup; return 1; }
    }

    if install_zeek_bundled; then
      echo "Zeek installed from bundled packages."
    elif install_zeek_obs; then
      echo "WARNING: bundled Zeek packages unavailable; installed Zeek from the OpenSUSE repository."
    else
      echo "WARNING: Zeek installation failed. Continuing to the sensor package install."
      echo "         The sensor requires Zeek 8.0.x at /opt/zeek/bin/zeek and will not run without it."
    fi

    # --- Warn when the installed Zeek is off the supported line ---
    ZEEK_VER=$(dpkg-query -W -f='${Version}' zeek-core 2>/dev/null || echo none)
    case "$ZEEK_VER" in
      8.0.*) ;;
      *) echo "WARNING: zeek-core version '$ZEEK_VER' is outside the supported 8.0.x line." ;;
    esac

    # --- Find and install Enigma Sensor .deb package ---
    sensor_debs=("$SCRIPT_DIR"/*.deb)
    if [ ! -e "${sensor_debs[0]}" ]; then
      sensor_debs=(./*.deb)
    fi
    PKG="${sensor_debs[0]}"
    if [ ! -e "$PKG" ]; then
      echo "ERROR: No .deb package found in $SCRIPT_DIR or the current directory."
      exit 1
    fi
    if ! dpkg -i "$PKG"; then
      apt-get install -f -y || true
    fi
    # apt-get install -f resolves a broken install by removing the package and
    # exits 0, so check the end state instead of trusting the exit status.
    if [ "$(dpkg-query -W -f='${Status}' enigma-sensor 2>/dev/null || true)" != "install ok installed" ]; then
      echo "ERROR: the Enigma Sensor package could not be installed."
      echo "       Its dependencies (zeek-core, tcpdump) are not satisfied on this host."
      echo "       Install Zeek 8.0.x and re-run this script."
      exit 1
    fi
    ;;
  centos|rhel|fedora)
    # --- Install Zeek, tcpdump, and dependencies ---
    # Pin Zeek to 8.0.5 to avoid breaking changes from new releases
    yum install -y epel-release || true
    yum install -y zeek-8.0.5-0 tcpdump || dnf install -y zeek-8.0.5-0 tcpdump
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
    "interface": "any",
    "retention_hours": 24
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

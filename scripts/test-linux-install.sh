#!/usr/bin/env bash
# Container-based install test for the Linux release layout.
#
# Proves the shipped release zip installs Zeek from the bundled debs at
# installer/linux/zeek/ without ever reaching the OpenSUSE Build Service, which
# is blackholed at the container's network layer for every run below.
#
# Usage: bash scripts/test-linux-install.sh   (no arguments, any cwd)
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
BUNDLE_DIR="$REPO_ROOT/installer/linux/zeek"

TEST_API_KEY="citest"
TEST_NETWORK_ID="ci-test-network"

FAILURES=0

pass() {
  echo "PASS: $1"
}

fail() {
  echo "FAIL: $1"
  if [ "$#" -gt 1 ]; then
    echo "      $2"
  fi
  FAILURES=$((FAILURES + 1))
}

# Reads the last "MARK <name>=<value>" line out of captured container output.
mark_value() {
  printf '%s\n' "$1" | sed -n "s/^MARK $2=//p" | tail -n 1
}

RELEASE_DIR=""
cleanup() {
  if [ -n "$RELEASE_DIR" ] && [ -d "$RELEASE_DIR" ]; then
    rm -rf "$RELEASE_DIR"
  fi
}
trap cleanup EXIT

# --- Prerequisites -----------------------------------------------------------
# A missing prerequisite is a hard error, never a silently skipped phase.
missing=""
for tool in go docker dos2unix fakeroot; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing="$missing $tool"
  fi
done
if [ -n "$missing" ]; then
  echo "ERROR: missing required tools:$missing"
  echo "       Install them and re-run, for example:"
  echo "       sudo apt-get update && sudo apt-get install -y dos2unix fakeroot"
  echo "       Go 1.24+ and Docker must also be on PATH."
  exit 1
fi

# --- Phase 1: build the release layout ---------------------------------------
echo "=== Phase 1: build the release layout ==="

cd "$REPO_ROOT"
mkdir -p bin
GOOS=linux GOARCH=amd64 go build -o bin/enigma-sensor-linux ./cmd/enigma-sensor
(cd "$REPO_ROOT/installer/debian" && bash build-deb.sh)

RELEASE_DIR=$(mktemp -d)
cp "$REPO_ROOT/installer/install-enigma-sensor.sh" "$RELEASE_DIR/"

sensor_debs=("$REPO_ROOT"/bin/enigma-sensor_*.deb)
if [ ! -e "${sensor_debs[0]}" ]; then
  echo "ERROR: no sensor deb produced at $REPO_ROOT/bin/enigma-sensor_*.deb"
  exit 1
fi
cp "${sensor_debs[0]}" "$RELEASE_DIR/"

# The release zip keeps the Zeek debs in a zeek/ subdirectory so the installer's
# top-level *.deb glob cannot mistake one for the sensor package.
mkdir -p "$RELEASE_DIR/zeek"
bundle_debs=("$BUNDLE_DIR"/*.deb)
if [ -e "${bundle_debs[0]}" ]; then
  cp "$BUNDLE_DIR"/*.deb "$RELEASE_DIR/zeek/"
  pass "release layout contains bundled Zeek debs under zeek/"
else
  fail "release layout contains bundled Zeek debs under zeek/" \
    "no *.deb found in $BUNDLE_DIR"
fi

# The release zip also ships the manifest, so the installer can verify the debs
# on the customer host. Mirrors the cp in build-artifacts-reusable.yml.
if [ -f "$BUNDLE_DIR/SHA256SUMS" ]; then
  cp "$BUNDLE_DIR/SHA256SUMS" "$RELEASE_DIR/zeek/"
fi
if [ -f "$RELEASE_DIR/zeek/SHA256SUMS" ]; then
  pass "release layout contains SHA256SUMS under zeek/"
else
  fail "release layout contains SHA256SUMS under zeek/" \
    "no SHA256SUMS found in $BUNDLE_DIR"
fi

# --- Phase 2: verify the vendored bytes --------------------------------------
echo "=== Phase 2: verify the vendored bytes ==="

if [ -f "$BUNDLE_DIR/SHA256SUMS" ]; then
  if (cd "$BUNDLE_DIR" && sha256sum -c SHA256SUMS); then
    pass "vendored Zeek debs match SHA256SUMS"
  else
    fail "vendored Zeek debs match SHA256SUMS" \
      "sha256sum -c failed in $BUNDLE_DIR"
  fi
else
  fail "vendored Zeek debs match SHA256SUMS" \
    "$BUNDLE_DIR/SHA256SUMS does not exist"
fi

# --- Phase 3: per-image install ----------------------------------------------
# The --add-host blackhole turns "never reached OBS" into a positive assertion:
# if the installer tries the OpenSUSE repo, the fetch fails outright. The
# container stays on the default network so apt can still resolve libssl3,
# libpcap0.8, libmaxminddb0, libzmq5 and libkrb5-3 from Ubuntu's own repos.
run_install_container() {
  local image="$1"
  docker run --rm -i \
    --add-host download.opensuse.org:127.0.0.1 \
    -e "ENIGMA_API_KEY=$TEST_API_KEY" \
    -e "ENIGMA_NETWORK_ID=$TEST_NETWORK_ID" \
    -e DEBIAN_FRONTEND=noninteractive \
    -v "$RELEASE_DIR:/release" \
    "$image" bash -s
}

INSTALL_SCRIPT=$(cat <<'CONTAINER'
apt-get update >/dev/null
cd /release
bash install-enigma-sensor.sh
echo "MARK installer_exit=$?"
echo "MARK zeek_version=$(/opt/zeek/bin/zeek --version 2>&1 | head -n 1)"
echo "MARK sensor_status=$(dpkg -s enigma-sensor 2>&1 | sed -n 's/^Status: //p')"
echo "MARK zeek_core_version=$(dpkg -s zeek-core 2>&1 | sed -n 's/^Version: //p')"
if [ -e /etc/apt/sources.list.d/security:zeek.list ]; then
  echo "MARK obs_list=present"
else
  echo "MARK obs_list=absent"
fi
if [ -e /etc/apt/trusted.gpg.d/security_zeek.gpg ]; then
  echo "MARK obs_gpg=present"
else
  echo "MARK obs_gpg=absent"
fi
CONTAINER
)

for image in ubuntu:22.04 ubuntu:24.04; do
  echo "=== Phase 3: install on $image ==="
  out=""
  status=0
  out=$(run_install_container "$image" <<<"$INSTALL_SCRIPT" 2>&1) || status=$?
  printf '%s\n' "$out"
  if [ "$status" -ne 0 ]; then
    fail "$image: container run completed" "docker run exited $status"
  fi

  installer_exit=$(mark_value "$out" installer_exit)
  if [ "$installer_exit" = "0" ]; then
    pass "$image: installer exit status is 0"
  else
    fail "$image: installer exit status is 0" "got '${installer_exit:-<no marker>}'"
  fi

  zeek_version=$(mark_value "$out" zeek_version)
  if printf '%s' "$zeek_version" | grep -q 'version 8\.0\.'; then
    pass "$image: /opt/zeek/bin/zeek reports 8.0.x"
  else
    fail "$image: /opt/zeek/bin/zeek reports 8.0.x" "got '${zeek_version:-<no marker>}'"
  fi

  sensor_status=$(mark_value "$out" sensor_status)
  if [ "$sensor_status" = "install ok installed" ]; then
    pass "$image: dpkg -s enigma-sensor is install ok installed"
  else
    fail "$image: dpkg -s enigma-sensor is install ok installed" \
      "got '${sensor_status:-<no marker>}'"
  fi

  zeek_core_version=$(mark_value "$out" zeek_core_version)
  case "$zeek_core_version" in
    8.0.*) pass "$image: dpkg -s zeek-core version is 8.0.x" ;;
    *) fail "$image: dpkg -s zeek-core version is 8.0.x" \
         "got '${zeek_core_version:-<no marker>}'" ;;
  esac

  obs_list=$(mark_value "$out" obs_list)
  if [ "$obs_list" = "absent" ]; then
    pass "$image: no OBS apt source at /etc/apt/sources.list.d/security:zeek.list"
  else
    fail "$image: no OBS apt source at /etc/apt/sources.list.d/security:zeek.list" \
      "got '${obs_list:-<no marker>}'"
  fi

  obs_gpg=$(mark_value "$out" obs_gpg)
  if [ "$obs_gpg" = "absent" ]; then
    pass "$image: no OBS key at /etc/apt/trusted.gpg.d/security_zeek.gpg"
  else
    fail "$image: no OBS key at /etc/apt/trusted.gpg.d/security_zeek.gpg" \
      "got '${obs_gpg:-<no marker>}'"
  fi
done

# --- Phase 4: cwd independence (22.04 only) ----------------------------------
# Fails if the installer resolves the bundle relative to the caller's cwd
# instead of the script's own directory.
echo "=== Phase 4: cwd independence on ubuntu:22.04 ==="
CWD_SCRIPT=$(cat <<'CONTAINER'
apt-get update >/dev/null
cd /
bash /release/install-enigma-sensor.sh
echo "MARK installer_exit=$?"
echo "MARK zeek_version=$(/opt/zeek/bin/zeek --version 2>&1 | head -n 1)"
CONTAINER
)
out=""
status=0
out=$(run_install_container ubuntu:22.04 <<<"$CWD_SCRIPT" 2>&1) || status=$?
printf '%s\n' "$out"
if [ "$status" -ne 0 ]; then
  fail "cwd independence: container run completed" "docker run exited $status"
fi

installer_exit=$(mark_value "$out" installer_exit)
if [ "$installer_exit" = "0" ]; then
  pass "cwd independence: installer exit status is 0 when run from /"
else
  fail "cwd independence: installer exit status is 0 when run from /" \
    "got '${installer_exit:-<no marker>}'"
fi

zeek_version=$(mark_value "$out" zeek_version)
if printf '%s' "$zeek_version" | grep -q 'version 8\.0\.'; then
  pass "cwd independence: /opt/zeek/bin/zeek reports 8.0.x"
else
  fail "cwd independence: /opt/zeek/bin/zeek reports 8.0.x" \
    "got '${zeek_version:-<no marker>}'"
fi

# --- Phase 5: regression test for the reported bug (22.04 only) --------------
# With the bundle removed and OBS blackholed, Zeek cannot be installed at all.
# The installer must still reach the sensor package install step instead of
# aborting at the Zeek step, and it must then fail honestly: nonzero exit, no
# claim of success while the sensor package is absent. This is also the only
# phase in which install_zeek_obs actually runs, so it is where the failed key
# fetch is proven to leave no apt trust behind.
echo "=== Phase 5: Zeek step is best effort on ubuntu:22.04 ==="
NO_BUNDLE_SCRIPT=$(cat <<'CONTAINER'
apt-get update >/dev/null
cp -a /release /tmp/release
rm -rf /tmp/release/zeek
cd /tmp/release
bash install-enigma-sensor.sh
echo "MARK installer_exit=$?"
echo "MARK sensor_status=$(dpkg -s enigma-sensor 2>&1 | sed -n 's/^Status: //p')"
if [ -e /etc/apt/sources.list.d/security:zeek.list ]; then
  echo "MARK obs_list=present"
else
  echo "MARK obs_list=absent"
fi
if [ -e /etc/apt/trusted.gpg.d/security_zeek.gpg ]; then
  echo "MARK obs_gpg=present"
else
  echo "MARK obs_gpg=absent"
fi
if [ -e /usr/share/keyrings/security_zeek.gpg ]; then
  echo "MARK obs_keyring=present"
else
  echo "MARK obs_keyring=absent"
fi
CONTAINER
)
out=""
status=0
out=$(run_install_container ubuntu:22.04 <<<"$NO_BUNDLE_SCRIPT" 2>&1) || status=$?
printf '%s\n' "$out"
if [ "$status" -ne 0 ]; then
  fail "best effort: container run completed" "docker run exited $status"
fi

if printf '%s' "$out" | grep -q 'Continuing to the sensor package install'; then
  pass "best effort: installer warns and continues past a failed Zeek install"
else
  fail "best effort: installer warns and continues past a failed Zeek install" \
    "expected the 'Continuing to the sensor package install' warning in the output"
fi

if printf '%s' "$out" | grep -Eq 'Selecting previously unselected package enigma-sensor|Unpacking enigma-sensor|dpkg: dependency problems|apt-get install -f'; then
  pass "best effort: installer reaches the sensor package install step"
else
  fail "best effort: installer reaches the sensor package install step" \
    "no dpkg or apt-get -f evidence for the sensor deb in the output"
fi

installer_exit=$(mark_value "$out" installer_exit)
if [ -n "$installer_exit" ] && [ "$installer_exit" != "0" ]; then
  pass "best effort: installer exits nonzero when Zeek is unavailable"
else
  fail "best effort: installer exits nonzero when Zeek is unavailable" \
    "got '${installer_exit:-<no marker>}'"
fi

sensor_status=$(mark_value "$out" sensor_status)
if [ "$sensor_status" != "install ok installed" ]; then
  pass "best effort: installer does not claim success with the sensor package absent"
else
  fail "best effort: installer does not claim success with the sensor package absent" \
    "sensor reports 'install ok installed' after a run that could not install Zeek"
fi

# The OBS fallback is the path that actually runs here, so these three prove a
# failed key fetch leaves no dangling apt trust behind.
obs_list=$(mark_value "$out" obs_list)
if [ "$obs_list" = "absent" ]; then
  pass "best effort: failed OBS fallback leaves no apt source at /etc/apt/sources.list.d/security:zeek.list"
else
  fail "best effort: failed OBS fallback leaves no apt source at /etc/apt/sources.list.d/security:zeek.list" \
    "got '${obs_list:-<no marker>}'"
fi

obs_gpg=$(mark_value "$out" obs_gpg)
if [ "$obs_gpg" = "absent" ]; then
  pass "best effort: failed OBS fallback leaves no key at /etc/apt/trusted.gpg.d/security_zeek.gpg"
else
  fail "best effort: failed OBS fallback leaves no key at /etc/apt/trusted.gpg.d/security_zeek.gpg" \
    "got '${obs_gpg:-<no marker>}'"
fi

obs_keyring=$(mark_value "$out" obs_keyring)
if [ "$obs_keyring" = "absent" ]; then
  pass "best effort: failed OBS fallback leaves no keyring at /usr/share/keyrings/security_zeek.gpg"
else
  fail "best effort: failed OBS fallback leaves no keyring at /usr/share/keyrings/security_zeek.gpg" \
    "got '${obs_keyring:-<no marker>}'"
fi

# --- Summary -----------------------------------------------------------------
echo "=== Summary ==="
if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES check(s) failed."
  exit 1
fi
echo "All checks passed."

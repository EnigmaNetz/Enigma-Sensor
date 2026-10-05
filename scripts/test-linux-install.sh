#!/usr/bin/env bash
# Container-based install test for the Linux release layout.
#
# Proves the shipped release zip installs Zeek from the bundled debs at
# installer/linux/zeek/ubuntu-<release>/ without ever reaching the OpenSUSE Build
# Service, which is blackholed at the container's network layer for every run
# below, and that it upgrades a host an earlier release installed.
#
# Usage: bash scripts/test-linux-install.sh   (no arguments, any cwd)
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
BUNDLE_DIR="$REPO_ROOT/installer/linux/zeek"
BUNDLE_RELEASES="22.04 24.04"

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
OLD_ZEEK_DIR=""
cleanup() {
  if [ -n "$RELEASE_DIR" ] && [ -d "$RELEASE_DIR" ]; then
    rm -rf "$RELEASE_DIR"
  fi
  if [ -n "$OLD_ZEEK_DIR" ] && [ -d "$OLD_ZEEK_DIR" ]; then
    rm -rf "$OLD_ZEEK_DIR"
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
  echo "       Go 1.25+ and Docker must also be on PATH."
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

# Pick the deb just built by its version: bin/ is a scratch directory, and an
# older build left there would otherwise sort first.
SENSOR_VERSION=$(awk '/^Version: /{print $2}' "$REPO_ROOT/installer/debian/DEBIAN/control")
SENSOR_DEB="$REPO_ROOT/bin/enigma-sensor_${SENSOR_VERSION}_amd64.deb"
if [ ! -e "$SENSOR_DEB" ]; then
  echo "ERROR: no sensor deb produced at $SENSOR_DEB"
  exit 1
fi
cp "$SENSOR_DEB" "$RELEASE_DIR/"

# The release zip keeps the Zeek debs in a zeek/ subdirectory so the installer's
# top-level *.deb glob cannot mistake one for the sensor package, with one set
# and its SHA256SUMS manifest per Ubuntu build channel. Mirrors the cp in
# build-artifacts-reusable.yml.
mkdir -p "$RELEASE_DIR/zeek"
for release in $BUNDLE_RELEASES; do
  src="$BUNDLE_DIR/ubuntu-$release"
  if [ -d "$src" ]; then
    cp -r "$src" "$RELEASE_DIR/zeek/"
  fi
  bundle_debs=("$RELEASE_DIR/zeek/ubuntu-$release"/*.deb)
  if [ -e "${bundle_debs[0]}" ]; then
    pass "release layout contains bundled Zeek debs under zeek/ubuntu-$release/"
  else
    fail "release layout contains bundled Zeek debs under zeek/ubuntu-$release/" \
      "no *.deb found in $src"
  fi
  if [ -f "$RELEASE_DIR/zeek/ubuntu-$release/SHA256SUMS" ]; then
    pass "release layout contains SHA256SUMS under zeek/ubuntu-$release/"
  else
    fail "release layout contains SHA256SUMS under zeek/ubuntu-$release/" \
      "no SHA256SUMS found in $src"
  fi
done

# --- Phase 2: verify the vendored bytes --------------------------------------
echo "=== Phase 2: verify the vendored bytes ==="

for release in $BUNDLE_RELEASES; do
  src="$BUNDLE_DIR/ubuntu-$release"
  if [ -f "$src/SHA256SUMS" ]; then
    if (cd "$src" && sha256sum -c SHA256SUMS); then
      pass "vendored Zeek debs for $release match SHA256SUMS"
    else
      fail "vendored Zeek debs for $release match SHA256SUMS" \
        "sha256sum -c failed in $src"
    fi
  else
    fail "vendored Zeek debs for $release match SHA256SUMS" \
      "$src/SHA256SUMS does not exist"
  fi
done

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
echo "MARK zeek_lts_core_version=$(dpkg -s zeek-lts-core 2>&1 | sed -n 's/^Version: //p')"
echo "MARK config_mode=$(stat -c %a /etc/enigma-sensor/config.json 2>&1)"
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

for image in ubuntu:22.04 ubuntu:24.04 debian:12 debian:13; do
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
  if printf '%s' "$zeek_version" | grep -q 'version 8\.0\.10$'; then
    pass "$image: /opt/zeek/bin/zeek reports 8.0.10"
  else
    fail "$image: /opt/zeek/bin/zeek reports 8.0.10" "got '${zeek_version:-<no marker>}'"
  fi

  sensor_status=$(mark_value "$out" sensor_status)
  if [ "$sensor_status" = "install ok installed" ]; then
    pass "$image: dpkg -s enigma-sensor is install ok installed"
  else
    fail "$image: dpkg -s enigma-sensor is install ok installed" \
      "got '${sensor_status:-<no marker>}'"
  fi

  zeek_lts_core_version=$(mark_value "$out" zeek_lts_core_version)
  if [ "$zeek_lts_core_version" = "8.0.10-0" ]; then
    pass "$image: dpkg -s zeek-lts-core version is 8.0.10-0"
  else
    fail "$image: dpkg -s zeek-lts-core version is 8.0.10-0" \
      "got '${zeek_lts_core_version:-<no marker>}'"
  fi

  # apt names the local file it installs, which proves the bundle matched the host.
  # Debian takes the 22.04 build (see install_zeek_bundled).
  case "$image" in
    ubuntu:*) release=${image#ubuntu:} ;;
    *) release=22.04 ;;
  esac
  if printf '%s' "$out" | grep -q "zeek/ubuntu-$release/zeek-lts-core_"; then
    pass "$image: installed Zeek from the zeek/ubuntu-$release/ bundle"
  else
    fail "$image: installed Zeek from the zeek/ubuntu-$release/ bundle" \
      "no zeek/ubuntu-$release/zeek-lts-core_ path in the installer output"
  fi

  config_mode=$(mark_value "$out" config_mode)
  if [ "$config_mode" = "600" ]; then
    pass "$image: /etc/enigma-sensor/config.json is mode 600"
  else
    fail "$image: /etc/enigma-sensor/config.json is mode 600" "got '${config_mode:-<no marker>}'"
  fi

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

# --- Phase 5b: a tampered bundle is refused (22.04 only) ----------------------
# One flipped byte in a bundled deb must fail the manifest check, so the
# installer never hands that file to apt. OBS is blackholed, so Zeek ends up
# not installed at all.
echo "=== Phase 5b: tampered bundle on ubuntu:22.04 ==="
TAMPER_SCRIPT=$(cat <<'CONTAINER'
apt-get update >/dev/null
cp -a /release /tmp/release
deb=$(ls /tmp/release/zeek/ubuntu-22.04/zeek-lts-core_*.deb)
printf '\x00' | dd of="$deb" bs=1 seek=4096 count=1 conv=notrunc 2>/dev/null
cd /tmp/release
bash install-enigma-sensor.sh
echo "MARK zeek_lts_core_status=$(dpkg -s zeek-lts-core 2>&1 | sed -n 's/^Status: //p')"
CONTAINER
)
out=""
status=0
out=$(run_install_container ubuntu:22.04 <<<"$TAMPER_SCRIPT" 2>&1) || status=$?
printf '%s\n' "$out"
if printf '%s' "$out" | grep -q 'fail checksum verification'; then
  pass "tampered bundle: installer reports the checksum failure"
else
  fail "tampered bundle: installer reports the checksum failure" \
    "expected 'fail checksum verification' in the output"
fi
if [ "$(mark_value "$out" zeek_lts_core_status)" != "install ok installed" ]; then
  pass "tampered bundle: the tampered Zeek package is not installed"
else
  fail "tampered bundle: the tampered Zeek package is not installed" "zeek-lts-core is installed"
fi

# --- Phase 6: upgrade from a pre-8.0.10 release (both images) ----------------
# Releases up to 1.9.3 installed Zeek 8.0.5 as zeek-core, zeekctl and zeek-client,
# and a sensor package that depends on zeek-core. The zeek-lts packages conflict
# with zeek-core and zeekctl, ship zeek-client's files, and take over the same
# conffiles, so this upgrades a host that has those exact 8.0.5 packages (taken
# from git: OBS no longer serves them) with edited conffiles. A stub stands in
# for the old sensor package; only its dependency matters.
OLD_ZEEK_REF=87f2f3c4f7e2d015526456f20218f3e84a8189e3
OLD_ZEEK_DEBS="zeek-core_8.0.5-0_amd64.deb zeekctl_8.0.5-0_amd64.deb zeek-client_8.0.5-0_all.deb"
if ! git -C "$REPO_ROOT" cat-file -e "$OLD_ZEEK_REF^{commit}" 2>/dev/null; then
  # CI checks out with depth 1.
  git -C "$REPO_ROOT" fetch -q --depth 1 origin "$OLD_ZEEK_REF"
fi
OLD_ZEEK_DIR=$(mktemp -d)
for deb in $OLD_ZEEK_DEBS; do
  git -C "$REPO_ROOT" show "$OLD_ZEEK_REF:installer/linux/zeek/$deb" > "$OLD_ZEEK_DIR/$deb"
done
git -C "$REPO_ROOT" show "$OLD_ZEEK_REF:installer/linux/zeek/SHA256SUMS" > "$OLD_ZEEK_DIR/SHA256SUMS"
if ! (cd "$OLD_ZEEK_DIR" && sha256sum -c --quiet SHA256SUMS); then
  echo "ERROR: the Zeek 8.0.5 packages from $OLD_ZEEK_REF fail their SHA256SUMS"
  exit 1
fi

run_upgrade_container() {
  local image="$1"
  docker run --rm -i \
    --add-host download.opensuse.org:127.0.0.1 \
    -e "ENIGMA_API_KEY=$TEST_API_KEY" \
    -e "ENIGMA_NETWORK_ID=$TEST_NETWORK_ID" \
    -e DEBIAN_FRONTEND=noninteractive \
    -v "$RELEASE_DIR:/release" \
    -v "$OLD_ZEEK_DIR:/old:ro" \
    "$image" bash -s
}

# Installs the earlier release's packages, then edits two conffiles. Shared by
# the upgrade and failed-upgrade runs below.
OLD_HOST_SETUP=$(cat <<'CONTAINER'
set -e
apt-get update >/dev/null
mkdir -p /tmp/stub/DEBIAN
printf 'Package: enigma-sensor\nVersion: 0.0.1\nArchitecture: all\nMaintainer: test\nDepends: zeek-core, tcpdump\nDescription: stub\n' > /tmp/stub/DEBIAN/control
dpkg-deb --build /tmp/stub /tmp/enigma-sensor-old.deb >/dev/null
apt-get install -y --no-install-recommends /old/*.deb /tmp/enigma-sensor-old.deb >/dev/null
echo "# enigma-upgrade-test" >> /opt/zeek/etc/node.cfg
echo "# enigma-upgrade-test" >> /opt/zeek/share/zeek/site/local.zeek
echo "MARK before_sensor=$(dpkg -s enigma-sensor | sed -n 's/^Version: //p')"
echo "MARK before_zeek=$(/opt/zeek/bin/zeek --version 2>&1 | head -n 1)"
set +e
CONTAINER
)

UPGRADE_SCRIPT="$OLD_HOST_SETUP"$(cat <<'CONTAINER'

cd /release
bash install-enigma-sensor.sh </dev/null
echo "MARK installer_exit=$?"
echo "MARK sensor_status=$(dpkg -s enigma-sensor 2>&1 | sed -n 's/^Status: //p')"
echo "MARK sensor_version=$(dpkg -s enigma-sensor 2>&1 | sed -n 's/^Version: //p')"
echo "MARK zeek_core_status=$(dpkg -s zeek-core 2>&1 | sed -n 's/^Status: //p')"
echo "MARK zeek_client_status=$(dpkg -s zeek-client 2>&1 | sed -n 's/^Status: //p')"
echo "MARK zeek_client_owner=$(dpkg -S /opt/zeek/bin/zeek-client 2>&1 | cut -d: -f1)"
echo "MARK zeek_version=$(/opt/zeek/bin/zeek --version 2>&1 | head -n 1)"
grep -q enigma-upgrade-test /opt/zeek/etc/node.cfg && echo "MARK node_cfg=kept" || echo "MARK node_cfg=lost"
grep -q enigma-upgrade-test /opt/zeek/share/zeek/site/local.zeek && echo "MARK local_zeek=kept" || echo "MARK local_zeek=lost"
CONTAINER
)

for image in ubuntu:22.04 ubuntu:24.04; do
  echo "=== Phase 6: upgrade from Zeek 8.0.5 on $image ==="
  out=""
  status=0
  out=$(run_upgrade_container "$image" <<<"$UPGRADE_SCRIPT" 2>&1) || status=$?
  printf '%s\n' "$out"
  if [ "$status" -ne 0 ]; then
    fail "upgrade $image: container run completed" "docker run exited $status"
  fi

  if [ "$(mark_value "$out" before_sensor)" = "0.0.1" ] \
    && printf '%s' "$(mark_value "$out" before_zeek)" | grep -q 'version 8\.0\.5$'; then
    pass "upgrade $image: earlier release installed (Zeek 8.0.5, old sensor package)"
  else
    fail "upgrade $image: earlier release installed (Zeek 8.0.5, old sensor package)" \
      "the 8.0.5 packages or the stub sensor did not install"
  fi

  installer_exit=$(mark_value "$out" installer_exit)
  if [ "$installer_exit" = "0" ]; then
    pass "upgrade $image: installer exit status is 0"
  else
    fail "upgrade $image: installer exit status is 0" "got '${installer_exit:-<no marker>}'"
  fi

  sensor_status=$(mark_value "$out" sensor_status)
  sensor_version=$(mark_value "$out" sensor_version)
  if [ "$sensor_status" = "install ok installed" ] && [ "$sensor_version" = "$SENSOR_VERSION" ]; then
    pass "upgrade $image: enigma-sensor $SENSOR_VERSION is installed"
  else
    fail "upgrade $image: enigma-sensor $SENSOR_VERSION is installed" \
      "got status '${sensor_status:-<none>}', version '${sensor_version:-<none>}'"
  fi

  if printf '%s' "$out" | grep -q '^Removing enigma-sensor'; then
    fail "upgrade $image: apt never removed the sensor" "the installer output shows 'Removing enigma-sensor'"
  else
    pass "upgrade $image: apt never removed the sensor"
  fi

  if [ "$(printf '%s' "$out" | grep -c '^Setting up enigma-sensor')" = "1" ]; then
    pass "upgrade $image: the sensor package is installed once"
  else
    fail "upgrade $image: the sensor package is installed once" \
      "expected exactly one 'Setting up enigma-sensor' line"
  fi

  if [ "$(mark_value "$out" zeek_core_status)" != "install ok installed" ]; then
    pass "upgrade $image: zeek-core is no longer installed"
  else
    fail "upgrade $image: zeek-core is no longer installed" "zeek-core is still installed"
  fi

  # zeek-lts-client ships zeek-client's files without declaring a conflict; apt
  # must remove zeek-client (it depends on the removed zeek-core) before unpacking.
  if [ "$(mark_value "$out" zeek_client_status)" != "install ok installed" ] \
    && [ "$(mark_value "$out" zeek_client_owner)" = "zeek-lts-client" ]; then
    pass "upgrade $image: zeek-client handed /opt/zeek/bin/zeek-client to zeek-lts-client"
  else
    fail "upgrade $image: zeek-client handed /opt/zeek/bin/zeek-client to zeek-lts-client" \
      "zeek-client status '$(mark_value "$out" zeek_client_status)', owner '$(mark_value "$out" zeek_client_owner)'"
  fi

  if printf '%s' "$out" | grep -q 'trying to overwrite'; then
    fail "upgrade $image: no file-overwrite conflict" "dpkg reported 'trying to overwrite'"
  else
    pass "upgrade $image: no file-overwrite conflict"
  fi

  zeek_version=$(mark_value "$out" zeek_version)
  if printf '%s' "$zeek_version" | grep -q 'version 8\.0\.10$'; then
    pass "upgrade $image: /opt/zeek/bin/zeek reports 8.0.10"
  else
    fail "upgrade $image: /opt/zeek/bin/zeek reports 8.0.10" "got '${zeek_version:-<no marker>}'"
  fi

  if [ "$(mark_value "$out" node_cfg)" = "kept" ] && [ "$(mark_value "$out" local_zeek)" = "kept" ]; then
    pass "upgrade $image: edited conffiles kept without a prompt"
  else
    fail "upgrade $image: edited conffiles kept without a prompt" \
      "node.cfg '$(mark_value "$out" node_cfg)', local.zeek '$(mark_value "$out" local_zeek)'"
  fi

  if printf '%s' "$out" | grep -q 'older than 8.0.10-0'; then
    fail "upgrade $image: no outdated-Zeek warning" "the installer warned that Zeek is outdated"
  else
    pass "upgrade $image: no outdated-Zeek warning"
  fi
done

# --- Phase 7: a failed Zeek upgrade is loud (22.04 only) ---------------------
# With the bundle gone and OBS blackholed, Zeek cannot be upgraded. The new
# sensor still installs against the old zeek-core (so the host keeps a working
# sensor), the installer says plainly that Zeek is outdated, and it exits 3.
echo "=== Phase 7: failed Zeek upgrade on ubuntu:22.04 ==="
FAILED_UPGRADE_SCRIPT="$OLD_HOST_SETUP"$(cat <<'CONTAINER'

cp -a /release /tmp/release
rm -rf /tmp/release/zeek
cd /tmp/release
bash install-enigma-sensor.sh </dev/null
echo "MARK installer_exit=$?"
echo "MARK sensor_version=$(dpkg -s enigma-sensor 2>&1 | sed -n 's/^Version: //p')"
echo "MARK zeek_version=$(/opt/zeek/bin/zeek --version 2>&1 | head -n 1)"
CONTAINER
)
out=""
status=0
out=$(run_upgrade_container ubuntu:22.04 <<<"$FAILED_UPGRADE_SCRIPT" 2>&1) || status=$?
printf '%s\n' "$out"
if [ "$(mark_value "$out" sensor_version)" = "$SENSOR_VERSION" ] \
  && printf '%s' "$(mark_value "$out" zeek_version)" | grep -q 'version 8\.0\.5$'; then
  pass "failed upgrade: new sensor installed, Zeek left at 8.0.5"
else
  fail "failed upgrade: new sensor installed, Zeek left at 8.0.5" \
    "sensor '$(mark_value "$out" sensor_version)', zeek '$(mark_value "$out" zeek_version)'"
fi
if printf '%s' "$out" | grep -q 'Zeek 8.0.5-0 is installed, older than 8.0.10-0'; then
  pass "failed upgrade: installer warns that Zeek is outdated"
else
  fail "failed upgrade: installer warns that Zeek is outdated" \
    "expected the outdated-Zeek warning in the output"
fi
# Exit 3 is the contract: the sensor stays, but the run is not a clean install.
installer_exit=$(mark_value "$out" installer_exit)
if [ "$installer_exit" = "3" ]; then
  pass "failed upgrade: installer exits 3"
else
  fail "failed upgrade: installer exits 3" "got '${installer_exit:-<no marker>}'"
fi

# --- Summary -----------------------------------------------------------------
echo "=== Summary ==="
if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES check(s) failed."
  exit 1
fi
echo "All checks passed."

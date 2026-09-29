#!/bin/bash
# Regenerates THIRD_PARTY_NOTICES at the repository root. Run it after changing go.mod or any
# file in this directory; CI fails when the committed file is out of date.
#
# The Go section is generated with go-licenses for every OS we ship (the dependency set differs
# slightly by platform), deduplicated by module. Zeek and NSSM are not Go modules, so their
# sections are maintained by hand in this directory.
set -euo pipefail
# Byte-order sorting, so the file is identical on every machine and CI can diff it.
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# Pinned here so CI and developers run the same version.
GO_LICENSES_PKG=github.com/google/go-licenses/v2@v2.0.1
OUT="$REPO_ROOT/THIRD_PARTY_NOTICES"
RULE='================================================================================'
SUBRULE='--------------------------------------------------------------------------------'

cd "$REPO_ROOT"
# The Linux Zeek version comes from the bundled package name, so an upgrade cannot leave it stale.
ZEEK_DEB="$(ls installer/linux/zeek/zeek-core_*_amd64.deb)"
ZEEK_VERSION="$(basename "$ZEEK_DEB" | sed -E 's/^zeek-core_([0-9.]+)-.*/\1/')"
MODCACHE="$(go env GOMODCACHE)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Built for the host before the loop: under GOOS=windows, `go run` would build a Windows binary.
GOBIN="$TMP" go install "$GO_LICENSES_PKG"

for os in linux windows darwin; do
  # Our own packages have no third-party license to report.
  GOOS=$os "$TMP/go-licenses" report ./cmd/enigma-sensor \
    --ignore EnigmaNetz/Enigma-Go-Sensor \
    --template "$SCRIPT_DIR/go-module.tmpl" >> "$TMP/rows" 2> "$TMP/err" \
    || { cat "$TMP/err" >&2; exit 1; }
done

# Each row is "<module cache path to LICENSE><TAB><license name>". The path encodes the
# module and version (<modcache>/<module>@<version>/...); the module cache escapes capitals
# as "!x", so undo that for display.
grep -v '^$' "$TMP/rows" | sort -u > "$TMP/unique"

{
  echo 'THIRD-PARTY SOFTWARE NOTICES'
  echo
  echo 'Enigma AI Sensor includes or is distributed with the third-party software listed'
  echo 'below. Each component is provided under its own license, reproduced here.'
  echo
  echo "$RULE"
  echo 'PART 1: Go modules compiled into the enigma-sensor binary (all platforms)'
  echo "$RULE"

  cut -f1 "$TMP/unique" | sort -u | while read -r path; do
    rel="${path#"$MODCACHE"/}"
    module="$(echo "${rel%%@*}" | perl -pe 's/!([a-z])/\U$1/g')"
    version="${rel#*@}"
    version="${version%%/*}"
    names="$(awk -F'\t' -v p="$path" '$1 == p { print $2 }' "$TMP/unique" | sort -u | paste -sd, -)"
    echo
    echo "$SUBRULE"
    echo "$module $version"
    echo "License: $names"
    echo "$SUBRULE"
    echo
    cat "$path"
    # Apache-2.0 section 4(d): a NOTICE file shipped with the module travels with it.
    for notice in "$(dirname "$path")"/NOTICE*; do
      [ -f "$notice" ] || continue
      echo
      echo "$module $(basename "$notice"):"
      echo
      cat "$notice"
    done
  done

  echo
  echo "$RULE"
  echo 'PART 2: Zeek'
  echo
  echo "Linux: the Zeek $ZEEK_VERSION packages in the release zip and the Docker image."
  echo 'Windows: the Zeek runtime installed with the sensor.'
  echo "$RULE"
  echo
  echo "$SUBRULE"
  echo 'Zeek (COPYING)'
  echo "$SUBRULE"
  echo
  cat "$SCRIPT_DIR/zeek/COPYING"
  echo
  echo "$SUBRULE"
  echo 'Software bundled with Zeek (COPYING-3rdparty)'
  echo "$SUBRULE"
  echo
  cat "$SCRIPT_DIR/zeek/COPYING-3rdparty"
  echo
  # The Linux packages' zeek binary has the Spicy runtime built in; see spicy/README.md.
  echo "$SUBRULE"
  echo 'Linux Zeek packages only: Spicy (LICENSE)'
  echo "$SUBRULE"
  echo
  cat "$SCRIPT_DIR/spicy/LICENSE"
  echo
  echo "$SUBRULE"
  echo 'Linux Zeek packages only: software bundled with Spicy (LICENSE.3rdparty)'
  echo "$SUBRULE"
  echo
  cat "$SCRIPT_DIR/spicy/LICENSE.3rdparty"
  echo
  # The Windows runtime is a custom build that also links libraries from outside Zeek's source
  # tree; see windows-zeek/README.md.
  for notice in "$SCRIPT_DIR"/windows-zeek/*.txt; do
    echo "$SUBRULE"
    echo 'Windows Zeek runtime only:'
    head -n1 "$notice"
    echo "$SUBRULE"
    echo
    tail -n +2 "$notice"
    echo
  done

  echo
  echo "$RULE"
  echo 'PART 3: NSSM'
  echo "$RULE"
  echo
  cat "$SCRIPT_DIR/nssm.txt"
} > "$OUT"

echo "Wrote $OUT"

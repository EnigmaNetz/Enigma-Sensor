#!/usr/bin/env bash
# Regenerates the records package's parity fixtures: one synthetic capture, run through Zeek
# twice with the sensor's embedded scripts, once writing tab-separated logs (the current upload
# format) and once writing JSON logs (LogAscii::use_json=T). -D makes Zeek's uids identical
# across the two runs so records can be compared one to one.
#
# Needs Zeek at /opt/zeek/bin/zeek (or ZEEK=...). Run from the repository root:
#   bash internal/records/testdata/regenerate.sh
set -euo pipefail

ZEEK="${ZEEK:-/opt/zeek/bin/zeek}"
here="internal/records/testdata"
scripts="internal/processor/common/zeekscripts"
logs=(conn.log dns.log dhcp.log ja3_ja4.log ja4s.log)

go run "./$here/genpcap" "$here/synthetic.pcap"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pcap="$(realpath "$here/synthetic.pcap")"
dhcp_script="$(realpath "$scripts/dhcp-fingerprint.zeek")"
ja3_script="$(realpath "$scripts/ja3-ja4-fingerprinting.zeek")"

for format in tsv json; do
  mkdir -p "$work/$format" "$here/$format"
  extra=()
  if [ "$format" = json ]; then extra=(LogAscii::use_json=T); fi
  # ${extra[@]+...} keeps an empty array from failing set -u on bash older than 4.4.
  (cd "$work/$format" && "$ZEEK" -D -C -r "$pcap" "$dhcp_script" "$ja3_script" ${extra[@]+"${extra[@]}"})
  for log in "${logs[@]}"; do cp "$work/$format/$log" "$here/$format/$log"; done
done

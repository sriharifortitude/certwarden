#!/usr/bin/env bash
# Prints the README's example: each command, then what it prints. Run from anywhere.
set -u
cd "$(dirname "$0")/.."
bin=${CERTWARDEN:-./bin/certwarden}
first=1
for f in fullchain expired wrong-order missing-intermediate weak; do
  [ $first -eq 1 ] || echo
  first=0
  echo "\$ certwarden testdata/$f.pem --now 2026-10-10T00:00:00Z"
  "$bin" "testdata/$f.pem" --now 2026-10-10T00:00:00Z | tr -d '\r'
done

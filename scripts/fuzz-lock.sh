#!/bin/sh
# Give the fuzz workspace (fuzz/, its own Cargo workspace) the main
# workspace's dependency versions: copy Cargo.lock to fuzz/Cargo.lock.
# Cargo then drops what the fuzz targets don't use and adds only what the
# main workspace doesn't have (libfuzzer-sys).
#
# fuzz/Cargo.lock is not committed (.gitignore): a committed copy went
# stale with every version bump or dependency change, and `--locked` builds
# of the fuzz targets failed. CI and scripts/fuzz.sh run this first; build
# the fuzz targets without `--locked`.
set -eu
cd "$(dirname "$0")/.."
cp Cargo.lock fuzz/Cargo.lock

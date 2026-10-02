#!/bin/sh
# Regenerate the FlatBuffers bindings (requires `cargo install planus-cli --version 1.3.0`).
set -e
cd "$(dirname "$0")"
planus rust -o src/generated.rs schema/wire.fbs

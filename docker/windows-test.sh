#!/bin/sh
# Run the Windows unit tests under Wine (x86_64 Linux container): builds the
# test binaries with cargo-xwin, then executes them. Covers DPAPI, named
# pipes, ACLs, process CPU time and everything platform-independent.
# Real Windows is still needed for wintun, NRPT and the service manager.
set -eu
cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
cargo xwin test --no-run --target x86_64-pc-windows-msvc -p webjetd -p webjet-core -p webjet-net --no-default-features --lib 2>&1 \
  | grep -oE 'target/x86_64-pc-windows-msvc/debug/deps/[a-z_-]+-[0-9a-f]+\.exe' | sort -u > target/windows-tests.txt
cat target/windows-tests.txt
# Each test runs in its own process: x86 emulation of Wine on Apple Silicon
# (Rosetta) sometimes faults ("invalid gdt selector"), which is reported as
# EMU instead of taking the remaining tests down with it.
docker run --rm --platform linux/amd64 -v "$PWD/target":/t -w /t ${WINE_IMAGE:-scottyhardy/docker-wine:stable-9.0} sh -c '
  export WINEDEBUG=-all WINEPREFIX=$HOME/wp; mkdir -p $HOME
  wineboot -i >/dev/null 2>&1 || true
  pass=0; fail=0; emu=0
  for T in $(sed "s#^target/##" windows-tests.txt); do
    echo "== $T"
    for t in $(wine $T --list 2>/dev/null | grep ": test" | sed "s/: test.*//" | tr -d "\r" | grep -v randomized); do
      r=$(wine $T --exact "$t" --test-threads=1 2>&1 | tr -d "\r")
      if echo "$r" | grep -q "test result: ok. 1 passed"; then pass=$((pass+1));
      elif echo "$r" | grep -q "rosetta error"; then emu=$((emu+1)); echo "EMU   $t";
      else fail=$((fail+1)); echo "FAIL  $t"; echo "$r" | grep -E "panicked|left|right" | head -4; fi
    done
  done
  echo "passed=$pass failed=$fail emulator-faults=$emu"
  [ $fail = 0 ]'

#!/bin/sh
# Run cargo for a macOS target, on a Mac or cross-compiled on Linux:
#
#   scripts/macos-cargo.sh aarch64-apple-darwin build --release -p webjetd
#   scripts/macos-cargo.sh x86_64-apple-darwin clippy -p webjetd --all-targets -- -D warnings
#
# On a Mac this is plain cargo for the target. On Linux it compiles with
# Clang and links with ld64.lld against a macOS SDK copied from a Mac (the
# CI image, webj8-internal/webjet-builder, has one):
#   WEBJET_MACOS_SDK   the SDK directory (the image sets /opt/macos-sdk/MacOSX.sdk)
#   WEBJET_MACOS_LLVM  directory with clang, clang++, llvm-ar and ld64.lld,
#                      if they aren't on PATH
# Output goes to target/<target>/.
set -eu

usage="usage: scripts/macos-cargo.sh <aarch64|x86_64>-apple-darwin <cargo args…>"
T=${1:?$usage}
shift
case $T in
    aarch64-apple-darwin) arch=arm64 min=11.0 ;;
    x86_64-apple-darwin) arch=x86_64 min=10.12 ;;
    *) echo "$usage" >&2; exit 2 ;;
esac
rustup target list --installed 2>/dev/null | grep -qx "$T" || rustup target add "$T" >&2
export CARGO_BUILD_TARGET=$T
# rustc's defaults for these targets, so the C code (BoringSSL, aws-lc)
# targets the same macOS versions as the Rust code.
export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-$min}
[ "$(uname -s)" = Darwin ] && exec cargo "$@"

SDK=${WEBJET_MACOS_SDK:?set WEBJET_MACOS_SDK to a macOS SDK directory (MacOSX.sdk)}
[ -f "$SDK/SDKSettings.json" ] || { echo "macos-cargo: $SDK is not a macOS SDK" >&2; exit 1; }
[ -z "${WEBJET_MACOS_LLVM:-}" ] || PATH=$WEBJET_MACOS_LLVM:$PATH
for tool in clang clang++ llvm-ar llvm-ranlib ld64.lld; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "macos-cargo: $tool not found (set WEBJET_MACOS_LLVM)" >&2
        exit 1
    }
done

# Build scripts ask xcrun for the SDK and tools (boring-sys for bindgen,
# CMake's Darwin platform files): answer from the SDK and LLVM.
tools=${XDG_CACHE_HOME:-${HOME:?}/.cache}/webjet-macos-tools
mkdir -p "$tools"
cat > "$tools/xcrun.new" <<'EOF'
#!/bin/sh
# xcrun for cross-compiling to macOS on Linux (scripts/macos-cargo.sh).
tool() {
    case $1 in
        cc | clang | gcc) echo clang ;;
        c++ | clang++ | g++) echo clang++ ;;
        ld) echo ld64.lld ;;
        ar | libtool) echo llvm-ar ;;
        ranlib | strip | lipo | otool | nm | objdump | install_name_tool) echo "llvm-$1" | tr _ - ;;
        *) echo "$1" ;;
    esac
}
while [ $# -gt 0 ]; do
    case $1 in
        --sdk | -sdk | --toolchain | -toolchain) shift ;;
        --show-sdk-path | -show-sdk-path) echo "$SDKROOT"; exit 0 ;;
        --show-sdk-version | -show-sdk-version)
            sed -n 's/.*"Version" *: *"\([^"]*\)".*/\1/p' "$SDKROOT/SDKSettings.json"; exit 0 ;;
        --show-sdk-platform-path | -show-sdk-platform-path) dirname "$SDKROOT"; exit 0 ;;
        --find | -find | -f) command -v "$(tool "$2")"; exit ;;
        --log | -log | --verbose | -v | --no-cache | -n | --kill-cache | -k) ;;
        -*) echo "xcrun: unsupported option $1" >&2; exit 1 ;;
        *) t=$(tool "$1"); shift; exec "$t" "$@" ;;
    esac
    shift
done
echo "xcrun: no tool given" >&2
exit 1
EOF
chmod +x "$tools/xcrun.new"
mv "$tools/xcrun.new" "$tools/xcrun"
# CMake's Darwin support looks for Apple's binary tools by their names.
for t in install_name_tool otool lipo; do
    p=$(command -v "llvm-$(echo "$t" | tr _ -)") || {
        echo "macos-cargo: llvm-$(echo "$t" | tr _ -) not found" >&2
        exit 1
    }
    ln -sf "$p" "$tools/$t"
done
PATH=$tools:$PATH
export PATH
# cc-rs and rustc take the SDK from here instead of running xcrun.
export SDKROOT=$SDK

v=$(echo "$T" | tr 'a-z-' 'A-Z_')
u=$(echo "$T" | tr '-' '_')
llvm_target=$arch-apple-macosx$MACOSX_DEPLOYMENT_TARGET
# The compilers for the target: Clang with the SDK, linking with ld64.lld
# (Clang would run the system's GNU ld, which can't link Mach-O). Wrappers
# rather than flags because CMake's checks (BoringSSL) link without
# CFLAGS' linker choice. ld64.lld signs arm64 programs ad hoc, as Apple's
# linker does (macOS refuses unsigned arm64 programs). The SDK's libc++
# headers, not LLVM's own: they must match the SDK's library.
for cc in clang clang++; do
    extra=
    [ $cc = clang++ ] && extra="-nostdinc++ -isystem $SDK/usr/include/c++/v1"
    cat > "$tools/$T-$cc.new" <<EOF
#!/bin/sh
exec $(command -v $cc) --target=$llvm_target -isysroot $SDK -fuse-ld=lld -Wno-unused-command-line-argument $extra "\$@"
EOF
    chmod +x "$tools/$T-$cc.new"
    mv "$tools/$T-$cc.new" "$tools/$T-$cc"
done
# C and C++ (BoringSSL, aws-lc, zstd).
export "CC_$u=$T-clang" "CXX_$u=$T-clang++" "AR_$u=llvm-ar"
export "BINDGEN_EXTRA_CLANG_ARGS_$u=--target=$llvm_target -isysroot $SDK"
# Linking the Rust programs.
export "CARGO_TARGET_${v}_LINKER=$T-clang"
exec cargo "$@"

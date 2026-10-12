# Patched crates

Copies of crates.io crates with a change Webjet needs, used through
`[patch.crates-io]` in the workspace `Cargo.toml`. They are not workspace
members (`exclude = ["vendor"]`), so clippy and `cargo fmt` don't check them.

## gpui 0.2.2 and gpui_media 0.2.2

Upstream: <https://github.com/zed-industries/zed> (`crates/gpui`,
`crates/media`), Apache-2.0, as published on crates.io (gpui: git
69e2130295c2649963eb639fc70b4f2ee8ea1624).

Change: their build scripts decide what to generate with
`#[cfg(target_os = ...)]`. A build script runs on the build machine, so
that is the build machine's OS, not the target's. Cross-compiling the app
on Linux (`scripts/macos-cargo.sh`, `cargo xwin`, the CI image), they
skipped the macOS and Windows steps, and gpui failed to compile without
`dispatch_sys.rs`, `stitched_shaders.metal` or `shaders_bytes.rs`. The
copies decide by `CARGO_CFG_TARGET_OS` instead:

- `gpui/build.rs`: runs `macos::build()` (bindgen for libdispatch, cbindgen
  for the shader header and, with `runtime_shaders` as webjet-app uses, the
  stitched shader source) for macOS targets on any build machine, and
  `windows::build()` for Windows targets. The WGSL check runs for Linux and
  FreeBSD targets as before.
- `gpui/build.rs`, Windows: no shader compilation any more (upstream ran
  `fxc.exe` from the Windows SDK in release builds and wrote
  `shaders_bytes.rs`). Only the manifest resource is left, which
  embed-resource builds with `llvm-rc` when cross-compiling.
- `gpui/src/platform/windows/directx_renderer.rs`, module
  `shader_resources`: compiles the shaders at run time in every build, with
  `D3DCompile` (d3dcompiler_47.dll, part of Windows) from the HLSL embedded
  with `include_str!` (`shaders.hlsl`, `color_text_raster.hlsl`, their
  `#include "alpha_correction.hlsl"` inlined by text replacement).
  Release builds use `D3DCOMPILE_OPTIMIZATION_LEVEL3` (fxc's `/O3`), debug
  builds debug info. Upstream used precompiled bytes in release builds and
  `D3DCompileFromFile` on the build machine's source path in debug builds.
  Same shader model (`vs_4_1`/`ps_4_1`) and entry points
  (`<module>_vertex`/`_fragment`).
- `gpui/build.rs`, Windows manifest: compiles a copy of
  `resources/windows/gpui.rc` from `OUT_DIR` that names the manifest by its
  absolute path; `llvm-rc` resolved the relative path against `OUT_DIR`
  ("file not found"). It fails if `gpui.rc` no longer names
  `"resources/windows/gpui.manifest.xml"`.
- `gpui/src/platform/windows/destination_list.rs`: the jump-list
  description's length is found in Rust instead of with ICU's `u_strlen`,
  so `webjet-app.exe` doesn't import `icuuc.dll` (only in Windows 10 1903
  and later, not in Wine).
- `gpui/Cargo.toml`: bindgen, cbindgen, naga and embed-resource are build
  dependencies for every target, as the build machine needs them whatever
  the target is. The example and test targets are removed (their sources
  aren't copied).
- `gpui/Cargo.toml` and `gpui_media/Cargo.toml`: `core-foundation` is
  `0.10` instead of exactly `=0.10.0`, because netconfig-rs 0.1.6 (through
  tun-rs in webjetd) needs 0.10.1; `taffy` is `0.9` instead of `=0.9.0`
  (0.9.2 is a bug-fix release). `cocoa` and `cocoa-foundation` stay pinned
  at `=0.26.0`/`=0.2.0`: cocoa 0.26.1 deprecates its whole API in favour of
  objc2, which floods the macOS build with hundreds of warnings.
- Trackpad pinch: upstream drops macOS magnify events, so a two-finger
  pinch did nothing. `gpui/src/interactive.rs` adds `PinchEvent` (position,
  `delta` = NSEvent `magnification`, modifiers, phase) and
  `PlatformInput::Pinch`; `gpui/src/window.rs` `dispatch_event` tracks its
  position like a scroll wheel event; `gpui/src/platform/mac/window.rs`
  registers `magnifyWithEvent:` and `gpui/src/platform/mac/events.rs` turns
  `NSEventTypeMagnify` into it. Listen with `window.on_mouse_event` (there
  is no element method). Windows sends pinches as Ctrl + wheel already.
- `gpui/src/taffy.rs`: the grid template's `length(0.0)`/`fr(1.0)` take
  explicit `f32` literals; rustc warns that falling back to `f32` there
  (`float_literal_f32_fallback`, rust-lang/rust#154024) will become an
  error.
- `gpui_media/build.rs`: generates its CoreMedia/CoreVideo bindings for macOS
  targets on any build machine. On Linux, `xcrun --show-sdk-path` is
  macos-cargo.sh's stand-in and bindgen takes the target from
  `BINDGEN_EXTRA_CLANG_ARGS_<target>`.

Every changed place has a `Webjet:` comment. To update gpui,
copy the new version's files over these (`build.rs`, `Cargo.toml`, `src/`,
`resources/`, `LICENSE-APACHE`, `README.md`), redo the changes above and
`cargo update -p gpui -p gpui_media`.

`scripts/gpui-vendor-check.sh` tells whether crates.io has a newer gpui,
gpui_media or gpui_http_client than these copies; the pre-commit hook (`.githooks/pre-commit`,
enabled with `git config core.hooksPath .githooks`) runs it once a day.

## gpui_http_client 0.2.2

Upstream: same repository (`crates/http_client`), Apache-2.0, as published
on crates.io. Unchanged except `Cargo.toml`: its `zed-async-tar`
dependency has `default-features = false`. The default feature `xattr`
pulled in `xattr` 0.2.3, which uses `libc::ENOATTR`; libc 0.2.190 removed
that constant on Linux, so webjet-app no longer built for Linux and libc
had to stay at 0.2.189. Only `github_download` uses the tar crate (to
unpack downloads), gpui never calls it, and extended attributes in tar
files don't matter to Webjet.

To update it, copy the new version's `Cargo.toml`, `src/` and
`LICENSE-APACHE` over this copy, set `default-features = false` again (it
has a `Webjet:` comment) and `cargo update -p gpui_http_client`.

## reed-solomon-erasure 6.0.0

Upstream: <https://github.com/darrenldl/reed-solomon-erasure>, MIT, as
published on crates.io (git a1ca49de5384445b68ade7d72f31f0379c199943).
Copied: `build.rs`, `Cargo.toml`, `src/`, `simd_c/`, `LICENSE`,
`README.md`, `CHANGELOG.md`.

Change: with `simd-accel` (webjet-net turns it on) upstream compiles
`simd_c/reedsolomon.c` once, for one CPU level picked at build time: on
x86_64 `-march=haswell`, so a release build died with SIGILL at the first
FEC group on CPUs without AVX2 (Celeron J1900/J4125/N5105, Pentium Silver:
common in fanless OPNsense boxes); built for plain x86-64 instead, the C
code (SSE2 only) is five times slower than the Rust fallback. It also left
out every `target_env = "msvc"` target. The copy chooses at run time:

- `build.rs` `compile_simd_c`: decides by `CARGO_CFG_TARGET_ARCH`/`_OS`
  (the target, not the build machine). x86_64: compiles the C file twice,
  with `-mssse3` and `-mavx2`, renaming its two exported functions with
  `-D` to `reedsolomon_gal_mul{,_xor}_ssse3` / `_avx2`. aarch64: once
  (NEON is always there; `RUST_REED_SOLOMON_ERASURE_ARCH` still adds a
  `-march`). MSVC targets build it too when the compiler is clang-cl (cargo
  xwin); MSVC's own `cl.exe` doesn't know the GCC vector extensions and
  gets the Rust code. Sets `cfg(rse_simd)` plus `rse_simd_x86` or
  `rse_simd_neon` when the C code was built.
- `src/galois_8.rs`: `kernels()` picks AVX2, else SSSE3 (by
  `std::is_x86_feature_detected!`, cached by std), else the Rust code;
  `mul_slice`/`mul_slice_xor` call it and finish the tail in Rust as
  before. `pub fn simd_level()` names the choice (webjetd logs it at start
  and shows it as `fec_simd` in `webjetctl local status`). Test
  `simd_kernels_match_the_rust_code` compares every kernel the CPU can run
  with the Rust code for all 256 constants.
- `src/lib.rs`: `extern crate std` on x86_64 with the C code, for the
  feature detection (the crate is `no_std` without its `std` feature, which
  Webjet leaves off).
- `Cargo.toml`: the `[[bench]]` entry is removed (`benches/` isn't copied).

Measured with 1280-byte shards, k = 10 data + 3 parity, encode /
reconstruct: Xeon Platinum 8372HC Rust 0.98 / 0.91 GB/s, SSSE3 build
(`x86-64-v2`) 4.3 / 3.1, AVX2 10.4 / 5.2; Apple M-series Rust 0.87 / 0.91,
NEON 2.95 / 3.60. Checked under `qemu-x86_64 -cpu Nehalem|core2duo|qemu64`:
SSSE3, SSSE3 and the Rust code are picked, and the crate's tests pass.

To update: copy the files above from the new release over the vendored
copy, redo the changes (every place has a `Webjet:` comment), then
`cargo update -p reed-solomon-erasure`.


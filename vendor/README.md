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
- `gpui_media/build.rs`: generates its CoreMedia/CoreVideo bindings for macOS
  targets on any build machine. On Linux, `xcrun --show-sdk-path` is
  macos-cargo.sh's stand-in and bindgen takes the target from
  `BINDGEN_EXTRA_CLANG_ARGS_<target>`.

Every changed place has a `Webjet:` comment. To update gpui,
copy the new version's files over these (`build.rs`, `Cargo.toml`, `src/`,
`resources/`, `LICENSE-APACHE`, `README.md`), redo the changes above and
`cargo update -p gpui -p gpui_media`.

`scripts/gpui-vendor-check.sh` tells whether crates.io has a newer gpui or
gpui_media than these copies; the pre-commit hook (`.githooks/pre-commit`,
enabled with `git config core.hooksPath .githooks`) runs it once a day.

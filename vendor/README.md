# Patched crates

Copies of crates.io crates with a change Webjet needs, used through
`[patch.crates-io]` in the workspace `Cargo.toml`. They are not workspace
members (`exclude = ["vendor"]`), so clippy and `cargo fmt` don't check them.

## gpui 0.2.2 and gpui_media 0.2.2

Upstream: <https://github.com/zed-industries/zed> (`crates/gpui`,
`crates/media`), Apache-2.0, as published on crates.io (gpui: git
69e2130295c2649963eb639fc70b4f2ee8ea1624).

Change: their build scripts decide what to generate with
`#[cfg(target_os = "macos")]`. A build script runs on the build machine, so
that is the build machine's OS, not the target's. Cross-compiling the macOS
app on Linux (`scripts/macos-cargo.sh`, the CI image), they skipped the
macOS steps, and gpui failed to compile without `dispatch_sys.rs` and
`stitched_shaders.metal`. The copies check `CARGO_CFG_TARGET_OS` instead:

- `gpui/build.rs`: runs `macos::build()` (bindgen for libdispatch, cbindgen
  for the shader header and, with `runtime_shaders` as webjet-app uses, the
  stitched shader source) for macOS targets on any build machine. The WGSL
  check runs for Linux and FreeBSD targets as before.
- `gpui/Cargo.toml`: bindgen, cbindgen and naga are build dependencies for
  every target, as the build machine needs them whatever the target is.
  The example and test targets are removed (their sources aren't copied).
- `gpui_media/build.rs`: generates its CoreMedia/CoreVideo bindings for macOS
  targets on any build machine. On Linux, `xcrun --show-sdk-path` is
  macos-cargo.sh's stand-in and bindgen takes the target from
  `BINDGEN_EXTRA_CLANG_ARGS_<target>`.

Windows is still built only on Windows: gpui's release build there needs
`fxc.exe` from the Windows SDK to compile its HLSL shaders.

Every changed place has a `Webjet:` comment. To update gpui,
copy the new version's files over these (`build.rs`, `Cargo.toml`, `src/`,
`resources/`, `LICENSE-APACHE`, `README.md`), redo the changes above and
`cargo update -p gpui -p gpui_media`.

`scripts/gpui-vendor-check.sh` tells whether crates.io has a newer gpui or
gpui_media than these copies; the pre-commit hook (`.githooks/pre-commit`,
enabled with `git config core.hooksPath .githooks`) runs it once a day.

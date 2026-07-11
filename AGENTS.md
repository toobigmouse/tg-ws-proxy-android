# tg-ws-proxy-android — Agent Guide

## What this is

A local MTProto proxy for Telegram Android. Runs a proxy on `127.0.0.1:1443` that relays Telegram traffic through WebSocket (WSS) connections, optionally via Cloudflare, to bypass network restrictions.

```
Telegram App → Local MTProto Proxy (127.0.0.1:1443) → Rust engine → WSS (direct/CF) → Telegram DC
```

## Build system (dual)

| Layer | Language | Entry point |
|-------|----------|-------------|
| Native engine (Android) | Rust (`src/lib.rs`) | Cdylib → `libtgwsproxy.so` |
| Native engine (Windows) | Rust (`src/main.rs`) | Binary → `tgwsproxy.exe` |
| Android app | Kotlin + Jetpack Compose (`app/`) | APK via Gradle |

**Android:** `.so` files are prebuilt and checked in at `app/src/main/jniLibs/`.  
**Windows:** binary uses the same engine code; build with `cargo build --release`.

## Commands

```bat
build_so.bat              # Build .so for arm64 + arm32 via cargo ndk (prerequisite: NDK, cargo-ndk, Rust targets)
build_apk.bat             # Build all release APKs (prerequisite: .so must exist in jniLibs/)
gradlew assembleRelease   # Build APKs directly (all flavors)
gradlew assembleArm64Release / assembleArm32Release / assembleUniversalRelease
gradlew installArm64Debug # Install debug on device
gradlew clean
```

## Critical gotchas

1. **Rust first, then APK** — `build_so.bat` must complete before `build_apk.bat`. The `.so` output goes into `jniLibs/` which Gradle reads.
2. **`local.properties` contains placeholders** — edit keystore path/password/alias and SDK path before any release build.
3. **No tests** — neither Rust tests (`#[cfg(test)]`) nor Android tests exist. No CI, no formatter, no linter config.
4. **Russian comments** throughout both Rust and Kotlin code.
5. **Rust release profile:** `opt-level = "z"`, LTO, `panic = "abort"` — any Rust panic kills the process.
6. **Desktop `cargo build`** works for syntax-checking the Rust crate but `android_logger` is gated behind `#[cfg(target_os = "android")]`.
7. **`cargo-ndk`** is installed automatically by `build_so.bat` if missing; Rust Android targets are installed automatically too.
8. **Three APK flavors:** `arm32` (minsdk 21), `arm64` (minsdk 24), `universal`.
9. **Windows binary** (`tgwsproxy-cli.exe`): `cargo build --release` produces it (plus `tgwsproxy.dll` — артефакт cdylib для Android, можно игнорировать). Run with `--help` for options.
10. **Android builds** now use `--lib` flag in `build_so.bat` to skip the binary target.
11. **Windows CLI:** `config.toml` auto-loaded from exe dir; CLI flags override it. Secret auto-generated if missing. Flags: `--bind`, `--port`, `--secret`, `--dc-ips`, `--pool-size`, `--log-file`, `--firewall`, `--tray`, `--gui`, `--install`, `--uninstall`, `--verbose`. `--install`/`--uninstall` require admin rights. `--tray` hides the console and shows a system tray icon. `--gui` opens a native window (egui). Ctrl+C for graceful shutdown. File logging (`--log-file`) appends to file + stdout simultaneously.

## Architecture notes

- **Rust engine** (`src/`): raw WebSocket handshake/framing via tokio+rustls, AES-256-CTR MTProto obfuscation, Cloudflare domain management (Caesar-encoded domains, DoH from 4 providers + system resolver), connection pool with background refill.
- **Kotlin app** (`app/src/main/java/com/amurcanov/tgwsproxy/`): Jetpack Compose UI (4 tabs), foreground service with JNA bridge to `.so`, DataStore preferences, auto-update via GitHub API, quick settings tile, boot receiver.
- **JNA bridge** (`NativeProxy.kt`) maps C-FFI exports from Rust (`StartProxy`, `StopProxy`, `SetPoolSize`, etc.).
- **Tokio runtime** is a global `OnceCell` singleton, created on first `StartProxy` call, never dropped.
- **Settings** use DataStore Preferences (not SharedPreferences).

## Testing

None. Any verification must be done via `gradlew installArm64Debug` and manual testing on device, or by inspecting Logcat output (the app parses its own Logcat via `ProcessBuilder` at runtime).

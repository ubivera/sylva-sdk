//! `gen-bindings` — generate the C# bindings (+ the native library) for the Hub
//! shells from the sylva-sdk FFI surface. Builds the `ffi`-feature cdylib, runs
//! `uniffi-bindgen-cs`, and copies the native library into the output dir.
//!
//!   cargo run --bin gen-bindings -- [--out-dir <dir>] [--release]
//!
//! Default `--out-dir`: `../sylva-client/bindings/csharp` (sibling layout).
//!
//! Cross-platform + cargo-native (replaces the old PowerShell script): the
//! native library name is resolved per-OS (`sylva_sdk.dll` / `libsylva_sdk.dylib`
//! / `libsylva_sdk.so`). Prerequisites: the MSVC build env on Windows (see
//! docs/dev/server-build-env.md) and `uniffi-bindgen-cs` whose `+vX.Y.Z` tag
//! matches the crate's `uniffi` pin (see docs/dev/hub-csharp-bindings.md).

use std::path::PathBuf;
use std::process::Command;

type Fallible = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn main() -> Fallible {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut out_dir = crate_dir
        .join("..")
        .join("sylva-client")
        .join("bindings")
        .join("csharp");
    let mut release = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out-dir" => out_dir = PathBuf::from(args.next().ok_or("--out-dir needs a value")?),
            "--release" => release = true,
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    ensure_tool()?;

    let profile = if release { "release" } else { "debug" };
    println!("Building sylva-sdk cdylib ({profile})...");
    let mut build = Command::new("cargo");
    build
        .current_dir(&crate_dir)
        .args(["build", "--features", "ffi", "--lib"]);
    if release {
        build.arg("--release");
    }
    run(build)?;

    let lib_name = format!(
        "{}sylva_sdk{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    let lib = crate_dir.join("target").join(profile).join(&lib_name);
    if !lib.exists() {
        return Err(format!("expected library not found: {}", lib.display()).into());
    }

    std::fs::create_dir_all(&out_dir)?;
    println!("Generating C# bindings -> {}", out_dir.display());
    let mut bindgen = Command::new("uniffi-bindgen-cs");
    bindgen
        .arg("--library")
        .arg(&lib)
        .arg("--out-dir")
        .arg(&out_dir);
    run(bindgen)?;

    std::fs::copy(&lib, out_dir.join(&lib_name))?;
    println!("Done: sylva_sdk.cs + {lib_name} in {}", out_dir.display());
    Ok(())
}

/// Confirm `uniffi-bindgen-cs` is on PATH (spawnable), else a helpful error.
fn ensure_tool() -> Fallible {
    if Command::new("uniffi-bindgen-cs")
        .arg("--version")
        .output()
        .is_err()
    {
        return Err("uniffi-bindgen-cs not found on PATH. Install the tag matching the crate's \
             uniffi pin — see docs/dev/hub-csharp-bindings.md."
            .into());
    }
    Ok(())
}

fn run(mut cmd: Command) -> Fallible {
    let status = cmd.status()?;
    if !status.success() {
        return Err(format!("command failed ({status}): {cmd:?}").into());
    }
    Ok(())
}

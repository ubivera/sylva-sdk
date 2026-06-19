//! `sync-proto` — re-vendor the canonical `.proto` files from the sibling
//! sylva-server repo into this crate's `proto/` tree. Run after Hearth's proto
//! contract changes, then rebuild (build.rs regenerates the stubs) and commit
//! the updated `proto/`.
//!
//!   cargo run --bin sync-proto
//!
//! Cross-platform + cargo-native (replaces the old PowerShell script). Assumes
//! the standard workspace layout (sylva-server + sylva-sdk as siblings).

use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src = crate_dir.join("..").join("sylva-server").join("proto");
    let dst = crate_dir.join("proto");

    if !src.is_dir() {
        return Err(format!(
            "server proto dir not found: {} (expected a sibling sylva-server checkout)",
            src.display()
        )
        .into());
    }

    println!("Syncing protos: {} -> {}", src.display(), dst.display());
    copy_dir(&src, &dst)?;
    println!("Done. Rebuild (cargo build) to regenerate stubs, then review + commit proto/.");
    Ok(())
}

/// Recursively copy `src` into `dst`, overwriting existing files (merge — it
/// does not delete files that no longer exist upstream).
fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

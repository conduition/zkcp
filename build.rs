//! Normally, this file would just contain a main function which executes `risc0_build::embed_methods()`
//! every time. However RISC0's implementation of this function will cause rebuilds every time, leading
//! to inefficient build pipelines downstream which will have to recompile everything that depends on
//! the ZKVM `methods` crate (this crate).
//!
//! In this custom build script, we hash the source files of the methods, and cache that "fingerprint"
//! in the build directory. We rebuild the risc0 methods only if the fingerprint changes.
//!
//! This bastardizes Cargo's own 'rerun-if-changed' features for build scripts:
//!
//!   https://doc.rust-lang.org/cargo/reference/build-scripts.html
//!
//! However I'm not sure how else to make it work given the way that `risc0_build` works upstream.
//! Probably a pull request upstream is needed to fix `embed_methods`.

use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

fn get_out_dir() -> PathBuf {
    PathBuf::from(&env::var_os("OUT_DIR").unwrap())
}

fn get_crate_dir() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
}

fn fingerprint_files_recursive(path: &Path, hasher: &mut Sha256, buf: &mut [u8]) -> io::Result<()> {
    println!("cargo::rerun-if-changed={}", path.display());
    if !path.is_dir() {
        hasher.update(path.as_os_str().as_encoded_bytes());
        let mut file = fs::File::open(path)?;
        loop {
            let n = file.read(buf)?;
            if n == 0 {
                break; // EOF
            }
            hasher.update(&buf[..n]);
        }
        return Ok(());
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        // Do not fingerprint the build directory
        if entry.file_name() != "target" {
            fingerprint_files_recursive(&entry.path(), hasher, buf)?;
        }
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let crate_dir = get_crate_dir();

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];

    fingerprint_files_recursive(&crate_dir.join("zkvm"), &mut hasher, &mut buf)?;
    fingerprint_files_recursive(&crate_dir.join("Cargo.toml"), &mut hasher, &mut buf)?;
    fingerprint_files_recursive(&crate_dir.join("Cargo.lock"), &mut hasher, &mut buf)?;
    fingerprint_files_recursive(&crate_dir.join("build.rs"), &mut hasher, &mut buf)?;

    let fingerprint: [u8; 32] = hasher.finalize().into();
    let fingerprint_filepath = get_out_dir().join("source_fingerprint");

    if fingerprint.as_ref() != fs::read(&fingerprint_filepath).unwrap_or_default() {
        risc0_build::embed_methods();
        fs::write(fingerprint_filepath, fingerprint)?;
    }

    Ok(())
}

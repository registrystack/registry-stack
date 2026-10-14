// SPDX-License-Identifier: Apache-2.0
//! Field-encryption data-key material for local deployments.
//!
//! The generated file is one base64-encoded 32-byte data key, exactly the
//! shape the runtime's `localFile` field-encryption provider resolves through
//! a `secret:file` reference. The key material never reaches standard output
//! and an existing output file is never overwritten.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use zeroize::Zeroizing;

/// Exactly 32 bytes: the field-encryption data key.
const DATA_KEY_BYTES: usize = 32;
/// Owner-only key file, matching every other secret this tool writes.
const PRIVATE_FILE_MODE: u32 = 0o600;
/// Missing parent directories of a key file are created owner-only.
const PRIVATE_DIR_MODE: u32 = 0o700;

/// What one successful generation wrote.
pub(crate) struct KeygenOutcome {
    /// The operator-named output path, safe to report after the write.
    pub output: PathBuf,
}

/// Value-free generation refusals.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum KeygenError {
    /// A relative path cannot name a deliberate deployment secret location.
    RelativeOutput,
    /// The output already exists; key material is never regenerated over it.
    OutputExists,
    /// The platform random source refused.
    RandomSource,
    /// The filesystem refused a parent directory or the key file itself.
    Write,
}

/// Write one fresh base64 data key to `output`.
///
/// The existence check plus create-new semantics mean a concurrent writer can
/// never be overwritten, and the file is created with its final owner-only
/// mode so there is no window with wider permissions.
pub(crate) fn keygen(output: &Path) -> Result<KeygenOutcome, KeygenError> {
    if !output.is_absolute() {
        return Err(KeygenError::RelativeOutput);
    }
    // `symlink_metadata` also refuses a dangling symlink at the output path,
    // which `exists()` alone would miss.
    match fs::symlink_metadata(output) {
        Ok(_) => return Err(KeygenError::OutputExists),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(KeygenError::Write),
    }

    let mut entropy = Zeroizing::new([0_u8; DATA_KEY_BYTES]);
    getrandom::fill(entropy.as_mut_slice()).map_err(|_| KeygenError::RandomSource)?;
    // Base64 text contains no NUL byte, so the file passes the secret loader's
    // value validation without rejection sampling.
    let encoded = Zeroizing::new(STANDARD.encode(entropy.as_slice()));

    if let Some(parent) = output.parent() {
        ensure_private_parents(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).mode(PRIVATE_FILE_MODE).create_new(true);
    let mut file = options.open(output).map_err(|_| KeygenError::Write)?;
    file.write_all(encoded.as_bytes())
        .map_err(|_| KeygenError::Write)?;
    file.sync_all().map_err(|_| KeygenError::Write)?;
    Ok(KeygenOutcome {
        output: output.to_owned(),
    })
}

/// Create missing parent directories owner-only. An existing directory is left
/// untouched: this tool did not create it and does not own its mode.
fn ensure_private_parents(dir: &Path) -> Result<(), KeygenError> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    match fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(KeygenError::Write),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(PRIVATE_DIR_MODE);
            builder.create(dir).map_err(|_| KeygenError::Write)
        }
        Err(_) => Err(KeygenError::Write),
    }
}

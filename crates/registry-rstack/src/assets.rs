// SPDX-License-Identifier: Apache-2.0
//! Release-asset acquisition and integrity checks shared by bootstrap and manager.

use crate::Asset;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;

pub struct AssetProvider {
    release: String,
    asset_dir: Option<PathBuf>,
}

impl AssetProvider {
    pub fn new(release: &str, asset_dir: Option<PathBuf>) -> Result<Self, String> {
        let version = release
            .strip_prefix('v')
            .ok_or("release must start with v")?;
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3
            || parts.iter().any(|part| {
                part.is_empty()
                    || (part.len() > 1 && part.starts_with('0'))
                    || !part.bytes().all(|byte| byte.is_ascii_digit())
                    || part.parse::<u64>().is_err()
            })
        {
            return Err("release must be an exact canonical vX.Y.Z tag".into());
        }
        Ok(Self {
            release: release.to_owned(),
            asset_dir,
        })
    }

    /// Fetch a small manifest or checksum list before its digest is known.
    /// Callers must verify it against the expected checksum before using it.
    pub fn fetch_metadata(&self, name: &str) -> Result<Vec<u8>, String> {
        safe_name(name)?;
        let mut reader = self.open(name)?;
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take((MAX_METADATA_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read {name}: {error}"))?;
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(format!("release metadata {name} exceeds 16 MiB"));
        }
        Ok(bytes)
    }

    /// Create an asset in a staging directory and make it usable only after
    /// both its exact length and SHA-256 match the release manifest.
    pub fn fetch(&self, asset: &Asset, destination: &Path) -> Result<(), String> {
        asset.validate()?;
        let mut reader = self.open(&asset.name)?;
        let mut writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|error| format!("cannot stage {}: {error}", asset.name))?;
        let result = (|| {
            let mut hash = Sha256::new();
            let mut total = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = reader
                    .read(&mut buffer)
                    .map_err(|error| format!("cannot read {}: {error}", asset.name))?;
                if count == 0 {
                    break;
                }
                total = total
                    .checked_add(count as u64)
                    .ok_or("asset size overflow")?;
                if total > asset.size {
                    return Err(format!("asset {} exceeds published size", asset.name));
                }
                hash.update(&buffer[..count]);
                writer
                    .write_all(&buffer[..count])
                    .map_err(|error| format!("cannot stage {}: {error}", asset.name))?;
            }
            if total != asset.size || hex::encode(hash.finalize()) != asset.sha256 {
                return Err(format!(
                    "asset {} does not match published digest and size",
                    asset.name
                ));
            }
            writer
                .sync_all()
                .map_err(|error| format!("cannot sync {}: {error}", asset.name))?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                drop(writer);
                match fs::remove_file(destination) {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(format!(
                        "{error}; cannot remove incomplete staging file {}: {cleanup}",
                        destination.display()
                    )),
                }
            }
        }
    }

    fn open(&self, name: &str) -> Result<Box<dyn Read>, String> {
        safe_name(name)?;
        if let Some(directory) = &self.asset_dir {
            let path = directory.join(name);
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect asset {name}: {error}"))?;
            if !metadata.file_type().is_file() {
                return Err(format!("asset {name} must be a regular file"));
            }
            return File::open(&path)
                .map(|file| Box::new(file) as Box<dyn Read>)
                .map_err(|error| format!("cannot open asset {name}: {error}"));
        }
        let url = format!(
            "https://github.com/registrystack/registry-stack/releases/download/{}/{name}",
            self.release
        );
        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_global(Some(Duration::from_secs(300)))
            .max_redirects(5)
            .build();
        let agent: ureq::Agent = config.into();
        let response = agent
            .get(&url)
            .call()
            .map_err(|error| format!("cannot fetch release asset {name}: {error}"))?;
        Ok(Box::new(response.into_body().into_reader()))
    }
}

pub fn checksum_for(raw: &[u8], wanted: &str) -> Result<String, String> {
    safe_name(wanted)?;
    let text = std::str::from_utf8(raw).map_err(|_| "SHA256SUMS is not UTF-8")?;
    let mut found = None;
    for line in text.lines() {
        let (digest, name) = line
            .split_once("  ")
            .ok_or("SHA256SUMS has a malformed line")?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("SHA256SUMS has an invalid SHA-256 digest".into());
        }
        safe_name(name)?;
        if name == wanted && found.replace(digest.to_owned()).is_some() {
            return Err(format!("SHA256SUMS repeats {wanted}"));
        }
    }
    found.ok_or_else(|| format!("SHA256SUMS omits {wanted}"))
}

pub fn verify_bytes(name: &str, bytes: &[u8], expected: &str) -> Result<(), String> {
    let observed = hex::encode(Sha256::digest(bytes));
    if observed != expected {
        return Err(format!("release asset checksum mismatch: {name}"));
    }
    Ok(())
}

fn safe_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err("asset name must be a safe basename".into());
    }
    Ok(())
}

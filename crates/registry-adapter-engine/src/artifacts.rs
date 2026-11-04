// SPDX-License-Identifier: Apache-2.0

//! Governed pack file bytes supplied either by a library host or by the
//! maintained file-based convenience loaders.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// The non-document files a pack inventory pins, keyed by the exact relative
/// path the pack names. Compilation verifies every consumed value against the
/// pack's digest before parsing or compiling it.
#[derive(Debug, Default)]
pub struct PackArtifactBytes {
    files: BTreeMap<String, Vec<u8>>,
}

/// Project-owned scripts and schemas use the same bounded in-memory byte
/// source as pack artifacts, but remain a distinct authority and namespace at
/// the compile boundary.
pub type ProjectArtifactBytes = PackArtifactBytes;

impl PackArtifactBytes {
    /// Build a supplied artifact set. Repeated paths keep the last supplied
    /// value; the pack digest still decides whether that value is admissible.
    pub fn new(files: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
        Self {
            files: files.into_iter().collect(),
        }
    }

    /// Add or replace one exact pack-relative path.
    pub fn insert(
        &mut self,
        path: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        self.files.insert(path.into(), bytes.into())
    }
}

/// A governed file was absent/unreadable or exceeded the caller's bound.
pub(crate) enum ArtifactReadError {
    Unavailable,
    TooLarge,
}

/// The one read seam used by script and query compilation. The in-memory
/// implementation performs no file-system operation; file-based hosts retain
/// their existing convenience path through the `Path` implementation.
pub(crate) trait ArtifactSource {
    fn read_bounded(&self, path: &str, limit: usize) -> Result<Vec<u8>, ArtifactReadError>;
}

impl ArtifactSource for PackArtifactBytes {
    fn read_bounded(&self, path: &str, limit: usize) -> Result<Vec<u8>, ArtifactReadError> {
        let bytes = self.files.get(path).ok_or(ArtifactReadError::Unavailable)?;
        if bytes.len() > limit {
            return Err(ArtifactReadError::TooLarge);
        }
        Ok(bytes.clone())
    }
}

impl ArtifactSource for Path {
    fn read_bounded(&self, path: &str, limit: usize) -> Result<Vec<u8>, ArtifactReadError> {
        let file = File::open(self.join(path)).map_err(|_| ArtifactReadError::Unavailable)?;
        let length = file
            .metadata()
            .map_err(|_| ArtifactReadError::Unavailable)?
            .len();
        if length > limit as u64 {
            return Err(ArtifactReadError::TooLarge);
        }
        let mut bytes = Vec::with_capacity(limit.min(length as usize));
        file.take(limit.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ArtifactReadError::Unavailable)?;
        if bytes.len() > limit {
            Err(ArtifactReadError::TooLarge)
        } else {
            Ok(bytes)
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
//! File audit sink with in-process rotation.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::{AuditEnvelope, AuditError, AuditFuture, AuditSink};

/// Writes audit records as JSONL to a configured file path.
///
/// Rotation is size-triggered and local to this process. `max_files`
/// counts the active file, so `max_files = 3` keeps `audit.jsonl`,
/// `audit.jsonl.1`, and `audit.jsonl.2`.
#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    max_size_bytes: u64,
    max_files: u32,
    lock: Mutex<()>,
}

impl FileSink {
    /// Construct a file sink and create the parent directory when one
    /// is configured in the path.
    pub fn new(
        path: impl Into<PathBuf>,
        max_size_mb: u64,
        max_files: u32,
    ) -> Result<Self, AuditError> {
        let path = path.into();
        ensure_parent_dir(&path)?;
        Ok(Self {
            path,
            max_size_bytes: max_size_mb.saturating_mul(1024 * 1024),
            max_files,
            lock: Mutex::new(()),
        })
    }

    fn write_line(&self, line: &str) -> Result<(), AuditError> {
        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_parent_dir(&self.path)?;
        self.rotate_if_needed(line.len() as u64)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(AuditError::Io)?;
        file.write_all(line.as_bytes()).map_err(AuditError::Io)?;
        file.flush().map_err(AuditError::Io)?;
        Ok(())
    }

    fn rotate_if_needed(&self, incoming_bytes: u64) -> Result<(), AuditError> {
        if self.max_size_bytes == 0 {
            return Ok(());
        }

        let current_size = match fs::metadata(&self.path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(AuditError::Io(error)),
        };

        if current_size.saturating_add(incoming_bytes) <= self.max_size_bytes {
            return Ok(());
        }

        self.rotate()
    }

    fn rotate(&self) -> Result<(), AuditError> {
        if self.max_files <= 1 {
            match fs::remove_file(&self.path) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(AuditError::Io(error)),
            }
        }

        let last_index = self.max_files - 1;
        let last_path = rotated_path(&self.path, last_index);
        match fs::remove_file(&last_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(AuditError::Io(error)),
        }

        for index in (1..last_index).rev() {
            let from = rotated_path(&self.path, index);
            let to = rotated_path(&self.path, index + 1);
            match fs::rename(&from, &to) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(AuditError::Io(error)),
            }
        }

        match fs::rename(&self.path, rotated_path(&self.path, 1)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AuditError::Io(error)),
        }
    }
}

impl AuditSink for FileSink {
    fn write<'a>(&'a self, envelope: AuditEnvelope) -> AuditFuture<'a> {
        Box::pin(async move {
            let line = envelope.to_jsonl()?;
            self.write_line(&line)
        })
    }

    fn flush<'a>(&'a self) -> AuditFuture<'a> {
        Box::pin(async move { Ok(()) })
    }
}

fn ensure_parent_dir(path: &Path) -> Result<(), AuditError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(AuditError::Io)?;
    }
    Ok(())
}

fn rotated_path(path: &Path, index: u32) -> PathBuf {
    PathBuf::from(format!("{}.{}", path.display(), index))
}

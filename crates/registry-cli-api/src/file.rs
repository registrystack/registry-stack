// SPDX-License-Identifier: Apache-2.0

use std::{
    fs,
    io::{self, Read as _},
    path::Path,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileReadError {
    NotFound,
    NotRegular,
    Unavailable,
}

/// Read at most one byte beyond `maximum` from a regular file.
pub(crate) fn read_bounded_regular_file(
    path: &Path,
    maximum: u64,
) -> Result<Vec<u8>, FileReadError> {
    let file = open_file(path)?;
    if !file
        .metadata()
        .map_err(|_| FileReadError::Unavailable)?
        .is_file()
    {
        return Err(FileReadError::NotRegular);
    }
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| FileReadError::Unavailable)?;
    Ok(bytes)
}

#[cfg(unix)]
fn open_file(path: &Path) -> Result<fs::File, FileReadError> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| classify_io_error(io::Error::from(error)))?;
    Ok(fs::File::from(descriptor))
}

#[cfg(not(unix))]
fn open_file(path: &Path) -> Result<fs::File, FileReadError> {
    fs::File::open(path).map_err(classify_io_error)
}

fn classify_io_error(error: io::Error) -> FileReadError {
    if error.kind() == io::ErrorKind::NotFound {
        FileReadError::NotFound
    } else {
        FileReadError::Unavailable
    }
}

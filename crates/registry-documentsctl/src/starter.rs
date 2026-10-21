// SPDX-License-Identifier: Apache-2.0

//! The starter `documentsctl init` writes: the maintained example under
//! `products/documents/examples/starter`, embedded file for file, so the
//! command and the published example cannot drift apart.

use std::fs;
use std::io;
use std::path::Path;

/// Every file of the starter, by its path relative to the new directory.
pub(crate) const FILES: [(&str, &str); 2] = [
    (
        "documents.yaml",
        include_str!("../../../products/documents/examples/starter/documents.yaml"),
    ),
    (
        "runtime.example.yaml",
        include_str!("../../../products/documents/examples/starter/runtime.example.yaml"),
    ),
];

#[derive(Debug)]
pub(crate) enum InitError {
    Exists,
    Io(io::Error),
}

impl From<io::Error> for InitError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Write the starter into `directory`, which must not exist. The files are
/// written into a staging directory beside it and published by one rename,
/// so a failure leaves no partial starter behind.
pub(crate) fn write(directory: &Path) -> Result<Vec<&'static str>, InitError> {
    match fs::symlink_metadata(directory) {
        Ok(_) => return Err(InitError::Exists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(InitError::Io(error)),
    }
    let parent = match directory.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".documents-init-")
        .tempdir_in(parent)?;
    let mut created = Vec::with_capacity(FILES.len());
    for (relative, contents) in FILES {
        fs::write(staging.path().join(relative), contents)?;
        created.push(relative);
    }
    let staging_path = staging.keep();
    if let Err(error) = fs::rename(&staging_path, directory) {
        // The rename is the failure reported; removing the staging
        // directory it left behind is best effort.
        let _ = fs::remove_dir_all(&staging_path);
        return Err(
            if error.kind() == io::ErrorKind::AlreadyExists
                || error.kind() == io::ErrorKind::DirectoryNotEmpty
            {
                InitError::Exists
            } else {
                InitError::Io(error)
            },
        );
    }
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_starter_embeds_every_file_of_the_published_example() {
        let example =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/documents/examples/starter");
        let mut published = fs::read_dir(&example)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        published.sort();
        let embedded = FILES.iter().map(|(name, _)| *name).collect::<Vec<_>>();
        assert_eq!(published, embedded);
        for (name, contents) in FILES {
            assert_eq!(fs::read_to_string(example.join(name)).unwrap(), contents);
        }
    }

    #[test]
    fn init_writes_the_starter_and_never_overwrites() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("project");
        assert_eq!(
            write(&directory).unwrap(),
            ["documents.yaml", "runtime.example.yaml"]
        );
        for (name, contents) in FILES {
            assert_eq!(fs::read_to_string(directory.join(name)).unwrap(), contents);
        }
        assert!(matches!(write(&directory), Err(InitError::Exists)));
        let leftovers = fs::read_dir(parent.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            leftovers,
            ["project"],
            "no staging directory is left behind"
        );
    }
}

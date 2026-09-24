// SPDX-License-Identifier: Apache-2.0

//! The starter `messagingctl init` writes: the maintained example under
//! `products/messaging/examples/starter`, embedded file for file, so the
//! command and the published example cannot drift apart.

use std::fs;
use std::io;
use std::path::Path;

/// Every file of the starter, by its path relative to the new directory.
pub(crate) const FILES: [(&str, &str); 19] = [
    (
        "messaging.yaml",
        include_str!("../../../products/messaging/examples/starter/messaging.yaml"),
    ),
    (
        "providers/sms-gateway/provider.yaml",
        include_str!("../../../products/messaging/examples/starter/providers/sms-gateway/provider.yaml"),
    ),
    (
        "providers/sms-gateway/scripts/interpret.rhai",
        include_str!("../../../products/messaging/examples/starter/providers/sms-gateway/scripts/interpret.rhai"),
    ),
    (
        "providers/sms-gateway/scripts/prepare.rhai",
        include_str!("../../../products/messaging/examples/starter/providers/sms-gateway/scripts/prepare.rhai"),
    ),
    (
        "providers/sms-gateway/scripts/receipt.rhai",
        include_str!("../../../products/messaging/examples/starter/providers/sms-gateway/scripts/receipt.rhai"),
    ),
    (
        "runtime.example.yaml",
        include_str!("../../../products/messaging/examples/starter/runtime.example.yaml"),
    ),
    (
        "templates/appointment-reminder-sms/1/en/text.j2",
        include_str!("../../../products/messaging/examples/starter/templates/appointment-reminder-sms/1/en/text.j2"),
    ),
    (
        "templates/appointment-reminder-sms/1/sample.json",
        include_str!("../../../products/messaging/examples/starter/templates/appointment-reminder-sms/1/sample.json"),
    ),
    (
        "templates/appointment-reminder-sms/1/schema.json",
        include_str!("../../../products/messaging/examples/starter/templates/appointment-reminder-sms/1/schema.json"),
    ),
    (
        "templates/appointment-reminder-sms/1/template.yaml",
        include_str!("../../../products/messaging/examples/starter/templates/appointment-reminder-sms/1/template.yaml"),
    ),
    (
        "templates/appointment-reminder/1/en/html.j2",
        include_str!("../../../products/messaging/examples/starter/templates/appointment-reminder/1/en/html.j2"),
    ),
    (
        "templates/appointment-reminder/1/en/subject.j2",
        include_str!("../../../products/messaging/examples/starter/templates/appointment-reminder/1/en/subject.j2"),
    ),
    (
        "templates/appointment-reminder/1/en/text.j2",
        include_str!("../../../products/messaging/examples/starter/templates/appointment-reminder/1/en/text.j2"),
    ),
    (
        "templates/appointment-reminder/1/fr/html.j2",
        include_str!("../../../products/messaging/examples/starter/templates/appointment-reminder/1/fr/html.j2"),
    ),
    (
        "templates/appointment-reminder/1/fr/subject.j2",
        include_str!("../../../products/messaging/examples/starter/templates/appointment-reminder/1/fr/subject.j2"),
    ),
    (
        "templates/appointment-reminder/1/fr/text.j2",
        include_str!("../../../products/messaging/examples/starter/templates/appointment-reminder/1/fr/text.j2"),
    ),
    (
        "templates/appointment-reminder/1/sample.json",
        include_str!("../../../products/messaging/examples/starter/templates/appointment-reminder/1/sample.json"),
    ),
    (
        "templates/appointment-reminder/1/schema.json",
        include_str!("../../../products/messaging/examples/starter/templates/appointment-reminder/1/schema.json"),
    ),
    (
        "templates/appointment-reminder/1/template.yaml",
        include_str!("../../../products/messaging/examples/starter/templates/appointment-reminder/1/template.yaml"),
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
        .prefix(".messaging-init-")
        .tempdir_in(parent)?;
    let mut created = Vec::with_capacity(FILES.len());
    for (relative, contents) in FILES {
        let target = staging.path().join(relative);
        if let Some(folder) = target.parent() {
            fs::create_dir_all(folder)?;
        }
        fs::write(target, contents)?;
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

// SPDX-License-Identifier: Apache-2.0
//! Export the fixed native Proposal event schema with the package's exact bytes.

use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        return Err("usage: proposal-event-schema --output FILE".into());
    }
    let output = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: proposal-event-schema --output FILE")?,
    );
    if arguments.next().is_some() {
        return Err("usage: proposal-event-schema --output FILE".into());
    }
    let bytes = registry_platform_canonical_json::canonicalize_json(
        &registry_breg::proposal_hooks::proposal_event_schema(),
    )?;
    fs::write(output, bytes)?;
    Ok(())
}

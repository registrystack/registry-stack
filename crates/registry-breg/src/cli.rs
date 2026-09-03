// SPDX-License-Identifier: Apache-2.0
//! Public process arguments, shared with the generated command reference.

use std::path::PathBuf;

use clap::{CommandFactory, Parser};

#[derive(Debug, Parser)]
#[command(
    name = "breg",
    about = "Serve one verified Base Registry Engine package",
    version = registry_platform_buildinfo::DISPLAY_VERSION
)]
pub struct Arguments {
    /// Absolute path to the runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    pub config: PathBuf,
}

/// Return the public command tree for documentation and completion.
pub fn command() -> clap::Command {
    Arguments::command()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_configuration_is_required() {
        assert!(Arguments::try_parse_from(["breg"]).is_err());
        let arguments = Arguments::try_parse_from(["breg", "--config", "/etc/breg/runtime.yaml"])
            .expect("the documented configuration argument parses");
        assert_eq!(arguments.config, PathBuf::from("/etc/breg/runtime.yaml"));
        command().debug_assert();
    }
}

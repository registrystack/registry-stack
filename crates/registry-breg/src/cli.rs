// SPDX-License-Identifier: Apache-2.0
//! Public process arguments, shared with the generated command reference.

use std::ffi::OsStr;
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
    #[arg(long = "runtime-config", value_name = "ABSOLUTE_FILE")]
    pub runtime_config: PathBuf,
}

/// Return the public command tree for documentation and completion.
pub fn command() -> clap::Command {
    Arguments::command()
}

/// The refusal for a removed runtime-configuration flag, checked before
/// argument parsing so the operator reads the replacement instead of clap's
/// unknown-argument error. Arguments after `--` are not flags.
pub fn removed_config_flag<I, S>(arguments: I) -> Option<&'static str>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    arguments
        .into_iter()
        .map_while(|argument| {
            let argument = argument.as_ref().as_encoded_bytes().to_vec();
            (argument != b"--").then_some(argument)
        })
        .any(|argument| argument == b"--config" || argument.starts_with(b"--config="))
        .then_some("--config is no longer accepted; pass --runtime-config FILE")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_configuration_is_required() {
        assert!(Arguments::try_parse_from(["breg"]).is_err());
        let arguments =
            Arguments::try_parse_from(["breg", "--runtime-config", "/etc/breg/runtime.yaml"])
                .expect("the documented configuration argument parses");
        assert_eq!(
            arguments.runtime_config,
            PathBuf::from("/etc/breg/runtime.yaml")
        );
        command().debug_assert();
    }

    #[test]
    fn the_removed_config_flag_names_its_replacement() {
        for arguments in [
            vec!["breg", "--config", "/etc/breg/runtime.yaml"],
            vec!["breg", "--config=/etc/breg/runtime.yaml"],
        ] {
            assert_eq!(
                removed_config_flag(&arguments),
                Some("--config is no longer accepted; pass --runtime-config FILE")
            );
            assert!(Arguments::try_parse_from(&arguments).is_err());
        }
        assert_eq!(
            removed_config_flag(["breg", "--runtime-config", "/etc/breg/runtime.yaml"]),
            None
        );
        assert_eq!(removed_config_flag(["breg", "--", "--config"]), None);
    }
}

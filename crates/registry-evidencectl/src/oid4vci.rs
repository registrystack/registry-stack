//! Named wallet-delivery commands backed by the selected Evidence helper.

use std::os::unix::process::CommandExt;
use std::{
    env,
    path::PathBuf,
    process::{Command as ProcessCommand, ExitCode},
};

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::evidence_binary::{self, HelperSpec};
use crate::OutputFormat;

const HELPER: HelperSpec = HelperSpec {
    binary: "evidence-oid4vci",
    component: "evidence",
    explicit_flag: "--oid4vci-bin",
    explicit_env: "EVIDENCE_OID4VCI_BIN",
    managed_env: "RSTACK_EVIDENCE_OID4VCI_BIN",
};

#[derive(Debug, Args)]
pub(crate) struct Oid4vciArgs {
    /// Explicit wallet-delivery binary outside an rstack installation.
    #[arg(long = "oid4vci-bin", hide = true)]
    oid4vci_bin: Option<PathBuf>,
    #[command(subcommand)]
    command: Oid4vciCommand,
}

impl Oid4vciArgs {
    pub(crate) fn is_check(&self) -> bool {
        matches!(self.command, Oid4vciCommand::Check { .. })
    }
}

#[derive(Debug, Subcommand)]
enum Oid4vciCommand {
    /// Check the wallet-delivery runtime file offline.
    Check {
        /// Runtime configuration file to validate.
        #[arg(
            long = "runtime-config",
            value_name = "FILE",
            env = "EVIDENCE_OID4VCI_RUNTIME_CONFIG"
        )]
        config: PathBuf,
        /// Exit 1 when a warning is reported.
        #[arg(long)]
        deny_warnings: bool,
        /// Resolve runtime environment expressions and check their values.
        #[arg(long)]
        environment: bool,
    },
    /// Print the derived protocol metadata for a deployment.
    Inspect {
        /// Runtime configuration file to inspect.
        #[arg(
            long = "runtime-config",
            value_name = "FILE",
            env = "EVIDENCE_OID4VCI_RUNTIME_CONFIG"
        )]
        config: PathBuf,
    },
    /// Render the OpenAPI 3.1 document.
    Openapi {
        /// Write the document to this file.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Serve wallet-delivery endpoints until terminated.
    Serve {
        /// Runtime configuration file for the service.
        #[arg(
            long = "runtime-config",
            value_name = "FILE",
            env = "EVIDENCE_OID4VCI_RUNTIME_CONFIG"
        )]
        config: PathBuf,
    },
}

pub(crate) fn run(args: Oid4vciArgs, format: OutputFormat) -> Result<ExitCode> {
    let binary = evidence_binary::resolve_helper_with_environment(
        HELPER,
        args.oid4vci_bin.as_deref(),
        env::var_os(HELPER.explicit_env).as_deref(),
        env::var_os("RSTACK_GENERATION_DIR").as_deref(),
        env::var_os(HELPER.managed_env).as_deref(),
        env::var_os("RSTACK_RELEASE_TAG").as_deref(),
        env::var_os("PATH").as_deref(),
    )?;
    let mut child = ProcessCommand::new(binary);
    match args.command {
        Oid4vciCommand::Check {
            config,
            deny_warnings,
            environment,
        } => {
            child.arg("check").arg("--runtime-config").arg(config);
            child.arg("--format").arg(match format {
                OutputFormat::Human => "human",
                OutputFormat::Json => "json",
            });
            if deny_warnings {
                child.arg("--deny-warnings");
            }
            if environment {
                child.arg("--environment");
            }
        }
        Oid4vciCommand::Inspect { config } => {
            child.arg("inspect").arg("--runtime-config").arg(config);
        }
        Oid4vciCommand::Openapi { output } => {
            child.arg("openapi");
            if let Some(output) = output {
                child.arg("--output").arg(output);
            }
        }
        Oid4vciCommand::Serve { config } => {
            child.arg("serve").arg("--runtime-config").arg(config);
        }
    }
    let failure = child.exec();
    Err(anyhow::Error::new(failure).context("cannot launch selected wallet-delivery binary"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsStr, fs};

    #[test]
    fn selected_wallet_helper_cannot_fall_back_to_path_or_wrong_override() {
        let generation = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let resolved = evidence_binary::resolve_helper_with_environment(
            HELPER,
            None,
            None,
            Some(generation.path().as_os_str()),
            None,
            Some(OsStr::new("v0.44.0")),
            Some(outside.path().parent().unwrap().as_os_str()),
        );
        assert!(resolved.is_err());
        let selected = generation
            .path()
            .join("components/evidence/evidence-oid4vci/evidence-oid4vci");
        fs::create_dir_all(selected.parent().unwrap()).unwrap();
        fs::write(&selected, b"fixture").unwrap();
        let mismatch = evidence_binary::resolve_helper_with_environment(
            HELPER,
            Some(outside.path()),
            None,
            Some(generation.path().as_os_str()),
            Some(selected.as_os_str()),
            Some(OsStr::new("v0.44.0")),
            None,
        );
        assert!(mismatch.is_err());
    }
}

//! Advanced: editor and tooling integration surfaces.
//!
//! These commands support an editor or another development tool rather than
//! an Evidence deployment; none of them read or write a project.

use std::process::ExitCode;

use anyhow::{anyhow, Result};
use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum ToolingCommand {
    /// Run cross-file navigation over the Language Server Protocol.
    LanguageServer,
}

pub fn run(command: ToolingCommand) -> Result<ExitCode> {
    match command {
        ToolingCommand::LanguageServer => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| anyhow!(error))?
                .block_on(registry_language_server::run_stdio());
            Ok(ExitCode::SUCCESS)
        }
    }
}

//! Advanced: editor and tooling integration surfaces.
//!
//! These commands support an editor or another development tool rather than
//! an Evidence deployment. `editor` writes its configuration into a project;
//! nothing else here reads or writes one.

use std::process::ExitCode;

use anyhow::{anyhow, Result};
use clap::Subcommand;

use crate::tooling_editor::{self, EditorArgs};

#[derive(Debug, Subcommand)]
pub enum ToolingCommand {
    /// Write project-local schema mappings for a YAML-aware editor.
    Editor(EditorArgs),
    /// Run cross-file navigation over the Language Server Protocol.
    LanguageServer,
}

pub fn run(command: ToolingCommand) -> Result<ExitCode> {
    match command {
        ToolingCommand::Editor(args) => tooling_editor::run(args),
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

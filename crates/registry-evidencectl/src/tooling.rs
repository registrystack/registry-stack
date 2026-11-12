//! Advanced: editor and tooling integration surfaces.
//!
//! These commands support an editor or another development tool rather than
//! an Evidence deployment. `editor` writes its configuration into a project;
//! nothing else here reads or writes one.

use std::process::ExitCode;

use anyhow::Result;
use clap::Subcommand;

use crate::{
    tooling_editor::{self, EditorArgs},
    OutputFormat,
};

#[derive(Debug, Subcommand)]
pub enum ToolingCommand {
    /// Write project-local schema mappings for a YAML-aware editor.
    Editor(EditorArgs),
}

pub fn run(command: ToolingCommand, format: OutputFormat) -> Result<ExitCode> {
    match command {
        ToolingCommand::Editor(args) => tooling_editor::run(args, format),
    }
}

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use registryctl::Sample;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { command } => match command {
            InitCommand::SpreadsheetApi { dir, sample } => {
                registryctl::init_spreadsheet_api(&dir, sample)?;
            }
        },
        Commands::Start => registryctl::start_project(&std::env::current_dir()?)?,
        Commands::Stop => registryctl::stop_project(&std::env::current_dir()?)?,
        Commands::Status => registryctl::status_project(&std::env::current_dir()?)?,
        Commands::Open => registryctl::open_project(&std::env::current_dir()?)?,
        Commands::Smoke => registryctl::smoke_project(&std::env::current_dir()?)?,
        Commands::Logs => registryctl::logs_project(&std::env::current_dir()?)?,
    }
    Ok(())
}

#[derive(Debug, Parser)]
#[command(name = "registryctl")]
#[command(version)]
#[command(about = "Create and run local Registry Commons projects")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create a local Registry Commons project.
    Init {
        #[command(subcommand)]
        command: InitCommand,
    },
    /// Start the local Registry Commons project.
    Start,
    /// Stop the local Registry Commons project.
    Stop,
    /// Print local runtime status.
    Status,
    /// Open or print the local API docs URL.
    Open,
    /// Run built-in local smoke checks.
    Smoke,
    /// Stream Compose logs for the local project.
    Logs,
}

#[derive(Debug, Subcommand)]
enum InitCommand {
    /// Create a local Relay-backed spreadsheet API project.
    SpreadsheetApi {
        /// Directory to create.
        dir: PathBuf,
        /// Sample project to generate.
        #[arg(long, value_enum, default_value_t = Sample::Benefits)]
        sample: Sample,
    },
}

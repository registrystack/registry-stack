use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use registryctl::{NotaryInitOptions, NotarySource, Sample};

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { command } => match *command {
            InitCommand::Relay { dir, sample } => {
                registryctl::init_spreadsheet_api(&dir, sample)?;
            }
            InitCommand::SpreadsheetApi { dir, sample } => {
                registryctl::init_spreadsheet_api(&dir, sample)?;
            }
            InitCommand::Notary {
                dir,
                source_url,
                source_token_from_env,
                source_token_env,
                source_dataset,
                source_entity,
                source_lookup_field,
                source_network,
                source_claim,
                source_claim_title,
            } => {
                registryctl::init_notary_project(
                    &dir,
                    NotaryInitOptions {
                        source_url,
                        source_token_from_env,
                        source_token_env,
                        source_dataset,
                        source_entity,
                        source_lookup_field,
                        source_network,
                        source_claim,
                        source_claim_title,
                    },
                )?;
            }
        },
        Commands::Add { command } => match command {
            AddCommand::Notary { from, force } => {
                registryctl::add_notary(&std::env::current_dir()?, from, force)?;
            }
        },
        Commands::Start => registryctl::start_project(&std::env::current_dir()?)?,
        Commands::Stop => registryctl::stop_project(&std::env::current_dir()?)?,
        Commands::Status => registryctl::status_project(&std::env::current_dir()?)?,
        Commands::Open => registryctl::open_project(&std::env::current_dir()?)?,
        Commands::Smoke => registryctl::smoke_project(&std::env::current_dir()?)?,
        Commands::Logs => registryctl::logs_project(&std::env::current_dir()?)?,
        Commands::Notary { command } => match command {
            NotaryCommand::Smoke => registryctl::notary_smoke_project(&std::env::current_dir()?)?,
            NotaryCommand::Open => registryctl::notary_open_project(&std::env::current_dir()?)?,
        },
        Commands::Bruno { command } => match command {
            BrunoCommand::Generate { force } => {
                registryctl::bruno_generate_project(&std::env::current_dir()?, force)?;
            }
            BrunoCommand::Open => registryctl::bruno_open_project(&std::env::current_dir()?)?,
            BrunoCommand::Run => registryctl::bruno_run_project(&std::env::current_dir()?)?,
        },
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
        command: Box<InitCommand>,
    },
    /// Add a Registry Commons product to the current project.
    Add {
        #[command(subcommand)]
        command: AddCommand,
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
    /// Work with the local Registry Notary product.
    Notary {
        #[command(subcommand)]
        command: NotaryCommand,
    },
    /// Work with the optional generated Bruno API collection.
    Bruno {
        #[command(subcommand)]
        command: BrunoCommand,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum InitCommand {
    /// Create a local Relay-backed spreadsheet API project.
    Relay {
        /// Directory to create.
        dir: PathBuf,
        /// Sample project to generate.
        #[arg(long, value_enum, default_value_t = Sample::Benefits)]
        sample: Sample,
    },
    /// Create a local Relay-backed spreadsheet API project.
    #[command(name = "spreadsheet-api", hide = true)]
    SpreadsheetApi {
        /// Directory to create.
        dir: PathBuf,
        /// Sample project to generate.
        #[arg(long, value_enum, default_value_t = Sample::Benefits)]
        sample: Sample,
    },
    /// Create a standalone local Notary project for an existing API.
    Notary {
        /// Directory to create.
        dir: PathBuf,
        /// Source Registry Data API base URL as seen from the Notary container.
        #[arg(long, default_value = "https://api.example.test")]
        source_url: String,
        /// Read the source API bearer token from this process environment variable.
        #[arg(long)]
        source_token_from_env: Option<String>,
        /// Env var name Notary should read for the source API bearer token.
        #[arg(long, default_value = "EVIDENCE_SOURCE_API_TOKEN")]
        source_token_env: String,
        /// Source dataset used by the starter claim.
        #[arg(long, default_value = "benefits_casework")]
        source_dataset: String,
        /// Source entity used by the starter claim.
        #[arg(long, default_value = "person")]
        source_entity: String,
        /// Source field used by the starter claim lookup.
        #[arg(long, default_value = "id")]
        source_lookup_field: String,
        /// Docker Compose network to join when the source API runs in another local Compose project.
        #[arg(long)]
        source_network: Option<String>,
        /// Starter claim id to generate.
        #[arg(long, default_value = "benefits-person-exists")]
        source_claim: String,
        /// Starter claim title to generate.
        #[arg(long, default_value = "Benefits person exists")]
        source_claim_title: String,
    },
}

#[derive(Debug, Subcommand)]
enum AddCommand {
    /// Add a local Notary backed by the generated Relay project.
    Notary {
        /// Source to use for the Notary evidence connection.
        #[arg(long, value_enum)]
        from: NotarySource,
        /// Replace existing Notary generated files.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
enum NotaryCommand {
    /// Run built-in local Notary smoke checks.
    Smoke,
    /// Print the local Notary API docs URL.
    Open,
}

#[derive(Debug, Subcommand)]
enum BrunoCommand {
    /// Generate or refresh the optional Bruno API collection.
    Generate {
        /// Overwrite existing Bruno files even if registryctl did not generate them.
        #[arg(long)]
        force: bool,
    },
    /// Open the generated Bruno collection when Bruno is installed.
    Open,
    /// Run the generated Bruno collection when the Bruno CLI is installed.
    Run,
}

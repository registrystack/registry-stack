//! Evidence adopter tooling: key generation, project scaffolding, fixture
//! runs. Companion to the frozen `evidence` runtime CLI; it never implements
//! Evidence semantics itself and shells out to the runtime binary for them.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod doctor;
mod fixtures;
mod jwks;
mod keygen;
mod scaffold;
mod suggest;

#[derive(Debug, Parser)]
#[command(
    name = "evidencectl",
    version,
    about = "Evidence adopter tooling: keys, project scaffolds, fixture runs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate Evidence deployment key material as owner-only files.
    #[command(subcommand)]
    Keygen(keygen::KeygenCommand),
    /// Assemble a public JWKS document from public JWK files.
    Jwks(jwks::JwksArgs),
    /// Scaffold a neutral Evidence deployment project.
    New(scaffold::NewArgs),
    /// Drive the evidence binary across a project's bundle fixtures.
    #[command(subcommand)]
    Fixtures(fixtures::FixturesCommand),
    /// Work with a project's sources, starting from their own API documents.
    #[command(subcommand)]
    Source(suggest::SourceCommand),
    /// Report every project artifact whose mode or owner the runtime refuses.
    Doctor(doctor::DoctorArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Keygen(command) => keygen::run(command),
        Command::Jwks(args) => jwks::run(args),
        Command::New(args) => scaffold::run(args),
        Command::Fixtures(command) => fixtures::run(command),
        Command::Source(command) => suggest::run(command),
        Command::Doctor(args) => doctor::run(args),
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("evidencectl: {error:#}");
            ExitCode::FAILURE
        }
    }
}

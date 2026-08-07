//! Evidence adopter tooling: key generation, OpenAPI-assisted authoring, and
//! fixture runs. Companion to the frozen `evidence` runtime CLI; it never
//! implements Evidence semantics itself and shells out to the runtime binary
//! for them.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod access;
mod audit_view;
mod authoring;
mod build;
mod dev;
mod doctor;
mod fixtures;
mod jwks;
mod keygen;
mod request;
mod scaffold;
mod suggest;
mod verify;

#[derive(Debug, Parser)]
#[command(
    name = "evidencectl",
    version,
    about = "Evidence adopter tooling: keys, OpenAPI authoring, fixture runs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage local caller access policies and clients.
    #[command(subcommand)]
    Access(access::AccessCommand),
    /// Generate Evidence deployment key material as owner-only files.
    #[command(subcommand)]
    Keygen(keygen::KeygenCommand),
    /// Assemble a public JWKS document from public JWK files.
    Jwks(jwks::JwksArgs),
    /// Start an editable Evidence authoring project from OpenAPI.
    New(scaffold::NewArgs),
    /// Compile an editable project into a reviewed deployment candidate.
    Build(build::BuildArgs),
    /// Drive the evidence binary across a project's bundle fixtures.
    #[command(subcommand)]
    Fixtures(fixtures::FixturesCommand),
    /// Work with a project's sources, starting from their own API documents.
    #[command(subcommand)]
    Source(suggest::SourceCommand),
    /// Report every project artifact whose mode or owner the runtime refuses.
    Doctor(doctor::DoctorArgs),
    /// Run the private local Mint and Evidence pair for an authored project.
    Dev(dev::DevArgs),
    /// Prepare a closed request for the active local project.
    #[command(subcommand)]
    Request(request::RequestCommand),
    /// Verify one retained Evidence response offline.
    Verify(verify::VerifyArgs),
    /// Inspect stopped local audit history.
    #[command(subcommand)]
    Audit(audit_view::AuditCommand),
    #[command(name = "__dev-supervisor", hide = true)]
    DevSupervisor(dev::SupervisorArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Access(command) => access::run(command),
        Command::Keygen(command) => keygen::run(command),
        Command::Jwks(args) => jwks::run(args),
        Command::New(args) => scaffold::run(args),
        Command::Build(args) => build::run(args),
        Command::Fixtures(command) => fixtures::run(command),
        Command::Source(command) => suggest::run(command),
        Command::Doctor(args) => doctor::run(args),
        Command::Dev(args) => dev::run(args),
        Command::Request(command) => request::run(command),
        Command::Verify(args) => verify::run(args),
        Command::Audit(command) => audit_view::run(command),
        Command::DevSupervisor(args) => dev::run_supervisor(args),
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("evidencectl: {error:#}");
            ExitCode::FAILURE
        }
    }
}

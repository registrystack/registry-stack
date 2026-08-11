//! Evidence adopter tooling: key generation, source authoring, and fixture
//! runs. Companion to the frozen `evidence` runtime CLI; it never
//! implements Evidence semantics itself and shells out to the runtime binary
//! for them.

use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};

mod access;
mod audit_view;
mod authoring;
mod build;
mod dev;
mod doctor;
mod evidence_binary;
mod fixtures;
mod jwks;
mod keygen;
mod request;
mod scaffold;
mod suggest;
mod tooling;
mod tooling_editor;
mod verify;

#[derive(Debug, Parser)]
#[command(
    name = "evidencectl",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Evidence adopter tooling: keys, source authoring, fixture runs"
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
    /// Generate Evidence Gateway deployment key material as owner-only files.
    #[command(subcommand)]
    Keygen(keygen::KeygenCommand),
    /// Assemble a public JWKS document from public JWK files.
    Jwks(jwks::JwksArgs),
    /// Start an editable Evidence Gateway project from OpenAPI or a SQLite extract.
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
    /// Run the private local Registry Mint and Evidence Gateway pair.
    Dev(dev::DevArgs),
    /// Prepare a closed request for the active local project.
    #[command(subcommand)]
    Request(request::RequestCommand),
    /// Verify one retained Evidence Gateway response offline.
    Verify(verify::VerifyArgs),
    /// Inspect stopped local audit history.
    #[command(subcommand)]
    Audit(audit_view::AuditCommand),
    /// Advanced: editor and tooling integration surfaces.
    #[command(subcommand)]
    Tooling(tooling::ToolingCommand),
    #[command(name = "__dev-supervisor", hide = true)]
    DevSupervisor(dev::SupervisorArgs),
}

/// Return the complete command tree without running Evidence adopter tooling.
pub fn command() -> clap::Command {
    let mut command = Cli::command();
    command.build();
    command
}

/// Parse process arguments and run one adopter-tooling operation.
pub fn main_entry() -> ExitCode {
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
        Command::Tooling(command) => tooling::run(command),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_reference_excludes_the_dev_supervisor() {
        let command = command();
        assert!(command
            .find_subcommand("__dev-supervisor")
            .is_some_and(clap::Command::is_hide_set));
    }
}

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
mod client;
mod dev;
mod doctor;
mod evidence_binary;
mod fixtures;
mod jwks;
mod keygen;
mod request;
mod scaffold;
mod source_mock;
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
    /// Configure progressive relying-party clients and fetch contract candidates.
    #[command(subcommand)]
    Client(client::ClientCommand),
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
        Command::Client(command) => client::run(command),
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
    use clap::error::ErrorKind;

    #[test]
    fn public_reference_excludes_the_dev_supervisor() {
        let command = command();
        assert!(command
            .find_subcommand("__dev-supervisor")
            .is_some_and(clap::Command::is_hide_set));
    }

    #[test]
    fn dev_syntax_separates_start_options_from_lifecycle_subcommands() {
        let missing_detach = Cli::try_parse_from(["evidencectl", "dev"])
            .expect_err("starting the local pair requires --detach");
        assert_eq!(missing_detach.kind(), ErrorKind::MissingRequiredArgument);

        assert!(Cli::try_parse_from(["evidencectl", "dev", "--detach"]).is_ok());
        assert!(Cli::try_parse_from(["evidencectl", "dev", "stop"]).is_ok());

        let mixed_mode = Cli::try_parse_from(["evidencectl", "dev", "--detach", "stop"])
            .expect_err("start options must not combine with a lifecycle subcommand");
        assert_eq!(mixed_mode.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn request_prepare_keeps_subject_input_forms_mutually_exclusive() {
        let base = [
            "evidencectl",
            "request",
            "prepare",
            "question",
            "--purpose",
            "eligibility",
            "--name",
            "retained-request",
        ];

        assert!(Cli::try_parse_from(base).is_ok());

        assert!(
            Cli::try_parse_from(base.into_iter().chain(["--subject", "person:id=123"]),).is_ok()
        );
        assert!(
            Cli::try_parse_from(base.into_iter().chain(["--subjects-file", "subjects.json"]),)
                .is_ok()
        );

        let duplicate_subject = Cli::try_parse_from(base.into_iter().chain([
            "--subject",
            "person:id=123",
            "--subjects-file",
            "subjects.json",
        ]))
        .expect_err("subject input forms are mutually exclusive");
        assert_eq!(duplicate_subject.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn materialized_source_mock_serve_rejects_ephemeral_generation_options() {
        for option in [
            ["--operation", "GET /records"],
            ["--seed", "1"],
            ["--as-of", "2026-08-13"],
        ] {
            let error = Cli::try_parse_from(
                [
                    "evidencectl",
                    "source",
                    "mock",
                    "serve",
                    "--config",
                    "source.yaml",
                ]
                .into_iter()
                .chain(option),
            )
            .expect_err("materialized serving must reject ephemeral generation options");
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }

        let explain = Cli::try_parse_from([
            "evidencectl",
            "source",
            "mock",
            "serve",
            "--config",
            "source.yaml",
            "--explain",
        ])
        .expect_err("materialized serving must reject generator explanations");
        assert_eq!(explain.kind(), ErrorKind::ArgumentConflict);

        assert!(Cli::try_parse_from([
            "evidencectl",
            "source",
            "mock",
            "serve",
            "--config",
            "source.yaml",
            "--http-addr",
            "127.0.0.1:4010",
        ])
        .is_ok());
    }

    #[test]
    fn stored_source_mock_generation_reuses_settings_and_can_append_cases() {
        for option in [["--seed", "1"], ["--as-of", "2026-08-13"]] {
            let error = Cli::try_parse_from(
                [
                    "evidencectl",
                    "source",
                    "mock",
                    "generate",
                    "--config",
                    "source.yaml",
                ]
                .into_iter()
                .chain(option),
            )
            .expect_err("stored generation must reject new generation inputs");
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }

        assert!(Cli::try_parse_from([
            "evidencectl",
            "source",
            "mock",
            "generate",
            "--config",
            "source.yaml",
            "--operation",
            "GET /records/{id}",
            "--case",
            "second-record",
            "--path-parameter",
            "id=123",
        ])
        .is_ok());

        assert!(Cli::try_parse_from([
            "evidencectl",
            "source",
            "mock",
            "generate",
            "--config",
            "source.yaml",
            "--explain",
        ])
        .is_ok());
    }

    /// Every argument in the built command tree, with the command path that
    /// owns it, so a rule can be asserted across the whole binary at once.
    fn tree_arguments(command: &clap::Command, path: &str) -> Vec<(String, clap::Arg)> {
        let mut arguments: Vec<(String, clap::Arg)> = command
            .get_arguments()
            .map(|argument| (path.to_owned(), argument.clone()))
            .collect();
        for subcommand in command.get_subcommands() {
            let child = format!("{path} {}", subcommand.get_name());
            arguments.extend(tree_arguments(subcommand, &child));
        }
        arguments
    }

    #[test]
    fn project_names_one_project_directory_across_every_subcommand() {
        let command = command();
        let arguments = tree_arguments(&command, command.get_name());
        let projects: Vec<_> = arguments
            .iter()
            .filter(|(_, argument)| argument.get_long() == Some("project"))
            .collect();
        assert!(
            projects.len() >= 18,
            "the whole tree must be walked, saw {:?}",
            projects.iter().map(|(path, _)| path).collect::<Vec<_>>()
        );

        let documented: Vec<_> = projects
            .iter()
            .filter(|(_, argument)| !argument.is_hide_set())
            .collect();
        assert_eq!(
            documented.len(),
            8,
            "every documented --project must be covered by this rule: {:?}",
            documented.iter().map(|(path, _)| path).collect::<Vec<_>>()
        );

        for (path, argument) in &projects {
            assert!(
                !argument.is_required_set(),
                "{path} --project must be optional so the current directory is always a valid answer"
            );
        }

        for (path, argument) in documented {
            let help = argument
                .get_help()
                .expect("every documented --project carries help")
                .to_string();
            assert!(
                help.starts_with("Evidence project directory"),
                "{path} --project help must open with the shared phrase, saw {help:?}"
            );
            let long_help = argument
                .get_long_help()
                .expect("every documented --project states the project shape it needs")
                .to_string();
            assert!(
                long_help.contains("editable project") || long_help.contains("deployment project"),
                "{path} --project must name the project shape it needs, saw {long_help:?}"
            );
            if *path == "evidencectl source suggest" {
                assert!(
                    help.contains("printed when this is absent"),
                    "{path} --project stays absent to keep the draft print-only, saw {help:?}"
                );
            } else {
                assert!(
                    help.contains("defaults to the current directory"),
                    "{path} --project must say the current directory is the default, saw {help:?}"
                );
            }
        }
    }

    #[test]
    fn the_project_commands_a_newcomer_reaches_for_run_without_the_flag() {
        for arguments in [
            vec!["evidencectl", "doctor"],
            vec!["evidencectl", "fixtures", "run"],
            vec![
                "evidencectl",
                "build",
                "--target",
                "deployment/local",
                "--output",
                "candidate",
            ],
            vec!["evidencectl", "tooling", "editor"],
        ] {
            assert!(
                Cli::try_parse_from(&arguments).is_ok(),
                "{arguments:?} must work from inside the project directory"
            );
        }
    }

    #[test]
    fn output_paths_are_spelled_one_way_in_help() {
        let command = command();
        for (path, argument) in tree_arguments(&command, command.get_name()) {
            let Some(long) = argument.get_long() else {
                continue;
            };
            assert!(
                !matches!(long, "out" | "out-dir" | "public-out"),
                "{path} still offers --{long} as a documented spelling"
            );
        }
    }

    #[test]
    fn retired_output_spellings_keep_parsing() {
        for arguments in [
            vec!["evidencectl", "keygen", "secret", "--out", "audit-hmac-key"],
            vec!["evidencectl", "keygen", "token", "--out", "source-token"],
            vec!["evidencectl", "keygen", "signing", "--out-dir", "secrets"],
            vec![
                "evidencectl",
                "keygen",
                "signing",
                "--out-dir",
                "secrets",
                "--public-out",
                "signing.jwk.json",
            ],
            vec!["evidencectl", "keygen", "holder", "--out-dir", "keys"],
            vec![
                "evidencectl",
                "keygen",
                "client-assertion",
                "--out-dir",
                "secrets",
                "--public-out",
                "assertion.jwk.json",
            ],
            vec![
                "evidencectl",
                "jwks",
                "--out",
                "trusted-issuer-keys.json",
                "signing-p256-public.jwk.json",
            ],
            vec![
                "evidencectl",
                "client",
                "contracts",
                "fetch",
                "--profile",
                "client-profile.json",
                "--out",
                "contracts.json",
            ],
            vec![
                "evidencectl",
                "client",
                "profile",
                "create",
                "--base-url",
                "https://evidence.example.test",
                "--client-id",
                "reporting",
                "--private-key-file",
                "client-private-jwk",
                "--out",
                "client-profile.json",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&arguments).is_ok(),
                "{arguments:?} must keep working as already published"
            );
        }
    }

    #[test]
    fn current_output_spellings_parse() {
        for arguments in [
            vec![
                "evidencectl",
                "keygen",
                "secret",
                "--output",
                "audit-hmac-key",
            ],
            vec!["evidencectl", "keygen", "token", "--output", "source-token"],
            vec![
                "evidencectl",
                "keygen",
                "signing",
                "--output-dir",
                "secrets",
                "--public-output",
                "signing.jwk.json",
            ],
            vec!["evidencectl", "keygen", "holder", "--output-dir", "keys"],
            vec![
                "evidencectl",
                "keygen",
                "client-assertion",
                "--output-dir",
                "secrets",
                "--public-output",
                "assertion.jwk.json",
            ],
            vec![
                "evidencectl",
                "jwks",
                "--output",
                "trusted-issuer-keys.json",
                "signing-p256-public.jwk.json",
            ],
            vec![
                "evidencectl",
                "client",
                "contracts",
                "fetch",
                "--profile",
                "client-profile.json",
                "--output",
                "contracts.json",
            ],
            vec![
                "evidencectl",
                "client",
                "profile",
                "create",
                "--base-url",
                "https://evidence.example.test",
                "--client-id",
                "reporting",
                "--private-key-file",
                "client-private-jwk",
                "--output",
                "client-profile.json",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&arguments).is_ok(),
                "{arguments:?} must parse"
            );
        }
    }

    #[test]
    fn request_verify_is_a_deprecated_alias_of_verify() {
        let command = command();
        let request = command
            .find_subcommand("request")
            .expect("request is published");
        let aliased = request
            .find_subcommand("verify")
            .expect("request verify stays available");
        let about = aliased
            .get_about()
            .expect("request verify carries help")
            .to_string();
        assert!(
            about.to_lowercase().contains("deprecated"),
            "request verify must announce itself as deprecated, saw {about:?}"
        );
        let long_about = aliased
            .get_long_about()
            .expect("request verify explains what replaces it")
            .to_string();
        assert!(
            long_about.contains("evidencectl verify"),
            "request verify must name the command that replaces it, saw {long_about:?}"
        );

        for arguments in [
            vec![
                "evidencectl",
                "verify",
                "response.jws",
                "--context",
                "context.json",
                "--output",
                "verified.json",
            ],
            vec![
                "evidencectl",
                "request",
                "verify",
                "response.jws",
                "--context",
                "context.json",
                "--output",
                "verified.json",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&arguments).is_ok(),
                "{arguments:?} must keep working"
            );
        }
    }
}

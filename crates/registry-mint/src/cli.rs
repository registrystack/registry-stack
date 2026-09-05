//! Registry Mint command-line contract.

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};

const DEFAULT_HEALTHCHECK_URL: &str = "http://127.0.0.1:8081/ready";

#[derive(Debug, Parser)]
#[command(
    name = "mint",
    about = "Registry Stack token issuer",
    version = registry_platform_buildinfo::DISPLAY_VERSION
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Load the configuration, keys, audit chain, and client registry, then exit.
    Check {
        /// Mint deployment configuration file.
        #[arg(long, env = "MINT_CONFIG")]
        config: PathBuf,
        /// Claim the audit writer and prove every serving dependency is ready.
        /// Use before startup, not against a Mint process that is already serving.
        #[arg(long)]
        require_runtime_dependencies: bool,
        /// Also prove the configured audit sink resolves inside this absolute
        /// directory, which the deployment declares persistent.
        ///
        /// The declared root is a storage boundary, not a second audit setting.
        /// Mint resolves `audit.path` against the configuration file exactly as
        /// startup resolves it and refuses when the result is not at or below
        /// the root, which is what stops a container from mounting durable
        /// storage at the conventional prefix while writing the chain somewhere
        /// ephemeral.
        #[arg(
            long,
            value_name = "ABSOLUTE_DIRECTORY",
            requires = "require_runtime_dependencies"
        )]
        require_audit_under: Option<PathBuf>,
    },
    /// Serve the token endpoint until terminated.
    Serve {
        /// Mint deployment configuration file.
        #[arg(long, env = "MINT_CONFIG")]
        config: PathBuf,
    },
    /// Probe a numeric private readiness endpoint without ambient proxy use.
    Healthcheck {
        /// Exact loopback or private-address readiness URL.
        #[arg(
            long,
            env = "MINT_HEALTHCHECK_URL",
            default_value = DEFAULT_HEALTHCHECK_URL
        )]
        url: String,
    },
    /// Verify the retained keyed Mint audit chain named by the configuration.
    VerifyAudit {
        /// Mint deployment configuration file.
        #[arg(long, env = "MINT_CONFIG")]
        config: PathBuf,
    },
    /// Provision high-entropy credentials for compatible managed clients.
    ClientSecret {
        #[command(subcommand)]
        command: ClientSecretCommand,
    },
    /// Obtain an access token from a running token endpoint, as a client would.
    ///
    /// This authenticates. It signs a client assertion with the caller's own
    /// key and posts it; the endpoint decides. Nothing here can produce a token
    /// the same request over the wire would not have produced.
    Token {
        /// The token endpoint, for example `https://mint.example.org/token`.
        #[arg(long)]
        url: String,
        /// The `clientId` this caller is registered under.
        #[arg(long)]
        client_id: String,
        /// The caller's private JWK. Must be owner-only and not a symlink.
        #[arg(long)]
        key: PathBuf,
        /// The endpoint's configured `clientAssertion.audience`. Defaults to
        /// `--url`, which is the usual configuration.
        #[arg(long)]
        audience: Option<String>,
        /// Request a delegated token for this actor. Requires `--subject-file`.
        #[arg(long, requires = "subject_file")]
        actor: Option<String>,
        /// A JSON object of subject selector fields, for the actor to act for.
        ///
        /// A file rather than repeated flags on purpose: these are a real
        /// person's identifying details, and command lines are visible to every
        /// process on the host and land in shell history.
        #[arg(long, requires = "actor")]
        subject_file: Option<PathBuf>,
        /// Assertion lifetime in seconds.
        #[arg(long, default_value_t = 120)]
        lifetime_seconds: i64,
        /// Trust this PEM certificate bundle in addition to the system roots,
        /// for a development deployment behind a private CA.
        #[arg(long)]
        ca_certificate: Option<PathBuf>,
        /// Print the full endpoint response instead of the access token alone.
        #[arg(long)]
        verbose: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ClientSecretCommand {
    /// Generate one credential file and print its non-secret fingerprint.
    Generate {
        /// New owner-only file that receives the printable client secret.
        #[arg(long)]
        out: PathBuf,
    },
}

/// Return the complete command tree without running Registry Mint.
pub fn command() -> clap::Command {
    let mut command = Cli::command();
    command.build();
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    const TOKEN_ARGS: [&str; 8] = [
        "mint",
        "token",
        "--url",
        "https://mint.example.org/token",
        "--client-id",
        "caller",
        "--key",
        "private.jwk",
    ];

    #[test]
    fn token_delegation_requires_the_actor_and_subject_file_together() {
        assert!(Cli::try_parse_from(TOKEN_ARGS).is_ok());

        for lone_option in [["--actor", "scheduler"], ["--subject-file", "subject.json"]] {
            let error = Cli::try_parse_from(
                TOKEN_ARGS
                    .into_iter()
                    .chain(lone_option)
                    .collect::<Vec<_>>(),
            )
            .expect_err("one delegation option must require the other");
            assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
        }

        assert!(Cli::try_parse_from(
            TOKEN_ARGS
                .into_iter()
                .chain(["--actor", "scheduler", "--subject-file", "subject.json",])
                .collect::<Vec<_>>(),
        )
        .is_ok());
    }

    #[test]
    fn client_secret_generation_requires_an_output_path() {
        assert!(Cli::try_parse_from([
            "mint",
            "client-secret",
            "generate",
            "--out",
            "client-secret"
        ])
        .is_ok());
        let error = Cli::try_parse_from(["mint", "client-secret", "generate"])
            .expect_err("the output path is required");
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn runtime_dependency_check_is_an_explicit_operator_choice() {
        let ordinary = Cli::try_parse_from(["mint", "check", "--config", "mint.yaml"])
            .expect("ordinary live-deployment check parses");
        assert!(matches!(
            ordinary.command,
            Command::Check {
                require_runtime_dependencies: false,
                ..
            }
        ));

        let preflight = Cli::try_parse_from([
            "mint",
            "check",
            "--config",
            "mint.yaml",
            "--require-runtime-dependencies",
        ])
        .expect("full dependency preflight parses");
        assert!(matches!(
            preflight.command,
            Command::Check {
                require_runtime_dependencies: true,
                ..
            }
        ));
    }

    #[test]
    fn requiring_an_audit_root_also_requires_the_runtime_dependency_proof() {
        let parsed = Cli::try_parse_from([
            "mint",
            "check",
            "--config",
            "mint.yaml",
            "--require-runtime-dependencies",
            "--require-audit-under",
            "/var/lib/registry-mint",
        ])
        .expect("the audit root pairs with the dependency proof");
        let Command::Check {
            require_audit_under,
            ..
        } = parsed.command
        else {
            panic!("check parsed as another command");
        };
        assert_eq!(
            Some(PathBuf::from("/var/lib/registry-mint")),
            require_audit_under
        );

        // Containment is a claim about the sink the dependency proof claims, so
        // it cannot be requested on its own.
        let error = Cli::try_parse_from([
            "mint",
            "check",
            "--config",
            "mint.yaml",
            "--require-audit-under",
            "/var/lib/registry-mint",
        ])
        .expect_err("containment alone proves nothing about writability");
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn healthcheck_uses_the_process_local_readiness_endpoint() {
        let command = command();
        let healthcheck = command
            .find_subcommand("healthcheck")
            .expect("healthcheck subcommand exists");
        let url = healthcheck
            .get_arguments()
            .find(|argument| argument.get_id() == "url")
            .expect("healthcheck URL argument exists");
        assert_eq!(
            url.get_default_values(),
            [std::ffi::OsStr::new(DEFAULT_HEALTHCHECK_URL)]
        );
        assert_eq!(
            url.get_env(),
            Some(std::ffi::OsStr::new("MINT_HEALTHCHECK_URL"))
        );
    }

    #[test]
    fn every_config_option_has_public_help() {
        let command = command();
        for name in ["check", "serve", "verify-audit"] {
            let subcommand = command.find_subcommand(name).expect("public subcommand");
            let config = subcommand
                .get_arguments()
                .find(|argument| argument.get_id() == "config")
                .expect("config option");
            assert!(
                config
                    .get_long_help()
                    .or_else(|| config.get_help())
                    .is_some_and(|help| !help.to_string().trim().is_empty()),
                "{name} --config lacks public help"
            );
        }
    }
}

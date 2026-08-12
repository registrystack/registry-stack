//! Registry Mint command-line contract.

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};

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
        #[arg(long, env = "MINT_CONFIG")]
        config: PathBuf,
    },
    /// Serve the token endpoint until terminated.
    Serve {
        #[arg(long, env = "MINT_CONFIG")]
        config: PathBuf,
    },
    /// Verify the retained keyed Mint audit chain named by the configuration.
    VerifyAudit {
        #[arg(long, env = "MINT_CONFIG")]
        config: PathBuf,
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
}

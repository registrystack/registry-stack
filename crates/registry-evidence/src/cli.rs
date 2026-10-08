//! Evidence runtime command-line contract.

use std::ffi::OsStr;
use std::path::PathBuf;

use clap::{ArgGroup, CommandFactory, Parser, Subcommand, ValueEnum};

/// The environment variable that used to name the runtime file. Evidence
/// refuses to start while it is set, so a deployment that still sets it learns
/// the file is now named on the command line instead of silently reading a
/// different one.
pub const REMOVED_RUNTIME_ENVIRONMENT_VARIABLE: &str = "REGISTRY_EVIDENCE_RUNTIME";

#[derive(Debug, Parser)]
#[command(
    name = "evidence",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Evidence Gateway Version 1"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// The removed runtime-file input an invocation still uses, as the refusal to
/// report, or `None`.
///
/// `arguments` are the command-line arguments after the program name. They are
/// read before parsing, so an invocation written for the removed flag is
/// refused with its replacement named rather than with a missing-argument
/// error. `runtime_environment_set` is whether
/// [`REMOVED_RUNTIME_ENVIRONMENT_VARIABLE`] is set in the process environment.
pub fn removed_runtime_input<I, S>(
    arguments: I,
    runtime_environment_set: bool,
) -> Option<&'static str>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let uses_removed_flag = arguments
        .into_iter()
        .map_while(|argument| {
            let argument = argument.as_ref().as_encoded_bytes().to_vec();
            (argument != b"--").then_some(argument)
        })
        .any(|argument| argument == b"--runtime" || argument.starts_with(b"--runtime="));
    if uses_removed_flag {
        return Some("--runtime is no longer accepted; pass --runtime-config FILE");
    }
    if runtime_environment_set {
        return Some(
            "REGISTRY_EVIDENCE_RUNTIME is no longer read; unset it and pass --runtime-config FILE",
        );
    }
    None
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check a runtime file and the package it binds, offline, and report
    /// every problem found.
    ///
    /// The check reads no secret material and contacts no network service. It
    /// reads the runtime file, verifies the package `package.root` names,
    /// loads and compiles the bundle, reads each CA bundle a trust profile
    /// names, and checks every binding between the runtime file and the
    /// bundle. Freezing, secret material, extract freshness, and runtime
    /// dependencies are proved on the target host with
    /// `--require-runtime-dependencies`.
    Check {
        /// The closed operator runtime file that binds the governed bundle.
        #[arg(long = "runtime-config", value_name = "FILE")]
        runtime_config: PathBuf,
        /// Report for a person (`human`) or as one JSON document on standard
        /// output (`json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
        /// Exit 1 when the check reports a warning.
        #[arg(long)]
        deny_warnings: bool,
        /// Substitute `${...}` expressions from this process's environment, as
        /// startup does, and check the values they fill. Without it an
        /// expression is checked by its syntax and position only.
        #[arg(long)]
        environment: bool,
        /// Also prove, on the target host, what startup proves: read-only
        /// deployment inputs, secret material, extract freshness, audit
        /// writability, signer readiness, source credentials, and access-token
        /// JWKS reachability.
        #[arg(long)]
        require_runtime_dependencies: bool,
        /// Also prove the configured audit sink resolves inside this absolute
        /// directory, which the deployment declares persistent.
        ///
        /// The declared root is a storage boundary, not a second audit setting.
        /// Evidence resolves its own configured destination exactly as startup
        /// resolves it and refuses when the result is not at or below the root,
        /// which is what stops a container from mounting durable storage at the
        /// conventional prefix while writing audit entries somewhere ephemeral.
        #[arg(
            long,
            value_name = "ABSOLUTE_DIRECTORY",
            requires = "require_runtime_dependencies"
        )]
        require_audit_under: Option<PathBuf>,
        /// Prove the audit destination without taking its single-writer lock,
        /// for a candidate staged beside the running instance that holds it.
        ///
        /// Modes, write access, and a complete final entry in the active file
        /// are still proved, and every other dependency is proved as without
        /// this flag. A second writer is not detected, so `serve` still
        /// refuses to start while one holds the lock.
        #[arg(long, requires = "require_runtime_dependencies")]
        without_audit_lock: bool,
    },
    /// Evaluate one bundle-owned fixture without source or credential access.
    Evaluate {
        /// The closed operator runtime file that binds the governed bundle.
        #[arg(long = "runtime-config", value_name = "FILE")]
        runtime_config: PathBuf,
        /// Bundle-relative fixture path referenced by exactly one requirement.
        #[arg(long)]
        fixture: PathBuf,
        /// Evaluate only the case with this exact identifier.
        #[arg(long)]
        case: Option<String>,
        /// Print the per-stage trace of what each case actually did.
        ///
        /// A failure names the contract that broke and nothing else, which says
        /// that a case failed but never why. The trace says how far each case
        /// got, what shape the response and facts had, and which declared
        /// concept the output gate was checking. It reports shapes, counts, and
        /// identifiers, never document values, and it never changes an outcome,
        /// an exit code, or a message.
        #[arg(long)]
        explain: bool,
        /// Render the `--explain` trace for a machine reader instead of a
        /// person. The JSON form is the whole of standard output, so the
        /// summary line's verdict and evaluated-case count move inside the
        /// document rather than trailing it.
        #[arg(long, value_enum, requires = "explain")]
        explain_format: Option<ExplainFormat>,
    },
    /// Internal Evidencectl seam for bundle-only semantic validation.
    #[command(hide = true)]
    BundleCheck {
        #[arg(long)]
        bundle: PathBuf,
        /// Return value-free bundle and requirement configuration revisions.
        #[arg(long)]
        json: bool,
    },
    /// Internal Evidencectl seam for bundle-only fixture evaluation.
    #[command(hide = true)]
    BundleEvaluate {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        fixture: PathBuf,
        #[arg(long)]
        case: Option<String>,
        /// Print the same value-free per-stage trace as deployment evaluation.
        #[arg(long)]
        explain: bool,
        /// Render the trace as the same single machine-readable document as
        /// deployment evaluation.
        #[arg(long, value_enum, requires = "explain")]
        explain_format: Option<ExplainFormat>,
    },
    /// Internal Evidencectl seam for deterministic provider-publication compilation.
    #[command(hide = true)]
    RenderDiscoveryDescription {
        #[arg(long)]
        config: PathBuf,
    },
    /// Start the native Evidence Gateway HTTP service.
    Serve {
        /// The closed operator runtime file that binds the governed bundle.
        #[arg(long = "runtime-config", value_name = "FILE")]
        runtime_config: PathBuf,
    },
    /// Re-verify one stored signed response offline against a pinned key set.
    ///
    /// Exactly one stored response is named, and its format is named with it.
    /// The command never infers a format from the file's contents, so a
    /// credential can never be re-verified under the other format's rules.
    #[command(group(ArgGroup::new("stored").required(true)))]
    Verify {
        /// Stored flattened JWS JSON response file.
        #[arg(long, group = "stored")]
        jws: Option<PathBuf>,
        /// Stored compact SD-JWT VC response file.
        #[arg(long = "sd-jwt-vc", group = "stored")]
        sd_jwt_vc: Option<PathBuf>,
        /// Pinned trusted JWKS document. This file is the complete trust set.
        #[arg(long)]
        jwks: PathBuf,
        /// Relying-procedure verification policy document.
        #[arg(long)]
        policy: PathBuf,
        /// Verification instant as strict RFC 3339 UTC; system time by default.
        #[arg(long)]
        at: Option<String>,
    },
    /// Re-verify one stored holder-bound presentation offline against a pinned
    /// key set.
    ///
    /// The named file is one compact SD-JWT VC serialization carrying the
    /// holder's key-binding JWT after its last tilde, so the proof is never a
    /// separate input. Naming the input states its shape: a stored credential
    /// that ends in a trailing tilde offers no proof of possession and is
    /// refused here rather than verified without one.
    ///
    /// Success proves the presenter held the confirmation key's private key
    /// when the key-binding JWT was signed. It does not prove that the
    /// presentation is fresh, single-use, or unreplayed: the expected challenge
    /// is compared, never consumed, and this command retains no state between
    /// runs, so the same file verifies again under the same policy. Retiring a
    /// challenge belongs to the relying party's own challenge lifecycle.
    VerifyPresentation {
        /// Stored compact SD-JWT VC presentation file.
        #[arg(long = "sd-jwt-vc-presentation")]
        sd_jwt_vc_presentation: PathBuf,
        /// Pinned trusted JWKS document. This file is the complete trust set.
        #[arg(long)]
        jwks: PathBuf,
        /// Holder-bound relying-procedure verification policy document.
        #[arg(long)]
        policy: PathBuf,
        /// Verification instant as strict RFC 3339 UTC; system time by default.
        #[arg(long)]
        at: Option<String>,
    },
    /// Internal local-adopter seam for bearer-free relying-procedure closure.
    #[command(hide = true)]
    PrepareLocalRelyingProcedure {
        /// The closed operator runtime file that binds the governed bundle.
        #[arg(long = "runtime-config", value_name = "FILE")]
        runtime_config: PathBuf,
        /// Owner-only JSON draft containing the request shape and audience.
        #[arg(long)]
        input: PathBuf,
    },
    /// Internal stopped-service audit inspection seam.
    #[command(hide = true)]
    LocalAuditLastOperation {
        /// The closed operator runtime file that binds the governed bundle.
        #[arg(long = "runtime-config", value_name = "FILE")]
        runtime_config: PathBuf,
    },
}

/// Who a check report is rendered for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum OutputFormat {
    /// Position-first diagnostic lines and a summary for a person.
    #[default]
    Human,
    /// One JSON document for a machine reader.
    Json,
}

/// Who the `--explain` trace is rendered for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum ExplainFormat {
    /// Aligned per-stage blocks for a person.
    #[default]
    Text,
    /// One JSON document for a machine reader.
    Json,
}

/// Return the complete command tree without running Evidence.
pub fn command() -> clap::Command {
    let mut command = Cli::command();
    command.build();
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requiring_an_audit_root_also_requires_the_runtime_dependency_proof() {
        let parsed = Cli::try_parse_from([
            "evidence",
            "check",
            "--runtime-config",
            "/etc/registry-evidence/runtime.yaml",
            "--require-runtime-dependencies",
            "--require-audit-under",
            "/var/lib/registry-evidence",
        ])
        .expect("the audit root pairs with the dependency proof");
        let Command::Check {
            runtime_config: _,
            format: _,
            deny_warnings: _,
            environment: _,
            require_runtime_dependencies,
            require_audit_under,
            without_audit_lock,
        } = parsed.command
        else {
            panic!("check parsed as another command");
        };
        assert!(require_runtime_dependencies);
        assert!(!without_audit_lock);
        assert_eq!(
            Some(PathBuf::from("/var/lib/registry-evidence")),
            require_audit_under
        );

        // Containment is a claim about the sink the dependency proof opens, so
        // it cannot be requested on its own.
        assert!(Cli::try_parse_from([
            "evidence",
            "check",
            "--runtime-config",
            "/etc/registry-evidence/runtime.yaml",
            "--require-audit-under",
            "/var/lib/registry-evidence",
        ])
        .is_err());
    }

    #[test]
    fn public_reference_excludes_internal_evidencectl_seams() {
        let command = command();
        for hidden in [
            "bundle-check",
            "bundle-evaluate",
            "render-discovery-description",
            "prepare-local-relying-procedure",
            "local-audit-last-operation",
        ] {
            assert!(
                command
                    .find_subcommand(hidden)
                    .is_some_and(clap::Command::is_hide_set),
                "{hidden} must remain hidden"
            );
        }
    }

    const RUNTIME_COMMANDS: [&str; 5] = [
        "check",
        "evaluate",
        "serve",
        "prepare-local-relying-procedure",
        "local-audit-last-operation",
    ];

    #[test]
    fn every_runtime_command_names_its_runtime_configuration_explicitly() {
        let command = command();
        for subcommand in RUNTIME_COMMANDS {
            let found = command
                .find_subcommand(subcommand)
                .expect("subcommand exists");
            let runtime = found
                .get_arguments()
                .find(|argument| argument.get_id() == "runtime_config")
                .expect("runtime configuration argument exists");
            assert_eq!(runtime.get_long(), Some("runtime-config"), "{subcommand}");
            assert_eq!(runtime.get_env(), None, "{subcommand}");
            assert!(runtime.get_default_values().is_empty(), "{subcommand}");
            assert!(runtime.is_required_set(), "{subcommand}");
        }
        assert!(Cli::try_parse_from(["evidence", "serve"]).is_err());
    }

    #[test]
    fn the_removed_runtime_flag_is_refused_with_its_replacement_named() {
        const REFUSAL: Option<&str> =
            Some("--runtime is no longer accepted; pass --runtime-config FILE");
        for arguments in [
            &["--runtime", "/etc/registry-evidence/runtime.yaml", "serve"][..],
            &["serve", "--runtime", "/etc/registry-evidence/runtime.yaml"],
            &["check", "--runtime=/etc/registry-evidence/runtime.yaml"],
        ] {
            assert_eq!(
                removed_runtime_input(arguments, false),
                REFUSAL,
                "{arguments:?}"
            );
        }
        assert_eq!(
            removed_runtime_input(
                [
                    "serve",
                    "--runtime-config",
                    "/etc/registry-evidence/runtime.yaml"
                ],
                false
            ),
            None
        );
        // After the terminator an argument is a value, never a flag.
        assert_eq!(removed_runtime_input(["--", "--runtime"], false), None);
        assert!(
            Cli::try_parse_from(["evidence", "--runtime", "/etc/runtime.yaml", "serve"]).is_err(),
            "the removed flag is not an alias"
        );
    }

    #[test]
    fn the_removed_runtime_environment_variable_is_refused_with_its_replacement_named() {
        let arguments = [
            "serve",
            "--runtime-config",
            "/etc/registry-evidence/runtime.yaml",
        ];
        assert_eq!(removed_runtime_input(arguments, false), None);
        assert_eq!(
            removed_runtime_input(arguments, true),
            Some(
                "REGISTRY_EVIDENCE_RUNTIME is no longer read; unset it and pass --runtime-config FILE"
            )
        );
    }
}

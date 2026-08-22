//! Evidence runtime command-line contract.

use std::path::PathBuf;

use clap::{ArgGroup, CommandFactory, Parser, Subcommand, ValueEnum};

const DEFAULT_RUNTIME_PATH: &str = "/etc/registry-evidence/runtime.yaml";

#[derive(Debug, Parser)]
#[command(
    name = "evidence",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Evidence Gateway Version 1"
)]
pub struct Cli {
    /// One closed operator runtime file that binds the governed bundle.
    #[arg(
        long,
        global = true,
        env = "REGISTRY_EVIDENCE_RUNTIME",
        default_value = DEFAULT_RUNTIME_PATH
    )]
    pub runtime: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Validate and compile the complete immutable bundle, and validate the
    /// mounted secret material exactly as startup does.
    Check {
        /// Also prove audit writability, signer readiness, source credentials,
        /// and access-token JWKS reachability in the target runtime context.
        #[arg(long)]
        require_runtime_dependencies: bool,
    },
    /// Evaluate one bundle-owned fixture without source or credential access.
    Evaluate {
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
    Serve,
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
    /// Run a full out-of-band verification pass over the audit chain.
    ///
    /// Startup verification is deliberately bounded to the active segment, so
    /// restart time does not grow with retained history; tampering inside an
    /// already sealed segment is not caught there. This is the counterpart
    /// check that catches it, meant to run out of band.
    VerifyAudit,
    /// Internal local-adopter seam for bearer-free relying-procedure closure.
    #[command(hide = true)]
    PrepareLocalRelyingProcedure {
        /// Owner-only JSON draft containing the request shape and audience.
        #[arg(long)]
        input: PathBuf,
    },
    /// Internal stopped-service audit inspection seam.
    #[command(hide = true)]
    LocalAuditLastOperation,
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
}

// SPDX-License-Identifier: Apache-2.0

use crate::check::{self, PROJECT_FORMAT};
use crate::report::{
    failure_status, ADAPTER_CTL_REPORT_API_VERSION, ADAPTER_CTL_REPORT_KIND, DOMAIN_REFUSAL_EXIT,
    OPERATIONAL_FAILURE_EXIT,
};
use crate::{check_posture, write_failure, write_success, OutputFormat};
use clap::{Args, Subcommand};
use registry_adapter::payments::config::{PaymentsConfig, API_VERSION, KIND};
use registry_adapter_core::AdapterProject;
use registry_cli_report::{ExplicitSettingLine, Report as CliReport};
use registry_platform_config::{
    Admitted, ClientRule, DeclaredPosture, RuntimeConfigLoader, RuntimeEnvelope,
};
use registry_platform_yaml::{Diagnostic, Related, Report, Source};
use registry_thunderid_tooling::identity_facts::{
    self, AccessProfile, Admission, ClaimType, IdentityFacts,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const COMMAND: &str = "generate identity-facts";

/// Generate an identity tooling input from the deployment.
#[derive(Debug, Args)]
pub(crate) struct GenerateArgs {
    #[command(subcommand)]
    command: GenerateCommand,
}

#[derive(Debug, Subcommand)]
enum GenerateCommand {
    /// Write the caller requirements of one configured issuer.
    IdentityFacts(IdentityFactsArgs),
}

#[derive(Debug, Args)]
struct IdentityFactsArgs {
    /// The authored Adapter project.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
    /// Runtime configuration file: its oidc block and the project's access
    /// profiles state the facts.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
    /// Write the identity facts to this file.
    #[arg(long, value_name = "FILE")]
    output: PathBuf,
    /// Absolute path to the payment connection configuration.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    payments_config: Option<PathBuf>,
    /// The issuer entry to describe when the runtime lists more than one.
    #[arg(long, value_name = "ID")]
    issuer: Option<String>,
}

pub(crate) fn command_name(_: &GenerateArgs) -> &'static str {
    COMMAND
}

pub(crate) fn run(
    args: GenerateArgs,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, ()> {
    let GenerateCommand::IdentityFacts(args) = args.command;
    match generate(&args) {
        Ok(generated) => {
            let result = json!({
                "ok": true,
                "command": COMMAND,
                "status": "complete",
                "apiVersion": ADAPTER_CTL_REPORT_API_VERSION,
                "kind": ADAPTER_CTL_REPORT_KIND,
                "output": args.output,
                "accessProfiles": generated.facts.access_profiles.len(),
                "claims": generated.facts.claims.len(),
            });
            if format == OutputFormat::Json {
                let envelope =
                    CliReport::new(&result, registry_platform_buildinfo::DISPLAY_VERSION)
                        .map_err(|_| ())?
                        .with_posture(generated.declared)
                        .explicit_settings(generated.settings);
                serde_json::to_writer_pretty(&mut *stdout, &envelope).map_err(|_| ())?;
                writeln!(stdout).map_err(|_| ())?;
                Ok(ExitCode::SUCCESS)
            } else {
                write_success(&result, &Report::new(Vec::new()), format, stdout)
            }
        }
        Err((exit, diagnostics)) => {
            let envelope = json!({
                "ok": false,
                "command": COMMAND,
                "status": failure_status(exit),
                "diagnostics": Report::new(diagnostics).to_json_value(),
            });
            write_failure(&envelope, format, stdout, stderr).map(|()| ExitCode::from(exit))
        }
    }
}

type Refused = (u8, Vec<Diagnostic>);

fn refusal(code: &str, path: &str, message: &str, action: &str) -> Refused {
    (
        DOMAIN_REFUSAL_EXIT,
        vec![Diagnostic::error(code, path, message, action)],
    )
}

fn input_refused(path: &str) -> Refused {
    refusal(
        "identity.facts.unstatable",
        path,
        "the identity facts input was refused",
        "Run the Adapter check for this file and correct its configuration.",
    )
}

fn file_failure(path: &str, source: &io::Error) -> Refused {
    (
        OPERATIONAL_FAILURE_EXIT,
        vec![file_diagnostic(
            path,
            "adapterctl.io-failure",
            &format!("the file could not be read: {source}"),
            "Correct the path or permissions, then retry.",
        )],
    )
}

fn check_failure(error: check::CheckFailure) -> Refused {
    let check::CheckFailure::Io { path, source } = error;
    file_failure(&path, &source)
}

fn file_diagnostic(path: &str, code: &str, message: &str, action: &str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(code, "", message, action);
    diagnostic.source = Some(Source {
        file: path.to_owned(),
        line: None,
        column: None,
    });
    diagnostic
}

fn existing_output() -> Refused {
    refusal(
        "output.exists",
        "--output",
        "the output file already exists",
        "Choose an unused output path.",
    )
}

struct Generated {
    facts: IdentityFacts,
    declared: DeclaredPosture,
    settings: Vec<ExplicitSettingLine>,
}

fn generate(args: &IdentityFactsArgs) -> Result<Generated, Refused> {
    if args.output.exists() {
        return Err(existing_output());
    }
    let declared = check_posture(None, false)
        .map_err(|(code, message, action)| refusal(code, "posture", message, action))?;
    if !args.runtime_config.is_absolute() {
        return Err(input_refused("--runtime-config"));
    }
    let mut report = Report::new(Vec::new());
    let mut files = 0;
    let runtime = check::load_runtime_for_check(
        &args.runtime_config,
        true,
        &mut report,
        &mut files,
        declared,
    )
    .map_err(check_failure)?;
    if report.has_errors() {
        return Err((DOMAIN_REFUSAL_EXIT, report.into_diagnostics()));
    }
    let runtime = runtime.ok_or_else(|| input_refused("--runtime-config"))?;
    let runtime_path = args.runtime_config.to_string_lossy();
    let settings = runtime
        .posture
        .explicit_settings()
        .iter()
        .map(|setting| ExplicitSettingLine::from_found(setting, Some(&runtime_path)))
        .collect();
    let runtime = runtime.config;
    let mut issuers = runtime.oidc.set.iter();
    let issuer = match args.issuer.as_deref() {
        Some(id) => {
            issuers
                .find(|(key, _)| key.as_str() == id)
                .ok_or_else(|| {
                    refusal(
                        "identity.facts.unknown-issuer",
                        "--issuer",
                        "the issuer entry is unknown",
                        "Name an entry under oidc.issuers.",
                    )
                })?
                .1
        }
        None if runtime.oidc.set.len() == 1 => {
            issuers
                .next()
                .ok_or_else(|| input_refused("--runtime-config"))?
                .1
        }
        None => {
            return Err(refusal(
                "identity.facts.issuer-required",
                "--issuer",
                "the runtime declares more than one issuer",
                "Specify the issuer entry with --issuer.",
            ))
        }
    };
    let core = &issuer.core;
    let Admitted::Listed(clients) = core.allowed_clients.admitted() else {
        return Err(input_refused("--runtime-config"));
    };
    let (project_path, _) = check::resolve_project(&args.project);
    let project =
        check::read::<AdapterProject>(&project_path, &PROJECT_FORMAT, &mut report, &mut files)
            .map_err(check_failure)?
            .map(|(decoded, _)| decoded.value)
            .ok_or_else(|| (DOMAIN_REFUSAL_EXIT, report.into_diagnostics()))?;
    let mut facts = IdentityFacts::new(
        "adapter",
        core.provider.issuer.as_str(),
        &core.provider.audience,
        Admission::Clients(clients.to_vec()),
    );
    let scope_claim = core.scope_claim.get().as_str();
    if scope_claim != "scope" {
        facts
            .claims
            .insert(scope_claim.to_owned(), ClaimType::StringArray);
    }
    let mut facade_profiles = BTreeMap::new();
    for (index, profile) in project.access_profiles.iter().enumerate() {
        facade_profiles.insert(profile.id.as_str(), index);
        facts.access_profiles.push(facts_profile(
            profile.id.as_str(),
            profile
                .scopes
                .iter()
                .map(|scope| scope.as_str().to_owned())
                .collect(),
            None,
            scope_claim,
        ));
    }
    let mut payment_profiles = BTreeMap::new();
    if let Some(path) = &args.payments_config {
        let payments = read_payments(path, declared)?;
        let collections = payments
            .connections
            .iter()
            .enumerate()
            .map(|(index, connection)| {
                (
                    format!("/connections/{index}/id"),
                    &connection.id,
                    &connection.required_scope,
                    &connection.allowed_clients,
                )
            });
        let disbursements = payments
            .disbursements
            .iter()
            .enumerate()
            .map(|(index, connection)| {
                (
                    format!("/disbursements/{index}/id"),
                    &connection.id,
                    &connection.required_scope,
                    &connection.allowed_clients,
                )
            });
        for (pointer, id, scope, connection_clients) in collections.chain(disbursements) {
            if let Some(index) = facade_profiles.get(id.as_str()) {
                let mut diagnostic = file_diagnostic(
                    &path.to_string_lossy(),
                    "identity.facts.unstatable",
                    "the payment connection id matches a facade access profile id",
                    "Give the payment connection and the facade access profile distinct ids.",
                );
                diagnostic.path = pointer;
                diagnostic.related.push(Related {
                    file: project_path.display().to_string(),
                    path: format!("/accessProfiles/{index}/id"),
                    line: None,
                    column: None,
                    message: "the matching facade access profile is declared here".to_owned(),
                });
                return Err((DOMAIN_REFUSAL_EXIT, vec![diagnostic]));
            }
            let listed: Vec<_> = connection_clients
                .iter()
                .filter(|client| clients.contains(client))
                .cloned()
                .collect();
            if !listed.is_empty() {
                payment_profiles.insert(
                    id.clone(),
                    Related {
                        file: path.display().to_string(),
                        path: pointer,
                        line: None,
                        column: None,
                        message: "the payment connection that generated this profile".to_owned(),
                    },
                );
                facts.access_profiles.push(facts_profile(
                    id,
                    vec![scope.clone()],
                    Some(listed),
                    scope_claim,
                ));
            }
        }
    }
    facts
        .access_profiles
        .sort_by(|first, second| first.id.cmp(&second.id));
    let yaml = facts.to_yaml().map_err(|error| {
        refusal(
            "identity.facts.unstatable",
            "--output",
            &error.to_string(),
            "Correct the identity facts inputs.",
        )
    })?;
    identity_facts::read("identity-facts", yaml.as_bytes()).map_err(|error| {
        let Some(report) = error.report() else {
            return refusal(
                "identity.facts.unstatable",
                "--output",
                &error.to_string(),
                "Correct the identity facts inputs.",
            );
        };
        let mut diagnostics = report.diagnostics().to_vec();
        for diagnostic in &mut diagnostics {
            let profile = diagnostic
                .path
                .strip_prefix("/accessProfiles/")
                .and_then(|path| path.split('/').next())
                .and_then(|index| index.parse::<usize>().ok())
                .and_then(|index| facts.access_profiles.get(index));
            if let Some(profile) = profile {
                if let Some(source) = payment_profiles.get(&profile.id) {
                    diagnostic.message =
                        format!("profile from {}: {}", source.path, diagnostic.message);
                    diagnostic.related.push(source.clone());
                } else {
                    diagnostic.message = format!("profile {}: {}", profile.id, diagnostic.message);
                }
            }
        }
        (DOMAIN_REFUSAL_EXIT, diagnostics)
    })?;
    let write = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)
        .and_then(|mut output| output.write_all(yaml.as_bytes()));
    match write {
        Ok(()) => Ok(Generated {
            facts,
            declared,
            settings,
        }),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(existing_output()),
        Err(error) => Err((
            OPERATIONAL_FAILURE_EXIT,
            vec![file_diagnostic(
                &args.output.to_string_lossy(),
                "output.failed",
                &format!("the output file could not be written: {error}"),
                "Check the output path and its directory permissions.",
            )],
        )),
    }
}

fn read_payments(path: &Path, declared: DeclaredPosture) -> Result<PaymentsConfig, Refused> {
    if !path.is_absolute() {
        return Err(input_refused("--payments-config"));
    }
    let shown = path.to_string_lossy();
    let path = std::fs::canonicalize(path).map_err(|error| file_failure(&shown, &error))?;
    let loaded = RuntimeConfigLoader::new(
        RuntimeEnvelope {
            api_version: API_VERSION,
            kind: KIND,
        },
        declared,
    )
    .load::<PaymentsConfig>(&path)
    .map_err(|error| {
        let mut diagnostics = error.diagnostics().to_vec();
        let unavailable = diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == registry_platform_config::UNAVAILABLE_CODE);
        for diagnostic in &mut diagnostics {
            if let Some(source) = &mut diagnostic.source {
                source.file = shown.to_string();
            }
            for related in &mut diagnostic.related {
                if related.file == path.to_string_lossy() {
                    related.file = shown.to_string();
                }
            }
        }
        let exit = if unavailable {
            OPERATIONAL_FAILURE_EXIT
        } else {
            DOMAIN_REFUSAL_EXIT
        };
        (exit, diagnostics)
    })?;
    loaded
        .config
        .validate(loaded.development.as_ref())
        .map_err(|error| {
            (
                DOMAIN_REFUSAL_EXIT,
                vec![file_diagnostic(
                    &shown,
                    error.code(),
                    &format!("the payments configuration was refused: {error}"),
                    "Correct the payment connections and their provider bindings.",
                )],
            )
        })?;
    Ok(loaded.config)
}

fn facts_profile(
    id: &str,
    scopes: Vec<String>,
    requester_clients: Option<Vec<String>>,
    scope_claim: &str,
) -> AccessProfile {
    let selected_by = if scope_claim == "scope" {
        BTreeMap::new()
    } else {
        BTreeMap::from([(scope_claim.to_owned(), scopes.clone())])
    };
    AccessProfile {
        id: id.to_owned(),
        scopes,
        purposes: Vec::new(),
        requester_clients,
        exchange: None,
        selected_by,
        actor_kind: None,
        required_claims: Vec::new(),
        admitted_actor_kinds: Vec::new(),
        refused_claims: Vec::new(),
    }
}

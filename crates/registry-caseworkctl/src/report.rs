// SPDX-License-Identifier: Apache-2.0

//! The report envelope every `--format json` command shares, aligned with the
//! sibling ctls.
//!
//! A report is one JSON object on standard output. It opens with `ok`,
//! `command`, and `status`, in that order, followed by the command's own
//! camelCase members, `apiVersion` and `kind` among them. `ok` is true
//! exactly when the process exits zero; `status` names what happened. A
//! report that is not ok carries a non-empty `diagnostics` array whose
//! entries each name a `suggestedAction`.

use std::io;

use serde::ser::{Serialize, SerializeMap as _, Serializer};
use serde_json::Value;

/// The command line was incomplete, conflicting, or unsupported.
pub(crate) const USAGE_EXIT: u8 = 2;
/// A file, process, or service the command depends on was unavailable.
pub(crate) const OPERATIONAL_FAILURE_EXIT: u8 = 3;

/// The members every report opens with, in the order they are written.
const HEAD: [&str; 3] = ["ok", "command", "status"];

/// The status a failure envelope carries for each exit class.
#[cfg(test)]
pub(crate) fn failure_status(exit: u8) -> &'static str {
    match exit {
        USAGE_EXIT => "usage-error",
        OPERATIONAL_FAILURE_EXIT => "operational-failure",
        _ => "domain-refusal",
    }
}

/// Describe a command line clap refused by the error kind and the argument
/// name only. Clap's own message is never repeated because it quotes the
/// rejected token, which may carry an operator value such as a change
/// reference that is otherwise recorded only as a hash. A value one of our
/// own parsers refused is described by that parser's reason instead, as
/// long as the reason does not repeat the value; a reason that does not name
/// the argument follows it.
pub(crate) fn usage_message(error: &clap::Error) -> String {
    use clap::error::ErrorKind;
    let argument = refused_argument(error);
    let named = |text: &str| match &argument {
        Some(argument) => format!("{text} {argument}"),
        None => text.to_owned(),
    };
    match error.kind() {
        ErrorKind::ValueValidation => {
            let general = named("invalid value for");
            match validator_reason(error) {
                Some(reason) if argument.as_deref().is_none_or(|name| reason.contains(name)) => {
                    reason
                }
                Some(reason) => format!("{general}: {reason}"),
                None => general,
            }
        }
        ErrorKind::InvalidValue => named("invalid value for"),
        ErrorKind::UnknownArgument => named("unexpected argument"),
        ErrorKind::InvalidSubcommand => "unrecognized subcommand".to_owned(),
        ErrorKind::NoEquals => named("an equals sign is required for"),
        ErrorKind::TooManyValues | ErrorKind::TooFewValues | ErrorKind::WrongNumberOfValues => {
            named("wrong number of values for")
        }
        ErrorKind::ArgumentConflict => named("conflicting use of"),
        ErrorKind::MissingRequiredArgument => named("missing required argument"),
        ErrorKind::MissingSubcommand | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            "missing subcommand".to_owned()
        }
        ErrorKind::InvalidUtf8 => "invalid UTF-8 in the command arguments".to_owned(),
        _ => "invalid command arguments".to_owned(),
    }
}

/// The reason one of our own value parsers gave, kept only while it does not
/// repeat the rejected value.
fn validator_reason(error: &clap::Error) -> Option<String> {
    use clap::error::{ContextKind, ContextValue};
    let reason = std::error::Error::source(error)?.to_string();
    let rejected = match error.get(ContextKind::InvalidValue) {
        Some(ContextValue::String(value)) => value.as_str(),
        _ => return None,
    };
    let repeats = !rejected.is_empty() && reason.contains(rejected);
    (!reason.is_empty() && !repeats).then_some(reason)
}

/// The name of the argument clap refused, without any value. An unknown
/// argument is the operator's own token, so it is named only when it has the
/// shape of a long option and only up to any `=`.
fn refused_argument(error: &clap::Error) -> Option<String> {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let names = match error.get(ContextKind::InvalidArg)? {
        ContextValue::String(name) => vec![name.as_str()],
        ContextValue::Strings(names) => names.iter().map(String::as_str).collect(),
        _ => return None,
    };
    let names = names
        .into_iter()
        .filter_map(|name| {
            if error.kind() == ErrorKind::UnknownArgument {
                let option = name.split('=').next()?;
                let flag = option.strip_prefix("--")?;
                let shaped = !flag.is_empty()
                    && flag.chars().all(|character| {
                        character.is_ascii_lowercase()
                            || character.is_ascii_digit()
                            || character == '-'
                    });
                shaped.then(|| option.to_owned())
            } else {
                name.split_whitespace().next().map(str::to_owned)
            }
        })
        .collect::<Vec<_>>();
    (!names.is_empty()).then(|| names.join(", "))
}

/// Write one report, envelope members first, and its trailing newline.
pub(crate) fn write(report: &Value, stdout: &mut dyn io::Write) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *stdout, &Ordered(report)).map_err(io::Error::other)?;
    writeln!(stdout)
}

/// Serialize the top-level object with the envelope members first, whatever
/// order the underlying map keeps.
struct Ordered<'a>(&'a Value);

impl Serialize for Ordered<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Value::Object(members) = self.0 else {
            return self.0.serialize(serializer);
        };
        let mut map = serializer.serialize_map(Some(members.len()))?;
        for key in HEAD {
            if let Some(value) = members.get(key) {
                map.serialize_entry(key, value)?;
            }
        }
        for (key, value) in members {
            if !HEAD.contains(&key.as_str()) {
                map.serialize_entry(key, value)?;
            }
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn validation_error(parser: fn(&str) -> Result<String, String>, value: &str) -> clap::Error {
        clap::Command::new("ctl")
            .arg(
                clap::Arg::new("reference")
                    .long("reference")
                    .value_parser(parser),
            )
            .try_get_matches_from(["ctl", "--reference", value])
            .unwrap_err()
    }

    #[test]
    fn a_reason_that_does_not_name_the_argument_is_prefixed_with_it() {
        let port = |value: &str| {
            clap::Command::new("ctl")
                .arg(
                    clap::Arg::new("port")
                        .long("port")
                        .value_parser(clap::value_parser!(u16)),
                )
                .try_get_matches_from(["ctl", "--port", value])
                .unwrap_err()
        };
        assert_eq!(
            usage_message(&port("x1")),
            "invalid value for --port: invalid digit found in string"
        );
        assert_eq!(usage_message(&port("70000")), "invalid value for --port");
    }

    #[test]
    fn a_validator_reason_is_the_message_unless_it_repeats_the_value() {
        let empty = validation_error(|_| Err("--reference must not be empty".to_owned()), "");
        assert_eq!(usage_message(&empty), "--reference must not be empty");
        let control = validation_error(
            |_| Err("--reference must not contain control characters".to_owned()),
            "change\n42",
        );
        assert_eq!(
            usage_message(&control),
            "--reference must not contain control characters"
        );
        let echoing = validation_error(
            |value| Err(format!("--reference refused {value}")),
            "sentinel-7f3a9c",
        );
        assert_eq!(usage_message(&echoing), "invalid value for --reference");
    }

    #[test]
    fn a_report_opens_with_ok_command_and_status_in_that_order() {
        let mut out = Vec::new();
        write(
            &json!({"apiVersion": "v", "status": "complete", "command": "check", "ok": true}),
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with(
                "{\n  \"ok\": true,\n  \"command\": \"check\",\n  \"status\": \"complete\",\n  \"apiVersion\""
            ),
            "{text}"
        );
    }

    #[test]
    fn failure_status_follows_the_exit_class() {
        assert_eq!(failure_status(1), "domain-refusal");
        assert_eq!(failure_status(USAGE_EXIT), "usage-error");
        assert_eq!(
            failure_status(OPERATIONAL_FAILURE_EXIT),
            "operational-failure"
        );
    }
}

pub(crate) const REPORT_API_VERSION: &str = "id.registrystack.org/formats/casework/report/v1alpha1";
pub(crate) const REPORT_KIND: &str = "CaseworkReport";

use registry_casework_core::*;
use registry_platform_yaml::Diagnostic;
use serde::{Deserialize, Serialize as DeriveSerialize};
use std::path::PathBuf;

#[derive(Clone, Debug, DeriveSerialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReportStatus {
    Complete,
    DomainRefusal,
    UsageError,
    OperationalFailure,
}

#[derive(DeriveSerialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReportCommon {
    pub ok: bool,
    pub status: ReportStatus,
    #[cfg_attr(feature="schema",schemars(extend("const"=REPORT_API_VERSION)))]
    pub api_version: &'static str,
    #[cfg_attr(feature="schema",schemars(extend("const"=REPORT_KIND)))]
    pub kind: &'static str,
    pub diagnostics: Vec<Diagnostic>,
}

macro_rules! payload {
    ($name:ident {$($(#[$meta:meta])* $field:ident:$ty:ty),* $(,)?})=>{
        #[derive(Deserialize,DeriveSerialize)]
        #[cfg_attr(feature="schema",derive(schemars::JsonSchema))]
        #[serde(rename_all="camelCase",deny_unknown_fields)]
        pub(crate) struct $name { $($(#[$meta])*pub $field:$ty),* }
    };
}
payload!(InitData {
    created: PathBuf,
    template: String,
    next: String
});
payload!(CheckData {project:PathBuf,policy_bindings:Vec<ReviewPolicyIdentity>,files_checked:usize,network_access:bool,database_access:bool,
    #[serde(default,skip_serializing_if="Option::is_none")]runtime_config:Option<PathBuf>,
    #[serde(default,skip_serializing_if="Option::is_none")]breg_package:Option<ProducerAgreementData>});
payload!(ProducerAgreementData {
    package: PathBuf,
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Digest"))]
    package_digest: String,
    agreements: Vec<ProducerAgreement>,
    network_access: bool,
    database_access: bool
});
payload!(ProducerAgreement {
    provider_id: String,
    context_contract: ReviewContextContract,
    registry_revision: String,
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Digest"))]
    schema_digest: String
});
payload!(ExplainPolicy {
    binding: ReviewPolicyIdentity,
    purpose: ReviewPurpose,
    #[cfg_attr(
        feature = "schema",
        schemars(extend("x-registry-foreign" = "json-schema-2020-12"))
    )]
    display_schema: Value,
    #[cfg_attr(
        feature = "schema",
        schemars(extend("x-registry-foreign" = "json-schema-2020-12"))
    )]
    result_schema: Option<Value>,
    clocks: Vec<String>,
    context: ReviewContextPolicy,
    context_custody: String,
    stages: Vec<ReviewStagePolicy>,
    outcomes: Vec<ReviewOutcomePolicy>,
    routing: Vec<RoutingRule>,
    routing_fields: Vec<String>,
    dependencies: ReviewPolicyDependencies,
    retention: ReviewRetentionPolicy,
    recovery: Vec<String>,
    refusals: Vec<String>
});
payload!(ExplainStaffing {
    next: String,
    holdings: String,
    caseload: String,
    routing: String,
    clock_recompute: String
});
payload!(ExplainData {project:ProjectIdentity,review_policies:Vec<ExplainPolicy>,context_providers:Vec<ReviewContextProviderPolicy>,staffing:ExplainStaffing,authority:String});
payload!(TestData {fixtures:Vec<PathBuf>,proof_boundary:String,production_closure:bool,network_access:bool,database_access:bool});
payload!(TypesData {output:PathBuf,files:Vec<String>});
payload!(ReaderAuthority {profile:Option<String>,operation:String,source_writes:bool});
payload!(ProviderPairData {
    applied: bool,
    provider_id: String,
    description: PathBuf,
    contract: ReviewContextContract,
    registry_revision: String,
    reader_authority: ReaderAuthority,
    next: String
});
payload!(LifecycleData {#[cfg_attr(feature="schema",schemars(with="Vec<registry_casework_core::LifecycleDescription>"))]lifecycles:Vec<Value>});
payload!(PackageData {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Digest"))]
    package_digest:String,
    #[serde(default,skip_serializing_if="Option::is_none")]dry_run:Option<bool>,
    #[serde(default,skip_serializing_if="Option::is_none")]files:Option<Vec<String>>,
    #[serde(default,skip_serializing_if="Option::is_none")]output:Option<PathBuf>,
    #[serde(default,skip_serializing_if="Option::is_none")]revision:Option<String>,
    #[serde(default,skip_serializing_if="Option::is_none")]secrets_included:Option<bool>});
payload!(DoctorChecks {
    configuration: String,
    package: String,
    database: String,
    audit: String
});
payload!(DoctorData {
    runtime_config: PathBuf,
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Digest"))]
    package_digest: String,
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_casework::ActivationPlan")
    )]
    activation: Value,
    checks: DoctorChecks
});
payload!(PlanData {
    runtime_config: PathBuf,
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_casework::ActivationPlan")
    )]
    plan: Value
});
payload!(ApplyData {runtime_config:PathBuf,#[cfg_attr(feature="schema",schemars(with="registry_casework::Activation"))]activation:Value,
    schema_versions_applied:Vec<i64>,#[cfg_attr(feature="schema",schemars(with="registry_casework::ActivationEffects"))]effects:Value,single_role_statement:Option<String>});
payload!(StatusData {runtime_config:PathBuf,#[cfg_attr(feature="schema",schemars(with="registry_casework::ActivationStatus"))]activation:Value,single_role_statement:Option<String>});
#[derive(Deserialize, DeriveSerialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DevState {
    Starting,
    Ready,
    Stopping,
    Stopped,
    Failed,
}
payload!(DevClient {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    id: String,
    profile: String,
    role: CaseworkRole,
    subject: String,
    client_id_file: PathBuf,
    assertion_key_file: PathBuf
});
payload!(DevDirectory {
    revision: i64,
    teams: usize
});
payload!(DevData {state:DevState,project:PathBuf,state_file:PathBuf,operator_config:PathBuf,
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    casework_url:String,token_endpoint:String,
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    issuer:String,client_assertion_audience:String,resource:String,audience:String,journal:PathBuf,context_providers:Vec<String>,clients:Vec<DevClient>,directory:DevDirectory,
    #[serde(default,skip_serializing_if="Option::is_none")]issuer_project:Option<PathBuf>});
payload!(DevEventsData {project:PathBuf,journal:PathBuf,events:Vec<String>,truncated:bool});
payload!(DevTokenData {
    header_file: PathBuf
});
payload!(DevGrantData {
    header_file: PathBuf,
    grant_expires_at: u64
});
payload!(DevIdentityData {
    client_id: String,
    subject: String
});
payload!(UsageData {});

macro_rules! reports {
    ($($variant:ident => $name:literal : $data:ty),* $(,)?)=>{
        #[derive(DeriveSerialize)]
        #[cfg_attr(feature="schema",derive(schemars::JsonSchema))]
        #[serde(tag="command",deny_unknown_fields)]
        pub(crate) enum CliReport {$(#[serde(rename=$name)]$variant{#[serde(flatten)]common:ReportCommon,#[serde(skip_serializing_if="Option::is_none")]data:Option<$data>}),*}
        impl CliReport {
            fn assemble(command:&str,common:ReportCommon,data:Option<Value>)->anyhow::Result<Self>{
                Ok(match command {$($name=>Self::$variant{common,data:data.map(serde_json::from_value::<$data>).transpose()?},)* _=>anyhow::bail!("the CLI report command is not declared")})
            }
        }
    }
}
reports!(Init=>"init":InitData,Check=>"check":CheckData,Explain=>"explain":ExplainData,Test=>"test":TestData,Types=>"types":TypesData,ProviderPair=>"provider-pair":ProviderPairData,Lifecycle=>"lifecycle":LifecycleData,Package=>"package":PackageData,Doctor=>"doctor":DoctorData,Plan=>"plan":PlanData,Apply=>"apply":ApplyData,Status=>"status":StatusData,Dev=>"dev":DevData,DevEvents=>"dev-events":DevEventsData,DevToken=>"dev-token":DevTokenData,DevGrant=>"dev-grant":DevGrantData,DevIdentity=>"dev-identity":DevIdentityData,Usage=>"usage":UsageData);

impl CliReport {
    pub(crate) fn from_value(command: &str, value: Value) -> anyhow::Result<Self> {
        let mut fields = value
            .as_object()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("the CLI command returned no report object"))?;
        let ok = fields
            .remove("ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        fields.remove("command");
        let raw_status = fields.remove("status");
        let diagnostics = fields
            .remove("diagnostics")
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        let mut diagnostics = diagnostics.into_iter().map(diagnostic).collect::<Vec<_>>();
        if !ok && diagnostics.is_empty() {
            if let Some(refusals) = fields
                .get("activation")
                .and_then(|v| v.get("refusals"))
                .and_then(Value::as_array)
            {
                diagnostics.extend(refusals.iter().cloned().map(diagnostic));
            }
            if diagnostics.is_empty() {
                diagnostics.push(Diagnostic::error(
                    "casework.operation.refused",
                    "",
                    "the requested operation was refused",
                    "Read the command details, correct the named configuration, and try again.",
                ));
            }
        }
        let data = match command {
            "plan" => {
                let runtime = fields
                    .remove("runtimeConfig")
                    .ok_or_else(|| anyhow::anyhow!("plan report has no runtime configuration"))?;
                serde_json::json!({"runtimeConfig":runtime,"plan":fields})
            }
            "status" => {
                let runtime = fields
                    .remove("runtimeConfig")
                    .ok_or_else(|| anyhow::anyhow!("status report has no runtime configuration"))?;
                let statement = fields.remove("singleRoleStatement").unwrap_or(Value::Null);
                serde_json::json!({"runtimeConfig":runtime,"singleRoleStatement":statement,"activation":fields})
            }
            "apply" => {
                let runtime = fields
                    .remove("runtimeConfig")
                    .ok_or_else(|| anyhow::anyhow!("apply report has no runtime configuration"))?;
                let versions = fields
                    .remove("schemaVersionsApplied")
                    .ok_or_else(|| anyhow::anyhow!("apply report has no schema result"))?;
                let effects = fields
                    .remove("effects")
                    .ok_or_else(|| anyhow::anyhow!("apply report has no effects"))?;
                let statement = fields.remove("singleRoleStatement").unwrap_or(Value::Null);
                serde_json::json!({"runtimeConfig":runtime,"schemaVersionsApplied":versions,"effects":effects,"singleRoleStatement":statement,"activation":fields})
            }
            "dev" => {
                fields.insert(
                    "state".into(),
                    raw_status.ok_or_else(|| anyhow::anyhow!("dev report has no state"))?,
                );
                Value::Object(fields)
            }
            _ => Value::Object(fields),
        };
        let common = ReportCommon {
            ok,
            status: if ok {
                ReportStatus::Complete
            } else {
                ReportStatus::DomainRefusal
            },
            api_version: REPORT_API_VERSION,
            kind: REPORT_KIND,
            diagnostics,
        };
        Self::assemble(command, common, Some(data))
    }

    pub(crate) fn failure(
        command: &str,
        status: ReportStatus,
        diagnostics: Vec<Diagnostic>,
    ) -> anyhow::Result<Self> {
        Self::assemble(
            command,
            ReportCommon {
                ok: false,
                status,
                api_version: REPORT_API_VERSION,
                kind: REPORT_KIND,
                diagnostics,
            },
            None,
        )
    }
}

fn diagnostic(value: Value) -> Diagnostic {
    if let Ok(diagnostic) = serde_json::from_value::<Diagnostic>(value.clone()) {
        return diagnostic;
    }
    operator_refusal_diagnostic(
        value["code"]
            .as_str()
            .unwrap_or("casework.operation.refused"),
        value["path"].as_str().unwrap_or(""),
        value["message"]
            .as_str()
            .unwrap_or("the requested operation was refused"),
    )
}

pub(crate) fn operator_refusal_diagnostic(code: &str, path: &str, message: &str) -> Diagnostic {
    Diagnostic::error(code,path,message,match code {
        "casework.activation.schema-newer"=>"Use a Casework release that supports this database schema; preserve the database until then.",
        "casework.activation.already-active"=>"The package is already active. Check caseworkctl status before choosing a different package.",
        "casework.activation.retired-schema"=>"Preserve the old database with the release that wrote it and configure a fresh database.",
        "casework.activation.beta-schema"=>"This release supports fresh installs only. Preserve the old database with the release that wrote it, create a fresh database, and apply the package.",
        _=>"Follow the named refusal, then run caseworkctl plan --runtime-config FILE before applying.",
    })
}

#[cfg(all(test, feature = "schema"))]
mod typed_report_tests {
    use super::*;
    #[test]
    fn authored_command_reports_match_the_owning_schema() {
        let directory = crate::canonical_tempdir();
        let project = directory.path().join("review");
        let documents = crate::schema::report_documents().unwrap();
        let schema: Value = serde_json::from_str(&documents["report.schema.json"]).unwrap();
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap();
        let reports = [
            (
                "init",
                crate::project::init(&project, "standalone-decision").unwrap(),
            ),
            (
                "check",
                crate::project::check(&project, false, false).unwrap(),
            ),
            ("explain", crate::project::explain(&project).unwrap()),
            ("test", crate::project::test(&project, false).unwrap()),
            (
                "types",
                crate::project_types::generate(&project, &directory.path().join("types")).unwrap(),
            ),
            (
                "package",
                crate::project::package_dry_run(&project, None).unwrap(),
            ),
            (
                "lifecycle",
                serde_json::json!({"ok":true,"lifecycles":[review_lifecycle()]}),
            ),
        ];
        for (command, raw) in reports {
            let report = CliReport::from_value(command, raw)
                .unwrap_or_else(|error| panic!("{command} report: {error}"));
            let value = serde_json::to_value(report).unwrap();
            if let Err(errors) = validator.validate(&value) {
                panic!(
                    "{command} schema mismatch at {}",
                    errors
                        .map(|error| error.instance_path.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            assert_eq!(value["apiVersion"], REPORT_API_VERSION);
            assert_eq!(value["kind"], REPORT_KIND);
        }
    }
    #[test]
    fn typed_report_rejects_unmodelled_payload_instead_of_losing_it() {
        assert!(CliReport::from_value(
            "types",
            serde_json::json!({"ok":true,"output":"types","files":[],"unexpected":true})
        )
        .is_err());
    }
}

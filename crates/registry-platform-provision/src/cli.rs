// SPDX-License-Identifier: Apache-2.0
//! The `provision` command every database-backed tool shares: its arguments,
//! its runner and its report.
//!
//! A product supplies a loader that turns its runtime file into a
//! [`ProvisionInput`]. The runner takes role and database names and passwords
//! from the two product URLs, so each credential is stored once. It never
//! prints a password, a verifier or a URL.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use registry_platform_yaml::Diagnostic;
use serde::Serialize;
use tokio_postgres::config::Host;
use tokio_postgres::Config;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    admin_config, execute_recording, render_script, verify_logins, AdminConfig, AdminConfigError,
    Failure, Mode, Needs, Outcome, Plan, PlanError, ProductDatabase, ProvisionError,
    ProvisionTarget, RoleCredential, Scope, StatementOutcome,
};

pub const REPORT_API_VERSION: &str =
    "id.registrystack.org/formats/platform/cli-database-provision-report/v1alpha1";
pub const REPORT_KIND: &str = "PlatformCliDatabaseProvisionReport";

/// How the command writes its result. A tool maps its own global `--format`
/// (`human | json`) onto this.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
}

/// The flags of `<tool> provision`. The output format is the tool's own global
/// `--format` flag, passed to [`run_provision`].
#[derive(clap::Args, Debug, Clone)]
pub struct ProvisionArgs {
    /// Runtime configuration file, the one `apply` reads
    #[arg(long, value_name = "FILE")]
    pub runtime_config: PathBuf,
    /// File holding the administrator PostgreSQL URL
    #[arg(
        long,
        value_name = "ADMIN_URL_FILE",
        conflicts_with_all = ["admin_url_env", "print_sql"],
        required_unless_present_any = ["admin_url_env", "print_sql"]
    )]
    pub admin_url_file: Option<PathBuf>,
    /// Name of the environment variable holding the administrator PostgreSQL URL
    #[arg(
        long,
        value_name = "ADMIN_URL_ENV",
        conflicts_with = "print_sql",
        required_unless_present_any = ["admin_url_file", "print_sql"]
    )]
    pub admin_url_env: Option<String>,
    /// Print the SQL script and connect to nothing
    #[arg(long)]
    pub print_sql: bool,
}

/// What a product's loader hands the runner. A loader refuses with one
/// diagnostic, boxed because the diagnostic is large.
pub struct ProvisionInput {
    pub product: ProductDatabase,
    pub migration_url: Zeroizing<String>,
    pub runtime_url: Zeroizing<String>,
    /// The CA behind `database.caBundleRef`, for the administrator connection.
    pub ca_pem: Option<Vec<u8>>,
}

/// Result class of a run, as in every other verb's report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReportStatus {
    Complete,
    DomainRefusal,
    UsageError,
    OperationalFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum RoleMode {
    Split,
    Single,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReportScope {
    Server,
    Database,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ReportNeeds {
    #[serde(rename = "createrole")]
    CreateRole,
    #[serde(rename = "createdb")]
    CreateDb,
    #[serde(rename = "database-owner")]
    DatabaseOwner,
    #[serde(rename = "superuser")]
    Superuser,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReportOutcome {
    Created,
    Present,
    Applied,
    NotRun,
}

/// One planned statement. `sql` is the printable form, never a password or a
/// verifier.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct ReportStatement {
    pub step: String,
    pub scope: ReportScope,
    pub needs: ReportNeeds,
    /// `not-run` for a statement the run did not reach, the one that failed
    /// included. After `platform.provision.effect-unconfirmed` the statement
    /// the diagnostic names was sent and may have taken effect.
    pub outcome: ReportOutcome,
    pub sql: String,
}

/// Machine-readable result of `provision` for every database-backed tool.
/// The identity members are absent when the run stopped before the product's
/// runtime file could name them.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct PlatformCliDatabaseProvisionReport {
    pub ok: bool,
    pub command: String,
    pub status: ReportStatus,
    pub api_version: String,
    pub kind: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// Whether a statement could have been sent to the server: false for a
    /// print-mode run and for a run that stopped before the first statement.
    /// True whenever a statement is listed as run.
    pub executed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_mode: Option<RoleMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migration_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_role: Option<String>,
    pub statements: Vec<ReportStatement>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Runs the plan and then checks that each product role can log in. A test
/// replaces it, so the report logic needs no server.
type Backend<'a> = &'a dyn Fn(&AdminConfig, &Plan, &ProvisionTarget) -> Result<Outcome, Failure>;

/// The most bytes read from the administrator URL file.
const MAXIMUM_ADMIN_URL_BYTES: u64 = 8192;
const DEFAULT_PORT: u16 = 5432;

/// A product URL reduced to what provisioning takes from it.
struct Endpoint {
    user: String,
    password: Zeroizing<String>,
    database: String,
    host: String,
    port: u16,
}

/// The query keys that would change which server, role or database a URL names.
const ENDPOINT_QUERY_KEYS: [&str; 6] = ["host", "hostaddr", "port", "user", "password", "dbname"];

/// Reads the role, password, database and endpoint out of a product URL.
/// The query is dropped after the keys that override the endpoint are refused:
/// the product's own reader validates the rest (`sslmode` and so on).
fn parse_endpoint(url: &str) -> Option<Endpoint> {
    let parsed = Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.cannot_be_a_base()
        || parsed.fragment().is_some()
        || parsed
            .query_pairs()
            .any(|(key, _)| ENDPOINT_QUERY_KEYS.contains(&key.as_ref()))
    {
        return None;
    }
    let mut bare = parsed;
    bare.set_query(None);
    let config = Config::from_str(bare.as_str()).ok()?;
    let host = match config.get_hosts() {
        [Host::Tcp(host)] => host.clone(),
        _ => return None,
    };
    let user = config.get_user().filter(|user| !user.is_empty())?;
    let password = config
        .get_password()
        .filter(|password| !password.is_empty())
        .and_then(|password| String::from_utf8(password.to_vec()).ok())?;
    let database = config.get_dbname().filter(|name| !name.is_empty())?;
    Some(Endpoint {
        user: user.to_owned(),
        password: Zeroizing::new(password),
        database: database.to_owned(),
        host,
        port: config.get_ports().first().copied().unwrap_or(DEFAULT_PORT),
    })
}

/// How a run ended before any report could be written.
struct Refusal {
    status: ReportStatus,
    diagnostic: Box<Diagnostic>,
}

fn refuse(
    status: ReportStatus,
    code: &str,
    path: &str,
    message: impl Into<String>,
    action: impl Into<String>,
) -> Refusal {
    Refusal {
        status,
        diagnostic: Box::new(Diagnostic::error(code, path, message, action)),
    }
}

fn target_invalid_with(message: &str, action: &str) -> Refusal {
    refuse(
        ReportStatus::UsageError,
        "platform.provision.target-invalid",
        "",
        message,
        action,
    )
}

fn target_invalid(message: &str) -> Refusal {
    target_invalid_with(
        message,
        "Correct database.migrationUrlRef and database.runtimeUrlRef in the runtime file, then \
         run provision again.",
    )
}

/// A name the plan refuses. The action names the URL member to correct and
/// never quotes its value.
fn plan_refusal(error: &PlanError) -> Refusal {
    let rule = "A role name must not hold a control character, a backslash or a bidirectional \
                formatting character, and must not be public, none or start with pg_.";
    let action = match error {
        PlanError::InvalidName {
            what: "database name",
        } => "Change the database name, the path of database.migrationUrlRef and \
              database.runtimeUrlRef. It must not hold a control character, a backslash, a \
              bidirectional formatting character or =, must not start with postgresql:// or \
              postgres://, and must not be postgres, template0 or template1."
            .to_owned(),
        PlanError::InvalidName {
            what: "migration role name",
        } => format!("Change the user in the migration URL (database.migrationUrlRef). {rule}"),
        PlanError::InvalidName {
            what: "runtime role name",
        } => format!("Change the user in the runtime URL (database.runtimeUrlRef). {rule}"),
        _ => "Correct database.migrationUrlRef and database.runtimeUrlRef in the runtime file, \
             then run provision again."
            .to_owned(),
    };
    target_invalid_with(&error.to_string(), &action)
}

fn target_mismatch(message: String) -> Refusal {
    refuse(
        ReportStatus::DomainRefusal,
        "platform.provision.target-mismatch",
        "",
        message,
        "Point the URLs at one server and one database, then run provision again.",
    )
}

/// The first of host, port and database that two endpoints disagree on.
fn first_difference(left: &Endpoint, right: &Endpoint) -> Option<&'static str> {
    if !left.host.eq_ignore_ascii_case(&right.host) {
        Some("host")
    } else if left.port != right.port {
        Some("port")
    } else if left.database != right.database {
        Some("database")
    } else {
        None
    }
}

fn read_admin_url(args: &ProvisionArgs) -> Result<Zeroizing<String>, Refusal> {
    let unusable = |message: String, action: &str| {
        refuse(
            ReportStatus::UsageError,
            "platform.provision.admin-url-invalid",
            "",
            message,
            action,
        )
    };
    let raw = match (&args.admin_url_file, &args.admin_url_env) {
        (Some(path), None) => {
            // The check before the open keeps a named pipe from blocking it.
            let read = std::fs::metadata(path).and_then(|metadata| {
                if metadata.is_file() {
                    std::fs::File::open(path)
                } else {
                    Err(std::io::Error::other("not a regular file"))
                }
            });
            let read = read.and_then(|file| {
                if !file.metadata()?.is_file() {
                    return Err(std::io::Error::other("not a regular file"));
                }
                let mut text = String::new();
                file.take(MAXIMUM_ADMIN_URL_BYTES + 1)
                    .read_to_string(&mut text)
                    .map(|_| text)
            });
            match read {
                Ok(text) if text.len() as u64 <= MAXIMUM_ADMIN_URL_BYTES => Zeroizing::new(text),
                Ok(_) => {
                    return Err(unusable(
                        "the administrator URL file is larger than 8 KiB".to_owned(),
                        "Put only the administrator PostgreSQL URL in the file.",
                    ))
                }
                Err(_) => {
                    return Err(unusable(
                        "the administrator URL file could not be read".to_owned(),
                        "Check that --admin-url-file names a readable file holding the \
                         administrator PostgreSQL URL.",
                    ))
                }
            }
        }
        (None, Some(name)) => match std::env::var(name) {
            Ok(value) => Zeroizing::new(value),
            Err(_) => {
                return Err(unusable(
                    format!("the environment variable {name} is not set or is not UTF-8 text"),
                    "Export the administrator PostgreSQL URL in the variable that \
                     --admin-url-env names.",
                ))
            }
        },
        _ => {
            return Err(unusable(
                "exactly one administrator URL source is required".to_owned(),
                "Pass --admin-url-file or --admin-url-env, or --print-sql.",
            ))
        }
    };
    let url = raw.trim();
    if url.is_empty() {
        return Err(unusable(
            "the administrator URL is empty".to_owned(),
            "Put the administrator PostgreSQL URL in the file or variable.",
        ));
    }
    Ok(Zeroizing::new(url.to_owned()))
}

fn admin_refusal(error: AdminConfigError) -> Refusal {
    let url_rule = error.code() == "platform.provision.admin-url-invalid";
    refuse(
        if url_rule {
            ReportStatus::UsageError
        } else {
            ReportStatus::DomainRefusal
        },
        error.code(),
        "",
        error.to_string(),
        if url_rule {
            "Correct the administrator URL, then run provision again."
        } else {
            "Correct database.caBundleRef in the runtime file, or install the CA in the system \
             trust store, then run provision again."
        },
    )
}

/// What the report says about a refusal from the executor, with the exit
/// class of its code.
fn execution_refusal(tool: &str, error: &ProvisionError) -> Refusal {
    use ProvisionError as E;
    let (status, action) = match error {
        E::AdminConnectFailed { sqlstate } if sqlstate.as_deref() == Some("3D000") => (
            ReportStatus::OperationalFailure,
            "The database the administrator URL names does not exist. Name one that does, such \
             as postgres, then run provision again."
                .to_owned(),
        ),
        E::AdminConnectFailed { .. } => (
            ReportStatus::OperationalFailure,
            "Check the host, port, credentials and TLS certificate of the administrator URL, \
             then run provision again."
                .to_owned(),
        ),
        E::DatabaseConnectFailed { .. } => (
            ReportStatus::OperationalFailure,
            "The administrator opened a session on the server, and the statements listed as run \
             took effect. Check that the administrator role's CONNECTION LIMIT leaves room for a \
             second session and that pg_hba.conf admits it to the new database, then run \
             provision again."
                .to_owned(),
        ),
        E::UnsupportedPostgres => (
            ReportStatus::DomainRefusal,
            "Provision a PostgreSQL 17 or newer server, then run provision again.".to_owned(),
        ),
        E::StatementNeedsPrivilege { .. } => (
            ReportStatus::DomainRefusal,
            format!(
                "run this statement as a role that has it, or run \"{tool} provision \
                 --print-sql\" and give the script to the database administrator, then run \
                 provision again"
            ),
        ),
        E::RoleAttributesDiffer { .. } => (
            ReportStatus::DomainRefusal,
            "Use another role name in the product URLs, or correct the role as an administrator, \
             then run provision again."
                .to_owned(),
        ),
        E::RoleSettingsDiffer { .. } => (
            ReportStatus::DomainRefusal,
            "Use another role name in the product URLs, or reset the role's role, search_path \
             and session_authorization defaults as an administrator, then run provision again."
                .to_owned(),
        ),
        E::RoleMembershipDiffers { .. } => (
            ReportStatus::DomainRefusal,
            "Use another role name in the product URLs, or revoke the role's memberships as an \
             administrator, then run provision again."
                .to_owned(),
        ),
        E::DatabaseIsTemplate { .. } => (
            ReportStatus::DomainRefusal,
            "Use another database name in the product URLs, then run provision again.".to_owned(),
        ),
        E::ExtensionIncomplete { .. } => (
            ReportStatus::DomainRefusal,
            "As a superuser, run every statement of the extension.postgis step, which \
             provision --print-sql prints, after dropping a PostGIS installed in another \
             schema, then run provision again."
                .to_owned(),
        ),
        E::DatabaseOwnerDiffers { .. } => (
            ReportStatus::DomainRefusal,
            "Use another database name, or run provision as the database owner or a role that \
             can act as it."
                .to_owned(),
        ),
        E::SchemaOwnerDiffers { .. } => (
            ReportStatus::DomainRefusal,
            "Make the migration role the owner of the schema as an administrator, or use \
             another database, then run provision again."
                .to_owned(),
        ),
        E::ExtensionTooOld { .. } => (
            ReportStatus::DomainRefusal,
            "Upgrade the extension as a superuser, then run provision again.".to_owned(),
        ),
        E::RoleLoginFailed { sqlstate, .. } => match sqlstate.as_deref() {
            Some("28P01") => (
                ReportStatus::DomainRefusal,
                "The role exists with a different password. Set its password to the one in \
                 its product URL as an administrator, or correct the URL, then run provision \
                 again."
                    .to_owned(),
            ),
            Some("28000") => (
                ReportStatus::DomainRefusal,
                "The server refused the role. Check that the role can log in and that \
                 pg_hba.conf lets it connect over TLS from this host, then run provision \
                 again."
                    .to_owned(),
            ),
            Some("53300") => (
                ReportStatus::OperationalFailure,
                "The role or the server has reached its connection limit. Raise the role's \
                 CONNECTION LIMIT or free a connection, then run provision again."
                    .to_owned(),
            ),
            Some(_) => (
                ReportStatus::DomainRefusal,
                "Read the PostgreSQL server log for the refused login, fix the cause, then run \
                 provision again."
                    .to_owned(),
            ),
            None => (
                ReportStatus::OperationalFailure,
                "Check that the server accepts connections from this host, then run provision \
                 again."
                    .to_owned(),
            ),
        },
        E::EffectUnconfirmed { .. } => (
            ReportStatus::OperationalFailure,
            "Run provision again.".to_owned(),
        ),
        E::StatementFailed { .. } => (
            ReportStatus::OperationalFailure,
            "Read the PostgreSQL server log for that statement, fix the cause, then run \
             provision again."
                .to_owned(),
        ),
    };
    refuse(
        status,
        error.code(),
        error.step().unwrap_or(""),
        error.to_string(),
        action,
    )
}

const fn exit_code(status: ReportStatus) -> u8 {
    match status {
        ReportStatus::Complete => 0,
        ReportStatus::DomainRefusal => 1,
        ReportStatus::UsageError => 2,
        ReportStatus::OperationalFailure => 3,
    }
}

fn report_scope(scope: Scope) -> ReportScope {
    match scope {
        Scope::Server => ReportScope::Server,
        Scope::Database => ReportScope::Database,
    }
}

fn report_needs(needs: Needs) -> ReportNeeds {
    match needs {
        Needs::CreateRole => ReportNeeds::CreateRole,
        Needs::CreateDb => ReportNeeds::CreateDb,
        Needs::DatabaseOwner => ReportNeeds::DatabaseOwner,
        Needs::Superuser => ReportNeeds::Superuser,
    }
}

fn report_outcome(outcome: StatementOutcome) -> ReportOutcome {
    match outcome {
        StatementOutcome::Created => ReportOutcome::Created,
        StatementOutcome::Present => ReportOutcome::Present,
        StatementOutcome::Applied => ReportOutcome::Applied,
    }
}

fn outcome_word(outcome: ReportOutcome) -> &'static str {
    match outcome {
        ReportOutcome::Created => "created",
        ReportOutcome::Present => "present",
        ReportOutcome::Applied => "applied",
        ReportOutcome::NotRun => "not-run",
    }
}

/// The plan's statements with the outcome of each statement the executor
/// reached, and `not-run` for the rest.
fn report_statements(
    plan: &Plan,
    reached: &[(&'static str, StatementOutcome)],
) -> Vec<ReportStatement> {
    plan.statements()
        .iter()
        .enumerate()
        .map(|(index, statement)| ReportStatement {
            step: statement.step.to_owned(),
            scope: report_scope(statement.scope),
            needs: report_needs(statement.needs),
            outcome: reached
                .get(index)
                .map_or(ReportOutcome::NotRun, |(_, outcome)| {
                    report_outcome(*outcome)
                }),
            sql: statement.printable.clone(),
        })
        .collect()
}

/// Writes the finished report and returns the exit code.
struct Output<'a> {
    format: OutputFormat,
    version: &'static str,
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
}

impl Output<'_> {
    /// Last resort when the streams themselves fail: the exit code carries it.
    fn write_failed(&mut self, ok: bool) -> u8 {
        if ok {
            0
        } else {
            let _ = writeln!(self.stderr, "provision could not write its output");
            3
        }
    }

    fn json(&mut self, report: &PlatformCliDatabaseProvisionReport) -> bool {
        let Ok(value) = serde_json::to_value(report) else {
            return false;
        };
        let Ok(envelope) = registry_cli_report::Report::new(&value, self.version) else {
            return false;
        };
        serde_json::to_writer_pretty(&mut *self.stdout, &envelope).is_ok()
            && writeln!(self.stdout).is_ok()
    }

    /// A refusal: the JSON report on stdout, or the diagnostics on stderr.
    fn refusal(&mut self, report: &PlatformCliDatabaseProvisionReport) -> u8 {
        let written = match self.format {
            OutputFormat::Json => self.json(report),
            OutputFormat::Human => {
                // A run that stopped part-way shows what it had already done.
                let ran = report
                    .statements
                    .iter()
                    .filter(|statement| statement.outcome != ReportOutcome::NotRun)
                    .all(|statement| {
                        writeln!(
                            self.stderr,
                            "{}  {}",
                            outcome_word(statement.outcome),
                            statement.step
                        )
                        .is_ok()
                    });
                ran && report
                    .diagnostics
                    .iter()
                    .all(|diagnostic| write!(self.stderr, "{}", diagnostic.render_human()).is_ok())
            }
        };
        let exit = exit_code(report.status);
        match self.write_failed(written) {
            0 => exit,
            failed => failed,
        }
    }
}

// The runner's inputs are independent (identity, arguments, format, loader,
// backend, two streams) and each is a test seam, so they stay positional.
#[allow(clippy::too_many_arguments)]
fn run_with(
    tool: &'static str,
    version: &'static str,
    args: &ProvisionArgs,
    format: OutputFormat,
    load: impl FnOnce(&Path) -> Result<ProvisionInput, Box<Diagnostic>>,
    backend: Backend<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let mut output = Output {
        format,
        version,
        stdout,
        stderr,
    };
    let mut report = PlatformCliDatabaseProvisionReport {
        ok: false,
        command: "provision".to_owned(),
        status: ReportStatus::DomainRefusal,
        api_version: REPORT_API_VERSION.to_owned(),
        kind: REPORT_KIND.to_owned(),
        version: version.to_owned(),
        product: None,
        executed: false,
        role_mode: None,
        database: None,
        migration_role: None,
        runtime_role: None,
        statements: Vec::new(),
        diagnostics: Vec::new(),
    };
    let refused = |report: &mut PlatformCliDatabaseProvisionReport, refusal: Refusal| {
        report.status = refusal.status;
        report.diagnostics = vec![*refusal.diagnostic];
    };

    let input = match load(&args.runtime_config) {
        Ok(input) => input,
        Err(diagnostic) => {
            refused(
                &mut report,
                Refusal {
                    status: ReportStatus::DomainRefusal,
                    diagnostic,
                },
            );
            return output.refusal(&report);
        }
    };
    report.product = Some(input.product.product.to_owned());
    let (Some(migration), Some(runtime)) = (
        parse_endpoint(&input.migration_url),
        parse_endpoint(&input.runtime_url),
    ) else {
        refused(
            &mut report,
            target_invalid(
                "the migration and runtime URLs must each be a postgres:// URL with a host, \
                 role, password and database, and no host, port, user, password or dbname \
                 in the query",
            ),
        );
        return output.refusal(&report);
    };
    report.database = Some(migration.database.clone());
    report.migration_role = Some(migration.user.clone());
    report.runtime_role = Some(runtime.user.clone());
    report.role_mode = Some(if migration.user == runtime.user {
        RoleMode::Single
    } else {
        RoleMode::Split
    });
    if let Some(what) = first_difference(&migration, &runtime) {
        refused(
            &mut report,
            target_mismatch(format!(
                "the migration and runtime URLs name different {what}s"
            )),
        );
        return output.refusal(&report);
    }

    let target = ProvisionTarget {
        database: migration.database.clone(),
        migration: RoleCredential::new(migration.user.as_str(), migration.password.as_str()),
        runtime: RoleCredential::new(runtime.user.as_str(), runtime.password.as_str()),
    };
    let plan = match crate::plan(&input.product, &target) {
        Ok(plan) => plan,
        Err(error) => {
            // A refused name is not repeated in the report.
            report.role_mode = None;
            report.database = None;
            report.migration_role = None;
            report.runtime_role = None;
            refused(&mut report, plan_refusal(&error));
            return output.refusal(&report);
        }
    };
    report.statements = report_statements(&plan, &[]);

    if args.print_sql {
        report.ok = true;
        report.status = ReportStatus::Complete;
        let written = match format {
            OutputFormat::Human => output
                .stdout
                .write_all(render_script(&plan).as_bytes())
                .is_ok(),
            OutputFormat::Json => output.json(&report),
        };
        return output.write_failed(written);
    }

    let admin_url = match read_admin_url(args) {
        Ok(url) => url,
        Err(refusal) => {
            refused(&mut report, refusal);
            return output.refusal(&report);
        }
    };
    let admin = match admin_config(&admin_url, input.ca_pem.as_deref()) {
        Ok(admin) => admin,
        Err(error) => {
            refused(&mut report, admin_refusal(error));
            return output.refusal(&report);
        }
    };
    let admin_endpoint = Endpoint {
        user: admin.user().to_owned(),
        password: Zeroizing::new(String::new()),
        database: migration.database.clone(),
        host: admin.host().to_owned(),
        port: admin.port(),
    };
    if let Some(what) = first_difference(&admin_endpoint, &migration) {
        refused(
            &mut report,
            target_mismatch(format!(
                "the administrator URL names a different {what} than the product URLs"
            )),
        );
        return output.refusal(&report);
    }

    if admin.database() == target.database {
        refused(
            &mut report,
            target_invalid_with(
                "the administrator URL names the product database, which provision creates",
                "Point the administrator URL at the postgres maintenance database or another \
                 existing database, then run provision again.",
            ),
        );
        return output.refusal(&report);
    }

    match backend(&admin, &plan, &target) {
        Ok(outcome) => {
            report.executed = true;
            report.ok = true;
            report.status = ReportStatus::Complete;
            report.statements = report_statements(&plan, &outcome.statements);
            let written = match format {
                OutputFormat::Json => output.json(&report),
                OutputFormat::Human => write_summary(output.stdout, &report, outcome.single_role),
            };
            output.write_failed(written)
        }
        Err(failure) => {
            report.executed =
                !failure.reached.is_empty() || failure.error.may_have_run_statements();
            report.statements = report_statements(&plan, &failure.reached);
            refused(&mut report, execution_refusal(tool, &failure.error));
            output.refusal(&report)
        }
    }
}

/// One line per statement, then the roles and the database.
fn write_summary(
    out: &mut dyn Write,
    report: &PlatformCliDatabaseProvisionReport,
    single_role: bool,
) -> bool {
    let mut text = String::new();
    for statement in &report.statements {
        text.push_str(&format!(
            "{}  {}\n",
            outcome_word(statement.outcome),
            statement.step
        ));
    }
    let name = |value: &Option<String>| value.clone().unwrap_or_default();
    text.push_str(&format!("database: {}\n", name(&report.database)));
    if single_role {
        text.push_str(&format!("role: {}\n", name(&report.migration_role)));
        text.push_str(registry_platform_activation::SINGLE_ROLE_STATEMENT);
        text.push('\n');
    } else {
        text.push_str(&format!(
            "migration role: {}\n",
            name(&report.migration_role)
        ));
        text.push_str(&format!("runtime role: {}\n", name(&report.runtime_role)));
    }
    out.write_all(text.as_bytes()).is_ok()
}

/// Converges the server, then opens a session as each product role.
fn server_backend(
    runtime: &tokio::runtime::Runtime,
) -> impl Fn(&AdminConfig, &Plan, &ProvisionTarget) -> Result<Outcome, Failure> + '_ {
    move |admin, plan, target| {
        runtime.block_on(async {
            let outcome = execute_recording(admin, plan, Mode::Converge).await?;
            match verify_logins(admin, target).await {
                Ok(()) => Ok(outcome),
                Err(error) => Err(Failure {
                    error,
                    reached: outcome.statements,
                }),
            }
        })
    }
}

/// Runs `<tool> provision`. `version` is the tool's own build version and goes
/// into the report. The exit code is 0 on success, 1 for a refusal, 2 for a
/// usage error and 3 for an operational failure.
pub fn run_provision(
    tool: &'static str,
    version: &'static str,
    args: &ProvisionArgs,
    format: OutputFormat,
    load: impl FnOnce(&Path) -> Result<ProvisionInput, Box<Diagnostic>>,
) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("{tool} provision could not start its async runtime");
            return ExitCode::from(3);
        }
    };
    let exit = run_with(
        tool,
        version,
        args,
        format,
        load,
        &server_backend(&runtime),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    ExitCode::from(exit)
}

/// The JSON Schema of [`PlatformCliDatabaseProvisionReport`].
#[cfg(feature = "schema")]
pub fn report_schema_document() -> Result<String, serde_json::Error> {
    const SCHEMA_ID: &str = "https://id.registrystack.org/schemas/platform/cli-database-provision-report/cli-database-provision-report.v1alpha1.schema.json";
    let mut settings = schemars::generate::SchemaSettings::draft2020_12();
    settings.contract = schemars::generate::Contract::Serialize;
    let schema = settings
        .into_generator()
        .into_root_schema_for::<PlatformCliDatabaseProvisionReport>();
    let mut value = serde_json::to_value(schema)?;
    value["$id"] = serde_json::Value::String(SCHEMA_ID.to_owned());
    value["title"] =
        serde_json::Value::String("Registry Stack CLI database provision report".to_owned());
    value["properties"]["apiVersion"] = serde_json::json!({"const": REPORT_API_VERSION});
    value["properties"]["kind"] = serde_json::json!({"const": REPORT_KIND});
    value["properties"]["command"] = serde_json::json!({"const": "provision"});
    close_direct_output_structs(&mut value);
    state_native_integer_bounds(&mut value);
    Ok(serde_json::to_string_pretty(&value)? + "\n")
}

/// Close the structs this module emits directly and the shared diagnostic DTOs.
#[cfg(feature = "schema")]
fn close_direct_output_structs(schema: &mut serde_json::Value) {
    use serde_json::Value;
    fn close(node: &mut Value) {
        let Value::Object(object) = node else {
            return;
        };
        if object.get("type") == Some(&Value::String("object".to_owned()))
            && object.contains_key("properties")
            && !object.contains_key("additionalProperties")
        {
            object.insert("additionalProperties".to_owned(), Value::Bool(false));
        }
    }
    if let Some(Value::Object(definitions)) = schema.get_mut("$defs") {
        definitions.values_mut().for_each(close);
    }
    close(schema);
}

/// State the native range of the `usize` positions a diagnostic's source carries.
#[cfg(feature = "schema")]
fn state_native_integer_bounds(schema: &mut serde_json::Value) {
    use serde_json::Value;
    match schema {
        Value::Object(object) => {
            let bounds = object
                .get("format")
                .and_then(Value::as_str)
                .and_then(native_integer_bounds);
            if let Some((minimum, maximum)) = bounds {
                object.entry("minimum").or_insert(minimum);
                object.entry("maximum").or_insert(maximum);
            }
            object.values_mut().for_each(state_native_integer_bounds);
        }
        Value::Array(items) => items.iter_mut().for_each(state_native_integer_bounds),
        _ => {}
    }
}

#[cfg(feature = "schema")]
fn native_integer_bounds(format: &str) -> Option<(serde_json::Value, serde_json::Value)> {
    use serde_json::Value;
    match format {
        "uint" => Some((Value::from(0), Value::from(usize::MAX as u64))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SchemaLayout, Spatial};
    use clap::Parser;
    use serde_json::Value;

    const MIGRATION_PASSWORD: &str = "mig-secret-7f3a";
    const RUNTIME_PASSWORD: &str = "run-secret-91bc";
    const ADMIN_PASSWORD: &str = "adm-secret-55de";

    #[derive(Parser)]
    struct Harness {
        #[command(flatten)]
        args: ProvisionArgs,
    }

    /// Splits a test's `--format human|json` off the verb's own flags, as the
    /// tool's global flag does.
    pub(super) fn split_format<'a>(arguments: &[&'a str]) -> (Vec<&'a str>, OutputFormat) {
        let mut rest = Vec::new();
        let mut format = OutputFormat::Human;
        let mut iter = arguments.iter().copied();
        while let Some(argument) = iter.next() {
            if argument == "--format" {
                format = match iter.next() {
                    Some("json") => OutputFormat::Json,
                    Some("human") => OutputFormat::Human,
                    other => panic!("test format {other:?} is not human or json"),
                };
            } else {
                rest.push(argument);
            }
        }
        (rest, format)
    }

    fn parse(arguments: &[&str]) -> Result<ProvisionArgs, clap::Error> {
        Harness::try_parse_from(std::iter::once("tool").chain(arguments.iter().copied()))
            .map(|harness| harness.args)
    }

    fn input_with(migration: &str, runtime: &str, product: ProductDatabase) -> ProvisionInput {
        ProvisionInput {
            product,
            migration_url: Zeroizing::new(migration.to_owned()),
            runtime_url: Zeroizing::new(runtime.to_owned()),
            ca_pem: None,
        }
    }

    fn owned_product() -> ProductDatabase {
        ProductDatabase {
            product: "casework",
            layout: SchemaLayout::Owned(vec!["casework".to_owned()]),
            btree_gist: true,
            spatial: None,
        }
    }

    fn split_input() -> ProvisionInput {
        input_with(
            &format!("postgres://app_migration:{MIGRATION_PASSWORD}@db.example:5432/app?sslmode=verify-full"),
            &format!("postgres://app_runtime:{RUNTIME_PASSWORD}@db.example:5432/app?sslmode=verify-full"),
            owned_product(),
        )
    }

    fn admin_url(host: &str, port: u16) -> String {
        format!("postgres://admin:{ADMIN_PASSWORD}@{host}:{port}/postgres?sslmode=verify-full")
    }

    struct Run {
        exit: u8,
        stdout: String,
        stderr: String,
    }

    impl Run {
        fn json(&self) -> Value {
            serde_json::from_str(&self.stdout).expect("stdout is one JSON report")
        }
        fn all_output(&self) -> String {
            format!("{}{}", self.stdout, self.stderr)
        }
    }

    fn execute_run(
        arguments: &[&str],
        admin_file: Option<&str>,
        input: Result<ProvisionInput, Box<Diagnostic>>,
        backend: Backend<'_>,
    ) -> Run {
        let directory = tempfile::tempdir().expect("scratch directory");
        let (arguments, format) = split_format(arguments);
        let mut full: Vec<String> = arguments.iter().map(|s| (*s).to_owned()).collect();
        if let Some(contents) = admin_file {
            let path = directory.path().join("admin.url");
            std::fs::write(&path, contents).expect("admin file");
            full.push("--admin-url-file".to_owned());
            full.push(path.display().to_string());
        }
        full.push("--runtime-config".to_owned());
        full.push("runtime.yaml".to_owned());
        let refs: Vec<&str> = full.iter().map(String::as_str).collect();
        let args = parse(&refs).expect("arguments parse");
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let exit = run_with(
            "casectl",
            "1.2.3-test",
            &args,
            format,
            |_| input,
            backend,
            &mut stdout,
            &mut stderr,
        );
        Run {
            exit,
            stdout: String::from_utf8(stdout).expect("utf-8"),
            stderr: String::from_utf8(stderr).expect("utf-8"),
        }
    }

    fn created_everything(
        _: &AdminConfig,
        plan: &Plan,
        _: &ProvisionTarget,
    ) -> Result<Outcome, Failure> {
        Ok(Outcome {
            statements: plan
                .statements()
                .iter()
                .map(|statement| {
                    let outcome = if statement.probe.is_some() {
                        StatementOutcome::Created
                    } else {
                        StatementOutcome::Applied
                    };
                    (statement.step, outcome)
                })
                .collect(),
            single_role: plan.single_role(),
        })
    }

    fn must_not_run(_: &AdminConfig, _: &Plan, _: &ProvisionTarget) -> Result<Outcome, Failure> {
        panic!("the backend must not run");
    }

    #[cfg(feature = "schema")]
    #[test]
    fn checked_in_schema_matches_the_owning_type() {
        assert_eq!(
            report_schema_document().expect("the report schema renders"),
            include_str!("../schema/provision-report.schema.json"),
            "regenerate with: cargo run --locked -p registry-platform-provision --features schema --example provision-report-schema -- --output crates/registry-platform-provision/schema/provision-report.schema.json"
        );
    }

    // ---- flags ----

    #[test]
    fn print_sql_conflicts_with_both_admin_flags() {
        for admin in [["--admin-url-file", "a"], ["--admin-url-env", "A"]] {
            let error = parse(&["--runtime-config", "r", "--print-sql", admin[0], admin[1]])
                .expect_err("print conflicts with an admin flag");
            assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
            assert_eq!(error.exit_code(), 2);
        }
    }

    #[test]
    fn the_two_admin_flags_conflict() {
        let error = parse(&[
            "--runtime-config",
            "r",
            "--admin-url-file",
            "a",
            "--admin-url-env",
            "A",
        ])
        .expect_err("two sources conflict");
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn executing_needs_exactly_one_admin_flag() {
        let error = parse(&["--runtime-config", "r"]).expect_err("no administrator source");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert_eq!(error.exit_code(), 2);
        assert!(parse(&["--runtime-config", "r", "--admin-url-file", "a"]).is_ok());
        assert!(parse(&["--runtime-config", "r", "--admin-url-env", "A"]).is_ok());
        assert!(parse(&["--runtime-config", "r", "--print-sql"]).is_ok());
    }

    /// A tool declares `--format human|json` globally and mounts the verb
    /// beneath it. clap refuses a verb flag that reuses a global flag's name.
    #[test]
    fn the_verb_mounts_under_a_tool_with_a_global_format_flag() {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
        enum ToolFormat {
            Human,
            Json,
        }
        let tool = clap::Command::new("tool")
            .arg(
                clap::Arg::new("format")
                    .long("format")
                    .global(true)
                    .value_parser(clap::value_parser!(ToolFormat))
                    .default_value("human"),
            )
            .subcommand(<ProvisionArgs as clap::Args>::augment_args(
                clap::Command::new("provision"),
            ));
        tool.clone().debug_assert();
        let matches = tool
            .try_get_matches_from([
                "tool",
                "provision",
                "--runtime-config",
                "r",
                "--print-sql",
                "--format",
                "json",
            ])
            .expect("the verb parses under the global format flag");
        let verb = matches.subcommand_matches("provision").expect("verb");
        assert_eq!(
            verb.get_one::<ToolFormat>("format"),
            Some(&ToolFormat::Json)
        );
    }

    #[test]
    fn the_verb_has_no_format_flag_of_its_own() {
        let error = parse(&["--runtime-config", "r", "--print-sql", "--format", "json"])
            .expect_err("format belongs to the tool");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn the_runtime_config_is_required() {
        assert!(parse(&["--print-sql"]).is_err());
        assert!(parse(&["--runtime-config", "r", "--print-sql"]).is_ok());
    }

    // ---- print mode ----

    #[test]
    fn print_mode_writes_only_the_script_to_stdout() {
        let run = execute_run(&["--print-sql"], None, Ok(split_input()), &must_not_run);
        assert_eq!(run.exit, 0, "{}", run.all_output());
        assert_eq!(run.stderr, "");
        assert!(run.stdout.starts_with("-- "), "{}", run.stdout);
        assert!(run.stdout.contains("CREATE ROLE \"app_migration\""));
        assert!(run.stdout.contains("\\password \"app_migration\""));
        assert!(run.stdout.contains("\\password \"app_runtime\""));
        assert!(run.stdout.contains("\\connect \"app\""));
        for secret in [
            MIGRATION_PASSWORD,
            RUNTIME_PASSWORD,
            "SCRAM-SHA-256$",
            "postgres://",
        ] {
            assert!(!run.stdout.contains(secret), "script holds {secret}");
        }
        assert!(!run.stdout.contains("PASSWORD '"));
    }

    #[test]
    fn print_mode_json_reports_every_statement_as_not_run() {
        let run = execute_run(
            &["--print-sql", "--format", "json"],
            None,
            Ok(split_input()),
            &must_not_run,
        );
        assert_eq!(run.exit, 0, "{}", run.all_output());
        let report = run.json();
        assert_eq!(report["ok"], true);
        assert_eq!(report["command"], "provision");
        assert_eq!(report["status"], "complete");
        assert_eq!(report["apiVersion"], REPORT_API_VERSION);
        assert_eq!(report["kind"], REPORT_KIND);
        assert_eq!(report["version"], "1.2.3-test");
        assert_eq!(report["product"], "casework");
        assert_eq!(report["executed"], false);
        assert_eq!(report["roleMode"], "split");
        assert_eq!(report["database"], "app");
        assert_eq!(report["migrationRole"], "app_migration");
        assert_eq!(report["runtimeRole"], "app_runtime");
        assert_eq!(report["diagnostics"], serde_json::json!([]));
        let statements = report["statements"].as_array().unwrap();
        assert!(statements.len() > 5);
        for statement in statements {
            assert_eq!(statement["outcome"], "not-run");
            assert!(statement["sql"].as_str().is_some_and(|sql| !sql.is_empty()));
        }
        assert_eq!(statements[0]["step"], "role.migration");
        assert_eq!(statements[0]["scope"], "server");
        assert_eq!(statements[0]["needs"], "createrole");
        for secret in [
            MIGRATION_PASSWORD,
            RUNTIME_PASSWORD,
            "SCRAM-SHA-256$",
            "postgres://",
        ] {
            assert!(!run.stdout.contains(secret));
        }
    }

    #[test]
    fn print_mode_marks_the_statement_that_needs_a_superuser() {
        let product = ProductDatabase {
            product: "breg",
            layout: SchemaLayout::PublicForMigration,
            btree_gist: false,
            spatial: Some(Spatial {
                schema: "registry_spatial_ext".to_owned(),
                bbox_role: "app_bbox".to_owned(),
                minimum_postgis: (3, 5),
            }),
        };
        let input = input_with(
            &format!("postgres://app_migration:{MIGRATION_PASSWORD}@db.example/app"),
            &format!("postgres://app_runtime:{RUNTIME_PASSWORD}@db.example/app"),
            product,
        );
        let text = execute_run(&["--print-sql"], None, Ok(input), &must_not_run);
        assert_eq!(text.exit, 0);
        assert!(text.stdout.contains("-- needs a superuser"));
    }

    #[test]
    fn print_mode_does_not_compare_against_an_administrator() {
        let run = execute_run(&["--print-sql"], None, Ok(split_input()), &must_not_run);
        assert_eq!(run.exit, 0);
    }

    // ---- complete runs ----

    #[test]
    fn a_complete_run_reports_each_outcome() {
        let admin = admin_url("db.example", 5432);
        let run = execute_run(
            &["--format", "json"],
            Some(&admin),
            Ok(split_input()),
            &created_everything,
        );
        assert_eq!(run.exit, 0, "{}", run.all_output());
        let report = run.json();
        assert_eq!(report["ok"], true);
        assert_eq!(report["status"], "complete");
        assert_eq!(report["executed"], true);
        assert_eq!(report["roleMode"], "split");
        let statements = report["statements"].as_array().unwrap();
        assert_eq!(statements[0]["outcome"], "created");
        assert!(statements.iter().any(|s| s["outcome"] == "applied"));
        assert!(statements.iter().all(|s| s["outcome"] != "not-run"));
        for secret in [
            MIGRATION_PASSWORD,
            RUNTIME_PASSWORD,
            ADMIN_PASSWORD,
            "SCRAM-SHA-256$",
            "postgres://",
        ] {
            assert!(!run.all_output().contains(secret));
        }
    }

    #[test]
    fn a_complete_text_run_lists_statements_roles_and_database() {
        let admin = admin_url("db.example", 5432);
        let run = execute_run(&[], Some(&admin), Ok(split_input()), &created_everything);
        assert_eq!(run.exit, 0, "{}", run.all_output());
        assert_eq!(run.stderr, "");
        assert!(
            run.stdout.contains("created  role.migration\n"),
            "{}",
            run.stdout
        );
        assert!(run.stdout.contains("applied  database.revoke-public\n"));
        assert!(run.stdout.contains("database: app\n"));
        assert!(run.stdout.contains("migration role: app_migration\n"));
        assert!(run.stdout.contains("runtime role: app_runtime\n"));
        assert!(!run.stdout.contains("single-role mode"));
    }

    #[test]
    fn single_role_mode_says_so() {
        let input = input_with(
            &format!("postgres://app:{MIGRATION_PASSWORD}@db.example/app"),
            &format!("postgres://app:{MIGRATION_PASSWORD}@db.example/app"),
            owned_product(),
        );
        let admin = admin_url("db.example", 5432);
        let run = execute_run(&[], Some(&admin), Ok(input), &created_everything);
        assert_eq!(run.exit, 0, "{}", run.all_output());
        assert!(run
            .stdout
            .contains(registry_platform_activation::SINGLE_ROLE_STATEMENT));
        let input = input_with(
            &format!("postgres://app:{MIGRATION_PASSWORD}@db.example/app"),
            &format!("postgres://app:{MIGRATION_PASSWORD}@db.example/app"),
            owned_product(),
        );
        let json = execute_run(
            &["--format", "json"],
            Some(&admin),
            Ok(input),
            &created_everything,
        );
        assert_eq!(json.json()["roleMode"], "single");
    }

    // ---- refusals from the executor ----

    fn refusal_json(error: ProvisionError) -> (u8, Value) {
        let admin = admin_url("db.example", 5432);
        let backend =
            move |_: &AdminConfig, _: &Plan, _: &ProvisionTarget| Err(error.clone().into());
        let run = execute_run(
            &["--format", "json"],
            Some(&admin),
            Ok(split_input()),
            &backend,
        );
        assert_eq!(run.stderr, "");
        for secret in [
            MIGRATION_PASSWORD,
            RUNTIME_PASSWORD,
            ADMIN_PASSWORD,
            "postgres://",
        ] {
            assert!(!run.stdout.contains(secret));
        }
        let report = run.json();
        (run.exit, report)
    }

    #[test]
    fn each_executor_refusal_has_its_code_status_and_path() {
        use ProvisionError as E;
        let cases: Vec<(E, &str, &str, u8, Option<&str>)> = vec![
            (
                E::AdminConnectFailed { sqlstate: None },
                "platform.provision.admin-connect-failed",
                "operational-failure",
                3,
                None,
            ),
            (
                E::UnsupportedPostgres,
                "platform.provision.unsupported-postgres",
                "domain-refusal",
                1,
                None,
            ),
            (
                E::StatementNeedsPrivilege {
                    step: "extension.postgis",
                    needs: Needs::Superuser,
                    scope: Scope::Database,
                    database: "app".to_owned(),
                },
                "platform.provision.statement-needs-privilege",
                "domain-refusal",
                1,
                Some("extension.postgis"),
            ),
            (
                E::RoleAttributesDiffer {
                    step: "role.runtime",
                    role: "app_runtime".to_owned(),
                },
                "platform.provision.role-attributes-differ",
                "domain-refusal",
                1,
                Some("role.runtime"),
            ),
            (
                E::DatabaseOwnerDiffers {
                    database: "app".to_owned(),
                },
                "platform.provision.database-owner-differs",
                "domain-refusal",
                1,
                Some("database.create"),
            ),
            (
                E::SchemaOwnerDiffers {
                    step: "schema.owned",
                    schema: "casework".to_owned(),
                    database: "app".to_owned(),
                },
                "platform.provision.schema-owner-differs",
                "domain-refusal",
                1,
                Some("schema.owned"),
            ),
            (
                E::ExtensionTooOld {
                    step: "extension.postgis",
                    extension: "postgis".to_owned(),
                },
                "platform.provision.extension-too-old",
                "domain-refusal",
                1,
                Some("extension.postgis"),
            ),
            (
                E::RoleLoginFailed {
                    role: "app_runtime".to_owned(),
                    sqlstate: Some("28P01".to_owned()),
                },
                "platform.provision.role-login-failed",
                "domain-refusal",
                1,
                None,
            ),
            (
                E::RoleLoginFailed {
                    role: "app_runtime".to_owned(),
                    sqlstate: None,
                },
                "platform.provision.role-login-failed",
                "operational-failure",
                3,
                None,
            ),
            (
                E::RoleMembershipDiffers {
                    step: "role.runtime",
                    role: "app_runtime".to_owned(),
                },
                "platform.provision.role-membership-differs",
                "domain-refusal",
                1,
                Some("role.runtime"),
            ),
            (
                E::DatabaseIsTemplate {
                    database: "app".to_owned(),
                },
                "platform.provision.database-is-template",
                "domain-refusal",
                1,
                Some("database.create"),
            ),
            (
                E::ExtensionIncomplete {
                    step: "extension.postgis",
                    extension: "postgis".to_owned(),
                },
                "platform.provision.extension-incomplete",
                "domain-refusal",
                1,
                Some("extension.postgis"),
            ),
            (
                E::RoleSettingsDiffer {
                    step: "role.runtime",
                    role: "app_runtime".to_owned(),
                },
                "platform.provision.role-settings-differ",
                "domain-refusal",
                1,
                Some("role.runtime"),
            ),
            (
                E::DatabaseConnectFailed {
                    database: "app".to_owned(),
                    sqlstate: Some("53300".to_owned()),
                },
                "platform.provision.database-connect-failed",
                "operational-failure",
                3,
                None,
            ),
            (
                E::RoleLoginFailed {
                    role: "app_runtime".to_owned(),
                    sqlstate: Some("53300".to_owned()),
                },
                "platform.provision.role-login-failed",
                "operational-failure",
                3,
                None,
            ),
            (
                E::EffectUnconfirmed {
                    step: "database.create",
                },
                "platform.provision.effect-unconfirmed",
                "operational-failure",
                3,
                Some("database.create"),
            ),
            (
                E::StatementFailed {
                    step: "role.migration",
                    sqlstate: "23505".to_owned(),
                },
                "platform.provision.statement-failed",
                "operational-failure",
                3,
                Some("role.migration"),
            ),
        ];
        for (error, code, status, exit, step) in cases {
            let (actual_exit, report) = refusal_json(error);
            assert_eq!(actual_exit, exit, "{code}");
            assert_eq!(report["ok"], false, "{code}");
            assert_eq!(report["status"], status, "{code}");
            let ran = !matches!(
                code,
                "platform.provision.admin-connect-failed"
                    | "platform.provision.unsupported-postgres"
            );
            assert_eq!(report["executed"], ran, "{code}");
            let diagnostics = report["diagnostics"].as_array().unwrap();
            assert_eq!(diagnostics.len(), 1, "{code}");
            let diagnostic = &diagnostics[0];
            assert_eq!(diagnostic["severity"], "error");
            assert_eq!(diagnostic["code"], code);
            assert_eq!(diagnostic["path"], step.unwrap_or(""), "{code}");
            assert!(!diagnostic["message"].as_str().unwrap().is_empty());
            assert!(!diagnostic["suggestedAction"].as_str().unwrap().is_empty());
            for statement in report["statements"].as_array().unwrap() {
                assert_eq!(statement["outcome"], "not-run", "{code}");
            }
        }
    }

    #[test]
    fn a_failure_part_way_reports_what_ran_before_it() {
        let admin = admin_url("db.example", 5432);
        let backend = |_: &AdminConfig, plan: &Plan, _: &ProvisionTarget| {
            let reached = plan
                .statements()
                .iter()
                .take(3)
                .map(|statement| {
                    let outcome = if statement.probe.is_some() {
                        StatementOutcome::Created
                    } else {
                        StatementOutcome::Applied
                    };
                    (statement.step, outcome)
                })
                .collect();
            Err(Failure {
                error: ProvisionError::StatementNeedsPrivilege {
                    step: "database.revoke-public",
                    needs: Needs::DatabaseOwner,
                    scope: Scope::Server,
                    database: "app".to_owned(),
                },
                reached,
            })
        };
        let run = execute_run(
            &["--format", "json"],
            Some(&admin),
            Ok(split_input()),
            &backend,
        );
        assert_eq!(run.exit, 1);
        let report = run.json();
        assert_eq!(report["executed"], true);
        let outcomes: Vec<&str> = report["statements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|statement| statement["outcome"].as_str().unwrap())
            .collect();
        assert_eq!(&outcomes[..3], ["created", "created", "created"]);
        assert!(outcomes[3..].iter().all(|outcome| *outcome == "not-run"));
    }

    #[test]
    fn a_login_check_failure_keeps_the_outcomes_of_the_run_that_preceded_it() {
        let admin = admin_url("db.example", 5432);
        let backend = |admin: &AdminConfig, plan: &Plan, target: &ProvisionTarget| {
            let outcome = created_everything(admin, plan, target)?;
            Err(Failure {
                error: ProvisionError::RoleLoginFailed {
                    role: "app_runtime".to_owned(),
                    sqlstate: Some("28P01".to_owned()),
                },
                reached: outcome.statements,
            })
        };
        let run = execute_run(
            &["--format", "json"],
            Some(&admin),
            Ok(split_input()),
            &backend,
        );
        assert_eq!(run.exit, 1);
        let report = run.json();
        assert_eq!(report["executed"], true);
        assert!(report["statements"]
            .as_array()
            .unwrap()
            .iter()
            .all(|statement| statement["outcome"] != "not-run"));
    }

    #[test]
    fn a_login_refusal_blames_the_password_only_for_a_password_failure() {
        let action_for = |sqlstate: Option<&str>| {
            let (_, report) = refusal_json(ProvisionError::RoleLoginFailed {
                role: "app_runtime".to_owned(),
                sqlstate: sqlstate.map(str::to_owned),
            });
            report["diagnostics"][0]["suggestedAction"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        assert!(action_for(Some("28P01")).contains("different password"));
        for other in [Some("28000"), Some("53300"), None] {
            assert!(
                !action_for(other).contains("different password"),
                "{other:?}"
            );
        }
        assert!(action_for(Some("28000")).contains("pg_hba.conf"));
    }

    #[test]
    fn a_connect_failure_in_the_new_database_reports_what_ran_and_names_the_database() {
        let admin = admin_url("db.example", 5432);
        let backend = |_: &AdminConfig, plan: &Plan, _: &ProvisionTarget| {
            let reached = plan
                .statements()
                .iter()
                .take(3)
                .map(|statement| (statement.step, StatementOutcome::Created))
                .collect();
            Err(Failure {
                error: ProvisionError::DatabaseConnectFailed {
                    database: "app".to_owned(),
                    sqlstate: Some("53300".to_owned()),
                },
                reached,
            })
        };
        let run = execute_run(
            &["--format", "json"],
            Some(&admin),
            Ok(split_input()),
            &backend,
        );
        assert_eq!(run.exit, 3, "{}", run.all_output());
        let report = run.json();
        assert_eq!(report["executed"], true);
        let diagnostic = &report["diagnostics"][0];
        assert_eq!(
            diagnostic["code"],
            "platform.provision.database-connect-failed"
        );
        let action = diagnostic["suggestedAction"].as_str().unwrap();
        assert!(
            action.contains("CONNECTION LIMIT") && action.contains("pg_hba.conf"),
            "{action}"
        );
        assert!(
            !action.contains("administrator URL"),
            "the URL was proved right: {action}"
        );
        assert_eq!(report["statements"][0]["outcome"], "created");
    }

    #[test]
    fn statements_that_ran_mean_executed_whatever_the_error() {
        let admin = admin_url("db.example", 5432);
        let backend = |_: &AdminConfig, plan: &Plan, _: &ProvisionTarget| {
            Err(Failure {
                error: ProvisionError::AdminConnectFailed { sqlstate: None },
                reached: vec![(plan.statements()[0].step, StatementOutcome::Created)],
            })
        };
        let run = execute_run(
            &["--format", "json"],
            Some(&admin),
            Ok(split_input()),
            &backend,
        );
        assert_eq!(run.json()["executed"], true);
    }

    #[test]
    fn a_text_refusal_lists_the_statements_that_ran_before_it() {
        let admin = admin_url("db.example", 5432);
        let backend = |_: &AdminConfig, plan: &Plan, _: &ProvisionTarget| {
            Err(Failure {
                error: ProvisionError::StatementFailed {
                    step: "database.create",
                    sqlstate: "42501".to_owned(),
                },
                reached: plan
                    .statements()
                    .iter()
                    .take(2)
                    .map(|statement| (statement.step, StatementOutcome::Created))
                    .collect(),
            })
        };
        let run = execute_run(&[], Some(&admin), Ok(split_input()), &backend);
        assert_eq!(run.exit, 3);
        assert_eq!(run.stdout, "");
        let ran = run
            .stderr
            .find("created  role.migration\ncreated  role.runtime\n")
            .unwrap_or_else(|| panic!("{}", run.stderr));
        let refusal = run
            .stderr
            .find("error[platform.provision.statement-failed]")
            .unwrap_or_else(|| panic!("{}", run.stderr));
        assert!(ran < refusal, "{}", run.stderr);
        assert!(!run.stderr.contains("not-run"), "{}", run.stderr);
    }

    #[test]
    fn a_refusal_before_any_statement_lists_no_statements() {
        let admin = admin_url("db.example", 5432);
        let backend = |_: &AdminConfig, _: &Plan, _: &ProvisionTarget| {
            Err(ProvisionError::UnsupportedPostgres.into())
        };
        let run = execute_run(&[], Some(&admin), Ok(split_input()), &backend);
        assert!(!run.stderr.contains("created"), "{}", run.stderr);
        assert!(run.stderr.starts_with("error["), "{}", run.stderr);
    }

    #[test]
    fn a_login_refusal_for_a_connection_limit_is_operational() {
        let (exit, report) = refusal_json(ProvisionError::RoleLoginFailed {
            role: "app_runtime".to_owned(),
            sqlstate: Some("53300".to_owned()),
        });
        assert_eq!(exit, 3);
        let action = report["diagnostics"][0]["suggestedAction"]
            .as_str()
            .unwrap();
        assert!(action.contains("CONNECTION LIMIT"), "{action}");
    }

    #[test]
    fn a_missing_administrator_database_gets_its_own_action() {
        let (exit, report) = refusal_json(ProvisionError::AdminConnectFailed {
            sqlstate: Some("3D000".to_owned()),
        });
        assert_eq!(exit, 3);
        let action = report["diagnostics"][0]["suggestedAction"]
            .as_str()
            .unwrap();
        assert!(action.contains("does not exist"), "{action}");
        assert!(!action.contains("host, port"), "{action}");
    }

    #[test]
    fn the_privilege_refusal_names_the_statement_and_offers_print_mode() {
        let (_, report) = refusal_json(ProvisionError::StatementNeedsPrivilege {
            step: "extension.postgis",
            needs: Needs::Superuser,
            scope: Scope::Database,
            database: "app".to_owned(),
        });
        let diagnostic = &report["diagnostics"][0];
        assert_eq!(
            diagnostic["message"],
            "the administrator role cannot run CREATE EXTENSION postgis in database \"app\"; it needs a superuser"
        );
        assert_eq!(
            diagnostic["suggestedAction"],
            "run this statement as a role that has it, or run \"casectl provision --print-sql\" \
             and give the script to the database administrator, then run provision again"
        );
    }

    #[test]
    fn a_text_refusal_goes_to_stderr_and_stdout_stays_empty() {
        let admin = admin_url("db.example", 5432);
        let backend = |_: &AdminConfig, _: &Plan, _: &ProvisionTarget| {
            Err(ProvisionError::UnsupportedPostgres.into())
        };
        let run = execute_run(&[], Some(&admin), Ok(split_input()), &backend);
        assert_eq!(run.exit, 1);
        assert_eq!(run.stdout, "");
        assert!(run
            .stderr
            .contains("error[platform.provision.unsupported-postgres]"));
    }

    // ---- refusals before any statement ----

    fn first_diagnostic(run: &Run) -> Value {
        run.json()["diagnostics"][0].clone()
    }

    #[test]
    fn a_bad_administrator_url_is_a_usage_error_that_names_the_rule() {
        let run = execute_run(
            &["--format", "json"],
            Some(&format!(
                "http://admin:{ADMIN_PASSWORD}@db.example/postgres"
            )),
            Ok(split_input()),
            &must_not_run,
        );
        assert_eq!(run.exit, 2);
        let report = run.json();
        assert_eq!(report["status"], "usage-error");
        assert_eq!(
            first_diagnostic(&run)["code"],
            "platform.provision.admin-url-invalid"
        );
        assert!(!run.stdout.contains(ADMIN_PASSWORD));
        assert!(!run.stdout.contains("http://"));
    }

    #[test]
    fn plaintext_and_weak_sslmode_in_the_administrator_url_are_refused() {
        let run = execute_run(
            &["--format", "json"],
            Some(&format!(
                "postgres://admin:{ADMIN_PASSWORD}@db.example/postgres?sslmode=disable"
            )),
            Ok(split_input()),
            &must_not_run,
        );
        assert_eq!(run.exit, 2);
        assert_eq!(
            first_diagnostic(&run)["code"],
            "platform.provision.admin-url-invalid"
        );
    }

    #[test]
    fn an_unreadable_administrator_file_is_an_admin_url_refusal() {
        let args = parse(&[
            "--runtime-config",
            "r",
            "--admin-url-file",
            "/nonexistent-provision-admin-url",
        ])
        .unwrap();
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let exit = run_with(
            "casectl",
            "1",
            &args,
            OutputFormat::Json,
            |_| Ok(split_input()),
            &must_not_run,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, 2);
        let report: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(
            report["diagnostics"][0]["code"],
            "platform.provision.admin-url-invalid"
        );
        assert!(!String::from_utf8(stdout).unwrap().contains("nonexistent"));
    }

    #[cfg(unix)]
    #[test]
    fn an_administrator_file_that_is_a_named_pipe_is_refused_without_opening_it() {
        let directory = tempfile::tempdir().expect("scratch directory");
        let pipe = directory.path().join("admin.url");
        let made = std::process::Command::new("mkfifo")
            .arg(&pipe)
            .status()
            .expect("mkfifo runs");
        assert!(made.success());
        let pipe = pipe.display().to_string();
        let args = parse(&["--runtime-config", "r", "--admin-url-file", &pipe]).unwrap();
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let exit = run_with(
            "casectl",
            "1",
            &args,
            OutputFormat::Json,
            |_| Ok(split_input()),
            &must_not_run,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, 2);
        let report: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(
            report["diagnostics"][0]["code"],
            "platform.provision.admin-url-invalid"
        );
    }

    #[test]
    fn an_unset_administrator_variable_is_an_admin_url_refusal_that_names_the_variable() {
        let args = parse(&[
            "--runtime-config",
            "r",
            "--admin-url-env",
            "PROVISION_TEST_UNSET_ADMIN_URL",
        ])
        .unwrap();
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let exit = run_with(
            "casectl",
            "1",
            &args,
            OutputFormat::Json,
            |_| Ok(split_input()),
            &must_not_run,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, 2);
        let report: Value = serde_json::from_slice(&stdout).unwrap();
        let diagnostic = &report["diagnostics"][0];
        assert_eq!(diagnostic["code"], "platform.provision.admin-url-invalid");
        assert!(diagnostic["message"]
            .as_str()
            .unwrap()
            .contains("PROVISION_TEST_UNSET_ADMIN_URL"));
    }

    #[test]
    fn an_invalid_ca_bundle_is_refused_with_the_ca_code() {
        let mut input = split_input();
        input.ca_pem = Some(b"not a certificate".to_vec());
        let run = execute_run(
            &["--format", "json"],
            Some(&admin_url("db.example", 5432)),
            Ok(input),
            &must_not_run,
        );
        assert_eq!(
            first_diagnostic(&run)["code"],
            "platform.provision.admin-ca-invalid"
        );
        assert_eq!(run.exit, 1);
        assert_eq!(run.json()["status"], "domain-refusal");
    }

    #[test]
    fn product_urls_naming_different_targets_are_a_mismatch() {
        let variants = [
            (
                "postgres://m:pw1@db-a.example/app",
                "postgres://r:pw2@db-b.example/app",
                "host",
            ),
            (
                "postgres://m:pw1@db.example:5432/app",
                "postgres://r:pw2@db.example:5433/app",
                "port",
            ),
            (
                "postgres://m:pw1@db.example/app",
                "postgres://r:pw2@db.example/other",
                "database",
            ),
        ];
        for (migration, runtime, what) in variants {
            let run = execute_run(
                &["--format", "json"],
                Some(&admin_url("db.example", 5432)),
                Ok(input_with(migration, runtime, owned_product())),
                &must_not_run,
            );
            assert_eq!(run.exit, 1, "{what}");
            let diagnostic = first_diagnostic(&run);
            assert_eq!(
                diagnostic["code"], "platform.provision.target-mismatch",
                "{what}"
            );
            assert!(diagnostic["message"].as_str().unwrap().contains(what));
            assert!(
                !run.stdout.contains("db-a.example"),
                "no host values: {what}"
            );
        }
    }

    #[test]
    fn a_mismatch_between_the_product_urls_is_refused_in_print_mode_too() {
        let run = execute_run(
            &["--print-sql", "--format", "json"],
            None,
            Ok(input_with(
                "postgres://m:pw1@db.example/app",
                "postgres://r:pw2@db.example/other",
                owned_product(),
            )),
            &must_not_run,
        );
        assert_eq!(run.exit, 1);
        assert_eq!(
            first_diagnostic(&run)["code"],
            "platform.provision.target-mismatch"
        );
    }

    #[test]
    fn an_administrator_on_another_host_or_port_is_a_mismatch() {
        for (host, port, what) in [
            ("other.example", 5432, "host"),
            ("db.example", 6543, "port"),
        ] {
            let run = execute_run(
                &["--format", "json"],
                Some(&admin_url(host, port)),
                Ok(split_input()),
                &must_not_run,
            );
            assert_eq!(run.exit, 1, "{what}");
            let diagnostic = first_diagnostic(&run);
            assert_eq!(diagnostic["code"], "platform.provision.target-mismatch");
            assert!(diagnostic["message"]
                .as_str()
                .unwrap()
                .contains("administrator"));
            assert!(diagnostic["message"].as_str().unwrap().contains(what));
        }
    }

    #[test]
    fn the_host_comparison_ignores_case() {
        let run = execute_run(
            &["--format", "json"],
            Some(&admin_url("DB.Example", 5432)),
            Ok(split_input()),
            &created_everything,
        );
        assert_eq!(run.exit, 0, "{}", run.all_output());
    }

    #[test]
    fn a_product_url_that_cannot_name_a_target_is_refused_without_echoing_it() {
        let cases = [
            "not a url at all, pw",
            "mysql://m:pw@db.example/app",
            "postgres://m@db.example/app",
            "postgres://m:pw@db.example",
            "postgres://m:pw@db.example/app?host=other.example",
        ];
        for bad in cases {
            let run = execute_run(
                &["--print-sql", "--format", "json"],
                None,
                Ok(input_with(
                    bad,
                    "postgres://r:pw2@db.example/app",
                    owned_product(),
                )),
                &must_not_run,
            );
            assert_eq!(run.exit, 2, "{bad}");
            assert_eq!(run.json()["status"], "usage-error");
            assert_eq!(
                first_diagnostic(&run)["code"],
                "platform.provision.target-invalid"
            );
            assert!(!run.stdout.contains("other.example"), "{bad}");
            assert!(!run.stdout.contains(bad), "{bad}");
        }
    }

    #[test]
    fn one_role_name_with_two_passwords_is_refused() {
        let run = execute_run(
            &["--print-sql", "--format", "json"],
            None,
            Ok(input_with(
                "postgres://app:pw1@db.example/app",
                "postgres://app:pw2@db.example/app",
                owned_product(),
            )),
            &must_not_run,
        );
        assert_eq!(run.exit, 2);
        assert_eq!(
            first_diagnostic(&run)["code"],
            "platform.provision.target-invalid"
        );
        assert!(!run.stdout.contains("pw1") && !run.stdout.contains("pw2"));
    }

    #[test]
    fn a_percent_encoded_role_name_and_password_are_decoded() {
        let input = input_with(
            "postgres://app%5Fmigration:p%40ss@db.example/app",
            "postgres://app%5Fruntime:p%40ss2@db.example/app",
            owned_product(),
        );
        let run = execute_run(
            &["--print-sql", "--format", "json"],
            None,
            Ok(input),
            &must_not_run,
        );
        assert_eq!(run.exit, 0, "{}", run.all_output());
        assert_eq!(run.json()["migrationRole"], "app_migration");
    }

    #[test]
    fn the_loader_diagnostic_is_reported_as_given() {
        let diagnostic = Diagnostic::error(
            "platform.runtime-config.unsafe-file",
            "",
            "the runtime file is unsafe",
            "Fix the file.",
        );
        let run = execute_run(
            &["--print-sql", "--format", "json"],
            None,
            Err(Box::new(diagnostic)),
            &must_not_run,
        );
        assert_eq!(run.exit, 1);
        let report = run.json();
        assert_eq!(report["status"], "domain-refusal");
        assert_eq!(report["executed"], false);
        assert_eq!(report["statements"], serde_json::json!([]));
        assert!(report.get("product").is_none());
        assert_eq!(
            report["diagnostics"][0]["code"],
            "platform.runtime-config.unsafe-file"
        );
    }

    #[test]
    fn a_control_character_in_a_role_name_is_refused_in_print_mode_with_no_script() {
        let migration = format!("postgres://app_migration:{MIGRATION_PASSWORD}@db.example/app");
        let runtime =
            format!("postgres://app_runtime%0A%5C!%20id:{RUNTIME_PASSWORD}@db.example/app");
        for format in [["--format", "human"], ["--format", "json"]] {
            let mut arguments = vec!["--print-sql"];
            arguments.extend(format);
            let run = execute_run(
                &arguments,
                None,
                Ok(input_with(&migration, &runtime, owned_product())),
                &must_not_run,
            );
            assert_eq!(run.exit, 2, "{}", run.all_output());
            let output = run.all_output();
            for script in [
                "CREATE ROLE",
                "\\password",
                "\\connect",
                "\\!",
                "-- provision script",
            ] {
                assert!(!output.contains(script), "{format:?}: {output}");
            }
            assert!(!output.contains(RUNTIME_PASSWORD), "{output}");
            if format[1] == "json" {
                let diagnostic = first_diagnostic(&run);
                assert_eq!(diagnostic["code"], "platform.provision.target-invalid");
                let action = diagnostic["suggestedAction"].as_str().unwrap();
                assert!(
                    action.contains("user") && action.contains("runtime"),
                    "{action}"
                );
                assert!(!action.contains("\\!"), "{action}");
                assert!(run.json().get("runtimeRole").is_none());
            } else {
                assert!(
                    output.contains("platform.provision.target-invalid"),
                    "{output}"
                );
            }
        }
    }

    #[test]
    fn each_refused_url_member_is_named_in_the_action_and_never_quoted() {
        let cases = [
            (
                "postgres://app_migration%0A:pw1@db.example/app",
                "postgres://app_runtime:pw2@db.example/app",
                "migration URL",
            ),
            (
                "postgres://app_migration:pw1@db.example/app%0Ax",
                "postgres://app_runtime:pw2@db.example/app%0Ax",
                "database name",
            ),
            (
                "postgres://app_migration:pw1@db.example/host%3Dattacker",
                "postgres://app_runtime:pw2@db.example/host%3Dattacker",
                "database name",
            ),
        ];
        for (migration, runtime, member) in cases {
            let run = execute_run(
                &["--print-sql", "--format", "json"],
                None,
                Ok(input_with(migration, runtime, owned_product())),
                &must_not_run,
            );
            assert_eq!(run.exit, 2, "{migration}");
            let diagnostic = first_diagnostic(&run);
            assert_eq!(diagnostic["code"], "platform.provision.target-invalid");
            let action = diagnostic["suggestedAction"].as_str().unwrap();
            assert!(action.contains(member), "{member}: {action}");
            assert!(!run.stdout.contains("attacker"), "{}", run.stdout);
        }
    }

    #[test]
    fn the_administrators_own_database_cannot_be_the_product_database() {
        let admin =
            format!("postgres://admin:{ADMIN_PASSWORD}@db.example:5432/app?sslmode=verify-full");
        let run = execute_run(
            &["--format", "json"],
            Some(&admin),
            Ok(split_input()),
            &must_not_run,
        );
        assert_eq!(run.exit, 2, "{}", run.all_output());
        assert_eq!(
            first_diagnostic(&run)["code"],
            "platform.provision.target-invalid"
        );
        assert!(!run.stdout.contains(ADMIN_PASSWORD));
    }

    fn admin_file_run(contents: &[u8]) -> Run {
        let directory = tempfile::tempdir().expect("scratch directory");
        let path = directory.path().join("admin.url");
        std::fs::write(&path, contents).expect("admin file");
        let path = path.display().to_string();
        let args = parse(&["--runtime-config", "r", "--admin-url-file", path.as_str()]).unwrap();
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let exit = run_with(
            "casectl",
            "1",
            &args,
            OutputFormat::Json,
            |_| Ok(split_input()),
            &must_not_run,
            &mut stdout,
            &mut stderr,
        );
        Run {
            exit,
            stdout: String::from_utf8(stdout).expect("utf-8"),
            stderr: String::from_utf8(stderr).expect("utf-8"),
        }
    }

    #[test]
    fn an_unusable_administrator_file_is_a_usage_error() {
        let oversized = vec![b'a'; 9000];
        let cases: [(&str, &[u8]); 4] = [
            ("larger than 8 KiB", &oversized),
            ("empty", b""),
            ("whitespace only", b"  \n\t\n"),
            ("not UTF-8", &[0xff, 0xfe, 0xfd]),
        ];
        for (what, contents) in cases {
            let run = admin_file_run(contents);
            assert_eq!(run.exit, 2, "{what}: {}", run.all_output());
            assert_eq!(
                first_diagnostic(&run)["code"],
                "platform.provision.admin-url-invalid",
                "{what}"
            );
        }
    }

    #[test]
    fn an_administrator_path_that_is_not_a_regular_file_is_a_usage_error() {
        let directory = tempfile::tempdir().expect("scratch directory");
        let path = directory.path().display().to_string();
        let args = parse(&["--runtime-config", "r", "--admin-url-file", path.as_str()]).unwrap();
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let exit = run_with(
            "casectl",
            "1",
            &args,
            OutputFormat::Json,
            |_| Ok(split_input()),
            &must_not_run,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(exit, 2);
        let report: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(
            report["diagnostics"][0]["code"],
            "platform.provision.admin-url-invalid"
        );
    }

    #[test]
    fn no_output_ever_holds_a_password_verifier_or_url() {
        let admin = admin_url("db.example", 5432);
        let backend = |_: &AdminConfig, _: &Plan, _: &ProvisionTarget| {
            Err(ProvisionError::StatementFailed {
                step: "role.migration",
                sqlstate: "42710".to_owned(),
            }
            .into())
        };
        for format in [["--format", "human"], ["--format", "json"]] {
            let run = execute_run(&format, Some(&admin), Ok(split_input()), &backend);
            let output = run.all_output();
            for secret in [
                MIGRATION_PASSWORD,
                RUNTIME_PASSWORD,
                ADMIN_PASSWORD,
                "SCRAM-SHA-256$",
                "postgres://",
            ] {
                assert!(!output.contains(secret), "{format:?} leaked {secret}");
            }
        }
    }
}

/// Runs the command against the disposable server named by
/// `PROVISION_TEST_DATABASE_URL` (a superuser, over TLS) and its CA file in
/// `PROVISION_TEST_DATABASE_CA`. A missing variable fails the test.
#[cfg(all(test, feature = "postgres-test"))]
mod postgres_tests {
    use super::*;
    use crate::SchemaLayout;
    use serde_json::Value;

    fn required(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("the postgres-test feature needs {name}"))
    }

    fn random_hex(bytes: usize) -> String {
        let mut buffer = vec![0_u8; bytes];
        getrandom::fill(&mut buffer).expect("random bytes");
        buffer.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Drops what the test created, even when an assertion failed.
    struct Cleanup {
        admin: AdminConfig,
        database: String,
        roles: Vec<String>,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("cleanup runtime");
            runtime.block_on(async {
                let session = self.admin.connect(None).await.expect("cleanup session");
                session
                    .client
                    .batch_execute(&format!(
                        "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
                        self.database
                    ))
                    .await
                    .expect("drop database");
                for role in &self.roles {
                    session
                        .client
                        .batch_execute(&format!("DROP ROLE IF EXISTS \"{role}\""))
                        .await
                        .expect("drop role");
                }
            });
        }
    }

    fn run_command(
        arguments: &[&str],
        admin_file: &Path,
        input: ProvisionInput,
        backend: Backend<'_>,
    ) -> (u8, String, String) {
        let admin_file = admin_file.display().to_string();
        let mut full = vec![
            "--runtime-config",
            "runtime.yaml",
            "--admin-url-file",
            admin_file.as_str(),
        ];
        let (arguments, format) = tests::split_format(arguments);
        full.extend_from_slice(&arguments);
        let args = {
            use clap::Parser;
            #[derive(Parser)]
            struct Harness {
                #[command(flatten)]
                args: ProvisionArgs,
            }
            Harness::try_parse_from(std::iter::once("tool").chain(full))
                .expect("arguments parse")
                .args
        };
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let exit = run_with(
            "casectl",
            "1.2.3-test",
            &args,
            format,
            |_| Ok(input),
            backend,
            &mut stdout,
            &mut stderr,
        );
        (
            exit,
            String::from_utf8(stdout).expect("utf-8"),
            String::from_utf8(stderr).expect("utf-8"),
        )
    }

    #[test]
    fn provision_converges_a_real_server_and_refuses_a_changed_password() {
        let admin_url = required("PROVISION_TEST_DATABASE_URL");
        let ca = std::fs::read(required("PROVISION_TEST_DATABASE_CA")).expect("CA file");
        let endpoint = parse_endpoint(&admin_url).expect("administrator URL");
        let suffix = random_hex(6);
        let (database, migration, runtime_role) = (
            format!("s3_{suffix}_db"),
            format!("s3_{suffix}_mig"),
            format!("s3_{suffix}_run"),
        );
        let (migration_password, runtime_password) = (random_hex(16), random_hex(16));
        let (host, port) = (endpoint.host.as_str(), endpoint.port);
        let input = |runtime_password: &str| ProvisionInput {
            product: ProductDatabase {
                product: "casework",
                layout: SchemaLayout::Owned(vec!["casework".to_owned()]),
                btree_gist: true,
                spatial: None,
            },
            migration_url: Zeroizing::new(format!(
                "postgres://{migration}:{migration_password}@{host}:{port}/{database}"
            )),
            runtime_url: Zeroizing::new(format!(
                "postgres://{runtime_role}:{runtime_password}@{host}:{port}/{database}"
            )),
            ca_pem: Some(ca.clone()),
        };
        let _cleanup = Cleanup {
            admin: admin_config(&admin_url, Some(&ca)).expect("administrator config"),
            database: database.clone(),
            roles: vec![migration.clone(), runtime_role.clone()],
        };
        let directory = tempfile::tempdir().expect("scratch directory");
        let admin_file = directory.path().join("admin.url");
        std::fs::write(&admin_file, &admin_url).expect("admin file");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let backend = server_backend(&runtime);

        let (exit, stdout, stderr) = run_command(
            &["--format", "json"],
            &admin_file,
            input(&runtime_password),
            &backend,
        );
        assert_eq!(exit, 0, "{stdout}{stderr}");
        let first: Value = serde_json::from_str(&stdout).expect("JSON report");
        let outcome = |report: &Value, step: &str| {
            report["statements"]
                .as_array()
                .expect("statements")
                .iter()
                .find(|statement| statement["step"] == step)
                .map(|statement| statement["outcome"].clone())
        };
        assert_eq!(outcome(&first, "role.migration"), Some("created".into()));
        assert_eq!(outcome(&first, "database.create"), Some("created".into()));
        assert_eq!(outcome(&first, "schema.owned"), Some("created".into()));
        assert_eq!(first["executed"], true);

        let (exit, stdout, stderr) = run_command(
            &["--format", "json"],
            &admin_file,
            input(&runtime_password),
            &backend,
        );
        assert_eq!(exit, 0, "{stdout}{stderr}");
        let second: Value = serde_json::from_str(&stdout).expect("JSON report");
        assert_eq!(outcome(&second, "role.migration"), Some("present".into()));
        assert_eq!(outcome(&second, "database.create"), Some("present".into()));
        assert_eq!(outcome(&second, "schema.owned"), Some("present".into()));
        for secret in [
            migration_password.as_str(),
            runtime_password.as_str(),
            "postgres://",
        ] {
            assert!(!stdout.contains(secret), "the report leaked a secret");
        }

        let (exit, stdout, _) = run_command(
            &["--format", "json"],
            &admin_file,
            input(&random_hex(16)),
            &backend,
        );
        assert_eq!(exit, 1, "{stdout}");
        let refused: Value = serde_json::from_str(&stdout).expect("JSON report");
        assert_eq!(
            refused["diagnostics"][0]["code"],
            "platform.provision.role-login-failed"
        );

        let (exit, stdout, stderr) =
            run_command(&[], &admin_file, input(&runtime_password), &backend);
        assert_eq!(exit, 0, "{stdout}{stderr}");
        assert!(stdout.contains("present  role.migration\n"), "{stdout}");
    }
}

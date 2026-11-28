// SPDX-License-Identifier: Apache-2.0
//! Runs a [`Plan`] against a server as an administrator.
//!
//! Every statement runs on its own, so a refusal names exactly one step. No
//! error carries statement text, a URL, a password, a verifier or a driver
//! message: errors name the step, the object and the SQLSTATE.

use std::fmt;

use crate::{
    admin::{bounded_call, AdminConfig, CallFailure, ConnectFailure, Session},
    plan::{verify_server_version, Needs, Plan, Probe, ProvisionTarget, Scope, Statement},
};

/// How [`execute`] treats objects that already exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Probe the catalog first, create only what is absent, and refuse what
    /// exists in a different shape. Every `*ctl provision` uses this.
    Converge,
    /// The server is known to be empty: no floor check and no probes.
    Fresh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementOutcome {
    /// The statement ran and its object did not exist before.
    Created,
    /// The object already existed in the expected shape, so nothing ran.
    Present,
    /// A grant, revoke or connection setting ran. It is a no-op when it
    /// already held.
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// One entry per planned statement, in plan order.
    pub statements: Vec<(&'static str, StatementOutcome)>,
    pub single_role: bool,
}

/// Why provisioning stopped. `code` is the diagnostic code of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionError {
    AdminConnectFailed {
        sqlstate: Option<String>,
    },
    UnsupportedPostgres,
    StatementNeedsPrivilege {
        step: &'static str,
        needs: Needs,
        scope: Scope,
        database: String,
    },
    RoleAttributesDiffer {
        step: &'static str,
        role: String,
    },
    /// An existing product role is a member of a role the plan did not grant it.
    RoleMembershipDiffers {
        step: &'static str,
        role: String,
    },
    DatabaseOwnerDiffers {
        database: String,
    },
    DatabaseIsTemplate {
        database: String,
    },
    SchemaOwnerDiffers {
        step: &'static str,
        schema: String,
        database: String,
    },
    ExtensionTooOld {
        step: &'static str,
        extension: String,
    },
    /// The extension exists, but not in the schema or with the role
    /// membership its statement block sets up.
    ExtensionIncomplete {
        step: &'static str,
        extension: String,
    },
    /// `sqlstate` is the server's answer, `None` when none came (a timeout or
    /// a lost connection).
    RoleLoginFailed {
        role: String,
        sqlstate: Option<String>,
    },
    EffectUnconfirmed {
        step: &'static str,
    },
    StatementFailed {
        step: &'static str,
        sqlstate: String,
    },
}

impl ProvisionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::AdminConnectFailed { .. } => "platform.provision.admin-connect-failed",
            Self::UnsupportedPostgres => "platform.provision.unsupported-postgres",
            Self::StatementNeedsPrivilege { .. } => "platform.provision.statement-needs-privilege",
            Self::RoleAttributesDiffer { .. } => "platform.provision.role-attributes-differ",
            Self::RoleMembershipDiffers { .. } => "platform.provision.role-membership-differs",
            Self::DatabaseOwnerDiffers { .. } => "platform.provision.database-owner-differs",
            Self::DatabaseIsTemplate { .. } => "platform.provision.database-is-template",
            Self::SchemaOwnerDiffers { .. } => "platform.provision.schema-owner-differs",
            Self::ExtensionTooOld { .. } => "platform.provision.extension-too-old",
            Self::ExtensionIncomplete { .. } => "platform.provision.extension-incomplete",
            Self::RoleLoginFailed { .. } => "platform.provision.role-login-failed",
            Self::EffectUnconfirmed { .. } => "platform.provision.effect-unconfirmed",
            Self::StatementFailed { .. } => "platform.provision.statement-failed",
        }
    }

    /// Whether any statement could have been sent before this error.
    pub fn may_have_run_statements(&self) -> bool {
        !matches!(
            self,
            Self::AdminConnectFailed { .. } | Self::UnsupportedPostgres
        )
    }

    /// The step of the plan the error belongs to, the report's `path`.
    pub fn step(&self) -> Option<&'static str> {
        match self {
            Self::StatementNeedsPrivilege { step, .. }
            | Self::RoleAttributesDiffer { step, .. }
            | Self::RoleMembershipDiffers { step, .. }
            | Self::SchemaOwnerDiffers { step, .. }
            | Self::ExtensionTooOld { step, .. }
            | Self::ExtensionIncomplete { step, .. }
            | Self::EffectUnconfirmed { step }
            | Self::StatementFailed { step, .. } => Some(step),
            Self::DatabaseOwnerDiffers { .. } | Self::DatabaseIsTemplate { .. } => {
                Some("database.create")
            }
            Self::AdminConnectFailed { .. }
            | Self::UnsupportedPostgres
            | Self::RoleLoginFailed { .. } => None,
        }
    }
}

fn statement_kind(step: &str) -> &str {
    match step {
        "role.migration" | "role.runtime" | "role.spatial-bbox" => "CREATE ROLE",
        "database.create" => "CREATE DATABASE",
        "database.revoke-public" => "REVOKE on the database",
        "database.grant-connect" => "GRANT CONNECT on the database",
        "database.grant-create" => "GRANT CREATE on the database",
        "database.allow-connections" => "ALTER DATABASE",
        "extension.btree-gist" => "CREATE EXTENSION btree_gist",
        "extension.postgis" => "CREATE EXTENSION postgis",
        "schema.owned" => "CREATE SCHEMA",
        "schema.public" => "GRANT on schema public",
        other => other,
    }
}

fn needed(needs: Needs) -> &'static str {
    match needs {
        Needs::CreateRole => "CREATEROLE",
        Needs::CreateDb => "CREATEDB",
        Needs::DatabaseOwner => "ownership of the database",
        Needs::Superuser => "a superuser",
    }
}

impl fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AdminConnectFailed { sqlstate: None } => {
                f.write_str("cannot open a session with the administrator URL")
            }
            Self::AdminConnectFailed {
                sqlstate: Some(sqlstate),
            } => write!(
                f,
                "cannot open a session with the administrator URL (SQLSTATE {sqlstate})"
            ),
            Self::UnsupportedPostgres => fmt::Display::fmt(&crate::plan::UnsupportedPostgres, f),
            Self::StatementNeedsPrivilege {
                step,
                needs,
                scope,
                database,
            } => {
                let place = match scope {
                    Scope::Server => "the server".to_owned(),
                    Scope::Database => format!("database \"{database}\""),
                };
                write!(
                    f,
                    "the administrator role cannot run {} in {place}; it needs {}",
                    statement_kind(step),
                    needed(*needs)
                )
            }
            Self::RoleAttributesDiffer { role, .. } => write!(
                f,
                "the role \"{role}\" already exists with attributes other than provisioning \
                 creates it with. It is not altered: use another name or correct the role as \
                 an administrator"
            ),
            Self::RoleMembershipDiffers { role, .. } => write!(
                f,
                "the role \"{role}\" already exists and is a member of a role provisioning did \
                 not grant it. It is not altered: use another name or revoke the membership as \
                 an administrator"
            ),
            Self::DatabaseIsTemplate { database } => write!(
                f,
                "the database \"{database}\" is a template database and is not adopted"
            ),
            Self::DatabaseOwnerDiffers { database } => write!(
                f,
                "the database \"{database}\" already exists under an owner the administrator \
                 role cannot act as"
            ),
            Self::SchemaOwnerDiffers {
                schema, database, ..
            } => write!(
                f,
                "the schema \"{schema}\" in database \"{database}\" already exists under a role \
                 other than the migration role"
            ),
            Self::ExtensionTooOld { extension, .. } => write!(
                f,
                "the extension \"{extension}\" is installed below the version this product needs"
            ),
            Self::ExtensionIncomplete { extension, .. } => write!(
                f,
                "the extension \"{extension}\" exists outside the schema or without the role \
                 membership its prerequisites set up"
            ),
            Self::RoleLoginFailed {
                role,
                sqlstate: None,
            } => write!(
                f,
                "the role \"{role}\" cannot open a session with its configured credential"
            ),
            Self::RoleLoginFailed {
                role,
                sqlstate: Some(sqlstate),
            } => write!(
                f,
                "the role \"{role}\" cannot open a session with its configured credential \
                 (SQLSTATE {sqlstate})"
            ),
            Self::EffectUnconfirmed { step } => write!(
                f,
                "the outcome of step {step} is unknown after a timeout or a lost connection; \
                 run provision again"
            ),
            Self::StatementFailed { step, sqlstate } => {
                write!(f, "step {step} failed on the server (SQLSTATE {sqlstate})")
            }
        }
    }
}

impl std::error::Error for ProvisionError {}

fn connect_failed(failure: ConnectFailure) -> ProvisionError {
    ProvisionError::AdminConnectFailed {
        sqlstate: failure.sqlstate,
    }
}

/// A row that did not have the shape the query selects: not a server error,
/// reported as the internal-error SQLSTATE.
fn unreadable(step: &'static str) -> ProvisionError {
    ProvisionError::StatementFailed {
        step,
        sqlstate: "XX000".to_owned(),
    }
}

fn call_error(step: &'static str, failure: CallFailure) -> ProvisionError {
    match failure {
        CallFailure::Unconfirmed => ProvisionError::EffectUnconfirmed { step },
        CallFailure::Server { sqlstate } => ProvisionError::StatementFailed { step, sqlstate },
    }
}

/// Why a run stopped, with the statements that had already run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub error: ProvisionError,
    /// The outcome of each statement before the one that failed, in plan order.
    pub reached: Vec<(&'static str, StatementOutcome)>,
}

impl From<ProvisionError> for Failure {
    fn from(error: ProvisionError) -> Self {
        Self {
            error,
            reached: Vec::new(),
        }
    }
}

/// Runs every statement of `plan` as the administrator `admin`.
///
/// In [`Mode::Converge`] the server version is checked against the shared
/// floor before the first statement. A statement with a probe runs only when
/// its object is absent, and a statement without one is re-applied. An
/// existing object in another shape is refused and never altered.
pub async fn execute(
    admin: &AdminConfig,
    plan: &Plan,
    mode: Mode,
) -> Result<Outcome, ProvisionError> {
    execute_recording(admin, plan, mode)
        .await
        .map_err(|failure| failure.error)
}

/// [`execute`] that keeps the outcomes of the statements that ran before a
/// failure, so a report can say what changed on the server.
pub async fn execute_recording(
    admin: &AdminConfig,
    plan: &Plan,
    mode: Mode,
) -> Result<Outcome, Failure> {
    let mut statements = Vec::with_capacity(plan.statements().len());
    match run_plan(admin, plan, mode, &mut statements).await {
        Ok(()) => Ok(Outcome {
            statements,
            single_role: plan.single_role(),
        }),
        Err(error) => Err(Failure {
            error,
            reached: statements,
        }),
    }
}

async fn run_plan(
    admin: &AdminConfig,
    plan: &Plan,
    mode: Mode,
    statements: &mut Vec<(&'static str, StatementOutcome)>,
) -> Result<(), ProvisionError> {
    let server = admin.connect(None).await.map_err(connect_failed)?;
    if mode == Mode::Converge {
        verify_floor(&server).await?;
    }
    let mut database: Option<Session> = None;
    for statement in plan.statements() {
        let session = match statement.scope {
            Scope::Server => &server,
            Scope::Database => match &mut database {
                Some(session) => session,
                empty => empty.insert(
                    admin
                        .connect(Some(plan.database()))
                        .await
                        .map_err(connect_failed)?,
                ),
            },
        };
        let outcome = run_statement(session, plan, statement, mode).await?;
        statements.push((statement.step, outcome));
    }
    Ok(())
}

async fn verify_floor(server: &Session) -> Result<(), ProvisionError> {
    const STEP: &str = "server.version";
    let row = bounded_call(server.client.query_one(
        "SELECT pg_catalog.current_setting('server_version_num')::int4",
        &[],
    ))
    .await
    .map_err(|failure| call_error(STEP, failure))?;
    let version: i32 = row.try_get(0).map_err(|_| unreadable(STEP))?;
    verify_server_version(version).map_err(|_| ProvisionError::UnsupportedPostgres)
}

async fn run_statement(
    session: &Session,
    plan: &Plan,
    statement: &Statement,
    mode: Mode,
) -> Result<StatementOutcome, ProvisionError> {
    if mode == Mode::Converge {
        if let Some(probe) = &statement.probe {
            if probe_is_satisfied(session, plan, statement, probe).await? {
                return Ok(StatementOutcome::Present);
            }
        }
    }
    apply(session, plan, statement).await?;
    Ok(if statement.probe.is_some() {
        StatementOutcome::Created
    } else {
        StatementOutcome::Applied
    })
}

async fn apply(
    session: &Session,
    plan: &Plan,
    statement: &Statement,
) -> Result<(), ProvisionError> {
    bounded_call(session.client.batch_execute(statement.executable()))
        .await
        .map_err(|failure| {
            if failure.lacks_privilege() {
                ProvisionError::StatementNeedsPrivilege {
                    step: statement.step,
                    needs: statement.needs,
                    scope: statement.scope,
                    database: plan.database().to_owned(),
                }
            } else {
                call_error(statement.step, failure)
            }
        })
}

/// Whether the probed object already exists in the shape the plan creates.
/// An object that exists in another shape is an error, not `false`.
async fn probe_is_satisfied(
    session: &Session,
    plan: &Plan,
    statement: &Statement,
    probe: &Probe,
) -> Result<bool, ProvisionError> {
    let step = statement.step;
    match probe {
        Probe::Role {
            name,
            login,
            member_of,
        } => {
            // Columns 1 to 7 are attributes that must be false: the six
            // flags and role-level settings. Column 8 is membership of any
            // role other than `member_of` granted as the plan grants it.
            let row = bounded_call(session.client.query_opt(
                "SELECT r.rolcanlogin, r.rolsuper, r.rolcreatedb, r.rolcreaterole, \
                        r.rolinherit, r.rolbypassrls, r.rolreplication, \
                        r.rolconfig IS NOT NULL, \
                        EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m \
                                  JOIN pg_catalog.pg_roles g ON g.oid = m.roleid \
                                 WHERE m.member = r.oid \
                                   AND NOT (coalesce(g.rolname = $2::text, false) \
                                            AND NOT m.inherit_option \
                                            AND m.set_option \
                                            AND NOT m.admin_option)) \
                   FROM pg_catalog.pg_roles r WHERE r.rolname = $1",
                &[name, member_of],
            ))
            .await
            .map_err(|failure| call_error(step, failure))?;
            let Some(row) = row else {
                return Ok(false);
            };
            let can_login: bool = row.try_get(0).map_err(|_| unreadable(step))?;
            let mut others = false;
            for column in 1..8 {
                let flag: bool = row.try_get(column).map_err(|_| unreadable(step))?;
                others |= flag;
            }
            if can_login != *login || others {
                return Err(ProvisionError::RoleAttributesDiffer {
                    step,
                    role: name.clone(),
                });
            }
            let other_membership: bool = row.try_get(8).map_err(|_| unreadable(step))?;
            if other_membership {
                return Err(ProvisionError::RoleMembershipDiffers {
                    step,
                    role: name.clone(),
                });
            }
            Ok(true)
        }
        Probe::Database { name } => {
            // Ownership privileges follow membership with INHERIT, which is
            // what `pg_has_role(..., 'USAGE')` tests, and are held by every
            // superuser.
            let row = bounded_call(session.client.query_opt(
                "SELECT pg_catalog.pg_has_role(current_user, datdba, 'USAGE'), datistemplate \
                   FROM pg_catalog.pg_database WHERE datname = $1",
                &[name],
            ))
            .await
            .map_err(|failure| call_error(step, failure))?;
            match row {
                None => Ok(false),
                Some(row) => {
                    let can_act: bool = row.try_get(0).map_err(|_| unreadable(step))?;
                    let template: bool = row.try_get(1).map_err(|_| unreadable(step))?;
                    if template {
                        Err(ProvisionError::DatabaseIsTemplate {
                            database: name.clone(),
                        })
                    } else if can_act {
                        Ok(true)
                    } else {
                        Err(ProvisionError::DatabaseOwnerDiffers {
                            database: name.clone(),
                        })
                    }
                }
            }
        }
        Probe::Extension {
            name,
            minimum_version,
            setup,
        } => {
            let row = bounded_call(session.client.query_opt(
                "SELECT extversion::text FROM pg_catalog.pg_extension WHERE extname = $1",
                &[name],
            ))
            .await
            .map_err(|failure| call_error(step, failure))?;
            let Some(row) = row else {
                return Ok(false);
            };
            let installed: String = row.try_get(0).map_err(|_| unreadable(step))?;
            if let Some(minimum) = minimum_version {
                if !version_at_least(&installed, *minimum) {
                    return Err(ProvisionError::ExtensionTooOld {
                        step,
                        extension: name.clone(),
                    });
                }
            }
            if let Some(setup) = setup {
                let row = bounded_call(session.client.query_one(
                    "SELECT coalesce((SELECT e.extnamespace = to_regnamespace($1::text)::oid \
                                        FROM pg_catalog.pg_extension e WHERE e.extname = $2), \
                                     false), \
                            pg_catalog.pg_has_role($3::text::name, $4::text::name, 'SET')",
                    &[&setup.schema, name, &setup.member, &setup.role],
                ))
                .await
                .map_err(|failure| call_error(step, failure))?;
                let in_schema: bool = row.try_get(0).map_err(|_| unreadable(step))?;
                let can_set: bool = row.try_get(1).map_err(|_| unreadable(step))?;
                if !in_schema || !can_set {
                    return Err(ProvisionError::ExtensionIncomplete {
                        step,
                        extension: name.clone(),
                    });
                }
            }
            Ok(true)
        }
        Probe::Schema { name, owner } => {
            let row = bounded_call(session.client.query_opt(
                "SELECT pg_catalog.pg_get_userbyid(nspowner)::text \
                   FROM pg_catalog.pg_namespace WHERE nspname = $1",
                &[name],
            ))
            .await
            .map_err(|failure| call_error(step, failure))?;
            match row {
                None => Ok(false),
                Some(row) => {
                    let actual: String = row.try_get(0).map_err(|_| unreadable(step))?;
                    if actual == *owner {
                        Ok(true)
                    } else {
                        Err(ProvisionError::SchemaOwnerDiffers {
                            step,
                            schema: name.clone(),
                            database: plan.database().to_owned(),
                        })
                    }
                }
            }
        }
    }
}

/// Compares the leading `major.minor` of an extension version such as
/// `3.5.2` or `3.6.0dev`.
fn version_at_least(version: &str, minimum: (u32, u32)) -> bool {
    let mut parts = version.split('.').map(|part| {
        part.chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse::<u32>()
            .ok()
    });
    match (parts.next().flatten(), parts.next().flatten()) {
        (Some(major), Some(minor)) => (major, minor) >= minimum,
        _ => false,
    }
}

/// Opens one session per product role, in the provisioned database, and asks
/// each who it is. A role that already existed keeps its stored password, so
/// this is what tells an operator that the configured credential does not
/// open a session. The administrator URL supplies only the endpoint and TLS.
pub async fn verify_logins(
    admin: &AdminConfig,
    target: &ProvisionTarget,
) -> Result<(), ProvisionError> {
    let mut roles = vec![&target.migration];
    if target.runtime.name != target.migration.name {
        roles.push(&target.runtime);
    }
    for role in roles {
        let failed = |sqlstate: Option<String>| ProvisionError::RoleLoginFailed {
            role: role.name.clone(),
            sqlstate,
        };
        let session = admin
            .connect_as(&target.database, &role.name, role.password())
            .await
            .map_err(|failure| failed(failure.sqlstate))?;
        let row = bounded_call(session.client.query_one("SELECT current_user::text", &[]))
            .await
            .map_err(|failure| {
                failed(match failure {
                    CallFailure::Server { sqlstate } => Some(sqlstate),
                    CallFailure::Unconfirmed => None,
                })
            })?;
        let current: String = row
            .try_get(0)
            .map_err(|_| failed(Some("XX000".to_owned())))?;
        if current != role.name {
            return Err(failed(Some("XX000".to_owned())));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_versions_compare_by_major_and_minor() {
        assert!(version_at_least("3.5.2", (3, 5)));
        assert!(version_at_least("3.6.0dev", (3, 5)));
        assert!(version_at_least("4.0.0", (3, 5)));
        assert!(!version_at_least("3.4.9", (3, 5)));
        assert!(!version_at_least("3", (3, 5)));
        assert!(!version_at_least("not a version", (3, 5)));
    }

    #[test]
    fn every_code_is_distinct_and_in_the_provision_family() {
        let errors = [
            ProvisionError::AdminConnectFailed { sqlstate: None },
            ProvisionError::UnsupportedPostgres,
            ProvisionError::StatementNeedsPrivilege {
                step: "database.create",
                needs: Needs::CreateDb,
                scope: Scope::Server,
                database: "d".to_owned(),
            },
            ProvisionError::RoleAttributesDiffer {
                step: "role.migration",
                role: "r".to_owned(),
            },
            ProvisionError::RoleMembershipDiffers {
                step: "role.runtime",
                role: "r".to_owned(),
            },
            ProvisionError::DatabaseOwnerDiffers {
                database: "d".to_owned(),
            },
            ProvisionError::DatabaseIsTemplate {
                database: "d".to_owned(),
            },
            ProvisionError::SchemaOwnerDiffers {
                step: "schema.owned",
                schema: "s".to_owned(),
                database: "d".to_owned(),
            },
            ProvisionError::ExtensionTooOld {
                step: "extension.postgis",
                extension: "postgis".to_owned(),
            },
            ProvisionError::ExtensionIncomplete {
                step: "extension.postgis",
                extension: "postgis".to_owned(),
            },
            ProvisionError::RoleLoginFailed {
                role: "r".to_owned(),
                sqlstate: Some("28P01".to_owned()),
            },
            ProvisionError::EffectUnconfirmed {
                step: "role.runtime",
            },
            ProvisionError::StatementFailed {
                step: "role.runtime",
                sqlstate: "42710".to_owned(),
            },
        ];
        let mut codes: Vec<&str> = errors.iter().map(ProvisionError::code).collect();
        assert!(codes
            .iter()
            .all(|code| code.starts_with("platform.provision.")));
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errors.len());
    }

    #[test]
    fn the_floor_error_uses_the_ledger_sentence() {
        assert!(ProvisionError::UnsupportedPostgres
            .to_string()
            .starts_with("PostgreSQL 17 or newer is required"));
    }
}

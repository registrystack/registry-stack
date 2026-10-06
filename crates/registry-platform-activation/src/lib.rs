// SPDX-License-Identifier: Apache-2.0
//! Shared PostgreSQL package activation ledger and runtime-role boundary.

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio_postgres::GenericClient;
use uuid::Uuid;

/// Said wherever the effective role mode is `single`.
pub const SINGLE_ROLE_STATEMENT: &str =
    "single-role mode: the ledger check catches a wrong package, but not someone holding this credential";

const ACTIVATION_COLUMNS: &str = "activation_id,apply_order,package_digest,\
    predecessor_package_digest,database_id,plan_kind,applied_at,\
    operator_reference_hash,backup_references,role_mode";

/// One trigger installed by a product migration and therefore allowed on a
/// product-owned relation in split-role mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KnownTrigger {
    pub relation: &'static str,
    pub trigger: &'static str,
    pub function: &'static str,
}

/// Trusted names describing one product's activation relations and objects.
#[derive(Clone, Debug)]
pub struct Layout {
    object_prefix: &'static str,
    ledger_relation: &'static str,
    migrations_relation: &'static str,
    known_triggers: &'static [KnownTrigger],
    stores_runtime_role: bool,
    sequence_select: bool,
}

impl Layout {
    /// Build a layout from product-owned static PostgreSQL identifiers.
    pub fn new(
        object_prefix: &'static str,
        ledger_relation: &'static str,
        migrations_relation: &'static str,
        known_triggers: &'static [KnownTrigger],
        stores_runtime_role: bool,
    ) -> Result<Self, Error> {
        for identifier in [object_prefix, ledger_relation, migrations_relation] {
            if !valid_identifier(identifier) {
                return Err(Error::InvalidLayout);
            }
        }
        for known in known_triggers {
            for identifier in [known.relation, known.trigger, known.function] {
                if !valid_identifier(identifier) {
                    return Err(Error::InvalidLayout);
                }
            }
        }
        Ok(Self {
            object_prefix,
            ledger_relation,
            migrations_relation,
            known_triggers,
            stores_runtime_role,
            sequence_select: false,
        })
    }

    /// Require and grant `SELECT` in addition to `USAGE` on owned sequences.
    #[must_use]
    pub fn with_sequence_select(mut self) -> Self {
        self.sequence_select = true;
        self
    }

    #[must_use]
    pub fn ledger_relation(&self) -> &'static str {
        self.ledger_relation
    }

    fn relation_pattern(&self) -> String {
        format!("{}\\_%", self.object_prefix)
    }

    fn trigger_columns(&self) -> [Vec<&'static str>; 3] {
        [
            self.known_triggers
                .iter()
                .map(|known| known.relation)
                .collect(),
            self.known_triggers
                .iter()
                .map(|known| known.trigger)
                .collect(),
            self.known_triggers
                .iter()
                .map(|known| known.function)
                .collect(),
        ]
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.bytes().enumerate().all(|(at, byte)| {
            byte == b'_' || byte.is_ascii_lowercase() || (at > 0 && byte.is_ascii_digit())
        })
}

/// A failure in the shared activation persistence boundary.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the activation layout contains an invalid PostgreSQL identifier")]
    InvalidLayout,
    #[error("PostgreSQL 17 or newer is required; upgrade the database server before activating or serving a package")]
    UnsupportedPostgres,
    #[error("the activation ledger is corrupt")]
    Corrupt,
    #[error(transparent)]
    Database(#[from] tokio_postgres::Error),
}

/// Whether the runtime credential can write the activation ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RoleMode {
    Single,
    Split,
}

impl RoleMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Split => "split",
        }
    }

    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "single" => Ok(Self::Single),
            "split" => Ok(Self::Split),
            _ => Err(Error::Corrupt),
        }
    }
}

/// Whether an activation is the database's first or follows another.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PlanKind {
    Initial,
    Successor,
}

impl PlanKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Successor => "successor",
        }
    }

    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "initial" => Ok(Self::Initial),
            "successor" => Ok(Self::Successor),
            _ => Err(Error::Corrupt),
        }
    }
}

/// One append-only package activation ledger row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Activation {
    pub activation_id: Uuid,
    pub apply_order: i64,
    pub package_digest: String,
    pub predecessor_package_digest: Option<String>,
    pub database_id: String,
    pub plan_kind: PlanKind,
    pub applied_at: DateTime<Utc>,
    pub operator_reference_hash: Option<String>,
    pub backup_references: Vec<String>,
    pub role_mode: RoleMode,
    /// Present for ledgers that retain the PostgreSQL runtime user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_role: Option<String>,
}

/// Values used to append one activation row.
pub struct NewActivation<'a> {
    pub activation_id: Uuid,
    pub package_digest: &'a str,
    pub database_id: &'a str,
    pub operator_reference_hash: Option<&'a str>,
    pub backup_references: &'a [String],
    pub role_mode: RoleMode,
    pub runtime_role: Option<&'a str>,
}

/// How a configured deployment identity compares with the ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DatabaseIdCheck {
    NotRecorded,
    Matches,
    Differs,
}

/// The runtime role's effective authority over product-owned objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleObservation {
    pub mode: RoleMode,
    pub grants_current: bool,
    pub readable: bool,
}

/// Applied and pending versions of one product schema.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SchemaState {
    pub applied: Vec<i64>,
    pub pending: Vec<i64>,
}

impl SchemaState {
    #[must_use]
    pub fn current(&self) -> Option<i64> {
        self.applied.iter().copied().max()
    }
}

/// Observe the schema migration ledger and derive pending versions.
pub async fn schema_state(
    client: &impl GenericClient,
    layout: &Layout,
    known_versions: &[i64],
) -> Result<SchemaState, Error> {
    let applied = if relation_exists(client, layout.migrations_relation).await? {
        client
            .query(
                &format!(
                    "SELECT version FROM {} ORDER BY version",
                    layout.migrations_relation
                ),
                &[],
            )
            .await?
            .iter()
            .map(|row| row.try_get(0))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    let pending = known_versions
        .iter()
        .copied()
        .filter(|version| !applied.contains(version))
        .collect();
    Ok(SchemaState { applied, pending })
}

/// Whether a relation visible through this connection's search path exists.
/// Refuses PostgreSQL older than 17 before reading an activation or migration ledger.
pub async fn relation_exists(client: &impl GenericClient, relation: &str) -> Result<bool, Error> {
    let row = client
        .query_one(
            "SELECT current_setting('server_version_num')::integer, to_regclass($1) IS NOT NULL",
            &[&relation],
        )
        .await?;
    verify_postgres_version(row.get(0))?;
    Ok(row.get(1))
}

fn verify_postgres_version(version_num: i32) -> Result<(), Error> {
    if version_num < 170_000 {
        return Err(Error::UnsupportedPostgres);
    }
    Ok(())
}

/// Read the latest activation row, if the database has been activated.
pub async fn active_activation(
    client: &impl GenericClient,
    layout: &Layout,
) -> Result<Option<Activation>, Error> {
    if !relation_exists(client, layout.ledger_relation).await? {
        return Ok(None);
    }
    let columns = activation_columns(layout);
    client
        .query_opt(
            &format!(
                "SELECT {columns} FROM {} ORDER BY apply_order DESC LIMIT 1",
                layout.ledger_relation
            ),
            &[],
        )
        .await?
        .as_ref()
        .map(|row| activation_from_row(row, layout))
        .transpose()
}

/// Read every activation row, oldest first.
pub async fn activation_history(
    client: &impl GenericClient,
    layout: &Layout,
) -> Result<Vec<Activation>, Error> {
    if !relation_exists(client, layout.ledger_relation).await? {
        return Ok(Vec::new());
    }
    let columns = activation_columns(layout);
    client
        .query(
            &format!(
                "SELECT {columns} FROM {} ORDER BY apply_order",
                layout.ledger_relation
            ),
            &[],
        )
        .await?
        .iter()
        .map(|row| activation_from_row(row, layout))
        .collect()
}

fn activation_columns(layout: &Layout) -> String {
    if layout.stores_runtime_role {
        format!("{ACTIVATION_COLUMNS},runtime_role")
    } else {
        ACTIVATION_COLUMNS.to_owned()
    }
}

fn activation_from_row(row: &tokio_postgres::Row, layout: &Layout) -> Result<Activation, Error> {
    Ok(Activation {
        activation_id: row.try_get(0)?,
        apply_order: row.try_get(1)?,
        package_digest: row.try_get(2)?,
        predecessor_package_digest: row.try_get(3)?,
        database_id: row.try_get(4)?,
        plan_kind: PlanKind::parse(row.try_get(5)?)?,
        applied_at: row.try_get(6)?,
        operator_reference_hash: row.try_get(7)?,
        backup_references: row.try_get(8)?,
        role_mode: RoleMode::parse(row.try_get(9)?)?,
        runtime_role: if layout.stores_runtime_role {
            Some(row.try_get(10)?)
        } else {
            None
        },
    })
}

/// Append one activation row and return exactly what the database recorded.
pub async fn append_activation(
    client: &impl GenericClient,
    layout: &Layout,
    request: &NewActivation<'_>,
) -> Result<Activation, Error> {
    let active = active_activation(client, layout).await?;
    let predecessor = active.as_ref().map(|row| row.package_digest.as_str());
    let plan_kind = if active.is_some() {
        PlanKind::Successor
    } else {
        PlanKind::Initial
    };
    let columns = activation_columns(layout);
    let row = if layout.stores_runtime_role {
        let runtime_role = request.runtime_role.ok_or(Error::Corrupt)?;
        client
            .query_one(
                &format!(
                    "INSERT INTO {}({columns}) \
                     SELECT $1,COALESCE(max(apply_order),0)+1,$2,$3,$4,$5,now(),$6,$7,$8,$9 \
                     FROM {} RETURNING {columns}",
                    layout.ledger_relation, layout.ledger_relation
                ),
                &[
                    &request.activation_id,
                    &request.package_digest,
                    &predecessor,
                    &request.database_id,
                    &plan_kind.as_str(),
                    &request.operator_reference_hash,
                    &request.backup_references,
                    &request.role_mode.as_str(),
                    &runtime_role,
                ],
            )
            .await?
    } else {
        client
            .query_one(
                &format!(
                    "INSERT INTO {}({columns}) \
                     SELECT $1,COALESCE(max(apply_order),0)+1,$2,$3,$4,$5,now(),$6,$7,$8 \
                     FROM {} RETURNING {columns}",
                    layout.ledger_relation, layout.ledger_relation
                ),
                &[
                    &request.activation_id,
                    &request.package_digest,
                    &predecessor,
                    &request.database_id,
                    &plan_kind.as_str(),
                    &request.operator_reference_hash,
                    &request.backup_references,
                    &request.role_mode.as_str(),
                ],
            )
            .await?
    };
    activation_from_row(&row, layout)
}

/// Whether the ledger contains an activation id, for commit read-back.
pub async fn activation_recorded(
    client: &impl GenericClient,
    layout: &Layout,
    activation_id: Uuid,
) -> Result<bool, Error> {
    if !relation_exists(client, layout.ledger_relation).await? {
        return Ok(false);
    }
    Ok(client
        .query_one(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM {} WHERE activation_id=$1)",
                layout.ledger_relation
            ),
            &[&activation_id],
        )
        .await?
        .get(0))
}

/// Compare the configured database id with the ledger without disclosing
/// either value in a diagnostic.
#[must_use]
pub fn database_id_check(active: Option<&Activation>, expected: &str) -> DatabaseIdCheck {
    match active {
        None => DatabaseIdCheck::NotRecorded,
        Some(active) if active.database_id == expected => DatabaseIdCheck::Matches,
        Some(_) => DatabaseIdCheck::Differs,
    }
}

/// Verify the package and database identity a runtime must serve.
pub async fn check_active_package(
    client: &impl GenericClient,
    layout: &Layout,
    database_id: &str,
    package_digest: &str,
) -> Result<Activation, ActivePackageError> {
    let active = active_activation(client, layout)
        .await?
        .ok_or(ActivePackageError::NotActivated)?;
    if active.database_id != database_id {
        return Err(ActivePackageError::DatabaseIdMismatch);
    }
    if active.package_digest != package_digest {
        return Err(ActivePackageError::PackageNotActive {
            active: active.package_digest,
            candidate: package_digest.to_owned(),
        });
    }
    Ok(active)
}

#[derive(Debug, thiserror::Error)]
pub enum ActivePackageError {
    #[error("no package is active")]
    NotActivated,
    #[error("the database belongs to another deployment")]
    DatabaseIdMismatch,
    #[error("package {candidate} is not active; the database serves {active}")]
    PackageNotActive { active: String, candidate: String },
    #[error(transparent)]
    Activation(#[from] Error),
}

/// The schema hiding an activation ledger this connection cannot read.
pub async fn unreadable_ledger(
    client: &impl GenericClient,
    layout: &Layout,
) -> Result<Option<String>, Error> {
    let row = client
        .query_opt(
            "SELECT n.nspname::text,
               has_schema_privilege(n.oid, 'USAGE')
               AND has_table_privilege(a.oid, 'SELECT')
               AND (m.oid IS NULL OR has_table_privilege(m.oid, 'SELECT'))
             FROM unnest(string_to_array(current_setting('search_path'), ','))
               WITH ORDINALITY AS p(entry, position)
             JOIN pg_namespace n ON n.nspname = CASE btrim(btrim(p.entry), '\"')
               WHEN '$user' THEN current_user::text ELSE btrim(btrim(p.entry), '\"') END
             JOIN pg_class a ON a.relnamespace=n.oid AND a.relname=$1
             LEFT JOIN pg_class m ON m.relnamespace=n.oid AND m.relname=$2
             ORDER BY p.position LIMIT 1",
            &[&layout.ledger_relation, &layout.migrations_relation],
        )
        .await?;
    Ok(row
        .filter(|row| !row.get::<_, bool>(1))
        .map(|row| row.get(0)))
}

/// Observe one role's write authority and required runtime grants.
pub async fn observe_role(
    client: &impl GenericClient,
    layout: &Layout,
    role: Option<&str>,
    extra_relations: &[String],
) -> Result<Option<RoleObservation>, Error> {
    let [tables, triggers, functions] = layout.trigger_columns();
    let pattern = layout.relation_pattern();
    let Some(row) = client
        .query_opt(
            "SELECT
               r.rolsuper OR r.rolbypassrls
               OR has_table_privilege(r.oid,c.oid,'DELETE,TRUNCATE')
               OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE')
               OR pg_has_role(r.oid,c.relowner,'MEMBER')
               OR pg_has_role(r.oid,n.nspowner,'MEMBER')
               OR ($1::text IS NOT NULL AND pg_has_role(r.oid,current_user,'MEMBER'))
               OR COALESCE(has_table_privilege(r.oid,to_regclass($2)::oid,'DELETE,TRUNCATE'),false)
               OR COALESCE(has_any_column_privilege(r.oid,to_regclass($2)::oid,'INSERT,UPDATE'),false)
               OR has_schema_privilege(r.oid,n.oid,'CREATE')
               OR EXISTS(SELECT 1 FROM pg_class t WHERE t.relnamespace=n.oid
                 AND (t.relname LIKE $3 OR format('%I.%I',n.nspname,t.relname)=ANY($4::text[]))
                 AND t.relkind IN ('r','p','v','m','S','f')
                 AND (pg_has_role(r.oid,t.relowner,'MEMBER')
                   OR (t.relkind IN ('r','p','v') AND has_table_privilege(r.oid,t.oid,'TRIGGER'))))
               OR EXISTS(SELECT 1 FROM pg_proc p WHERE p.pronamespace=n.oid
                 AND p.proname LIKE $3 AND pg_has_role(r.oid,p.proowner,'MEMBER'))
               OR EXISTS(SELECT 1 FROM pg_trigger g JOIN pg_class t ON t.oid=g.tgrelid
                 WHERE t.relnamespace=n.oid AND t.relname LIKE $3 AND NOT g.tgisinternal
                 AND NOT EXISTS(SELECT 1 FROM unnest($5::text[],$6::text[],$7::text[]) k(relname,tgname,proname)
                   JOIN pg_proc f ON f.oid=g.tgfoid WHERE k.relname=t.relname AND k.tgname=g.tgname
                     AND f.proname=k.proname AND f.pronamespace=n.oid)),
               has_schema_privilege(r.oid,n.oid,'USAGE')
               AND NOT EXISTS(SELECT 1 FROM pg_class t WHERE t.relnamespace=n.oid
                 AND (t.relname LIKE $3 OR format('%I.%I',n.nspname,t.relname)=ANY($4::text[]))
                 AND t.relkind IN ('r','p','v','m','f','S') AND NOT CASE
                   WHEN t.relkind='S' THEN has_sequence_privilege(r.oid,t.oid,'USAGE')
                     AND (NOT $9::boolean OR has_sequence_privilege(r.oid,t.oid,'SELECT'))
                   WHEN t.relname IN ($8,$2) THEN has_table_privilege(r.oid,t.oid,'SELECT')
                   ELSE has_table_privilege(r.oid,t.oid,'SELECT')
                     AND has_table_privilege(r.oid,t.oid,'INSERT')
                     AND has_table_privilege(r.oid,t.oid,'UPDATE')
                     AND has_table_privilege(r.oid,t.oid,'DELETE') END)
               AND NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.pronamespace=n.oid
                 AND p.proname LIKE $3 AND p.prokind='f'
                 AND NOT has_function_privilege(r.oid,p.oid,'EXECUTE')),
               has_schema_privilege(r.oid,n.oid,'USAGE')
               AND NOT EXISTS(SELECT 1 FROM pg_class t WHERE t.relnamespace=n.oid
                 AND (t.relname LIKE $3 OR format('%I.%I',n.nspname,t.relname)=ANY($4::text[]))
                 AND t.relkind IN ('r','p','v','m','f')
                 AND NOT has_table_privilege(r.oid,t.oid,'SELECT'))
             FROM pg_roles r, pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE r.rolname=COALESCE($1::text,current_user::text) AND c.oid=to_regclass($8)",
            &[
                &role,
                &layout.migrations_relation,
                &pattern,
                &extra_relations,
                &tables,
                &triggers,
                &functions,
                &layout.ledger_relation,
                &layout.sequence_select,
            ],
        )
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(RoleObservation {
        mode: if row.get(0) {
            RoleMode::Single
        } else {
            RoleMode::Split
        },
        grants_current: row.get(1),
        readable: row.get(2),
    }))
}

/// SQL statements that remove a runtime role's indirect authority to write
/// the activation ledger through migration-owned code.
pub async fn stray_authority(
    client: &impl GenericClient,
    layout: &Layout,
    role: Option<&str>,
) -> Result<Vec<String>, Error> {
    let [tables, triggers, functions] = layout.trigger_columns();
    let pattern = layout.relation_pattern();
    let Some(row) = client
        .query_opt(
            "WITH reference AS (SELECT CASE WHEN $1::text IS NOT NULL
                 THEN (SELECT oid FROM pg_roles WHERE rolname=current_user::text)
                 ELSE (SELECT relowner FROM pg_class WHERE oid=to_regclass($2)) END AS oid)
             SELECT r.rolsuper OR reference.oid IS NULL OR pg_has_role(r.oid,reference.oid,'MEMBER')
                 OR pg_has_role(r.oid,n.nspowner,'MEMBER'),
               quote_ident(COALESCE((SELECT rolname FROM pg_roles WHERE oid=reference.oid),'')),
               quote_ident(n.nspname),
               ARRAY(SELECT DISTINCT quote_ident(o.rolname) FROM (
                 SELECT c.relowner owner FROM pg_class c WHERE c.relnamespace=n.oid
                   AND c.relname LIKE $3 AND c.relkind IN ('r','p','v','m','S','f')
                 UNION SELECT p.proowner FROM pg_proc p WHERE p.pronamespace=n.oid AND p.proname LIKE $3
               ) owned JOIN pg_roles o ON o.oid=owned.owner
                 WHERE pg_has_role(r.oid,owned.owner,'MEMBER') ORDER BY 1),
               ARRAY(SELECT DISTINCT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE quote_ident(g.rolname) END
                 FROM aclexplode(n.nspacl) a LEFT JOIN pg_roles g ON g.oid=a.grantee
                 WHERE a.privilege_type='CREATE' AND (a.grantee=0 OR pg_has_role(r.oid,a.grantee,'MEMBER')) ORDER BY 1),
               ARRAY(SELECT DISTINCT format('%s.%s FROM %s',quote_ident(n.nspname),quote_ident(t.relname),
                   CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE quote_ident(g.rolname) END)
                 FROM pg_class t,aclexplode(t.relacl) a LEFT JOIN pg_roles g ON g.oid=a.grantee
                 WHERE t.relnamespace=n.oid AND t.relname LIKE $3 AND t.relkind IN ('r','p','v')
                   AND a.privilege_type='TRIGGER' AND (a.grantee=0 OR pg_has_role(r.oid,a.grantee,'MEMBER')) ORDER BY 1),
               ARRAY(SELECT format('%s ON %s.%s',quote_ident(g.tgname),quote_ident(n.nspname),quote_ident(t.relname))
                 FROM pg_trigger g JOIN pg_class t ON t.oid=g.tgrelid
                 WHERE t.relnamespace=n.oid AND t.relname LIKE $3 AND NOT g.tgisinternal
                   AND NOT EXISTS(SELECT 1 FROM unnest($4::text[],$5::text[],$6::text[]) k(relname,tgname,proname)
                     JOIN pg_proc f ON f.oid=g.tgfoid WHERE k.relname=t.relname AND k.tgname=g.tgname
                       AND f.proname=k.proname AND f.pronamespace=n.oid)
                 ORDER BY t.relname,g.tgname)
             FROM pg_roles r,pg_namespace n,reference
             WHERE r.rolname=COALESCE($1::text,current_user::text) AND n.nspname=current_schema()",
            &[&role, &layout.ledger_relation, &pattern, &tables, &triggers, &functions],
        )
        .await?
    else {
        return Ok(Vec::new());
    };
    if row.get(0) {
        return Ok(Vec::new());
    }
    let migration_role: String = row.get(1);
    let schema: String = row.get(2);
    let owners: Vec<String> = row.get(3);
    let grantees: Vec<String> = row.get(4);
    let trigger_grants: Vec<String> = row.get(5);
    let stray_triggers: Vec<String> = row.get(6);
    Ok(owners
        .into_iter()
        .map(|owner| format!("REASSIGN OWNED BY {owner} TO {migration_role}"))
        .chain(
            grantees
                .into_iter()
                .map(|grantee| format!("REVOKE CREATE ON SCHEMA {schema} FROM {grantee}")),
        )
        .chain(
            trigger_grants
                .into_iter()
                .map(|grant| format!("REVOKE TRIGGER ON {grant}")),
        )
        .chain(
            stray_triggers
                .into_iter()
                .map(|trigger| format!("DROP TRIGGER {trigger}")),
        )
        .collect())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachedTrigger {
    pub name: String,
    pub relation: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityCause {
    OwnedObject { owner: String },
    TriggerPrivilege { relation: String, grantee: String },
    SchemaCreate { grantee: String },
    AttachedTriggers(Vec<AttachedTrigger>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityWeakness {
    pub runtime_role: String,
    pub schema: String,
    pub migration_role: String,
    pub cause: AuthorityCause,
}

/// The first indirect path through which `role` can write migration-owned
/// state, with quoted names so the consuming product can preserve its own
/// refusal vocabulary.
pub async fn first_authority_weakness(
    client: &impl GenericClient,
    layout: &Layout,
    role: &str,
) -> Result<Option<AuthorityWeakness>, Error> {
    let pattern = layout.relation_pattern();
    let Some(row) = client
        .query_opt(
            "SELECT quote_ident(r.rolname),quote_ident(n.nspname),
               quote_ident(pg_get_userbyid(c.relowner)),
               (SELECT quote_ident(pg_get_userbyid(owner)) FROM (
                 SELECT n.nspowner owner UNION ALL
                 SELECT o.relowner FROM pg_class o WHERE o.relnamespace=n.oid AND o.relname LIKE $3
                 UNION ALL SELECT p.proowner FROM pg_proc p WHERE p.pronamespace=n.oid AND p.proname LIKE $3
               ) owners WHERE pg_has_role(r.oid,owner,'MEMBER')
                 ORDER BY owner=r.oid DESC,pg_get_userbyid(owner) LIMIT 1),
               triggers.relation,triggers.grantee,
               has_schema_privilege(r.oid,n.oid,'CREATE'),
               (SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(a.grantee)) END
                 FROM aclexplode(n.nspacl) a WHERE a.privilege_type='CREATE'
                   AND (a.grantee=0 OR pg_has_role(r.oid,a.grantee,'MEMBER'))
                 ORDER BY a.grantee=r.oid DESC,a.grantee=0 DESC LIMIT 1)
             FROM pg_roles r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             LEFT JOIN LATERAL (
               SELECT format('%I.%I',n.nspname,t.relname) relation,
                 (SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(a.grantee)) END
                   FROM aclexplode(t.relacl) a WHERE a.privilege_type='TRIGGER'
                     AND (a.grantee=0 OR pg_has_role(r.oid,a.grantee,'MEMBER'))
                   ORDER BY a.grantee=r.oid DESC,a.grantee=0 DESC LIMIT 1) grantee
               FROM pg_class t WHERE t.relnamespace=n.oid AND t.relname LIKE $3
                 AND t.relkind IN ('r','p','v','m','f') AND has_table_privilege(r.oid,t.oid,'TRIGGER')
               ORDER BY t.relname LIMIT 1
             ) triggers ON true
             WHERE r.rolname=$1 AND c.oid=to_regclass($2)
               AND NOT pg_has_role(r.oid,c.relowner,'MEMBER') AND NOT r.rolsuper",
            &[&role, &layout.ledger_relation, &pattern],
        )
        .await?
    else {
        return Ok(None);
    };
    let runtime_role: String = row.get(0);
    let schema: String = row.get(1);
    let migration_role: String = row.get(2);
    let owner: Option<String> = row.get(3);
    let trigger_relation: Option<String> = row.get(4);
    let trigger_grantee: Option<String> = row.get(5);
    let creates: bool = row.get(6);
    let create_grantee: Option<String> = row.get(7);
    let cause = if let Some(owner) = owner {
        AuthorityCause::OwnedObject { owner }
    } else if let Some(relation) = trigger_relation {
        AuthorityCause::TriggerPrivilege {
            relation,
            grantee: trigger_grantee.unwrap_or_else(|| runtime_role.clone()),
        }
    } else if creates {
        AuthorityCause::SchemaCreate {
            grantee: create_grantee.unwrap_or_else(|| runtime_role.clone()),
        }
    } else {
        let [tables, triggers, functions] = layout.trigger_columns();
        let attached = client
            .query(
                "SELECT quote_ident(g.tgname),format('%I.%I',n.nspname,t.relname)
                 FROM pg_trigger g JOIN pg_class t ON t.oid=g.tgrelid
                 JOIN pg_namespace n ON n.oid=t.relnamespace
                 WHERE NOT g.tgisinternal AND t.relname LIKE $1
                   AND n.oid=(SELECT relnamespace FROM pg_class WHERE oid=to_regclass($2))
                   AND NOT EXISTS(SELECT 1 FROM unnest($3::text[],$4::text[],$5::text[]) k(relname,tgname,proname)
                     JOIN pg_proc f ON f.oid=g.tgfoid WHERE k.relname=t.relname AND k.tgname=g.tgname
                       AND f.proname=k.proname AND f.pronamespace=n.oid)
                 ORDER BY 2,1",
                &[&pattern, &layout.ledger_relation, &tables, &triggers, &functions],
            )
            .await?
            .iter()
            .map(|row| AttachedTrigger {
                name: row.get(0),
                relation: row.get(1),
            })
            .collect::<Vec<_>>();
        if attached.is_empty() {
            return Ok(None);
        }
        AuthorityCause::AttachedTriggers(attached)
    };
    Ok(Some(AuthorityWeakness {
        runtime_role,
        schema,
        migration_role,
        cause,
    }))
}

/// A statement that removes a migration-role default TRIGGER grant inherited
/// by the runtime role, if one exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultTriggerGrant {
    pub runtime_role: String,
    pub migration_role: String,
    pub scope: String,
    pub grantee: String,
}

impl DefaultTriggerGrant {
    #[must_use]
    pub fn statement(&self) -> String {
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {}{} REVOKE TRIGGER ON TABLES FROM {}",
            self.migration_role, self.scope, self.grantee
        )
    }
}

pub async fn default_trigger_grant(
    client: &impl GenericClient,
    role: &str,
) -> Result<Option<DefaultTriggerGrant>, Error> {
    Ok(client
        .query_opt(
            "SELECT quote_ident(r.rolname),quote_ident(current_user::text),
               CASE WHEN d.defaclnamespace=0 THEN '' ELSE ' IN SCHEMA '||quote_ident(n.nspname) END,
               CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(a.grantee)) END
             FROM pg_roles r CROSS JOIN pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a
             LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace
             WHERE r.rolname=$1 AND d.defaclrole=(SELECT oid FROM pg_roles WHERE rolname=current_user)
               AND d.defaclobjtype='r' AND (d.defaclnamespace=0 OR n.nspname=current_schema())
               AND a.privilege_type='TRIGGER' AND (a.grantee=0 OR pg_has_role(r.oid,a.grantee,'MEMBER'))
             ORDER BY a.grantee=r.oid DESC,a.grantee=0 DESC,d.defaclnamespace DESC LIMIT 1",
            &[&role],
        )
        .await?
        .map(|row| DefaultTriggerGrant {
            runtime_role: row.get(0),
            migration_role: row.get(1),
            scope: row.get(2),
            grantee: row.get(3),
        }))
}

/// Grant the runtime role access to product-owned objects while withholding
/// writes to the activation and schema ledgers.
pub async fn grant_runtime_role(
    client: &impl GenericClient,
    layout: &Layout,
    runtime_role: &str,
    extra_relations: &[String],
) -> Result<(), Error> {
    let row = client
        .query_one(
            "SELECT quote_ident($1),quote_ident(current_schema())",
            &[&runtime_role],
        )
        .await?;
    let role: String = row.get(0);
    let schema: String = row.get(1);
    let pattern = layout.relation_pattern();
    let mut statements = vec![format!("GRANT USAGE ON SCHEMA {schema} TO {role}")];
    for row in client
        .query(
            "SELECT format('%I.%I',n.nspname,c.relname),c.relkind::text
             FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname=current_schema()
               AND (c.relname LIKE $1 OR format('%I.%I',n.nspname,c.relname)=ANY($2::text[]))
               AND c.relkind IN ('r','p','v','m','f','S') ORDER BY c.relname",
            &[&pattern, &extra_relations],
        )
        .await?
    {
        let name: String = row.get(0);
        let kind: String = row.get(1);
        statements.push(if kind == "S" && layout.sequence_select {
            format!("GRANT USAGE, SELECT ON SEQUENCE {name} TO {role}")
        } else if kind == "S" {
            format!("GRANT USAGE ON SEQUENCE {name} TO {role}")
        } else {
            format!("GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {name} TO {role}")
        });
    }
    for row in client
        .query(
            "SELECT format('%I.%I(%s)',n.nspname,p.proname,pg_get_function_identity_arguments(p.oid))
             FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
             WHERE n.nspname=current_schema() AND p.proname LIKE $1 AND p.prokind='f' ORDER BY 1",
            &[&pattern],
        )
        .await?
    {
        let name: String = row.get(0);
        statements.push(format!("GRANT EXECUTE ON FUNCTION {name} TO {role}"));
    }
    for ledger in [layout.ledger_relation, layout.migrations_relation] {
        statements.push(format!(
            "REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON TABLE {schema}.{ledger} FROM {role}"
        ));
        statements.push(format!("REVOKE ALL ON TABLE {schema}.{ledger} FROM PUBLIC"));
        statements.push(format!("GRANT SELECT ON TABLE {schema}.{ledger} TO {role}"));
    }
    for statement in statements {
        client.batch_execute(&statement).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_version_floor_refuses_16_and_accepts_17_or_newer() {
        for version in [150_000, 160_999, 169_999] {
            assert!(matches!(
                verify_postgres_version(version),
                Err(Error::UnsupportedPostgres)
            ));
        }
        for version in [170_000, 170_011, 180_000] {
            assert!(verify_postgres_version(version).is_ok());
        }
    }

    #[test]
    fn layouts_accept_only_unquoted_postgres_identifiers() {
        assert!(Layout::new(
            "casework",
            "casework_activations",
            "casework_schema_migrations",
            &[],
            false
        )
        .is_ok());
        assert!(matches!(
            Layout::new("bad-prefix", "a", "b", &[], false),
            Err(Error::InvalidLayout)
        ));
    }

    #[test]
    fn schema_state_reports_the_highest_applied_version() {
        let state = SchemaState {
            applied: vec![1, 2, 9],
            pending: vec![],
        };
        assert_eq!(state.current(), Some(9));
    }
}

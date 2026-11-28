// SPDX-License-Identifier: Apache-2.0
//! The provisioning plan: which statements a product needs, in order, and the
//! rules that make running them again safe.

use std::fmt;

use zeroize::Zeroizing;

use crate::sql;

/// What one product needs from an empty server. Built by the product, never by
/// this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductDatabase {
    /// Names the product in reports only.
    pub product: &'static str,
    pub layout: SchemaLayout,
    pub btree_gist: bool,
    pub spatial: Option<Spatial>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaLayout {
    /// Tables live in `public`. The migration role gets USAGE and CREATE on it.
    PublicForMigration,
    /// Named schemas, each created with AUTHORIZATION the migration role.
    Owned(Vec<String>),
    /// `apply` creates the schema. The migration role gets CREATE on the database.
    CreatedByApply,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spatial {
    /// Schema holding PostGIS. Written unquoted, so it must be a plain lower-case identifier.
    pub schema: String,
    pub bbox_role: String,
    pub minimum_postgis: (u32, u32),
}

/// A role name and its password. `Debug` prints the name only.
pub struct RoleCredential {
    pub name: String,
    password: Zeroizing<String>,
}

impl RoleCredential {
    pub fn new(name: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            password: Zeroizing::new(password.into()),
        }
    }

    /// For the login check, which opens a session as this role.
    pub(crate) fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for RoleCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoleCredential")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Role names, database name and passwords.
#[derive(Debug)]
pub struct ProvisionTarget {
    pub database: String,
    pub migration: RoleCredential,
    /// The same name as `migration` means single-role mode.
    pub runtime: RoleCredential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Server,
    Database,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Needs {
    CreateRole,
    CreateDb,
    DatabaseOwner,
    Superuser,
}

/// The catalog fact that tells a converging run the object already exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Role {
        name: String,
        login: bool,
        /// The one role this plan itself grants to the role, with
        /// `INHERIT FALSE, SET TRUE, ADMIN FALSE`. Membership of any other
        /// role is refused: it would carry privileges the plan did not grant.
        member_of: Option<String>,
    },
    Database {
        name: String,
    },
    Extension {
        name: String,
        minimum_version: Option<(u32, u32)>,
        /// What the same statement block sets up beside the extension. An
        /// extension present without it was installed outside the plan.
        setup: Option<ExtensionSetup>,
    },
    Schema {
        name: String,
        owner: String,
    },
}

/// The schema an extension must live in and the role membership the
/// extension's statement block grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionSetup {
    pub schema: String,
    /// `member` must be able to `SET ROLE` to `role`.
    pub member: String,
    pub role: String,
}

pub struct Statement {
    pub step: &'static str,
    pub scope: Scope,
    pub needs: Needs,
    /// Never holds a password or a verifier.
    pub printable: String,
    /// `None`: re-applied on every run, a no-op when already true.
    pub probe: Option<Probe>,
    /// The role the printed script asks the administrator to set a password for.
    pub password_for: Option<String>,
    executable: Zeroizing<String>,
}

impl Statement {
    /// The text an executor sends. Holds the SCRAM verifier, so it is never printed.
    pub(crate) fn executable(&self) -> &str {
        &self.executable
    }
}

impl fmt::Debug for Statement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Statement")
            .field("step", &self.step)
            .field("scope", &self.scope)
            .field("needs", &self.needs)
            .field("printable", &self.printable)
            .field("probe", &self.probe)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct Plan {
    product: &'static str,
    database: String,
    single_role: bool,
    statements: Vec<Statement>,
}

impl Plan {
    pub fn product(&self) -> &'static str {
        self.product
    }
    pub fn database(&self) -> &str {
        &self.database
    }
    pub fn single_role(&self) -> bool {
        self.single_role
    }
    pub fn statements(&self) -> &[Statement] {
        &self.statements
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    /// Names the field, never its value.
    #[error("invalid {what}")]
    InvalidName { what: &'static str },
    #[error("an owned schema layout needs at least one schema")]
    NoSchemas,
    #[error("single-role mode needs one password for the one role")]
    SingleRolePasswordsDiffer,
}

/// The sentence is the activation ledger's own, so every product refuses an
/// old server in the same words.
#[derive(Debug, PartialEq, Eq)]
pub struct UnsupportedPostgres;

impl fmt::Display for UnsupportedPostgres {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&registry_platform_activation::Error::UnsupportedPostgres, f)
    }
}

impl std::error::Error for UnsupportedPostgres {}

/// Refuses a `server_version_num` below the shared PostgreSQL floor.
pub fn verify_server_version(version_num: i32) -> Result<(), UnsupportedPostgres> {
    if version_num < registry_platform_activation::MINIMUM_SERVER_VERSION_NUM {
        return Err(UnsupportedPostgres);
    }
    Ok(())
}

const MAX_NAME_BYTES: usize = 63;

/// Databases a product must never be provisioned into: PostgreSQL's own.
const RESERVED_DATABASES: [&str; 3] = ["postgres", "template0", "template1"];

/// A name reaches the printed `psql` script, where a line break would end a
/// meta-command and a backslash would start one, and a bidirectional override
/// would make a reviewed line read differently from what runs. So no control
/// character (C0, DEL or C1), backslash or bidirectional formatting character
/// is allowed in any name.
fn check_name(what: &'static str, name: &str) -> Result<(), PlanError> {
    let unsafe_char = |c: char| {
        c.is_control()
            || c == '\\'
            || matches!(
                c,
                '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            )
    };
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name.chars().any(unsafe_char) {
        return Err(PlanError::InvalidName { what });
    }
    Ok(())
}

/// `public` and `none` are keywords in a `GRANT` list, and `pg_` names belong
/// to PostgreSQL.
fn check_role_name(what: &'static str, name: &str) -> Result<(), PlanError> {
    check_name(what, name)?;
    let lower = name.to_ascii_lowercase();
    if lower == "public" || lower == "none" || lower.starts_with("pg_") {
        return Err(PlanError::InvalidName { what });
    }
    Ok(())
}

/// `\connect` reads a database name holding `=`, or starting with a URI
/// scheme, as a connection string and so can reach another server.
fn check_database_name(what: &'static str, name: &str) -> Result<(), PlanError> {
    check_name(what, name)?;
    let lower = name.to_ascii_lowercase();
    if name.contains('=')
        || lower.starts_with("postgresql://")
        || lower.starts_with("postgres://")
        || RESERVED_DATABASES.contains(&name)
    {
        return Err(PlanError::InvalidName { what });
    }
    Ok(())
}

/// The PostGIS schema is written unquoted in the statement text.
fn check_plain_identifier(what: &'static str, name: &str) -> Result<(), PlanError> {
    check_name(what, name)?;
    let mut bytes = name.bytes();
    let first_ok = bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b == b'_');
    if !first_ok || !bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
        return Err(PlanError::InvalidName { what });
    }
    Ok(())
}

fn statement(
    step: &'static str,
    scope: Scope,
    needs: Needs,
    printable: String,
    probe: Option<Probe>,
) -> Statement {
    Statement {
        step,
        scope,
        needs,
        executable: Zeroizing::new(printable.clone()),
        printable,
        probe,
        password_for: None,
    }
}

fn login_role(
    step: &'static str,
    credential: &RoleCredential,
    member_of: Option<&str>,
) -> Statement {
    let verifier = Zeroizing::new(postgres_protocol::password::scram_sha_256(
        credential.password.as_bytes(),
    ));
    let mut statement = statement(
        step,
        Scope::Server,
        Needs::CreateRole,
        sql::create_role_printable_sql(&credential.name),
        Some(Probe::Role {
            name: credential.name.clone(),
            login: true,
            member_of: member_of.map(str::to_owned),
        }),
    );
    statement.executable = Zeroizing::new(sql::create_role_sql(&credential.name, &verifier));
    statement.password_for = Some(credential.name.clone());
    statement
}

/// Builds the ordered statements one product needs on an empty server.
///
/// A statement with a `probe` runs only when its object is absent. One
/// without is a grant, revoke or connection switch that is a no-op when it
/// already holds, so it runs every time. Passwords reach only the private
/// executable text, as SCRAM verifiers.
pub fn plan(product: &ProductDatabase, target: &ProvisionTarget) -> Result<Plan, PlanError> {
    check_database_name("database name", &target.database)?;
    check_role_name("migration role name", &target.migration.name)?;
    check_role_name("runtime role name", &target.runtime.name)?;
    let single_role = target.migration.name == target.runtime.name;
    if single_role && *target.migration.password != *target.runtime.password {
        return Err(PlanError::SingleRolePasswordsDiffer);
    }
    if let SchemaLayout::Owned(schemas) = &product.layout {
        if schemas.is_empty() {
            return Err(PlanError::NoSchemas);
        }
        for schema in schemas {
            check_name("schema name", schema)?;
        }
    }
    if let Some(spatial) = &product.spatial {
        check_plain_identifier("PostGIS schema name", &spatial.schema)?;
        check_role_name("PostGIS bbox role name", &spatial.bbox_role)?;
    }

    let database = target.database.as_str();
    let migration = target.migration.name.as_str();
    let runtime = target.runtime.name.as_str();
    // The migration role is the one the plan makes a member of the bbox role.
    let bbox = product
        .spatial
        .as_ref()
        .map(|spatial| spatial.bbox_role.as_str());
    let mut statements = vec![login_role("role.migration", &target.migration, bbox)];
    if !single_role {
        statements.push(login_role("role.runtime", &target.runtime, None));
    }
    if let Some(spatial) = &product.spatial {
        statements.push(statement(
            "role.spatial-bbox",
            Scope::Server,
            Needs::CreateRole,
            sql::create_nologin_role_sql(&spatial.bbox_role),
            Some(Probe::Role {
                name: spatial.bbox_role.clone(),
                login: false,
                member_of: None,
            }),
        ));
    }
    let owner =
        |step, printable| statement(step, Scope::Server, Needs::DatabaseOwner, printable, None);
    statements.push(statement(
        "database.create",
        Scope::Server,
        Needs::CreateDb,
        sql::create_database_sql(database),
        Some(Probe::Database {
            name: database.to_owned(),
        }),
    ));
    statements.push(owner(
        "database.revoke-public",
        sql::revoke_public_sql(database),
    ));
    let grantees: Vec<&str> = if single_role {
        vec![migration]
    } else {
        vec![migration, runtime]
    };
    statements.push(owner(
        "database.grant-connect",
        sql::grant_connect_sql(database, &grantees),
    ));
    if product.layout == SchemaLayout::CreatedByApply {
        statements.push(owner(
            "database.grant-create",
            sql::grant_create_sql(database, migration),
        ));
    }
    statements.push(owner(
        "database.allow-connections",
        sql::allow_connections_sql(database),
    ));

    let in_database = |step, printable, probe| {
        statement(
            step,
            Scope::Database,
            Needs::DatabaseOwner,
            printable,
            probe,
        )
    };
    if product.btree_gist {
        statements.push(in_database(
            "extension.btree-gist",
            sql::btree_gist_sql().to_owned(),
            Some(Probe::Extension {
                name: "btree_gist".to_owned(),
                minimum_version: None,
                setup: None,
            }),
        ));
    }
    match &product.layout {
        SchemaLayout::Owned(schemas) => {
            for schema in schemas {
                statements.push(in_database(
                    "schema.owned",
                    sql::owned_schema_sql(schema, migration),
                    Some(Probe::Schema {
                        name: schema.clone(),
                        owner: migration.to_owned(),
                    }),
                ));
            }
        }
        SchemaLayout::PublicForMigration => {
            statements.push(in_database(
                "schema.public",
                sql::public_schema_sql(migration, runtime),
                None,
            ));
        }
        SchemaLayout::CreatedByApply => {}
    }
    if let Some(spatial) = &product.spatial {
        let mut postgis = in_database(
            "extension.postgis",
            sql::postgis_prerequisites_sql(&spatial.schema, migration, runtime, &spatial.bbox_role),
            Some(Probe::Extension {
                name: "postgis".to_owned(),
                minimum_version: Some(spatial.minimum_postgis),
                setup: Some(ExtensionSetup {
                    schema: spatial.schema.clone(),
                    member: migration.to_owned(),
                    role: spatial.bbox_role.clone(),
                }),
            }),
        );
        postgis.needs = Needs::Superuser;
        statements.push(postgis);
    }

    Ok(Plan {
        product: product.product,
        database: target.database.clone(),
        single_role,
        statements,
    })
}

/// The script an administrator reviews and runs with `psql`. It holds no
/// password and no verifier: each login role is followed by a `\password`
/// line so `psql` prompts for it.
pub fn render_script(plan: &Plan) -> String {
    let mut script = format!(
        "-- provision script, product {}. Nothing was run.\n\
         -- For a server where these objects do not exist yet. Review, then run with psql as an\n\
         -- administrator that has CREATEROLE and CREATEDB. It stops at the first error.\n\
         \\set ON_ERROR_STOP on\n\
         SET createrole_self_grant = {};\n",
        plan.product,
        sql::quote_literal(sql::CREATEROLE_SELF_GRANT),
    );
    let mut connected = false;
    for statement in &plan.statements {
        if statement.scope == Scope::Database && !connected {
            script.push_str(&format!(
                "\\connect {}\n",
                sql::quote_identifier(&plan.database)
            ));
            connected = true;
        }
        if statement.needs == Needs::Superuser {
            script.push_str("-- needs a superuser\n");
        }
        script.push_str(&statement.printable);
        if !statement.printable.ends_with(';') {
            script.push(';');
        }
        script.push('\n');
        if let Some(role) = &statement.password_for {
            script.push_str(&format!("\\password {}\n", sql::quote_identifier(role)));
        }
    }
    script
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::*;

    const PASSWORD_M: &str = "migration-pass-0123";
    const PASSWORD_R: &str = "runtime-pass-4567";

    fn target() -> ProvisionTarget {
        ProvisionTarget {
            database: "casework".to_owned(),
            migration: RoleCredential::new("casework_migration", PASSWORD_M),
            runtime: RoleCredential::new("casework_runtime", PASSWORD_R),
        }
    }

    fn product(layout: SchemaLayout) -> ProductDatabase {
        ProductDatabase {
            product: "casework",
            layout,
            btree_gist: false,
            spatial: None,
        }
    }

    fn breg_schemas() -> Vec<String> {
        [
            "registry_internal",
            "registry_data",
            "registry_source",
            "registry_derived",
            "registry_context",
        ]
        .map(str::to_owned)
        .to_vec()
    }

    fn breg_spatial() -> ProductDatabase {
        ProductDatabase {
            product: "breg",
            layout: SchemaLayout::Owned(breg_schemas()),
            btree_gist: true,
            spatial: Some(Spatial {
                schema: "registry_spatial_ext".to_owned(),
                bbox_role: "casework_runtime__spatial_bbox".to_owned(),
                minimum_postgis: (3, 5),
            }),
        }
    }

    fn steps(plan: &Plan) -> Vec<&'static str> {
        plan.statements().iter().map(|s| s.step).collect()
    }

    #[test]
    fn plan_lists_statements_in_order_for_public_layout() {
        let plan = plan(&product(SchemaLayout::PublicForMigration), &target()).unwrap();
        assert_eq!(
            steps(&plan),
            [
                "role.migration",
                "role.runtime",
                "database.create",
                "database.revoke-public",
                "database.grant-connect",
                "database.allow-connections",
                "schema.public",
            ]
        );
        assert!(!plan.single_role());
    }

    #[test]
    fn plan_lists_statements_in_order_for_owned_layout_with_spatial() {
        let plan = plan(&breg_spatial(), &target()).unwrap();
        assert_eq!(
            steps(&plan),
            [
                "role.migration",
                "role.runtime",
                "role.spatial-bbox",
                "database.create",
                "database.revoke-public",
                "database.grant-connect",
                "database.allow-connections",
                "extension.btree-gist",
                "schema.owned",
                "schema.owned",
                "schema.owned",
                "schema.owned",
                "schema.owned",
                "extension.postgis",
            ]
        );
        let postgis = plan.statements().last().unwrap();
        assert_eq!(postgis.needs, Needs::Superuser);
        assert_eq!(postgis.scope, Scope::Database);
    }

    #[test]
    fn plan_lists_statements_in_order_for_created_by_apply_layout() {
        let plan = plan(&product(SchemaLayout::CreatedByApply), &target()).unwrap();
        assert_eq!(
            steps(&plan),
            [
                "role.migration",
                "role.runtime",
                "database.create",
                "database.revoke-public",
                "database.grant-connect",
                "database.grant-create",
                "database.allow-connections",
            ]
        );
    }

    #[test]
    fn statements_carry_scope_needs_and_probe() {
        let plan = plan(&product(SchemaLayout::PublicForMigration), &target()).unwrap();
        let by_step = |step| plan.statements().iter().find(|s| s.step == step).unwrap();
        let role = by_step("role.migration");
        assert_eq!((role.scope, role.needs), (Scope::Server, Needs::CreateRole));
        assert_eq!(
            role.probe,
            Some(Probe::Role {
                name: "casework_migration".to_owned(),
                login: true,
                member_of: None,
            })
        );
        let create = by_step("database.create");
        assert_eq!(create.needs, Needs::CreateDb);
        assert_eq!(
            create.probe,
            Some(Probe::Database {
                name: "casework".to_owned()
            })
        );
        for step in [
            "database.revoke-public",
            "database.grant-connect",
            "database.allow-connections",
            "schema.public",
        ] {
            assert_eq!(by_step(step).probe, None, "{step}");
            assert_eq!(by_step(step).needs, Needs::DatabaseOwner, "{step}");
        }
        assert_eq!(by_step("schema.public").scope, Scope::Database);
        assert_eq!(by_step("database.revoke-public").scope, Scope::Server);
    }

    #[test]
    fn rendered_script_holds_no_password_and_no_verifier() {
        for product in [product(SchemaLayout::PublicForMigration), breg_spatial()] {
            let target = target();
            let plan = plan(&product, &target).unwrap();
            let script = render_script(&plan);
            for secret in [PASSWORD_M, PASSWORD_R, "SCRAM-SHA-256", "PASSWORD '"] {
                assert!(!script.contains(secret), "{secret} in {script}");
            }
            for rendered in [format!("{plan:?}"), format!("{target:?}")] {
                assert!(!rendered.contains(PASSWORD_M) && !rendered.contains(PASSWORD_R));
                assert!(!rendered.contains("SCRAM-SHA-256"));
            }
            for statement in plan.statements() {
                assert!(!statement.printable.contains("SCRAM-SHA-256"));
                assert!(!statement.printable.contains(PASSWORD_M));
            }
        }
    }

    #[test]
    fn executable_role_statements_carry_a_verifier_never_the_password() {
        let plan = plan(&product(SchemaLayout::PublicForMigration), &target()).unwrap();
        for statement in plan
            .statements()
            .iter()
            .filter(|s| s.password_for.is_some())
        {
            let executable = statement.executable();
            assert!(
                executable.contains("PASSWORD 'SCRAM-SHA-256$"),
                "{}",
                statement.step
            );
            assert!(!executable.contains(PASSWORD_M) && !executable.contains(PASSWORD_R));
        }
    }

    #[test]
    fn rendered_script_asks_for_passwords_and_switches_database() {
        let script = render_script(&plan(&breg_spatial(), &target()).unwrap());
        assert!(script.contains("Nothing was run"), "{script}");
        assert!(
            script.contains("SET createrole_self_grant = 'set,inherit';"),
            "{script}"
        );
        assert!(
            script.contains("\\password \"casework_migration\""),
            "{script}"
        );
        assert!(
            script.contains("\\password \"casework_runtime\""),
            "{script}"
        );
        assert!(
            !script.contains("\\password \"casework_runtime__spatial_bbox\""),
            "{script}"
        );
        let connect = script.find("\\connect \"casework\"").expect("connect line");
        let allow = script.find("ALLOW_CONNECTIONS true").unwrap();
        let btree = script.find("CREATE EXTENSION btree_gist").unwrap();
        assert!(allow < connect && connect < btree, "{script}");
        let marker = script.find("-- needs a superuser").unwrap();
        assert!(script[marker..].contains("CREATE EXTENSION IF NOT EXISTS postgis"));
        assert_eq!(script.matches("-- needs a superuser").count(), 1);
    }

    #[test]
    fn single_role_target_plans_one_role() {
        let target = ProvisionTarget {
            database: "adapter".to_owned(),
            migration: RoleCredential::new("adapter", PASSWORD_M),
            runtime: RoleCredential::new("adapter", PASSWORD_M),
        };
        let plan = plan(&product(SchemaLayout::PublicForMigration), &target).unwrap();
        assert!(plan.single_role());
        let roles: Vec<_> = plan
            .statements()
            .iter()
            .filter(|s| s.step.starts_with("role."))
            .collect();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].step, "role.migration");
        let grant = plan
            .statements()
            .iter()
            .find(|s| s.step == "database.grant-connect")
            .unwrap();
        assert_eq!(
            grant.printable.matches("\"adapter\"").count(),
            2,
            "{}",
            grant.printable
        );
        assert!(
            grant.printable.ends_with("TO \"adapter\""),
            "{}",
            grant.printable
        );
    }

    #[test]
    fn single_role_with_two_passwords_is_refused() {
        let target = ProvisionTarget {
            database: "adapter".to_owned(),
            migration: RoleCredential::new("adapter", PASSWORD_M),
            runtime: RoleCredential::new("adapter", PASSWORD_R),
        };
        assert!(matches!(
            plan(&product(SchemaLayout::PublicForMigration), &target),
            Err(PlanError::SingleRolePasswordsDiffer)
        ));
    }

    #[test]
    fn unusable_names_are_refused_without_echoing_them() {
        let mut bad = target();
        bad.database = String::new();
        let error = plan(&product(SchemaLayout::PublicForMigration), &bad).unwrap_err();
        assert_eq!(
            error,
            PlanError::InvalidName {
                what: "database name"
            }
        );

        let mut long = target();
        long.migration = RoleCredential::new("m".repeat(64), PASSWORD_M);
        assert!(plan(&product(SchemaLayout::PublicForMigration), &long).is_err());

        let mut nul = target();
        nul.runtime = RoleCredential::new("a\0b", PASSWORD_R);
        assert!(plan(&product(SchemaLayout::PublicForMigration), &nul).is_err());

        assert_eq!(
            plan(&product(SchemaLayout::Owned(Vec::new())), &target()).unwrap_err(),
            PlanError::NoSchemas
        );

        let mut spatial = breg_spatial();
        spatial.spatial.as_mut().unwrap().schema = "bad schema; DROP".to_owned();
        assert_eq!(
            plan(&spatial, &target()).unwrap_err(),
            PlanError::InvalidName {
                what: "PostGIS schema name"
            }
        );
    }

    fn invalid(what: &'static str) -> PlanError {
        PlanError::InvalidName { what }
    }

    fn plan_for(target: &ProvisionTarget) -> Result<Plan, PlanError> {
        plan(&product(SchemaLayout::PublicForMigration), target)
    }

    #[test]
    fn names_with_control_characters_or_backslashes_are_refused() {
        for bad in ["a\nb", "a\rb", "a\x1bb", "a\x7fb", "a\\b", "a\tb"] {
            let mut database = target();
            database.database = bad.to_owned();
            assert_eq!(
                plan_for(&database).unwrap_err(),
                invalid("database name"),
                "{bad:?}"
            );

            let mut migration = target();
            migration.migration = RoleCredential::new(bad, PASSWORD_M);
            assert_eq!(
                plan_for(&migration).unwrap_err(),
                invalid("migration role name"),
                "{bad:?}"
            );

            let mut runtime = target();
            runtime.runtime = RoleCredential::new(bad, PASSWORD_R);
            assert_eq!(
                plan_for(&runtime).unwrap_err(),
                invalid("runtime role name"),
                "{bad:?}"
            );

            let mut spatial = breg_spatial();
            spatial.spatial.as_mut().unwrap().bbox_role = bad.to_owned();
            assert_eq!(
                plan(&spatial, &target()).unwrap_err(),
                invalid("PostGIS bbox role name"),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_database_name_with_an_equals_sign_is_refused_but_a_role_name_may_hold_one() {
        let mut database = target();
        database.database = "host=attacker.example dbname=x".to_owned();
        assert_eq!(plan_for(&database).unwrap_err(), invalid("database name"));

        let mut role = target();
        role.runtime = RoleCredential::new("app=runtime", PASSWORD_R);
        assert!(plan_for(&role).is_ok());
    }

    #[test]
    fn a_database_name_that_starts_with_a_connection_uri_scheme_is_refused() {
        for bad in [
            "postgresql://evil.example/x",
            "postgres://evil.example/x",
            "PostgreSQL://evil.example/x",
            "POSTGRES://evil.example/x",
        ] {
            let mut database = target();
            database.database = bad.to_owned();
            assert_eq!(
                plan_for(&database).unwrap_err(),
                invalid("database name"),
                "{bad}"
            );
        }
        // Only a leading scheme is read as a URI, and a role name may hold one.
        let mut inner = target();
        inner.database = "app-postgres://x".to_owned();
        assert!(plan_for(&inner).is_ok());
        let mut role = target();
        role.runtime = RoleCredential::new("postgres://runtime", PASSWORD_R);
        assert!(plan_for(&role).is_ok());
    }

    #[test]
    fn names_with_c1_controls_or_bidirectional_overrides_are_refused() {
        for bad in [
            "a\u{85}b",
            "a\u{9f}b",
            "a\u{202e}b",
            "a\u{2066}b",
            "a\u{200f}b",
        ] {
            let mut database = target();
            database.database = bad.to_owned();
            assert_eq!(
                plan_for(&database).unwrap_err(),
                invalid("database name"),
                "{bad:?}"
            );
            let mut runtime = target();
            runtime.runtime = RoleCredential::new(bad, PASSWORD_R);
            assert_eq!(
                plan_for(&runtime).unwrap_err(),
                invalid("runtime role name"),
                "{bad:?}"
            );
        }
        let mut accented = target();
        accented.database = "cafe\u{301}".to_owned();
        assert!(plan_for(&accented).is_ok());
    }

    #[test]
    fn reserved_role_names_are_refused() {
        for reserved in [
            "public",
            "PUBLIC",
            "none",
            "None",
            "pg_read_all_data",
            "PG_x",
        ] {
            let mut migration = target();
            migration.migration = RoleCredential::new(reserved, PASSWORD_M);
            assert_eq!(
                plan_for(&migration).unwrap_err(),
                invalid("migration role name"),
                "{reserved}"
            );
            let mut runtime = target();
            runtime.runtime = RoleCredential::new(reserved, PASSWORD_R);
            assert_eq!(
                plan_for(&runtime).unwrap_err(),
                invalid("runtime role name"),
                "{reserved}"
            );
        }
        let mut spatial = breg_spatial();
        spatial.spatial.as_mut().unwrap().bbox_role = "public".to_owned();
        assert_eq!(
            plan(&spatial, &target()).unwrap_err(),
            invalid("PostGIS bbox role name")
        );
        let mut single = target();
        single.migration = RoleCredential::new("public", PASSWORD_M);
        single.runtime = RoleCredential::new("public", PASSWORD_M);
        assert!(plan_for(&single).is_err());
    }

    #[test]
    fn the_postgres_template_and_maintenance_databases_are_refused() {
        for reserved in ["postgres", "template0", "template1"] {
            let mut database = target();
            database.database = reserved.to_owned();
            assert_eq!(
                plan_for(&database).unwrap_err(),
                invalid("database name"),
                "{reserved}"
            );
        }
    }

    #[test]
    fn the_printed_script_stops_at_the_first_error_before_anything_else() {
        let script = render_script(&plan(&breg_spatial(), &target()).unwrap());
        let first = script
            .lines()
            .find(|line| !line.starts_with("--"))
            .expect("a statement line");
        assert_eq!(first, "\\set ON_ERROR_STOP on", "{script}");
    }

    #[test]
    fn the_runtime_role_gets_usage_on_public_from_the_plan() {
        let plan = plan(&product(SchemaLayout::PublicForMigration), &target()).unwrap();
        let public = plan
            .statements()
            .iter()
            .find(|statement| statement.step == "schema.public")
            .unwrap();
        assert_eq!(public.probe, None);
        assert_eq!(public.scope, Scope::Database);
        assert_eq!(
            public.printable,
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC; \
             GRANT USAGE, CREATE ON SCHEMA public TO \"casework_migration\"; \
             GRANT USAGE ON SCHEMA public TO \"casework_runtime\""
        );
        assert!(!public.printable.contains("GRANT OPTION"));
    }

    #[test]
    fn single_role_public_layout_grants_the_one_role_once() {
        let target = ProvisionTarget {
            database: "adapter".to_owned(),
            migration: RoleCredential::new("adapter", PASSWORD_M),
            runtime: RoleCredential::new("adapter", PASSWORD_M),
        };
        let plan = plan(&product(SchemaLayout::PublicForMigration), &target).unwrap();
        let public = plan
            .statements()
            .iter()
            .find(|statement| statement.step == "schema.public")
            .unwrap();
        assert_eq!(
            public.printable,
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC; \
             GRANT USAGE, CREATE ON SCHEMA public TO \"adapter\""
        );
    }

    #[test]
    fn literals_with_a_backslash_are_written_as_escape_strings() {
        assert_eq!(quote_literal("a\\b'c"), "E'a\\\\b''c'");
        assert_eq!(quote_literal("plain"), "'plain'");
    }

    #[test]
    fn server_below_the_floor_is_refused() {
        for version in [0, 90_600, 160_999, 169_999] {
            assert_eq!(
                verify_server_version(version),
                Err(UnsupportedPostgres),
                "{version}"
            );
        }
        for version in [170_000, 170_011, 180_000] {
            assert_eq!(verify_server_version(version), Ok(()), "{version}");
        }
        assert!(UnsupportedPostgres
            .to_string()
            .starts_with("PostgreSQL 17 or newer is required"));
        assert_eq!(
            registry_platform_activation::MINIMUM_SERVER_VERSION_NUM,
            170_000
        );
    }

    // Builder and quoting tests, carried over from `registry-rstack-dev`.

    #[test]
    fn identifiers_and_passwords_are_quoted_for_postgresql() {
        assert_eq!(quote_identifier("a\"b"), "\"a\"\"b\"");
        assert_eq!(quote_literal("a'b"), "'a''b'");
    }

    #[test]
    fn role_statement_carries_a_postgresql_scram_verifier_not_cleartext() {
        let password = "a-throwaway-credential";
        let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
        let sql = create_role_sql("rstack_role", &verifier);
        let expected = format!(
            "CREATE ROLE \"rstack_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{verifier}'"
        );
        assert!(verifier.starts_with("SCRAM-SHA-256$"));
        assert!(sql == expected && !sql.contains(password));
    }

    #[test]
    fn nologin_role_statement_has_no_password_clause() {
        assert_eq!(
            create_nologin_role_sql("bbox"),
            "CREATE ROLE \"bbox\" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS"
        );
    }

    #[test]
    fn database_creation_is_closed_to_connections() {
        assert_eq!(
            create_database_sql("db\"x"),
            "CREATE DATABASE \"db\"\"x\" WITH ALLOW_CONNECTIONS false"
        );
    }

    #[test]
    fn database_access_is_closed_to_public_before_connections_are_enabled() {
        let sql = database_access_sql("casework", "casework_migration", "casework_runtime");
        let revoke = sql.find("REVOKE ALL ON DATABASE").unwrap();
        let grant = sql.find("GRANT CONNECT ON DATABASE").unwrap();
        let enable = sql.find("ALLOW_CONNECTIONS true").unwrap();
        assert!(revoke < grant && grant < enable, "{sql}");
        assert!(sql.contains(&quote_identifier("casework_migration")));
        assert!(sql.contains(&quote_identifier("casework_runtime")));
        assert_eq!(
            sql,
            "REVOKE ALL ON DATABASE \"casework\" FROM PUBLIC; \
             GRANT CONNECT ON DATABASE \"casework\" TO \"casework_migration\", \"casework_runtime\"; \
             ALTER DATABASE \"casework\" ALLOW_CONNECTIONS true"
        );
    }

    #[test]
    fn grant_create_is_on_the_database_for_the_migration_role() {
        assert_eq!(
            grant_create_sql("coordinator", "coordinator_migration"),
            "GRANT CREATE ON DATABASE \"coordinator\" TO \"coordinator_migration\""
        );
    }

    #[test]
    fn breg_setup_installs_extension_and_all_owned_schemas() {
        let layout = SchemaLayout::Owned(breg_schemas());
        let sql = database_setup_sql("casework_migration", "casework_runtime", &layout, true);
        assert!(sql.starts_with("CREATE EXTENSION btree_gist;"), "{sql}");
        for schema in breg_schemas() {
            assert!(
                sql.contains(&format!(
                    "CREATE SCHEMA {} AUTHORIZATION {}",
                    quote_identifier(&schema),
                    quote_identifier("casework_migration")
                )),
                "{sql}"
            );
            assert!(
                sql.contains(&format!(
                    "REVOKE ALL ON SCHEMA {} FROM PUBLIC",
                    quote_identifier(&schema)
                )),
                "{sql}"
            );
        }
    }

    #[test]
    fn public_setup_restricts_create_and_grants_both_roles() {
        assert_eq!(
            database_setup_sql(
                "casework_migration",
                "casework_runtime",
                &SchemaLayout::PublicForMigration,
                false
            ),
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC; \
             GRANT USAGE, CREATE ON SCHEMA public TO \"casework_migration\"; \
             GRANT USAGE ON SCHEMA public TO \"casework_runtime\""
        );
        assert_eq!(
            database_setup_sql("m", "r", &SchemaLayout::CreatedByApply, false),
            ""
        );
    }

    #[test]
    fn postgis_prerequisites_name_the_schema_and_both_roles() {
        let sql = postgis_prerequisites_sql("registry_spatial_ext", "m", "r", "bbox");
        assert_eq!(
            sql,
            "CREATE SCHEMA IF NOT EXISTS registry_spatial_ext;\n\
             REVOKE ALL ON SCHEMA registry_spatial_ext FROM PUBLIC;\n\
             CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA registry_spatial_ext;\n\
             GRANT USAGE ON SCHEMA registry_spatial_ext TO \"m\", \"r\";\n\
             GRANT \"bbox\" TO \"m\" WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;\n\
             GRANT USAGE ON SCHEMA registry_spatial_ext TO \"bbox\";"
        );
    }
}

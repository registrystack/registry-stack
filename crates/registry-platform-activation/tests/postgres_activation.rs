// SPDX-License-Identifier: Apache-2.0

use registry_platform_activation::{
    activation_history, activation_recorded, active_activation, append_activation,
    check_active_package, database_id_check, first_authority_weakness, grant_runtime_role,
    observe_role, stray_authority, ActivePackageError, AuthorityCause, DatabaseIdCheck, Layout,
    NewActivation, PlanKind, RoleMode,
};
use tokio_postgres::NoTls;
use uuid::Uuid;

fn database_url() -> String {
    std::env::var("ACTIVATION_TEST_DATABASE_URL")
        .expect("ACTIVATION_TEST_DATABASE_URL must name a disposable PostgreSQL database")
}

fn layout() -> Layout {
    Layout::new(
        "fixture",
        "fixture_activations",
        "fixture_schema_migrations",
        &[],
        false,
    )
    .expect("static fixture layout")
}

#[tokio::test]
async fn ledger_identity_and_split_role_share_one_postgres_boundary() {
    let (mut client, connection) = tokio_postgres::connect(&database_url(), NoTls)
        .await
        .expect("connect to disposable PostgreSQL");
    let connection_task = tokio::spawn(connection);
    let suffix = Uuid::new_v4().simple().to_string();
    let schema = format!("activation_{suffix}");
    let runtime_role = format!("activation_runtime_{suffix}");
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema};
             CREATE ROLE {runtime_role} NOLOGIN;
             SET search_path TO {schema};
             CREATE TABLE fixture_schema_migrations(
               version bigint PRIMARY KEY,
               applied_at timestamptz NOT NULL DEFAULT now()
             );
             CREATE TABLE fixture_records(
               record_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
               document text NOT NULL
             );
             CREATE TABLE fixture_activations(
               activation_id uuid PRIMARY KEY,
               apply_order bigint NOT NULL UNIQUE,
               package_digest text NOT NULL,
               predecessor_package_digest text,
               database_id text NOT NULL,
               plan_kind text NOT NULL CHECK(plan_kind IN ('initial','successor')),
               applied_at timestamptz NOT NULL,
               operator_reference_hash text,
               backup_references text[] NOT NULL,
               role_mode text NOT NULL CHECK(role_mode IN ('single','split'))
             );"
        ))
        .await
        .expect("create isolated activation fixture");

    let transaction = client.transaction().await.expect("start transaction");
    assert!(active_activation(&transaction, &layout())
        .await
        .expect("read empty ledger")
        .is_none());

    grant_runtime_role(&transaction, &layout(), &runtime_role, &[])
        .await
        .expect("grant split runtime role");
    let role = observe_role(&transaction, &layout(), Some(&runtime_role), &[])
        .await
        .expect("observe split role")
        .expect("ledger exists");
    assert_eq!(role.mode, RoleMode::Split);
    assert!(role.grants_current);

    let activation_id = Uuid::new_v4();
    let activation = append_activation(
        &transaction,
        &layout(),
        &NewActivation {
            activation_id,
            package_digest: "sha256:fixture",
            database_id: "fixture-database",
            operator_reference_hash: None,
            backup_references: &[],
            role_mode: role.mode,
            runtime_role: None,
        },
    )
    .await
    .expect("append activation");
    assert_eq!(activation.plan_kind, PlanKind::Initial);
    assert_eq!(
        database_id_check(Some(&activation), "fixture-database"),
        DatabaseIdCheck::Matches
    );
    assert_eq!(
        database_id_check(Some(&activation), "another-database"),
        DatabaseIdCheck::Differs
    );
    assert!(activation_recorded(&transaction, &layout(), activation_id)
        .await
        .expect("read activation id"));
    assert_eq!(
        activation_history(&transaction, &layout())
            .await
            .expect("read activation history"),
        vec![activation.clone()]
    );
    check_active_package(
        &transaction,
        &layout(),
        "fixture-database",
        "sha256:fixture",
    )
    .await
    .expect("accept exact active package");
    assert!(matches!(
        check_active_package(
            &transaction,
            &layout(),
            "another-database",
            "sha256:fixture"
        )
        .await,
        Err(ActivePackageError::DatabaseIdMismatch)
    ));

    transaction
        .batch_execute(&format!(
            "REVOKE INSERT ON TABLE {schema}.fixture_records FROM {runtime_role}"
        ))
        .await
        .expect("remove one required runtime grant");
    let role = observe_role(&transaction, &layout(), Some(&runtime_role), &[])
        .await
        .expect("observe incomplete split grants")
        .expect("ledger exists");
    assert_eq!(role.mode, RoleMode::Split);
    assert!(!role.grants_current);

    transaction
        .batch_execute(&format!(
            "GRANT CREATE ON SCHEMA {schema} TO {runtime_role}"
        ))
        .await
        .expect("weaken split role");
    let fixes = stray_authority(&transaction, &layout(), Some(&runtime_role))
        .await
        .expect("identify stray authority");
    assert_eq!(
        fixes,
        vec![format!(
            "REVOKE CREATE ON SCHEMA {schema} FROM {runtime_role}"
        )]
    );
    transaction
        .rollback()
        .await
        .expect("roll back fixture state");

    client
        .batch_execute(&format!(
            "RESET search_path; DROP SCHEMA {schema} CASCADE; DROP ROLE {runtime_role};"
        ))
        .await
        .expect("remove isolated activation fixture");
    drop(client);
    connection_task
        .await
        .expect("join PostgreSQL connection")
        .expect("PostgreSQL connection completes");
}

/// Ownership remediation must touch only product objects in the activation
/// layout. A runtime role can own unrelated objects in the same database, and
/// correcting the product boundary must leave those objects with that role.
#[tokio::test]
async fn ownership_remediation_leaves_unrelated_objects_unchanged() {
    let (mut client, connection) = tokio_postgres::connect(&database_url(), NoTls)
        .await
        .expect("connect to disposable PostgreSQL");
    let connection_task = tokio::spawn(connection);
    let suffix = Uuid::new_v4().simple().to_string();
    let schema = format!("activation_{suffix}");
    let unrelated_schema = format!("unrelated_{suffix}");
    let runtime_role = format!("activation_runtime_{suffix}");
    let transaction = client.transaction().await.expect("start transaction");
    transaction
        .batch_execute(&format!(
            "CREATE ROLE {runtime_role} NOLOGIN;
             CREATE SCHEMA {schema};
             CREATE SCHEMA {unrelated_schema};
             SET search_path TO {schema};
             CREATE TABLE fixture_schema_migrations(version bigint PRIMARY KEY);
             CREATE TABLE fixture_activations(activation_id uuid PRIMARY KEY);
             CREATE TABLE fixture_records(record_id bigint PRIMARY KEY);
             ALTER TABLE fixture_records OWNER TO {runtime_role};
             CREATE TABLE fixture_partitioned(record_id bigint) PARTITION BY RANGE(record_id);
             ALTER TABLE fixture_partitioned OWNER TO {runtime_role};
             CREATE TABLE fixture_z_identity(
               record_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY
             );
             ALTER TABLE fixture_z_identity OWNER TO {runtime_role};
             ALTER SEQUENCE fixture_z_identity_record_id_seq RENAME TO fixture_a_identity;
             CREATE VIEW \"fixture_View\" AS SELECT record_id FROM fixture_records;
             ALTER VIEW \"fixture_View\" OWNER TO {runtime_role};
             CREATE MATERIALIZED VIEW fixture_materialized AS SELECT record_id FROM fixture_records;
             ALTER MATERIALIZED VIEW fixture_materialized OWNER TO {runtime_role};
             CREATE SEQUENCE fixture_sequence;
             ALTER SEQUENCE fixture_sequence OWNER TO {runtime_role};
             CREATE FUNCTION fixture_transform(value integer) RETURNS integer
               LANGUAGE sql IMMUTABLE AS $body$ SELECT value $body$;
             CREATE FUNCTION fixture_transform(value text) RETURNS text
               LANGUAGE sql IMMUTABLE AS $body$ SELECT value $body$;
             ALTER FUNCTION fixture_transform(integer) OWNER TO {runtime_role};
             ALTER FUNCTION fixture_transform(text) OWNER TO {runtime_role};
             CREATE PROCEDURE fixture_refresh() LANGUAGE sql AS $body$ SELECT 1 $body$;
             ALTER PROCEDURE fixture_refresh() OWNER TO {runtime_role};
             CREATE AGGREGATE fixture_total(integer)
               (SFUNC = pg_catalog.int4pl, STYPE = integer, INITCOND = '0');
             ALTER AGGREGATE fixture_total(integer) OWNER TO {runtime_role};
             CREATE TABLE unrelated_records(record_id bigint PRIMARY KEY);
             ALTER TABLE unrelated_records OWNER TO {runtime_role};
             CREATE SEQUENCE unrelated_sequence;
             ALTER SEQUENCE unrelated_sequence OWNER TO {runtime_role};
             CREATE FUNCTION unrelated_transform(value integer) RETURNS integer
               LANGUAGE sql IMMUTABLE AS $body$ SELECT value $body$;
             ALTER FUNCTION unrelated_transform(integer) OWNER TO {runtime_role};
             ALTER SCHEMA {schema} OWNER TO {runtime_role};
             CREATE TABLE {unrelated_schema}.unrelated_records(record_id bigint PRIMARY KEY);
             ALTER TABLE {unrelated_schema}.unrelated_records OWNER TO {runtime_role};"
        ))
        .await
        .expect("create owned product and unrelated objects");

    let fixes = stray_authority(&transaction, &layout(), Some(&runtime_role))
        .await
        .expect("identify ownership remediation");
    assert!(!fixes.is_empty(), "owned product object needs remediation");
    assert!(fixes.iter().all(|fix| !fix.starts_with("REASSIGN OWNED")));
    for fragment in [
        format!("ALTER SCHEMA {schema} OWNER TO"),
        format!("ALTER TABLE {schema}.fixture_records OWNER TO"),
        format!("ALTER TABLE {schema}.fixture_partitioned OWNER TO"),
        format!("ALTER TABLE {schema}.fixture_z_identity OWNER TO"),
        format!("ALTER VIEW {schema}.\"fixture_View\" OWNER TO"),
        format!("ALTER MATERIALIZED VIEW {schema}.fixture_materialized OWNER TO"),
        format!("ALTER SEQUENCE {schema}.fixture_sequence OWNER TO"),
        format!("ALTER SEQUENCE {schema}.fixture_a_identity OWNER TO"),
        format!("ALTER ROUTINE {schema}.fixture_transform(value integer) OWNER TO"),
        format!("ALTER ROUTINE {schema}.fixture_transform(value text) OWNER TO"),
        format!("ALTER ROUTINE {schema}.fixture_refresh() OWNER TO"),
        format!("ALTER ROUTINE {schema}.fixture_total(integer) OWNER TO"),
    ] {
        assert!(
            fixes.iter().any(|fix| fix.starts_with(&fragment)),
            "missing exact remediation {fragment:?}: {fixes:?}"
        );
    }
    let position = |prefix: &str| {
        fixes
            .iter()
            .position(|fix| fix.starts_with(prefix))
            .expect("expected correction is present")
    };
    let identity_table = format!("ALTER TABLE {schema}.fixture_z_identity OWNER TO");
    let identity_sequence = format!("ALTER SEQUENCE {schema}.fixture_a_identity OWNER TO");
    let first_routine = format!("ALTER ROUTINE {schema}.fixture_refresh() OWNER TO");
    let last_sequence = fixes
        .iter()
        .rposition(|fix| fix.starts_with("ALTER SEQUENCE "))
        .expect("at least one sequence correction is present");
    assert!(position(&identity_table) < position(&identity_sequence));
    assert!(last_sequence < position(&first_routine));
    let weakness = first_authority_weakness(&transaction, &layout(), &runtime_role)
        .await
        .expect("inspect the first authority weakness")
        .expect("owned product objects weaken the role boundary");
    match weakness.cause {
        AuthorityCause::OwnedObjects { owners, statements } => {
            assert_eq!(owners, vec![runtime_role.clone()]);
            assert_eq!(statements, fixes);
        }
        cause => panic!("expected exact ownership corrections, got {cause:?}"),
    }
    for fix in &fixes {
        transaction
            .batch_execute(fix)
            .await
            .expect("execute emitted ownership remediation");
    }

    let owners = transaction
        .query_one(
            "SELECT
               pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid=to_regclass($1))),
               pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid=to_regclass($2)))",
            &[
                &format!("{schema}.fixture_records"),
                &format!("{unrelated_schema}.unrelated_records"),
            ],
        )
        .await
        .expect("read resulting owners");
    let migration_role: String = transaction
        .query_one("SELECT current_user::text", &[])
        .await
        .expect("read migration role")
        .get(0);
    assert_eq!(owners.get::<_, String>(0), migration_role);
    let remaining_product_owners: i64 = transaction
        .query_one(
            "SELECT
               (SELECT count(*) FROM pg_namespace n
                 WHERE n.nspname=$1 AND pg_get_userbyid(n.nspowner)<>current_user::text)
               + (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                  WHERE n.nspname=$1 AND c.relname LIKE 'fixture\\_%'
                    AND c.relkind IN ('r','p','v','m','S','f')
                    AND pg_get_userbyid(c.relowner)<>current_user::text)
               + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                  WHERE n.nspname=$1 AND p.proname LIKE 'fixture\\_%'
                    AND pg_get_userbyid(p.proowner)<>current_user::text)",
            &[&schema],
        )
        .await
        .expect("inspect every remediated product owner")
        .get(0);
    assert_eq!(remaining_product_owners, 0);
    let unchanged_same_schema_owners: i64 = transaction
        .query_one(
            "SELECT count(*) FROM (
               SELECT c.relowner owner FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                 WHERE n.nspname=$1 AND c.relname IN ('unrelated_records','unrelated_sequence')
               UNION ALL
               SELECT p.proowner FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                 WHERE n.nspname=$1 AND p.proname='unrelated_transform'
             ) objects JOIN pg_roles r ON r.oid=objects.owner WHERE r.rolname=$2",
            &[&schema, &runtime_role],
        )
        .await
        .expect("inspect unrelated same-schema owners")
        .get(0);
    assert_eq!(
        unchanged_same_schema_owners, 3,
        "product remediation must not change unrelated same-schema object owners"
    );
    assert_eq!(
        owners.get::<_, String>(1),
        runtime_role,
        "product remediation must not change an unrelated object's owner"
    );

    transaction
        .rollback()
        .await
        .expect("roll back isolated ownership fixture");
    drop(client);
    connection_task
        .await
        .expect("join PostgreSQL connection")
        .expect("PostgreSQL connection completes");
}

/// Ownership checks resolve the product schema from the ledger rather than
/// from the first schema on the connection's search path. That preserves
/// unrelated, same-prefix objects in an earlier schema.
#[tokio::test]
async fn ownership_remediation_follows_the_ledger_namespace_across_search_path_schemas() {
    let (mut client, connection) = tokio_postgres::connect(&database_url(), NoTls)
        .await
        .expect("connect to disposable PostgreSQL");
    let connection_task = tokio::spawn(connection);
    let suffix = Uuid::new_v4().simple().to_string();
    let schema = format!("Activation_{suffix}");
    let quoted_schema = format!("\"{schema}\"");
    let decoy_schema = format!("decoy_{suffix}");
    let runtime_role = format!("activation_runtime_{suffix}");
    let transaction = client.transaction().await.expect("start transaction");
    transaction
        .batch_execute(&format!(
            "CREATE ROLE {runtime_role} NOLOGIN;
             CREATE SCHEMA {quoted_schema};
             CREATE SCHEMA {decoy_schema};
             CREATE TABLE {quoted_schema}.fixture_schema_migrations(version bigint PRIMARY KEY);
             CREATE TABLE {quoted_schema}.fixture_activations(activation_id uuid PRIMARY KEY);
             CREATE SEQUENCE {quoted_schema}.fixture_sequence;
             ALTER SEQUENCE {quoted_schema}.fixture_sequence OWNER TO {runtime_role};
             CREATE FUNCTION {quoted_schema}.fixture_transform(value integer) RETURNS integer
               LANGUAGE sql IMMUTABLE AS $body$ SELECT value $body$;
             ALTER FUNCTION {quoted_schema}.fixture_transform(integer) OWNER TO {runtime_role};
             CREATE TABLE {decoy_schema}.fixture_records(record_id bigint PRIMARY KEY);
             ALTER TABLE {decoy_schema}.fixture_records OWNER TO {runtime_role};
             CREATE SEQUENCE {decoy_schema}.fixture_sequence;
             ALTER SEQUENCE {decoy_schema}.fixture_sequence OWNER TO {runtime_role};
             CREATE FUNCTION {decoy_schema}.fixture_transform(value integer) RETURNS integer
               LANGUAGE sql IMMUTABLE AS $body$ SELECT value $body$;
             ALTER FUNCTION {decoy_schema}.fixture_transform(integer) OWNER TO {runtime_role};
             CREATE FUNCTION {decoy_schema}.fixture_trigger() RETURNS trigger
               LANGUAGE plpgsql AS $body$ BEGIN RETURN NEW; END $body$;
             CREATE TRIGGER decoy_trigger BEFORE INSERT ON {decoy_schema}.fixture_records
               FOR EACH ROW EXECUTE FUNCTION {decoy_schema}.fixture_trigger();
             ALTER SCHEMA {decoy_schema} OWNER TO {runtime_role};
             GRANT CREATE ON SCHEMA {decoy_schema} TO {runtime_role};
             GRANT TRIGGER ON {decoy_schema}.fixture_records TO {runtime_role};
             SET search_path TO {decoy_schema},{quoted_schema};"
        ))
        .await
        .expect("create product and earlier decoy schemas");
    let migration_role: String = transaction
        .query_one("SELECT quote_ident(current_user)", &[])
        .await
        .expect("read quoted migration role")
        .get(0);
    let expected = vec![
        format!("ALTER SEQUENCE {quoted_schema}.fixture_sequence OWNER TO {migration_role}"),
        format!(
            "ALTER ROUTINE {quoted_schema}.fixture_transform(value integer) OWNER TO {migration_role}"
        ),
    ];

    let weakness = first_authority_weakness(&transaction, &layout(), &runtime_role)
        .await
        .expect("inspect indirect ownership authority")
        .expect("actual product objects weaken the split role");
    match weakness.cause {
        AuthorityCause::OwnedObjects { statements, .. } => assert_eq!(statements, expected),
        cause => panic!("expected ownership corrections, got {cause:?}"),
    }
    let fixes = stray_authority(&transaction, &layout(), Some(&runtime_role))
        .await
        .expect("identify exact ownership remediation");
    assert_eq!(fixes, expected);
    for fix in &fixes {
        transaction
            .batch_execute(fix)
            .await
            .expect("execute emitted ownership remediation");
    }

    let owners = transaction
        .query_one(
            "SELECT
               pg_get_userbyid((SELECT relowner FROM pg_class c JOIN pg_namespace n
                 ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname='fixture_sequence')),
               pg_get_userbyid((SELECT proowner FROM pg_proc p JOIN pg_namespace n
                 ON n.oid=p.pronamespace WHERE n.nspname=$1 AND p.proname='fixture_transform')),
               pg_get_userbyid((SELECT nspowner FROM pg_namespace WHERE nspname=$2)),
               pg_get_userbyid((SELECT relowner FROM pg_class c JOIN pg_namespace n
                 ON n.oid=c.relnamespace WHERE n.nspname=$2 AND c.relname='fixture_records')),
               pg_get_userbyid((SELECT relowner FROM pg_class c JOIN pg_namespace n
                 ON n.oid=c.relnamespace WHERE n.nspname=$2 AND c.relname='fixture_sequence')),
               pg_get_userbyid((SELECT proowner FROM pg_proc p JOIN pg_namespace n
                 ON n.oid=p.pronamespace WHERE n.nspname=$2 AND p.proname='fixture_transform'))",
            &[&schema, &decoy_schema],
        )
        .await
        .expect("read product and decoy owners");
    let current_user: String = transaction
        .query_one("SELECT current_user::text", &[])
        .await
        .expect("read migration role")
        .get(0);
    assert_eq!(owners.get::<_, String>(0), current_user);
    assert_eq!(owners.get::<_, String>(1), current_user);
    for column in 2..6 {
        assert_eq!(
            owners.get::<_, String>(column),
            runtime_role,
            "decoy owner in column {column} must remain unchanged"
        );
    }
    assert!(
        first_authority_weakness(&transaction, &layout(), &runtime_role)
            .await
            .expect("reinspect ownership boundary")
            .is_none()
    );
    assert!(
        stray_authority(&transaction, &layout(), Some(&runtime_role))
            .await
            .expect("reinspect ownership remediation")
            .is_empty()
    );

    transaction
        .rollback()
        .await
        .expect("roll back isolated multi-schema fixture");
    drop(client);
    connection_task
        .await
        .expect("join PostgreSQL connection")
        .expect("PostgreSQL connection completes");
}

/// Before the ledger exists, an apply connection still has an explicit
/// migration role and ownership remediation uses its current schema.
#[tokio::test]
async fn ownership_remediation_falls_back_to_current_schema_before_the_ledger_exists() {
    let (mut client, connection) = tokio_postgres::connect(&database_url(), NoTls)
        .await
        .expect("connect to disposable PostgreSQL");
    let connection_task = tokio::spawn(connection);
    let suffix = Uuid::new_v4().simple().to_string();
    let schema = format!("activation_{suffix}");
    let runtime_role = format!("activation_runtime_{suffix}");
    let transaction = client.transaction().await.expect("start transaction");
    transaction
        .batch_execute(&format!(
            "CREATE ROLE {runtime_role} NOLOGIN;
             CREATE SCHEMA {schema};
             SET search_path TO {schema};
             CREATE TABLE fixture_records(record_id bigint PRIMARY KEY);
             ALTER TABLE fixture_records OWNER TO {runtime_role};"
        ))
        .await
        .expect("create pre-ledger product object");
    let migration_role: String = transaction
        .query_one("SELECT quote_ident(current_user)", &[])
        .await
        .expect("read quoted migration role")
        .get(0);
    let expected = format!("ALTER TABLE {schema}.fixture_records OWNER TO {migration_role}");

    let fixes = stray_authority(&transaction, &layout(), Some(&runtime_role))
        .await
        .expect("identify pre-ledger ownership remediation");
    assert_eq!(fixes, vec![expected]);
    transaction
        .batch_execute(&fixes[0])
        .await
        .expect("execute pre-ledger ownership remediation");
    let owner: String = transaction
        .query_one(
            "SELECT pg_get_userbyid(c.relowner) FROM pg_class c JOIN pg_namespace n
             ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname='fixture_records'",
            &[&schema],
        )
        .await
        .expect("read corrected owner")
        .get(0);
    let current_user: String = transaction
        .query_one("SELECT current_user::text", &[])
        .await
        .expect("read migration role")
        .get(0);
    assert_eq!(owner, current_user);

    transaction
        .rollback()
        .await
        .expect("roll back isolated pre-ledger fixture");
    drop(client);
    connection_task
        .await
        .expect("join PostgreSQL connection")
        .expect("PostgreSQL connection completes");
}

#[tokio::test]
async fn postgres_version_floor_precedes_missing_ledger_observation() {
    let (client, connection) = tokio_postgres::connect(&database_url(), NoTls)
        .await
        .expect("connect to disposable PostgreSQL");
    let connection_task = tokio::spawn(connection);
    let version: i32 = client
        .query_one("SELECT current_setting('server_version_num')::integer", &[])
        .await
        .expect("server version")
        .get(0);
    let missing = format!("missing_{}", Uuid::new_v4().simple());
    let result = registry_platform_activation::relation_exists(&client, &missing).await;
    if version < 170_000 {
        assert!(matches!(
            result,
            Err(registry_platform_activation::Error::UnsupportedPostgres)
        ));
        assert!(matches!(
            active_activation(&client, &layout()).await,
            Err(registry_platform_activation::Error::UnsupportedPostgres)
        ));
        assert!(matches!(
            registry_platform_activation::schema_state(&client, &layout(), &[1]).await,
            Err(registry_platform_activation::Error::UnsupportedPostgres)
        ));
    } else {
        assert!(!result.expect("supported server"));
    }
    drop(client);
    connection_task
        .await
        .expect("connection task")
        .expect("connection closes");
}

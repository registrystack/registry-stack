//! Database-boundary regressions: transient writes inside a Directory transaction
//! do not revoke authority, but committed loss cannot be undone by later regain.
use registry_casework::{DatabaseConfig, PostgresStore};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::json;
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

async fn fixture() -> (Client, Client, String) {
    let base = std::env::var("CASEWORK_ASSIGNMENT_TEST_DATABASE_URL")
        .expect("CASEWORK_ASSIGNMENT_TEST_DATABASE_URL must name a disposable database");
    let schema = format!("task_grants_{}", Uuid::new_v4().simple());
    let (admin, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let secret = format!("CASEWORK_TASK_TEST_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&secret, &scoped);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp").unwrap();
    let config = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret}"),
        migration_url_ref: format!("secret:env/{secret}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    PostgresStore::connect_migration(&config, &secrets)
        .unwrap()
        .migrate()
        .await
        .unwrap();
    std::env::remove_var(secret);
    let (database, connection) = tokio_postgres::connect(&scoped, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    database.batch_execute("INSERT INTO casework_teams(team_id,revision) VALUES('team',1); INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES('team','https://issuer.test','human','staff'); INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES('review','team',1)").await.unwrap();
    (database, admin, schema)
}

async fn grant(db: &Client) -> (Uuid, Uuid) {
    let item = Uuid::new_v4();
    let grant = Uuid::new_v4();
    let binding = json!({"sourceRevision":"1","version":"proposal-1","generation":"source-1"});
    db.execute("INSERT INTO casework_items(item_id,source_id,subject_kind,subject_id,occurrence_kind,occurrence_key,binding,state,queue_id,holder_issuer,holder_subject,revision,first_observed_at,updated_at) VALUES($1,'source','request',$2,'review',$2,$3,'claimed','review','https://issuer.test','human',1,now(),now())", &[&item,&item.to_string(),&binding]).await.unwrap();
    let record = json!({"template":{"itemStates":["claimed","waiting_applicant"],"itemKinds":["request"],"source":"source","eligibleTeams":["team"]},"proposal":{"version":"proposal-1","generation":"source-1","integrity":null},"subjects":{"person_reference":"synthetic-person"}});
    db.execute("INSERT INTO casework_task_grants(grant_id,item_id,approver_issuer,approver_subject,approver_profile,idempotency_key,request_hash,record,approved_at,expires_at) VALUES($1,$2,'https://issuer.test','human','staff',$3,'synthetic-hash',$4,now(),now()+interval '900 seconds')", &[&grant,&item,&grant.to_string(),&record]).await.unwrap();
    (item, grant)
}

async fn active(db: &Client, grant: Uuid) -> bool {
    db.query_one(
        "SELECT invalidated_at IS NULL FROM casework_task_grants WHERE grant_id=$1",
        &[&grant],
    )
    .await
    .unwrap()
    .get(0)
}

#[tokio::test]
async fn directory_loss_is_permanent_but_atomic_replacement_preserves_grants() {
    let (db, admin, schema) = fixture().await;
    let (_, id) = grant(&db).await;
    db.batch_execute("BEGIN; DELETE FROM casework_memberships; INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES('team','https://issuer.test','human','staff'); UPDATE casework_meta SET directory_revision=directory_revision+1; COMMIT").await.unwrap();
    assert!(
        active(&db, id).await,
        "unchanged atomic replacement preserves authority"
    );
    db.batch_execute("BEGIN; DELETE FROM casework_memberships; UPDATE casework_meta SET directory_revision=directory_revision+1; COMMIT").await.unwrap();
    assert!(
        !active(&db, id).await,
        "committed loss invalidates without an assertion lookup"
    );
    db.batch_execute("INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES('team','https://issuer.test','human','staff'); UPDATE casework_meta SET directory_revision=directory_revision+1").await.unwrap();
    assert!(
        !active(&db, id).await,
        "later regain cannot revive the grant"
    );
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM casework_history WHERE kind='task_invalidated'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1, "invalidation produces one durable event");
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
async fn holder_and_proposal_loss_are_permanent_but_revision_churn_is_allowed() {
    let (db, admin, schema) = fixture().await;
    let (item, id) = grant(&db).await;
    db.execute("UPDATE casework_items SET binding=jsonb_set(binding,'{sourceRevision}','\"2\"'),revision=revision+1 WHERE item_id=$1", &[&item]).await.unwrap();
    assert!(active(&db, id).await);
    db.execute(
        "UPDATE casework_items SET holder_subject='other' WHERE item_id=$1",
        &[&item],
    )
    .await
    .unwrap();
    db.execute(
        "UPDATE casework_items SET holder_subject='human' WHERE item_id=$1",
        &[&item],
    )
    .await
    .unwrap();
    assert!(!active(&db, id).await);
    let (item, id) = grant(&db).await;
    db.execute("UPDATE casework_items SET binding=jsonb_set(binding,'{version}','\"proposal-2\"') WHERE item_id=$1", &[&item]).await.unwrap();
    db.execute("UPDATE casework_items SET binding=jsonb_set(binding,'{version}','\"proposal-1\"') WHERE item_id=$1", &[&item]).await.unwrap();
    assert!(!active(&db, id).await);
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
async fn item_erasure_removes_selector_bearing_grant_records() {
    let (db, admin, schema) = fixture().await;
    let (item, id) = grant(&db).await;
    db.execute(
        "UPDATE casework_items SET erased_at=now() WHERE item_id=$1",
        &[&item],
    )
    .await
    .unwrap();
    assert!(db
        .query_opt(
            "SELECT record FROM casework_task_grants WHERE grant_id=$1",
            &[&id]
        )
        .await
        .unwrap()
        .is_none());
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

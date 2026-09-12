use super::*;
use registry_platform_config::{SecretProvider, SecretResolver};

#[tokio::test]
async fn template_versions_are_immutable_and_retirement_cannot_revive_existing_grants() {
    let base = std::env::var("CASEWORK_ASSIGNMENT_TEST_DATABASE_URL")
        .expect("CASEWORK_ASSIGNMENT_TEST_DATABASE_URL must name a disposable database");
    let schema = format!("task_templates_{}", Uuid::new_v4().simple());
    let (admin, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let secret = format!("CASEWORK_TEMPLATE_TEST_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&secret, &scoped);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp").unwrap();
    let config = crate::DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret}"),
        migration_url_ref: format!("secret:env/{secret}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let store = PostgresStore::connect_migration(&config, &secrets).unwrap();
    store.migrate().await.unwrap();
    std::env::remove_var(secret);
    let template: TaskTemplate = serde_json::from_value(json!({
        "id":"summary", "version":"1", "label":"Prepare summary", "eligibleTeams":["team"], "eligibleProfiles":["staff"],
        "source":"source", "itemKinds":["request"], "itemStates":["claimed"],
        "agent":{"issuer":"https://issuer.test","subject":"agent"}, "client":"agent-client", "resource":"urn:test:breg",
        "purpose":"prepare-summary","scopes":["records:get"], "bounds":{"type":"breg","permissions":[{"collection":"people","operations":["get"]}]},
        "subjects":{"person_reference":"person-reference"}, "lifetimeSeconds":900
    })).unwrap();
    store
        .activate_task_templates(std::slice::from_ref(&template))
        .await
        .unwrap();
    store
        .activate_task_templates(std::slice::from_ref(&template))
        .await
        .unwrap();
    let mut changed = template.clone();
    changed.purpose = "different-purpose".into();
    assert!(matches!(
        store.activate_task_templates(&[changed]).await,
        Err(StoreError::Configuration)
    ));
    let db = store.client().await.unwrap();
    let item = Uuid::new_v4();
    let grant = Uuid::new_v4();
    db.execute("INSERT INTO casework_items(item_id,source_id,subject_kind,subject_id,occurrence_kind,occurrence_key,binding,state,queue_id,revision,first_observed_at,updated_at) VALUES($1,'source','request','request-1','review','review-1',$2,'claimed','review',1,now(),now())", &[&item,&json!({"sourceRevision":"1","version":"1","generation":"1"})]).await.unwrap();
    db.execute("INSERT INTO casework_task_grants(grant_id,item_id,approver_issuer,approver_subject,approver_profile,idempotency_key,request_hash,record,approved_at,expires_at) VALUES($1,$2,'https://issuer.test','human','staff','key','hash',$3,now(),now()+interval '900 seconds')", &[&grant,&item,&json!({"template":template})]).await.unwrap();
    store.activate_task_templates(&[]).await.unwrap();
    let invalidated: bool = db
        .query_one(
            "SELECT invalidated_at IS NOT NULL FROM casework_task_grants WHERE grant_id=$1",
            &[&grant],
        )
        .await
        .unwrap()
        .get(0);
    assert!(invalidated);
    store.activate_task_templates(&[template]).await.unwrap();
    let invalidated: bool = db
        .query_one(
            "SELECT invalidated_at IS NOT NULL FROM casework_task_grants WHERE grant_id=$1",
            &[&grant],
        )
        .await
        .unwrap()
        .get(0);
    assert!(invalidated, "reactivation only permits new approvals");
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

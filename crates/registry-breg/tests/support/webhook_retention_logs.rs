// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::io;
use tracing::instrument::WithSubscriber;

#[derive(Clone, Default)]
struct Logs(Arc<std::sync::Mutex<Vec<u8>>>);
impl io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

async fn tick(
    service: &WebhookDeliveryService,
    batches: usize,
) -> (Result<(u64, bool), WebhookDeliveryError>, Vec<Value>) {
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(logs.clone())
        .finish();
    let result = service
        .prune_terminal_for_test(batches)
        .with_subscriber(subscriber)
        .await;
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    for canary in ["canary-retention", RECORD_VALUE_CANARY, "postgresql://"] {
        assert!(
            !text.contains(canary),
            "operational logs contain no raw canaries"
        );
    }
    let entries = text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|entry| {
            entry["fields"]["message"]
                .as_str()
                .is_some_and(|m| m.starts_with("hook metadata retention"))
        })
        .collect();
    (result, entries)
}

struct Fixture {
    database: TestDatabase,
    service: WebhookDeliveryService,
    receiver: HttpsReceiver,
    lock: RegistryLockKey,
    identity: ExpectedRegistryIdentity,
    compiled: CompiledRegistry,
}
impl Fixture {
    async fn start(rows: i32) -> Self {
        let receiver = HttpsReceiver::start().await;
        let database = TestDatabase::create(8).await;
        let (migration, migration_task) = database.connect_migration().await;
        let compiled = compiled_registry();
        install_compiled_schema(&migration, &compiled, &database.runtime_role)
            .await
            .unwrap();
        let identity = initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &compiled,
            registry_state_test_identity(),
        )
        .await
        .unwrap();
        migration_task.abort();
        let destination = DestinationFixture::new(&receiver);
        let destinations = Arc::new(destination.activate(&compiled));
        let pool = database.runtime_config.build_pool().unwrap();
        let profile = AuditProfile::production_from_secret_bytes(vec![0x6b; 32].into()).unwrap();
        let lock = RegistryLockKey::derive("webhook-delivery-registry").unwrap();
        let coordinator = MutationTransaction::new_with_event_destinations(
            lock,
            Duration::from_secs(2),
            identity.clone(),
            "webhook-delivery-instance",
            database.audit(profile.clone()),
            Some(destinations.clone()),
        );
        let service = WebhookDeliveryService::new(
            pool.clone(),
            destinations,
            hook_handlers(&compiled, &identity.activation_id),
            Arc::new(compiled.clone()),
            identity.clone(),
            "webhook-delivery-instance",
            lock,
            Duration::from_millis(100),
            database.audit(profile),
        );
        receiver.enqueue(ResponsePlan::Status(204)).await;
        let mut client = pool.get_for_test().await.unwrap();
        let event = create_event(
            &database,
            &coordinator,
            &mut client,
            &MutationPlan::from_compiled(&compiled, "records.case.create").unwrap(),
            &mutation_claims(&compiled),
            "canary-retention-log",
            "canary-retention-value",
        )
        .await;
        drop(client);
        service.deliver_once().await.unwrap();
        database.admin.execute("UPDATE registry_internal.registry_webhook_delivery_state SET updated_at=transaction_timestamp()-interval '400 days', delivered_at=transaction_timestamp()-interval '400 days' WHERE event_id=$1", &[&event.event_id]).await.unwrap();
        for table in [
            "registry_outbox",
            "registry_webhook_deliveries",
            "registry_webhook_delivery_state",
        ] {
            let sequence = if table == "registry_outbox" {
                ", 'outbox_id', nextval('registry_internal.registry_outbox_outbox_id_seq')"
            } else {
                ""
            };
            let overriding = if table == "registry_outbox" {
                " OVERRIDING SYSTEM VALUE"
            } else {
                ""
            };
            database
                .admin
                .batch_execute(&format!(
                    "INSERT INTO registry_internal.{table}{overriding}
                SELECT (jsonb_populate_record(NULL::registry_internal.{table}, to_jsonb(template) ||
                jsonb_build_object('event_id',md5('canary-retention-copy-' || n){sequence}))).*
                FROM registry_internal.{table} template CROSS JOIN generate_series(1,{copies}) n
                WHERE template.event_id='{event}'::uuid",
                    copies = rows - 1,
                    event = event.event_id
                ))
                .await
                .unwrap();
        }
        Self {
            database,
            service,
            receiver,
            lock,
            identity,
            compiled,
        }
    }
    async fn count(&self) -> i64 {
        self.database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_webhook_delivery_state",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn finish(self) {
        drop(self.service);
        drop(self.receiver);
        self.database.cleanup().await;
    }
}

fn failure(entries: &[Value], removed: u64, reason: &str) {
    assert_eq!(entries.len(), 1, "one operational failure per tick");
    assert_eq!(entries[0]["level"], "ERROR");
    assert_eq!(
        entries[0]["fields"],
        json!({"message":"hook metadata retention failed", "removed":removed, "reason":reason})
    );
}

#[tokio::test]
async fn retention_logs_one_count_per_nonzero_tick_and_keeps_idle_silent() {
    let fixture = Fixture::start(257).await;
    let (result, entries) = tick(&fixture.service, 1).await;
    assert_eq!(result.unwrap(), (256, true));
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["level"], "WARN");
    assert_eq!(
        entries[0]["fields"],
        json!({"message":"hook metadata retention reached its per-tick batch bound", "removed":256})
    );
    let (result, entries) = tick(&fixture.service, 100).await;
    assert_eq!(result.unwrap(), (1, false));
    assert_eq!(fixture.count().await, 0);
    assert_eq!(entries.len(), 1, "nonzero normal tick must be visible");
    assert_eq!(entries[0]["level"], "INFO");
    assert_eq!(
        entries[0]["fields"],
        json!({"message":"hook metadata retention completed","removed":1})
    );
    let (result, entries) = tick(&fixture.service, 100).await;
    assert_eq!(result.unwrap(), (0, false));
    assert!(entries.is_empty(), "idle ticks stay quiet");
    fixture.finish().await;
}

#[tokio::test]
async fn retention_logs_only_committed_progress_when_a_later_batch_fails() {
    let fixture = Fixture::start(257).await;
    fixture.database.admin.batch_execute("CREATE SEQUENCE registry_internal.retention_log_probe;
        GRANT USAGE,SELECT ON SEQUENCE registry_internal.retention_log_probe TO PUBLIC;
        CREATE FUNCTION registry_internal.retention_log_fail() RETURNS trigger LANGUAGE plpgsql AS $body$
        BEGIN IF nextval('registry_internal.retention_log_probe') > 256 THEN
          RAISE EXCEPTION 'canary-retention-database-message'; END IF; RETURN OLD; END $body$;
        CREATE TRIGGER retention_log_fail BEFORE DELETE ON registry_internal.registry_webhook_delivery_state
        FOR EACH ROW EXECUTE FUNCTION registry_internal.retention_log_fail()").await.unwrap();
    let (result, entries) = tick(&fixture.service, 100).await;
    assert!(result.is_err());
    assert_eq!(
        fixture.count().await,
        1,
        "first batch commits; failed second batch rolls back"
    );
    failure(&entries, 256, "database");
    fixture.finish().await;
}

#[tokio::test]
async fn retention_logs_registry_refusal_without_deletion() {
    let fixture = Fixture::start(1).await;
    fixture.database.admin.batch_execute("UPDATE registry_internal.registry_state SET maintenance_status='failed',maintenance_target_package_digest=active_package_digest").await.unwrap();
    let (result, entries) = tick(&fixture.service, 100).await;
    assert!(result.is_err());
    assert_eq!(fixture.count().await, 1);
    failure(&entries, 0, "registry-not-ready");
    fixture.finish().await;
}

#[tokio::test]
async fn retention_logs_lock_timeout_without_changing_record_refusal() {
    let fixture = Fixture::start(1).await;
    fixture
        .database
        .admin
        .execute("SELECT pg_advisory_lock($1)", &[&fixture.lock.get()])
        .await
        .unwrap();
    let (result, entries) = tick(&fixture.service, 100).await;
    assert!(result.is_err());
    assert_eq!(fixture.count().await, 1);
    let pool = fixture.database.runtime_config.build_pool().unwrap();
    let mut client = pool.get_for_test().await.unwrap();
    assert!(
        matches!(
            registry_breg::postgres::begin_record_transaction(
                &mut client,
                fixture.lock,
                Duration::from_millis(100),
                &fixture.identity,
                &mutation_claims(&fixture.compiled)
            )
            .await,
            Err(registry_breg::postgres::PostgresKernelError::RegistryUnavailable)
        ),
        "public record refusal is unchanged"
    );
    fixture
        .database
        .admin
        .execute("SELECT pg_advisory_unlock($1)", &[&fixture.lock.get()])
        .await
        .unwrap();
    drop(client);
    drop(pool);
    failure(&entries, 0, "lock-timeout");
    fixture.finish().await;
}

#[tokio::test]
async fn retention_logs_budget_cancellation_as_query_cancelled() {
    let fixture = Fixture::start(1).await;
    fixture.database.admin.batch_execute("CREATE FUNCTION registry_internal.retention_log_wait() RETURNS trigger LANGUAGE plpgsql AS $body$
        BEGIN PERFORM pg_sleep(11); RETURN OLD; END $body$;
        CREATE TRIGGER retention_log_wait BEFORE DELETE ON registry_internal.registry_webhook_delivery_state
        FOR EACH ROW EXECUTE FUNCTION registry_internal.retention_log_wait()").await.unwrap();
    let (result, entries) = tick(&fixture.service, 100).await;
    assert!(result.is_err());
    assert_eq!(fixture.count().await, 1);
    failure(&entries, 0, "query-cancelled");
    fixture.finish().await;
}

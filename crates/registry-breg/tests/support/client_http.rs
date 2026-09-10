// SPDX-License-Identifier: Apache-2.0

//! Real loopback HTTP for SDK tests using the owning database fixtures.
//!
//! These fixtures supply already-verified claims at the same seam as their
//! in-process router tests. Authentication itself is covered by the signed
//! package and mock-IdP journey in `pilot_acceptance_harness`.

use axum::{Extension, Router};
use registry_breg::api::VerifiedRequestClaims;
use registry_breg_client::{BaseRegistryClient, BaseRegistryClientConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

use super::postgres_harness::TestDatabase;
use registry_breg::api::{HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture};
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema, ExpectedRegistryIdentity,
    PostgresRecordMutationService, PostgresRecordReadService, PostgresRevisionReadService,
    PostgresSnapshotReadService, RegistryLockKey, RegistryStateTestIdentity,
};
use registry_platform_audit::AuditProfile;
use zeroize::Zeroizing;

pub struct ClientHttp {
    pub client: BaseRegistryClient,
    pub base_url: String,
    task: JoinHandle<()>,
}

impl ClientHttp {
    pub async fn start(router: Router, claims: VerifiedRequestClaims) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("SDK fixture binds a private loopback listener");
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let app = router.layer(Extension(claims));
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("SDK fixture HTTP server serves the real router");
        });
        let config = BaseRegistryClientConfig::new(base_url.parse().unwrap());
        let client = BaseRegistryClient::new(config).expect("loopback SDK config is valid");
        Self {
            client,
            base_url,
            task,
        }
    }
}

impl Drop for ClientHttp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The existing test database lifecycle with all ordinary BREG HTTP services.
/// Fixtures still own their compiled model and their verified claims.
pub struct ClientFixture {
    pub database: TestDatabase,
    pub registry: Arc<registry_breg::CompiledRegistry>,
    pub identity: ExpectedRegistryIdentity,
    pub http: ClientHttp,
}

impl ClientFixture {
    pub async fn start(
        registry: registry_breg::CompiledRegistry,
        claims: VerifiedRequestClaims,
    ) -> Self {
        assert!(
            !registry.ddl().requires_postgis,
            "spatial SDK tests use SpatialHarness"
        );
        let database = TestDatabase::create(8).await;
        if registry.ddl().requires_btree_gist {
            database
                .admin
                .batch_execute("CREATE EXTENSION btree_gist")
                .await
                .unwrap();
        }
        let registry = Arc::new(registry);
        let (migration, migration_task) = database.connect_migration().await;
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .unwrap();
        let identity = initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: registry.registry_id(),
                environment: "local",
                instance_id: "client-capability-test",
                database_id: "client-capability-database",
                package_revision: "client-capability-package-1",
                package_sequence: 1,
            },
        )
        .await
        .unwrap();
        drop(migration);
        migration_task.abort();
        let pool = database.runtime_config.build_pool().unwrap();
        let lock_key = RegistryLockKey::derive(registry.registry_id()).unwrap();
        let audit = AuditProfile::production_from_secret_bytes(vec![0x61; 32].into()).unwrap();
        let cursors = Arc::new(
            CursorCodec::new(Zeroizing::new(vec![0x62; 32]), Duration::from_secs(300)).unwrap(),
        );
        let records = PostgresRecordReadService::new(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            audit.clone(),
            cursors.clone(),
        );
        let mutations = PostgresRecordMutationService::new(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            audit.clone(),
        );
        let revisions = PostgresRevisionReadService::new(
            pool.clone(),
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            audit.clone(),
        );
        let snapshots = PostgresSnapshotReadService::new(
            pool,
            registry.clone(),
            identity.clone(),
            lock_key,
            Duration::from_secs(2),
            audit,
            cursors.clone(),
        );
        let service = HttpService::new(
            registry.clone(),
            ReadRuntimeIdentity {
                package_revision: identity.package_revision.clone(),
                schema_fingerprint: identity.schema_fingerprint.clone(),
            },
            Arc::new(records),
            Arc::new(Ready),
            cursors,
        )
        .with_postgres_mutations(Arc::new(mutations))
        .with_postgres_revisions(Arc::new(revisions))
        .with_snapshots(Arc::new(snapshots));
        let http = ClientHttp::start(registry_breg::api::router(Arc::new(service)), claims).await;
        Self {
            database,
            registry,
            identity,
            http,
        }
    }

    pub async fn finish(self) {
        drop(self.http);
        self.database.cleanup().await;
    }
}

struct Ready;

impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

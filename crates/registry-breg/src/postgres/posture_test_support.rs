// SPDX-License-Identifier: Apache-2.0

use registry_platform_config::Posture;

pub(crate) use super::external_projection::postgres_tests::harness::TestDatabase;
use super::ExpectedRegistryIdentity;

pub(crate) const MISMATCHES: [(Option<&str>, Posture); 3] = [
    (Some("development"), Posture::Production),
    (Some("production"), Posture::Development),
    (None, Posture::Development),
];

pub(crate) async fn install_ready_identity(database: &TestDatabase) -> ExpectedRegistryIdentity {
    let (migration, task) = database.connect_migration().await;
    migration
        .batch_execute(
            "CREATE TABLE registry_internal.registry_state (
            singleton boolean PRIMARY KEY,
            package_id text,
            database_id text,
            active_package_digest text,
            active_activation_id uuid,
            schema_fingerprint text,
            maintenance_status text,
            posture text
        );
        INSERT INTO registry_internal.registry_state VALUES
            (true, 'registry', 'database', 'package-digest',
             '00000000-0000-4000-8000-000000000001', 'fingerprint', 'ready', 'production')",
        )
        .await
        .unwrap();
    task.abort();
    ExpectedRegistryIdentity {
        package_id: "registry".into(),
        database_id: "database".into(),
        package_digest: "package-digest".into(),
        activation_id: "00000000-0000-4000-8000-000000000001".into(),
        schema_fingerprint: "fingerprint".into(),
    }
}

pub(crate) async fn record_posture(database: &TestDatabase, posture: Option<&str>) {
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state SET posture = $1 WHERE singleton",
            &[&posture],
        )
        .await
        .unwrap();
}

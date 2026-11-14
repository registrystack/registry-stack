// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]

use registry_adapter::payments::store::{migrate, PaymentStore};
use registry_payment_protocol::PaymentProblemCode;

#[tokio::test]
async fn same_key_different_body_never_aliases_a_command() {
    let url = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("postgres-test requires ADAPTER_TEST_DATABASE_URL");
    let config = url.parse().unwrap();
    let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
    let pool = deadpool_postgres::Pool::builder(manager)
        .max_size(4)
        .build()
        .unwrap();
    let mut client = pool.get().await.unwrap();
    migrate(&mut client).await.unwrap();
    let store = PaymentStore::new(pool, format!("payment-test-{}", uuid::Uuid::new_v4()));
    let id = uuid::Uuid::new_v4();
    store
        .claim_command("fees", "caller", "receipt", "key", "digest-1", id)
        .await
        .unwrap();
    assert_eq!(
        store
            .lookup_command("fees", "caller", "receipt", "key", "digest-1")
            .await
            .unwrap(),
        Some(id)
    );
    assert_eq!(
        store
            .lookup_command("fees", "caller", "receipt", "key", "digest-2")
            .await
            .unwrap_err(),
        PaymentProblemCode::Conflict
    );
    assert_eq!(
        store
            .lookup_command("fees", "other-caller", "receipt", "key", "digest-1")
            .await
            .unwrap(),
        None
    );
}

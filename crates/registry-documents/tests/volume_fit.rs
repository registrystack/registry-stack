// SPDX-License-Identifier: Apache-2.0

//! The populating half of the volume-fit measurement for PostgreSQL
//! `bytea` storage, driven by `products/documents/scripts/measure-volume-fit.sh`.
//!
//! This is a measurement, not verification, so it is ignored and never
//! part of a test run. It reserves, uploads, and verifies
//! `DOCUMENTS_VOLUME_DOCUMENTS` documents of `DOCUMENTS_VOLUME_BYTES` bytes
//! each through the runtime's own routes into a fresh schema of the
//! database `DOCUMENTS_TEST_DATABASE_URL` names, then prints one JSON line:
//! the schema, the document count and size, and the database and relation
//! sizes PostgreSQL reports. The schema is left in place for the script to
//! dump and restore. Each body is pseudo-random after a PDF header, so
//! neither TOAST compression nor the dump's compression flatters it: real
//! PDFs are mostly compressed streams.

mod support;

use axum::body::Body;
use registry_documents::runtime::prepare_with_verifier;
use support::{
    reservation, Api, Deployment, FakeVerifier, APP, APPROVE, DATABASE_STORAGE, DISABLED_VERIFIER,
};

const PDF: &str = "application/pdf";

fn count(name: &str) -> usize {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} names a positive count"))
        .parse()
        .unwrap_or_else(|_| panic!("{name} names a positive count"))
}

/// `length` bytes: a PDF header, then a xorshift stream seeded by `seed`.
fn body(length: usize, seed: u64) -> Vec<u8> {
    let mut bytes = b"%PDF-1.7\n".to_vec();
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    while bytes.len() < length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(length);
    bytes
}

#[tokio::test]
#[ignore = "measurement: run by products/documents/scripts/measure-volume-fit.sh"]
async fn populate_bytea_storage_for_the_volume_fit_measurement() {
    let documents = count("DOCUMENTS_VOLUME_DOCUMENTS");
    let bytes = count("DOCUMENTS_VOLUME_BYTES");
    assert!(documents > 0 && bytes > 0, "the counts are positive");
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let empty: i64 = deployment
        .scalar("SELECT pg_database_size(current_database())")
        .await;
    let verifier = FakeVerifier::new("volume-fit", APPROVE);
    let prepared = prepare_with_verifier(&deployment.runtime, verifier)
        .await
        .expect("the runtime prepares");
    let api = Api::new(&prepared);
    let started = std::time::Instant::now();
    for index in 0..documents {
        let content = body(bytes, index as u64 + 1);
        let custodian = format!("volume-citizen-{index}");
        let reserved = api
            .reserve(APP, "citizen-delivery", &custodian, &content, PDF)
            .await;
        let (_, _, path) = reservation(&reserved);
        let put = api.put(APP, &path, PDF, Body::from(content)).await;
        assert_eq!(put.status, 200, "{}", String::from_utf8_lossy(&put.body));
        if index % 100 == 99 {
            prepared.verify_due().await;
        }
    }
    prepared.verify_due().await;
    let elapsed = started.elapsed();
    let ready: i64 = deployment
        .scalar("SELECT count(*) FROM documents_contents")
        .await;
    assert_eq!(ready, documents as i64);
    deployment.execute("ANALYZE").await;
    let database: i64 = deployment
        .scalar("SELECT pg_database_size(current_database())")
        .await;
    let contents: i64 = deployment
        .scalar("SELECT pg_total_relation_size('documents_contents')")
        .await;
    let payload: i64 = deployment
        .scalar("SELECT sum(octet_length(content))::bigint FROM documents_contents")
        .await;
    let stored: i64 = deployment
        .scalar("SELECT sum(pg_column_size(content))::bigint FROM documents_contents")
        .await;
    println!(
        "{}",
        serde_json::json!({
            "schema": deployment.schema,
            "documents": documents,
            "documentBytes": bytes,
            "payloadBytes": payload,
            "storedColumnBytes": stored,
            "emptyDatabaseBytes": empty,
            "databaseBytes": database,
            "contentsRelationBytes": contents,
            "populateSeconds": elapsed.as_secs_f64(),
        })
    );
}

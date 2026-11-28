// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn storage_installs_the_ask_mirror_answers_and_feed_checkpoint() {
    let authority = Authority::start(false, true).await;
    let fixture = fixture(&authority).await;
    for table in [
        "registry_proposal_review_asks",
        "registry_proposal_review_ask_answers",
        "registry_proposal_review_ask_feed_events",
        "registry_proposal_review_ask_feed_checkpoints",
    ] {
        let name = format!("registry_internal.{table}");
        let found: Option<String> = fixture
            .database
            .admin
            .query_one("SELECT to_regclass($1)::text", &[&name])
            .await
            .unwrap()
            .get(0);
        assert!(found.is_some(), "missing ask storage: {table}");
    }
    fixture.finish().await;
}

// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn concealed_or_deleted_apply_targets_create_no_block_or_revision() {
    for deleted in [false, true] {
        let fixture =
            client_http::ClientFixture::start(registry(false), claims("author", "zone-a")).await;
        let client = &fixture.http.client;
        let draft = start(&fixture, "After", "hidden-target").await;
        let submitted = client
            .execute_proposal(
                &client
                    .prepare_proposal(&draft, "submit", json!({}), &key("hidden-submit"))
                    .unwrap(),
            )
            .await
            .unwrap()
            .value;
        let target =
            uuid::Uuid::parse_str(submitted.input().unwrap()["target"].as_str().unwrap()).unwrap();
        let entity = &fixture.registry.entities()["target"];
        let sql = if deleted {
            format!(
                "DELETE FROM registry_data.\"{}\" WHERE record_id=$1",
                entity.physical_table
            )
        } else {
            format!(
                "UPDATE registry_data.\"{}\" SET \"{}\"='zone-b' WHERE record_id=$1",
                entity.physical_table, entity.fields["jurisdiction"].physical_name
            )
        };
        fixture
            .database
            .admin
            .execute(&sql, &[&target])
            .await
            .unwrap();
        let refused = client.execute_proposal(&client.prepare_proposal(&submitted, "apply", json!({"submissionVersion":submitted.submission_version(),"effectDigest":submitted.effect_digest().unwrap()}), &key("hidden-apply")).unwrap()).await.unwrap_err();
        assert_eq!(
            refused.problem_code(),
            Some(BRegProblemCode::PreconditionFailed)
        );
        assert_eq!(
            client
                .read_proposal(&submitted)
                .await
                .unwrap_err()
                .problem_code(),
            Some(BRegProblemCode::ResourceNotFound)
        );
        let revision: i64 = fixture
            .database
            .admin
            .query_one(
                "SELECT workflow_revision FROM registry_internal.registry_proposal_state",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(revision as u64, submitted.revision());
        let blocks: i64 = fixture.database.admin.query_one("SELECT count(*) FROM registry_internal.registry_proposal_state WHERE blocked_reason IS NOT NULL", &[]).await.unwrap().get(0);
        assert_eq!(blocks, 0, "deleted={deleted}");
        fixture.finish().await;
    }
}

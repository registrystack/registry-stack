// SPDX-License-Identifier: Apache-2.0
//! RLS-scoped witness selection for targeted external projection refreshes.

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use crate::api::external_views::ExternalViewRequest;
use crate::model::CompiledRegistry;

use super::{active_scope, Plan, RefreshAfter, RefreshRows, Result, RootKeys};
use crate::postgres::external_label_acquisition::LabelAcquisition;
use crate::postgres::external_projection::{ProjectionGeneration, ProjectionScope};
use crate::postgres::GuardedTransaction;

/// Resolve one exact local root under the refresh worker's current RLS
/// context. An empty page is an exhaustive non-match, including a cleared
/// link. Database cancellation and statement-budget expiry remain errors.
pub(super) async fn exact_root(
    transaction: &GuardedTransaction<'_>,
    plan: &Plan<'_>,
    record_id: Uuid,
) -> Result<RefreshRows> {
    active_scope(transaction, plan.source, plan.projection.id.as_str()).await?;
    let keys = RootKeys::new(plan)?;
    let rows = keys
        .for_root(transaction, record_id)
        .await?
        .and_then(|selector| selector.filter(|selector| !selector.is_empty()))
        .map(|selector| vec![(record_id, Some(selector))])
        .unwrap_or_default();
    Ok(root_rows(keys, rows))
}

/// Find one RLS-visible root that currently links to `selector`. One witness
/// is sufficient because the accepted snapshot is shared inside its bound
/// projection scope. The publication guard rechecks the returned root.
pub(super) async fn primary_selector(
    transaction: &GuardedTransaction<'_>,
    plan: &Plan<'_>,
    selector: &str,
) -> Result<RefreshRows> {
    active_scope(transaction, plan.source, plan.projection.id.as_str()).await?;
    let keys = RootKeys::new(plan)?;
    let row = transaction
        .transaction()
        .query_opt(&primary_selector_sql(&keys), &[&selector])
        .await
        .map_err(|_| crate::api::external_views::ExternalViewError::Unavailable)?;
    let rows = row
        .map(|row| (row.get::<_, Uuid>(0), Some(row.get::<_, String>(1))))
        .into_iter()
        .collect();
    Ok(root_rows(keys, rows))
}

/// Resolve one label selector only through a current, fresh, complete parent
/// collection and an RLS-visible root. The returned supporting snapshot is
/// carried into both the pre-I/O authority guard and guarded publication.
pub(super) async fn label_selector(
    transaction: &GuardedTransaction<'_>,
    registry: &CompiledRegistry,
    request: &ExternalViewRequest,
    plan: &Plan<'_>,
    parent: &(ProjectionScope, ProjectionGeneration),
    selector: &str,
) -> Result<RefreshRows> {
    verify_label_scopes(transaction, plan, parent).await?;
    let labels = label_acquisition(registry, request, plan, parent)?;
    let page = labels
        .selector(transaction, selector)
        .await
        .map_err(|_| crate::api::external_views::ExternalViewError::Unavailable)?;
    Ok(label_rows(&labels, page))
}

/// Page the approved label selectors held by one current eligible parent root.
/// This is used after a targeted parent collection refresh, without restarting
/// a full label sweep.
#[allow(clippy::too_many_arguments)]
pub(super) async fn label_page_for_root(
    transaction: &GuardedTransaction<'_>,
    registry: &CompiledRegistry,
    request: &ExternalViewRequest,
    plan: &Plan<'_>,
    parent: &(ProjectionScope, ProjectionGeneration),
    root_id: Uuid,
    after_member: Option<&str>,
    limit: u16,
) -> Result<RefreshRows> {
    verify_label_scopes(transaction, plan, parent).await?;
    let labels = label_acquisition(registry, request, plan, parent)?;
    let page = labels
        .page_for_root(transaction, root_id, after_member, limit)
        .await
        .map_err(|_| crate::api::external_views::ExternalViewError::Unavailable)?;
    let next = page.continuation.as_ref().map(|after| RefreshAfter::Label {
        root_id: after.root_id,
        member_key: after.member_key.clone(),
    });
    let mut rows = label_rows(&labels, page);
    rows.next = next;
    Ok(rows)
}

impl RefreshRows {
    /// Recheck at most one hundred selected keys in one RLS statement. Each
    /// parallel-array entry carries one root chosen from the original page;
    /// every entry must still satisfy the same eligibility fragment used by
    /// guarded publication.
    pub(super) async fn targeted_witnesses_current(
        &self,
        transaction: &GuardedTransaction<'_>,
        selectors: &[String],
    ) -> Result<bool> {
        if selectors.len() > 100 {
            return Err(crate::api::external_views::ExternalViewError::Unavailable);
        }
        if selectors.is_empty() {
            return Ok(true);
        }
        let witnesses = self
            .rows
            .iter()
            .filter_map(|(root, candidate)| candidate.as_deref().map(|key| (key, *root)))
            .collect::<BTreeMap<_, _>>();
        let roots = selectors
            .iter()
            .map(|selector| witnesses.get(selector.as_str()).copied())
            .collect::<Option<Vec<_>>>();
        let Some(roots) = roots else { return Ok(false) };
        let selectors = selectors.to_vec();
        transaction
            .transaction()
            .query_one(
                &eligibility_batch_probe_sql(&self.eligibility)?,
                &[&selectors, &roots],
            )
            .await
            .map(|row| row.get::<_, bool>(0))
            .map_err(|_| crate::api::external_views::ExternalViewError::Unavailable)
    }
}

async fn verify_label_scopes(
    transaction: &GuardedTransaction<'_>,
    plan: &Plan<'_>,
    parent: &(ProjectionScope, ProjectionGeneration),
) -> Result<()> {
    active_scope(transaction, plan.source, plan.projection.id.as_str()).await?;
    let configured = plan
        .label_parent
        .as_ref()
        .ok_or(crate::api::external_views::ExternalViewError::Concealed)?;
    let current = active_scope(
        transaction,
        configured.source,
        configured.projection.id.as_str(),
    )
    .await?;
    if current.epoch != parent.0.epoch {
        return Err(
            crate::api::external_views::ExternalViewError::ProjectionUnavailable(
                configured.projection.id.to_string(),
            ),
        );
    }
    Ok(())
}

fn label_acquisition(
    registry: &CompiledRegistry,
    request: &ExternalViewRequest,
    plan: &Plan<'_>,
    parent: &(ProjectionScope, ProjectionGeneration),
) -> Result<LabelAcquisition> {
    if plan.label_parent.is_none() {
        return Err(crate::api::external_views::ExternalViewError::Concealed);
    }
    LabelAcquisition::new(
        registry,
        request.context.selected_profile(),
        request
            .context
            .purpose()
            .ok_or(crate::api::external_views::ExternalViewError::Concealed)?,
        &request.view,
        &request.link,
        &parent.0,
        parent.1,
    )
    .map_err(|_| crate::api::external_views::ExternalViewError::Concealed)
}

fn root_rows(keys: RootKeys, rows: Vec<(Uuid, Option<String>)>) -> RefreshRows {
    RefreshRows {
        rows,
        next: None,
        eligibility: keys.publication_eligibility,
        supporting_until: None,
        supporting: Vec::new(),
    }
}

fn label_rows(
    labels: &LabelAcquisition,
    page: crate::postgres::external_label_acquisition::LabelSelectorPage,
) -> RefreshRows {
    RefreshRows {
        rows: page
            .rows
            .into_iter()
            .map(|row| (row.root_id, Some(row.selector)))
            .collect(),
        next: None,
        eligibility: labels.publication_eligibility().to_owned(),
        supporting_until: page.minimum_parent_expires_at,
        supporting: page.supporting,
    }
}

fn primary_selector_sql(keys: &RootKeys) -> String {
    // The subquery is a simple projection, so PostgreSQL can push this
    // equality into the generated source relation and use the managed current
    // link index while RLS applies the worker's complete row policy.
    format!(
        "SELECT root_id,subject_key FROM ({}) AS eligible_roots(root_id,subject_key) \
         WHERE subject_key = $1::text ORDER BY root_id LIMIT 1",
        keys.select
    )
}

#[cfg(test)]
fn eligibility_probe_sql(publication_eligibility: &str) -> Result<String> {
    let rebound = remap_eligibility_parameters(publication_eligibility, "$1", "$2")?;
    Ok(format!("SELECT EXISTS({rebound})"))
}

fn eligibility_batch_probe_sql(publication_eligibility: &str) -> Result<String> {
    let rebound = remap_eligibility_parameters(
        publication_eligibility,
        "targets.selector",
        "ARRAY[targets.root_id]",
    )?;
    Ok(format!(
        "SELECT COALESCE(bool_and(EXISTS({rebound})),true) \
         FROM unnest($1::text[], $2::uuid[]) AS targets(selector,root_id)"
    ))
}

fn remap_eligibility_parameters(
    publication_eligibility: &str,
    selector: &'static str,
    roots: &'static str,
) -> Result<String> {
    let mut parameters = BTreeSet::new();
    let bytes = publication_eligibility.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset] != b'$' {
            offset += 1;
            continue;
        }
        let start = offset + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end == start {
            return Err(crate::api::external_views::ExternalViewError::Unavailable);
        }
        parameters.insert(&publication_eligibility[start..end]);
        offset = end;
    }
    if parameters != BTreeSet::from(["6", "12"]) {
        return Err(crate::api::external_views::ExternalViewError::Unavailable);
    }
    Ok(publication_eligibility
        .replace("$12", "__ROOTS_PARAMETER__")
        .replace("$6", selector)
        .replace("__ROOTS_PARAMETER__", roots))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> RootKeys {
        RootKeys {
            select: "SELECT root_id, subject_key FROM registry_source.roots".to_owned(),
            publication_eligibility: "SELECT 1 FROM registry_source.roots WHERE root_id = ANY($12::uuid[]) AND subject_key = $6::text".to_owned(),
            id: "root_id".to_owned(),
            base_id: "base.record_id".to_owned(),
        }
    }

    #[test]
    fn primary_selector_seeks_one_rls_visible_root_by_key() {
        let sql = primary_selector_sql(&keys());
        assert!(sql.contains("subject_key = $1::text"));
        assert!(sql.contains("ORDER BY root_id"));
        assert!(sql.ends_with("LIMIT 1"));
        assert!(!sql.contains("OFFSET"));
    }

    #[test]
    fn pre_io_witness_probe_reuses_publication_eligibility() {
        let sql = eligibility_probe_sql(&keys().publication_eligibility).unwrap();
        assert_eq!(
            sql,
            "SELECT EXISTS(SELECT 1 FROM registry_source.roots WHERE root_id = ANY($2::uuid[]) AND subject_key = $1::text)"
        );
    }

    #[test]
    fn batch_witness_probe_reuses_publication_eligibility_once_for_parallel_arrays() {
        let sql = eligibility_batch_probe_sql(&keys().publication_eligibility).unwrap();
        assert!(sql.contains("unnest($1::text[], $2::uuid[])"));
        assert!(sql.contains("subject_key = targets.selector::text"));
        assert!(sql.contains("root_id = ANY(ARRAY[targets.root_id]::uuid[])"));
        assert!(sql.contains("bool_and(EXISTS("));
        assert_eq!(sql.matches("registry_source.roots").count(), 1);
    }

    #[test]
    fn witness_probe_rejects_an_unexpected_parameter_contract() {
        assert!(eligibility_probe_sql("SELECT 1 WHERE value=$5").is_err());
        assert!(
            eligibility_probe_sql("SELECT 1 WHERE value=$6 AND root=ANY($12) AND extra=$3")
                .is_err()
        );
    }
}

#[cfg(test)]
#[cfg(feature = "postgres-test")]
mod postgres_tests {
    use super::*;
    use crate::postgres::read::ReadRelations;
    use serde_json::{json, Value};
    use tokio_postgres::NoTls;

    #[allow(dead_code)]
    mod harness {
        use crate as registry_breg;
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/postgres_harness.rs"
        ));
    }

    fn registry() -> CompiledRegistry {
        let project = json!({
            "apiVersion": crate::compiler::AUTHORING_API_VERSION,
            "kind": "BRegProject",
            "project": {"id":"targeted-lookup","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://fixture.example.test"},
            "datasets": [{"id":"records"}],
            "recordTypes": [{"id":"local-record","primaryDataset":"records","route":"records","mutationMode":"mutable","classification":"internal","fields":[
                {"id":"subject-key","type":"string","maximumLength":64,"classification":"internal"},
                {"id":"tenant","type":"string","maximumLength":32,"classification":"internal"}
            ]}],
            "externalRecordTypes": [{"id":"subject","authority":"urn:test:source","identifierScheme":"urn:test:subject","fields":[{"id":"name","type":"string","classification":"internal"}]}],
            "externalProjections": [{"id":"subjects","recordType":"subject","operation":"subjects","operationVersion":"1","purpose":"consultation","scope":"eligible","selectorScheme":"urn:test:subject","mode":"indexed","cardinality":"one","cacheTtlSeconds":60,"fields":["name"]}],
            "externalViews": [{"id":"view","recordType":"local-record","links":[{"id":"subject","projection":"subjects","fromField":"subject-key","identifierScheme":"urn:test:subject","fields":["name"]}]}],
            "accessProfiles": [{"id":"refresh","principalClaim":"registry_principal","actorKind":"service","requesterClients":["worker"],"requiredScopes":["registry.refresh"],"requiredPurposes":["consultation"],"permissions":{
                "records":[{"recordType":"local-record","operations":["list"],"rowBoundaries":[{"field":"tenant","claim":"tenant","operator":"equals"}]}],
                "refreshExternalProjections":["subjects"]
            }}]
        });
        let project =
            crate::contract::parse_project_json(&serde_json::to_vec(&project).unwrap()).unwrap();
        crate::compiler::compile_project(&project, &[], crate::compiler::CompileProfile::Authoring)
            .unwrap()
    }

    fn keys(registry: &CompiledRegistry) -> RootKeys {
        let entity = &registry.entities()["local-record"];
        let relations = ReadRelations::statistics(entity, &["subject-key".to_owned()]).unwrap();
        let key = relations.field_expression(entity, "subject-key").unwrap();
        RootKeys {
            select: format!(
                "SELECT {}, ({})::text FROM {}",
                relations.id_expression, key.sql, relations.from_sql
            ),
            publication_eligibility: format!(
                "SELECT 1 FROM {} WHERE {} = ANY($12::uuid[]) AND ({})::text = $6::text",
                relations.from_sql, relations.id_expression, key.sql
            ),
            id: relations.id_expression,
            base_id: format!("{}.record_id", relations.base_alias),
        }
    }

    fn plan_nodes<'a>(plan: &'a Value, nodes: &mut Vec<&'a Value>) {
        nodes.push(plan);
        for child in plan["Plans"].as_array().into_iter().flatten() {
            plan_nodes(child, nodes);
        }
    }

    #[tokio::test]
    async fn selector_lookup_skips_a_large_excluded_prefix_and_exhausts_no_witness() {
        let database = harness::TestDatabase::create(2).await;
        let (migration, migration_task) = database.connect_migration().await;
        let registry = registry();
        super::super::super::install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .unwrap();
        let entity = &registry.entities()["local-record"];
        let column = |id: &str| {
            entity
                .stored_fields
                .iter()
                .find(|field| field.logical.id == id)
                .unwrap()
                .physical_name
                .clone()
        };
        database.admin.batch_execute(&format!(
            "INSERT INTO registry_data.\"{table}\" (record_id,active_package_revision,\"{key}\",\"{tenant}\")
             SELECT ('00000000-0000-4000-8001-'||lpad(to_hex(g),12,'0'))::uuid,'fixture',
                    CASE WHEN g<=50000 THEN 'target' ELSE 'unmatched' END,'aaa'
             FROM generate_series(1,100000) AS g;
             INSERT INTO registry_data.\"{table}\" (record_id,active_package_revision,\"{key}\",\"{tenant}\")
             VALUES ('00000000-0000-4000-8000-000000000001','fixture','target','zzz'),
                    ('00000000-0000-4000-8000-000000000002','fixture','second','zzz');
             ANALYZE registry_data.\"{table}\";",
            table = entity.physical_table,
            key = column("subject-key"),
            tenant = column("tenant"),
        )).await.unwrap();
        let (runtime, connection) = database
            .runtime_config
            .postgres()
            .connect(NoTls)
            .await
            .unwrap();
        let runtime_task = tokio::spawn(async move { connection.await.unwrap() });
        runtime.batch_execute("SET registry.access_profile='refresh'; SET registry.principal='worker'; SET registry.purpose='consultation'; SET registry.row_boundaries='[{\"field\":\"tenant\",\"operator\":\"equals\",\"values\":[\"zzz\"]}]';").await.unwrap();
        let sql = primary_selector_sql(&keys(&registry));
        let expected = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        assert_eq!(
            runtime
                .query_one(&sql, &[&"target"])
                .await
                .unwrap()
                .get::<_, Uuid>(0),
            expected
        );
        assert!(runtime
            .query_opt(&sql, &[&"unmatched"])
            .await
            .unwrap()
            .is_none());
        let batch_sql =
            eligibility_batch_probe_sql(&keys(&registry).publication_eligibility).unwrap();
        let second = Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap();
        assert!(runtime
            .query_one(
                &batch_sql,
                &[
                    &vec!["target".to_owned(), "second".to_owned()],
                    &vec![expected, second]
                ],
            )
            .await
            .unwrap()
            .get::<_, bool>(0));
        let excluded = Uuid::parse_str("00000000-0000-4000-8001-00000000c351").unwrap();
        assert!(!runtime
            .query_one(
                &batch_sql,
                &[
                    &vec!["target".to_owned(), "unmatched".to_owned()],
                    &vec![expected, excluded]
                ],
            )
            .await
            .unwrap()
            .get::<_, bool>(0));
        for selector in ["target", "unmatched"] {
            let explained: Value = runtime
                .query_one(
                    &format!(
                        "EXPLAIN (ANALYZE, FORMAT JSON, COSTS OFF, TIMING OFF, SUMMARY OFF) {sql}"
                    ),
                    &[&selector],
                )
                .await
                .unwrap()
                .get(0);
            let mut nodes = Vec::new();
            plan_nodes(&explained[0]["Plan"], &mut nodes);
            assert!(
                nodes.iter().any(|node| {
                    node["Node Type"]
                        .as_str()
                        .is_some_and(|kind| kind.contains("Index"))
                }),
                "{selector}: {explained}"
            );
            for node in nodes {
                let loops = node["Actual Loops"].as_f64().unwrap_or(1.0);
                let rows = node["Actual Rows"].as_f64().unwrap_or(0.0) * loops;
                let removed = node["Rows Removed by Filter"].as_f64().unwrap_or(0.0) * loops;
                assert!(rows + removed <= 20.0, "{selector}: {explained}");
            }
        }
        runtime_task.abort();
        migration_task.abort();
        drop(runtime);
        drop(migration);
        database.cleanup().await;
    }
}

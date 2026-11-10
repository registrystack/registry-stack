// SPDX-License-Identifier: Apache-2.0
//! Internal label selectors reached through authorized, fresh related rows.

use std::fmt;

use serde::Deserialize;
use uuid::Uuid;

use crate::contract::{ActorKindSource, Operation};
use crate::external_views::{ExternalCardinality, ExternalFieldType, ExternalProjectionMode};
use crate::model::CompiledRegistry;

use super::external_projection::{ProjectionGeneration, ProjectionScope};
use super::external_view_query::ExternalQueryError;
use super::read::ReadRelations;
use super::GuardedTransaction;

type Result<T> = std::result::Result<T, ExternalQueryError>;

/// Internal position, carried only in an encrypted, generation-bound cursor.
#[derive(Clone)]
pub(crate) struct LabelAfter {
    pub(crate) root_id: Uuid,
    pub(crate) member_key: String,
}

impl fmt::Debug for LabelAfter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LabelAfter(<redacted>)")
    }
}

#[derive(Deserialize)]
pub(crate) struct LabelSelector {
    pub(crate) root_id: Uuid,
    pub(crate) member_key: String,
    pub(crate) selector: String,
    parent_key: String,
    parent_snapshot: String,
    parent_expires_at: i64,
}

/// One parent snapshot that supplied label selectors. Acquisition goes ahead
/// only while that exact snapshot is still current and unexpired.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SupportingSnapshot {
    pub(crate) subject_key: String,
    pub(crate) snapshot_id: String,
}

impl fmt::Debug for SupportingSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SupportingSnapshot(<redacted>)")
    }
}

impl fmt::Debug for LabelSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LabelSelector(<redacted>)")
    }
}

pub(crate) struct LabelSelectorPage {
    pub(crate) rows: Vec<LabelSelector>,
    pub(crate) continuation: Option<LabelAfter>,
    pub(crate) minimum_parent_expires_at: Option<i64>,
    pub(crate) supporting: Vec<SupportingSnapshot>,
}

pub(crate) struct LabelAcquisition {
    page_sql: String,
    publication_sql: String,
}

impl LabelAcquisition {
    /// The caller admits the service identity and current source grants, then
    /// installs the root claim context in its guarded transaction. This seam
    /// rechecks the compiled grants for both hops without disclosing selectors.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        registry: &CompiledRegistry,
        profile_id: &str,
        purpose: &str,
        view_id: &str,
        link_id: &str,
        parent_scope: &ProjectionScope,
        parent_generation: ProjectionGeneration,
    ) -> Result<Self> {
        let inventory = registry.external_views();
        let view = inventory
            .views
            .get(view_id)
            .ok_or(ExternalQueryError::NotPermitted)?;
        let link = view
            .links
            .iter()
            .find(|link| link.id.as_str() == link_id)
            .ok_or(ExternalQueryError::NotPermitted)?;
        let label = link
            .label
            .as_ref()
            .ok_or(ExternalQueryError::NotPermitted)?;
        let parent = inventory
            .projections
            .get(link.projection.as_str())
            .ok_or(ExternalQueryError::NotPermitted)?;
        let target = inventory
            .projections
            .get(label.projection.as_str())
            .ok_or(ExternalQueryError::NotPermitted)?;
        let entity = registry
            .entities()
            .get(view.record_type.as_str())
            .ok_or(ExternalQueryError::NotPermitted)?;
        let profile = entity
            .access_profiles
            .get(profile_id)
            .ok_or(ExternalQueryError::NotPermitted)?;
        let refresh = inventory
            .refresh
            .get(profile_id)
            .ok_or(ExternalQueryError::NotPermitted)?;
        let direct_selector = inventory
            .record_types
            .get(parent.record_type.as_str())
            .is_some_and(|record| {
                record.fields.iter().any(|field| {
                    field.id == label.from_field
                        && matches!(
                            field.value_type,
                            ExternalFieldType::String | ExternalFieldType::Uuid
                        )
                })
            });
        if profile.actor_kind != Some(ActorKindSource::Service)
            || profile.requester_clients.is_empty()
            || profile.required_scopes.is_empty()
            || !profile.required_purposes.contains(purpose)
            || !profile.operations.contains(&Operation::List)
            || !refresh.contains(&parent.id)
            || !refresh.contains(&target.id)
            || parent.mode != ExternalProjectionMode::Indexed
            || target.mode != ExternalProjectionMode::Indexed
            || parent.cardinality != ExternalCardinality::Many
            || target.cardinality != ExternalCardinality::One
            || parent.purpose.as_str() != purpose
            || target.purpose.as_str() != purpose
            || target.selector_scheme != label.identifier_scheme
            || !parent.fields.contains(&label.from_field)
            || !direct_selector
            || parent_scope.projection_id != parent.id.as_str()
            || parent_scope.epoch != parent_generation.epoch
            || parent_generation.generation < 0
        {
            return Err(ExternalQueryError::NotPermitted);
        }
        let key_field = link.from_field.as_str();
        let relations = ReadRelations::statistics(entity, &[key_field.to_owned()])
            .map_err(|_| ExternalQueryError::Unavailable)?;
        let key = relations
            .field_expression(entity, key_field)
            .map_err(|_| ExternalQueryError::Unavailable)?;
        if key.encrypted {
            return Err(ExternalQueryError::NotPermitted);
        }
        let root_sql=format!("SELECT {} AS root_id,({})::text AS subject_key FROM {} WHERE current_setting('registry.access_profile',true)={} AND current_setting('registry.purpose',true)={}",relations.id_expression,key.sql,relations.from_sql,literal(profile_id),literal(purpose));
        let state_sql=format!("SELECT projection_id,epoch FROM registry_internal.registry_external_projection_scopes WHERE projection_id={} AND epoch={}::uuid AND binding_digest={} AND grant_digest={} AND generation={} AND active",literal(&parent_scope.projection_id),literal(&parent_scope.epoch.to_string()),literal(&parent_scope.binding_digest),literal(&parent_scope.grant_digest),parent_generation.generation);
        Ok(Self::statements(
            &root_sql,
            &state_sql,
            label.from_field.as_str(),
        ))
    }

    fn statements(root_sql: &str, state_sql: &str, selector_field: &str) -> Self {
        // These replacements contain only compiled identifiers, profile names,
        // and scope fingerprints. Member positions and selectors are bound.
        let eligible = ELIGIBLE_SQL
            .replace("__ROOT_SQL__", root_sql)
            .replace("__SELECTOR_FIELD__", &literal(selector_field));
        let page_sql = PAGE_SQL
            .replace("__STATE_SQL__", state_sql)
            .replace("__ELIGIBLE_SQL__", &eligible);
        let publication_sql = PUBLICATION_SQL
            .replace("__STATE_SQL__", state_sql)
            .replace("__ELIGIBLE_SQL__", &eligible);
        Self {
            page_sql,
            publication_sql,
        }
    }

    /// Use with publish_for_roots: $6 is the label selector, $12 the admitted
    /// root IDs. Current parent generation and member association are checked
    /// in that same statement, without interpolating source keys into SQL.
    pub(crate) fn publication_eligibility(&self) -> &str {
        &self.publication_sql
    }

    pub(crate) async fn page(
        &self,
        transaction: &GuardedTransaction<'_>,
        after: Option<&LabelAfter>,
        limit: u16,
    ) -> Result<LabelSelectorPage> {
        if !(1..=1000).contains(&limit)
            || after.is_some_and(|position| {
                position.member_key.is_empty() || position.member_key.len() > 1024
            })
        {
            return Err(ExternalQueryError::InvalidQuery);
        }
        let root = after.map(|position| position.root_id);
        let member = after.map(|position| position.member_key.as_str());
        let bound = i64::from(limit) + 1;
        let result = transaction
            .transaction()
            .query_one(&self.page_sql, &[&root, &member, &bound])
            .await
            .map_err(|_| ExternalQueryError::Unavailable)?;
        if !result.get::<_, bool>(0) {
            return Err(ExternalQueryError::GenerationChanged);
        }
        let rows: Vec<LabelSelector> =
            serde_json::from_value(result.get(1)).map_err(|_| ExternalQueryError::Unavailable)?;
        Ok(bounded_page(rows, limit))
    }
}

fn bounded_page(mut rows: Vec<LabelSelector>, limit: u16) -> LabelSelectorPage {
    let has_more = rows.len() > usize::from(limit);
    rows.truncate(usize::from(limit));
    let continuation = if has_more {
        rows.last().map(|row| LabelAfter {
            root_id: row.root_id,
            member_key: row.member_key.clone(),
        })
    } else {
        None
    };
    let minimum_parent_expires_at = rows.iter().map(|row| row.parent_expires_at).min();
    let supporting = rows
        .iter()
        .map(|row| SupportingSnapshot {
            subject_key: row.parent_key.clone(),
            snapshot_id: row.parent_snapshot.clone(),
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    LabelSelectorPage {
        rows,
        continuation,
        minimum_parent_expires_at,
        supporting,
    }
}

fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

const ELIGIBLE_SQL: &str = r#"
SELECT roots.root_id,members.source_key AS member_key,members.fields->>__SELECTOR_FIELD__ AS selector,
    snapshot.subject_key AS parent_key,snapshot.snapshot_id AS parent_snapshot,snapshot.expires_at AS parent_expires_at
FROM (__ROOT_SQL__) AS roots
JOIN parent_state AS scope ON true
JOIN registry_internal.registry_external_projection_snapshots AS snapshot
    ON snapshot.projection_id=scope.projection_id AND snapshot.epoch=scope.epoch
    AND snapshot.subject_key=roots.subject_key AND snapshot.kind='complete-collection'
    AND snapshot.expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint
JOIN registry_internal.registry_external_projection_values AS members
    ON members.projection_id=snapshot.projection_id AND members.epoch=snapshot.epoch AND members.subject_key=snapshot.subject_key
WHERE jsonb_typeof(members.fields->__SELECTOR_FIELD__)='string'
    AND octet_length(members.fields->>__SELECTOR_FIELD__) BETWEEN 1 AND 1024
    AND (members.fields->>__SELECTOR_FIELD__) !~ '[[:cntrl:]]'
"#;

const PAGE_SQL: &str = r#"
WITH parent_state AS MATERIALIZED (__STATE_SQL__), selected AS (
    __ELIGIBLE_SQL__
), page AS MATERIALIZED (
    SELECT root_id,member_key,selector,parent_key,parent_snapshot,parent_expires_at FROM selected
    WHERE $1::uuid IS NULL OR root_id>$1::uuid OR (root_id=$1::uuid AND member_key COLLATE "C">$2::text COLLATE "C")
    ORDER BY root_id,member_key COLLATE "C" LIMIT $3::bigint
)
SELECT EXISTS(SELECT 1 FROM parent_state),COALESCE((SELECT jsonb_agg(jsonb_build_object(
    'root_id',root_id,'member_key',member_key,'selector',selector,'parent_key',parent_key,
    'parent_snapshot',parent_snapshot,'parent_expires_at',parent_expires_at) ORDER BY root_id,member_key COLLATE "C") FROM page),'[]'::jsonb)
"#;

const PUBLICATION_SQL: &str = r#"
WITH parent_state AS MATERIALIZED (__STATE_SQL__)
SELECT 1 FROM (__ELIGIBLE_SQL__) AS selected
WHERE selected.root_id=ANY($12::uuid[]) AND selected.selector=$6::text
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(super) fn registry(grants: &[&str]) -> CompiledRegistry {
        let project = json!({
            "apiVersion":crate::compiler::AUTHORING_API_VERSION,"kind":"BRegProject",
            "project":{"id":"label-acquisition","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://fixture.example.test"},
            "datasets":[{"id":"records"}],
            "recordTypes":[{"id":"local-record","primaryDataset":"records","route":"records","mutationMode":"mutable","classification":"internal","fields":[
                {"id":"subject-key","type":"string","maximumLength":64,"classification":"internal"},
                {"id":"tenant","type":"string","maximumLength":32,"classification":"internal"}]}],
            "externalRecordTypes":[
                {"id":"member","authority":"urn:test:source","identifierScheme":"urn:test:member","fields":[{"id":"holder","type":"string","classification":"restricted","nullable":true}]},
                {"id":"label-record","authority":"urn:test:source","identifierScheme":"urn:test:person","fields":[{"id":"name","type":"string","classification":"internal"}]}],
            "externalProjections":[
                {"id":"parent","recordType":"member","operation":"members","operationVersion":"1","purpose":"consultation","scope":"eligible","selectorScheme":"urn:test:keys","mode":"indexed","cardinality":"many","cacheTtlSeconds":60,"fields":["holder"]},
                {"id":"label","recordType":"label-record","operation":"batch","operationVersion":"1","purpose":"consultation","scope":"eligible","selectorScheme":"urn:test:person","mode":"indexed","cardinality":"one","cacheTtlSeconds":60,"fields":["name"]}],
            "externalViews":[{"id":"view","recordType":"local-record","links":[{"id":"members","projection":"parent","fromField":"subject-key","identifierScheme":"urn:test:keys","fields":["holder"],"label":{"projection":"label","fromField":"holder","identifierScheme":"urn:test:person","fields":["name"]}}]}],
            "accessProfiles":[{"id":"refresh","principalClaim":"registry_principal","actorKind":"service","requesterClients":["worker"],"requiredScopes":["registry.refresh"],"requiredPurposes":["consultation"],"permissions":{
                "records":[{"recordType":"local-record","operations":["list"],"rowBoundaries":[{"field":"tenant","claim":"tenant","operator":"equals"}]}],
                "refreshExternalProjections":["parent","label"]}}]
        });
        let project =
            crate::contract::parse_project_json(&serde_json::to_vec(&project).unwrap()).unwrap();
        let compiled = crate::compiler::compile_project(
            &project,
            &[],
            crate::compiler::CompileProfile::Authoring,
        )
        .unwrap();
        // Exercise the SQL seam's independent grant check on a bounded copy.
        let mut value = serde_json::to_value(compiled).unwrap();
        value["externalViews"]["refresh"]["refresh"] = json!(grants);
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn separate_machine_grants_and_same_purpose_are_required() {
        let scope = ProjectionScope::new("parent", Uuid::new_v4(), "binding", "grant", 60).unwrap();
        let generation = ProjectionGeneration {
            epoch: scope.epoch,
            generation: 1,
        };
        for grants in [vec!["parent"], vec!["label"]] {
            assert!(LabelAcquisition::new(
                &registry(&grants),
                "refresh",
                "consultation",
                "view",
                "members",
                &scope,
                generation
            )
            .is_err());
        }
        let registry = registry(&["parent", "label"]);
        assert!(LabelAcquisition::new(
            &registry,
            "refresh",
            "different",
            "view",
            "members",
            &scope,
            generation
        )
        .is_err());
        let plan = LabelAcquisition::new(
            &registry,
            "refresh",
            "consultation",
            "view",
            "members",
            &scope,
            generation,
        )
        .unwrap();
        assert!(plan.publication_eligibility().contains("$6::text"));
        assert!(plan.publication_eligibility().contains("$12::uuid[]"));
        assert!(plan
            .publication_eligibility()
            .contains("complete-collection"));
        assert!(plan.publication_eligibility().contains("clock_timestamp()"));
        assert!(plan.page_sql.contains("$2::text"));
        assert!(plan.page_sql.contains("COLLATE \"C\""));
    }

    #[test]
    fn acquisition_deadline_excludes_the_lookahead_row() {
        let rows = [200, 300, 100]
            .into_iter()
            .enumerate()
            .map(|(index, expiry)| LabelSelector {
                root_id: Uuid::nil(),
                member_key: index.to_string(),
                selector: "internal".to_owned(),
                parent_key: format!("parent-{}", index / 2),
                parent_snapshot: format!("snapshot-{}", index / 2),
                parent_expires_at: expiry,
            })
            .collect();
        let page = bounded_page(rows, 2);
        assert_eq!(page.minimum_parent_expires_at, Some(200));
        assert_eq!(
            page.supporting,
            [SupportingSnapshot {
                subject_key: "parent-0".to_owned(),
                snapshot_id: "snapshot-0".to_owned(),
            }]
        );
        assert_eq!(page.continuation.unwrap().member_key, "1");
        assert_eq!(bounded_page(vec![], 2).minimum_parent_expires_at, None);
    }

    #[test]
    fn cursor_and_selector_debug_never_disclose_source_values() {
        let position = LabelAfter {
            root_id: Uuid::nil(),
            member_key: "PRIVATE_MEMBER_CANARY".to_owned(),
        };
        let selector = LabelSelector {
            root_id: Uuid::nil(),
            member_key: "PRIVATE_MEMBER_CANARY".to_owned(),
            selector: "PRIVATE_SELECTOR_CANARY".to_owned(),
            parent_key: "PRIVATE_PARENT_CANARY".to_owned(),
            parent_snapshot: "PRIVATE_SNAPSHOT_CANARY".to_owned(),
            parent_expires_at: 1000,
        };
        let supporting = SupportingSnapshot {
            subject_key: "PRIVATE_PARENT_CANARY".to_owned(),
            snapshot_id: "PRIVATE_SNAPSHOT_CANARY".to_owned(),
        };
        assert!(!format!("{position:?} {selector:?} {supporting:?}").contains("CANARY"));
    }
}

#[cfg(test)]
#[cfg(feature = "postgres-test")]
mod postgres_tests {
    use super::super::external_projection::{configure_scope, publication_statement, INSTALL_SQL};
    use super::*;
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

    #[tokio::test]
    async fn indirect_label_uses_root_rls_fresh_complete_parent_and_current_membership() {
        let database = harness::TestDatabase::create(2).await;
        let (migration, migration_task) = database.connect_migration().await;
        let registry = super::tests::registry(&["parent", "label"]);
        super::super::install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .unwrap();
        migration
            .batch_execute(&INSTALL_SQL.replace(
                "floor(extract(epoch FROM clock_timestamp()))::bigint",
                "1000",
            ))
            .await
            .unwrap();
        let parent =
            ProjectionScope::new("parent", Uuid::new_v4(), "binding", "grant", 60).unwrap();
        let label =
            ProjectionScope::new("label", Uuid::new_v4(), "label-binding", "label-grant", 60)
                .unwrap();
        configure_scope(&migration, &parent).await.unwrap();
        configure_scope(&migration, &label).await.unwrap();
        let entity = &registry.entities()["local-record"];
        let key = &entity
            .stored_fields
            .iter()
            .find(|field| field.logical.id == "subject-key")
            .unwrap()
            .physical_name;
        let tenant = &entity
            .stored_fields
            .iter()
            .find(|field| field.logical.id == "tenant")
            .unwrap()
            .physical_name;
        database.admin.batch_execute(&format!("INSERT INTO registry_data.\"{}\" (record_id,active_package_revision,\"{key}\",\"{tenant}\") VALUES ('00000000-0000-4000-8000-000000000001','fixture','allowed-parent','allowed'),('00000000-0000-4000-8000-000000000002','fixture','denied-parent','other'),('00000000-0000-4000-8000-000000000003','fixture','expired-parent','allowed')",entity.physical_table)).await.unwrap();
        for subject in ["allowed-parent", "denied-parent", "expired-parent"] {
            let ticket: i64 = migration
                .query_one(
                    "SELECT registry_internal.allocate_external_projection_refresh($1,$2,$3,$4,$5)",
                    &[
                        &parent.projection_id,
                        &parent.epoch,
                        &parent.binding_digest,
                        &parent.grant_digest,
                        &subject,
                    ],
                )
                .await
                .unwrap()
                .get(0);
            let rows = json!([{"source_key":"a","fields":{"holder":"indirect-person"}},{"source_key":"b","fields":{"holder":null}},{"source_key":"c","fields":{}},{"source_key":"d","fields":{"holder":"second-person"}}]);
            let answer:String=migration.query_one("SELECT registry_internal.publish_external_projection($1,$2,$3,$4,$5,$6,'members',990,1050,'complete-collection',$7)",&[&parent.projection_id,&parent.epoch,&parent.binding_digest,&parent.grant_digest,&ticket,&subject,&rows]).await.unwrap().get(0);
            assert_eq!(answer, "published");
        }
        migration.execute("UPDATE registry_internal.registry_external_projection_snapshots SET expires_at=999 WHERE projection_id='parent' AND subject_key='expired-parent'",&[]).await.unwrap();
        let (runtime, connection) = database
            .runtime_config
            .postgres()
            .connect(NoTls)
            .await
            .unwrap();
        let runtime_task = tokio::spawn(async move {
            connection.await.unwrap();
        });
        runtime.batch_execute("SET registry.access_profile='refresh'; SET registry.principal='worker'; SET registry.purpose='consultation'; SET registry.row_boundaries='[{\"field\":\"tenant\",\"operator\":\"equals\",\"values\":[\"allowed\"]}]';").await.unwrap();
        let plan = LabelAcquisition::new(
            &registry,
            "refresh",
            "consultation",
            "view",
            "members",
            &parent,
            // Publication leaves the configured scope generation unchanged.
            ProjectionGeneration {
                epoch: parent.epoch,
                generation: 0,
            },
        )
        .unwrap();
        let page_sql = plan.page_sql.replace(
            "floor(extract(epoch FROM clock_timestamp()))::bigint",
            "1000",
        );
        let page = runtime
            .query_one(&page_sql, &[&None::<Uuid>, &None::<String>, &2_i64])
            .await
            .unwrap();
        assert!(page.get::<_, bool>(0));
        let rows: Value = page.get(1);
        assert_eq!(rows.as_array().unwrap().len(), 2);
        assert_eq!(rows[0]["selector"], "indirect-person");
        assert_eq!(rows[0]["parent_key"], "allowed-parent");
        assert_eq!(rows[0]["parent_snapshot"], "members");
        assert_eq!(rows[1]["member_key"], "d");
        let allowed = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let next = runtime
            .query_one(&page_sql, &[&Some(allowed), &Some("a"), &2_i64])
            .await
            .unwrap();
        assert_eq!(next.get::<_, Value>(1).as_array().unwrap().len(), 1);
        let sql = publication_statement(plan.publication_eligibility()).replace(
            "floor(extract(epoch FROM clock_timestamp()))::bigint",
            "1000",
        );
        let ticket:i64=runtime.query_one("SELECT registry_internal.allocate_external_projection_refresh($1,$2,$3,$4,'indirect-person')",&[&label.projection_id,&label.epoch,&label.binding_digest,&label.grant_digest]).await.unwrap().get(0);
        let rows = json!([{"source_key":"indirect-person","fields":{"name":"retained"}}]);
        let roots = vec![allowed];
        let outcome: String = runtime
            .query_one(
                &sql,
                &[
                    &label.projection_id,
                    &label.epoch,
                    &label.binding_digest,
                    &label.grant_digest,
                    &ticket,
                    &"indirect-person",
                    &"label",
                    &999_i64,
                    &1059_i64,
                    &"one",
                    &rows,
                    &roots,
                ],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(outcome, "published");
        migration.execute("UPDATE registry_internal.registry_external_projection_values SET fields='{}' WHERE projection_id='parent' AND subject_key='allowed-parent' AND source_key='a'",&[]).await.unwrap();
        let outcome: String = runtime
            .query_one(
                &sql,
                &[
                    &label.projection_id,
                    &label.epoch,
                    &label.binding_digest,
                    &label.grant_digest,
                    &ticket,
                    &"indirect-person",
                    &"label",
                    &999_i64,
                    &1059_i64,
                    &"one",
                    &rows,
                    &roots,
                ],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(outcome, "ineligible");
        assert_eq!(runtime.query_one("SELECT fields->>'name' FROM registry_internal.registry_external_projection_values WHERE projection_id='label'",&[]).await.unwrap().get::<_,String>(0),"retained");
        migration.execute("UPDATE registry_internal.registry_external_projection_scopes SET generation=generation+1 WHERE projection_id='parent'",&[]).await.unwrap();
        let page = runtime
            .query_one(&page_sql, &[&None::<Uuid>, &None::<String>, &2_i64])
            .await
            .unwrap();
        assert!(!page.get::<_, bool>(0));
        assert_eq!(page.get::<_, Value>(1), json!([]));
        runtime_task.abort();
        migration_task.abort();
        drop(runtime);
        drop(migration);
        database.cleanup().await;
    }
}

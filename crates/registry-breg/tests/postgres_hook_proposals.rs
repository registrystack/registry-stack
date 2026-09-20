// SPDX-License-Identifier: Apache-2.0

//! A hook answer that proposes applies as a registry mutation: the
//! post-commit delivery, the proposal document, the principal the hook
//! declared, and the mutation path the proposal rides, in one place.
//!
//! Every proposing fixture answers with the same canonical proposal message
//! over the same `open-followup` action, so the handler kinds are the only
//! moving part and the parity journey compares answer digests, dispositions,
//! and the record each kind produced. The apply target is the `followup`
//! entity, which carries no hooks of its own in every registry except the
//! loop journey, where one followup hook makes the chain self-referential
//! and the causation ceiling is the only thing that ends it.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use postgres_harness::TestDatabase;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_json, ModuleAssetSource};
use registry_breg::event_destination::ActivatedEventDestinationRegistry;
use registry_breg::field_encryption::{FieldEncryptionProvider, FieldEncryptionService};
use registry_breg::hook_handler::HookHandlerRegistry;
use registry_breg::model::CompiledRegistry;
use registry_breg::mutation::{MutationBody, MutationCoordinator, MutationPlan, MutationRequest};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema, ClaimContext,
    ExpectedRegistryIdentity, RegistryLockKey, RegistryStateTestIdentity, RowBoundaryContext,
    RuntimePool,
};
use registry_breg::runtime_config::parse_runtime_config;
use registry_breg::webhook::{WebhookDeliveryError, WebhookDeliveryService, WebhookWorkOutcome};
use registry_platform_audit::AuditProfile;
use registry_platform_config::{SecretProvider, SecretReference, SecretResolver};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

const PACKAGE_REVISION: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RECORD_VALUE_CANARY: &str = "restricted-record-value-canary";
const DESTINATION_ID: &str = "case-operations";
const DELIVERY_PATH: &str = "/registry-events";
const HMAC_KEY: &[u8] = b"hook-proposal-signing-key-0123456789abcdef";
const KEY_REF_CANARY: &str = "hook-proposal-signing-key-canary";
const CA_REF_CANARY: &str = "hook-proposal-ca-bundle-canary";

/// The canonical proposal message every proposing fixture answers with.
///
/// The keys are fully sorted at every level, so the Rhai literal, the URL
/// response body, and the WASM result window all produce these exact bytes,
/// and the delivery row records the same digest whichever kind answered.
const HOOK_PROPOSAL_STR: &str = r#"{"answer":"proposal","document":{"action":"open-followup","input":{"jurisdiction":"zone-a","origin":"hook-proposal"},"outcome":{"effects":[{"id":"followup","set":{"jurisdiction":"zone-a","label":"hook followup","origin":"hook-proposal"}}]}}}"#;

const HOOK_PROPOSAL_MESSAGE: &[u8] = HOOK_PROPOSAL_STR.as_bytes();

/// A second valid proposal for the same action with materially different
/// values: the answer a changed handler returns on retry after the first
/// application committed but finalization did not happen.
const DRIFTED_PROPOSAL_STR: &str = r#"{"answer":"proposal","document":{"action":"open-followup","input":{"jurisdiction":"zone-a","origin":"hook-proposal-drift"},"outcome":{"effects":[{"id":"followup","set":{"jurisdiction":"zone-a","label":"hook followup drifted","origin":"hook-proposal-drift"}}]}}}"#;

const DRIFTED_PROPOSAL_MESSAGE: &[u8] = DRIFTED_PROPOSAL_STR.as_bytes();

/// The proposing hook: reads the change, answers with the proposal above.
/// Rhai map literals open with `#{` at every level, so the answer's nested
/// objects are `#{...}` rather than the JSON `{...}` they serialize to.
const PROPOSAL_HOOK_SCRIPT: &[u8] = br#"fn handle(ctx) {
    #{"answer":"proposal","document":#{"action":"open-followup","input":#{"jurisdiction":"zone-a","origin":"hook-proposal"},"outcome":#{"effects":[#{"id":"followup","set":#{"jurisdiction":"zone-a","label":"hook followup","origin":"hook-proposal"}}]}}}
}"#;

/// A proposal whose outcome names a write slot the action handler never
/// declared, so the proposed outcome fails validation before anything runs.
const INVALID_PROPOSAL_HOOK_SCRIPT: &[u8] = br#"fn handle(ctx) {
    #{"answer":"proposal","document":#{"action":"open-followup","input":#{"jurisdiction":"zone-a","origin":"hook-proposal"},"outcome":#{"effects":[#{"id":"nonexistent-slot","set":#{"jurisdiction":"zone-a"}}]}}}
}"#;

/// A hook that observes and proposes nothing: an empty answer.
const SILENT_HOOK_SCRIPT: &[u8] = br#"fn handle(ctx) { () }"#;

/// The reviewed program behind the `open-followup` action handler. The apply
/// path validates the proposal through the handler's declared writes and
/// injects the proposed effects as the candidate, so the program itself is
/// never the source of the applied values in these journeys.
const ACTION_HANDLER_SCRIPT: &[u8] = br#"fn handle(ctx) {
    return #{effects: [#{id: "followup", set: #{jurisdiction: ctx.inputs["jurisdiction"], label: "hook followup", origin: ctx.inputs["origin"]}}]};
}"#;

/// One hook's project JSON: `after` phase, `created` trigger, the `label`
/// projection, and, when `principal` is set, the principal a proposal from
/// this hook is applied under.
fn hook_json(id: &str, principal: bool, handler: &str) -> String {
    let principal_field = if principal {
        r#""principal":"case-hook","#
    } else {
        ""
    };
    format!(
        r#"{{"phase":"after","id":"{id}","trigger":"created",{principal_field}"projection":["label"],"handler":{handler}}}"#
    )
}

const PROPOSING_RHAI_HANDLER: &str =
    r#"{"kind":"rhai","script":"hooks/propose.rhai","abi":"registry.hook-handler/v1"}"#;

fn rhai_asset(path: &str, bytes: &[u8]) -> ModuleAssetSource {
    ModuleAssetSource {
        module: None,
        path: path.to_owned(),
        bytes: bytes.to_vec(),
    }
}

/// The shared proposal project: a hooked `case` entity, an unhooked
/// `followup` target, the `open-followup` handler action, and the two
/// profiles that matter, the operator who creates cases and the `case-hook`
/// principal a proposal is applied under. The `case-hook` grant's result set
/// and the action's declared write slots are parameterized, so a journey can
/// expose a declared slot the proposal never applies: a legal nonempty grant
/// whose filtering hides every applied effect.
fn hook_project_json(
    case_hooks: &str,
    followup_hooks: &str,
    case_hook_results: &str,
    extra_writes: &str,
) -> String {
    format!(
        r#"{{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{{"id":"hook-proposal-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
          "entities":[{{
            "id":"case","primaryDataset":"test-dataset","route":"cases","mutationMode":"create_only","classification":"restricted",
            "fields":[
              {{"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"}},
              {{"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}},
              {{"id":"restricted_note","type":"string","maxLength":64,"required":true,"classification":"restricted"}}
            ],
            "hooks":{case_hooks}
          }},{{
            "id":"followup","primaryDataset":"test-dataset","route":"followups","mutationMode":"create_only","classification":"internal",
            "fields":[
              {{"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"internal"}},
              {{"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}},
              {{"id":"origin","type":"string","maxLength":64,"required":true,"classification":"internal"}}
            ],
            "hooks":{followup_hooks}
          }}],
          "actions":[{{
            "id":"open-followup",
            "inputs":[
              {{"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"internal"}},
              {{"id":"origin","apiName":"origin","type":"string","maxLength":64,"required":true,"classification":"internal"}}
            ],
            "handler":{{
              "kind":"rhai","script":"scripts/open-followup.rhai","abi":"registry.action-handler/v1",
              "writes":[{{"id":"followup","target":{{"entity":"followup"}},"operation":"create","fields":["jurisdiction","label","origin"]}}{extra_writes}]
            }}
          }}],
          "accessProfiles":[{{
            "id":"operator","default":true,"principalClaim":"registry_principal",
            "requiredPurposes":["case-management"],
            "permissions":[{{
              "entity":"case","operations":["create","get","list"],
              "readableFields":["jurisdiction","label","restricted_note"],
              "writableFields":["jurisdiction","label","restricted_note"],
              "rowBoundaries":[{{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}}]
            }}]
          }},{{
            "id":"case-hook","principalClaim":"registry_principal",
            "permissions":[{{
              "action":"open-followup","operations":["invoke"],
              "targets":[{{"entity":"followup","rowBoundaries":[]}}],
              {case_hook_results}
            }}]
          }}]
        }}"#,
        case_hooks = case_hooks,
        followup_hooks = followup_hooks,
        case_hook_results = case_hook_results,
        extra_writes = extra_writes,
    )
}

fn compile_proposal_registry(
    case_hooks: &str,
    followup_hooks: &str,
    hook_assets: &[ModuleAssetSource],
) -> CompiledRegistry {
    compile_proposal_registry_with_grant(
        case_hooks,
        followup_hooks,
        r#""results":["followup"]"#,
        "",
        hook_assets,
    )
}

#[allow(clippy::too_many_arguments)]
fn compile_proposal_registry_with_grant(
    case_hooks: &str,
    followup_hooks: &str,
    case_hook_results: &str,
    extra_writes: &str,
    hook_assets: &[ModuleAssetSource],
) -> CompiledRegistry {
    let project = parse_project_json(
        hook_project_json(case_hooks, followup_hooks, case_hook_results, extra_writes).as_bytes(),
    )
    .expect("hook proposal fixture parses");
    let mut assets = vec![rhai_asset(
        "scripts/open-followup.rhai",
        ACTION_HANDLER_SCRIPT,
    )];
    assets.extend(hook_assets.iter().cloned());
    compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring)
        .expect("hook proposal fixture compiles")
}

/// The standard journey registry: one proposing, principal-declaring hook on
/// `case`, nothing on `followup`, so one case create proposes and applies
/// exactly one followup.
fn proposal_registry() -> CompiledRegistry {
    compile_proposal_registry(
        &format!(
            "[{}]",
            hook_json("case-created", true, PROPOSING_RHAI_HANDLER)
        ),
        "[]",
        &[rhai_asset("hooks/propose.rhai", PROPOSAL_HOOK_SCRIPT)],
    )
}

/// The standard proposal registry with the action's `origin` target sealed
/// at rest. The proposal still carries plaintext process-local input; only
/// the committed field changes storage shape.
fn encrypted_proposal_registry() -> CompiledRegistry {
    let hooks = format!(
        "[{}]",
        hook_json("case-created", true, PROPOSING_RHAI_HANDLER)
    );
    let mut project_json: Value = serde_json::from_str(&hook_project_json(
        &hooks,
        "[]",
        r#""results":["followup"]"#,
        "",
    ))
    .expect("hook proposal fixture is JSON");
    project_json["entities"][1]["classification"] = json!("restricted");
    project_json["entities"][1]["fields"][2]["classification"] = json!("restricted");
    project_json["entities"][1]["fields"][2]["encrypted"] = json!(true);
    let project = parse_project_json(
        &serde_json::to_vec(&project_json).expect("hook proposal fixture serializes"),
    )
    .expect("encrypted hook proposal fixture parses");
    compile_project_with_assets(
        &project,
        &[],
        &[
            rhai_asset("scripts/open-followup.rhai", ACTION_HANDLER_SCRIPT),
            rhai_asset("hooks/propose.rhai", PROPOSAL_HOOK_SCRIPT),
        ],
        CompileProfile::Authoring,
    )
    .expect("encrypted hook proposal fixture compiles")
}

/// The loop journey registry: the followup entity carries the same proposing
/// hook, so every applied proposal creates the next event whose hook proposes
/// again, and only the causation ceiling ends the chain.
fn loop_registry() -> CompiledRegistry {
    compile_proposal_registry(
        &format!(
            "[{}]",
            hook_json("case-created", true, PROPOSING_RHAI_HANDLER)
        ),
        &format!(
            "[{}]",
            hook_json("followup-created", true, PROPOSING_RHAI_HANDLER)
        ),
        &[rhai_asset("hooks/propose.rhai", PROPOSAL_HOOK_SCRIPT)],
    )
}

/// The disposition journey registry: four hooks on one case-created trigger,
/// one per proposal disposition.
fn dispositions_registry() -> CompiledRegistry {
    let hooks = format!(
        "[{},{},{},{}]",
        hook_json("case-applier", true, PROPOSING_RHAI_HANDLER),
        hook_json(
            "invalid-proposer",
            true,
            r#"{"kind":"rhai","script":"hooks/invalid.rhai","abi":"registry.hook-handler/v1"}"#
        ),
        hook_json("principal-less-proposer", false, PROPOSING_RHAI_HANDLER),
        hook_json(
            "silent-observer",
            false,
            r#"{"kind":"rhai","script":"hooks/silent.rhai","abi":"registry.hook-handler/v1"}"#
        ),
    );
    compile_proposal_registry(
        &hooks,
        "[]",
        &[
            rhai_asset("hooks/propose.rhai", PROPOSAL_HOOK_SCRIPT),
            rhai_asset("hooks/invalid.rhai", INVALID_PROPOSAL_HOOK_SCRIPT),
            rhai_asset("hooks/silent.rhai", SILENT_HOOK_SCRIPT),
        ],
    )
}

fn principal_less_registry() -> CompiledRegistry {
    compile_proposal_registry(
        &format!(
            "[{}]",
            hook_json("principal-less-proposer", false, PROPOSING_RHAI_HANDLER)
        ),
        "[]",
        &[rhai_asset("hooks/propose.rhai", PROPOSAL_HOOK_SCRIPT)],
    )
}

fn invalid_proposal_registry() -> CompiledRegistry {
    compile_proposal_registry(
        &format!(
            "[{}]",
            hook_json(
                "invalid-proposer",
                true,
                r#"{"kind":"rhai","script":"hooks/invalid.rhai","abi":"registry.hook-handler/v1"}"#
            )
        ),
        "[]",
        &[rhai_asset(
            "hooks/invalid.rhai",
            INVALID_PROPOSAL_HOOK_SCRIPT,
        )],
    )
}

fn silent_registry() -> CompiledRegistry {
    compile_proposal_registry(
        &format!(
            "[{}]",
            hook_json(
                "silent-observer",
                false,
                r#"{"kind":"rhai","script":"hooks/silent.rhai","abi":"registry.hook-handler/v1"}"#
            )
        ),
        "[]",
        &[rhai_asset("hooks/silent.rhai", SILENT_HOOK_SCRIPT)],
    )
}

/// The hidden-result journey registry: the action declares a second write slot
/// the proposal never applies, and the `case-hook` grant's result set names
/// only that slot. The grant is legal and nonempty, but its disclosure
/// filtering hides every applied effect, so the delivery row's completion
/// cannot come from the response the grant filters.
fn hidden_result_registry() -> CompiledRegistry {
    compile_proposal_registry_with_grant(
        &format!(
            "[{}]",
            hook_json("case-created", true, PROPOSING_RHAI_HANDLER)
        ),
        "[]",
        r#""results":["note"]"#,
        r#",
              {"id":"note","target":{"entity":"followup"},"operation":"create","fields":["jurisdiction","label","origin"]}"#,
        &[rhai_asset("hooks/propose.rhai", PROPOSAL_HOOK_SCRIPT)],
    )
}

/// One journey's deployment: database, compiled schema, activated
/// destinations (a full destination table or none, per the handler kinds the
/// registry holds), mutation coordinator, and delivery service.
struct Setup {
    database: TestDatabase,
    compiled: CompiledRegistry,
    pool: RuntimePool,
    identity: ExpectedRegistryIdentity,
    coordinator: MutationCoordinator,
    service: WebhookDeliveryService,
    // Kept alive for the deployment's lifetime, not read: the activated
    // bindings were resolved out of this directory.
    #[allow(dead_code)]
    fixture: DestinationFixture,
}

async fn setup(
    compiled: CompiledRegistry,
    receiver: &HttpsReceiver,
    with_destinations: bool,
) -> Setup {
    setup_with_pool_size(compiled, receiver, with_destinations, 8).await
}

async fn setup_with_pool_size(
    compiled: CompiledRegistry,
    receiver: &HttpsReceiver,
    with_destinations: bool,
    pool_size: usize,
) -> Setup {
    setup_with_options(compiled, receiver, with_destinations, pool_size, false).await
}

async fn setup_with_field_encryption(
    compiled: CompiledRegistry,
    receiver: &HttpsReceiver,
    with_destinations: bool,
) -> Setup {
    setup_with_options(compiled, receiver, with_destinations, 8, true).await
}

async fn setup_with_options(
    compiled: CompiledRegistry,
    receiver: &HttpsReceiver,
    with_destinations: bool,
    pool_size: usize,
    enable_field_encryption: bool,
) -> Setup {
    let database = TestDatabase::create(pool_size).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs delivery state with the compiled schema");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        registry_state_test_identity(),
    )
    .await
    .expect("migration initializes active package identity with empty history");
    let field_encryption = if enable_field_encryption {
        Some(test_field_encryption_service(&migration).await)
    } else {
        None
    };
    migration_task.abort();

    let fixture = DestinationFixture::new(receiver);
    let destinations = Arc::new(if with_destinations {
        fixture.activate(&compiled)
    } else {
        fixture.activate_without_destinations(&compiled)
    });
    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x5a; 32].into())
        .expect("test owns a keyed audit profile");
    let lock_key =
        RegistryLockKey::derive("hook-proposal-registry").expect("test lock identity is bounded");
    let coordinator = MutationCoordinator::new_with_event_destinations(
        lock_key,
        Duration::from_secs(2),
        identity.clone(),
        audit_profile.clone(),
        Some(Arc::clone(&destinations)),
    );
    let coordinator = match field_encryption.clone() {
        Some(field_encryption) => coordinator.with_field_encryption(field_encryption),
        None => coordinator,
    };
    let service = WebhookDeliveryService::new_with_field_encryption(
        pool.clone(),
        Arc::clone(&destinations),
        Arc::new(HookHandlerRegistry::new(
            &compiled,
            &identity.package_revision,
        )),
        Arc::new(compiled.clone()),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit_profile.clone(),
        field_encryption,
    );
    drop(destinations);
    Setup {
        database,
        compiled,
        pool,
        identity,
        coordinator,
        service,
        fixture,
    }
}

async fn test_field_encryption_service(
    store: &tokio_postgres::Client,
) -> Arc<FieldEncryptionService> {
    let root = tempfile::Builder::new()
        .prefix("breg-hook-field-dek-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("temporary parent canonicalizes"),
        )
        .expect("field-encryption secret root creates");
    let dek_path = root.path().join("field-dek");
    write_secret(&dek_path, STANDARD.encode([0x42_u8; 32]).as_bytes());
    let dek_ref = SecretReference::parse("secret:file/field-dek")
        .expect("field-encryption key reference parses");
    let secrets = SecretResolver::new([SecretProvider::File], root.path())
        .expect("field-encryption secret resolver builds");
    Arc::new(
        FieldEncryptionService::activate(
            &FieldEncryptionProvider::LocalFile { dek_ref },
            "hook-proposal-registry",
            PACKAGE_REVISION,
            &secrets,
            store,
        )
        .await
        .expect("field-encryption key state activates"),
    )
}

impl Setup {
    fn service_for_identity(&self, identity: ExpectedRegistryIdentity) -> WebhookDeliveryService {
        let destinations = Arc::new(self.fixture.activate(&self.compiled));
        let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x5a; 32].into())
            .expect("test owns a keyed audit profile");
        let lock_key = RegistryLockKey::derive("hook-proposal-registry")
            .expect("test lock identity is bounded");
        WebhookDeliveryService::new(
            self.pool.clone(),
            destinations,
            Arc::new(HookHandlerRegistry::new(
                &self.compiled,
                &identity.package_revision,
            )),
            Arc::new(self.compiled.clone()),
            identity,
            lock_key,
            Duration::from_secs(2),
            audit_profile,
        )
    }

    /// Release the deployment. Tests that own the loopback receiver stop it
    /// themselves, so several legs can share one.
    async fn teardown(self) {
        drop(self.service);
        drop(self.pool);
        drop(self.fixture);
        self.database.cleanup().await;
    }
}

fn registry_state_test_identity() -> RegistryStateTestIdentity<'static> {
    RegistryStateTestIdentity {
        package_id: "hook-proposal-registry",
        environment: "local",
        instance_id: "hook-proposal-instance",
        database_id: "hook-proposal-database",
        package_revision: PACKAGE_REVISION,
        package_sequence: 1,
    }
}

fn mutation_claims(registry: &CompiledRegistry) -> ClaimContext {
    ClaimContext::for_compiled(
        registry,
        "case",
        Some("operator-principal".to_owned()),
        "operator",
        Some("case-management".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("compiled authority context is valid")
}

/// One committed case create and the delivery rows it captured.
struct CapturedEvent {
    event_id: Uuid,
    compiled_delivery_ids: Vec<String>,
}

async fn create_case(
    setup: &Setup,
    client: &mut deadpool_postgres::Client,
    label: &str,
) -> CapturedEvent {
    let plan = MutationPlan::from_compiled(&setup.compiled, "records.case.create")
        .expect("create plan retains the exact compiler delivery");
    let claims = mutation_claims(&setup.compiled);
    setup
        .coordinator
        .execute(
            client,
            MutationRequest {
                plan: &plan,
                idempotency_key: label,
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("label".to_owned(), json!(label)),
                    ("restrictedNote".to_owned(), json!(RECORD_VALUE_CANARY)),
                ])),
                response_fields: BTreeSet::from([
                    "jurisdiction".to_owned(),
                    "label".to_owned(),
                    "restricted_note".to_owned(),
                ]),
                representation: registry_breg::record_profile::RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("record mutation atomically captures its hook deliveries");
    let row = setup
        .database
        .admin
        .query_one(
            "SELECT outbox.event_id,
                    (SELECT array_agg(delivery.compiled_delivery_id ORDER BY delivery.compiled_delivery_id)
                       FROM registry_internal.registry_webhook_deliveries AS delivery
                      WHERE delivery.event_id = outbox.event_id)
               FROM registry_internal.registry_outbox AS outbox
             ORDER BY outbox.outbox_id DESC
             LIMIT 1",
            &[],
        )
        .await
        .expect("administrator can inspect the newest capture identity");
    CapturedEvent {
        event_id: row.get(0),
        compiled_delivery_ids: row
            .get::<_, Option<Vec<String>>>(1)
            .expect("the capture wrote its delivery rows"),
    }
}

/// The delivery-state columns an operator reads to know what became of the
/// proposal one delivery carried. A terminal row retains the answer's digest
/// and never the answer bytes themselves.
struct DeliveryRow {
    state: String,
    attempt: i16,
    disposition: Option<String>,
    resulting_revision: Option<i64>,
    code: Option<String>,
    summary: Option<String>,
    message: Option<Vec<u8>>,
    message_digest: Option<Vec<u8>>,
}

async fn delivery_row(setup: &Setup, event_id: Uuid, compiled_delivery_id: &str) -> DeliveryRow {
    let row = setup
        .database
        .admin
        .query_one(
            "SELECT state, attempt, proposal_disposition, proposal_resulting_revision,
                    proposal_code, proposal_summary, handler_message, handler_message_digest
             FROM registry_internal.registry_webhook_delivery_state
             WHERE event_id = $1 AND compiled_delivery_id = $2",
            &[&event_id, &compiled_delivery_id],
        )
        .await
        .expect("the delivery state row is readable");
    DeliveryRow {
        state: row.get(0),
        attempt: row.get(1),
        disposition: row.get(2),
        resulting_revision: row.get(3),
        code: row.get(4),
        summary: row.get(5),
        message: row.get(6),
        message_digest: row.get(7),
    }
}

/// The digest of exactly the canonical proposal message, the value a terminal
/// delivery row retains in place of the answer bytes.
fn proposal_message_digest() -> Vec<u8> {
    use sha2::Digest as _;
    sha2::Sha256::digest(HOOK_PROPOSAL_MESSAGE).to_vec()
}

/// Every (event, delivery) pair the case entity's hooks captured, ordered by
/// compiled delivery id. One outbox event exists per hook, so a multi-hook
/// entity captures one pair per hook, each with its own event id.
async fn case_deliveries(setup: &Setup) -> Vec<(Uuid, String)> {
    setup
        .database
        .admin
        .query(
            "SELECT outbox.event_id, delivery.compiled_delivery_id
             FROM registry_internal.registry_outbox AS outbox
             JOIN registry_internal.registry_webhook_deliveries AS delivery
               ON delivery.event_id = outbox.event_id
             WHERE outbox.entity_id = 'case'
             ORDER BY delivery.compiled_delivery_id",
            &[],
        )
        .await
        .expect("administrator reads every case delivery")
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect()
}

async fn record_count(setup: &Setup, entity_id: &str) -> i64 {
    let table = &setup
        .compiled
        .entities()
        .get(entity_id)
        .unwrap_or_else(|| panic!("entity {entity_id} is compiled"))
        .physical_table;
    setup
        .database
        .admin
        .query_one(&format!("SELECT count(*) FROM registry_data.{table}"), &[])
        .await
        .expect("administrator can count records")
        .get(0)
}

/// The one applied followup's stored values. Column names are derived like
/// the table name, so each selection resolves the field's physical column.
async fn followup_content(setup: &Setup) -> (String, String, String) {
    let inventory = &setup
        .compiled
        .physical_names()
        .entities
        .get("followup")
        .expect("the followup entity is compiled");
    let column = |id: &str| {
        inventory
            .fields
            .get(id)
            .unwrap_or_else(|| panic!("field {id} is compiled"))
            .as_str()
    };
    let row = setup
        .database
        .admin
        .query_one(
            &format!(
                "SELECT {}, {}, {} FROM registry_data.{}",
                column("jurisdiction"),
                column("label"),
                column("origin"),
                inventory.table
            ),
            &[],
        )
        .await
        .expect("exactly one applied followup exists");
    (row.get(0), row.get(1), row.get(2))
}

/// The retained outbox payload of one delivery, read before the worker's
/// successful finalize erases it.
async fn outbox_payload(setup: &Setup, event: &CapturedEvent) -> Vec<u8> {
    setup
        .database
        .admin
        .query_one(
            "SELECT payload FROM registry_internal.registry_outbox WHERE event_id = $1",
            &[&event.event_id],
        )
        .await
        .expect("the captured payload is retained")
        .get(0)
}

/// Simulate a worker that applied the proposal and then lost everything
/// after the apply: the row goes back to a crashed, expired-lease shape with
/// no answer and no disposition recorded, and the payload a finalize would
/// have erased is put back, because in the simulated world that finalize
/// never ran.
async fn rewind_to_crashed_lease(
    setup: &Setup,
    event: &CapturedEvent,
    compiled_delivery_id: &str,
    payload: &[u8],
) {
    let changed = setup
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_delivery_state
             SET state = 'leased', next_attempt_at = NULL,
                 attempt_started_at = transaction_timestamp() - interval '60 seconds',
                 lease_expires_at = transaction_timestamp() - interval '1 second',
                 lease_token = gen_random_uuid(),
                 delivered_at = NULL, dead_lettered_at = NULL, expired_at = NULL,
                 handler_message = NULL, handler_message_digest = NULL,
                 proposal_disposition = NULL, proposal_resulting_revision = NULL,
                 proposal_code = NULL, proposal_summary = NULL,
                 updated_at = transaction_timestamp()
             WHERE event_id = $1 AND compiled_delivery_id = $2",
            &[&event.event_id, &compiled_delivery_id],
        )
        .await
        .expect("administrator simulates a crashed lease over a delivered row");
    assert_eq!(changed, 1);
    let restored = setup
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_outbox
             SET payload = $2, payload_expires_at = transaction_timestamp() + interval '7 days'
             WHERE event_id = $1",
            &[&event.event_id, &payload],
        )
        .await
        .expect("the crashed world still holds its captured payload");
    assert_eq!(restored, 1);
}

/// Expire a genuinely leased row's lease so the reaper can recover it.
async fn expire_lease(setup: &Setup, event: &CapturedEvent, compiled_delivery_id: &str) {
    let changed = setup
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_delivery_state
             SET attempt_started_at = transaction_timestamp() - interval '60 seconds',
                 lease_expires_at = transaction_timestamp() - interval '1 second',
                 updated_at = transaction_timestamp()
             WHERE event_id = $1 AND compiled_delivery_id = $2 AND state = 'leased'",
            &[&event.event_id, &compiled_delivery_id],
        )
        .await
        .expect("administrator expires one lease for recovery");
    assert_eq!(changed, 1);
}

/// Waits until the scheduled retry is claimable on the database clock.
async fn wait_until_delivery_is_due(
    setup: &Setup,
    event: &CapturedEvent,
    compiled_delivery_id: &str,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let due: bool = setup
                .database
                .admin
                .query_one(
                    "SELECT state = 'pending'
                            AND next_attempt_at IS NOT NULL
                            AND next_attempt_at <= transaction_timestamp()
                       FROM registry_internal.registry_webhook_delivery_state
                      WHERE event_id = $1 AND compiled_delivery_id = $2",
                    &[&event.event_id, &compiled_delivery_id],
                )
                .await
                .expect("administrator can inspect the exact retry schedule")
                .get(0);
            if due {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the scheduled retry becomes claimable");
}

async fn wait_for_runtime_advisory_waits(setup: &Setup, minimum: i64) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let waiting: i64 = setup
                .database
                .admin
                .query_one(
                    "SELECT count(*)
                           FROM pg_locks AS lock
                           JOIN pg_stat_activity AS activity USING (pid)
                          WHERE activity.datname = current_database()
                            AND activity.usename = $1
                            AND lock.locktype = 'advisory'
                            AND NOT lock.granted",
                    &[&setup.database.runtime_role.as_str()],
                )
                .await
                .expect("administrator observes proposal advisory lock waits")
                .get(0);
            if waiting >= minimum {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the expected proposal advisory lock waits are reached");
}

async fn revoke_followup_insert(setup: &Setup) {
    let table = &setup
        .compiled
        .entities()
        .get("followup")
        .expect("the followup entity is compiled")
        .physical_table;
    setup
        .database
        .admin
        .batch_execute(&format!(
            "REVOKE INSERT ON registry_data.{table} FROM \"{}\";",
            setup.database.runtime_role.as_str()
        ))
        .await
        .expect("administrator injects an apply-time write fault");
}

async fn grant_followup_insert(setup: &Setup) {
    let table = &setup
        .compiled
        .entities()
        .get("followup")
        .expect("the followup entity is compiled")
        .physical_table;
    setup
        .database
        .admin
        .batch_execute(&format!(
            "GRANT INSERT ON registry_data.{table} TO \"{}\";",
            setup.database.runtime_role.as_str()
        ))
        .await
        .expect("administrator restores the apply write path");
}

fn single_delivery(event: &CapturedEvent) -> &str {
    assert_eq!(event.compiled_delivery_ids.len(), 1);
    &event.compiled_delivery_ids[0]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn real_postgres_hook_proposal_seals_an_encrypted_action_field() {
    let receiver = HttpsReceiver::start().await;
    let setup = setup_with_field_encryption(encrypted_proposal_registry(), &receiver, false).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "encrypted-proposal").await;
    let delivery_id = single_delivery(&event).to_owned();
    drop(mutation_client);

    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    let delivery = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(delivery.disposition.as_deref(), Some("applied"));
    assert_eq!(delivery.resulting_revision, Some(1));
    assert_eq!(delivery.message, None, "the plaintext proposal is erased");

    let followup = setup
        .compiled
        .entities()
        .get("followup")
        .expect("the followup entity compiles");
    let origin = followup
        .fields
        .get("origin")
        .expect("the encrypted origin field compiles");
    assert!(origin.encryption.is_some());
    let data_type: String = setup
        .database
        .admin
        .query_one(
            "SELECT data_type
               FROM information_schema.columns
              WHERE table_schema = 'registry_data'
                AND table_name = $1
                AND column_name = $2",
            &[&followup.physical_table, &origin.physical_name],
        )
        .await
        .expect("the encrypted field's physical column exists")
        .get(0);
    assert_eq!(data_type, "bytea", "the field has only envelope storage");
    let envelope: Vec<u8> = setup
        .database
        .admin
        .query_one(
            &format!(
                "SELECT {} FROM registry_data.{}",
                origin.physical_name, followup.physical_table
            ),
            &[],
        )
        .await
        .expect("the applied followup stores one envelope")
        .get(0);
    assert!(envelope.len() > 32, "the stored value is a sealed envelope");
    assert!(
        !envelope
            .windows(b"hook-proposal".len())
            .any(|window| window == b"hook-proposal"),
        "the envelope does not retain the proposed plaintext"
    );

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn real_postgres_hook_loop_terminates_at_the_causation_ceiling_and_dead_letters() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let receiver = HttpsReceiver::start().await;
    let setup = setup(loop_registry(), &receiver, false).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "loop-seed").await;
    drop(mutation_client);

    let mut outcomes = Vec::new();
    for _ in 0..24 {
        let outcome = setup
            .service
            .deliver_once()
            .await
            .expect("one loop iteration completes");
        outcomes.push(outcome);
        if outcome == WebhookWorkOutcome::DeadLettered {
            break;
        }
    }
    // The chain is strictly sequential: each applied proposal creates the
    // next event whose hook proposes again, so the sequence is exactly
    // ceiling-many delivered applies and then the refusal.
    assert_eq!(
        outcomes,
        [
            WebhookWorkOutcome::Delivered,
            WebhookWorkOutcome::Delivered,
            WebhookWorkOutcome::Delivered,
            WebhookWorkOutcome::Delivered,
            WebhookWorkOutcome::Delivered,
            WebhookWorkOutcome::Delivered,
            WebhookWorkOutcome::Delivered,
            WebhookWorkOutcome::Delivered,
            WebhookWorkOutcome::DeadLettered,
        ],
        "the loop delivers exactly eight applies and dead-letters the ninth"
    );
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Idle),
        "the dead letter is terminal: no further work is due"
    );
    assert_eq!(record_count(&setup, "followup").await, 8);
    assert_eq!(record_count(&setup, "case").await, 1);

    let rows = setup
        .database
        .admin
        .query(
            "SELECT proposal_disposition, proposal_resulting_revision
             FROM registry_internal.registry_webhook_delivery_state
             ORDER BY compiled_delivery_id",
            &[],
        )
        .await
        .expect("administrator reads every delivery disposition");
    assert_eq!(rows.len(), 9, "one case and eight followup deliveries");
    let applied = rows
        .iter()
        .filter(|row| row.get::<_, Option<String>>(0).as_deref() == Some("applied"))
        .count();
    assert_eq!(applied, 8, "every delivered proposal applied");
    assert!(
        rows.iter()
            .filter(|row| row.get::<_, Option<String>>(0).as_deref() == Some("applied"))
            .all(|row| row.get::<_, Option<i64>>(1) == Some(1)),
        "every applied proposal produced revision one"
    );

    // The refusal is computed before any enqueue, so the dead-lettered row
    // keeps its outbox payload and the envelope still names its hop.
    let dead_letter = setup
        .database
        .admin
        .query_one(
            "SELECT state.proposal_disposition, state.proposal_code, state.proposal_summary,
                    convert_from(outbox.payload, 'UTF8')
             FROM registry_internal.registry_webhook_delivery_state AS state
             JOIN registry_internal.registry_outbox AS outbox
               ON outbox.event_id = state.event_id
             WHERE state.state = 'dead_lettered'",
            &[],
        )
        .await
        .expect("exactly one dead-lettered row keeps its payload");
    assert_eq!(
        dead_letter.get::<_, Option<String>>(0).as_deref(),
        Some("dead_lettered")
    );
    assert_eq!(
        dead_letter.get::<_, Option<String>>(1).as_deref(),
        Some("hook.causation.hop_beyond_ceiling"),
        "the reason code names the causation ceiling"
    );
    assert!(
        dead_letter
            .get::<_, Option<String>>(2)
            .as_deref()
            .is_some_and(|summary| summary.contains("ceiling of 8")),
        "the summary names the ceiling it refused to exceed"
    );
    let envelope: Value = serde_json::from_str(dead_letter.get::<_, String>(3).as_str())
        .expect("the retained envelope parses");
    assert_eq!(
        envelope.pointer("/causation/hop").and_then(Value::as_i64),
        Some(8),
        "the refused proposal came from an envelope at hop eight"
    );
    assert_eq!(
        envelope
            .pointer("/causation/root")
            .and_then(Value::as_str)
            .expect("the root is carried"),
        event.event_id.to_string(),
        "the whole chain carries the triggering event as its root"
    );

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_redelivered_hook_answer_applies_once() {
    let receiver = HttpsReceiver::start().await;
    let setup = setup(proposal_registry(), &receiver, false).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "redelivery").await;
    let delivery_id = single_delivery(&event).to_owned();
    let payload = outbox_payload(&setup, &event).await;
    drop(mutation_client);

    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    let first = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(first.state, "delivered");
    assert_eq!(first.attempt, 1);
    assert_eq!(first.disposition.as_deref(), Some("applied"));
    assert_eq!(first.resulting_revision, Some(1));
    assert_eq!(
        first.message, None,
        "the raw answer is erased at settlement"
    );
    assert_eq!(
        first.message_digest.as_deref(),
        Some(proposal_message_digest().as_slice()),
        "the digest of exactly the answer is what the row retains"
    );
    let malformed = setup
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_delivery_state
             SET handler_message = $3, handler_message_digest = NULL
             WHERE event_id = $1 AND compiled_delivery_id = $2",
            &[&event.event_id, &delivery_id, &HOOK_PROPOSAL_MESSAGE],
        )
        .await
        .expect_err("a delivered raw answer without its digest is refused by the schema");
    assert_eq!(
        malformed.code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION),
        "the answer-shape refusal is enforced by a database CHECK"
    );
    assert_eq!(
        malformed.as_db_error().and_then(|error| error.constraint()),
        Some("registry_webhook_delivery_state_answer_digest_required")
    );
    assert_eq!(record_count(&setup, "followup").await, 1);

    // The worker applied the proposal and died before finalization: the row
    // is rewound to a crashed, expired lease with nothing recorded, and the
    // answer is delivered again from scratch.
    rewind_to_crashed_lease(&setup, &event, &delivery_id, &payload).await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Idle),
        "the expired lease is reaped to a scheduled retry, not claimed at once"
    );
    wait_until_delivery_is_due(&setup, &event, &delivery_id).await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered),
        "the redelivered answer settles through the same application identity"
    );
    let second = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(second.state, "delivered");
    assert_eq!(second.attempt, 2, "the redelivery was a second attempt");
    assert_eq!(second.disposition.as_deref(), Some("applied"));
    assert_eq!(second.message, None);
    assert_eq!(
        second.message_digest, first.message_digest,
        "the redelivery retained the same digest, and still no bytes"
    );
    assert_eq!(
        second.resulting_revision,
        Some(1),
        "the replay resolves to the revision the first application produced"
    );
    assert_eq!(
        record_count(&setup, "followup").await,
        1,
        "the same answer applied once, not twice"
    );
    assert_eq!(
        record_count(&setup, "case").await,
        1,
        "the triggering record is still the only case"
    );

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_a_retained_local_delivery_survives_restart_verification() {
    let receiver = HttpsReceiver::start().await;
    let setup = setup(proposal_registry(), &receiver, false).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "retained-local").await;
    let delivery_id = single_delivery(&event).to_owned();
    drop(mutation_client);

    // A local delivery holds no logical destination, so restart verification
    // must check it against the deployed handler binding, not the destination
    // table: a healthy undelivered local row is not a deployment defect.
    setup
        .service
        .verify_retained_bindings()
        .await
        .expect("a retained local delivery verifies against its handler binding");

    // The same row with a digest no deployed program answers to is a genuine
    // binding mismatch, and startup still refuses it.
    let changed = setup
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_deliveries
             SET destination_binding_digest = $3
             WHERE event_id = $1 AND compiled_delivery_id = $2",
            &[
                &event.event_id,
                &delivery_id,
                &"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ],
        )
        .await
        .expect("administrator corrupts one retained local binding");
    assert_eq!(changed, 1);
    assert_eq!(
        setup.service.verify_retained_bindings().await,
        Err(WebhookDeliveryError::Unavailable),
        "a retained local delivery whose digest no handler answers to still blocks startup"
    );

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_a_changed_answer_cannot_reapply_one_delivery() {
    let receiver = HttpsReceiver::start().await;
    let url_registry = compile_proposal_registry(
        &format!(
            "[{}]",
            hook_json(
                "case-created",
                true,
                r#"{"kind":"url","destinationId":"case-operations"}"#,
            )
        ),
        "[]",
        &[],
    );
    let setup = setup(url_registry, &receiver, true).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "answer-drift").await;
    let delivery_id = single_delivery(&event).to_owned();
    let payload = outbox_payload(&setup, &event).await;
    drop(mutation_client);

    receiver
        .enqueue(ResponsePlan::Answer {
            body: HOOK_PROPOSAL_MESSAGE.to_vec(),
        })
        .await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    let first = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(first.state, "delivered");
    assert_eq!(first.disposition.as_deref(), Some("applied"));
    assert_eq!(first.resulting_revision, Some(1));
    assert_eq!(record_count(&setup, "followup").await, 1);

    // The worker applied the proposal and died before finalization; the
    // recovered retry now meets a handler whose answer changed. One delivery
    // is one application: the first stands, and the drifted answer terminates
    // as a readable conflict instead of applying a second record.
    rewind_to_crashed_lease(&setup, &event, &delivery_id, &payload).await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Idle),
        "the expired lease is reaped to a scheduled retry"
    );
    wait_until_delivery_is_due(&setup, &event, &delivery_id).await;
    receiver
        .enqueue(ResponsePlan::Answer {
            body: DRIFTED_PROPOSAL_MESSAGE.to_vec(),
        })
        .await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::DeadLettered),
        "a changed answer after the commit dead-letters as a stable conflict"
    );
    let drifted = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(drifted.state, "dead_lettered");
    assert_eq!(drifted.attempt, 2);
    assert_eq!(drifted.disposition.as_deref(), Some("dead_lettered"));
    assert_eq!(drifted.resulting_revision, None);
    assert_eq!(
        drifted.code.as_deref(),
        Some("hook.proposal.answer_conflict"),
        "the row names the answer conflict without logs"
    );
    assert!(
        drifted
            .summary
            .as_deref()
            .is_some_and(|summary| !summary.is_empty()),
        "the conflict records a bounded human-readable reason"
    );
    assert_eq!(
        record_count(&setup, "followup").await,
        1,
        "the first application stands; the drifted answer applied nothing"
    );

    // Cross-kind drift follows the same receipt. A later empty/none answer
    // must not overwrite the delivery row with `none` after the first
    // proposal already committed.
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let none_event = create_case(&setup, &mut mutation_client, "answer-drift-none").await;
    let none_delivery_id = single_delivery(&none_event).to_owned();
    let none_payload = outbox_payload(&setup, &none_event).await;
    drop(mutation_client);
    receiver
        .enqueue(ResponsePlan::Answer {
            body: HOOK_PROPOSAL_MESSAGE.to_vec(),
        })
        .await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    assert_eq!(record_count(&setup, "followup").await, 2);
    rewind_to_crashed_lease(&setup, &none_event, &none_delivery_id, &none_payload).await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Idle),
        "the expired lease is reaped to a scheduled retry"
    );
    wait_until_delivery_is_due(&setup, &none_event, &none_delivery_id).await;
    receiver
        .enqueue(ResponsePlan::Answer { body: Vec::new() })
        .await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::DeadLettered),
        "a changed none answer cannot hide an already committed proposal"
    );
    let none = delivery_row(&setup, none_event.event_id, &none_delivery_id).await;
    assert_eq!(none.state, "dead_lettered");
    assert_eq!(none.disposition.as_deref(), Some("dead_lettered"));
    assert_eq!(none.code.as_deref(), Some("hook.proposal.answer_conflict"));
    assert_eq!(
        record_count(&setup, "followup").await,
        2,
        "the first applications stand and neither drifted answer applies again"
    );

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_same_answer_replays_after_a_compatible_package_upgrade() {
    const SUCCESSOR_PACKAGE_REVISION: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let receiver = HttpsReceiver::start().await;
    let url_registry = compile_proposal_registry(
        &format!(
            "[{}]",
            hook_json(
                "case-created",
                true,
                r#"{"kind":"url","destinationId":"case-operations"}"#,
            )
        ),
        "[]",
        &[],
    );
    let setup = setup(url_registry, &receiver, true).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "successor-replay").await;
    let delivery_id = single_delivery(&event).to_owned();
    let payload = outbox_payload(&setup, &event).await;
    drop(mutation_client);

    receiver
        .enqueue(ResponsePlan::Answer {
            body: HOOK_PROPOSAL_MESSAGE.to_vec(),
        })
        .await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    assert_eq!(record_count(&setup, "followup").await, 1);
    rewind_to_crashed_lease(&setup, &event, &delivery_id, &payload).await;

    let mut successor_identity = setup.identity.clone();
    successor_identity.package_revision = SUCCESSOR_PACKAGE_REVISION.to_owned();
    successor_identity.package_sequence += 1;
    let changed = setup
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
             SET active_package_revision = $1, package_sequence = $2
             WHERE singleton",
            &[
                &successor_identity.package_revision,
                &successor_identity.package_sequence,
            ],
        )
        .await
        .expect("administrator activates the compatible successor identity");
    assert_eq!(changed, 1);
    let successor_service = setup.service_for_identity(successor_identity);

    assert_eq!(
        successor_service.deliver_once().await,
        Ok(WebhookWorkOutcome::Idle),
        "the successor reaps the predecessor delivery to a scheduled retry"
    );
    wait_until_delivery_is_due(&setup, &event, &delivery_id).await;
    receiver
        .enqueue(ResponsePlan::Answer {
            body: HOOK_PROPOSAL_MESSAGE.to_vec(),
        })
        .await;
    assert_eq!(
        successor_service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered),
        "the exact committed answer replays before successor-package validation"
    );
    let replayed = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(replayed.state, "delivered");
    assert_eq!(replayed.attempt, 2);
    assert_eq!(replayed.disposition.as_deref(), Some("applied"));
    assert_eq!(replayed.resulting_revision, Some(1));
    assert_eq!(
        record_count(&setup, "followup").await,
        1,
        "the committed proposal is returned, not applied a second time"
    );

    drop(successor_service);
    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn real_postgres_receipt_recovery_waits_for_an_in_flight_application() {
    const PROPOSAL_WRITE_LOCK: i64 = 819_275;

    let receiver = HttpsReceiver::start().await;
    let url_registry = compile_proposal_registry(
        &format!(
            "[{}]",
            hook_json(
                "case-created",
                true,
                r#"{"kind":"url","destinationId":"case-operations"}"#,
            )
        ),
        "[]",
        &[],
    );
    let setup = setup(url_registry, &receiver, true).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "concurrent-recovery").await;
    let delivery_id = single_delivery(&event).to_owned();
    drop(mutation_client);

    let followup_table = &setup
        .compiled
        .entities()
        .get("followup")
        .expect("the followup entity is compiled")
        .physical_table;
    setup
        .database
        .admin
        .batch_execute(&format!(
            "CREATE FUNCTION registry_internal.pause_hook_proposal_application()
                 RETURNS trigger LANGUAGE plpgsql AS $$
                 BEGIN
                     PERFORM pg_advisory_xact_lock({PROPOSAL_WRITE_LOCK});
                     RETURN NEW;
                 END;
             $$;
             CREATE TRIGGER pause_hook_proposal_application
                 BEFORE INSERT ON registry_data.{followup_table}
                 FOR EACH ROW
                 EXECUTE FUNCTION registry_internal.pause_hook_proposal_application();"
        ))
        .await
        .expect("administrator installs the proposal-application pause");
    setup
        .database
        .admin
        .query_one("SELECT pg_advisory_lock($1)", &[&PROPOSAL_WRITE_LOCK])
        .await
        .expect("administrator holds the proposal write lock");

    receiver
        .enqueue(ResponsePlan::Answer {
            body: HOOK_PROPOSAL_MESSAGE.to_vec(),
        })
        .await;
    let first_service = setup.service.clone();
    let first = tokio::spawn(async move { first_service.deliver_once().await });
    wait_for_runtime_advisory_waits(&setup, 1).await;

    // Model the lease expiring while the original application is still in
    // its mutation transaction. The retry receives `none`; it must wait for
    // that transaction, then classify the committed receipt as a conflict.
    let changed = setup
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_delivery_state
                SET state = 'pending', next_attempt_at = transaction_timestamp(),
                    attempt_started_at = NULL, lease_expires_at = NULL,
                    lease_token = NULL, updated_at = transaction_timestamp()
              WHERE event_id = $1 AND compiled_delivery_id = $2
                AND state = 'leased' AND attempt = 1",
            &[&event.event_id, &delivery_id],
        )
        .await
        .expect("administrator expires and requeues the in-flight delivery");
    assert_eq!(changed, 1);
    receiver
        .enqueue(ResponsePlan::Answer { body: Vec::new() })
        .await;
    let second_service = setup.service.clone();
    let second = tokio::spawn(async move { second_service.deliver_once().await });
    wait_for_runtime_advisory_waits(&setup, 2).await;

    let unlocked: bool = setup
        .database
        .admin
        .query_one("SELECT pg_advisory_unlock($1)", &[&PROPOSAL_WRITE_LOCK])
        .await
        .expect("administrator releases the proposal write lock")
        .get(0);
    assert!(unlocked);
    assert_eq!(
        first.await.expect("the first worker joins"),
        Err(WebhookDeliveryError::Unavailable),
        "the stale first lease cannot finalize"
    );
    assert_eq!(
        second.await.expect("the recovery worker joins"),
        Ok(WebhookWorkOutcome::DeadLettered),
        "the retry observes the committed receipt and records the answer conflict"
    );
    let row = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(row.state, "dead_lettered");
    assert_eq!(row.attempt, 2);
    assert_eq!(row.disposition.as_deref(), Some("dead_lettered"));
    assert_eq!(row.code.as_deref(), Some("hook.proposal.answer_conflict"));
    assert_eq!(record_count(&setup, "followup").await, 1);

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn real_postgres_terminal_retry_fences_a_late_proposal_application() {
    let receiver = HttpsReceiver::start().await;
    let url_registry = compile_proposal_registry(
        &format!(
            "[{}]",
            hook_json(
                "case-created",
                true,
                r#"{"kind":"url","destinationId":"case-operations"}"#,
            )
        ),
        "[]",
        &[],
    );
    let setup = setup(url_registry, &receiver, true).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "late-proposal-fence").await;
    let delivery_id = single_delivery(&event).to_owned();
    drop(mutation_client);

    // Hold the first worker after it sent the request but before it receives
    // the proposing answer, so it has not acquired the proposal lock yet.
    let (request_seen_tx, request_seen_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    receiver
        .enqueue(ResponsePlan::GatedAnswer {
            body: HOOK_PROPOSAL_MESSAGE.to_vec(),
            request_seen: request_seen_tx,
            release: release_rx,
        })
        .await;
    let first_service = setup.service.clone();
    let first = tokio::spawn(async move { first_service.deliver_once().await });
    tokio::time::timeout(Duration::from_secs(3), request_seen_rx)
        .await
        .expect("the first handler request arrives")
        .expect("the receiver reports the first handler request");

    expire_lease(&setup, &event, &delivery_id).await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Idle),
        "the expired first lease is reaped to its final retry"
    );
    wait_until_delivery_is_due(&setup, &event, &delivery_id).await;
    receiver
        .enqueue(ResponsePlan::Answer { body: Vec::new() })
        .await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered),
        "the final retry settles the delivery with no proposal"
    );

    let _ = release_tx.send(());
    assert_eq!(
        first.await.expect("the first worker joins"),
        Err(WebhookDeliveryError::Unavailable),
        "the stale lease cannot apply after the final retry settles"
    );
    let row = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(row.state, "delivered");
    assert_eq!(row.attempt, 2);
    assert_eq!(row.disposition.as_deref(), Some("none"));
    assert_eq!(
        record_count(&setup, "followup").await,
        0,
        "the late proposal creates no registry state"
    );

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_exhausted_failed_retry_recovers_a_committed_proposal() {
    let receiver = HttpsReceiver::start().await;
    let url_registry = compile_proposal_registry(
        &format!(
            "[{}]",
            hook_json(
                "case-created",
                true,
                r#"{"kind":"url","destinationId":"case-operations"}"#,
            )
        ),
        "[]",
        &[],
    );
    let setup = setup(url_registry, &receiver, true).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "failed-retry-recovery").await;
    let delivery_id = single_delivery(&event).to_owned();
    let payload = outbox_payload(&setup, &event).await;
    drop(mutation_client);

    receiver
        .enqueue(ResponsePlan::Answer {
            body: HOOK_PROPOSAL_MESSAGE.to_vec(),
        })
        .await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    rewind_to_crashed_lease(&setup, &event, &delivery_id, &payload).await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Idle),
        "the expired first lease is reaped to its final retry"
    );
    wait_until_delivery_is_due(&setup, &event, &delivery_id).await;

    receiver.enqueue(ResponsePlan::NonSuccess).await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::DeadLettered),
        "the exhausted failed retry recovers the committed proposal receipt"
    );
    let row = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(row.state, "dead_lettered");
    assert_eq!(row.attempt, 2);
    assert_eq!(row.disposition.as_deref(), Some("dead_lettered"));
    assert_eq!(row.code.as_deref(), Some("hook.proposal.answer_conflict"));
    assert_eq!(
        record_count(&setup, "followup").await,
        1,
        "the committed proposal stands and is not applied again"
    );

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_final_expired_lease_recovers_a_committed_proposal() {
    let receiver = HttpsReceiver::start().await;
    let url_registry = compile_proposal_registry(
        &format!(
            "[{}]",
            hook_json(
                "case-created",
                true,
                r#"{"kind":"url","destinationId":"case-operations"}"#,
            )
        ),
        "[]",
        &[],
    );
    let setup = setup_with_pool_size(url_registry, &receiver, true, 1).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "final-lease-recovery").await;
    let delivery_id = single_delivery(&event).to_owned();
    let payload = outbox_payload(&setup, &event).await;
    drop(mutation_client);

    receiver
        .enqueue(ResponsePlan::Answer {
            body: HOOK_PROPOSAL_MESSAGE.to_vec(),
        })
        .await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    rewind_to_crashed_lease(&setup, &event, &delivery_id, &payload).await;
    let changed = setup
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_delivery_state
             SET attempt = 2
             WHERE event_id = $1 AND compiled_delivery_id = $2",
            &[&event.event_id, &delivery_id],
        )
        .await
        .expect("administrator models a crash on the final allowed attempt");
    assert_eq!(changed, 1);

    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Idle),
        "the reaper terminalizes the expired final lease before claiming new work"
    );
    let row = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(row.state, "dead_lettered");
    assert_eq!(row.attempt, 2);
    assert_eq!(row.disposition.as_deref(), Some("dead_lettered"));
    assert_eq!(row.code.as_deref(), Some("hook.proposal.answer_conflict"));
    assert_eq!(
        record_count(&setup, "followup").await,
        1,
        "the final worker's committed proposal stands"
    );

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_a_hidden_effect_proposal_finalizes_as_applied() {
    let receiver = HttpsReceiver::start().await;
    let setup = setup(hidden_result_registry(), &receiver, false).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "hidden-result").await;
    let delivery_id = single_delivery(&event).to_owned();
    drop(mutation_client);

    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered),
        "a proposal whose granted result set hides every applied effect still completes"
    );
    let row = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(row.state, "delivered");
    assert_eq!(row.disposition.as_deref(), Some("applied"));
    assert_eq!(
        row.resulting_revision,
        Some(1),
        "the committed revision comes from the applied result records, not the filtered response"
    );
    assert_eq!(record_count(&setup, "followup").await, 1);

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_uncertain_hook_apply_fails_closed_and_recovers() {
    let receiver = HttpsReceiver::start().await;
    let setup = setup(proposal_registry(), &receiver, false).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "uncertain").await;
    let delivery_id = single_delivery(&event).to_owned();
    drop(mutation_client);

    // The apply fails after the handler answered, in a way the worker cannot
    // distinguish from a commit it cannot see: the outcome is uncertain.
    revoke_followup_insert(&setup).await;
    assert_eq!(
        setup.service.deliver_once().await,
        Err(WebhookDeliveryError::Unavailable),
        "an uncertain apply fails closed instead of recording a disposition"
    );
    let uncertain = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(uncertain.state, "leased", "the row keeps its lease");
    assert_eq!(uncertain.attempt, 1);
    assert_eq!(uncertain.message, None, "no answer is recorded");
    assert_eq!(uncertain.message_digest, None);
    assert_eq!(uncertain.disposition, None, "no disposition is recorded");
    assert_eq!(uncertain.resulting_revision, None);
    assert_eq!(uncertain.code, None);
    assert_eq!(uncertain.summary, None);
    assert_eq!(
        record_count(&setup, "followup").await,
        0,
        "nothing was applied under the fault"
    );

    // The fault clears and lease expiry recovers the row: the retry re-asks
    // the handler, re-applies the same answer, and this time records it.
    grant_followup_insert(&setup).await;
    expire_lease(&setup, &event, &delivery_id).await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Idle),
        "the expired lease is reaped to a scheduled retry"
    );
    wait_until_delivery_is_due(&setup, &event, &delivery_id).await;
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    let recovered = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(recovered.state, "delivered");
    assert_eq!(recovered.attempt, 2);
    assert_eq!(recovered.disposition.as_deref(), Some("applied"));
    assert_eq!(recovered.resulting_revision, Some(1));
    assert_eq!(record_count(&setup, "followup").await, 1);

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_hook_delivery_rows_record_every_proposal_disposition() {
    let receiver = HttpsReceiver::start().await;
    let setup = setup(dispositions_registry(), &receiver, false).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    create_case(&setup, &mut mutation_client, "dispositions").await;
    drop(mutation_client);

    // One outbox event exists per hook, so one case create captured four
    // (event, delivery) pairs, one per declared hook.
    let deliveries = case_deliveries(&setup).await;
    assert_eq!(
        deliveries.len(),
        4,
        "every declared hook captured its delivery"
    );
    let event_of = |delivery_id: &str| {
        deliveries
            .iter()
            .find(|(_, id)| id == delivery_id)
            .map(|(event_id, _)| *event_id)
            .unwrap_or_else(|| panic!("delivery {delivery_id} was captured"))
    };

    // The claim order across the four rows follows their random event ids,
    // so the journey compares the four outcomes as a set: three delivered
    // answers and the one dead letter.
    let mut outcome_names = Vec::new();
    for _ in 0..4 {
        let outcome = setup
            .service
            .deliver_once()
            .await
            .expect("one disposition journey iteration completes");
        outcome_names.push(match outcome {
            WebhookWorkOutcome::Delivered => "delivered",
            WebhookWorkOutcome::DeadLettered => "dead_lettered",
            WebhookWorkOutcome::RetryScheduled => "retry_scheduled",
            WebhookWorkOutcome::Idle => "idle",
        });
    }
    outcome_names.sort_unstable();
    assert_eq!(
        outcome_names,
        ["dead_lettered", "delivered", "delivered", "delivered"],
        "three hooks delivered their answers and the principal-less proposal dead-lettered"
    );
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Idle)
    );

    let none_row = delivery_row(
        &setup,
        event_of("events.case.silent-observer.webhook"),
        "events.case.silent-observer.webhook",
    )
    .await;
    assert_eq!(none_row.state, "delivered");
    assert_eq!(none_row.disposition.as_deref(), Some("none"));
    assert_eq!(none_row.resulting_revision, None);
    assert_eq!(none_row.code, None);
    assert_eq!(
        none_row.message, None,
        "the none answer's bytes are not retained"
    );
    assert_eq!(
        none_row.message_digest.as_ref().map(Vec::len),
        Some(32),
        "the none answer is recorded by its digest"
    );

    let applied_row = delivery_row(
        &setup,
        event_of("events.case.case-applier.webhook"),
        "events.case.case-applier.webhook",
    )
    .await;
    assert_eq!(applied_row.state, "delivered");
    assert_eq!(applied_row.disposition.as_deref(), Some("applied"));
    assert_eq!(applied_row.resulting_revision, Some(1));
    assert_eq!(applied_row.code, None);
    assert_eq!(applied_row.message, None);
    assert_eq!(
        applied_row.message_digest.as_deref(),
        Some(proposal_message_digest().as_slice())
    );

    let refused_row = delivery_row(
        &setup,
        event_of("events.case.invalid-proposer.webhook"),
        "events.case.invalid-proposer.webhook",
    )
    .await;
    assert_eq!(refused_row.state, "delivered");
    assert_eq!(refused_row.disposition.as_deref(), Some("refused"));
    assert_eq!(refused_row.resulting_revision, None);
    assert_eq!(
        refused_row.code.as_deref(),
        Some("hook.proposal.outcome_refused")
    );
    assert!(
        refused_row
            .summary
            .as_deref()
            .is_some_and(|summary| !summary.is_empty()),
        "a refusal records a bounded human-readable reason"
    );

    let dead_row = delivery_row(
        &setup,
        event_of("events.case.principal-less-proposer.webhook"),
        "events.case.principal-less-proposer.webhook",
    )
    .await;
    assert_eq!(dead_row.state, "dead_lettered");
    assert_eq!(dead_row.disposition.as_deref(), Some("dead_lettered"));
    assert_eq!(dead_row.resulting_revision, None);
    assert_eq!(
        dead_row.code.as_deref(),
        Some("hook.proposal.no_principal"),
        "the row names the deployment defect a principal-less proposal is"
    );
    assert!(dead_row
        .summary
        .as_deref()
        .is_some_and(|summary| !summary.is_empty()));

    assert_eq!(record_count(&setup, "followup").await, 1);
    assert_eq!(record_count(&setup, "case").await, 1);

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn real_postgres_the_same_proposal_applies_identically_across_handler_kinds() {
    let receiver = HttpsReceiver::start().await;

    // The legs collect what each handler kind produced: the recorded answer
    // digest, the disposition columns, and the applied record itself.
    type HandlerKindLeg = (Vec<u8>, DeliveryRow, (String, String, String));
    let mut legs: Vec<HandlerKindLeg> = Vec::new();

    {
        let url_registry = compile_proposal_registry(
            &format!(
                "[{}]",
                hook_json(
                    "case-created",
                    true,
                    r#"{"kind":"url","destinationId":"case-operations"}"#,
                )
            ),
            "[]",
            &[],
        );
        let setup = setup(url_registry, &receiver, true).await;
        let mut mutation_client = setup
            .pool
            .get_for_test()
            .await
            .expect("runtime mutation connection is available");
        let event = create_case(&setup, &mut mutation_client, "parity-url").await;
        let delivery_id = single_delivery(&event).to_owned();
        drop(mutation_client);
        receiver
            .enqueue(ResponsePlan::Answer {
                body: HOOK_PROPOSAL_MESSAGE.to_vec(),
            })
            .await;
        assert_eq!(
            setup.service.deliver_once().await,
            Ok(WebhookWorkOutcome::Delivered)
        );
        let row = delivery_row(&setup, event.event_id, &delivery_id).await;
        legs.push((
            row.message_digest
                .clone()
                .expect("the url answer digest is recorded"),
            row,
            followup_content(&setup).await,
        ));
        setup.teardown().await;
    }

    {
        let rhai_registry = compile_proposal_registry(
            &format!(
                "[{}]",
                hook_json("case-created", true, PROPOSING_RHAI_HANDLER)
            ),
            "[]",
            &[rhai_asset("hooks/propose.rhai", PROPOSAL_HOOK_SCRIPT)],
        );
        let setup = setup(rhai_registry, &receiver, false).await;
        let mut mutation_client = setup
            .pool
            .get_for_test()
            .await
            .expect("runtime mutation connection is available");
        let event = create_case(&setup, &mut mutation_client, "parity-rhai").await;
        let delivery_id = single_delivery(&event).to_owned();
        drop(mutation_client);
        assert_eq!(
            setup.service.deliver_once().await,
            Ok(WebhookWorkOutcome::Delivered)
        );
        let row = delivery_row(&setup, event.event_id, &delivery_id).await;
        legs.push((
            row.message_digest
                .clone()
                .expect("the rhai answer digest is recorded"),
            row,
            followup_content(&setup).await,
        ));
        setup.teardown().await;
    }

    #[cfg(feature = "wasm")]
    {
        let wasm_registry = compile_proposal_registry(
            &format!(
                "[{}]",
                hook_json(
                    "case-created",
                    true,
                    r#"{"kind":"wasm","module":"hooks/case-created.wasm","abi":"registry.hook-handler/v1"}"#,
                )
            ),
            "[]",
            &[ModuleAssetSource {
                module: None,
                path: "hooks/case-created.wasm".to_owned(),
                bytes: outcome_guest(HOOK_PROPOSAL_STR),
            }],
        );
        // Assembling the delivery path directly bypasses the server startup
        // path, so this embedder installs the process WASM runtime itself.
        registry_breg::wasm_runtime::install_default().expect("the wasm runtime installs");
        let setup = setup(wasm_registry, &receiver, false).await;
        let mut mutation_client = setup
            .pool
            .get_for_test()
            .await
            .expect("runtime mutation connection is available");
        let event = create_case(&setup, &mut mutation_client, "parity-wasm").await;
        let delivery_id = single_delivery(&event).to_owned();
        drop(mutation_client);
        assert_eq!(
            setup.service.deliver_once().await,
            Ok(WebhookWorkOutcome::Delivered)
        );
        let row = delivery_row(&setup, event.event_id, &delivery_id).await;
        legs.push((
            row.message_digest
                .clone()
                .expect("the wasm answer digest is recorded"),
            row,
            followup_content(&setup).await,
        ));
        setup.teardown().await;
    }

    assert!(
        legs.len() >= 2,
        "at least the url and rhai legs ran in this build"
    );
    for (message_digest, row, followup) in &legs {
        assert_eq!(
            message_digest.as_slice(),
            proposal_message_digest().as_slice(),
            "every kind recorded the same canonical proposal digest"
        );
        assert_eq!(row.message, None, "no kind retains the answer bytes");
        assert_eq!(row.state, "delivered");
        assert_eq!(row.disposition.as_deref(), Some("applied"));
        assert_eq!(row.resulting_revision, Some(1));
        assert_eq!(
            followup,
            &(
                "zone-a".to_owned(),
                "hook followup".to_owned(),
                "hook-proposal".to_owned()
            ),
            "every kind applied the same record values"
        );
    }

    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_a_hook_without_a_principal_compiles_and_delivers() {
    let receiver = HttpsReceiver::start().await;
    let compiled = silent_registry();
    assert_eq!(
        compiled.event_deliveries().deliveries.len(),
        1,
        "a hook that declares no principal compiles into its delivery"
    );
    let setup = setup(compiled, &receiver, false).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "silent").await;
    let delivery_id = single_delivery(&event).to_owned();
    drop(mutation_client);

    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered),
        "a non-proposing, principal-less hook delivers normally"
    );
    let row = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(row.state, "delivered");
    assert_eq!(row.attempt, 1);
    assert_eq!(row.disposition.as_deref(), Some("none"));
    assert_eq!(row.resulting_revision, None);
    assert_eq!(row.code, None);
    assert_eq!(record_count(&setup, "followup").await, 0);

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_a_proposal_without_a_declared_principal_is_dead_lettered_readable() {
    let receiver = HttpsReceiver::start().await;
    let setup = setup(principal_less_registry(), &receiver, false).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "principal-less").await;
    let delivery_id = single_delivery(&event).to_owned();
    drop(mutation_client);

    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::DeadLettered),
        "a principal-less proposal is dead-lettered on its first attempt"
    );
    let row = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(row.state, "dead_lettered");
    assert_eq!(row.attempt, 1);
    assert_eq!(row.disposition.as_deref(), Some("dead_lettered"));
    assert_eq!(row.resulting_revision, None);
    assert_eq!(row.code.as_deref(), Some("hook.proposal.no_principal"));
    assert!(
        row.summary
            .as_deref()
            .is_some_and(|summary| !summary.is_empty()),
        "the dead-letter reason is readable from the row without logs"
    );
    assert_eq!(
        record_count(&setup, "followup").await,
        0,
        "nothing was applied"
    );
    assert_eq!(record_count(&setup, "case").await, 1);
    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Idle),
        "the dead letter is terminal"
    );

    setup.teardown().await;
    receiver.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_a_proposal_failing_outcome_validation_is_refused_not_applied() {
    let receiver = HttpsReceiver::start().await;
    let setup = setup(invalid_proposal_registry(), &receiver, false).await;
    let mut mutation_client = setup
        .pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let event = create_case(&setup, &mut mutation_client, "invalid").await;
    let delivery_id = single_delivery(&event).to_owned();
    drop(mutation_client);

    assert_eq!(
        setup.service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered),
        "a refused proposal still completes its delivery"
    );
    let row = delivery_row(&setup, event.event_id, &delivery_id).await;
    assert_eq!(row.state, "delivered");
    assert_eq!(row.attempt, 1);
    assert_eq!(row.disposition.as_deref(), Some("refused"));
    assert_eq!(row.resulting_revision, None);
    assert_eq!(
        row.code.as_deref(),
        Some("hook.proposal.outcome_refused"),
        "the refusal names the validation that refused it"
    );
    assert!(row
        .summary
        .as_deref()
        .is_some_and(|summary| !summary.is_empty()));
    assert_eq!(
        record_count(&setup, "followup").await,
        0,
        "an invalid proposal applies nothing, not even a part"
    );
    assert_eq!(record_count(&setup, "case").await, 1);

    setup.teardown().await;
    receiver.stop().await;
}

// ---------------------------------------------------------------------------
// Deployment fixtures: the loopback TLS receiver a `url` hook answers
// through, and the runtime binding that activates its destination.
// ---------------------------------------------------------------------------

struct DestinationFixture {
    root: PathBuf,
    secret_root: PathBuf,
    package_root: PathBuf,
    trust_anchor: PathBuf,
    receiver_port: u16,
}

impl DestinationFixture {
    fn new(receiver: &HttpsReceiver) -> Self {
        let temporary_parent = std::env::temp_dir()
            .canonicalize()
            .expect("temporary parent canonicalizes");
        let root = tempfile::Builder::new()
            .prefix("breg-hook-proposals-")
            .tempdir_in(temporary_parent)
            .expect("unique fixture root creates")
            .keep();
        let secret_root = root.join("secrets");
        let package_root = root.join("package");
        fs::create_dir_all(&secret_root).expect("secret root creates");
        fs::create_dir(&package_root).expect("package root creates");
        let trust_anchor = root.join("trust-anchor.json");
        fs::write(&trust_anchor, "{}").expect("trust anchor placeholder writes");
        write_secret(&secret_root.join(KEY_REF_CANARY), HMAC_KEY);
        write_secret(
            &secret_root.join(CA_REF_CANARY),
            receiver.certificate_pem.as_bytes(),
        );
        Self {
            root,
            secret_root,
            package_root,
            trust_anchor,
            receiver_port: receiver.address.port(),
        }
    }

    fn activate(
        &self,
        compiled: &registry_breg::CompiledRegistry,
    ) -> ActivatedEventDestinationRegistry {
        parse_runtime_config(&self.runtime_config(&format!(
            r#"eventDestinations:
  {DESTINATION_ID}:
    origin: https://localhost:{}/
    path: {DELIVERY_PATH}
    networkProfile: pinnedLoopbackHttpsTest
    dnsFamily: ipv4Only
    allowedPrivateCidrs: []
    hmacSha256KeyRef: secret:file/{KEY_REF_CANARY}
    classificationCeiling: restricted
    tls:
      caBundleRef: secret:file/{CA_REF_CANARY}
    deliveryCeilings:
      attemptTimeoutMilliseconds: 2000
      maximumAttempts: 2
"#,
            self.receiver_port,
        )))
        .expect("strict pinned-loopback HTTPS config parses")
        .activate_event_destinations(compiled)
        .expect("exact destination inventory and TLS material activate")
    }

    /// The same deployment with no destination configured at all, for a
    /// package whose hooks all run local programs.
    fn activate_without_destinations(
        &self,
        compiled: &registry_breg::CompiledRegistry,
    ) -> ActivatedEventDestinationRegistry {
        parse_runtime_config(&self.runtime_config(""))
            .expect("a deployment without destinations parses")
            .activate_event_destinations(compiled)
            .expect("an empty destination inventory matches a local-only package")
    }

    fn runtime_config(&self, event_destinations: &str) -> String {
        format!(
            r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:8080
identity:
  environment: local
  instanceId: hook-proposal-instance
  databaseId: hook-proposal-database
  databaseInitializationEnvironment: local
secretProviders:
  file:
    root: {}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 12
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: registry_migration
    runtime: registry_runtime
package:
  root: {}
  trustAnchorPath: {}
  compilerSourceRevision: source-revision-1
  activeRevision: {}
  activeSequence: 1
authentication:
  oidc:
    issuer: https://issuer.example
    audience: urn:breg:hook-proposals
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [registry-client]
    deniedKids: [denied-kid]
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 900
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
{event_destinations}operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 30000
  migrationStatementMilliseconds: 60000
"#,
            self.secret_root.display(),
            self.package_root.display(),
            self.trust_anchor.display(),
            PACKAGE_REVISION,
        )
    }
}

impl Drop for DestinationFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_secret(path: &std::path::Path, value: &[u8]) {
    fs::write(path, value).expect("test secret writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("test secret permissions set");
    }
}

enum ResponsePlan {
    /// A 2xx that answers with the exact body a remote hook handler returns.
    Answer { body: Vec<u8> },
    /// A 2xx answer held after the request arrives, for ordering a worker
    /// before proposal application without timing assumptions.
    GatedAnswer {
        body: Vec<u8>,
        request_seen: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
    },
    /// A retryable HTTP failure that carries no accepted handler answer.
    NonSuccess,
}

struct HttpsReceiver {
    address: std::net::SocketAddr,
    certificate_pem: String,
    plans: Arc<Mutex<VecDeque<ResponsePlan>>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl HttpsReceiver {
    async fn start() -> Self {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("loopback TLS certificate generates");
        let certificate_der = cert.der().clone();
        let certificate_pem = pem("CERTIFICATE", certificate_der.as_ref());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key)
            .expect("loopback TLS server configuration builds");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback TLS receiver binds");
        let address = listener
            .local_addr()
            .expect("receiver address is available");
        let plans = Arc::new(Mutex::new(VecDeque::new()));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let task_plans = Arc::clone(&plans);
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = &mut shutdown_rx => return,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, _)) = accepted else {
                    return;
                };
                let acceptor = acceptor.clone();
                let plans = Arc::clone(&task_plans);
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    if drain_request(&mut stream).await.is_err() {
                        return;
                    }
                    let plan = plans.lock().await.pop_front();
                    let (status, body) = match plan {
                        Some(ResponsePlan::Answer { body }) => (200, body),
                        Some(ResponsePlan::GatedAnswer {
                            body,
                            request_seen,
                            release,
                        }) => {
                            let _ = request_seen.send(());
                            let _ = release.await;
                            (200, body)
                        }
                        Some(ResponsePlan::NonSuccess) => (503, Vec::new()),
                        None => (204, Vec::new()),
                    };
                    let reason = match status {
                        200 => "OK",
                        204 => "No Content",
                        _ => "Server Error",
                    };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    if !body.is_empty() {
                        let _ = stream.write_all(&body).await;
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            address,
            certificate_pem,
            plans,
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    async fn enqueue(&self, plan: ResponsePlan) {
        self.plans.lock().await.push_back(plan);
    }

    /// Stop the accept loop and wait for it to exit.
    async fn stop(self) {
        if let Some(shutdown) = self.shutdown {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

/// Read and discard one request, so the receiver can answer it correctly.
async fn drain_request<S>(stream: &mut S) -> Result<(), ()>
where
    S: AsyncReadExt + Unpin,
{
    let mut bytes = Vec::with_capacity(2_048);
    let header_end = loop {
        let mut chunk = [0_u8; 1_024];
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 || bytes.len() + read > 2_097_152 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end]).map_err(|_| ())?;
    let content_length = header_text
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .ok_or(())?;
    while bytes.len() - header_end < content_length {
        let mut chunk = [0_u8; 1_024];
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 || bytes.len() + read > 2_097_152 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(())
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is UTF-8"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

#[cfg(feature = "wasm")]
fn hex_escape(bytes: &[u8]) -> String {
    let mut escaped = String::with_capacity(bytes.len() * 4);
    for byte in bytes {
        escaped.push_str(&format!("\\{byte:02x}"));
    }
    escaped
}

/// A wat guest whose result window holds `document` verbatim: the same guest
/// contract an action handler module speaks, answering the hook ABI.
#[cfg(feature = "wasm")]
fn outcome_guest(document: &str) -> Vec<u8> {
    let document = document.as_bytes();
    let wat = format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{escaped}")
  (func (export "alloc") (param $len i32) (result i32) (i32.const 4096))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i32) (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 1024))
  (func (export "result_len") (result i32) (i32.const {len}))
)"#,
        escaped = hex_escape(document),
        len = document.len(),
    );
    wat::parse_str(&wat).expect("guest wat compiles to a binary module")
}

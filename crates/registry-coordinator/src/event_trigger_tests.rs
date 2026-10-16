// SPDX-License-Identifier: Apache-2.0
use super::*;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::delivery_signature::{sign_v1, SignatureFields};
use serde_json::json;
use uuid::Uuid;

const KEY: &[u8] = &[0x5a; 32];
const BREG_SOURCE: &str = "urn:registrystack:registry:synthetic:instance:local";
const EVENT_TYPE: &str = "contact-created-v1";
const DATA_SCHEMA: &str = "urn:example:contact-created:v1";
const TARGET: &str = "/v1/events/record-follow-up/record-saved";

fn source() -> EventSourceConfig {
    EventSourceConfig {
        source: ExternalId::new(BREG_SOURCE).unwrap(),
        signing_key_ref: SecretReference::parse("secret:file/event-key").unwrap(),
    }
}
fn trigger() -> EventTrigger {
    EventTrigger {
        source: "registry".into(),
        event_type: EVENT_TYPE.into(),
        data_schema: DATA_SCHEMA.into(),
        event: json!({"type":"object"}),
        input: Mapping::Fields {
            fields: BTreeMap::from([(
                "recordId".into(),
                crate::definition::Reference::Input {
                    path: Some("/data/recordId".into()),
                },
            )]),
        },
    }
}
fn event() -> Value {
    let id = Uuid::new_v4().to_string();
    json!({
        "id":id,"type":EVENT_TYPE,"source":BREG_SOURCE,"time":"2020-01-01T00:00:00.123Z",
        "subject":{"recordReference":"sha256:synthetic-record","recordRevision":1},
        "dataschema":DATA_SCHEMA,
        "data":{"recordType":"contact","recordId":"00000000-0000-4000-8000-000000000001","revision":1,
            "trigger":"created","packageRevision":"sha256:synthetic","values":{"name":"Synthetic name"}},
        "causation":{"root":id,"hop":0}
    })
}
fn signed(
    value: &Value,
    target: &str,
    generation: u32,
    delivery_key: &str,
) -> (Vec<u8>, HeaderMap) {
    let body = canonicalize_json(value).unwrap();
    let mut headers = HeaderMap::new();
    for (name, text) in [
        ("content-type", "application/json".to_owned()),
        ("ce-specversion", "1.0".to_owned()),
        ("ce-id", value["id"].as_str().unwrap().to_owned()),
        ("ce-source", value["source"].as_str().unwrap().to_owned()),
        ("ce-type", value["type"].as_str().unwrap().to_owned()),
        ("ce-time", value["time"].as_str().unwrap().to_owned()),
        (
            "ce-dataschema",
            value["dataschema"].as_str().unwrap().to_owned(),
        ),
        ("x-registry-event-generation", generation.to_string()),
        ("x-registry-delivery-attempt", "1".to_owned()),
        (
            "x-registry-delivery-time",
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ),
        ("idempotency-key", delivery_key.to_owned()),
    ] {
        headers.insert(name, HeaderValue::from_str(&text).unwrap());
    }
    sign_headers(&mut headers, &body, target);
    (body, headers)
}
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}
fn sign_headers(headers: &mut HeaderMap, body: &[u8], target: &str) {
    let signature = sign_v1(
        KEY,
        SignatureFields {
            id: header(headers, "ce-id").unwrap(),
            source: header(headers, "ce-source").unwrap(),
            event_type: header(headers, "ce-type").unwrap(),
            time: header(headers, "ce-time").unwrap(),
            data_schema: header(headers, "ce-dataschema").unwrap(),
            generation: header(headers, "x-registry-event-generation").unwrap(),
            attempt: header(headers, "x-registry-delivery-attempt").unwrap(),
            delivery_time: header(headers, "x-registry-delivery-time").unwrap(),
            method: "POST",
            request_target: target,
            content_type: "application/json",
            idempotency_key: header(headers, "idempotency-key").unwrap(),
            body,
        },
    )
    .unwrap();
    headers.insert(
        "x-registry-signature",
        HeaderValue::from_str(&signature).unwrap(),
    );
}
fn verify(body: &[u8], headers: &HeaderMap) -> Result<VerifiedEvent> {
    verify_delivery(
        &source(),
        "registry",
        &trigger(),
        "record-saved",
        &Method::POST,
        TARGET,
        headers,
        body,
        KEY,
        SystemTime::now(),
    )
}

#[test]
fn event_authentication_challenges_the_signature_transport() {
    let response = event_problem(unauthenticated());
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[axum::http::header::WWW_AUTHENTICATE],
        "Registry-Signature version=\"v1\""
    );
    let bearer = crate::http::problem(CoordinatorError::new("access.unauthenticated", "synthetic"));
    assert_eq!(
        bearer.headers()[axum::http::header::WWW_AUTHENTICATE],
        "Bearer"
    );
}

#[test]
fn exact_event_identity_survives_retry_replay_and_old_commit_time() {
    let value = event();
    let (body, headers) = signed(&value, TARGET, 1, "first-delivery");
    let first = verify(&body, &headers).unwrap();
    let (replay_body, replay_headers) = signed(&value, TARGET, 2, "operator-replay");
    let replay = verify(&replay_body, &replay_headers).unwrap();
    assert_eq!(first.key, replay.key);
    assert_eq!(first.digest, replay.digest);
    let mut alias = value.clone();
    alias["id"] = json!(value["id"].as_str().unwrap().to_ascii_uppercase());
    alias["causation"]["root"] = alias["id"].clone();
    let (alias_body, alias_headers) = signed(&alias, TARGET, 1, "uuid-spelling-alias");
    let alias = verify(&alias_body, &alias_headers).unwrap();
    assert_eq!(
        first.key, alias.key,
        "UUID spelling cannot manufacture a new logical event"
    );
    assert_eq!(
        first.actor.issuer,
        "urn:registrystack:coordinator:event-source"
    );
    assert!(!first.actor.operator);
    let mut changed = value;
    changed["data"]["values"]["name"] = json!("Changed ignored projection");
    let (body, headers) = signed(&changed, TARGET, 1, "other-delivery");
    let changed = verify(&body, &headers).unwrap();
    assert_eq!(changed.key, first.key);
    assert_ne!(
        changed.digest, first.digest,
        "full envelope is bound even if mapping ignores changed values"
    );
}

#[test]
fn event_ownership_follows_the_authenticated_producer_across_source_aliases() {
    let value = event();
    let (body, headers) = signed(&value, TARGET, 1, "first-delivery");
    let first = verify(&body, &headers).unwrap();
    let mut renamed = trigger();
    renamed.source = "renamed-registry".into();
    let replay = verify_delivery(
        &source(),
        &renamed.source,
        &renamed,
        "record-saved",
        &Method::POST,
        TARGET,
        &headers,
        &body,
        KEY,
        SystemTime::now(),
    )
    .unwrap();
    assert_eq!(first.key, replay.key);
    assert_eq!(first.actor.issuer, replay.actor.issuer);
    assert_eq!(first.actor.subject, replay.actor.subject);
    assert_eq!(first.actor.client_id, replay.actor.client_id);
    assert!(!replay.actor.operator);

    assert!(
        verify_delivery(
            &source(),
            "registry",
            &renamed,
            "record-saved",
            &Method::POST,
            TARGET,
            &headers,
            &body,
            KEY,
            SystemTime::now(),
        )
        .is_err(),
        "the trigger must still select the configured source alias"
    );

    let mut other = value;
    other["source"] = json!("urn:example:another-authenticated-producer");
    let mut other_source = source();
    other_source.source = ExternalId::new(other["source"].as_str().unwrap()).unwrap();
    let (body, headers) = signed(&other, TARGET, 1, "other-producer");
    let other = verify_delivery(
        &other_source,
        "registry",
        &trigger(),
        "record-saved",
        &Method::POST,
        TARGET,
        &headers,
        &body,
        KEY,
        SystemTime::now(),
    )
    .unwrap();
    assert_ne!(first.key, other.key);
    assert_ne!(first.actor.subject, other.actor.subject);
    assert_ne!(first.actor.client_id, other.actor.client_id);
    assert!(
        verify(&body, &headers).is_err(),
        "another producer cannot use the original source binding"
    );
}

#[test]
fn a_conforming_alternate_product_uses_the_same_verifier() {
    let mut value = event();
    value["source"] = json!("urn:registrystack:scheduling:synthetic:local");
    value["type"] = json!("appointment-confirmed-v1");
    value["dataschema"] = json!("urn:example:appointment-confirmed:v1");
    value["subject"] = json!({"recordReference":"/v1/appointments/00000000-0000-4000-8000-000000000002","recordRevision":1});
    value["data"] =
        json!({"appointmentId":"00000000-0000-4000-8000-000000000002","state":"confirmed"});
    let mut source = source();
    source.source = ExternalId::new(value["source"].as_str().unwrap()).unwrap();
    let mut trigger = trigger();
    trigger.source = "appointments".into();
    trigger.event_type = value["type"].as_str().unwrap().into();
    trigger.data_schema = value["dataschema"].as_str().unwrap().into();
    let (body, headers) = signed(&value, TARGET, 1, "scheduling-delivery");
    let verified = verify_delivery(
        &source,
        "appointments",
        &trigger,
        "appointment-saved",
        &Method::POST,
        TARGET,
        &headers,
        &body,
        KEY,
        SystemTime::now(),
    )
    .unwrap();
    assert_eq!(verified.value["data"]["state"], "confirmed");
}

#[test]
fn substituted_signature_destination_source_and_contract_are_refused() {
    let value = event();
    let (body, original) = signed(&value, TARGET, 1, "delivery");
    for (name, replacement) in [
        (
            "x-registry-signature",
            "v1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        ("ce-source", "urn:example:another-source"),
        ("ce-type", "another-event-v1"),
        ("ce-dataschema", "urn:example:another-schema"),
        ("ce-specversion", "0.3"),
        ("x-registry-event-generation", "0"),
        ("x-registry-delivery-attempt", "-1"),
    ] {
        let mut headers = original.clone();
        headers.insert(name, HeaderValue::from_static(replacement));
        assert!(verify(&body, &headers).is_err(), "{name}");
    }
    assert!(verify_delivery(
        &source(),
        "registry",
        &trigger(),
        "record-saved",
        &Method::POST,
        "/different-target",
        &original,
        &body,
        KEY,
        SystemTime::now()
    )
    .is_err());
    assert!(verify_delivery(
        &source(),
        "registry",
        &trigger(),
        "record-saved",
        &Method::PUT,
        TARGET,
        &original,
        &body,
        KEY,
        SystemTime::now()
    )
    .is_err());
    let mut duplicate = original;
    duplicate.append("ce-source", HeaderValue::from_static(BREG_SOURCE));
    assert!(
        verify(&body, &duplicate).is_err(),
        "ambiguous signed headers are refused"
    );
}

#[test]
fn stale_delivery_noncanonical_body_and_header_body_disagreement_are_refused() {
    let value = event();
    let (body, mut headers) = signed(&value, TARGET, 1, "delivery");
    headers.insert(
        "x-registry-delivery-time",
        HeaderValue::from_static("2020-01-01T00:00:00Z"),
    );
    sign_headers(&mut headers, &body, TARGET);
    assert!(verify(&body, &headers).is_err());
    let (_, mut headers) = signed(&value, TARGET, 1, "delivery");
    let mut spaced = body.clone();
    spaced.push(b' ');
    sign_headers(&mut headers, &spaced, TARGET);
    assert!(verify(&spaced, &headers).is_err());
    let mut changed = value.clone();
    changed["id"] = json!(Uuid::new_v4().to_string());
    changed["causation"]["root"] = changed["id"].clone();
    let changed = canonicalize_json(&changed).unwrap();
    sign_headers(&mut headers, &changed, TARGET);
    assert!(verify(&changed, &headers).is_err());
    assert!(verify(&vec![b' '; MAXIMUM_EVENT_BYTES + 1], &headers).is_err());
}

#[test]
fn the_intake_bound_is_the_signable_bound_and_its_refusal_names_the_limit() {
    assert_eq!(
        MAXIMUM_EVENT_BYTES,
        registry_platform_crypto::delivery_signature::MAX_BODY_BYTES
    );
    // A signed event above the former 64 KiB intake bound and within the
    // structured-value profile is admitted.
    let mut value = event();
    for index in 0..6 {
        value["data"]["values"][format!("field{index}")] = json!("x".repeat(15_000));
    }
    let (body, headers) = signed(&value, TARGET, 1, "large-delivery");
    assert!(body.len() > 65_536);
    verify(&body, &headers).unwrap();
    let error = verify(&vec![b' '; MAXIMUM_EVENT_BYTES + 1], &headers)
        .err()
        .unwrap();
    assert_eq!(error.code, "request.body-too-large");
    assert!(error.message.contains("1048576"), "{}", error.message);
}

#[test]
fn a_signed_event_over_the_value_profile_is_refused_naming_the_bound_and_fix() {
    // Within the signable bound, but over the 131,072-byte event value profile.
    let mut value = event();
    for index in 0..20 {
        value["data"]["values"][format!("field{index}")] = json!("x".repeat(15_000));
    }
    let (body, headers) = signed(&value, TARGET, 1, "oversized-value");
    assert!(body.len() > crate::functions::MAXIMUM_VALUE_BYTES);
    assert!(body.len() <= MAXIMUM_EVENT_BYTES);
    let error = verify(&body, &headers).err().unwrap();
    assert_eq!(error.code, "event-too-large");
    let message = error.message.clone();

    let response = event_problem(error);
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let problem = crate::problem::ProblemCode::EventTooLarge;
    assert_eq!(problem.code(), "event.too-large");
    let detail = problem.detail();
    for bound in [
        format!("{} canonical bytes", crate::functions::MAXIMUM_VALUE_BYTES),
        format!(
            "{} levels of nesting",
            crate::functions::MAXIMUM_VALUE_DEPTH
        ),
        format!("{} values", crate::functions::MAXIMUM_VALUE_NODES),
        format!(
            "{} items per array",
            crate::functions::MAXIMUM_VALUE_ARRAY_ITEMS
        ),
        format!(
            "{} members per object",
            crate::functions::MAXIMUM_VALUE_OBJECT_MEMBERS
        ),
        format!(
            "{} bytes per string",
            crate::functions::MAXIMUM_VALUE_STRING_BYTES
        ),
    ] {
        assert!(detail.contains(&bound), "{bound}: {detail}");
        assert!(message.contains(&bound), "{bound}: {message}");
    }
    assert!(
        detail.contains("project fewer or smaller fields into the event"),
        "{detail}"
    );
}

#[test]
fn delivery_counters_follow_the_shared_receiver_grammar() {
    let value = event();
    for (counter, accepted) in [
        ("1", true),
        ("4294967296", true),
        ("9223372036854775807", true),
        ("01", false),
        ("0", false),
        ("9223372036854775808", false),
    ] {
        for name in ["x-registry-event-generation", "x-registry-delivery-attempt"] {
            let (body, mut headers) = signed(&value, TARGET, 1, "delivery");
            headers.insert(name, HeaderValue::from_static(counter));
            sign_headers(&mut headers, &body, TARGET);
            assert_eq!(
                verify(&body, &headers).is_ok(),
                accepted,
                "{name}={counter}"
            );
        }
    }
}

fn project_text() -> &'static str {
    r#"
apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project: {id: record-follow-up, version: v1}
types:
  event:
    type: object
    required: [data]
    properties:
      data:
        type: object
        required: [recordId]
        properties:
          recordId: {type: string, format: uuid}
workflow:
  input:
    type: object
    additionalProperties: false
    required: [recordId]
    properties:
      recordId: {type: string, format: uuid}
  eventTriggers:
    record-saved:
      source: registry
      eventType: contact-created-v1
      dataSchema: urn:example:contact-created:v1
      event: {typeRef: event}
      input:
        type: fields
        fields:
          recordId: {type: input, path: /data/recordId}
  deadlineSeconds: 3600
  start: complete
  steps:
    complete:
      type: finish
      outcome: handled
      output: {type: input}
  outcomes:
    handled:
      type: object
      additionalProperties: false
      required: [recordId]
      properties:
        recordId: {type: string, format: uuid}
"#
}
fn definition(text: &str) -> Definition {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("workflow.yaml"), text).unwrap();
    Definition::load(project.path()).unwrap()
}

#[test]
fn authored_event_mapping_is_typed_and_part_of_the_workflow_revision() {
    let first = definition(project_text());
    let trigger = &first.workflow.event_triggers["record-saved"];
    let input = trigger.map(&first, &event()).unwrap();
    assert_eq!(
        input,
        json!({"recordId":"00000000-0000-4000-8000-000000000001"})
    );
    let changed = definition(&project_text().replace("contact-created-v1", "contact-patched-v1"));
    assert_ne!(first.digest, changed.digest);
    let mut invalid = event();
    invalid["data"]["recordId"] = json!("not-a-uuid");
    assert!(trigger.map(&first, &invalid).is_err());
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("workflow.yaml"),
        project_text().replace("path: /data/recordId", "path: /data/missing"),
    )
    .unwrap();
    assert!(
        Definition::load(project.path()).is_err(),
        "the existing typed mapping validator checks event paths"
    );
}

#[test]
fn owner_generated_breg_event_schema_is_validated_without_changing_source_or_revision() {
    let owner_schema: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/product-events/breg-application-created-v1.schema.json"
    ))
    .unwrap();
    let original = canonicalize_json(&owner_schema).unwrap();
    let mut authored = registry_platform_yaml::Reader::new("workflow.yaml")
        .scan(project_text().as_bytes())
        .unwrap()
        .unwrap()
        .to_json_value();
    authored["workflow"]["eventTriggers"]["record-saved"]["event"] = json!({
        "type":"object","required":["data"],"properties":{"data":owner_schema}
    });
    let loaded = definition(&authored.to_string());
    let trigger = &loaded.workflow.event_triggers["record-saved"];
    assert_eq!(
        canonicalize_json(&trigger.event["properties"]["data"]).unwrap(),
        original,
        "the governed snapshot retains the exact imported schema shape"
    );
    let mut value = event();
    value["data"]["recordType"] = json!("application");
    value["data"]["values"] = json!({"tenant":"tenant-a"});
    trigger.map(&loaded, &value).unwrap();
    for revision in [
        json!(0),
        json!(1.5),
        json!("1"),
        json!(9_007_199_254_740_992u64),
    ] {
        value["data"]["revision"] = revision;
        assert!(
            trigger.map(&loaded, &value).is_err(),
            "invalid or unsafe producer revisions cannot enter a Run"
        );
    }
    authored["workflow"]["eventTriggers"]["record-saved"]["event"]["properties"]["data"]
        ["properties"]["revision"]["format"] = json!("int32");
    assert_ne!(
        loaded.digest,
        definition(&authored.to_string()).digest,
        "the original numeric annotation stays covered by the Workflow revision"
    );
}

#[cfg(feature = "schema")]
#[test]
fn optional_event_maps_match_parser_and_generated_schema_bounds() {
    fn value(text: &str) -> Value {
        registry_platform_yaml::Reader::new("fixture.yaml")
            .scan(text.as_bytes())
            .unwrap()
            .unwrap()
            .to_json_value()
    }
    fn validator(schema: &Value) -> jsonschema::JSONSchema {
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(schema)
            .unwrap()
    }
    let mut runtime = value(include_str!(
        "../../../products/coordinator/examples/delayed-follow-up/runtime.yaml"
    ));
    runtime["eventSources"] = json!({});
    let schema: Value = serde_json::from_str(&crate::runtime::runtime_schema().unwrap()).unwrap();
    assert!(
        validator(&schema).is_valid(&runtime),
        "an explicit empty optional source map means no sources"
    );
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("runtime.yaml");
    std::fs::write(&path, runtime.to_string()).unwrap();
    assert!(crate::runtime::RuntimeConfig::load(&path)
        .unwrap()
        .event_sources
        .is_empty());

    let schema: Value = serde_json::from_str(&crate::authoring::project_schema().unwrap()).unwrap();
    let validator = validator(&schema);
    let mut project = value(project_text());
    let trigger = project["workflow"]["eventTriggers"]["record-saved"].clone();
    let triggers = project["workflow"]["eventTriggers"]
        .as_object_mut()
        .unwrap();
    triggers.clear();
    for index in 0..16 {
        triggers.insert(format!("record-saved-{index}"), trigger.clone());
    }
    assert!(validator.is_valid(&project));
    definition(&project.to_string());
    project["workflow"]["eventTriggers"]
        .as_object_mut()
        .unwrap()
        .insert("record-saved-16".into(), trigger);
    assert!(
        !validator.is_valid(&project),
        "the schema rejects a seventeenth trigger"
    );
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("workflow.yaml"), project.to_string()).unwrap();
    assert!(
        Definition::load(root.path()).is_err(),
        "the parser/compiler enforces the same trigger bound"
    );
}

#[test]
fn a_function_used_only_by_an_event_trigger_is_hash_covered() {
    let project = tempfile::tempdir().unwrap();
    let workflow = project_text()
        .replace(
            "workflow:\n  input:",
            r#"functions:
  event-input:
    runtime: rhai
    source: functions.rhai
    entrypoint: event_input
    inputs: {event: {typeRef: event}}
    output:
      type: object
      additionalProperties: false
      required: [recordId]
      properties:
        recordId: {type: string, format: uuid}
workflow:
  input:"#,
        )
        .replace(
            r#"      input:
        type: fields
        fields:
          recordId: {type: input, path: /data/recordId}"#,
            r#"      input:
        type: function
        function: event-input
        inputs:
          event: {type: input}"#,
        );
    std::fs::write(project.path().join("workflow.yaml"), workflow).unwrap();
    std::fs::write(
        project.path().join("functions.rhai"),
        "fn event_input(args) { #{recordId: args.event.data.recordId} }",
    )
    .unwrap();
    let first = Definition::load(project.path()).unwrap();
    assert!(first.workflow.event_triggers["record-saved"]
        .map(&first, &event())
        .is_ok());
    std::fs::write(
        project.path().join("functions.rhai"),
        "fn event_input(args) { let value = args.event.data.recordId; #{recordId: value} }",
    )
    .unwrap();
    let second = Definition::load(project.path()).unwrap();
    assert_ne!(first.digest, second.digest);
}

#[cfg(feature = "postgres-test")]
mod postgres {
    use super::*;
    use crate::{runtime::RuntimeConfig, store::Store};

    fn runtime(namespace: &str) -> RuntimeConfig {
        serde_json::from_value(json!({
            "secretProviders":{"environment":{},"file":{"root":"/private/tmp"}},
            "database":{"runtimeUrlRef":"secret:env/COORDINATOR_TEST_DATABASE_URL","migrationUrlRef":"secret:env/COORDINATOR_TEST_DATABASE_URL"},
            "namespace":namespace,
            "eventSources":{"registry":{"source":BREG_SOURCE,"signingKeyRef":"secret:file/event-key"}},
            "connections":{"source":{"type":"breg","baseUrl":"http://127.0.0.1:9999","profile":"synthetic-reader",
                "authorization":{"tokenEndpoint":"http://127.0.0.1:9998/token","clientId":"synthetic-client",
                    "signingKeyRef":"secret:file/client-key","resource":"urn:example:registry","scopes":["records:read"]}}}
        })).unwrap()
    }
    async fn admit(
        store: &Store,
        definition: &Definition,
        runtime: &RuntimeConfig,
        event: VerifiedEvent,
    ) -> Result<Uuid> {
        let trigger = &definition.workflow.event_triggers["record-saved"];
        let binding = runtime.binding_digest_for(&definition.workflow)?;
        store
            .admit_event_owned(
                definition,
                event.value,
                trigger,
                &event.actor,
                &event.key,
                &binding,
                runtime,
                &event.digest,
            )
            .await
    }

    struct NoEffects {
        runtime: RuntimeConfig,
        digest: String,
    }
    #[async_trait::async_trait]
    impl crate::protocol::AdapterSet for NoEffects {
        fn binding_digest(&self) -> &str {
            &self.digest
        }
        fn binding_digest_for(&self, workflow: &crate::definition::Workflow) -> String {
            self.runtime.binding_digest_for(workflow).unwrap()
        }
        async fn call(&self, _: &crate::protocol::CallRequest) -> crate::protocol::CallOutcome {
            panic!("the synthetic queued Run only finishes locally")
        }
    }

    #[tokio::test]
    async fn removing_event_ingress_preserves_historical_run_inspection_and_dispatch() {
        let database = std::env::var("COORDINATOR_TEST_DATABASE_URL")
            .expect("a disposable real PostgreSQL database is required");
        let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
        let store = Store::connect(&database, &namespace).await.unwrap();
        store.migrate().await.unwrap();
        let mut runtime = runtime(&namespace);
        let historical = definition(project_text());
        runtime.validate_workflow(&historical.workflow).unwrap();
        let original_binding = runtime.binding_digest_for(&historical.workflow).unwrap();
        let value = event();
        let (body, headers) = signed(&value, TARGET, 1, "before-ingress-revocation");
        let verified = verify(&body, &headers).unwrap();
        let actor = verified.actor.clone();
        let run = admit(&store, &historical, &runtime, verified)
            .await
            .unwrap();
        drop(store);

        runtime.event_sources.clear();
        assert!(
            runtime.validate_workflow(&historical.workflow).is_err(),
            "an active trigger still requires its declared source"
        );
        let mut active = historical.workflow.clone();
        active.event_triggers.clear();
        runtime.validate_workflow(&active).unwrap();
        assert_eq!(
            runtime.binding_digest_for(&historical.workflow).unwrap(),
            original_binding,
            "source removal does not alter the original effect binding identity"
        );
        let reopened = std::sync::Arc::new(Store::connect(&database, &namespace).await.unwrap());
        reopened.check_runtime_bindings(&runtime).await.unwrap();
        reopened
            .inspect_runtime_owned(run, &runtime, &actor)
            .await
            .unwrap();
        let adapters = std::sync::Arc::new(NoEffects {
            digest: runtime.binding_digest().unwrap(),
            runtime,
        });
        let worker = crate::worker::Worker::new(reopened.clone(), adapters);
        assert!(worker.tick().await.unwrap());
        assert_eq!(
            reopened.status(run).await.unwrap().state,
            "finished",
            "the original pinned Run drains after its ingress has been removed"
        );
        let (client, connection) = tokio_postgres::connect(&database, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        client
            .batch_execute(&format!("DROP SCHEMA {namespace} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn source_alias_rename_recovers_one_original_run_after_restart() {
        let database = std::env::var("COORDINATOR_TEST_DATABASE_URL")
            .expect("a disposable real PostgreSQL database is required");
        let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
        let store = Store::connect(&database, &namespace).await.unwrap();
        store.migrate().await.unwrap();
        let mut runtime = runtime(&namespace);
        let original = definition(project_text());
        runtime.validate_workflow(&original.workflow).unwrap();
        let value = event();
        let (body, headers) = signed(&value, TARGET, 1, "before-alias-rename");
        let run = admit(
            &store,
            &original,
            &runtime,
            verify(&body, &headers).unwrap(),
        )
        .await
        .unwrap();
        drop(store);

        let source = runtime.event_sources.remove("registry").unwrap();
        runtime
            .event_sources
            .insert("renamed-registry".into(), source);
        let renamed = definition(
            &project_text()
                .replace("source: registry", "source: renamed-registry")
                .replace(
                    "{type: input, path: /data/recordId}",
                    "{type: literal, value: '00000000-0000-4000-8000-000000000099'}",
                ),
        );
        runtime.validate_workflow(&renamed.workflow).unwrap();
        assert_ne!(original.digest, renamed.digest);
        let store = Store::connect(&database, &namespace).await.unwrap();
        store.check_runtime_bindings(&runtime).await.unwrap();
        let (body, headers) = signed(&value, TARGET, 2, "after-alias-rename");
        let trigger = &renamed.workflow.event_triggers["record-saved"];
        let verify_renamed = || {
            verify_delivery(
                &runtime.event_sources[&trigger.source],
                &trigger.source,
                trigger,
                "record-saved",
                &Method::POST,
                TARGET,
                &headers,
                &body,
                KEY,
                SystemTime::now(),
            )
            .unwrap()
        };
        let (replay, retry) = tokio::join!(
            admit(&store, &renamed, &runtime, verify_renamed()),
            admit(&store, &renamed, &runtime, verify_renamed()),
        );
        assert_eq!(
            run,
            replay.unwrap(),
            "renaming a local source alias recovers the original Run"
        );
        assert_eq!(
            run,
            retry.unwrap(),
            "concurrent exact retries cannot admit more work"
        );
        assert_eq!(store.list_runs(100).await.unwrap().len(), 1);
        let actor = verify_renamed().actor;
        assert_eq!(
            store.definition_owned(run, &actor).await.unwrap().digest,
            original.digest
        );
        let mut conflict = value.clone();
        conflict["data"]["values"]["name"] = json!("Changed ignored projection");
        let (conflict_body, conflict_headers) = signed(&conflict, TARGET, 3, "renamed-conflict");
        let conflict = verify_delivery(
            &runtime.event_sources[&trigger.source],
            &trigger.source,
            trigger,
            "record-saved",
            &Method::POST,
            TARGET,
            &conflict_headers,
            &conflict_body,
            KEY,
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(
            admit(&store, &renamed, &runtime, conflict)
                .await
                .unwrap_err()
                .code,
            "start-conflict"
        );

        let mut other = value.clone();
        other["source"] = json!("urn:example:another-authenticated-producer");
        let mut other_source = runtime.event_sources[&trigger.source].clone();
        other_source.source = ExternalId::new(other["source"].as_str().unwrap()).unwrap();
        let (other_body, other_headers) = signed(&other, TARGET, 1, "other-producer");
        let other = verify_delivery(
            &other_source,
            &trigger.source,
            trigger,
            "record-saved",
            &Method::POST,
            TARGET,
            &other_headers,
            &other_body,
            KEY,
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(
            store
                .status_owned(run, &other.actor)
                .await
                .unwrap_err()
                .code,
            "run-absent",
            "another authenticated URI cannot inspect the original producer's Run"
        );

        let (client, connection) = tokio_postgres::connect(&database, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        let counts = client.query_one(&format!("SELECT (SELECT count(*) FROM {namespace}.runs),(SELECT count(*) FROM {namespace}.jobs)"), &[]).await.unwrap();
        assert_eq!(counts.get::<_, i64>(0), 1);
        assert_eq!(
            counts.get::<_, i64>(1),
            1,
            "alias replay creates no second dispatch job"
        );
        let replay = verify_renamed();
        let store = std::sync::Arc::new(store);
        let adapters = std::sync::Arc::new(NoEffects {
            digest: runtime.binding_digest().unwrap(),
            runtime: runtime.clone(),
        });
        let worker = crate::worker::Worker::new(store.clone(), adapters);
        assert!(worker.tick().await.unwrap());
        let status = store.status_owned(run, &actor).await.unwrap();
        assert_eq!(status.state, "finished");
        assert_eq!(
            status.output,
            Some(json!({"recordId":"00000000-0000-4000-8000-000000000001"})),
            "renamed ingress preserves the original mapped input despite active mapping changes"
        );
        assert_eq!(
            admit(&store, &renamed, &runtime, replay).await.unwrap(),
            run
        );
        assert_eq!(store.list_runs(100).await.unwrap().len(), 1);
        client
            .batch_execute(&format!("DROP SCHEMA {namespace} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn event_admission_is_atomic_deduplicated_and_recovers_after_restart_and_activation() {
        let database = std::env::var("COORDINATOR_TEST_DATABASE_URL")
            .expect("a disposable real PostgreSQL database is required");
        let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
        let store = Store::connect(&database, &namespace).await.unwrap();
        store.migrate().await.unwrap();
        let runtime = runtime(&namespace);
        let first = definition(project_text());
        let value = event();
        let (body, headers) = signed(&value, TARGET, 1, "first-delivery");
        let (run, duplicate) = tokio::join!(
            admit(&store, &first, &runtime, verify(&body, &headers).unwrap()),
            admit(&store, &first, &runtime, verify(&body, &headers).unwrap())
        );
        let run = run.unwrap();
        assert_eq!(
            run,
            duplicate.unwrap(),
            "concurrent deliveries atomically admit one Run"
        );
        assert_eq!(store.list_runs(100).await.unwrap().len(), 1);
        drop(store);
        let reopened = Store::connect(&database, &namespace).await.unwrap();
        let (body, headers) = signed(&value, TARGET, 2, "operator-replay-after-restart");
        let replay = admit(
            &reopened,
            &first,
            &runtime,
            verify(&body, &headers).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(run, replay);
        let changed_definition = definition(&project_text().replace(
            "{type: input, path: /data/recordId}",
            "{type: literal, value: '00000000-0000-4000-8000-000000000099'}",
        ));
        assert_ne!(first.digest, changed_definition.digest);
        let replay = admit(
            &reopened,
            &changed_definition,
            &runtime,
            verify(&body, &headers).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            run, replay,
            "exact historical event returns its original pinned Run across mapping activation"
        );
        let mut conflict = value.clone();
        conflict["data"]["values"]["name"] = json!("Changed ignored projection");
        let (body, headers) = signed(&conflict, TARGET, 2, "conflicting-generation");
        let refused = admit(
            &reopened,
            &first,
            &runtime,
            verify(&body, &headers).unwrap(),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.code, "start-conflict");
        let mut invalid = event();
        invalid["data"]["recordId"] = json!("synthetic-invalid-input");
        let (body, headers) = signed(&invalid, TARGET, 1, "invalid-new-event");
        assert!(admit(
            &reopened,
            &first,
            &runtime,
            verify(&body, &headers).unwrap()
        )
        .await
        .is_err());
        assert_eq!(
            reopened.list_runs(100).await.unwrap().len(),
            1,
            "refusals create no Run or dispatch job"
        );
        let (client, connection) = tokio_postgres::connect(&database, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        let counts = client.query_one(&format!("SELECT (SELECT count(*) FROM {namespace}.runs),(SELECT count(*) FROM {namespace}.jobs)"),&[]).await.unwrap();
        assert_eq!(counts.get::<_, i64>(0), 1);
        assert_eq!(
            counts.get::<_, i64>(1),
            1,
            "Run and initial job commit once together"
        );
        client.batch_execute(&format!("CREATE FUNCTION {namespace}.reject_event_job() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic job insertion failure'; END $$; CREATE TRIGGER reject_event_job BEFORE INSERT ON {namespace}.jobs FOR EACH ROW EXECUTE FUNCTION {namespace}.reject_event_job();")).await.unwrap();
        let later = event();
        let (body, headers) = signed(&later, TARGET, 1, "rolled-back-new-event");
        assert!(admit(
            &reopened,
            &first,
            &runtime,
            verify(&body, &headers).unwrap()
        )
        .await
        .is_err());
        let count = client
            .query_one(&format!("SELECT count(*) FROM {namespace}.runs"), &[])
            .await
            .unwrap()
            .get::<_, i64>(0);
        assert_eq!(
            count, 1,
            "failed job insertion rolls back Run admission in real PostgreSQL"
        );
        client.batch_execute(&format!("DROP TRIGGER reject_event_job ON {namespace}.jobs; DROP FUNCTION {namespace}.reject_event_job();")).await.unwrap();
        let fresh = admit(
            &reopened,
            &first,
            &runtime,
            verify(&body, &headers).unwrap(),
        )
        .await
        .unwrap();
        assert_ne!(fresh, run, "the rolled-back event identity was not spent");
        let verified = verify(&body, &headers).unwrap();
        reopened
            .cancel_owned(fresh, &verified.actor, "synthetic-event-cancel")
            .await
            .unwrap();
        assert_eq!(
            admit(&reopened, &first, &runtime, verified).await.unwrap(),
            fresh,
            "replay cannot undo cancellation or admit new work"
        );
        client
            .batch_execute(&format!("DROP SCHEMA {namespace} CASCADE"))
            .await
            .unwrap();
    }
}

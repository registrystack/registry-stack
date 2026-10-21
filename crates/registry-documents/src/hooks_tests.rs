// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::config::DestinationsConfig;
use registry_documents_core::DOCUMENT_VERSION_EVENT_FIELDS;
use registry_platform_config::SecretProvider;

const DOCUMENT: &str = "0d6f2a5e-7c1b-4b8e-9f3a-2c4d5e6f7a81";
const VERSION: &str = "1e7a3b6f-8d2c-4c9f-8a4b-3d5e6f7a8b92";
const GRANT: &str = "2f8b4c7a-9e3d-4dab-9b5c-4e6f7a8b9ca3";
const EXPIRES_AT: &str = "2026-10-29T08:30:00.000Z";
const DIGEST: &str = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

/// Lowercase kebab-case, the spelling of every value a machine matches.
fn is_kebab_case(word: &str) -> bool {
    !word.is_empty()
        && word.split('-').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        })
        && word.starts_with(|character: char| character.is_ascii_lowercase())
}

fn observer(trigger: HookTrigger) -> HookDeclaration {
    HookDeclaration {
        id: "custodian".to_owned(),
        phase: HookPhase::After,
        trigger: trigger.as_str().to_owned(),
        when: None,
        principal: None,
        projection: trigger
            .fields()
            .iter()
            .map(|field| (*field).to_owned())
            .collect(),
        handler: HookHandlerSource::Url {
            destination_id: "owning-system-events".to_owned(),
        },
    }
}

/// `declarations`, each scoped to the one policy the test events name.
fn scoped(declarations: impl IntoIterator<Item = HookDeclaration>) -> Vec<ScopedHook> {
    declarations
        .into_iter()
        .map(|declaration| ScopedHook {
            declaration,
            policies: vec!["civil-record".to_owned()],
        })
        .collect()
}

fn version_event(trigger: HookTrigger) -> DocumentEvent {
    DocumentEvent {
        trigger,
        document_id: DOCUMENT.parse().unwrap(),
        version_id: VERSION.parse().unwrap(),
        version_digest: DIGEST.to_owned(),
        policy_id: "civil-record".to_owned(),
        policy_version: "2026-10".to_owned(),
        revision: 3,
        grant: None,
    }
}

fn grant_event(change: GrantChange) -> DocumentEvent {
    DocumentEvent {
        trigger: HookTrigger::DocumentGrantChanged,
        revision: match change {
            GrantChange::Issued => 1,
            GrantChange::Revoked => 2,
        },
        grant: Some(GrantFacts {
            grant_id: GRANT.parse().unwrap(),
            change,
            actor_kind: ActorKind::Human,
            expires_at: EXPIRES_AT.parse().unwrap(),
        }),
        ..version_event(HookTrigger::DocumentVersionReady)
    }
}

fn full_projection(trigger: HookTrigger) -> Vec<String> {
    trigger
        .fields()
        .iter()
        .map(|field| (*field).to_owned())
        .collect()
}

fn assert_capability_refused(mut declaration: HookDeclaration, capability: HookCapability) {
    declaration.id = "refused".to_owned();
    let error = CompiledHooks::compile(&scoped([
        observer(HookTrigger::DocumentVersionReady),
        declaration,
    ]))
    .expect_err("a declaration outside the url-only capabilities is refused");
    assert_eq!(
        error,
        HookActivationError::UnsupportedCapability {
            index: 1,
            capability,
        }
    );
    assert_eq!(error.code(), Some("hook.capability.unsupported"));
    assert!(
        error
            .to_string()
            .starts_with("hook.capability.unsupported: "),
        "{error}"
    );
}

#[test]
fn compile_accepts_a_url_observer_on_every_trigger() {
    let declarations = HookTrigger::ALL
        .iter()
        .enumerate()
        .map(|(index, trigger)| HookDeclaration {
            id: format!("observer-{index}"),
            ..observer(*trigger)
        })
        .collect::<Vec<_>>();
    let compiled = CompiledHooks::compile(&scoped(declarations)).expect("url observers compile");
    assert!(!compiled.is_empty());
    assert!(compiled.schema_fingerprint().starts_with("sha256:"));
}

#[test]
fn compile_refuses_a_hook_scoped_to_no_policy_or_to_one_twice() {
    for policies in [
        vec![],
        vec!["civil-record".to_owned(), "civil-record".to_owned()],
        vec!["Civil Record".to_owned()],
    ] {
        let hook = ScopedHook {
            declaration: observer(HookTrigger::DocumentVersionReady),
            policies: policies.clone(),
        };
        assert_eq!(
            CompiledHooks::compile(&[hook]).err(),
            Some(HookActivationError::UnsupportedContract),
            "{policies:?}"
        );
    }
}

#[test]
fn the_compiled_fingerprint_covers_the_policy_scope_but_not_its_order() {
    let fingerprint = |policies: &[&str]| {
        CompiledHooks::compile(&[ScopedHook {
            declaration: observer(HookTrigger::DocumentVersionReady),
            policies: policies.iter().map(|policy| (*policy).to_owned()).collect(),
        }])
        .unwrap()
        .schema_fingerprint()
        .to_owned()
    };
    assert_ne!(
        fingerprint(&["civil-record"]),
        fingerprint(&["named-share"])
    );
    assert_eq!(
        fingerprint(&["civil-record", "named-share"]),
        fingerprint(&["named-share", "civil-record"])
    );
}

#[test]
fn compile_refuses_a_condition() {
    let mut declaration = observer(HookTrigger::DocumentVersionReady);
    declaration.when = Some(json!(true));
    assert_capability_refused(declaration, HookCapability::When);
}

#[test]
fn compile_refuses_a_principal() {
    let mut declaration = observer(HookTrigger::DocumentVersionReady);
    declaration.principal = Some("operator".to_owned());
    assert_capability_refused(declaration, HookCapability::Principal);
}

#[test]
fn compile_refuses_a_rhai_handler() {
    let mut declaration = observer(HookTrigger::DocumentVersionReady);
    declaration.handler = HookHandlerSource::Rhai {
        script: "hooks/observe.rhai".to_owned(),
        abi: Some(registry_platform_hooks::HOOK_HANDLER_ABI_V1.to_owned()),
    };
    assert_capability_refused(declaration, HookCapability::RhaiHandler);
}

#[test]
fn compile_refuses_a_wasm_handler() {
    let mut declaration = observer(HookTrigger::DocumentVersionReady);
    declaration.handler = HookHandlerSource::Wasm {
        module: "hooks/observe.wasm".to_owned(),
        abi: Some(registry_platform_hooks::HOOK_HANDLER_ABI_V1.to_owned()),
    };
    assert_capability_refused(declaration, HookCapability::WasmHandler);
}

#[test]
fn compile_refuses_a_phase_other_than_after() {
    let mut declaration = observer(HookTrigger::DocumentVersionReady);
    declaration.phase = HookPhase::Before;
    assert!(CompiledHooks::compile(&scoped([declaration])).is_err());
}

#[test]
fn compile_refuses_an_unknown_trigger_and_a_field_outside_its_trigger() {
    let mut unknown = observer(HookTrigger::DocumentVersionReady);
    unknown.trigger = "document.erased".to_owned();
    assert!(CompiledHooks::compile(&scoped([unknown])).is_err());

    for field in [
        "actorKind",
        "change",
        "expiresAt",
        "grantId",
        "label",
        "mediaType",
        "subject",
        "content",
    ] {
        let mut declaration = observer(HookTrigger::DocumentVersionRejected);
        declaration.projection.insert(field.to_owned());
        assert!(
            CompiledHooks::compile(&scoped([declaration])).is_err(),
            "a version observer may not project {field}"
        );
    }
}

#[test]
fn each_family_projects_exactly_its_closed_fields() {
    for trigger in [
        HookTrigger::DocumentVersionReady,
        HookTrigger::DocumentVersionRejected,
    ] {
        assert_eq!(
            projected(&version_event(trigger), &full_projection(trigger)).unwrap(),
            json!({
                "documentId": DOCUMENT,
                "policyId": "civil-record",
                "policyVersion": "2026-10",
                "versionDigest": DIGEST,
                "versionId": VERSION,
            })
        );
    }
    for (change, spelling) in [
        (GrantChange::Issued, "issued"),
        (GrantChange::Revoked, "revoked"),
    ] {
        assert_eq!(
            projected(
                &grant_event(change),
                &full_projection(HookTrigger::DocumentGrantChanged)
            )
            .unwrap(),
            json!({
                "actorKind": "human",
                "change": spelling,
                "documentId": DOCUMENT,
                "expiresAt": EXPIRES_AT,
                "grantId": GRANT,
                "policyId": "civil-record",
                "policyVersion": "2026-10",
                "versionDigest": DIGEST,
                "versionId": VERSION,
            })
        );
    }
}

#[test]
fn a_projection_carries_only_the_fields_it_names() {
    let data = projected(
        &grant_event(GrantChange::Issued),
        &["change".to_owned(), "grantId".to_owned()],
    )
    .unwrap();
    assert_eq!(data, json!({"change": "issued", "grantId": GRANT}));
}

#[test]
fn no_forbidden_field_can_be_projected() {
    let forbidden = [
        "bytes",
        "content",
        "label",
        "labels",
        "mediaType",
        "filename",
        "name",
        "subject",
        "describedParty",
        "recipient",
        "grantee",
        "grantedBy",
    ];
    for field in forbidden {
        assert!(!DOCUMENT_GRANT_EVENT_FIELDS.contains(&field), "{field}");
        for event in [
            version_event(HookTrigger::DocumentVersionReady),
            grant_event(GrantChange::Revoked),
        ] {
            assert_eq!(
                projected(&event, &[field.to_owned()]),
                Err(HookCaptureError::InvalidCapture),
                "{field} must not be projectable"
            );
        }
    }
    // A version event refuses the grant fields it has no value for, the
    // kind of the caller that made the grant included.
    for field in ["actorKind", "change", "expiresAt", "grantId"] {
        assert_eq!(
            projected(
                &version_event(HookTrigger::DocumentVersionReady),
                &[field.to_owned()]
            ),
            Err(HookCaptureError::InvalidCapture)
        );
    }
    // Every published field is one of the closed facts, and the version
    // families' fields are the grant family's without the grant.
    for field in DOCUMENT_VERSION_EVENT_FIELDS {
        assert!(DOCUMENT_GRANT_EVENT_FIELDS.contains(field));
    }
}

#[test]
fn every_projection_conforms_to_its_published_data_schema() {
    let cases = [
        version_event(HookTrigger::DocumentVersionReady),
        version_event(HookTrigger::DocumentVersionRejected),
        grant_event(GrantChange::Issued),
        grant_event(GrantChange::Revoked),
    ];
    for event in cases {
        let schema = event_data_schema(event.trigger);
        assert_eq!(schema["$id"], json!(event.trigger.data_schema_id()));
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .expect("the data schema compiles");
        let data = projected(&event, &full_projection(event.trigger)).unwrap();
        assert!(validator.is_valid(&data), "{data}");
        let mut widened = data.as_object().unwrap().clone();
        widened.insert("label".to_owned(), json!("passport"));
        assert!(
            !validator.is_valid(&Value::Object(widened)),
            "the data schema is closed"
        );
        let published = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let fields = event
            .trigger
            .fields()
            .iter()
            .map(|field| (*field).to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(published, fields);
    }
}

#[test]
fn event_subjects_name_the_record_and_its_revision() {
    let version = version_event(HookTrigger::DocumentVersionReady)
        .subject()
        .unwrap();
    assert_eq!(
        version.record_reference,
        format!("/documents/{DOCUMENT}/versions/{VERSION}")
    );
    assert_eq!(version.record_revision, 3, "the revision the change left");
    let issued = grant_event(GrantChange::Issued).subject().unwrap();
    assert_eq!(issued.record_reference, format!("/document-grants/{GRANT}"));
    assert_eq!(issued.record_revision, 1);
    assert_eq!(
        grant_event(GrantChange::Revoked)
            .subject()
            .unwrap()
            .record_revision,
        2
    );
    let mut mismatched = version_event(HookTrigger::DocumentGrantChanged);
    mismatched.grant = None;
    assert_eq!(mismatched.subject(), Err(HookCaptureError::InvalidCapture));
}

#[test]
fn an_observer_proposal_is_refused_with_a_kebab_case_code() {
    let ProposalOutcome::Refused { code, summary } = proposal_refusal() else {
        panic!("a proposal is always refused");
    };
    assert_eq!(code.as_str(), PROPOSAL_UNSUPPORTED_CODE);
    assert!(code.as_str().split('.').all(is_kebab_case), "{code:?}");
    assert!(!summary.as_str().is_empty());
}

#[test]
fn retries_back_off_from_thirty_seconds_to_an_hour() {
    let mut expected = vec![
        30_000, 60_000, 120_000, 240_000, 480_000, 960_000, 1_920_000,
    ];
    expected.resize(usize::from(MAX_HOOK_ATTEMPTS) - 1, 3_600_000);
    assert_eq!(retry_delays_ms(), expected);
}

fn file_secrets() -> (tempfile::TempDir, SecretResolver) {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("the test secret directory");
    let key_path = directory.path().join("hook-key");
    std::fs::write(&key_path, [0x5a; 32]).expect("write the test hook key");
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict the test hook key");
    let secrets = SecretResolver::new([SecretProvider::File], directory.path())
        .expect("the test secret resolver");
    (directory, secrets)
}

fn configured(value: Value) -> BTreeMap<String, UrlHookDestinationConfig> {
    serde_json::from_value::<DestinationsConfig>(json!({ "hooks": value }))
        .expect("the test hook destinations read")
        .hooks
}

fn identity() -> HookRuntimeIdentity {
    HookRuntimeIdentity {
        project_id: "district-registry".to_owned(),
        package_digest: DIGEST.to_owned(),
        database_id: "documents-test".to_owned(),
    }
}

/// The binding digests a deployed Document Store records with every
/// captured delivery. A retained delivery is refused once its recorded
/// digest no longer matches the activated destination, so these values are
/// pinned: a change to the digest shape is a breaking change.
#[test]
fn hook_destination_binding_digests_are_pinned() {
    let (_directory, secrets) = file_secrets();
    let configured = configured(json!({
        "owning-system-events": {
            "url": "https://events.example.test/documents",
            "hmacSha256KeyRef": "secret:file/hook-key",
        },
        "audit-mirror": {
            "url": "http://127.0.0.1:8080/hooks",
            "hmacSha256KeyRef": "secret:file/hook-key",
            "attemptTimeoutMilliseconds": 250,
            "maximumAttempts": 3,
        },
    }));
    let expected = ["owning-system-events".to_owned()].into_iter().collect();

    let activated = activate_destinations(&expected, &configured, &secrets)
        .expect("the pinned hook destinations activate");

    assert_eq!(
        activated.binding_digest,
        "sha256:dc81f68b54c313d5cc310258dbefd0743b5e35e7e53f65ad2a0b89dc93f5b40f"
    );
    assert_eq!(
        activated.bindings["owning-system-events"].binding_digest(),
        "sha256:cd4da816b206e19dfa0a04a81c09b9fee12cac3edd1efaaffdecfa55c8e76a58"
    );
    assert_eq!(
        activated.bindings["audit-mirror"].binding_digest(),
        "sha256:545d6c1a305c7a38085da5520df5e1ba8db18c0eb5a2b234a919eeae8055550e"
    );
}

#[test]
fn activation_refuses_a_hook_whose_destination_is_not_bound() {
    let (_directory, secrets) = file_secrets();
    let error = ActivatedHooks::activate(
        &scoped([observer(HookTrigger::DocumentVersionReady)]),
        &configured(json!({
            "other-events": {
                "url": "https://events.example.test/documents",
                "hmacSha256KeyRef": "secret:file/hook-key",
            },
        })),
        &secrets,
        identity(),
        "public".to_owned(),
        Duration::from_secs(7 * 24 * 60 * 60),
    )
    .expect_err("an unbound destination is refused");
    assert_eq!(error, HookActivationError::DestinationInventoryMismatch);
}

#[test]
fn activation_refuses_a_signing_secret_it_cannot_resolve() {
    let secrets =
        SecretResolver::new([SecretProvider::Environment], "/").expect("the test secret resolver");
    let error = ActivatedHooks::activate(
        &scoped([observer(HookTrigger::DocumentVersionReady)]),
        &configured(json!({
            "owning-system-events": {
                "url": "https://events.example.test/documents",
                "hmacSha256KeyRef": "secret:file/hook-key",
            },
        })),
        &secrets,
        identity(),
        "public".to_owned(),
        Duration::from_secs(7 * 24 * 60 * 60),
    )
    .expect_err("an unresolvable signing secret is refused");
    assert_eq!(error, HookActivationError::InvalidSigningMaterial);
}

#[test]
fn activation_refuses_an_invalid_identity_or_retention() {
    let (_directory, secrets) = file_secrets();
    let destinations = configured(json!({
        "owning-system-events": {
            "url": "https://events.example.test/documents",
            "hmacSha256KeyRef": "secret:file/hook-key",
        },
    }));
    let day = Duration::from_secs(24 * 60 * 60);
    let activate = |identity: HookRuntimeIdentity, schema: &str, retention: Duration| {
        ActivatedHooks::activate(
            &scoped([observer(HookTrigger::DocumentVersionReady)]),
            &destinations,
            &secrets,
            identity,
            schema.to_owned(),
            retention,
        )
        .map(drop)
    };
    activate(identity(), "public", 7 * day).expect("a valid identity activates");
    let bad_project = HookRuntimeIdentity {
        project_id: "District Registry".to_owned(),
        ..identity()
    };
    let bad_digest = HookRuntimeIdentity {
        package_digest: "sha256:ABC".to_owned(),
        ..identity()
    };
    let bad_database = HookRuntimeIdentity {
        database_id: String::new(),
        ..identity()
    };
    for (identity, schema, retention) in [
        (bad_project, "public", 7 * day),
        (bad_digest, "public", 7 * day),
        (bad_database, "public", 7 * day),
        (identity(), "Public", 7 * day),
        (identity(), "public", day / 2),
        (identity(), "public", 31 * day),
    ] {
        assert_eq!(
            activate(identity, schema, retention),
            Err(HookActivationError::InvalidIdentity)
        );
    }
}

#[test]
fn the_event_source_names_the_project() {
    let (_directory, secrets) = file_secrets();
    let activated = ActivatedHooks::activate(
        &scoped([observer(HookTrigger::DocumentGrantChanged)]),
        &configured(json!({
            "owning-system-events": {
                "url": "https://events.example.test/documents",
                "hmacSha256KeyRef": "secret:file/hook-key",
            },
        })),
        &secrets,
        identity(),
        "public".to_owned(),
        Duration::from_secs(7 * 24 * 60 * 60),
    )
    .expect("the hooks activate");
    assert_eq!(
        activated.delivery_source,
        "urn:registrystack:documents:district-registry"
    );
}

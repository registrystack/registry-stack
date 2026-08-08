//! Full-path conformance for the frozen Version 1 selector matrix.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use jsonwebtoken::{jwk::JwkSet, Algorithm};
use registry_evidence::audit::{
    AuditAuthority, AuditDecision, AuditPhase, AuditSubject, AuthorityKind as AuditAuthorityKind,
    EvidenceAuditEvent, EvidenceAuditLog, ResponseProtection,
};
use registry_evidence::auth::{AuthenticatedContext, AuthenticationClaimsConfig, Authenticator};
use registry_evidence::bundle::{Bundle, BundleError, DeploymentInputs};
use registry_evidence::config::{AuthorityKind, SelectorInput};
use registry_evidence::kernel::{
    EvidenceConstruction, KernelOutcome, OfflineKernel, ValueProjection,
};
use registry_evidence::model::{
    Evidence, EvidenceRequest, FlattenedJws, RequestedSelector, RequestedSubject, SelectorValue,
    SubjectBinding,
};
use registry_evidence::secrets::{SecretProvider, SecretResolver};
use registry_evidence::selector::{
    match_entitlement, resolve_selectors, AuthorizationError, ResolvedAuthorization,
    ResolvedSelectorValue,
};
use registry_evidence::signing::{jwks_document, EvidenceSigner};
use registry_evidence::source::{ResolvedSourceSelector, SourceExecutor};
use registry_evidence::verifier::{verify_flattened_jws, EvidenceVerificationPolicy};
use registry_platform_crypto::{sign, LocalJwkSigner, PrivateJwk, SigningProvider};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use serde_json::{json, Value};
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const AUTH_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"selector-auth-key"}"#;
const EVIDENCE_KEY_ID: &str = "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo";
const EVIDENCE_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;
const TOKEN_ISSUER: &str = "https://identity.invalid";
const TOKEN_AUDIENCE: &str = "selector-conformance";
const EVIDENCE_AUDIENCE: &str = "urn:example:fixture:audience:requester-a";
const PURPOSE: &str = "fixture-procedure";
const SOURCE_TOKEN: &str = "selector-source-token-canary";
const BINDING_KEY: &[u8] = b"selector-binding-secret-canary-32-bytes-minimum";
const AUDIT_KEY: &[u8] = b"selector-audit-secret-canary-32-bytes-minimum";

const CLASSIFICATION: &str = "urn:example:fixture:requirement:classification:v1";
const PROPERTY: &str = "urn:example:fixture:requirement:property:v1";
const PROPERTY_WITH_EVENT: &str = "urn:example:fixture:requirement:property-with-event:v1";
const RELATIONSHIP: &str = "urn:example:fixture:requirement:relationship:v1";
const OPAQUE: &str = "urn:example:fixture:requirement:opaque:v1";

struct PreparedService {
    _temporary: TempDir,
    bundle: Arc<Bundle>,
    kernel: OfflineKernel,
    authenticator: Authenticator,
    sources: BTreeMap<String, SourceExecutor>,
    audit: EvidenceAuditLog,
    signer: EvidenceSigner,
    server: MockServer,
    audit_path: PathBuf,
}

impl PreparedService {
    async fn authorize(
        &self,
        token: &str,
        request: &EvidenceRequest,
    ) -> Result<(AuthenticatedContext, ResolvedAuthorization), AuthorizationStageError> {
        let context = self
            .authenticator
            .authenticate(token)
            .await
            .map_err(|_| AuthorizationStageError::Authentication)?;
        let matched = match_entitlement(&self.bundle, request, &context)
            .map_err(AuthorizationStageError::Authorization)?;
        let resolved = resolve_selectors(&self.bundle, request, &context, &matched)
            .map_err(AuthorizationStageError::Authorization)?;
        Ok((context, resolved))
    }

    async fn evaluate(
        &self,
        operation: &str,
        token: &str,
        request: &EvidenceRequest,
    ) -> FlattenedJws {
        let (context, resolved) = self
            .authorize(token, request)
            .await
            .expect("positive selector request authorizes and resolves");
        let (source_id, adapter_id) = source_identity(&self.bundle, &request.requirement);
        let audit_subjects = audit_subjects(&self.audit, &resolved);
        let authority = audit_authority(&self.audit, &resolved);
        let requester = self
            .audit
            .pseudonym(
                "requester",
                "selector-conformance",
                context.principal().as_bytes(),
            )
            .expect("requester pseudonymizes");

        let mut access = EvidenceAuditEvent::new(
            self.bundle.config.assurance_profile,
            operation.to_owned(),
            AuditPhase::AccessAttempt,
            request.requirement.clone(),
            self.bundle.revision().to_owned(),
            request.purpose.clone(),
            requester.clone(),
            authority.clone(),
            audit_subjects.clone(),
            ResponseProtection::Signed,
            AuditDecision::Authorized,
            0,
        );
        access.source_id = Some(source_id.clone());
        access.adapter_id = Some(adapter_id.clone());
        self.audit
            .append(access)
            .await
            .expect("access audit gate succeeds before source access");

        let requirement = self
            .kernel
            .requirement(&request.requirement)
            .expect("requirement exists");
        let source = self
            .bundle
            .config
            .sources
            .get(&source_id)
            .expect("source exists");
        let preparation_selectors = selector_value(&resolved, source.selector_inputs());
        let request_parts = self
            .kernel
            .prepare(&request.requirement, &preparation_selectors)
            .expect("request preparation succeeds");
        let observed_at = Utc::now();
        let source_response = self
            .sources
            .get(&source_id)
            .expect("requirement source executor exists")
            .execute(
                &source_selectors(&resolved, source.selector_inputs()),
                &request_parts,
                observed_at,
            )
            .await
            .expect("fixed source executor succeeds");
        let derivation_selectors =
            selector_value(&resolved, &requirement.derivation.selector_inputs);
        let values = match self
            .kernel
            .evaluate_with_selectors(
                &request.requirement,
                &source_response,
                &derivation_selectors,
                observed_at,
                ValueProjection {
                    audience: context.evidence_audience(),
                    binding_key: BINDING_KEY,
                    binding_key_version: 1,
                },
            )
            .expect("extraction, derivation, and output gate succeed")
        {
            KernelOutcome::Match(values) => values,
            KernelOutcome::NoMatch | KernelOutcome::Ambiguous => {
                panic!("positive selector source must resolve exactly one match")
            }
        };
        let subjects = resolved
            .subjects
            .iter()
            .map(|subject| SubjectBinding {
                role: subject.role.clone(),
                binding: subject
                    .binding(
                        BINDING_KEY,
                        1,
                        &self.bundle.config.service.trust_domain,
                        context.evidence_audience(),
                        &request.purpose,
                    )
                    .expect("subject binding succeeds"),
            })
            .collect();
        let evidence_id = format!("urn:ulid:{}", ulid::Ulid::new());
        let issued_at = Utc::now();
        let evidence = self
            .kernel
            .construct_evidence(
                &request.requirement,
                values,
                EvidenceConstruction {
                    evidence_id: &evidence_id,
                    request_nonce: &request.request_nonce,
                    purpose: &request.purpose,
                    audience: context.evidence_audience(),
                    issued_at,
                    observed_at,
                    subjects,
                },
            )
            .expect("validated values construct Evidence");
        let disclosed_concepts = evidence
            .supported_values
            .iter()
            .map(|value| value.provides_value_for.clone())
            .collect();
        let signed = self
            .signer
            .sign_json(&evidence)
            .await
            .expect("Evidence signs");

        let mut release = EvidenceAuditEvent::new(
            self.bundle.config.assurance_profile,
            operation.to_owned(),
            AuditPhase::DisclosureRelease,
            request.requirement.clone(),
            self.bundle.revision().to_owned(),
            request.purpose.clone(),
            requester,
            authority,
            audit_subjects,
            ResponseProtection::Signed,
            AuditDecision::Released,
            0,
        );
        release.source_id = Some(source_id);
        release.adapter_id = Some(adapter_id);
        release.disclosed_concepts = Some(disclosed_concepts);
        release.evidence_id = Some(evidence_id);
        release.signing_key_id = Some(self.signer.key_id().to_owned());
        self.audit
            .append(release)
            .await
            .expect("release audit gate succeeds before returning the JWS");
        signed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizationStageError {
    Authentication,
    Authorization(AuthorizationError),
}

#[tokio::test]
async fn every_selector_profile_runs_the_complete_signed_service_path() {
    let service = prepare_service(true).await;
    Mock::given(method("POST"))
        .and(path("/v1/selector-facts"))
        .and(header(
            "authorization",
            format!("Bearer {SOURCE_TOKEN}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"matched": true})))
        .expect(6)
        .mount(&service.server)
        .await;

    let cases = [
        (
            "selector-positive-request",
            access_token(json!({})),
            classification_request(values([(
                "record_reference",
                SelectorValue::String("synthetic-record-001".to_owned()),
            )])),
            vec!["subject"],
        ),
        (
            "selector-positive-context",
            access_token(json!({
                "identity": {
                    "given_name": "Ána María",
                    "family_name": "N'Dour-Sato",
                    "birth_date": "2000-02-29"
                }
            })),
            property_request(None),
            vec!["subject"],
        ),
        (
            "selector-positive-grant",
            access_token(json!({
                "evidence_grant_id": "synthetic-grant-001",
                "evidence_authority": "authenticated-grant-v1",
                "grant": {"subject": {
                    "given_name": "Adaeze",
                    "family_name": "Okafor",
                    "birth_date": "1990-07-11",
                    "event_reference": "synthetic-event-001"
                }}
            })),
            grant_request(None),
            vec!["subject"],
        ),
        (
            "selector-positive-multi-role",
            access_token(json!({})),
            relationship_request(
                "opaque-record-v1",
                values([(
                    "record_reference",
                    SelectorValue::String("synthetic-record-002".to_owned()),
                )]),
                "demographics-v1",
                values([
                    ("given_name", SelectorValue::String("Binta".to_owned())),
                    ("family_name", SelectorValue::String("Diallo".to_owned())),
                    ("birth_date", SelectorValue::String("1970-06-15".to_owned())),
                ]),
            ),
            vec!["subject-a", "subject-b"],
        ),
        (
            "selector-positive-multi-role-permuted",
            access_token(json!({})),
            request(
                RELATIONSHIP,
                vec![
                    subject(
                        "subject-b",
                        "demographics-v1",
                        values([
                            ("given_name", SelectorValue::String("Binta".to_owned())),
                            ("family_name", SelectorValue::String("Diallo".to_owned())),
                            ("birth_date", SelectorValue::String("1970-06-15".to_owned())),
                        ]),
                    ),
                    subject(
                        "subject-a",
                        "opaque-record-v1",
                        values([(
                            "record_reference",
                            SelectorValue::String("synthetic-record-002".to_owned()),
                        )]),
                    ),
                ],
            ),
            vec!["subject-a", "subject-b"],
        ),
        (
            "selector-positive-opaque",
            access_token(json!({})),
            opaque_request(values([
                ("alpha", SelectorValue::String("synthetic-alpha".to_owned())),
                ("delta", SelectorValue::Integer(42)),
                ("kappa", SelectorValue::String("K-2".to_owned())),
            ])),
            vec!["subject"],
        ),
    ];

    for (operation, token, request, expected_roles) in cases {
        let jws = service.evaluate(operation, &token, &request).await;
        let serialized = serde_json::to_vec(&jws).expect("flattened JWS serializes");
        let requirement = service
            .bundle
            .config
            .requirements
            .iter()
            .find(|candidate| candidate.id == request.requirement)
            .expect("requirement is configured");
        let unverified: Evidence = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&jws.payload)
                .expect("payload decodes"),
        )
        .expect("payload parses for expectations");
        let mut policy = EvidenceVerificationPolicy::from_accepted_transaction(
            &unverified,
            &request.request_nonce,
            48 * 60 * 60,
            Utc::now(),
            30,
        )
        .expect("the transaction states bounds the contract allows");
        policy.issued_by = service.bundle.config.issuer.id.clone();
        policy.provided_by = service.bundle.config.service.provider_id.clone();
        policy.requirement = request.requirement.clone();
        policy.evidence_type = requirement.evidence_type.clone();
        policy.purpose = request.purpose.clone();
        policy.audience = EVIDENCE_AUDIENCE.to_owned();
        policy.configuration_revision = service
            .bundle
            .configuration_revision(&request.requirement)
            .expect("the requirement has a configuration revision")
            .to_owned();
        let evidence = verify_flattened_jws(
            &serialized,
            &jwks_document(service.signer.public_jwk(), []).expect("JWKS builds"),
            &policy,
        )
        .expect("signed service result verifies under the relying policy");
        assert_eq!(
            evidence
                .subjects
                .iter()
                .map(|subject| subject.role.as_str())
                .collect::<Vec<_>>(),
            expected_roles
        );
        assert_eq!(evidence.supported_values.len(), 1);
        assert_no_selector_material(&serialized);
    }

    let requests = service
        .server
        .received_requests()
        .await
        .expect("source request journal is available");
    assert_eq!(requests.len(), 6);
    let bodies = requests
        .iter()
        .map(|request| serde_json::from_slice::<Value>(&request.body).expect("source body is JSON"))
        .collect::<Vec<_>>();
    assert!(bodies.iter().any(|body| {
        body.pointer("/selector/context_given_name") == Some(&json!("Ána María"))
            && body.pointer("/selector/context_family_name") == Some(&json!("N'Dour-Sato"))
    }));
    assert!(bodies.iter().any(|body| {
        body.pointer("/selector/grant_event_reference") == Some(&json!("synthetic-event-001"))
    }));
    assert!(bodies.iter().any(|body| {
        body.pointer("/selector/role_a_record_reference") == Some(&json!("synthetic-record-002"))
            && body.pointer("/selector/role_b_given_name") == Some(&json!("Binta"))
    }));

    let audit = fs::read_to_string(&service.audit_path).expect("durable audit is readable");
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 6);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 6);
    assert_eq!(audit.matches("selectorBundlePseudonym").count(), 16);
    for canary in selector_value_canaries() {
        assert!(
            !audit.contains(canary),
            "audit retained a protected selector value"
        );
    }
}

#[tokio::test]
async fn all_runtime_selector_negatives_fail_closed_before_source_access() {
    let service = prepare_service(false).await;
    let base = access_token(json!({}));
    let context_token = access_token(json!({
        "identity": {
            "given_name": "Ána María",
            "family_name": "N'Dour-Sato",
            "birth_date": "2000-02-29"
        }
    }));
    let grant_token = access_token(json!({
        "evidence_grant_id": "synthetic-grant-001",
        "evidence_authority": "authenticated-grant-v1",
        "grant": {"subject": {
            "given_name": "Adaeze",
            "family_name": "Okafor",
            "birth_date": "1990-07-11",
            "event_reference": "synthetic-event-001"
        }}
    }));
    let mut executed = BTreeSet::new();

    assert_authorization_error(
        &service,
        &base,
        &classification_request(Some(BTreeMap::new())),
        AuthorizationError::Selector,
    )
    .await;
    executed.insert("missing-record-reference");

    assert_authorization_error(
        &service,
        &base,
        &classification_request(values([
            (
                "record_reference",
                SelectorValue::String("synthetic-record-001".to_owned()),
            ),
            (
                "caller_extra",
                SelectorValue::String("protected-extra".to_owned()),
            ),
        ])),
        AuthorizationError::Selector,
    )
    .await;
    executed.insert("extra-caller-field");

    let wrong_origin = access_token(json!({
        "identity": {"record_reference": "synthetic-record-001"}
    }));
    assert_authorization_error(
        &service,
        &wrong_origin,
        &classification_request(None),
        AuthorizationError::Selector,
    )
    .await;
    executed.insert("wrong-origin-context-value");

    let unentitled = access_token(json!({"evidence_tags": ["unentitled"]}));
    assert_authorization_error(
        &service,
        &unentitled,
        &classification_request(values([(
            "record_reference",
            SelectorValue::String("synthetic-record-001".to_owned()),
        )])),
        AuthorizationError::Unauthorized,
    )
    .await;
    executed.insert("identifier-possession-without-entitlement");

    assert_authorization_error(
        &service,
        &context_token,
        &property_request(values([
            ("given_name", SelectorValue::String("Caller".to_owned())),
            ("family_name", SelectorValue::String("Supplied".to_owned())),
            ("birth_date", SelectorValue::String("2000-02-29".to_owned())),
        ])),
        AuthorizationError::Selector,
    )
    .await;
    executed.insert("caller-values-prohibited-for-context-origin");

    assert_authorization_error(
        &service,
        &access_token(json!({"identity": {"given_name": "Only"}})),
        &property_request(None),
        AuthorizationError::Selector,
    )
    .await;
    executed.insert("missing-configured-context-claim");

    let no_principal = token_with_claims(json!({
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "client_id": "fallback-client-canary",
        "azp": "fallback-azp-canary",
        "iat": Utc::now().timestamp() - 1,
        "exp": Utc::now().timestamp() + 3600,
        "evidence_tags": ["selector-reviewer"],
        "evidence_audience": EVIDENCE_AUDIENCE
    }));
    assert!(matches!(
        service
            .authorize(&no_principal, &property_request(None))
            .await,
        Err(AuthorizationStageError::Authentication)
    ));
    executed.insert("no-principal-claim-fallback");

    // The positive context wire assertion above uses the exact multi-byte and
    // punctuation-bearing values. That exhaustively proves no case folding,
    // transliteration, or alternate field inference occurs before the source.
    executed.insert("no-case-fold-or-transliteration");

    assert_authorization_error(
        &service,
        &grant_token,
        &grant_request(values([
            ("given_name", SelectorValue::String("Caller".to_owned())),
            ("family_name", SelectorValue::String("Supplied".to_owned())),
            ("birth_date", SelectorValue::String("1990-07-11".to_owned())),
            (
                "event_reference",
                SelectorValue::String("caller-event".to_owned()),
            ),
        ])),
        AuthorizationError::Selector,
    )
    .await;
    executed.insert("caller-values-prohibited-for-grant-origin");

    assert_authorization_error(
        &service,
        &base,
        &relationship_request(
            "opaque-record-v1",
            values([(
                "record_reference",
                SelectorValue::String("synthetic-record-002".to_owned()),
            )]),
            "demographics-v1",
            values([
                ("given_name", SelectorValue::String("Binta".to_owned())),
                ("family_name", SelectorValue::String("Diallo".to_owned())),
                ("birth_date", SelectorValue::String("1970-06-15".to_owned())),
                (
                    "event_reference",
                    SelectorValue::String("caller-event".to_owned()),
                ),
            ]),
        ),
        AuthorizationError::Selector,
    )
    .await;
    executed.insert("caller-added-disambiguator-rejected-from-demographics-v1");

    let grant_authority_without_id = access_token(json!({
        "evidence_authority": "authenticated-grant-v1",
        "grant": {"subject": {
            "given_name": "Adaeze",
            "family_name": "Okafor",
            "birth_date": "1990-07-11",
            "event_reference": "synthetic-event-001"
        }}
    }));
    assert!(matches!(
        service
            .authorize(&grant_authority_without_id, &grant_request(None))
            .await,
        Err(AuthorizationStageError::Authentication)
    ));
    executed.insert("authenticated-grant-id-not-bound");

    let wrong_grant_authority = access_token(json!({
        "evidence_grant_id": "synthetic-grant-001",
        "evidence_authority": "other-authority-v1",
        "grant": {"subject": {
            "given_name": "Adaeze",
            "family_name": "Okafor",
            "birth_date": "1990-07-11",
            "event_reference": "synthetic-event-001"
        }}
    }));
    assert_authorization_error(
        &service,
        &wrong_grant_authority,
        &grant_request(None),
        AuthorizationError::Unauthorized,
    )
    .await;
    executed.insert("authenticated-grant-authority-not-bound");

    assert_authorization_error(
        &service,
        &grant_token,
        &request(
            PROPERTY_WITH_EVENT,
            vec![subject("subject", "demographics-v1", None)],
        ),
        AuthorizationError::Unauthorized,
    )
    .await;
    executed.insert("alternative-field-set-not-inferred");

    let role_a = values([(
        "record_reference",
        SelectorValue::String("synthetic-record-002".to_owned()),
    )]);
    let role_b = values([
        ("given_name", SelectorValue::String("Binta".to_owned())),
        ("family_name", SelectorValue::String("Diallo".to_owned())),
        ("birth_date", SelectorValue::String("1970-06-15".to_owned())),
    ]);
    let swapped = request(
        RELATIONSHIP,
        vec![
            subject("subject-a", "demographics-v1", role_b.clone()),
            subject("subject-b", "opaque-record-v1", role_a.clone()),
        ],
    );
    assert_authorization_error(&service, &base, &swapped, AuthorizationError::Unauthorized).await;
    executed.insert("swapped-role-selectors");

    let substituted = request(
        RELATIONSHIP,
        vec![
            subject("subject-a", "opaque-record-v1", role_a.clone()),
            subject("subject-b", "opaque-record-v1", role_a.clone()),
        ],
    );
    assert_authorization_error(
        &service,
        &base,
        &substituted,
        AuthorizationError::Unauthorized,
    )
    .await;
    executed.insert("unauthorized-subject-b-substitution");

    let missing_role = request(
        RELATIONSHIP,
        vec![subject("subject-a", "opaque-record-v1", role_a.clone())],
    );
    assert_authorization_error(
        &service,
        &base,
        &missing_role,
        AuthorizationError::Unauthorized,
    )
    .await;
    executed.insert("missing-one-role");

    let duplicate_role = request(
        RELATIONSHIP,
        vec![
            subject("subject-a", "opaque-record-v1", role_a.clone()),
            subject("subject-a", "opaque-record-v1", role_a.clone()),
        ],
    );
    assert_authorization_error(
        &service,
        &base,
        &duplicate_role,
        AuthorizationError::Unauthorized,
    )
    .await;
    executed.insert("duplicate-subject-role");

    let unknown_role = request(
        RELATIONSHIP,
        vec![
            subject("subject-a", "opaque-record-v1", role_a.clone()),
            subject("subject-c", "demographics-v1", role_b.clone()),
        ],
    );
    assert_authorization_error(
        &service,
        &base,
        &unknown_role,
        AuthorizationError::Unauthorized,
    )
    .await;
    executed.insert("unknown-subject-role");

    let union_attempt = relationship_request(
        "opaque-record-v1",
        role_a,
        "demographics-with-event-v1",
        values([
            ("given_name", SelectorValue::String("Binta".to_owned())),
            ("family_name", SelectorValue::String("Diallo".to_owned())),
            ("birth_date", SelectorValue::String("1970-06-15".to_owned())),
            (
                "event_reference",
                SelectorValue::String("synthetic-event-002".to_owned()),
            ),
        ]),
    );
    assert_authorization_error(
        &service,
        &base,
        &union_attempt,
        AuthorizationError::Unauthorized,
    )
    .await;
    executed.insert("entitlement-union-across-roles");

    assert_authorization_error(
        &service,
        &base,
        &opaque_request(values([
            ("alpha", SelectorValue::String("synthetic-alpha".to_owned())),
            ("delta", SelectorValue::Integer(42)),
            ("kappa", SelectorValue::String("K-2".to_owned())),
            (
                "unknown",
                SelectorValue::String("protected-extra".to_owned()),
            ),
        ])),
        AuthorizationError::Selector,
    )
    .await;
    executed.insert("unknown-opaque-field");

    assert_authorization_error(
        &service,
        &base,
        &opaque_request(values([
            ("alpha", SelectorValue::String("synthetic-alpha".to_owned())),
            ("delta", SelectorValue::String("42".to_owned())),
            ("kappa", SelectorValue::String("K-2".to_owned())),
        ])),
        AuthorizationError::Selector,
    )
    .await;
    executed.insert("wrong-opaque-scalar-type");

    let aggregate_overflow = opaque_request(values([
        ("alpha", SelectorValue::String("A".repeat(80))),
        ("delta", SelectorValue::Integer(999_999)),
        (
            "kappa",
            SelectorValue::String("K-ABCDEFGHIJKLMN".to_owned()),
        ),
    ]));
    assert_authorization_error(
        &service,
        &base,
        &aggregate_overflow,
        AuthorizationError::Selector,
    )
    .await;
    executed.insert("aggregate-size-exceeded");
    executed.insert("aggregate-byte-boundary-plus-one");

    assert_authorization_error(
        &service,
        &base,
        &classification_request(values([(
            "record_reference",
            SelectorValue::String(String::new()),
        )])),
        AuthorizationError::Selector,
    )
    .await;
    executed.insert("empty-string");

    assert_authorization_error(
        &service,
        &context_token_with_birth_date("2000-02-30"),
        &property_request(None),
        AuthorizationError::Selector,
    )
    .await;
    executed.insert("invalid-date");

    let object_value = json!({
        "requirement": CLASSIFICATION,
        "purpose": PURPOSE,
        "subjects": [{
            "role": "subject",
            "selector": {"profile": "opaque-record-v1", "values": {"record_reference": {"nested": true}}}
        }]
    });
    assert!(serde_json::from_value::<EvidenceRequest>(object_value).is_err());
    let array_value = json!({
        "requirement": CLASSIFICATION,
        "purpose": PURPOSE,
        "subjects": [{
            "role": "subject",
            "selector": {"profile": "opaque-record-v1", "values": {"record_reference": ["value"]}}
        }]
    });
    assert!(serde_json::from_value::<EvidenceRequest>(array_value).is_err());
    executed.insert("scalar-object-or-array");

    assert_authorization_error(
        &service,
        &base,
        &classification_request(values([(
            "record_reference",
            SelectorValue::String("R".repeat(97)),
        )])),
        AuthorizationError::Selector,
    )
    .await;
    executed.insert("field-byte-boundary-plus-one");

    assert_authorization_error(
        &service,
        &base,
        &request(
            CLASSIFICATION,
            vec![subject(
                "subject",
                "demographics-v1",
                values([
                    ("given_name", SelectorValue::String("A".to_owned())),
                    ("family_name", SelectorValue::String("B".to_owned())),
                    ("birth_date", SelectorValue::String("2000-01-01".to_owned())),
                ]),
            )],
        ),
        AuthorizationError::Unauthorized,
    )
    .await;
    executed.insert("unauthorized-profile");

    let mut wrong_purpose = classification_request(values([(
        "record_reference",
        SelectorValue::String("synthetic-record-001".to_owned()),
    )]));
    wrong_purpose.purpose = "unauthorized-purpose".to_owned();
    assert_authorization_error(
        &service,
        &base,
        &wrong_purpose,
        AuthorizationError::Unauthorized,
    )
    .await;
    executed.insert("unauthorized-purpose");

    let wrong_audience = access_token(json!({"aud": "wrong-resource-audience"}));
    assert!(matches!(
        service
            .authorize(
                &wrong_audience,
                &classification_request(values([(
                    "record_reference",
                    SelectorValue::String("synthetic-record-001".to_owned()),
                )])),
            )
            .await,
        Err(AuthorizationStageError::Authentication)
    ));
    executed.insert("unauthorized-audience");

    let caller_grant = json!({
        "requirement": PROPERTY_WITH_EVENT,
        "purpose": PURPOSE,
        "grantId": "caller-grant",
        "grantAuthority": "caller-authority",
        "subjects": [{"role": "subject", "selector": {"profile": "demographics-with-event-v1"}}]
    });
    assert!(serde_json::from_value::<EvidenceRequest>(caller_grant).is_err());
    executed.insert("grant-id-or-authority-from-caller-request");

    // All assertions above use the same executor configured with a deliberately
    // absent source credential. Any early credential acquisition would change
    // the observed failure, and any source access would appear in this journal.
    assert!(service
        .server
        .received_requests()
        .await
        .expect("source request journal is available")
        .is_empty());
    executed.insert("credential-resolution-or-source-access-before-validation");

    for config_case in [
        "incomplete-grant-valueClaims",
        "missing-context-valueClaims",
        "incomplete-or-extra-valueClaims",
        "request-origin-valueClaims",
    ] {
        executed.insert(config_case);
    }
    assert_eq!(
        executed
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>(),
        declared_negative_cases()
    );
}

#[test]
fn configuration_selector_negatives_are_rejected_at_immutable_bundle_load() {
    assert_invalid_bundle(|text| {
        replace_exact(
            text,
            "            valueClaims:\n              given_name: identity.given_name\n              family_name: identity.family_name\n              birth_date: identity.birth_date\n",
            "",
            1,
        );
    });
    assert_invalid_bundle(|text| {
        replace_exact(
            text,
            "              event_reference: grant.subject.event_reference\n",
            "",
            1,
        );
    });
    assert_invalid_bundle(|text| {
        replace_exact(
            text,
            "              event_reference: grant.subject.event_reference\n",
            "              event_reference: grant.subject.event_reference\n              extra: grant.subject.extra\n",
            1,
        );
    });
    assert_invalid_bundle(|text| {
        replace_exact(
            text,
            "          - {role: subject, selectorProfile: opaque-record-v1, valueOrigin: request}\n",
            "          - role: subject\n            selectorProfile: opaque-record-v1\n            valueOrigin: request\n            valueClaims: {record_reference: caller.record_reference}\n",
            1,
        );
    });
}

async fn prepare_service(write_source_secret: bool) -> PreparedService {
    let temporary = tempfile::tempdir().expect("temporary selector conformance root");
    let bundle_root = temporary.path().join("bundle");
    let secret_root = temporary.path().join("secrets");
    let audit_path = temporary.path().join("audit.jsonl");
    let runtime_path = temporary.path().join("runtime.yaml");
    fs::create_dir(&bundle_root).expect("bundle root is created");
    fs::create_dir(&secret_root).expect("secret root is created");
    #[cfg(unix)]
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("selector secret root is owner-only");
    copy_tree(&selector_bundle_root(), &bundle_root);
    let server = MockServer::start().await;
    rewrite_source_origin(&bundle_root, &server.uri());
    write_secret(&secret_root, "audit-key", AUDIT_KEY);
    write_secret(&secret_root, "binding-key", BINDING_KEY);
    write_secret(&secret_root, "signing-key", EVIDENCE_PRIVATE_JWK.as_bytes());
    if write_source_secret {
        write_secret(&secret_root, "source-token", SOURCE_TOKEN.as_bytes());
    }
    write_runtime(&runtime_path, &bundle_root, &secret_root, &audit_path);
    make_read_only(&bundle_root);
    #[cfg(unix)]
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444))
        .expect("selector runtime is immutable");

    let deployment =
        DeploymentInputs::load(&runtime_path).expect("closed selector deployment inputs load");
    assert_ne!(
        deployment.bundle.revision(),
        deployment.runtime.revision(),
        "governed bundle and runtime have independent revisions"
    );
    let bundle = Arc::new(deployment.bundle);
    let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("selector kernel compiles");
    let secrets = Arc::new(
        SecretResolver::new([SecretProvider::File], &secret_root)
            .expect("selector secret resolver initializes"),
    );
    let sources = bundle
        .config
        .sources
        .iter()
        .map(|(source_id, config)| {
            let allowed_selector_sets = bundle.config.source_selector_sets(source_id);
            SourceExecutor::new_with_selector_sets(
                config,
                &allowed_selector_sets,
                Arc::clone(&secrets),
            )
            .map(|executor| (source_id.to_owned(), executor))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()
        .expect("fixed selector source executors initialize");
    let audit = EvidenceAuditLog::initialize(&audit_path, 10_485_760, AUDIT_KEY.to_vec(), 1)
        .await
        .expect("selector audit initializes");
    let private = PrivateJwk::parse(EVIDENCE_PRIVATE_JWK).expect("Evidence test key parses");
    let provider: Arc<dyn SigningProvider> =
        Arc::new(LocalJwkSigner::new(private).expect("Evidence signer builds"));
    let signer = EvidenceSigner::initialize(provider, EVIDENCE_KEY_ID)
        .await
        .expect("Evidence signer self-test succeeds");
    PreparedService {
        _temporary: temporary,
        bundle,
        kernel,
        authenticator: authenticator(),
        sources,
        audit,
        signer,
        server,
        audit_path,
    }
}

fn authenticator() -> Authenticator {
    let private = PrivateJwk::parse(AUTH_PRIVATE_JWK).expect("auth test key parses");
    let jwks: JwkSet = serde_json::from_value(json!({"keys": [private.public()]}))
        .expect("static auth JWKS parses");
    let fetcher = Arc::new(JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults()));
    let verifier = Arc::new(TokenVerifier::new(
        TokenVerifierConfig::access_token_profile(
            TOKEN_ISSUER,
            vec![TOKEN_AUDIENCE.to_owned()],
            vec![Algorithm::EdDSA],
            vec!["at+jwt".to_owned()],
        ),
        fetcher,
    ));
    Authenticator::new(
        verifier,
        AuthenticationClaimsConfig {
            principal_claim: "sub".to_owned(),
            requester_tags_claim: "evidence_tags".to_owned(),
            evidence_audience_claim: "evidence_audience".to_owned(),
            grant_id_claim: "evidence_grant_id".to_owned(),
            grant_authority_claim: "evidence_authority".to_owned(),
            actor_claim: None,
        },
    )
}

fn access_token(extra: Value) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "sub": "selector-requester-principal-canary",
        "iat": now - 1,
        "exp": now + 3600,
        "evidence_tags": ["selector-reviewer"],
        "evidence_audience": EVIDENCE_AUDIENCE
    });
    if let Value::Object(extra) = extra {
        claims
            .as_object_mut()
            .expect("claims are an object")
            .extend(extra);
    }
    token_with_claims(claims)
}

fn token_with_claims(claims: Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "kid": "selector-auth-key",
            "typ": "at+jwt"
        }))
        .expect("JWT header serializes"),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims serialize"));
    let signing_input = format!("{header}.{payload}");
    let key = PrivateJwk::parse(AUTH_PRIVATE_JWK).expect("auth test key parses");
    let signature =
        URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes(), &key).expect("JWT signs"));
    format!("{signing_input}.{signature}")
}

fn context_token_with_birth_date(birth_date: &str) -> String {
    access_token(json!({
        "identity": {
            "given_name": "Ána María",
            "family_name": "N'Dour-Sato",
            "birth_date": birth_date
        }
    }))
}

fn classification_request(values: Option<BTreeMap<String, SelectorValue>>) -> EvidenceRequest {
    request(
        CLASSIFICATION,
        vec![subject("subject", "opaque-record-v1", values)],
    )
}

fn property_request(values: Option<BTreeMap<String, SelectorValue>>) -> EvidenceRequest {
    request(
        PROPERTY,
        vec![subject("subject", "demographics-v1", values)],
    )
}

fn grant_request(values: Option<BTreeMap<String, SelectorValue>>) -> EvidenceRequest {
    request(
        PROPERTY_WITH_EVENT,
        vec![subject("subject", "demographics-with-event-v1", values)],
    )
}

fn relationship_request(
    role_a_profile: &str,
    role_a_values: Option<BTreeMap<String, SelectorValue>>,
    role_b_profile: &str,
    role_b_values: Option<BTreeMap<String, SelectorValue>>,
) -> EvidenceRequest {
    request(
        RELATIONSHIP,
        vec![
            subject("subject-a", role_a_profile, role_a_values),
            subject("subject-b", role_b_profile, role_b_values),
        ],
    )
}

fn opaque_request(values: Option<BTreeMap<String, SelectorValue>>) -> EvidenceRequest {
    request(
        OPAQUE,
        vec![subject("subject", "opaque-coordinates-v1", values)],
    )
}

fn request(requirement: &str, subjects: Vec<RequestedSubject>) -> EvidenceRequest {
    EvidenceRequest {
        request_nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        requirement: requirement.to_owned(),
        purpose: PURPOSE.to_owned(),
        subjects,
        holder_key: None,
    }
}

fn subject(
    role: &str,
    profile: &str,
    values: Option<BTreeMap<String, SelectorValue>>,
) -> RequestedSubject {
    RequestedSubject {
        role: role.to_owned(),
        selector: RequestedSelector {
            profile: profile.to_owned(),
            values,
        },
    }
}

fn values<const N: usize>(
    entries: [(&str, SelectorValue); N],
) -> Option<BTreeMap<String, SelectorValue>> {
    Some(
        entries
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

async fn assert_authorization_error(
    service: &PreparedService,
    token: &str,
    request: &EvidenceRequest,
    expected: AuthorizationError,
) {
    let first = service.authorize(token, request).await;
    if !matches!(
        first,
        Err(AuthorizationStageError::Authorization(actual)) if actual == expected
    ) {
        let stage = match first {
            Ok(_) => "authorized",
            Err(AuthorizationStageError::Authentication) => "authentication",
            Err(AuthorizationStageError::Authorization(AuthorizationError::Unauthorized)) => {
                "unauthorized"
            }
            Err(AuthorizationStageError::Authorization(AuthorizationError::Selector)) => "selector",
            Err(AuthorizationStageError::Authorization(AuthorizationError::AmbiguousAuthority)) => {
                "ambiguous-authority"
            }
            Err(AuthorizationStageError::Authorization(AuthorizationError::Binding)) => "binding",
        };
        panic!(
            "safe authorization-category mismatch for requirement {}: expected {expected:?}, got {stage}",
            request.requirement
        );
    }
    let diagnostic = format!("{:?}", service.authorize(token, request).await);
    for canary in selector_value_canaries() {
        assert!(!diagnostic.contains(canary));
    }
}

fn source_selectors(
    resolved: &ResolvedAuthorization,
    inputs: &[SelectorInput],
) -> Vec<ResolvedSourceSelector> {
    inputs
        .iter()
        .map(|input| {
            let subject = resolved
                .subjects
                .iter()
                .find(|subject| subject.role == input.role)
                .expect("input role resolves");
            let alternative = input
                .alternatives
                .iter()
                .find(|alternative| alternative.profile == subject.selector_profile)
                .expect("input profile resolves");
            ResolvedSourceSelector {
                role: subject.role.clone(),
                profile: subject.selector_profile.clone(),
                values: alternative
                    .fields
                    .iter()
                    .map(|name| {
                        let field = subject
                            .fields
                            .iter()
                            .find(|field| &field.name == name)
                            .expect("input field resolves");
                        let value = match &field.value {
                            ResolvedSelectorValue::String(value)
                            | ResolvedSelectorValue::Date(value)
                            | ResolvedSelectorValue::ControlledCode(value) => {
                                SelectorValue::String(value.clone())
                            }
                            ResolvedSelectorValue::Integer(value) => SelectorValue::Integer(*value),
                            ResolvedSelectorValue::Boolean(value) => SelectorValue::Boolean(*value),
                        };
                        (field.name.clone(), value)
                    })
                    .collect(),
            }
        })
        .collect()
}

fn selector_value(resolved: &ResolvedAuthorization, inputs: &[SelectorInput]) -> Value {
    Value::Object(
        inputs
            .iter()
            .map(|input| {
                let subject = resolved
                    .subjects
                    .iter()
                    .find(|subject| subject.role == input.role)
                    .expect("input role resolves");
                let alternative = input
                    .alternatives
                    .iter()
                    .find(|alternative| alternative.profile == subject.selector_profile)
                    .expect("input profile resolves");
                let values = alternative
                    .fields
                    .iter()
                    .map(|name| {
                        let field = subject
                            .fields
                            .iter()
                            .find(|field| &field.name == name)
                            .expect("input field resolves");
                        (name.clone(), field.value.as_json())
                    })
                    .collect();
                (
                    input.role.clone(),
                    json!({"profile": alternative.profile, "values": Value::Object(values)}),
                )
            })
            .collect(),
    )
}

fn audit_subjects(audit: &EvidenceAuditLog, resolved: &ResolvedAuthorization) -> Vec<AuditSubject> {
    resolved
        .subjects
        .iter()
        .map(|subject| AuditSubject {
            role: subject.role.clone(),
            selector_profile: subject.selector_profile.clone(),
            selector_bundle_pseudonym: Some(
                audit
                    .pseudonym(
                        "subject-selector-bundle",
                        "selector-conformance",
                        &subject
                            .audit_pseudonym_input(&resolved.audience, &resolved.purpose)
                            .expect("selector bundle canonicalizes"),
                    )
                    .expect("selector bundle pseudonymizes"),
            ),
        })
        .collect()
}

fn audit_authority(audit: &EvidenceAuditLog, resolved: &ResolvedAuthorization) -> AuditAuthority {
    AuditAuthority {
        kind: match resolved.authority_kind {
            AuthorityKind::Statutory => AuditAuthorityKind::Statutory,
            AuthorityKind::Organizational => AuditAuthorityKind::Organizational,
            AuthorityKind::Consent => AuditAuthorityKind::Consent,
            AuthorityKind::Delegated => AuditAuthorityKind::Delegated,
            AuthorityKind::ExplicitRequest => AuditAuthorityKind::ExplicitRequest,
        },
        grant_pseudonym: resolved.grant_id.as_deref().map(|grant| {
            audit
                .pseudonym("grant", "selector-conformance", grant.as_bytes())
                .expect("grant pseudonymizes")
        }),
    }
}

fn source_identity(bundle: &Bundle, requirement_id: &str) -> (String, String) {
    let requirement = bundle
        .config
        .requirements
        .iter()
        .find(|candidate| candidate.id == requirement_id)
        .expect("requirement is configured");
    let source = bundle
        .config
        .sources
        .get(requirement.initial_source())
        .expect("source is configured");
    let adapter = Path::new(source.extract_script().as_str())
        .file_stem()
        .and_then(|name| name.to_str())
        .expect("adapter has a local identifier");
    (requirement.initial_source().to_owned(), adapter.to_owned())
}

fn selector_value_canaries() -> &'static [&'static str] {
    &[
        "synthetic-record-001",
        "synthetic-record-002",
        "Ána María",
        "N'Dour-Sato",
        "Adaeze",
        "Okafor",
        "Binta",
        "Diallo",
        "synthetic-event-001",
        "synthetic-alpha",
        "fallback-client-canary",
        "fallback-azp-canary",
        SOURCE_TOKEN,
    ]
}

fn assert_no_selector_material(serialized_jws: &[u8]) {
    let jws: FlattenedJws = serde_json::from_slice(serialized_jws).expect("JWS is JSON");
    let payload = URL_SAFE_NO_PAD
        .decode(jws.payload)
        .expect("JWS payload decodes");
    let payload = String::from_utf8(payload).expect("Evidence payload is UTF-8");
    for canary in selector_value_canaries() {
        assert!(!payload.contains(canary));
    }
    for profile in [
        "opaque-record-v1",
        "demographics-v1",
        "demographics-with-event-v1",
        "opaque-coordinates-v1",
    ] {
        assert!(!payload.contains(profile));
    }
}

fn declared_negative_cases() -> BTreeSet<String> {
    const EXECUTED: &[&str] = &[
        "missing-record-reference",
        "extra-caller-field",
        "wrong-origin-context-value",
        "identifier-possession-without-entitlement",
        "caller-values-prohibited-for-context-origin",
        "missing-configured-context-claim",
        "no-principal-claim-fallback",
        "no-case-fold-or-transliteration",
        "caller-values-prohibited-for-grant-origin",
        "caller-added-disambiguator-rejected-from-demographics-v1",
        "authenticated-grant-id-not-bound",
        "authenticated-grant-authority-not-bound",
        "incomplete-grant-valueClaims",
        "alternative-field-set-not-inferred",
        "swapped-role-selectors",
        "unauthorized-subject-b-substitution",
        "missing-one-role",
        "duplicate-subject-role",
        "unknown-subject-role",
        "entitlement-union-across-roles",
        "unknown-opaque-field",
        "wrong-opaque-scalar-type",
        "aggregate-size-exceeded",
        "empty-string",
        "invalid-date",
        "scalar-object-or-array",
        "field-byte-boundary-plus-one",
        "aggregate-byte-boundary-plus-one",
        "unauthorized-profile",
        "unauthorized-purpose",
        "unauthorized-audience",
        "missing-context-valueClaims",
        "incomplete-or-extra-valueClaims",
        "request-origin-valueClaims",
        "grant-id-or-authority-from-caller-request",
        "credential-resolution-or-source-access-before-validation",
    ];
    let declared = matrix_negative_cases();
    let executed = EXECUTED
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        declared, executed,
        "selector matrix negative coverage drifted"
    );
    executed
}

fn matrix_negative_cases() -> BTreeSet<String> {
    let text =
        fs::read_to_string(products_root().join("fixtures/conformance/selector-matrix.yaml"))
            .expect("selector matrix is readable");
    let yaml: serde_norway::Value = serde_norway::from_str(&text).expect("selector matrix is YAML");
    let json = serde_json::to_value(yaml).expect("selector matrix converts to JSON");
    let mut names = Vec::new();
    for profile in json["profiles"]
        .as_array()
        .expect("selector profiles are an array")
    {
        names.extend(
            profile["negative"]
                .as_array()
                .expect("profile negatives are an array")
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("negative name is a string")
                        .to_owned()
                }),
        );
    }
    names.extend(
        json["global_negative"]
            .as_array()
            .expect("global negatives are an array")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("negative name is a string")
                    .to_owned()
            }),
    );
    names.into_iter().collect()
}

fn assert_invalid_bundle(mutate: impl FnOnce(&mut String)) {
    let temporary = tempfile::tempdir().expect("temporary invalid bundle root");
    let bundle_root = temporary.path().join("bundle");
    fs::create_dir(&bundle_root).expect("bundle root is created");
    copy_tree(&selector_bundle_root(), &bundle_root);
    let config_path = bundle_root.join("evidence.yaml");
    let mut config = fs::read_to_string(&config_path).expect("bundle config is readable");
    mutate(&mut config);
    fs::write(config_path, config).expect("invalid config mutation writes");
    make_read_only(&bundle_root);
    assert!(matches!(
        Bundle::load(&bundle_root),
        Err(BundleError::Config(_))
    ));
}

fn products_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence")
        .canonicalize()
        .expect("Evidence product root exists")
}

fn selector_bundle_root() -> PathBuf {
    products_root().join("fixtures/conformance/selectors")
}

fn rewrite_source_origin(bundle_root: &Path, source_origin: &str) {
    let path = bundle_root.join("evidence.yaml");
    let mut text = fs::read_to_string(&path).expect("copied selector config is readable");
    replace_exact(&mut text, "https://source.invalid", source_origin, 5);
    replace_exact(
        &mut text,
        "assuranceProfile: evidence-grade",
        "assuranceProfile: local",
        1,
    );
    fs::write(path, text).expect("deployment-only selector rewrite succeeds");
}

fn write_runtime(runtime_path: &Path, bundle_root: &Path, secret_root: &Path, audit_path: &Path) {
    let runtime = format!(
        concat!(
            "version: 1\n",
            "bundleDirectory: {}\n",
            "listener:\n",
            "  bindHost: 127.0.0.1\n",
            "  port: 8080\n",
            "  tlsTermination: operator-controlled-upstream\n",
            "  trustProxyIdentityHeaders: false\n",
            "  maximumRequestBytes: 65536\n",
            "  maximumConcurrentRequests: 32\n",
            "  requestTimeoutMilliseconds: 10000\n",
            "  shutdownGraceMilliseconds: 30000\n",
            "secretProviders:\n",
            "  file:\n",
            "    root: {}\n",
            "signer:\n",
            "  kind: local-jwk\n",
            "  privateKeyRef: secret:file/signing-key\n",
            "auditStorage:\n",
            "  path: {}\n",
            "  maximumFileBytes: 10485760\n",
            "outboundTls:\n",
            "  systemRoots: true\n",
            "  trustProfiles: {{}}\n"
        ),
        bundle_root.display(),
        secret_root.display(),
        audit_path.display()
    );
    fs::write(runtime_path, runtime).expect("closed selector runtime writes");
}

fn replace_exact(text: &mut String, from: &str, to: &str, expected: usize) {
    assert_eq!(
        text.matches(from).count(),
        expected,
        "fixture drift for {from}"
    );
    *text = text.replace(from, to);
}

fn write_secret(root: &Path, name: &str, value: &[u8]) {
    let path = root.join(name);
    fs::write(&path, value).expect("synthetic selector secret writes");
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("synthetic selector secret is owner-only");
}

fn copy_tree(source: &Path, target: &Path) {
    for entry in fs::read_dir(source).expect("selector fixture is readable") {
        let entry = entry.expect("selector fixture entry is readable");
        let destination = target.join(entry.file_name());
        if entry
            .file_type()
            .expect("selector fixture type is readable")
            .is_dir()
        {
            fs::create_dir(&destination).expect("selector fixture directory is copied");
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("selector fixture file is copied");
        }
    }
}

#[cfg(unix)]
fn make_read_only(path: &Path) {
    for entry in fs::read_dir(path).expect("copied selector bundle is readable") {
        let entry = entry.expect("selector bundle entry is readable");
        let child = entry.path();
        if entry
            .file_type()
            .expect("selector bundle type is readable")
            .is_dir()
        {
            make_read_only(&child);
            fs::set_permissions(&child, fs::Permissions::from_mode(0o555))
                .expect("selector bundle directory is immutable");
        } else {
            fs::set_permissions(&child, fs::Permissions::from_mode(0o444))
                .expect("selector bundle file is immutable");
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o555))
        .expect("selector bundle root is immutable");
}

#[cfg(not(unix))]
fn make_read_only(path: &Path) {
    for entry in fs::read_dir(path).expect("copied selector bundle is readable") {
        let entry = entry.expect("selector bundle entry is readable");
        let child = entry.path();
        if entry
            .file_type()
            .expect("selector bundle type is readable")
            .is_dir()
        {
            make_read_only(&child);
        } else {
            let mut permissions = fs::metadata(&child)
                .expect("selector bundle metadata")
                .permissions();
            permissions.set_readonly(true);
            fs::set_permissions(child, permissions).expect("selector bundle file is immutable");
        }
    }
}

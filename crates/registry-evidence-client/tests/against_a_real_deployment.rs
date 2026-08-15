#![cfg(unix)]

//! Proof that this client and a real Evidence deployment agree.
//!
//! Every case here drives the actual runtime over loopback HTTP: the real
//! bundle loader, the real authenticator, the real authorization and selector
//! path, the real signer, and the real problem contract. The client's own
//! request types, discovery types, and problem parser are asserted against that
//! runtime rather than against a stub of this crate's making, so a disagreement
//! about a member name, a media type, a status code, or a policy field fails
//! here.
//!
//! The deployment is the tracked synthetic acceptance fixture, rewritten for the
//! local assurance profile. An externally driven runtime has to use the public
//! `initialize` seam, which builds the deployed authenticator and therefore
//! requires a loopback token issuer, which only the local profile permits.
//! Nothing in the fixture names a source product.
//!
//! Most cases are their own token issuer: the suite publishes a key set and signs
//! the credentials it presents. The credential-acquisition cases instead run a
//! real authorization server on its own loopback origin and let the client's
//! provider authenticate to it with a signed client assertion, so acquisition,
//! caching, and refusal are proven against a server that enforces the grant
//! rather than against a stub of this crate's making.

use std::{
    error::Error,
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use registry_evidence::{runtime::EvidenceRuntime, server};
use registry_evidence_client::{
    AssuranceProfile, AudienceScopedRequest, ConceptForm, DefinitionCardinality, DefinitionKind,
    EvidenceClient, EvidenceClientConfig, EvidenceClientError, EvidenceDefinitionsDocument,
    EvidenceRequestSpec, EvidenceResponseFormat, OAuthErrorCode, PrivateKeyJwt,
    PrivateKeyJwtConfig, PublicValue, SelectorField, SelectorValue, SelectorValueOrigin,
    StaticToken, SubjectContinuity, SubjectExpectations, SubjectRequest, TokenError, TokenProvider,
    TransportKind, VerificationError, VerifiedAudienceScopedEvidence,
    EVIDENCE_DEFINITIONS_SCHEMA_V1,
};
use registry_mint::{
    config::MintConfig,
    server::{self as mint_server, MintService},
};
use registry_platform_crypto::{sign, PrivateJwk, PublicJwk};
use serde_json::{json, Value};
use url::Url;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

/// Vocabulary the tracked acceptance fixture publishes.
const TOKEN_AUDIENCE: &str = "evidence-fixture";
const CONFIGURED_TAG: &str = "fixture-agency";
const REQUIREMENT: &str = "urn:example:fixture:requirement:adult-status:v1";
const FIXTURE_SIGNING_KEY_ID: &str = "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo";

/// Vocabulary this suite chooses.
const RELYING_AUDIENCE: &str = "https://relying.invalid/procedure";
const PRINCIPAL: &str = "client-suite-principal";
const AUTH_KEY_ID: &str = "client-suite-auth-key";
const SOURCE_BEARER: &str = "source-bearer-canary";

/// The registered client the acquisition cases authenticate as, the key it
/// signs its assertions with, and the key the authorization server signs the
/// credentials it issues with.
const CLIENT_ID: &str = "client-suite-relying-party";
const CLIENT_KEY_ID: &str = "client-suite-client-key";
const ES256_CLIENT_KEY_ID: &str = "client-suite-client-key-es256";

/// The shortest access token lifetime the authorization server accepts. The
/// refresh margin case needs a margin wider than a whole credential's life.
const ISSUED_TOKEN_LIFETIME_SECONDS: i64 = 60;

/// Serialize the narrow handoff from a held ephemeral port to a real service.
///
/// The services under test have to know their configured port before binding it.
/// Without this guard, another parallel case in this test binary can reserve the
/// just-released port before the spawned service reaches `bind`.
static LOOPBACK_PORT_HANDOFF: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Prefix the runtime gives every published subject binding.
const BINDING_PREFIX: &str = "urn:evidence:subject:v1_";

/// The requirement states a validity of exactly one day. The verifier refuses an
/// assertion whose lifetime exceeds the policy's own maximum, and the comparison
/// is strict, so the exact configured validity is an accepted policy.
const MAXIMUM_ASSERTION_LIFETIME_SECONDS: u64 = 86_400;
const CLOCK_SKEW_SECONDS: u64 = 30;

/// A source answer that resolves to exactly one record.
fn resolved_source_answer() -> Value {
    json!({"total": 1, "date_of_birth": "2000-01-01"})
}

/// A source answer that resolves to no record. The public contract collapses
/// this with ambiguity and with a missing fact into one unavailable answer.
fn unresolved_source_answer() -> Value {
    json!({"total": 0})
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

/// The first exchange has no binding to pin, so it adopts the one the response
/// carries; the second pins what the first exposed. This is the whole documented
/// workflow, against a deployment that computes bindings with a secret the
/// relying party never holds.
#[tokio::test]
async fn first_use_acceptance_then_pinning_completes_two_verified_exchanges() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let first = client.prepare(spec(
            &definitions,
            "first-use",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        let accepted = client.request_and_verify(&first).await?;

        let pinned = accepted.pinned_subject_expectations();
        let second = client.prepare(spec(
            &definitions,
            "first-use",
            SubjectExpectations::Pinned(pinned.clone()),
        ))?;
        let repinned = client.request_and_verify(&second).await?;
        Ok((
            accepted,
            pinned,
            repinned,
            first.request_nonce().to_owned(),
            second.request_nonce().to_owned(),
        ))
    }
    .await;
    let (accepted, pinned, repinned, first_nonce, second_nonce) =
        proof.expect("the deployment answers and the response verifies");

    let evidence = accepted.evidence();
    assert_eq!(evidence.assurance_profile, AssuranceProfile::Local);
    assert_eq!(evidence.supports_requirement, REQUIREMENT);
    assert_eq!(evidence.audience, Some(RELYING_AUDIENCE.to_owned()));
    assert_eq!(evidence.request_nonce, Some(first_nonce.clone()));
    assert_eq!(evidence.subjects.len(), 1);
    assert_eq!(evidence.subjects[0].role, "subject");
    assert!(
        evidence.subjects[0].binding.starts_with(BINDING_PREFIX),
        "the published binding uses the versioned prefix"
    );
    assert_eq!(evidence.supported_values.len(), 1);
    assert_eq!(
        evidence.supported_values[0].value,
        PublicValue::Boolean(true)
    );
    assert!(
        accepted.trace_id().is_some_and(|trace_id| {
            trace_id.len() == 32
                && trace_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }),
        "the exchange carries a canonical trace identifier"
    );

    // Persisting the accepted bindings and pinning them is what turns the next
    // answer about another subject into a verification failure.
    assert_eq!(pinned.len(), 1);
    assert_eq!(pinned[0].role, "subject");
    assert_eq!(pinned[0].binding, evidence.subjects[0].binding);
    assert_eq!(
        repinned.evidence().request_nonce,
        Some(second_nonce.clone())
    );
    assert_eq!(
        repinned.evidence().subjects[0].binding,
        evidence.subjects[0].binding,
        "the same subject keeps the same binding across exchanges"
    );
    assert_ne!(
        first_nonce, second_nonce,
        "each prepared request is its own"
    );
}

/// The property pinning exists for: once a binding is pinned, an assertion about
/// another subject is refused even though it is correctly signed, correctly
/// scoped, and answers this exact request.
#[tokio::test]
async fn a_pinned_binding_refuses_an_assertion_about_another_subject() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let request = client.prepare(spec(
            &definitions,
            "known-subject",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        let known = client.request_and_verify(&request).await?;

        // The same request shape, a different subject, and the first subject's
        // binding pinned.
        let other = client.prepare(spec(
            &definitions,
            "other-subject",
            SubjectExpectations::Pinned(known.pinned_subject_expectations()),
        ))?;
        Ok((
            known.pinned_subject_expectations(),
            client.request_and_verify(&other).await,
        ))
    }
    .await;
    let (pinned, refusal) = proof.expect("both exchanges reach the deployment");

    assert_eq!(
        refusal.expect_err("the pinned expectation refuses the other subject"),
        EvidenceClientError::Verification(VerificationError::Policy),
    );
    assert!(pinned[0].binding.starts_with(BINDING_PREFIX));
}

/// Discovery is authoring input, and these are the client's own closed types
/// reading it. A runtime that renamed a member, changed a case convention, or
/// published a shape outside the closed set would fail to deserialize.
#[tokio::test]
async fn discovery_publishes_shapes_this_client_parses_exactly() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());
    let definitions = client
        .discover()
        .await
        .expect("the deployment publishes the requester's definitions");

    assert_eq!(definitions.schema, EVIDENCE_DEFINITIONS_SCHEMA_V1);
    assert_eq!(definitions.assurance_profile, AssuranceProfile::Local);
    assert_eq!(definitions.definitions.len(), 1);

    let definition = definitions
        .definition(REQUIREMENT)
        .expect("the requester is entitled to the fixture requirement");
    // The revision is published per definition, because that is the scope an
    // assertion for one requirement carries.
    assert!(definition.configuration_revision.starts_with("sha256:"));
    assert_eq!(definition.configuration_revision.len(), 71);
    assert_eq!(definition.kind, DefinitionKind::Criterion);
    assert_eq!(definition.purpose, "fixture-eligibility");
    assert_eq!(definition.subjects.len(), 1);
    assert_eq!(
        definition.subjects[0].cardinality,
        DefinitionCardinality::One
    );
    assert_eq!(
        definition.subjects[0].selector.value_origin,
        SelectorValueOrigin::Request
    );
    assert!(
        !definition.subjects[0].selector.fields.is_empty(),
        "a request-origin selector publishes its fields"
    );
    assert_eq!(definition.concepts.len(), 1);
    assert_eq!(
        definition.concepts[0].form,
        registry_evidence_client::definitions::DefinitionConceptForm::Scalar(ConceptForm::Boolean)
    );
    assert!(
        definition.concepts[0].scalar_expected_output().is_some(),
        "a boolean concept yields a scalar expectation"
    );
}

/// The published key set is discovery, not a trust anchor: this proves the
/// fetched document is the deployment's own, which is what makes an out-of-band
/// review of it meaningful. Verification still uses only the pinned set.
#[tokio::test]
async fn the_published_key_set_is_the_deployments_own() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());
    let published = client
        .fetch_jwks()
        .await
        .expect("the deployment publishes its verification keys");

    assert_eq!(&published, deployment.runtime.jwks());
    assert_eq!(published.keys.len(), 1);
    let published_key: PublicJwk =
        serde_json::from_value(published.keys[0].clone()).expect("the published key parses");
    let thumbprint = published_key.jkt().expect("the thumbprint computes");
    assert_eq!(published_key.kid.as_deref(), Some(thumbprint.as_str()));
    assert_eq!(
        published.keys[0].get("d"),
        None,
        "the published key set carries no private material"
    );
}

/// A credential the issuer did not sign is refused, and the refusal names only
/// the closed public code.
#[tokio::test]
async fn a_tampered_credential_is_refused_without_detail() {
    let deployment = start(resolved_source_answer()).await;
    let mut tampered = deployment.token();
    let last = tampered.pop().expect("the credential has a signature");
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    let client = deployment.client(&tampered);

    let error = client
        .discover()
        .await
        .expect_err("a credential that fails signature verification is refused");
    let EvidenceClientError::Denied {
        status,
        code,
        trace_id,
        retry_after_seconds,
    } = error
    else {
        panic!("the refusal maps onto the denied failure");
    };
    assert_eq!(status, 401);
    assert_eq!(code, "auth.invalid_credential");
    assert!(trace_id.is_some_and(|trace_id| !trace_id.is_empty()));
    assert_eq!(retry_after_seconds, None);
}

/// A valid credential the deployment does not entitle is refused at the request
/// endpoint. Discovery answers it, with nothing in it.
#[tokio::test]
async fn a_credential_without_the_configured_tag_is_refused() {
    let deployment = start(resolved_source_answer()).await;
    let entitled = deployment.client(&deployment.token());
    let unentitled = deployment.client(&deployment.token_with_tags(&["other-agency"]));

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = entitled.discover().await?;
        let visible = unentitled.discover().await?;
        let prepared = unentitled.prepare(spec(
            &definitions,
            "unentitled",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        Ok((visible, unentitled.request_and_verify(&prepared).await))
    }
    .await;
    let (visible, refusal) = proof.expect("both callers authenticate");

    assert!(
        visible.definitions.is_empty(),
        "discovery lists only what the caller may invoke"
    );
    let EvidenceClientError::Denied { status, code, .. } =
        refusal.expect_err("an unentitled caller cannot request evidence")
    else {
        panic!("the refusal maps onto the denied failure");
    };
    assert_eq!(status, 403);
    assert_eq!(code, "evidence.denied");
}

/// The unavailable answer is its own failure, distinct from a refusal, and it
/// must not be read as a statement about the subject.
#[tokio::test]
async fn a_request_the_deployment_cannot_answer_reports_no_evidence() {
    let deployment = start(unresolved_source_answer()).await;
    let client = deployment.client(&deployment.token());

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let prepared = client.prepare(spec(
            &definitions,
            "unresolved",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        Ok(client.request_and_verify(&prepared).await)
    }
    .await;
    let refusal = proof.expect("the deployment answers");

    let EvidenceClientError::NotAvailable { trace_id } =
        refusal.expect_err("an unresolved request produces no evidence")
    else {
        panic!("the unavailable answer maps onto its own failure");
    };
    assert!(trace_id.is_some_and(|trace_id| !trace_id.is_empty()));
}

/// A nonce identifies exactly one request. A real signed response that verifies
/// against its own prepared request must not verify against another one, which
/// is why a retry has to be a fresh `prepare` rather than a resend.
#[tokio::test]
async fn a_response_cannot_verify_against_another_prepared_request() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let sent = client.prepare(spec(
            &definitions,
            "nonce-check",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        let other = client.prepare(spec(
            &definitions,
            "nonce-check",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        let response = client.send(&sent).await?;
        Ok((
            client.verify(&sent, &response),
            client.verify(&other, &response),
        ))
    }
    .await;
    let (own, foreign) = proof.expect("the deployment answers the request that was sent");

    own.expect("the response verifies against the request it answered");
    assert_eq!(
        foreign.expect_err("the response cannot answer a request it never saw"),
        EvidenceClientError::Verification(VerificationError::Policy),
    );
}

/// The same bytes that verify from the deployment are refused when they arrive
/// under a media type the response contract does not use. The real runtime
/// cannot emit that, so the replay comes from a stub; the bytes are the
/// runtime's own.
#[tokio::test]
async fn a_response_under_the_wrong_media_type_is_refused() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let prepared = client.prepare(spec(
            &definitions,
            "media-type",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        let response = client.send(&prepared).await?;
        client.verify(&prepared, &response)?;

        let replay = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/evidence"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(response.body().to_vec(), "application/json"),
            )
            .mount(&replay)
            .await;
        let replayed = EvidenceClient::new(EvidenceClientConfig::new(
            Url::parse(&replay.uri())?,
            Arc::new(StaticToken::new(deployment.token())?),
            deployment.runtime.jwks().clone(),
            Vec::new(),
        ))?;
        // A prepared request is good for one send, and the one above is spent,
        // so the replay leg carries its own. The media type is refused before
        // anything about the request is compared to anything in the response.
        let replayed_request = replayed.prepare(spec(
            &definitions,
            "media-type",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        Ok(replayed.send(&replayed_request).await)
    }
    .await;
    let refusal = proof.expect("the deployment answers and the stub replays");

    let EvidenceClientError::Protocol { status, code, .. } =
        refusal.expect_err("a response outside the contract's media type is refused")
    else {
        panic!("a contract violation maps onto the protocol failure");
    };
    assert_eq!(status, 200);
    assert_eq!(code, None);
}

/// The response bound is the relying party's, enforced before the body is
/// parsed.
#[tokio::test]
async fn a_response_beyond_the_configured_bound_is_refused() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());
    let bounded = deployment.bounded_client(&deployment.token(), 64);

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let prepared = bounded.prepare(spec(
            &definitions,
            "bounded",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        Ok(bounded.send(&prepared).await)
    }
    .await;
    let refusal = proof.expect("the deployment answers");

    assert_eq!(
        refusal.expect_err("a response past the bound is refused"),
        EvidenceClientError::Transport {
            kind: TransportKind::ResponseTooLarge
        },
    );
}

/// The whole chain, with no credential this suite signed: the provider proves who
/// it is to a real authorization server with a signed assertion, the server issues
/// an access token, and the deployment accepts that token for an exchange whose
/// response verifies.
#[tokio::test]
async fn an_acquired_credential_completes_a_verified_exchange() {
    let issuer = start_token_issuer().await;
    let deployment = start_trusting(resolved_source_answer(), Some(&issuer.origin)).await;
    let client = deployment.client_using(issuer.provider());

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let prepared = client.prepare(spec(
            &definitions,
            "acquired-credential",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        Ok(client.request_and_verify(&prepared).await?)
    }
    .await;
    let accepted = proof.expect("the acquired credential is accepted and the response verifies");

    let evidence = accepted.evidence();
    assert_eq!(evidence.supports_requirement, REQUIREMENT);
    assert_eq!(evidence.supported_values.len(), 1);
    assert_eq!(
        evidence.supported_values[0].value,
        PublicValue::Boolean(true)
    );
    // The audience is the one the authorization server registered for this
    // client, not one the request could choose: the deployment compares the two
    // and refuses a mismatch. Reaching a verified response therefore proves the
    // acquired credential carried the registered identity.
    assert_eq!(evidence.audience, Some(RELYING_AUDIENCE.to_owned()));
    assert_eq!(evidence.subjects.len(), 1);
    assert!(evidence.subjects[0].binding.starts_with(BINDING_PREFIX));
}

/// A profile owns only application configuration while public service metadata
/// closes the rest of the request. The in-memory key is the secret-manager seam:
/// no client key is copied into the profile written for this exchange.
#[tokio::test]
async fn a_local_profile_completes_first_use_then_matches_the_opaque_receipt() {
    let issuer = start_token_issuer().await;
    let deployment =
        start_trusting_with_request_burst(resolved_source_answer(), Some(&issuer.origin), 100)
            .await;
    let profile_directory = tempfile::tempdir().expect("create an owner-only profile directory");
    fs::set_permissions(profile_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("the profile directory is owner-only");
    let profile_path = profile_directory.path().join("client.json");
    fs::write(
        &profile_path,
        serde_json::to_vec_pretty(&json!({
            "schema": "registry.evidence-client-profile/v1",
            "baseUrl": deployment.base_url.as_str().trim_end_matches('/'),
            "clientId": CLIENT_ID,
            "privateKey": {"source": "file", "path": "unused-by-in-memory-key.jwk"},
            "trust": {"type": "local-loopback-discovery"},
            "contracts": {"type": "published"},
            "verification": {
                "maximumAssertionLifetimeSeconds": MAXIMUM_ASSERTION_LIFETIME_SECONDS,
                "clockSkewSeconds": CLOCK_SKEW_SECONDS
            }
        }))
        .expect("the profile serializes"),
    )
    .expect("write the owner-only profile");
    fs::set_permissions(&profile_path, fs::Permissions::from_mode(0o600))
        .expect("the profile is owner-only");

    let client =
        EvidenceClient::from_profile_path_with_key(&profile_path, issuer.client_key.clone())
            .expect("the local profile and in-memory registered key configure the client");
    let request = || {
        AudienceScopedRequest::new(
            "adult-status",
            std::collections::BTreeMap::from([
                (
                    "given_name".to_owned(),
                    SelectorValue::from("synthetic-reader"),
                ),
                (
                    "family_name".to_owned(),
                    SelectorValue::from("synthetic-reader"),
                ),
                ("birth_date".to_owned(), SelectorValue::from("2000-01-01")),
            ]),
        )
    };

    let (first, concurrent_first) =
        tokio::join!(client.request(request()), client.request(request()));
    let first = first.expect("the profile-driven first use obtains and verifies an assertion");
    let concurrent_first = concurrent_first
        .expect("a concurrent profile-driven request obtains and verifies an assertion");
    let (first_artifact, first_nonce, receipt) = match first {
        VerifiedAudienceScopedEvidence::Assertion(verified) => {
            assert!(
                !verified.assertion_bytes().is_empty(),
                "the exact JWS bytes are retained"
            );
            let artifact: Value = serde_json::from_slice(verified.assertion_bytes())
                .expect("the retained response is flattened JWS JSON");
            assert!(artifact["protected"].is_string());
            assert!(artifact["payload"].is_string());
            assert!(artifact["signature"].is_string());
            assert_eq!(verified.values().len(), 1);
            assert_eq!(
                verified.value().expect("one published output"),
                &PublicValue::Boolean(true)
            );
            assert!(
                verified.trace_id().is_some(),
                "the verified result carries the trace id"
            );
            let receipt = match verified.subject_continuity() {
                SubjectContinuity::FirstUse { receipt } => receipt.clone(),
                SubjectContinuity::Matched { .. } => panic!("the first result cannot be matched"),
            };
            (
                verified.assertion_bytes().to_vec(),
                verified.evidence().request_nonce.clone(),
                receipt,
            )
        }
        VerifiedAudienceScopedEvidence::Credential(_) => panic!("signed JWS is the default"),
    };
    match concurrent_first {
        VerifiedAudienceScopedEvidence::Assertion(verified) => {
            assert_ne!(verified.assertion_bytes(), first_artifact.as_slice());
            assert_ne!(verified.evidence().request_nonce, first_nonce);
            assert!(matches!(
                verified.subject_continuity(),
                SubjectContinuity::FirstUse { .. }
            ));
        }
        VerifiedAudienceScopedEvidence::Credential(_) => panic!("signed JWS is the default"),
    }

    let matched_jws = client
        .request(request().with_binding_receipt(receipt.clone()))
        .await
        .expect("the application-owned receipt pins the second request");
    match matched_jws {
        VerifiedAudienceScopedEvidence::Assertion(verified) => {
            assert_ne!(verified.assertion_bytes(), first_artifact.as_slice());
            assert_ne!(verified.evidence().request_nonce, first_nonce);
            assert!(matches!(
                verified.subject_continuity(),
                SubjectContinuity::Matched { .. }
            ));
        }
        VerifiedAudienceScopedEvidence::Credential(_) => panic!("signed JWS is the default"),
    }
    let matched_sd_jwt = client
        .request(
            request()
                .with_response_format(EvidenceResponseFormat::SdJwtVc)
                .with_binding_receipt(receipt),
        )
        .await
        .expect("the same request can return an audience-scoped credential");
    match matched_sd_jwt {
        VerifiedAudienceScopedEvidence::Credential(verified) => {
            assert!(!verified.credential().is_empty());
            assert_eq!(verified.credential().split('.').count(), 3);
            assert_eq!(verified.values().len(), 1);
            assert_eq!(
                verified.value().expect("one published output"),
                &PublicValue::Boolean(true)
            );
            assert!(matches!(
                verified.subject_continuity(),
                SubjectContinuity::Matched { .. }
            ));
        }
        VerifiedAudienceScopedEvidence::Assertion(_) => panic!("the selected format is SD-JWT VC"),
    }
    assert_eq!(
        issuer.issued_credential_count(),
        1,
        "one cached client-credentials token carries concurrent and matched high-level requests"
    );

    let mut reviewed = serde_json::to_value(
        client
            .contracts_candidate()
            .await
            .expect("the authenticated deployment publishes a contract candidate"),
    )
    .expect("the candidate serializes");
    reviewed["definitions"][0]["configurationRevision"] =
        Value::String(format!("sha256:{}", "0".repeat(64)));
    let reviewed_path = profile_directory.path().join("reviewed-contracts.json");
    fs::write(
        &reviewed_path,
        serde_json::to_vec(&reviewed).expect("the reviewed catalog serializes"),
    )
    .expect("write the owner-owned reviewed catalog");
    fs::set_permissions(&reviewed_path, fs::Permissions::from_mode(0o600))
        .expect("the reviewed catalog is owner-only");
    let reviewed_profile_path = profile_directory.path().join("reviewed-client.json");
    fs::write(
        &reviewed_profile_path,
        serde_json::to_vec(&json!({
            "schema": "registry.evidence-client-profile/v1",
            "baseUrl": deployment.base_url.as_str().trim_end_matches('/'),
            "clientId": CLIENT_ID,
            "privateKey": {"source": "file", "path": "unused-by-in-memory-key.jwk"},
            "trust": {"type": "local-loopback-discovery"},
            "contracts": {"type": "reviewed", "file": "reviewed-contracts.json"},
            "verification": {
                "maximumAssertionLifetimeSeconds": MAXIMUM_ASSERTION_LIFETIME_SECONDS,
                "clockSkewSeconds": CLOCK_SKEW_SECONDS
            }
        }))
        .expect("the reviewed profile serializes"),
    )
    .expect("write the reviewed profile");
    fs::set_permissions(&reviewed_profile_path, fs::Permissions::from_mode(0o600))
        .expect("the reviewed profile is owner-only");
    let reviewed_client = EvidenceClient::from_profile_path_with_key(
        &reviewed_profile_path,
        issuer.client_key.clone(),
    )
    .expect("the reviewed profile configures the client");
    let fresh_candidate = reviewed_client
        .contracts_candidate()
        .await
        .expect("a reviewed profile can still fetch a fresh published candidate");
    assert_ne!(
        fresh_candidate.definitions[0].configuration_revision,
        format!("sha256:{}", "0".repeat(64)),
        "candidate fetching must not copy the already-reviewed catalog"
    );
    let reviewed_result = reviewed_client.request(request()).await;
    let Err(reviewed_error) = reviewed_result else {
        panic!("a reviewed revision cannot silently adopt a live revision");
    };
    assert_eq!(
        reviewed_error,
        EvidenceClientError::Verification(VerificationError::Policy)
    );
}

/// A credential is acquired once and reused while it has life left. Two whole
/// exchanges are four requests, and every one of them presents the one credential
/// the authorization server issued.
#[tokio::test]
async fn a_cached_credential_serves_every_request_inside_its_window() {
    let issuer = start_token_issuer().await;
    let deployment = start_trusting(resolved_source_answer(), Some(&issuer.origin)).await;
    let client = deployment.client_using(issuer.provider());

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let first = client.prepare(spec(
            &definitions,
            "cached-credential",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        let accepted = client.request_and_verify(&first).await?;
        let again = client.discover().await?;
        let second = client.prepare(spec(
            &again,
            "cached-credential",
            SubjectExpectations::Pinned(accepted.pinned_subject_expectations()),
        ))?;
        client.request_and_verify(&second).await?;
        Ok(())
    }
    .await;
    proof.expect("both exchanges are accepted and verify");

    assert_eq!(
        issuer.issued_credential_count(),
        1,
        "four requests inside the cache window asked the authorization server once"
    );
}

/// A credential with less life left than the refresh margin is replaced rather
/// than presented, and the replacement is one the deployment accepts.
///
/// A margin wider than the issuer's whole token lifetime puts every credential
/// inside it as soon as it arrives, which is the state an expiring credential
/// reaches on its own. The boundary itself is driven against a movable clock in
/// the crate's own suite; what this proves is that acquiring again against a real
/// server yields a working credential rather than a stale or refused one.
#[tokio::test]
async fn a_credential_inside_the_refresh_margin_is_replaced() {
    let issuer = start_token_issuer().await;
    let deployment = start_trusting(resolved_source_answer(), Some(&issuer.origin)).await;
    let provider = issuer.provider_with_refresh_margin(ISSUED_TOKEN_LIFETIME_SECONDS * 2);
    let client = deployment.client_using(Arc::clone(&provider) as Arc<dyn TokenProvider>);

    let proof: Result<_, Box<dyn Error>> = async {
        let first = provider.bearer_token().await?;
        let second = provider.bearer_token().await?;
        let definitions = client.discover().await?;
        let prepared = client.prepare(spec(
            &definitions,
            "refreshed-credential",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        let accepted = client.request_and_verify(&prepared).await?;
        Ok((first, second, accepted))
    }
    .await;
    let (first, second, accepted) =
        proof.expect("each acquisition is accepted and the last response verifies");

    // The issuer states a lifetime, so each acquisition is cached; the margin
    // configured above is twice that lifetime, so a cached credential is
    // already outside it the moment it lands. Two direct acquisitions, then
    // one for discovery and one for the request: every one of the four finds
    // the cache unusable and asks the server for its own.
    assert_eq!(issuer.issued_credential_count(), 4);
    assert_eq!(
        accepted.evidence().supports_requirement,
        REQUIREMENT,
        "the replacement credential is one the deployment accepts"
    );
    // Neither acquisition can be printed, which is what keeps a credential out of
    // a test log as much as out of a production one.
    assert_eq!(format!("{first:?}"), "BearerToken { .. }");
    assert_eq!(format!("{second:?}"), "BearerToken { .. }");
}

/// An ES256 client key authenticates against a real token endpoint and carries a
/// request all the way to a verified assertion.
///
/// This is the key an adopter actually holds: `evidencectl access client add
/// --generate-local-key` writes a P-256/ES256 JWK, and the published tutorial
/// feeds that file straight into this provider. The client therefore has to sign
/// with what the key states rather than one fixed algorithm, and the proof that
/// it does is a real server accepting the assertion, not a header assertion in a
/// unit test.
#[tokio::test]
async fn an_es256_client_key_authenticates_and_carries_a_request() {
    let issuer = start_token_issuer().await;
    let deployment = start_trusting(resolved_source_answer(), Some(&issuer.origin)).await;
    let client =
        deployment.client_using(issuer.provider_signing_with(issuer.es256_client_key.clone()));

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let prepared = client.prepare(spec(
            &definitions,
            "es256-client-key",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        Ok(client.request_and_verify(&prepared).await?)
    }
    .await;
    let accepted = proof.expect("the ES256 client authenticates and the response verifies");

    assert_eq!(
        accepted.evidence().supports_requirement,
        REQUIREMENT,
        "the deployment accepted the credential the ES256 assertion bought"
    );
    // One acquisition covers both discovery and the request: the credential the
    // ES256 assertion bought is cached and still inside its window for the
    // second. That it is one rather than none is what says the server
    // authenticated this key at all.
    assert_eq!(issuer.issued_credential_count(), 1);
}

/// A client whose key the authorization server never registered acquires
/// nothing, and the failure is the registered OAuth code. This is proven
/// against the issuer's own audit chain, which records zero credentials
/// issued; it does not observe the Evidence deployment's own request count,
/// only that `discover` returns the token failure before it would reach one.
#[tokio::test]
async fn an_unregistered_client_key_is_refused_without_detail() {
    let issuer = start_token_issuer().await;
    let deployment = start_trusting(resolved_source_answer(), Some(&issuer.origin)).await;
    // The registered key identifier over key material the server has never seen,
    // so the assertion is refused on its signature rather than for naming a key
    // the server cannot find.
    let unregistered = generate_key(CLIENT_KEY_ID);
    let client = deployment.client_using(issuer.provider_signing_with(unregistered));

    let refusal = client
        .discover()
        .await
        .expect_err("a client the server cannot authenticate acquires no credential");

    assert_eq!(
        refusal,
        EvidenceClientError::Token(TokenError::Refused {
            code: OAuthErrorCode::InvalidClient
        }),
    );
    assert_eq!(
        refusal.to_string(),
        "the authorization server declined to issue a token: invalid_client",
        "the refusal reports the registered code and nothing else"
    );
    assert_eq!(issuer.issued_credential_count(), 0);
}

// ---------------------------------------------------------------------------
// Request specifications
// ---------------------------------------------------------------------------

/// Build a request specification from the deployment's own definitions
/// document.
///
/// Everything except the audience and the subject expectations comes from the
/// published definition, which is what a relying party reads once while
/// authoring its procedure. The audience is the relying party's own registered
/// identifier, which the deployment takes from the authenticated caller.
fn spec(
    definitions: &EvidenceDefinitionsDocument,
    subject_label: &str,
    subject_expectations: SubjectExpectations,
) -> EvidenceRequestSpec {
    let definition = definitions
        .definition(REQUIREMENT)
        .expect("the requester is entitled to the fixture requirement");
    EvidenceRequestSpec {
        response_format: registry_evidence_client::EvidenceResponseFormat::SignedJws,
        requirement: definition.requirement.clone(),
        purpose: definition.purpose.clone(),
        audience: RELYING_AUDIENCE.to_owned(),
        evidence_type: definition.evidence_type.clone(),
        issued_by: definitions.issued_by.clone(),
        provided_by: definitions.provided_by.clone(),
        configuration_revision: definition.configuration_revision.clone(),
        expected_assurance_profile: definitions.assurance_profile,
        subjects: definition
            .subjects
            .iter()
            .map(|subject| SubjectRequest {
                role: subject.role.clone(),
                selector_profile: subject.selector.profile.clone(),
                selector_values: Some(
                    subject
                        .selector
                        .fields
                        .iter()
                        .map(|field| {
                            (
                                field.name().to_owned(),
                                selector_value(field, subject_label),
                            )
                        })
                        .collect(),
                ),
            })
            .collect(),
        holder_keys: Vec::new(),
        expected_outputs: definition
            .concepts
            .iter()
            .map(|concept| {
                concept
                    .scalar_expected_output()
                    .expect("the fixture publishes one scalar concept")
            })
            .collect(),
        maximum_assertion_lifetime_seconds: MAXIMUM_ASSERTION_LIFETIME_SECONDS,
        clock_skew_seconds: CLOCK_SKEW_SECONDS,
        subject_expectations,
    }
}

/// A synthetic value for one published selector field.
///
/// Selector values are the relying party's own lookup input. The fixed source in
/// this suite answers on method and path alone, so only the published field
/// metadata constrains them, and two different labels name two different
/// subjects to the deployment.
fn selector_value(field: &SelectorField, subject_label: &str) -> SelectorValue {
    match field {
        SelectorField::String {
            name,
            minimum_bytes,
            maximum_bytes,
        } => {
            let value = format!("synthetic-{subject_label}");
            let length = u64::try_from(value.len()).expect("the value length fits");
            assert!(
                (*minimum_bytes..=*maximum_bytes).contains(&length),
                "the synthetic value for {name} is within the published bounds"
            );
            SelectorValue::from(value)
        }
        SelectorField::Date { .. } => SelectorValue::from("2000-01-01"),
        SelectorField::Integer { minimum, .. } => SelectorValue::from(*minimum),
        SelectorField::Boolean { .. } => SelectorValue::from(true),
        SelectorField::ControlledCode { name, .. } => {
            panic!("the fixture selector profile publishes no controlled code field: {name}")
        }
    }
}

// ---------------------------------------------------------------------------
// Shared loopback harness
// ---------------------------------------------------------------------------

/// Reserve an ephemeral loopback port and read it back.
///
/// The caller has to know the port before it authors the deployment that will
/// be served on it, so the listener is returned rather than dropped here. Hold
/// it until immediately before the real service binds the same port.
fn reserve_loopback_port() -> (TcpListener, u16) {
    let reservation = TcpListener::bind(("127.0.0.1", 0)).expect("reserve a loopback port");
    let port = reservation
        .local_addr()
        .expect("read the reserved address")
        .port();
    (reservation, port)
}

/// Ask a spawned service to stop and abandon its task.
///
/// A drop cannot await the graceful stop, so the task is aborted rather than
/// joined. Taking the shutdown sender is what makes this safe to call from a
/// `Drop` impl more than once.
fn stop_service(
    shutdown: &mut Option<tokio::sync::oneshot::Sender<()>>,
    server: &tokio::task::JoinHandle<std::io::Result<()>>,
) {
    if let Some(shutdown) = shutdown.take() {
        let _ = shutdown.send(());
    }
    server.abort();
}

// ---------------------------------------------------------------------------
// The deployment harness
// ---------------------------------------------------------------------------

/// One real Evidence deployment, serving on loopback for the life of one test.
struct Deployment {
    /// Both the token issuer's key source and the deployment's fixed source.
    /// One server keeps the issuer on the canonical loopback origin the local
    /// assurance profile requires, and its uri is that origin.
    _source: MockServer,
    issuer: String,
    auth_key: PrivateJwk,
    base_url: Url,
    runtime: Arc<EvidenceRuntime>,
    bundle_root: PathBuf,
    runtime_path: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    /// Held so the deployment on disk outlives the runtime that reads it.
    _directory: tempfile::TempDir,
}

impl Deployment {
    /// A client pinned to this deployment's published verification keys.
    ///
    /// Pinning the runtime's own key set is the out-of-band review this suite
    /// stands in for: the keys are taken from the runtime object, not from the
    /// response being verified.
    fn client(&self, access_token: &str) -> EvidenceClient {
        self.build_client(access_token, None)
    }

    /// The same client under a smaller response bound.
    fn bounded_client(&self, access_token: &str, max_response_bytes: u64) -> EvidenceClient {
        self.build_client(access_token, Some(max_response_bytes))
    }

    /// A client that acquires its credential from a provider rather than
    /// presenting one this suite signed.
    fn client_using(&self, token_provider: Arc<dyn TokenProvider>) -> EvidenceClient {
        EvidenceClient::new(EvidenceClientConfig::new(
            self.base_url.clone(),
            token_provider,
            self.runtime.jwks().clone(),
            Vec::new(),
        ))
        .expect("the client configuration is usable")
    }

    fn build_client(&self, access_token: &str, max_response_bytes: Option<u64>) -> EvidenceClient {
        let mut config = EvidenceClientConfig::new(
            self.base_url.clone(),
            Arc::new(StaticToken::new(access_token).expect("the credential is header-safe")),
            self.runtime.jwks().clone(),
            Vec::new(),
        );
        if let Some(max_response_bytes) = max_response_bytes {
            config = config.with_max_response_bytes(max_response_bytes);
        }
        EvidenceClient::new(config).expect("the client configuration is usable")
    }

    /// A credential the deployment entitles.
    fn token(&self) -> String {
        self.token_with_tags(&[CONFIGURED_TAG])
    }

    /// A credential this suite signed, carrying the requester tags given.
    ///
    /// The deployment accepts it only where the suite is the issuer it trusts. A
    /// deployment pointed at an external authorization server publishes a key set
    /// this key is not in, so its credentials come from that server instead.
    fn token_with_tags(&self, requester_tags: &[&str]) -> String {
        let now = Utc::now().timestamp();
        let claims = json!({
            "iss": self.issuer,
            "aud": TOKEN_AUDIENCE,
            "sub": PRINCIPAL,
            "iat": now - 1,
            "exp": now + 60,
            "evidence_tags": requester_tags,
            "evidence_audience": RELYING_AUDIENCE,
        });
        let header = json!({"alg": "EdDSA", "kid": AUTH_KEY_ID, "typ": "at+jwt"});
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("the header serializes")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("the claims serialize")),
        );
        let signature = sign(signing_input.as_bytes(), &self.auth_key).expect("the issuer signs");
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }
}

impl Drop for Deployment {
    fn drop(&mut self) {
        // The temporary deployment the abandoned task reads is removed below,
        // and the process ends with the test binary.
        stop_service(&mut self.shutdown, &self.server);
        // The runtime requires an immutable deployment, so the staged tree was
        // sealed. Restoring write permission is what lets the temporary
        // directory be removed; a failure here leaves a directory behind for
        // the test host to reclaim, and a drop has nowhere to report it.
        let _ = fs::set_permissions(&self.runtime_path, fs::Permissions::from_mode(0o644));
        unseal(&self.bundle_root);
    }
}

/// Stage, seal, load, and serve one deployment whose fixed source answers with
/// `source_answer`, trusting this suite as its token issuer.
async fn start(source_answer: Value) -> Deployment {
    start_trusting(source_answer, None).await
}

/// The same deployment, trusting the token issuer at `external_issuer` when one
/// is named.
///
/// Without one the suite publishes its own key set beside the fixed source and
/// signs the credentials it presents. With one, the deployment fetches keys from
/// that origin and only credentials that server issued are accepted.
async fn start_trusting(source_answer: Value, external_issuer: Option<&str>) -> Deployment {
    start_trusting_with_request_burst(source_answer, external_issuer, 10).await
}

/// Start a deployment with an explicit request burst ceiling.
///
/// The progressive profile journey deliberately performs several authenticated
/// metadata and assertion exchanges against one deployment. Giving that test a
/// larger budget keeps its final contract-drift assertion independent of the
/// runtime scheduler while every ordinary deployment retains the fixture limit.
async fn start_trusting_with_request_burst(
    source_answer: Value,
    external_issuer: Option<&str>,
    request_burst: u32,
) -> Deployment {
    let source = MockServer::start().await;
    let auth_key = generate_key(AUTH_KEY_ID);
    let issuer = match external_issuer {
        Some(origin) => origin.to_owned(),
        None => {
            // The issuer's key set and the fixed source share this origin. Under
            // the local assurance profile the authentication issuer must be a
            // canonical loopback HTTP origin, which is exactly what a wiremock
            // server publishes.
            Mock::given(method("GET"))
                .and(path("/.well-known/jwks.json"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({"keys": [auth_key.public()]})),
                )
                .mount(&source)
                .await;
            source.uri()
        }
    };

    // Matched on method and path only. The request the adapter builds is the
    // runtime's own contract, proven by the runtime's suite; re-pinning it here
    // would test the fixture rather than this client.
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(source_answer))
        .mount(&source)
        .await;

    // Hold the allocation while the matching deployment is authored, and
    // release it only immediately before the service binds it.
    let (reservation, port) = reserve_loopback_port();

    let directory = tempfile::tempdir().expect("temporary deployment root");
    let bundle_root = directory.path().join("bundle");
    let secret_root = directory.path().join("secrets");
    let runtime_path = directory.path().join("runtime.yaml");
    let audit_path = directory.path().join("audit.jsonl");
    fs::create_dir(&bundle_root).expect("create the bundle root");
    fs::create_dir(&secret_root).expect("create the secret root");
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("the secret root is owner-only");
    copy_tree(&fixture_root(), &bundle_root);
    let (signing_key, signing_public) = service_key();
    let signing_key_id = signing_public
        .kid
        .as_deref()
        .expect("the service key has a thumbprint");
    rewrite_for_local_profile(
        &bundle_root,
        &source.uri(),
        &issuer,
        &format!("http://127.0.0.1:{port}"),
        signing_key_id,
    );
    rewrite_request_burst(&bundle_root, request_burst);
    fs::remove_file(
        bundle_root
            .join("public-keys")
            .join(format!("{FIXTURE_SIGNING_KEY_ID}.jwk.json")),
    )
    .expect("remove the tracked fixture public key");
    fs::write(
        bundle_root
            .join("public-keys")
            .join(format!("{signing_key_id}.jwk.json")),
        serde_json::to_vec(&signing_public).expect("the public key serializes"),
    )
    .expect("write the staged Evidence public key");

    write_secret(
        &secret_root,
        "audit-hash-key",
        "audit-hash-secret-canary-32-bytes-minimum",
    );
    write_secret(
        &secret_root,
        "subject-binding-key",
        "subject-binding-secret-canary-32-bytes-minimum",
    );
    write_secret(&secret_root, "signing-key", &signing_key);
    write_secret(&secret_root, "source-a-token", SOURCE_BEARER);
    fs::write(
        &runtime_path,
        runtime_document(port, &bundle_root, &secret_root, &audit_path),
    )
    .expect("write the runtime configuration");
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444))
        .expect("the runtime configuration is immutable");
    seal(&bundle_root);

    let runtime = Arc::new(
        EvidenceRuntime::initialize(&runtime_path)
            .await
            .expect("the staged local deployment initializes"),
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let served = Arc::clone(&runtime);
    let port_handoff = LOOPBACK_PORT_HANDOFF.lock().await;
    drop(reservation);
    let server = tokio::spawn(async move {
        server::serve(served, async {
            let _ = shutdown_rx.await;
        })
        .await
    });

    let deployment = Deployment {
        _source: source,
        issuer,
        auth_key,
        base_url: Url::parse(&format!("http://127.0.0.1:{port}")).expect("the base URL parses"),
        runtime,
        bundle_root,
        runtime_path,
        shutdown: Some(shutdown_tx),
        server,
        _directory: directory,
    };
    await_readiness(
        "the deployment",
        deployment
            .base_url
            .join("ready")
            .expect("the readiness URL resolves"),
        &deployment.server,
    )
    .await;
    drop(port_handoff);
    deployment
}

fn rewrite_request_burst(bundle_root: &Path, request_burst: u32) {
    let configuration_path = bundle_root.join("evidence.yaml");
    let mut document =
        fs::read_to_string(&configuration_path).expect("the staged configuration is readable");
    replace_exact(
        &mut document,
        "burstPerPrincipal: 10",
        &format!("burstPerPrincipal: {request_burst}"),
        1,
    );
    fs::write(&configuration_path, document).expect("the request burst is written");
}

/// Wait until the service reports itself ready, or fail with the reason it did
/// not.
async fn await_readiness(
    label: &str,
    ready: Url,
    server: &tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let probe = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .expect("the readiness probe client builds");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                !server.is_finished(),
                "{label} stopped before it reported readiness"
            );
            if probe
                .get(ready.clone())
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{label} reports readiness"));
}

// ---------------------------------------------------------------------------
// The token issuer harness
// ---------------------------------------------------------------------------

/// One real authorization server, issuing access tokens on loopback for the life
/// of one test.
///
/// It is the reference issuer for this stack, driven here as an ordinary OAuth 2.0
/// token endpoint: the provider under test carries nothing specific to it, and any
/// server accepting the `client_credentials` grant with the `private_key_jwt`
/// authentication method would serve.
struct TokenIssuer {
    origin: String,
    token_endpoint: Url,
    /// The key the registered client signs its assertions with.
    client_key: PrivateJwk,
    /// A second key registered to the same client, signing with ES256.
    es256_client_key: PrivateJwk,
    /// The issuer's own audit chain, which is where a released credential is
    /// recorded and therefore how this suite counts what it issued.
    audit_path: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    /// Held so the deployment on disk outlives the service that reads it.
    _directory: tempfile::TempDir,
}

impl TokenIssuer {
    /// A provider authenticating as the registered client with its own key.
    fn provider(&self) -> Arc<dyn TokenProvider> {
        self.build_provider(self.client_key.clone(), None)
    }

    /// The same provider, treating this much of a credential's life as spent.
    fn provider_with_refresh_margin(&self, seconds: i64) -> Arc<PrivateKeyJwt> {
        self.build_provider(self.client_key.clone(), Some(seconds))
    }

    /// The same provider, signing with the key given instead of the registered
    /// one.
    fn provider_signing_with(&self, client_key: PrivateJwk) -> Arc<dyn TokenProvider> {
        self.build_provider(client_key, None)
    }

    fn build_provider(
        &self,
        client_key: PrivateJwk,
        refresh_margin_seconds: Option<i64>,
    ) -> Arc<PrivateKeyJwt> {
        // The assertion audience is left to its default, which is the token
        // endpoint URL. This server requires exactly that, so the default is what
        // is under test.
        let mut config =
            PrivateKeyJwtConfig::new(self.token_endpoint.clone(), CLIENT_ID, client_key);
        if let Some(seconds) = refresh_margin_seconds {
            config = config.with_refresh_margin_seconds(seconds);
        }
        Arc::new(PrivateKeyJwt::new(config).expect("the provider configuration is usable"))
    }

    /// How many credentials this server has released.
    ///
    /// The audit chain is written before a credential leaves the endpoint, so a
    /// count taken after an exchange has settled includes every release that
    /// exchange caused.
    fn issued_credential_count(&self) -> usize {
        let chain =
            fs::read_to_string(&self.audit_path).expect("the issuer audit chain is readable");
        chain
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str::<Value>(line).expect("every audit line is one JSON envelope")
            })
            .filter(|envelope| envelope["record"]["decision"] == json!("issued"))
            .count()
    }
}

impl Drop for TokenIssuer {
    fn drop(&mut self) {
        // The temporary deployment the abandoned task reads is removed with this
        // struct, and the process ends with the test binary.
        stop_service(&mut self.shutdown, &self.server);
    }
}

/// Author, load, and serve one authorization server with a single registered
/// client whose identity matches what the Evidence fixture entitles.
async fn start_token_issuer() -> TokenIssuer {
    // Hold the allocation while the matching deployment is authored, and release
    // it only immediately before the service binds it. The issuer identity is
    // part of that deployment, so the port has to be known first.
    let (reservation, port) = reserve_loopback_port();
    let origin = format!("http://127.0.0.1:{port}");
    let token_endpoint = Url::parse(&format!("{origin}/token")).expect("the token endpoint parses");

    let directory = tempfile::tempdir().expect("temporary issuer root");
    let root = directory.path();
    let secret_root = root.join("secrets");
    fs::create_dir(&secret_root).expect("create the issuer secret root");
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("the issuer secret root is owner-only");
    fs::create_dir(root.join("clients")).expect("create the client registry");
    fs::create_dir(root.join("public-keys")).expect("create the issuer public-key directory");
    let (issuer_signing_key, issuer_public_key) = service_key();
    let issuer_key_id = issuer_public_key
        .kid
        .as_deref()
        .expect("the Mint service key has a thumbprint");
    write_secret(&secret_root, "signing.jwk", &issuer_signing_key);
    fs::write(
        root.join(format!("public-keys/{issuer_key_id}.jwk.json")),
        serde_json::to_vec(&issuer_public_key).expect("the issuer public key serializes"),
    )
    .expect("write the issuer public key");
    write_secret(
        &secret_root,
        "audit-hash-key",
        "issuer-audit-secret-canary-32-bytes-minimum",
    );

    // The registered client carries the principal, the relying-party audience, and
    // the requester tag. None of them is anything the client can ask for: the
    // deployment reads them from the credential this server issues.
    let client_key = generate_key(CLIENT_KEY_ID);
    let public_key =
        serde_json::to_string(&client_key.public()).expect("the public key serializes");
    // A second registered key for the same client, signing with ES256 rather than
    // EdDSA. This is the shape `evidencectl access client add
    // --generate-local-key` writes, so registering it here is what proves an
    // adopter's own key against a real token endpoint. The assertion's `kid`
    // selects between the two.
    let es256_client_key = generate_es256_key(ES256_CLIENT_KEY_ID);
    let es256_public_key =
        serde_json::to_string(&es256_client_key.public()).expect("the public key serializes");
    fs::write(
        root.join(format!("clients/{CLIENT_ID}.yaml")),
        format!(
            "clientId: {CLIENT_ID}\nprincipal: {PRINCIPAL}\nevidenceAudience: {RELYING_AUDIENCE}\nrequesterTags: [{CONFIGURED_TAG}]\nkeys: [{public_key}, {es256_public_key}]\n"
        ),
    )
    .expect("write the client registration");

    let config_path = root.join("mint.yaml");
    fs::write(
        &config_path,
        format!(
            r#"version: 1
validationMode: supervised-local-development
issuer: {origin}
listener: {{address: 127.0.0.1, port: {port}}}
signing:
  algorithm: ES256
  activePublicJwkFile: public-keys/{issuer_key_id}.jwk.json
  publishedPublicJwkFiles: []
  revokedKeyIds: []
signer:
  kind: local-jwk
  privateKeyRef: secret:file/signing.jwk
secretProviders:
  file:
    root: {secret_root}
audit:
  path: audit/decisions.jsonl
  maximumFileBytes: 1073741824
  hashKeyRef: secret:file/audit-hash-key
  hashKeyVersion: 1
accessTokens:
  audiences: [{TOKEN_AUDIENCE}]
  lifetimeSeconds: {ISSUED_TOKEN_LIFETIME_SECONDS}
  claims:
    principal: sub
    requesterTags: evidence_tags
    evidenceAudience: evidence_audience
    grantId: evidence_grant_id
    grantAuthority: evidence_authority
clientAssertion:
  audience: {token_endpoint}
  maximumLifetimeSeconds: 300
  algorithms: [EdDSA, ES256]
clients:
  directory: clients
"#,
            secret_root = secret_root.display(),
        ),
    )
    .expect("write the issuer configuration");

    let config = MintConfig::load(&config_path).expect("the staged issuer configuration is valid");
    let audit_path = config.audit.path.clone();
    let service = Arc::new(
        MintService::load(config)
            .await
            .expect("the staged issuer loads"),
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let port_handoff = LOOPBACK_PORT_HANDOFF.lock().await;
    drop(reservation);
    let server = tokio::spawn(async move {
        mint_server::serve(service, async {
            let _ = shutdown_rx.await;
        })
        .await
    });

    let issuer = TokenIssuer {
        origin,
        token_endpoint,
        client_key,
        es256_client_key,
        audit_path,
        shutdown: Some(shutdown_tx),
        server,
        _directory: directory,
    };
    await_readiness(
        "the token issuer",
        Url::parse(&format!("{}/ready", issuer.origin)).expect("the readiness URL parses"),
        &issuer.server,
    )
    .await;
    drop(port_handoff);
    issuer
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/fixtures/acceptance/adult-status")
}

/// Point the staged bundle at this test's source and token issuer, and lower it
/// to the local assurance profile.
///
/// The local profile is what permits a loopback token issuer. Every other
/// security decision in the bundle, including authentication, authorization,
/// selector validation, subject binding, signing, and audit, is unchanged.
fn rewrite_for_local_profile(
    bundle_root: &Path,
    source_origin: &str,
    issuer_origin: &str,
    public_origin: &str,
    signing_key_id: &str,
) {
    let configuration_path = bundle_root.join("evidence.yaml");
    let mut document =
        fs::read_to_string(&configuration_path).expect("the staged configuration is readable");
    replace_exact(
        &mut document,
        "assuranceProfile: evidence-grade",
        "assuranceProfile: local",
        1,
    );
    replace_exact(
        &mut document,
        "baseUrl: https://source.invalid",
        &format!("baseUrl: {source_origin}"),
        1,
    );
    replace_exact(
        &mut document,
        "publicOrigin: https://evidence.invalid",
        &format!("publicOrigin: {public_origin}"),
        1,
    );
    replace_exact(
        &mut document,
        "issuer: https://identity.invalid",
        &format!("issuer: {issuer_origin}"),
        1,
    );
    replace_exact(
        &mut document,
        "jwksUri: https://identity.invalid/.well-known/jwks.json",
        &format!("jwksUri: {issuer_origin}/.well-known/jwks.json"),
        1,
    );
    replace_exact(
        &mut document,
        "algorithms: [ES256]",
        "algorithms: [EdDSA, ES256]",
        1,
    );
    replace_exact(
        &mut document,
        "responseFormats: [signed-jws]",
        "responseFormats: [signed-jws, sd-jwt-vc]",
        2,
    );
    replace_exact(
        &mut document,
        &format!("activePublicJwkFile: public-keys/{FIXTURE_SIGNING_KEY_ID}.jwk.json"),
        &format!("activePublicJwkFile: public-keys/{signing_key_id}.jwk.json"),
        1,
    );
    fs::write(&configuration_path, document).expect("the local configuration is written");
    regenerate_discovery_description(bundle_root);
}

fn regenerate_discovery_description(bundle_root: &Path) {
    let config = registry_evidence::config::EvidenceConfig::parse_yaml(
        &fs::read(bundle_root.join("evidence.yaml"))
            .expect("the rewritten configuration is readable"),
    )
    .expect("the rewritten configuration validates");
    let description = registry_evidence::discovery::render(&config)
        .expect("the provider description renders")
        .expect("the acceptance publication remains configured");
    fs::write(bundle_root.join("catalog.jsonld"), description)
        .expect("the provider description is regenerated");
}

fn runtime_document(
    port: u16,
    bundle_root: &Path,
    secret_root: &Path,
    audit_path: &Path,
) -> String {
    format!(
        r#"version: 1
bundleDirectory: {bundle}
listener:
  bindHost: 127.0.0.1
  port: {port}
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file:
    root: {secrets}
signer:
  kind: local-jwk
  privateKeyRef: secret:file/signing-key
auditStorage:
  path: {audit}
  maximumFileBytes: 10485760
outboundTls:
  systemRoots: true
  trustProfiles: {{}}
"#,
        bundle = bundle_root.display(),
        secrets = secret_root.display(),
        audit = audit_path.display(),
    )
}

/// A fresh Ed25519 private JWK for an externally owned client or token issuer.
fn private_client_jwk(key_id: &str) -> String {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("the test host supplies randomness");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "kid": key_id,
        "d": URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
        "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
    })
    .to_string()
}

fn generate_key(key_id: &str) -> PrivateJwk {
    PrivateJwk::parse(&private_client_jwk(key_id)).expect("the generated key parses")
}

/// A fresh ES256 private JWK for a client, in the shape `evidencectl access
/// client add --generate-local-key` writes.
fn generate_es256_key(key_id: &str) -> PrivateJwk {
    let signing_key = SigningKey::random(&mut OsRng);
    let point = signing_key.verifying_key().to_encoded_point(false);
    let document = json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "kid": key_id,
        "d": URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("the public point has x")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("the public point has y")),
    })
    .to_string();
    PrivateJwk::parse(&document).expect("the generated key parses")
}

/// A fresh ES256 service key whose identifier is its RFC 7638 thumbprint.
fn service_key() -> (String, PublicJwk) {
    let signing_key = SigningKey::random(&mut OsRng);
    let point = signing_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().expect("the public point has x"));
    let y = URL_SAFE_NO_PAD.encode(point.y().expect("the public point has y"));
    let mut public = PublicJwk {
        kty: "EC".to_owned(),
        kid: None,
        alg: Some("ES256".to_owned()),
        crv: Some("P-256".to_owned()),
        x: Some(x.clone()),
        y: Some(y.clone()),
        n: None,
        e: None,
    };
    let key_id = public.jkt().expect("the thumbprint computes");
    public.kid = Some(key_id.clone());
    let private = json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "kid": key_id,
        "d": URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
        "x": x,
        "y": y,
    })
    .to_string();
    (private, public)
}

fn replace_exact(document: &mut String, from: &str, to: &str, expected: usize) {
    assert_eq!(
        document.matches(from).count(),
        expected,
        "fixture drift for {from}"
    );
    *document = document.replace(from, to);
}

fn write_secret(secret_root: &Path, name: &str, value: &str) {
    let path = secret_root.join(name);
    fs::write(&path, value.as_bytes()).expect("write the synthetic secret");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("the synthetic secret is owner-only");
}

fn copy_tree(source: &Path, target: &Path) {
    for entry in fs::read_dir(source).expect("the tracked fixture is readable") {
        let entry = entry.expect("the fixture entry is readable");
        let destination = target.join(entry.file_name());
        if entry
            .file_type()
            .expect("the fixture file type is readable")
            .is_dir()
        {
            fs::create_dir(&destination).expect("copy the fixture directory");
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("copy the fixture file");
        }
    }
}

/// Make the staged bundle immutable, as the runtime requires.
fn seal(root: &Path) {
    for entry in fs::read_dir(root).expect("the staged bundle is readable") {
        let entry = entry.expect("the staged entry is readable");
        let child = entry.path();
        if entry
            .file_type()
            .expect("the staged file type is readable")
            .is_dir()
        {
            seal(&child);
            fs::set_permissions(&child, fs::Permissions::from_mode(0o555))
                .expect("the bundle directory is immutable");
        } else {
            fs::set_permissions(&child, fs::Permissions::from_mode(0o444))
                .expect("the bundle file is immutable");
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o555))
        .expect("the bundle root is immutable");
}

/// Restore write permission so the temporary directory can be removed.
fn unseal(root: &Path) {
    let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o755));
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if child.is_dir() {
            unseal(&child);
        } else {
            let _ = fs::set_permissions(&child, fs::Permissions::from_mode(0o644));
        }
    }
}

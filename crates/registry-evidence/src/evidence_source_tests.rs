//! Two independently authorized Evidence runtimes, joined by a signed source.
use super::*;
use axum::{extract::Request, middleware::Next, response::Response};
use registry_evidence_client::EvidenceDefinitionsDocument;
use tokio::sync::Mutex;

const UPSTREAM_AUDIENCE: &str = "https://downstream.invalid/source-consumer";

struct ComposedRuntime {
    upstream: AcceptanceRuntime,
    downstream: PreparedFixture,
    runtime: Arc<EvidenceRuntime>,
    token_server: MockServer,
    serving: tokio::task::JoinHandle<()>,
    requests: Arc<Mutex<Vec<Value>>>,
    fault: Arc<AtomicUsize>,
}

impl Drop for ComposedRuntime {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

async fn composed_runtime() -> ComposedRuntime {
    composed_runtime_for_wallet(false).await
}

async fn composed_runtime_for_wallet(wallet: bool) -> ComposedRuntime {
    let server = MockServer::start().await;
    let mut ceilings = FixtureCeilings::deployment_defaults();
    ceilings.burst_per_principal = 30;
    let prepared = prepare_fixture_with_mutation(
        "upstream-subject-binding-secret-32-bytes-minimum",
        &server.uri(),
        &ceilings,
        |root| {
            let path = root.join("evidence.yaml");
            let mut config: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
            config["authentication"]["oidc"]["allowedClients"] = json!([BASIC_USER]);
            config["authorityProfiles"][AUTHORITY]["requesterClients"] = json!([BASIC_USER]);
            fs::write(path, serde_norway::to_string(&config).unwrap()).unwrap();
        },
    );
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(
            &prepared.runtime_path,
            authenticator_with_client_admission(None, Some(vec![BASIC_USER.to_owned()])),
        )
        .await
        .unwrap(),
    );
    let upstream = AcceptanceRuntime {
        _temporary: prepared.temporary,
        bundle_root: prepared.bundle_root,
        runtime_path: prepared.runtime_path,
        runtime,
        server,
        audit_path: prepared.audit_path,
    };
    let token = access_token_for(
        "downstream-source-service",
        Some(json!({
            "evidence_audience": UPSTREAM_AUDIENCE, "client_id": BASIC_USER
        })),
    );
    let http = TestServer::new(build_app(Arc::clone(&upstream.runtime)));
    let definitions = http
        .get("/v1/evidence-definitions")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    definitions.assert_status_ok();
    let mut contract: EvidenceDefinitionsDocument = definitions.json();
    contract
        .definitions
        .retain(|definition| definition.handle == "residence-region");
    assert_eq!(contract.definitions.len(), 1);

    let requests = Arc::new(Mutex::new(Vec::new()));
    let fault = Arc::new(AtomicUsize::new(0));
    let signer = Arc::new(
        EvidenceSigner::initialize(
            Arc::new(
                LocalJwkSigner::new(PrivateJwk::parse(EVIDENCE_PRIVATE_JWK).unwrap()).unwrap(),
            ),
            EVIDENCE_KEY_ID,
        )
        .await
        .unwrap(),
    );
    let router = build_app(Arc::clone(&upstream.runtime)).layer(axum::middleware::from_fn({
        let requests = Arc::clone(&requests);
        let fault = Arc::clone(&fault);
        move |request: Request, next: Next| {
            let requests = Arc::clone(&requests);
            let fault = Arc::clone(&fault);
            let signer = Arc::clone(&signer);
            async move {
                if request.uri().path() != "/v1/evidence" {
                    return next.run(request).await;
                }
                let (parts, body) = request.into_parts();
                assert_eq!(parts.headers["accept"], EVIDENCE_JWS_MEDIA_TYPE);
                assert!(!parts.headers.contains_key("registry-access-requester"));
                assert!(!parts.headers.contains_key("registry-access-purpose"));
                let bytes = axum::body::to_bytes(body, 65536).await.unwrap();
                requests
                    .lock()
                    .await
                    .push(serde_json::from_slice(&bytes).unwrap());
                let response = next
                    .run(Request::from_parts(parts, Body::from(bytes)))
                    .await;
                let mode = fault.load(Ordering::SeqCst);
                if mode == 0 || !response.status().is_success() {
                    return response;
                }
                let (mut parts, body) = response.into_parts();
                parts.headers.remove(axum::http::header::CONTENT_LENGTH);
                let bytes = axum::body::to_bytes(body, 65536).await.unwrap();
                // Header-only faults keep the genuinely signed body intact.
                if (12..=22).contains(&mode) {
                    let content_type = axum::http::header::CONTENT_TYPE;
                    match mode {
                        12 => {
                            parts
                                .headers
                                .insert(content_type, "Application/JOSE+JSON".parse().unwrap());
                        }
                        13 => {
                            parts.headers.insert(
                                content_type,
                                "application/jose+json; charset=utf-8".parse().unwrap(),
                            );
                        }
                        14 => {
                            parts.headers.remove(content_type);
                        }
                        15 => {
                            parts
                                .headers
                                .append(content_type, EVIDENCE_JWS_MEDIA_TYPE.parse().unwrap());
                        }
                        16 => {
                            parts
                                .headers
                                .insert(content_type, "application/jose".parse().unwrap());
                        }
                        17 => parts.status = axum::http::StatusCode::CREATED,
                        18 => parts.status = axum::http::StatusCode::PARTIAL_CONTENT,
                        19 => {
                            parts.headers.remove("traceparent");
                        }
                        20 => {
                            let traceparent = parts.headers["traceparent"].clone();
                            parts.headers.append("traceparent", traceparent);
                        }
                        21 => {
                            parts.headers.insert(
                                "traceparent",
                                "00-00000000000000000000000000000000-0123456789abcdef-01"
                                    .parse()
                                    .unwrap(),
                            );
                        }
                        22 => {
                            for index in
                                0..registry_platform_httputil::MAXIMUM_RESPONSE_HEADER_FIELDS
                            {
                                parts.headers.insert(
                                    axum::http::HeaderName::try_from(format!("x-filler-{index}"))
                                        .unwrap(),
                                    "1".parse().unwrap(),
                                );
                            }
                        }
                        _ => unreachable!(),
                    }
                    return Response::from_parts(parts, Body::from(bytes));
                }
                let jws: FlattenedJws = serde_json::from_slice(&bytes).unwrap();
                let mut payload = serde_json::to_value(decode_evidence(&jws)).unwrap();
                match mode {
                    1 => payload["requestNonce"] = json!(fresh_request_nonce()),
                    2 => payload["purpose"] = json!("different-purpose"),
                    3 => payload["audience"] = json!(EVIDENCE_AUDIENCE),
                    4 => {
                        payload["configurationRevision"] =
                            json!(format!("sha256:{}", "0".repeat(64)))
                    }
                    5 => {
                        payload["issuedAt"] =
                            json!((Utc::now() - chrono::Duration::minutes(10)).to_rfc3339());
                        payload["observedAt"] = payload["issuedAt"].clone();
                        payload["validUntil"] =
                            json!((Utc::now() - chrono::Duration::minutes(5)).to_rfc3339());
                    }
                    6 => payload["issuedBy"] = json!("https://unaccepted.invalid/issuer"),
                    7 => payload["subjects"][0]["role"] = json!("undeclared"),
                    8 => payload["supportedValues"][0]["value"] = json!(true),
                    9 | 10 => {
                        if mode == 10 {
                            parts
                                .headers
                                .insert("content-type", "application/json".parse().unwrap());
                        }
                        return Response::from_parts(
                            parts,
                            Body::from(serde_json::to_vec(&payload).unwrap()),
                        );
                    }
                    11 => {
                        let mut corrupt = serde_json::to_value(jws).unwrap();
                        corrupt["signature"] = json!(URL_SAFE_NO_PAD.encode([0; 64]));
                        return Response::from_parts(
                            parts,
                            Body::from(serde_json::to_vec(&corrupt).unwrap()),
                        );
                    }
                    _ => unreachable!(),
                }
                let modified = signer.sign_json(&payload).await.unwrap();
                Response::from_parts(parts, Body::from(serde_json::to_vec(&modified).unwrap()))
            }
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let serving = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let token_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": token, "token_type": "Bearer", "expires_in": 298
        })))
        .mount(&token_server)
        .await;
    let jwks = serde_json::to_value(upstream.runtime.jwks()).unwrap();
    let downstream = prepare_fixture_with_mutation(
        "downstream-subject-binding-secret-32-bytes-minimum",
        &origin,
        &FixtureCeilings::deployment_defaults(),
        |root| {
            configure_source(
                root,
                &contract,
                &jwks,
                &format!("{}/token", token_server.uri()),
                wallet,
            )
        },
    );
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&downstream.runtime_path, authenticator())
            .await
            .expect("downstream signed-source deployment initializes"),
    );
    ComposedRuntime {
        upstream,
        downstream,
        runtime,
        token_server,
        serving,
        requests,
        fault,
    }
}

fn configure_source(
    root: &Path,
    contract: &EvidenceDefinitionsDocument,
    jwks: &Value,
    token_endpoint: &str,
    wallet: bool,
) {
    let path = root.join("evidence.yaml");
    let mut config: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
    let source = &mut config["sources"]["source-b"];
    source["evidence"] = json!({
        "contract": contract,
        "trustedJwks": jwks,
        "maximumAssertionLifetimeSeconds": 300,
        "clockSkewSeconds": 0
    });
    source["authentication"] = json!({
        "kind": "oauth2-client-credentials",
        "tokenEndpoint": token_endpoint,
        "clientIdRef": "secret:file/source-c-username",
        "clientSecretRef": "secret:file/source-c-password",
        "scope": "evidence.read",
        "credentialPlacement": "form-body",
        "maximumCacheSeconds": 60
    });
    source["request"]["path"] = json!("/v1/evidence");
    source["request"]["fixedHeaders"] = json!([]);
    source["request"]["projection"] = json!(["/values/region"]);
    if wallet {
        config["responseFormats"]
            .as_array_mut()
            .unwrap()
            .push(json!("sd-jwt-vc"));
        for grant in config["authorityProfiles"][AUTHORITY]["grants"]
            .as_array_mut()
            .unwrap()
        {
            if grant["purpose"] == "fixture-routing" {
                grant["responseFormats"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("sd-jwt-vc"));
                grant["subjectBindingModes"] = json!(["holder-bound"]);
            }
        }
        for requirement in config["requirements"].as_array_mut().unwrap() {
            if requirement["handle"] == "residence-region" {
                requirement["subjectBinding"] = json!("holder-bound");
            }
        }
    }
    let schema: Value = serde_norway::from_slice(include_bytes!(
        "../../../products/evidence/contracts/bundle.schema.yaml"
    ))
    .unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&schema)
        .unwrap();
    if let Err(errors) = validator.validate(&config) {
        panic!(
            "signed-source deployment violates its published schema: {:?}",
            errors.map(|error| error.to_string()).collect::<Vec<_>>()
        );
    }
    fs::write(path, serde_norway::to_string(&config).unwrap()).unwrap();
    if wallet {
        regenerate_discovery_description(root);
    }
    fs::write(root.join("adapters/residence-region-prepare.rhai"), r#"
fn prepare(selectors, context) {
    #{query: [], body: #{subjects: [#{role: "subject", selector: #{
        profile: "residence-record-v1", values: #{record_reference: selectors["subject"]["values"]["record_reference"]}
    }}]}}
}
"#).unwrap();
    fs::write(
        root.join("adapters/residence-region-source.rhai"),
        r#"
fn extract(response, context) {
    #{outcome: "match", facts: #{official_residence_code: response.values.region}}
}
"#,
    )
    .unwrap();
    fs::write(root.join("derivations/residence-region.rhai"), r#"
fn derive(facts, selectors, context) {
    [#{concept_id: "urn:example:fixture:concept:residence-region", value: facts.official_residence_code}]
}
"#).unwrap();
    fs::write(
        root.join("schemas/residence-region-response.schema.yaml"),
        r#"
type: object
additionalProperties: false
required: [values]
properties:
  values:
    type: object
    additionalProperties: false
    required: [region]
    properties:
      region: {type: string, enum: [REGION-NORTH, REGION-SOUTH]}
"#,
    )
    .unwrap();
}

#[tokio::test]
async fn signed_evidence_source_composes_two_authorized_services_with_fresh_values() {
    let fixture = composed_runtime().await;
    let calls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST")).and(path("/v1/facts"))
        .respond_with({
            let calls = Arc::clone(&calls);
            move |_: &wiremock::Request| ResponseTemplate::new(200).set_body_json(json!({
                "total": 1,
                "official_residence_code": if calls.fetch_add(1, Ordering::SeqCst) == 0 { "R-101" } else { "R-201" }
            }))
        }).expect(2).mount(&fixture.upstream.server).await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    for expected in ["REGION-NORTH", "REGION-SOUTH"] {
        let request = residence_request();
        let response = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {}", access_token(None)))
            .add_header("accept", EVIDENCE_JWS_MEDIA_TYPE)
            .json(&request)
            .await;
        response.assert_status_ok();
        let bytes = response.as_bytes();
        let evidence = verify_flattened_jws(
            bytes,
            fixture.runtime.jwks(),
            &verification_policy(&fixture.runtime, &request, bytes),
        )
        .unwrap();
        assert_eq!(
            evidence.supported_values[0].value,
            PublicValue::String(expected.to_owned())
        );
        assert_eq!(evidence.audience.as_deref(), Some(EVIDENCE_AUDIENCE));
    }
    let requests = fixture.requests.lock().await;
    assert_eq!(requests.len(), 2);
    assert_ne!(requests[0]["requestNonce"], requests[1]["requestNonce"]);
    for request in requests.iter() {
        assert_eq!(request["purpose"], "fixture-routing");
        assert_eq!(
            request["subjects"],
            serde_json::to_value(residence_request().subjects).unwrap()
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(request["requestNonce"].as_str().unwrap())
                .unwrap()
                .len(),
            32
        );
    }
    let token_requests = fixture.token_server.received_requests().await.unwrap();
    assert_eq!(
        token_requests.len(),
        1,
        "existing OAuth cache remains shared"
    );
    let parameters: BTreeMap<_, _> = url::form_urlencoded::parse(&token_requests[0].body)
        .into_owned()
        .collect();
    assert_eq!(
        parameters.get("scope").map(String::as_str),
        Some("evidence.read")
    );
    assert_eq!(
        parameters.get("client_id").map(String::as_str),
        Some(BASIC_USER)
    );
    for audit_path in [&fixture.upstream.audit_path, &fixture.downstream.audit_path] {
        let audit = fs::read_to_string(audit_path).unwrap();
        assert_paired_audit_entries(&audit);
        for canary in [
            "REGION-NORTH",
            "REGION-SOUTH",
            "synthetic-residence-record-001",
            "R-101",
            "R-201",
        ] {
            assert!(!audit.contains(canary));
        }
        for request in requests.iter() {
            assert!(!audit.contains(request["requestNonce"].as_str().unwrap()));
        }
    }
}

#[tokio::test]
async fn signed_evidence_source_feeds_a_verifiable_holder_bound_credential() {
    use registry_evidence_verifier::verifier::{
        verify_sd_jwt_vc_presentation, HolderBoundPresentationPolicyDocument,
    };
    let fixture = composed_runtime_for_wallet(true).await;
    mount_residence_source(&fixture.upstream.server).await;
    let holder = PrivateJwk::parse(AUTH_PRIVATE_JWK).unwrap();
    let holder_public = holder.public();
    let holder_thumbprint = holder_public.jkt().unwrap();
    let request = residence_request();
    let mut body = serde_json::to_value(&request).unwrap();
    body["holderKeys"] = json!([holder_public]);
    let response = TestServer::new(build_app(Arc::clone(&fixture.runtime)))
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&body)
        .await;
    response.assert_status_ok();
    let credential = response.text();
    let payload = released_credential_payload(&credential);
    let challenge = fresh_request_nonce();
    let verifier_audience = "https://verifier.invalid/credential-check";
    let wallet = registry_platform_sdjwt::SdJwtIssuer::from_jwk(holder).unwrap();
    let proof = wallet.sign_compact_jwt("kb+jwt", json!({
        "aud": verifier_audience, "nonce": challenge, "iat": Utc::now().timestamp(),
        "sd_hash": URL_SAFE_NO_PAD.encode(registry_platform_sdjwt::presentation_disclosure_hash(&credential))
    })).await.unwrap();
    let config = &fixture.runtime.bundle().config;
    let policy: HolderBoundPresentationPolicyDocument = serde_json::from_value(json!({
        "subjectBinding": "holder-bound", "expectedAssuranceProfile": config.assurance_profile,
        "issuedBy": config.issuer.id, "providedBy": config.service.provider_id,
        "requirement": request.requirement,
        "evidenceType": "urn:example:fixture:evidence-type:residence-region:v1",
        "expectedIssuancePurpose": request.purpose,
        "configurationRevision": fixture.runtime.bundle().configuration_revision(&request.requirement).unwrap(),
        "expectedSubjects": payload["subjects"],
        "expectedOutputs": [{"handle": "region", "concept": "urn:example:fixture:concept:residence-region", "required": true, "form": "string"}],
        "revokedKeyIds": [], "maximumAssertionLifetimeSeconds": 300,
        "keyBindingAudience": verifier_audience, "keyBindingNonce": challenge,
        "maximumKeyBindingAgeSeconds": 300, "clockSkewSeconds": 0,
        "expectedHolderKeyThumbprint": holder_thumbprint
    })).unwrap();
    let evidence = verify_sd_jwt_vc_presentation(
        format!("{credential}{proof}").as_bytes(),
        fixture.runtime.jwks(),
        &policy.try_into_policy(Utc::now()).unwrap(),
    )
    .expect("the holder proves possession and the credential verifies");
    assert_eq!(
        evidence.supported_values[0].value,
        PublicValue::String("REGION-NORTH".to_owned())
    );
    assert!(evidence.audience.is_none());
    assert!(evidence.request_nonce.is_none());
    let upstream_requests = fixture.requests.lock().await;
    assert_eq!(upstream_requests.len(), 1);
    assert!(
        upstream_requests[0].get("holderKeys").is_none(),
        "wallet keys stay downstream"
    );
}

#[tokio::test]
async fn signed_evidence_source_refuses_untrusted_protocol_results_without_release() {
    let fixture = composed_runtime().await;
    mount_residence_source_expecting(&fixture.upstream.server, 11).await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    for mode in 1..=11 {
        fixture.fault.store(mode, Ordering::SeqCst);
        // Distinct authorized principals keep this protocol test independent
        // of the deliberately low per-principal acceptance-fixture budget.
        let response = http
            .post("/v1/evidence")
            .add_header(
                "authorization",
                format!(
                    "Bearer {}",
                    access_token_for(&format!("protocol-test-{mode}"), None)
                ),
            )
            .add_header("accept", EVIDENCE_JWS_MEDIA_TYPE)
            .json(&residence_request())
            .await;
        assert_eq!(
            response.status_code(),
            StatusCode::SERVICE_UNAVAILABLE,
            "fault {mode}: {}",
            response.text()
        );
        assert_eq!(response.json::<Value>()["code"], "source.unavailable");
    }
    let audit = fs::read_to_string(&fixture.downstream.audit_path).unwrap();
    assert!(released_evidence_ids(&audit).is_empty());
    assert!(!audit.contains("REGION-NORTH"));
    assert!(!audit.contains("synthetic-residence-record-001"));
}

#[tokio::test]
async fn signed_evidence_source_compares_the_response_media_type_essence() {
    let fixture = composed_runtime().await;
    mount_residence_source_expecting(&fixture.upstream.server, 5).await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    // 12: upper-case essence, 13: a parameter, 14: no Content-Type,
    // 15: a repeated Content-Type, 16: a different essence.
    for (mode, accepted) in [
        (12, true),
        (13, true),
        (14, false),
        (15, false),
        (16, false),
    ] {
        fixture.fault.store(mode, Ordering::SeqCst);
        let request = residence_request();
        let response = http
            .post("/v1/evidence")
            .add_header(
                "authorization",
                format!(
                    "Bearer {}",
                    access_token_for(&format!("media-type-test-{mode}"), None)
                ),
            )
            .add_header("accept", EVIDENCE_JWS_MEDIA_TYPE)
            .json(&request)
            .await;
        if accepted {
            response.assert_status_ok();
            let bytes = response.as_bytes();
            let evidence = verify_flattened_jws(
                bytes,
                fixture.runtime.jwks(),
                &verification_policy(&fixture.runtime, &request, bytes),
            )
            .unwrap();
            assert_eq!(
                evidence.supported_values[0].value,
                PublicValue::String("REGION-NORTH".to_owned()),
                "mode {mode}"
            );
        } else {
            assert_eq!(
                response.status_code(),
                StatusCode::SERVICE_UNAVAILABLE,
                "mode {mode}: {}",
                response.text()
            );
            assert_eq!(response.json::<Value>()["code"], "source.unavailable");
        }
    }
}

#[tokio::test]
async fn signed_evidence_source_accepts_only_http_200() {
    let fixture = composed_runtime().await;
    mount_residence_source_expecting(&fixture.upstream.server, 2).await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    // 17: 201 Created, 18: 206 Partial Content, each around a genuinely
    // signed body the canonical client would refuse.
    for mode in [17, 18] {
        fixture.fault.store(mode, Ordering::SeqCst);
        let response = http
            .post("/v1/evidence")
            .add_header(
                "authorization",
                format!(
                    "Bearer {}",
                    access_token_for(&format!("status-test-{mode}"), None)
                ),
            )
            .add_header("accept", EVIDENCE_JWS_MEDIA_TYPE)
            .json(&residence_request())
            .await;
        assert_eq!(
            response.status_code(),
            StatusCode::SERVICE_UNAVAILABLE,
            "mode {mode}: {}",
            response.text()
        );
        assert_eq!(response.json::<Value>()["code"], "source.unavailable");
    }
}

#[tokio::test]
async fn signed_evidence_source_refuses_untrusted_response_headers() {
    let fixture = composed_runtime().await;
    mount_residence_source_expecting(&fixture.upstream.server, 4).await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    // 19: no traceparent, 20: a repeated traceparent, 21: a traceparent
    // whose all-zero trace ID W3C Trace Context forbids, 22: more header
    // fields than the canonical client reads. Each keeps a genuinely signed
    // body the canonical client would still refuse.
    for mode in [19, 20, 21, 22] {
        fixture.fault.store(mode, Ordering::SeqCst);
        let response = http
            .post("/v1/evidence")
            .add_header(
                "authorization",
                format!(
                    "Bearer {}",
                    access_token_for(&format!("header-test-{mode}"), None)
                ),
            )
            .add_header("accept", EVIDENCE_JWS_MEDIA_TYPE)
            .json(&residence_request())
            .await;
        assert_eq!(
            response.status_code(),
            StatusCode::SERVICE_UNAVAILABLE,
            "mode {mode}: {}",
            response.text()
        );
        assert_eq!(response.json::<Value>()["code"], "source.unavailable");
    }
}

#[tokio::test]
async fn signed_evidence_source_schema_matches_runtime_constraints() {
    let fixture = composed_runtime().await;
    let baseline: Value = serde_norway::from_slice(
        &fs::read(fixture.downstream.bundle_root.join("evidence.yaml")).unwrap(),
    )
    .unwrap();
    let schema: Value = serde_norway::from_slice(include_bytes!(
        "../../../products/evidence/contracts/bundle.schema.yaml"
    ))
    .unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&schema)
        .unwrap();
    let runtime_accepts = |value: &Value| {
        crate::config::EvidenceConfig::parse_yaml(&serde_json::to_vec(value).unwrap()).is_ok()
    };
    assert!(validator.is_valid(&baseline));
    assert!(runtime_accepts(&baseline));

    let mut prefixed = baseline.clone();
    prefixed["sources"]["source-b"]["request"]["path"] = json!("/agency/v1/evidence");
    assert!(validator.is_valid(&prefixed));
    assert!(runtime_accepts(&prefixed));

    // A canonical RFC 7638 SHA-256 thumbprint: 43 base64url characters whose
    // final character leaves the unused low bits zero.
    let mut revoked = baseline.clone();
    revoked["sources"]["source-b"]["evidence"]["revokedKeyIds"] =
        json!([format!("{}A", "A".repeat(42))]);
    assert!(validator.is_valid(&revoked));
    assert!(runtime_accepts(&revoked));

    for mode in [
        "get",
        "path",
        "template",
        "query",
        "body",
        "accept",
        "batch",
        "unresolved",
        "holder-bound",
        "unsigned",
        "batch-format",
        "authenticated-context",
        "authenticated-grant",
        "forward-attribution",
        "non-canonical-revoked-key-id",
        "unauthenticated",
        "empty-trusted-jwk",
        "private-trusted-jwk",
    ] {
        let mut candidate = baseline.clone();
        let source = &mut candidate["sources"]["source-b"];
        match mode {
            "get" => {
                source["request"]["method"] = json!("GET");
                source["request"]["preparationLimits"]["query"] = json!("allowed");
                source["request"]["preparationLimits"]["jsonBody"] = json!("forbidden");
            }
            "path" => source["request"]["path"] = json!("/v1/facts"),
            "template" => {
                source["request"].as_object_mut().unwrap().remove("path");
                source["request"]["pathTemplate"] = json!("/v1/{reference}/evidence");
                source["request"]["pathBindings"] = json!({"reference": {
                    "from": "selector", "role": "subject", "profile": "residence-record-v1",
                    "field": "record_reference"
                }});
            }
            "query" => source["request"]["preparationLimits"]["query"] = json!("allowed"),
            "body" => source["request"]["preparationLimits"]["jsonBody"] = json!("allowed"),
            "accept" => {
                source["request"]["fixedHeaders"] = json!([
                    {"name": "aCcEpT", "value": "application/jose+json"}
                ])
            }
            "batch" => {
                source["batch"] = json!({
                    "maximumItems": 2, "prepareScript": "adapters/batch-prepare.rhai",
                    "extractScript": "adapters/batch-extract.rhai",
                    "responseSchema": "schemas/batch-response.schema.json",
                    "projection": ["/values/region"]
                })
            }
            "unresolved" => {
                source["unresolvedProblem"] = json!({
                    "status": 404, "type": "https://source.invalid/problems/unresolved",
                    "code": "source.unresolved"
                })
            }
            "holder-bound" => {
                source["evidence"]["contract"]["definitions"][0]["subjectBindingMode"] =
                    json!("holder-bound")
            }
            "unsigned" => {
                source["evidence"]["contract"]["definitions"][0]["responseFormats"] =
                    json!(["unsigned-json"])
            }
            "batch-format" => {
                source["evidence"]["contract"]["definitions"][0]["responseFormats"] =
                    json!(["signed-jws", "sd-jwt-vc-batch"])
            }
            "authenticated-context" | "authenticated-grant" => {
                source["evidence"]["contract"]["definitions"][0]["subjects"][0]["selector"]
                    ["valueOrigin"] = json!(mode)
            }
            "forward-attribution" => source["forwardAccessAttribution"] = json!(true),
            // Forty-three base64url characters that do not decode and re-encode
            // to themselves, because the final character sets unused bits.
            "non-canonical-revoked-key-id" => {
                source["evidence"]["revokedKeyIds"] = json!([format!("{}B", "A".repeat(42))])
            }
            "unauthenticated" => source["authentication"] = json!({"kind": "none"}),
            "empty-trusted-jwk" => source["evidence"]["trustedJwks"]["keys"] = json!([{}]),
            "private-trusted-jwk" => {
                source["evidence"]["trustedJwks"]["keys"][0]["d"] = json!("A".repeat(43))
            }
            _ => unreachable!(),
        }
        assert!(!runtime_accepts(&candidate), "runtime accepted {mode}");
        assert!(!validator.is_valid(&candidate), "schema accepted {mode}");
        // Each candidate is otherwise valid HTTP-source configuration. The
        // signed protocol, rather than an unrelated malformed field, refuses it.
        candidate["sources"]["source-b"]
            .as_object_mut()
            .unwrap()
            .remove("evidence");
        assert!(
            validator.is_valid(&candidate),
            "ordinary schema refused {mode}"
        );
    }
}

#[tokio::test]
async fn signed_evidence_source_refuses_selectors_the_upstream_resolves_from_its_caller() {
    let fixture = composed_runtime().await;
    let baseline: Value = serde_norway::from_slice(
        &fs::read(fixture.downstream.bundle_root.join("evidence.yaml")).unwrap(),
    )
    .unwrap();
    // The upstream would resolve these origins from the downstream service's
    // own source credential, never from the downstream caller's subject.
    for origin in ["authenticated-context", "authenticated-grant"] {
        let mut candidate = baseline.clone();
        candidate["sources"]["source-b"]["evidence"]["contract"]["definitions"][0]["subjects"][0]
            ["selector"]["valueOrigin"] = json!(origin);
        let Err(error) = crate::config::EvidenceConfig::parse_yaml_reporting_rule(
            &serde_json::to_vec(&candidate).unwrap(),
        ) else {
            panic!("runtime accepted {origin}");
        };
        assert_eq!(
            error.to_string(),
            "configuration violates the Evidence Version 1 contract: a signed Evidence source \
             accepts only request-origin selectors, because the upstream would resolve an \
             authenticated selector from this service's own source credential",
            "{origin}"
        );
    }
    assert!(fixture.requests.lock().await.is_empty());
    assert!(fixture
        .token_server
        .received_requests()
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn signed_evidence_source_refuses_forwarded_access_attribution() {
    let fixture = composed_runtime().await;
    let mut candidate: Value = serde_norway::from_slice(
        &fs::read(fixture.downstream.bundle_root.join("evidence.yaml")).unwrap(),
    )
    .unwrap();
    candidate["sources"]["source-b"]["forwardAccessAttribution"] = json!(true);
    let Err(error) = crate::config::EvidenceConfig::parse_yaml_reporting_rule(
        &serde_json::to_vec(&candidate).unwrap(),
    ) else {
        panic!("runtime accepted forwarded access attribution");
    };
    assert_eq!(
        error.to_string(),
        "configuration violates the Evidence Version 1 contract: a signed Evidence source \
         cannot set forwardAccessAttribution, because the upstream authorizes and audits this \
         service's own source credential"
    );
    assert!(fixture.requests.lock().await.is_empty());
}

#[tokio::test]
async fn signed_evidence_source_refuses_unauthenticated_access() {
    let fixture = composed_runtime().await;
    let mut candidate: Value = serde_norway::from_slice(
        &fs::read(fixture.downstream.bundle_root.join("evidence.yaml")).unwrap(),
    )
    .unwrap();
    candidate["sources"]["source-b"]["authentication"] = json!({"kind": "none"});
    let Err(error) = crate::config::EvidenceConfig::parse_yaml_reporting_rule(
        &serde_json::to_vec(&candidate).unwrap(),
    ) else {
        panic!("runtime accepted an unauthenticated signed Evidence source");
    };
    assert_eq!(
        error.to_string(),
        "configuration violates the Evidence Version 1 contract: a signed Evidence source \
         requires source authentication, because the upstream authorizes and audits this \
         service's own source credential"
    );
    // Without the signed protocol the same local loopback source is ordinary
    // unauthenticated HTTP configuration the local profile permits.
    candidate["sources"]["source-b"]
        .as_object_mut()
        .unwrap()
        .remove("evidence");
    crate::config::EvidenceConfig::parse_yaml_reporting_rule(
        &serde_json::to_vec(&candidate).unwrap(),
    )
    .expect("the local profile accepts an unauthenticated loopback HTTP source");
    assert!(fixture.requests.lock().await.is_empty());
}

#[tokio::test]
async fn signed_evidence_source_pins_revocations_and_refuses_invalid_preparation() {
    let fixture = composed_runtime().await;
    let crate::config::SourceConfig::HttpJson {
        request,
        evidence: Some(profile),
        ..
    } = fixture
        .runtime
        .bundle()
        .config
        .sources
        .get("source-b")
        .unwrap()
    else {
        panic!("signed source")
    };
    let subjects = json!({"subjects": residence_request().subjects});
    for body in [
        json!({"subjects": residence_request().subjects, "purpose": "override"}),
        json!({"subjects": [{"role": "subject", "selector": {
            "profile": "residence-record-v1", "values": {"record_reference": true}
        }}]}),
        json!({"subjects": [{"role": "subject", "selector": {
            "profile": "residence-record-v1", "values": {"record_reference": "", "extra": "value"}
        }}]}),
    ] {
        assert!(profile.prepare(Some(&body), 65536).is_err());
    }
    assert!(profile.prepare(Some(&subjects), 16).is_err());
    let mut invalid = profile.clone();
    invalid.contract.definitions[0].purpose = "https://invalid.example/purpose".to_owned();
    assert!(invalid.validate(request).is_err());
    invalid = profile.clone();
    invalid.contract.definitions[0].subject_binding_mode =
        Some(registry_evidence_verifier::model::SubjectBindingMode::HolderBound);
    assert!(invalid.validate(request).is_err());
    invalid = profile.clone();
    invalid.trusted_jwks.keys[0]["d"] = json!("private-key-member");
    assert!(invalid.validate(request).is_err());
    assert!(fixture.requests.lock().await.is_empty());
    assert!(fixture
        .upstream
        .server
        .received_requests()
        .await
        .unwrap()
        .is_empty());
    assert!(fixture
        .token_server
        .received_requests()
        .await
        .unwrap()
        .is_empty());

    // Retain a policy denying an otherwise trusted key before acquiring the
    // answer. Its valid signature must never turn a revoked key back on.
    let mut revoked = profile.clone();
    revoked.revoked_key_ids = vec![EVIDENCE_KEY_ID.to_owned()];
    let (bytes, verification) = revoked.prepare(Some(&subjects), 65536).unwrap();
    mount_residence_source(&fixture.upstream.server).await;
    let response = TestServer::new(build_app(Arc::clone(&fixture.upstream.runtime)))
        .post("/v1/evidence")
        .add_header(
            "authorization",
            format!(
                "Bearer {}",
                access_token_for(
                    "downstream-source-service",
                    Some(json!({"evidence_audience": UPSTREAM_AUDIENCE, "client_id": BASIC_USER}))
                )
            ),
        )
        .add_header("accept", EVIDENCE_JWS_MEDIA_TYPE)
        .json(&serde_json::from_slice::<Value>(&bytes).unwrap())
        .await;
    response.assert_status_ok();
    assert!(matches!(
        revoked.verified_values(&verification, response.as_bytes()),
        Err(crate::source::SourceError::Verification)
    ));
}

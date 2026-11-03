//! Two independently authorized Evidence runtimes, joined by a signed source.
#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
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
    responses: Arc<Mutex<Vec<Vec<u8>>>>,
    upstream_valid_until: Arc<Mutex<Vec<String>>>,
    fault: Arc<AtomicUsize>,
    protocol: crate::source_evidence::EvidenceSourceConfig,
}

struct ReplayHooks;

impl registry_adapter_engine::evidence::EvidenceHostHooks for ReplayHooks {
    fn before_acquisition<'a>(
        &'a self,
        _intent: registry_adapter_engine::evidence::EvidenceAcquisitionIntent,
    ) -> registry_adapter_engine::evidence::EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
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
    composed_runtime_with_route(wallet, false).await
}

async fn composed_runtime_with_finally_terminal_precedence() -> ComposedRuntime {
    composed_runtime_with_route(false, true).await
}

async fn composed_runtime_with_route(
    wallet: bool,
    finally_terminal_precedence: bool,
) -> ComposedRuntime {
    let server = MockServer::start().await;
    let mut ceilings = FixtureCeilings::deployment_defaults();
    ceilings.burst_per_principal = 30;
    let prepared = prepare_fixture_with_pack_variant(
        "upstream-subject-binding-secret-32-bytes-minimum",
        &server.uri(),
        &ceilings,
        AcceptancePackVariant::Base,
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

    let requests: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let responses = Arc::new(Mutex::new(Vec::new()));
    let upstream_valid_until = Arc::new(Mutex::new(Vec::new()));
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
        let responses = Arc::clone(&responses);
        let upstream_valid_until = Arc::clone(&upstream_valid_until);
        let fault = Arc::clone(&fault);
        let runtime = Arc::clone(&upstream.runtime);
        move |request: Request, next: Next| {
            let requests = Arc::clone(&requests);
            let responses = Arc::clone(&responses);
            let upstream_valid_until = Arc::clone(&upstream_valid_until);
            let fault = Arc::clone(&fault);
            let signer = Arc::clone(&signer);
            let runtime = Arc::clone(&runtime);
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
                if response.status().is_success() {
                    assert_eq!(
                        response.headers().get(axum::http::header::CONTENT_TYPE),
                        Some(&EVIDENCE_JWS_MEDIA_TYPE.parse().unwrap()),
                        "the upstream response carries the governed media type"
                    );
                    assert!(
                        response.headers().contains_key("traceparent"),
                        "the upstream response carries its canonical trace context"
                    );
                    registry_platform_httpsec::response_trace_id(response.headers())
                        .expect("the upstream trace context has the canonical response shape");
                }
                let mode = fault.load(Ordering::SeqCst);
                if !response.status().is_success() {
                    return response;
                }
                let (mut parts, body) = response.into_parts();
                parts.headers.remove(axum::http::header::CONTENT_LENGTH);
                let bytes = axum::body::to_bytes(body, 65536).await.unwrap();
                if mode == 0 {
                    let source_request: EvidenceRequest = serde_json::from_value(
                        requests
                            .lock()
                            .await
                            .last()
                            .expect("the signed-source request was captured")
                            .clone(),
                    )
                    .expect("the captured signed-source request is an Evidence request");
                    let mut policy = verification_policy(&runtime, &source_request, &bytes);
                    policy.audience = UPSTREAM_AUDIENCE.to_owned();
                    verify_flattened_jws(&bytes, runtime.jwks(), &policy)
                        .expect("the upstream signed response independently verifies");
                    responses.lock().await.push(bytes.to_vec());
                    return Response::from_parts(parts, Body::from(bytes));
                }
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
                        // Make a wrongly catchable verification refusal
                        // observable: a second send would receive a valid
                        // response and let the hostile catch path manufacture
                        // otherwise valid matched facts.
                        fault.store(0, Ordering::SeqCst);
                        let mut corrupt = serde_json::to_value(jws).unwrap();
                        corrupt["signature"] = json!(URL_SAFE_NO_PAD.encode([0; 64]));
                        return Response::from_parts(
                            parts,
                            Body::from(serde_json::to_vec(&corrupt).unwrap()),
                        );
                    }
                    23 => {
                        let issued_at = payload["issuedAt"]
                            .as_str()
                            .unwrap()
                            .parse::<DateTime<Utc>>()
                            .unwrap();
                        let valid_until = (issued_at + chrono::Duration::seconds(60)).to_rfc3339();
                        payload["validUntil"] = json!(valid_until);
                        upstream_valid_until.lock().await.push(valid_until);
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
    let protocol = signed_evidence_protocol_config(&contract, &jwks);
    let protocol_bytes = serde_json::to_vec(&protocol).expect("host protocol config serializes");
    let downstream = if finally_terminal_precedence {
        prepare_signed_evidence_finally_precedence_fixture(
            "downstream-subject-binding-secret-32-bytes-minimum",
            &origin,
            &format!("{}/token", token_server.uri()),
            &protocol_bytes,
            &FixtureCeilings::deployment_defaults(),
            |root| configure_source(root, wallet),
        )
    } else {
        prepare_signed_evidence_fixture(
            "downstream-subject-binding-secret-32-bytes-minimum",
            &origin,
            &format!("{}/token", token_server.uri()),
            &protocol_bytes,
            &FixtureCeilings::deployment_defaults(),
            |root| configure_source(root, wallet),
        )
    };
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
        responses,
        upstream_valid_until,
        fault,
        protocol,
    }
}

fn signed_evidence_protocol_config(
    contract: &EvidenceDefinitionsDocument,
    jwks: &Value,
) -> crate::source_evidence::EvidenceSourceConfig {
    serde_json::from_value(json!({
        "contract": contract,
        "trustedJwks": jwks,
        "maximumAssertionLifetimeSeconds": 300,
        "clockSkewSeconds": 0
    }))
    .expect("the signed Evidence protocol config parses")
}

fn configure_source(root: &Path, wallet: bool) {
    fs::write(
        root.join("derivations/residence-region.rhai"),
        r#"fn derive(facts, selectors, evaluation_context) {
    [#{
        concept_id: "urn:example:fixture:concept:residence-region",
        value: facts.official_residence_code
    }]
}
"#,
    )
    .expect("the signed-source passthrough derivation is written");
    if !wallet {
        return;
    }
    let path = root.join("evidence.yaml");
    let mut config: Value = serde_norway::from_slice(&fs::read(&path).unwrap()).unwrap();
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
    regenerate_discovery_description(root);
}

#[tokio::test]
async fn signed_evidence_fixture_credentials_are_ready_before_acquisition() {
    let fixture = composed_runtime().await;
    let readiness = source_credential_readiness(&fixture.runtime).await;
    assert!(
        readiness.values().all(Result::is_ok),
        "the composed signed-source credentials are ready: {readiness:?}"
    );
}

#[tokio::test]
async fn signed_evidence_fixture_prepares_the_exact_selector_only_body() {
    let fixture = composed_runtime().await;
    let body = json!({
        "subjects": [{
            "role": "subject",
            "selector": {
                "profile": "residence-record-v1",
                "values": {"record_reference": "synthetic-residence-record-001"}
            }
        }]
    });
    fixture
        .protocol
        .validate_subjects(Some(&body))
        .expect("the minimized pack output matches the signed-source contract");
    fixture
        .protocol
        .prepare(Some(&body), 65_536)
        .expect("the signed-source contract prepares its bounded request");
}

#[test]
fn signed_evidence_lookup_script_consumes_the_verified_projection() {
    let protocol = serde_json::to_vec(&signed_evidence_test_protocol()).unwrap();
    let prepared = prepare_signed_evidence_fixture(
        "script-subject-binding-secret-32-bytes-minimum",
        "https://source.invalid",
        "https://identity.invalid/token",
        &protocol,
        &FixtureCeilings::deployment_defaults(),
        |_| {},
    );
    let bundle = crate::bundle::Bundle::load(&prepared.bundle_root)
        .expect("the signed Evidence test package loads");
    let source = bundle.config.sources.get("source-b").unwrap();
    let closure = bundle.source_pack("source-b").unwrap();
    let pack = closure.pack();
    let pack_directory = prepared
        .bundle_root
        .join(source.pack.artifact_prefix.as_str());
    let mut scripts = registry_adapter_engine::scripts::ScriptSet::default();
    scripts
        .add(
            &pack,
            &pack_directory,
            "scripts/signed-evidence-lookup.rhai",
            "signed_evidence_lookup",
        )
        .expect("the digest-pinned signed Evidence lookup script compiles");
    let lookup = scripts
        .call(
            &Arc::new(BTreeMap::new()),
            "scripts/signed-evidence-lookup.rhai",
            "signed_evidence_lookup",
            &json!({
                "body": {"values": {"region": "REGION-NORTH"}},
                "headers": {},
                "properties": {}
            }),
        )
        .expect("the signed Evidence lookup consumes verified projected values");
    assert_eq!(
        lookup,
        json!({"lookup": "matched", "facts": {"official_residence_code": "REGION-NORTH"}})
    );
    let checked = registry_adapter_engine::evidence::compile_evidence_pack_with_protocols(
        &pack,
        "residence-region",
        &closure.artifacts(),
        registry_adapter_engine::evidence::EvidenceLimits::default(),
        &crate::host_protocol::registry().expect("the Evidence host protocols register"),
    )
    .expect("the signed Evidence route compiles without I/O");
    assert!(checked
        .facts_schema()
        .validate(&json!({"official_residence_code": "REGION-NORTH"})));
}

#[tokio::test]
async fn current_pack_residence_route_returns_reviewed_facts_under_replay() {
    let server = MockServer::start().await;
    let prepared = prepare_fixture_with_pack_variant(
        "replay-subject-binding-secret-32-bytes-minimum",
        &server.uri(),
        &FixtureCeilings::deployment_defaults(),
        AcceptancePackVariant::Base,
        |_| {},
    );
    let bundle = crate::bundle::Bundle::load(&prepared.bundle_root)
        .expect("the current acceptance package loads");
    let closure = bundle
        .source_pack("source-b")
        .expect("the residence source pack is captured");
    let pack = closure.pack();
    let artifacts = closure.artifacts();
    let checked = registry_adapter_engine::evidence::compile_evidence_pack(
        &pack,
        "residence-region",
        &artifacts,
        registry_adapter_engine::evidence::EvidenceLimits::default(),
    )
    .expect("the current residence route compiles without I/O");
    let transcript = Arc::new(
        registry_adapter_engine::replay::ReplayTranscript::from_exchanges(
            serde_json::from_value(json!([{"type": "endpoint", "endpoint": "source-b"}]))
                .expect("the replay intercept parses"),
            serde_json::from_value(json!([{
                "request": {
                    "endpoint": "source-b",
                    "method": "POST",
                    "path": "/v1/facts",
                    "headers": {"accept": "application/json"},
                    "body": {
                        "lookup": {"record_reference": "synthetic-residence-record-001"},
                        "fields": ["official_residence_code"],
                        "limit": 2
                    }
                },
                "response": {
                    "status": 200,
                    "body": {"total": 1, "official_residence_code": "R-101"}
                }
            }]))
            .expect("the replay exchange parses"),
        ),
    );
    let program = checked
        .bind_replay(Arc::clone(&transcript))
        .expect("the current residence route binds to sealed replay");
    let acquisition = program
        .begin_acquisition(Arc::new(ReplayHooks))
        .await
        .expect("the replay acquisition begins");
    let lookup = program
        .execute(
            &acquisition,
            json!({"recordReference": "synthetic-residence-record-001"}),
        )
        .await
        .expect("the current residence route returns reviewed facts");
    assert_eq!(
        lookup,
        registry_adapter_engine::evidence::EvidenceLookup::Matched {
            facts: json!({"official_residence_code": "R-101"})
        }
    );
    transcript
        .finish()
        .expect("the route consumes the exact sealed exchange");
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
        if response.status_code() != StatusCode::OK {
            let token_request_count = fixture
                .token_server
                .received_requests()
                .await
                .unwrap()
                .len();
            let signed_request_count = fixture.requests.lock().await.len();
            let provider_requests = fixture.upstream.server.received_requests().await.unwrap();
            let provider_request_count = provider_requests.len();
            let provider_request_matches = provider_requests.first().is_some_and(|request| {
                request.url.path() == "/v1/facts"
                    && serde_json::from_slice::<Value>(&request.body).ok()
                        == Some(json!({
                            "lookup": {"record_reference": "synthetic-residence-record-001"},
                            "fields": ["official_residence_code"],
                            "limit": 2
                        }))
            });
            let audit = fs::read_to_string(&fixture.downstream.audit_path).unwrap();
            let terminal_category = audit.lines().find_map(|line| {
                let event = serde_json::from_str::<Value>(line).ok()?;
                (event["record"]["phase"] == "terminal-failure")
                    .then(|| event["record"]["safeErrorCategory"].as_str())
                    .flatten()
                    .map(str::to_owned)
            });
            let upstream_audit = fs::read_to_string(&fixture.upstream.audit_path).unwrap();
            let upstream_terminal_category = upstream_audit.lines().find_map(|line| {
                let event = serde_json::from_str::<Value>(line).ok()?;
                (event["record"]["phase"] == "terminal-failure")
                    .then(|| event["record"]["safeErrorCategory"].as_str())
                    .flatten()
                    .map(str::to_owned)
            });
            let captured_request = fixture.requests.lock().await[0].clone();
            let subjects = json!({"subjects": residence_request().subjects});
            let (_, retained) = fixture.protocol.prepare(Some(&subjects), 65_536).unwrap();
            let mut retained = serde_json::to_value(retained).unwrap();
            retained["verificationPolicy"]["requestNonce"] =
                captured_request["requestNonce"].clone();
            let retained = registry_evidence_client::RetainedEvidenceVerification::from_slice(
                &serde_json::to_vec(&retained).unwrap(),
            )
            .unwrap();
            let (projected, _) = fixture
                .protocol
                .verified_values(&retained, &fixture.responses.lock().await[0])
                .expect("the retained verifier reproduces the host-protocol projection");
            let projected_values_match = projected == json!({"values": {"region": "REGION-NORTH"}});
            panic!(
                "signed source failed before release: status={}, token_requests={}, signed_requests={}, provider_requests={}, provider_request_matches={}, projected_values_match={}, downstream_access_attempts={}, downstream_releases={}, downstream_category={terminal_category:?}, upstream_access_attempts={}, upstream_releases={}, upstream_category={upstream_terminal_category:?}",
                response.status_code(),
                token_request_count,
                signed_request_count,
                provider_request_count,
                provider_request_matches,
                projected_values_match,
                audit.matches("\"phase\":\"access-attempt\"").count(),
                audit.matches("\"phase\":\"disclosure-release\"").count(),
                upstream_audit.matches("\"phase\":\"access-attempt\"").count(),
                upstream_audit.matches("\"phase\":\"disclosure-release\"").count(),
            );
        }
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
async fn signed_evidence_source_caps_downstream_validity_at_the_upstream_deadline() {
    let fixture = composed_runtime().await;
    fixture.fault.store(23, Ordering::SeqCst);
    mount_residence_source(&fixture.upstream.server).await;
    let request = residence_request();
    let response = TestServer::new(build_app(Arc::clone(&fixture.runtime)))
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
    let upstream_valid_until = fixture.upstream_valid_until.lock().await;
    assert_eq!(upstream_valid_until.len(), 1);
    assert_eq!(
        evidence.valid_until.parse::<DateTime<Utc>>().unwrap(),
        upstream_valid_until[0].parse::<DateTime<Utc>>().unwrap(),
        "the downstream assertion must use the verified upstream deadline exactly"
    );
    assert!(
        evidence.valid_until.parse::<DateTime<Utc>>().unwrap()
            > evidence.issued_at.parse::<DateTime<Utc>>().unwrap()
    );
}

#[tokio::test]
async fn signed_evidence_source_caps_each_sequential_request_batch_item() {
    let fixture = composed_runtime().await;
    fixture.fault.store(23, Ordering::SeqCst);
    mount_residence_source_expecting(&fixture.upstream.server, 2).await;
    let response = TestServer::new(build_app(Arc::clone(&fixture.runtime)))
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&request_batch_from_request(&residence_request(), 2))
        .await;
    response.assert_status_ok();
    let response = response.json::<EvidenceRequestBatchResponse>();
    assert_eq!(response.items.len(), 2);
    let upstream_valid_until = fixture.upstream_valid_until.lock().await;
    assert_eq!(upstream_valid_until.len(), 2);
    for (item, upstream_valid_until) in response.items.into_iter().zip(upstream_valid_until.iter())
    {
        let EvidenceRequestBatchResponseItem::Evidence { evidence } = item else {
            panic!("each signed-source batch item should produce evidence");
        };
        let evidence = decode_evidence(&evidence);
        assert_eq!(
            evidence.valid_until.parse::<DateTime<Utc>>().unwrap(),
            upstream_valid_until.parse::<DateTime<Utc>>().unwrap(),
            "each item keeps its own verified upstream deadline"
        );
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
        "apiVersion": "id.registrystack.org/formats/evidence/holder-bound-verification-policy/v1",
        "kind": "EvidenceHolderBoundVerificationPolicy",
        "subjectBinding": "holder-bound", "expectedAssuranceProfile": config.assurance_profile,
        "issuedBy": config.issuer.id, "providedBy": config.service.provider_id,
        "requirement": request.requirement,
        "evidenceType": "urn:example:fixture:evidence-type:residence-region:v1",
        "expectedIssuancePurpose": request.purpose,
        "configurationRevision": fixture.runtime.bundle().configuration_revision(&request.requirement).unwrap(),
        "expectedSubjects": payload["subjects"],
        "expectedOutputs": [{"handle": "region", "concept": "urn:example:fixture:concept:residence-region", "required": true, "form": {"type": "string"}}],
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

/// Cryptographic verification is an Evidence terminal boundary, not an
/// ordinary route failure. The reviewed fixture deliberately declares a
/// catchable `upstream.http` fallback that retries and manufactures valid
/// matched facts; an invalid signature must bypass it before that later send,
/// derivation, or disclosure release.
#[tokio::test]
async fn signed_evidence_verification_is_terminal_before_do_try_fallback_or_release() {
    let fixture = composed_runtime().await;
    fixture.fault.store(11, Ordering::SeqCst);
    mount_residence_source(&fixture.upstream.server).await;

    let response = TestServer::new(build_app(Arc::clone(&fixture.runtime)))
        .post("/v1/evidence")
        .add_header(
            "authorization",
            format!("Bearer {}", access_token_for("terminal-verification", None)),
        )
        .add_header("accept", EVIDENCE_JWS_MEDIA_TYPE)
        .json(&residence_request())
        .await;

    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.json::<Value>()["code"], "source.unavailable");
    assert_eq!(
        fixture.requests.lock().await.len(),
        1,
        "the catch fallback must not perform its second signed-source send"
    );
    let audit = fs::read_to_string(&fixture.downstream.audit_path).unwrap();
    assert!(released_evidence_ids(&audit).is_empty());
    assert!(audit.contains("\"safeErrorCategory\":\"source-protocol\""));
    assert!(!audit.contains("signed-source-catch-canary"));
}

/// An uncatchable Evidence terminal failure also prevents `doFinally` from
/// performing effects. The reviewed fixture's finally block detects the
/// still-pending protocol send and retries it; the one-shot corrupt response
/// makes that retry succeed, so a second request would prove the terminal
/// boundary leaked into ordinary route cleanup.
#[tokio::test]
async fn signed_evidence_verification_is_terminal_before_do_finally_effects() {
    let fixture = composed_runtime().await;
    fixture.fault.store(11, Ordering::SeqCst);
    mount_residence_source(&fixture.upstream.server).await;

    let response = TestServer::new(build_app(Arc::clone(&fixture.runtime)))
        .post("/v1/evidence")
        .add_header(
            "authorization",
            format!("Bearer {}", access_token_for("terminal-finally", None)),
        )
        .add_header("accept", EVIDENCE_JWS_MEDIA_TYPE)
        .json(&residence_request())
        .await;

    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.json::<Value>()["code"], "source.unavailable");
    assert_eq!(
        fixture.requests.lock().await.len(),
        1,
        "the doFinally block must not retry after an uncatchable verification failure"
    );
    let audit = fs::read_to_string(&fixture.downstream.audit_path).unwrap();
    assert!(released_evidence_ids(&audit).is_empty());
    assert!(audit.contains("\"safeErrorCategory\":\"source-protocol\""));
    assert!(!audit.contains("signed-source-catch-canary"));
}

/// Evidence must build resilience state from the same retained step tree it
/// serves. This route's breaker guards one ordinary authored failure raised
/// after a successful finally send; its `doCatch` then performs a second valid
/// send and releases the verified result.
#[tokio::test]
async fn signed_evidence_source_route_circuit_breaker_uses_retained_step_identity() {
    let fixture = composed_runtime_with_finally_terminal_precedence().await;
    mount_residence_source_expecting(&fixture.upstream.server, 2).await;

    let response = TestServer::new(build_app(Arc::clone(&fixture.runtime)))
        .post("/v1/evidence")
        .add_header(
            "authorization",
            format!(
                "Bearer {}",
                access_token_for("source-route-breaker-identity", None)
            ),
        )
        .add_header("accept", EVIDENCE_JWS_MEDIA_TYPE)
        .json(&residence_request())
        .await;

    assert_eq!(
        fixture.requests.lock().await.len(),
        2,
        "the retained breaker step executes its try and finally sends"
    );
    let audit = fs::read_to_string(&fixture.downstream.audit_path).unwrap();
    let terminal_category = audit.lines().find_map(|line| {
        let event = serde_json::from_str::<Value>(line).ok()?;
        (event["record"]["phase"] == "terminal-failure")
            .then(|| event["record"]["safeErrorCategory"].as_str())
            .flatten()
            .map(str::to_owned)
    });
    assert_eq!(
        response.status_code(),
        StatusCode::OK,
        "the doCatch returns verified facts; terminal category: {terminal_category:?}"
    );
    assert_eq!(released_evidence_ids(&audit).len(), 1);
}

/// When an ordinary source failure is already pending, an uncatchable signed
/// verification refusal raised by `doFinally` must replace it. The hostile
/// `doCatch` would otherwise perform a second valid send, manufacture matched
/// facts, and turn the terminal refusal into successful Evidence.
#[tokio::test]
async fn signed_evidence_do_finally_terminal_failure_replaces_pending_dependency() {
    let fixture = composed_runtime_with_finally_terminal_precedence().await;
    fixture.fault.store(11, Ordering::SeqCst);
    mount_residence_source(&fixture.upstream.server).await;

    let response = TestServer::new(build_app(Arc::clone(&fixture.runtime)))
        .post("/v1/evidence")
        .add_header(
            "authorization",
            format!(
                "Bearer {}",
                access_token_for("terminal-finally-precedence", None)
            ),
        )
        .add_header("accept", EVIDENCE_JWS_MEDIA_TYPE)
        .json(&residence_request())
        .await;

    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.json::<Value>()["code"], "source.unavailable");
    assert_eq!(
        fixture.requests.lock().await.len(),
        1,
        "the doCatch must not send after doFinally raises a terminal refusal"
    );
    let audit = fs::read_to_string(&fixture.downstream.audit_path).unwrap();
    assert!(released_evidence_ids(&audit).is_empty());
    assert!(audit.contains("\"safeErrorCategory\":\"source-protocol\""));
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

/// The signed protocol owns trace context verification. Missing, repeated,
/// and invalid traceparent values therefore remain one closed verification
/// metric, without retaining trace, selector, source, or credential values.
#[tokio::test]
async fn signed_evidence_trace_context_refusals_are_value_free_verification_metrics() {
    let fixture = composed_runtime().await;
    mount_residence_source_expecting(&fixture.upstream.server, 4).await;
    let metrics = crate::observability::Metrics::new(
        fixture.runtime.rate_limiter(),
        fixture.runtime.source_diagnostics(),
    );

    for mode in [19, 20, 21] {
        fixture.fault.store(mode, Ordering::SeqCst);
        let operation = format!("trace-context-verification-{mode}");
        let failure = fixture
            .runtime
            .evaluate(
                &operation,
                &access_token_for(&operation, None),
                &residence_request(),
            )
            .await
            .expect_err("unverified trace context releases no Evidence");
        assert_eq!(failure.problem(), ProblemCode::DependencyUnavailable);
        for forbidden in [
            operation.as_str(),
            "00000000000000000000000000000000",
            "synthetic-residence-record-001",
            "REGION-NORTH",
            BASIC_USER,
            BASIC_PASSWORD,
        ] {
            assert!(!format!("{failure:?} {failure}").contains(forbidden));
        }
    }

    fixture.fault.store(15, Ordering::SeqCst);
    let media_operation = "duplicate-content-type-protocol";
    let media_failure = fixture
        .runtime
        .evaluate(
            media_operation,
            &access_token_for(media_operation, None),
            &residence_request(),
        )
        .await
        .expect_err("a repeated Content-Type releases no Evidence");
    assert_eq!(media_failure.problem(), ProblemCode::DependencyUnavailable);

    let rendered = metrics.render();
    assert!(
        rendered.contains(
            "evidence_source_requests_total{source=\"source-b\",outcome=\"verification\"} 3"
        ),
        "unexpected closed source metrics:\n{rendered}"
    );
    assert!(
        rendered
            .contains("evidence_source_requests_total{source=\"source-b\",outcome=\"protocol\"} 1"),
        "duplicate Content-Type remains a protocol refusal:\n{rendered}"
    );
    for forbidden in [
        "trace-context-verification",
        media_operation,
        "00000000000000000000000000000000",
        "synthetic-residence-record-001",
        "REGION-NORTH",
        BASIC_USER,
        BASIC_PASSWORD,
    ] {
        assert!(!rendered.contains(forbidden));
    }
}

fn signed_evidence_test_protocol() -> crate::source_evidence::EvidenceSourceConfig {
    signed_evidence_protocol_config(
        &serde_json::from_value(json!({
            "schema": "registry.evidence-definitions/v1",
            "assuranceProfile": "local",
            "audience": "urn:example:source-consumer",
            "issuedBy": "urn:example:upstream",
            "providedBy": "urn:example:provider",
            "maximumHolderBoundBatchSize": 1,
            "definitions": [{
                "handle": "residence-region",
                "requirement": "urn:example:requirement:residence-region",
                "configurationRevision": format!("sha256:{}", "1".repeat(64)),
                "kind": "criterion",
                "evidenceType": "urn:example:evidence:residence-region",
                "purpose": "fixture-routing",
                "responseFormats": ["signed-jws"],
                "referenceFrameworks": ["urn:example:framework"],
                "subjects": [{
                    "role": "subject",
                    "cardinality": "one",
                    "selector": {
                        "profile": "residence-record-v1",
                        "valueOrigin": "request",
                        "fields": [{
                            "type": "string",
                            "name": "record_reference",
                            "minimumBytes": 1,
                            "maximumBytes": 200
                        }]
                    }
                }],
                "concepts": [{
                    "handle": "region",
                    "concept": "urn:example:concept:region",
                    "required": true,
                    "form": {"type": "string"}
                }]
            }]
        }))
        .unwrap(),
        &json!({"keys": [serde_json::from_str::<Value>(
            r#"{"kty":"EC","crv":"P-256","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#
        ).unwrap()]}),
    )
}

#[test]
fn source_failures_remain_categorical_and_value_free() {
    let private = "PRIVATE-SOURCE-VALUE";
    for (error, category) in [
        (
            crate::source_evidence::SignedSourceError::InvalidPlan,
            "the fixed source plan is invalid",
        ),
        (
            crate::source_evidence::SignedSourceError::Verification,
            "the source signed response failed verification",
        ),
    ] {
        assert_eq!(error.to_string(), category);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(private));
    }
}

#[test]
fn signed_evidence_host_config_closes_contract_request_and_selector_shape() {
    let profile = signed_evidence_test_protocol();
    profile
        .validate_contract()
        .expect("the pinned contract validates");
    crate::source_evidence::EvidenceSourceConfig::validate_request_shape(
        registry_adapter_core::HttpMethod::Post,
        "/v1/evidence",
        false,
    )
    .expect("the signed protocol owns the exact POST shape");
    for (method, path, query) in [
        (
            registry_adapter_core::HttpMethod::Get,
            "/v1/evidence",
            false,
        ),
        (registry_adapter_core::HttpMethod::Post, "/v1/facts", false),
        (
            registry_adapter_core::HttpMethod::Post,
            "/{{tenant}}/v1/evidence",
            false,
        ),
        (
            registry_adapter_core::HttpMethod::Post,
            "/v1/evidence",
            true,
        ),
    ] {
        assert!(
            crate::source_evidence::EvidenceSourceConfig::validate_request_shape(
                method, path, query,
            )
            .is_err()
        );
    }

    let subjects = json!({"subjects": [{
        "role": "subject",
        "selector": {
            "profile": "residence-record-v1",
            "values": {"record_reference": "record-123"}
        }
    }]});
    profile
        .validate_subjects(Some(&subjects))
        .expect("the selector-only body validates");
    for invalid in [
        json!({"subjects": [], "purpose": "override"}),
        json!({"subjects": [{"role": "other", "selector": {
            "profile": "residence-record-v1", "values": {"record_reference": "record-123"}
        }}]}),
        json!({"subjects": [{"role": "subject", "selector": {
            "profile": "residence-record-v1", "values": {"record_reference": true}
        }}]}),
        json!({"subjects": [{"role": "subject", "selector": {
            "profile": "residence-record-v1",
            "values": {"record_reference": "record-123", "extra": "refused"}
        }}]}),
    ] {
        assert!(profile.validate_subjects(Some(&invalid)).is_err());
    }
    assert!(profile.prepare(Some(&subjects), 16).is_err());

    for origin in [
        registry_evidence_client::SelectorValueOrigin::AuthenticatedContext,
        registry_evidence_client::SelectorValueOrigin::AuthenticatedGrant,
    ] {
        let mut candidate = profile.clone();
        candidate.contract.definitions[0].subjects[0]
            .selector
            .value_origin = origin;
        assert!(candidate.validate_contract().is_err());
    }
    let mut holder_bound = profile.clone();
    holder_bound.contract.definitions[0].subject_binding_mode =
        Some(registry_evidence_verifier::model::SubjectBindingMode::HolderBound);
    assert!(holder_bound.validate_contract().is_err());
    let mut private_key = profile.clone();
    private_key.trusted_jwks.keys[0]["d"] = json!("private-key-member");
    assert!(private_key.validate_contract().is_err());
}

#[test]
fn signed_evidence_host_config_has_no_access_attribution_override_surface() {
    let mut candidate = serde_json::to_value(
        serde_json::from_value::<crate::source_evidence::EvidenceSourceConfig>(json!({
            "contract": {
                "schema": "registry.evidence-definitions/v1",
                "assuranceProfile": "local",
                "audience": "urn:example:audience",
                "issuedBy": "urn:example:issuer",
                "providedBy": "urn:example:provider",
                "maximumHolderBoundBatchSize": 1,
                "definitions": []
            },
            "trustedJwks": {"keys": []},
            "maximumAssertionLifetimeSeconds": 300
        }))
        .unwrap(),
    )
    .unwrap();
    candidate["forwardAccessAttribution"] = json!(true);
    assert!(
        serde_json::from_value::<crate::source_evidence::EvidenceSourceConfig>(candidate).is_err()
    );
}

#[test]
fn signed_evidence_pack_refuses_unauthenticated_protocol_before_io() {
    let protocol = serde_json::to_vec(&signed_evidence_test_protocol()).unwrap();
    let prepared = prepare_unauthenticated_signed_evidence_fixture(
        "drift-subject-binding-secret-32-bytes-minimum",
        "https://source.invalid",
        "https://identity.invalid/token",
        &protocol,
        &FixtureCeilings::deployment_defaults(),
        |_| {},
    );
    let bundle = crate::bundle::Bundle::load(&prepared.bundle_root)
        .expect("the all-none test package is otherwise valid");
    let closure = bundle
        .source_pack("source-b")
        .expect("the signed Evidence source pack is captured");
    let pack = closure.pack();
    let artifacts = closure.artifacts();
    let result = registry_adapter_engine::evidence::compile_evidence_pack_with_protocols(
        &pack,
        "residence-region",
        &artifacts,
        registry_adapter_engine::evidence::EvidenceLimits::default(),
        &crate::host_protocol::registry().expect("the Evidence host protocols register"),
    );
    let error = match result {
        Ok(_) => panic!("the signed Evidence protocol requires an authenticated endpoint"),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            registry_adapter_engine::evidence::EvidenceCompileError::HostProtocol
        ),
        "unexpected pure compile refusal: {error:?}"
    );
}

#[tokio::test]
async fn signed_evidence_source_pins_revocations_and_refuses_invalid_preparation() {
    let fixture = composed_runtime().await;
    let profile = &fixture.protocol;
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
    assert!(invalid.validate_contract().is_err());
    invalid = profile.clone();
    invalid.contract.definitions[0].subject_binding_mode =
        Some(registry_evidence_verifier::model::SubjectBindingMode::HolderBound);
    assert!(invalid.validate_contract().is_err());
    invalid = profile.clone();
    invalid.trusted_jwks.keys[0]["d"] = json!("private-key-member");
    assert!(invalid.validate_contract().is_err());
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
        Err(crate::source_evidence::SignedSourceError::Verification)
    ));
}

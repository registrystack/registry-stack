// SPDX-License-Identifier: Apache-2.0

fn execute_all_fixtures(
    loaded: &LoadedCountryProject,
    compiled: &CompiledCountry,
) -> Result<Vec<FixtureReport>> {
    let relay_config = compiled
        .relay_private
        .get(Path::new("config/relay.yaml"))
        .ok_or_else(|| anyhow!("generated Relay config is absent"))?;
    let relay_fixture = compile_generated_relay_fixture(relay_config, &compiled.relay_private)?;
    let mut reports = Vec::new();
    for (alias, integration) in &loaded.integrations {
        for (fixture_path, fixture) in &integration.fixtures {
            let preflight = fixture_preflight(loaded, alias, fixture);
            let mut actual_calls = Vec::new();
            let (result, evaluated_claims) = match preflight {
                Err(error) => (Err(error), None),
                Ok(()) if fixture_requires_product_pre_relay_denial(loaded, alias, fixture) => {
                    match evaluate_product_claims(loaded, compiled, alias, fixture, None)
                        .with_context(|| {
                            format!(
                                "failed the product Notary pre-Relay denial for fixture {}.{}",
                                alias, fixture.name
                            )
                        })? {
                        Ok(claims) => (Ok((BTreeMap::new(), "no_match")), Some(claims)),
                        Err(error) => (Err(error), None),
                    }
                }
                Ok(()) => {
                    let relay = execute_fixture(
                        compiled,
                        &relay_fixture,
                        alias,
                        fixture,
                        &mut actual_calls,
                    );
                    match relay {
                        Ok((facts, outcome)) if matches!(outcome, "match" | "no_match") => {
                            match evaluate_product_claims(
                                loaded,
                                compiled,
                                alias,
                                fixture,
                                Some((&facts, outcome)),
                            )
                            .with_context(|| {
                                format!(
                                    "failed to evaluate product claims for fixture {}.{}",
                                    alias, fixture.name
                                )
                            })? {
                                Ok(claims) => (Ok((facts, outcome)), Some(claims)),
                                Err(error) => (Err(error), None),
                            }
                        }
                        Ok(result) => (Ok(result), None),
                        Err(error) => (Err(error), None),
                    }
                }
            };
            let passed = match (&result, &fixture.expect.error) {
                (Ok((facts, _)), None) => {
                    let outcome_matches =
                        fixture.expect.outcome.as_deref().is_none_or(|expected| {
                            result
                                .as_ref()
                                .is_ok_and(|(_, outcome)| *outcome == expected)
                        });
                    let claims_match = if result
                        .as_ref()
                        .is_ok_and(|(_, outcome)| *outcome == "ambiguous")
                    {
                        fixture.expect.claims.is_empty()
                            && fixture.expect.disclosed_claims.is_empty()
                    } else {
                        evaluated_claims.as_ref() == Some(&fixture.expect.claims)
                    };
                    facts == &fixture.expect.facts
                        && claims_match
                        && outcome_matches
                        && (fixture.expect.calls.is_empty() || fixture.expect.calls == actual_calls)
                        && fixture.expect.source_access.is_none_or(|expected| expected)
                }
                (Err(code), Some(expected)) => {
                    code == expected
                        && (fixture.expect.calls.is_empty() || fixture.expect.calls == actual_calls)
                        && fixture.expect.disclosed_claims.is_empty()
                        && fixture
                            .expect
                            .source_access
                            .is_none_or(|expected| expected == error_implies_source_access(code))
                }
                _ => false,
            };
            let failure = (!passed).then(|| match (&result, &fixture.expect.error) {
                (Ok((facts, _)), None) if facts != &fixture.expect.facts => format!(
                    "facts_mismatch: fields={}",
                    mismatched_map_keys(facts, &fixture.expect.facts).join("|")
                ),
                (Ok((_, outcome)), None)
                    if fixture
                        .expect
                        .outcome
                        .as_deref()
                        .is_some_and(|expected| expected != *outcome) =>
                {
                    format!(
                        "outcome_mismatch: expected={}, actual={outcome}",
                        fixture.expect.outcome.as_deref().unwrap_or("unspecified")
                    )
                }
                (Ok(_), None) if evaluated_claims.as_ref() != Some(&fixture.expect.claims) => {
                    format!(
                        "claims_mismatch: claims={}",
                        mismatched_optional_map_keys(
                            evaluated_claims.as_ref(),
                            &fixture.expect.claims,
                        )
                        .join("|")
                    )
                }
                (Ok(_), None) | (Err(_), Some(_))
                    if !fixture.expect.calls.is_empty() && fixture.expect.calls != actual_calls =>
                {
                    format!(
                        "calls_mismatch: expected={}, actual={}",
                        fixture.expect.calls.join("|"),
                        actual_calls.join("|")
                    )
                }
                (Err(actual), Some(expected)) if actual != expected => {
                    format!("error_mismatch: expected={expected}, actual={actual}")
                }
                (Err(actual), None) => format!("unexpected_error: actual={actual}"),
                (Ok(_), Some(expected)) => {
                    format!("expected_error_missing: expected={expected}")
                }
                _ => "expectation_mismatch".to_string(),
            });
            let failure = failure.map(|failure| {
                let relative = fixture_path
                    .strip_prefix(&loaded.root)
                    .unwrap_or(fixture_path)
                    .display();
                let field = result
                    .as_ref()
                    .err()
                    .filter(|code| code.as_str() == "input.pattern_mismatch")
                    .and_then(|_| invalid_fixture_input_field(&integration.document, fixture))
                    .map(|field| format!(" field=input.{field}"))
                    .unwrap_or_default();
                format!("file={relative}{field} {failure}")
            });
            let facts = result
                .as_ref()
                .ok()
                .map(|(facts, _)| facts.keys().cloned().collect())
                .unwrap_or_default();
            reports.push(FixtureReport {
                integration: alias.clone(),
                fixture: fixture.name.clone(),
                inputs: fixture.input.keys().cloned().collect(),
                calls: actual_calls,
                facts,
                claims: evaluated_claims
                    .as_ref()
                    .map(|claims| claims.keys().cloned().collect())
                    .unwrap_or_default(),
                outcome: result
                    .as_ref()
                    .ok()
                    .map(|(_, outcome)| (*outcome).to_string()),
                expected_error: fixture.expect.error.clone(),
                source_access: result
                    .as_ref()
                    .err()
                    .map(|code| error_implies_source_access(code)),
                passed,
                failure,
            });
        }
    }
    Ok(reports)
}

fn invalid_fixture_input_field<'a>(
    integration: &'a IntegrationDocument,
    fixture: &FixtureDocument,
) -> Option<&'a str> {
    integration.input.iter().find_map(|(name, declaration)| {
        let Some(value) = fixture.input.get(name).and_then(Value::as_str) else {
            return Some(name.as_str());
        };
        if value.len() > usize::from(declaration.bytes) {
            return Some(name.as_str());
        }
        if declaration.input_type == InputType::FullDate && validate_full_date(value).is_err() {
            return Some(name.as_str());
        }
        let canonical = match declaration.canonicalization {
            Canonicalization::Identity => std::borrow::Cow::Borrowed(value),
            Canonicalization::AsciiLowercase => std::borrow::Cow::Owned(value.to_ascii_lowercase()),
        };
        let pattern = relay_input_pattern(&declaration.pattern).ok()?;
        (!regex::Regex::new(&pattern).ok()?.is_match(&canonical)).then_some(name.as_str())
    })
}

fn mismatched_map_keys<T: PartialEq>(
    actual: &BTreeMap<String, T>,
    expected: &BTreeMap<String, T>,
) -> Vec<String> {
    actual
        .keys()
        .chain(expected.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|key| actual.get(*key) != expected.get(*key))
        .cloned()
        .collect()
}

fn mismatched_optional_map_keys<T: PartialEq>(
    actual: Option<&BTreeMap<String, T>>,
    expected: &BTreeMap<String, T>,
) -> Vec<String> {
    actual.map_or_else(
        || expected.keys().cloned().collect(),
        |actual| mismatched_map_keys(actual, expected),
    )
}

fn error_implies_source_access(code: &str) -> bool {
    code.starts_with("source.")
}

fn fixture_preflight(
    _loaded: &LoadedCountryProject,
    _integration_alias: &str,
    fixture: &FixtureDocument,
) -> std::result::Result<(), String> {
    if fixture.request_overrides.is_some() {
        return Err("fixture.request_override_forbidden".to_string());
    }
    Ok(())
}

fn fixture_requires_product_pre_relay_denial(
    loaded: &LoadedCountryProject,
    integration_alias: &str,
    fixture: &FixtureDocument,
) -> bool {
    fixture.request_context.as_ref().is_some_and(|context| {
        context.caller.starts_with("unauthorized")
            || !context.scopes.is_empty()
            || !loaded.project.services.values().any(|service| {
                service.kind == ServiceKind::Evidence
                    && service.purpose == context.purpose
                    && service
                        .consultations
                        .values()
                        .any(|consultation| consultation.integration == integration_alias)
            })
    })
}

fn evaluate_product_claims(
    loaded: &LoadedCountryProject,
    compiled: &CompiledCountry,
    integration_alias: &str,
    fixture: &FixtureDocument,
    relay_result: Option<(&BTreeMap<String, Value>, &str)>,
) -> Result<std::result::Result<BTreeMap<String, Value>, String>> {
    use registry_notary_core::{
        ClaimRef, EvaluateRequest, EvidenceEntity, EvidenceIdentifier, RequestVariables,
        FORMAT_CLAIM_RESULT_JSON,
    };
    use registry_notary_server::standalone::{
        OfflineAuthentication, OfflineNotaryHarness, OfflineNotaryRequest,
        OfflineRelayConsultation, OfflineRelayOutcome,
    };

    let empty_facts = BTreeMap::new();
    let (facts, outcome) = relay_result.unwrap_or((&empty_facts, "no_match"));
    let relay_outcome = match outcome {
        "match" => OfflineRelayOutcome::Match,
        "no_match" => OfflineRelayOutcome::NoMatch,
        "ambiguous" => OfflineRelayOutcome::Ambiguous,
        _ => bail!("offline Relay returned an unknown product outcome"),
    };
    let relay_inputs = fixture
        .input
        .iter()
        .map(|(name, value)| {
            let value = value
                .as_str()
                .ok_or_else(|| anyhow!("fixture input is not a bounded string"))?;
            Ok((name.clone(), value.to_string()))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let relay_evidence = compiled
        .fixture_profiles
        .iter()
        .filter(|profile| profile.integration_alias == integration_alias)
        .map(|profile| {
            let purpose = &loaded.project.services[&profile.service_id].purpose;
            OfflineRelayConsultation::decoded_inputs(
                profile.id.clone(),
                profile.version.clone(),
                profile.contract_hash.clone(),
                purpose.clone(),
                relay_inputs.clone(),
                relay_outcome,
                if relay_outcome == OfflineRelayOutcome::Match {
                    facts.clone()
                } else {
                    BTreeMap::new()
                },
            )
        })
        .collect::<Vec<_>>();
    if relay_evidence.is_empty() {
        bail!("offline Notary fixture has no exact Relay consultation profile");
    }
    let notary_config = compiled
        .notary_private
        .get(Path::new("config/notary.yaml"))
        .ok_or_else(|| anyhow!("generated Notary config is absent"))?;
    let notary_config: StandaloneRegistryNotaryConfig = serde_yaml::from_slice(notary_config)
        .context("generated Notary config did not parse for offline evaluation")?;
    let harness =
        OfflineNotaryHarness::compile(notary_config, relay_evidence, country_cel_worker_config()?)
            .context("production Notary offline harness did not compile")?;
    let authentication =
        fixture
            .request_context
            .as_ref()
            .map_or(OfflineAuthentication::Valid, |context| {
                if context.caller.starts_with("unauthorized") {
                    OfflineAuthentication::WrongCredential
                } else if !context.scopes.is_empty() {
                    OfflineAuthentication::InsufficientScope
                } else {
                    OfflineAuthentication::Valid
                }
            });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build the offline Notary evaluation runtime")?;
    let mut claims = BTreeMap::new();
    let mut evaluated_any = false;
    for service in loaded.project.services.values() {
        if service.kind != ServiceKind::Evidence {
            continue;
        }
        let mut claim_groups = BTreeMap::<DisclosureMode, Vec<String>>::new();
        for (claim_id, claim) in &service.claims {
            let consultation = claim_consultation_name(service, claim)?;
            if service.consultations[consultation].integration != integration_alias {
                continue;
            }
            let disclosure = match &claim.disclosure {
                DisclosureDeclaration::Mode(mode) => *mode,
                DisclosureDeclaration::Policy { default, .. } => *default,
            };
            claim_groups
                .entry(disclosure)
                .or_default()
                .push(claim_id.clone());
        }
        if claim_groups.is_empty() {
            continue;
        }
        evaluated_any = true;
        let mut target = EvidenceEntity::new("person");
        let mut identifiers = BTreeMap::new();
        for consultation in service
            .consultations
            .values()
            .filter(|consultation| consultation.integration == integration_alias)
        {
            for (name, request_path) in &consultation.input {
                let value = fixture
                    .input
                    .get(name)
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("fixture omitted a compiled consultation input"))?;
                if request_path == "request.target.id" {
                    target.id = Some(value.to_string());
                } else if let Some(scheme) =
                    request_path.strip_prefix("request.target.identifiers.")
                {
                    identifiers.insert(scheme.to_string(), value.to_string());
                } else {
                    bail!("compiled consultation input uses an unsupported target path");
                }
            }
        }
        target.identifiers = identifiers
            .into_iter()
            .map(|(scheme, value)| EvidenceIdentifier {
                scheme,
                value,
                issuer: None,
                country: None,
            })
            .collect();
        let variables = fixture
            .variables
            .iter()
            .map(|(name, value)| {
                value
                    .as_str()
                    .map(|value| (name.clone(), value.to_string()))
                    .ok_or_else(|| anyhow!("fixture variable is not a full-date string"))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let purpose = fixture
            .request_context
            .as_ref()
            .map_or(service.purpose.as_str(), |context| context.purpose.as_str());
        let variables = RequestVariables::try_new(variables).map_err(|error| anyhow!(error))?;
        for (disclosure, claim_ids) in claim_groups {
            let request = EvaluateRequest {
                requester: None,
                target: Some(target.clone()),
                relationship: None,
                on_behalf_of: None,
                variables: variables.clone(),
                claims: claim_ids
                    .iter()
                    .map(|claim| ClaimRef::from(claim.as_str()))
                    .collect(),
                disclosure: Some(
                    match disclosure {
                        DisclosureMode::Value => "value",
                        DisclosureMode::Predicate => "predicate",
                        DisclosureMode::Redacted => "redacted",
                    }
                    .to_string(),
                ),
                format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
                purpose: Some(purpose.to_string()),
            };
            let evidence = runtime.block_on(harness.evaluate(
                OfflineNotaryRequest::new(authentication, request).with_header_purpose(purpose),
            ));
            if evidence.direct_source_calls() != 0 {
                bail!("offline Notary attempted a forbidden direct source read");
            }
            if let Some(error) = evidence.error_class() {
                if fixture_requires_product_pre_relay_denial(loaded, integration_alias, fixture)
                    && evidence.relay_calls() != 0
                {
                    bail!("offline Notary authorization denial occurred after Relay access");
                }
                if !fixture_requires_product_pre_relay_denial(loaded, integration_alias, fixture) {
                    if let Some(product_error_code) = evidence.product_error_code() {
                        bail!("offline Notary product evaluation failed: {product_error_code}");
                    }
                }
                return Ok(Err(error.as_str().to_string()));
            }
            if evidence.relay_calls() != evidence.consultation_count() as u64 {
                bail!("offline Notary did not reuse each request-scoped consultation exactly once");
            }
            for claim in evidence.claims() {
                let value = if claim.disclosure() == "redacted" {
                    Value::String("redacted".to_string())
                } else if claim.disclosure() == "predicate" {
                    claim.satisfied().map_or(Value::Null, Value::Bool)
                } else if let Some(value) = claim.value() {
                    value.clone()
                } else {
                    Value::Null
                };
                if claims.insert(claim.claim_id().to_string(), value).is_some() {
                    bail!("offline Notary returned a duplicate country claim id");
                }
            }
        }
    }
    if !evaluated_any {
        bail!("offline fixture does not select a country Notary service");
    }
    Ok(Ok(claims))
}

fn country_cel_worker_config() -> Result<registry_notary_server::cel_worker::CelWorkerConfig> {
    let mut config =
        registry_notary_server::cel_worker::CelWorkerConfig::for_current_exe_subcommand();
    config.command = country_registryctl_program()?;
    config.command_args = vec![std::ffi::OsString::from("__registryctl-cel-worker-v1")];
    config.command_envs.clear();
    config.current_dir = None;
    // Debug and sanitizer builds can take longer than the production worker's
    // evaluation deadline to cold-start the isolated subprocess. Country
    // conformance remains bounded, but must measure the rule rather than the
    // test binary's startup latency.
    config.request_timeout = std::time::Duration::from_secs(10);
    Ok(config)
}

fn country_registryctl_program() -> Result<PathBuf> {
    let current = std::env::current_exe().context("current executable is unavailable")?;
    if current
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "deps")
    {
        let mut candidate = current
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| anyhow!("registryctl worker path is unavailable"))?
            .join("registryctl");
        candidate.set_extension(std::env::consts::EXE_EXTENSION);
        if !candidate.is_file() {
            bail!("registryctl worker executable is unavailable");
        }
        Ok(candidate)
    } else {
        Ok(current)
    }
}

fn execute_fixture<'a>(
    compiled: &CompiledCountry,
    relay_fixture: &registry_relay::offline_fixture::OfflineRelayFixture,
    integration_alias: &str,
    fixture: &'a FixtureDocument,
    calls: &mut Vec<String>,
) -> std::result::Result<(BTreeMap<String, Value>, &'a str), String> {
    execute_compiled_relay_fixture(compiled, relay_fixture, integration_alias, fixture, calls)
}

fn execute_compiled_relay_fixture<'a>(
    compiled: &CompiledCountry,
    relay_fixture: &registry_relay::offline_fixture::OfflineRelayFixture,
    integration_alias: &str,
    fixture: &'a FixtureDocument,
    calls: &mut Vec<String>,
) -> std::result::Result<(BTreeMap<String, Value>, &'a str), String> {
    use registry_relay::offline_fixture::{
        OfflineFixtureError, OfflineFixtureOutcome, OfflineFixtureRequest, OfflineProfilePin,
        OfflineSourceResponse,
    };

    let source = fixture
        .source
        .iter()
        .map(|(operation, response)| {
            let response = match response {
                FixtureSourceResponse::Http { status, body } => OfflineSourceResponse::Http {
                    status: *status,
                    body: serde_json::to_vec(body)
                        .map_err(|_| "source.response_malformed".to_string())?,
                },
                FixtureSourceResponse::Timeout { timeout } => {
                    parse_duration_ms(timeout)
                        .map_err(|_| "source.deadline_exceeded".to_string())?;
                    OfflineSourceResponse::Timeout
                }
                FixtureSourceResponse::RawBody { status, raw_body } => {
                    OfflineSourceResponse::Http {
                        status: *status,
                        body: raw_body.as_bytes().to_vec(),
                    }
                }
                FixtureSourceResponse::BodyBytes { status, body_bytes } => {
                    OfflineSourceResponse::DeclaredBodyBytes {
                        status: *status,
                        body_bytes: *body_bytes,
                    }
                }
                FixtureSourceResponse::Outcome { outcome }
                    if matches!(
                        outcome.as_str(),
                        "credential_success" | "credential-operation-succeeded"
                    ) =>
                {
                    OfflineSourceResponse::CredentialSuccess
                }
                FixtureSourceResponse::Outcome { outcome } if outcome == "no_match" => {
                    OfflineSourceResponse::NoMatch
                }
                FixtureSourceResponse::Outcome { outcome } if outcome == "unavailable" => {
                    OfflineSourceResponse::Unavailable
                }
                FixtureSourceResponse::Outcome { .. } => {
                    return Err("source.response_malformed".to_string())
                }
            };
            Ok((operation.clone(), response))
        })
        .collect::<std::result::Result<BTreeMap<_, _>, String>>()?;
    let input = fixture
        .input
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|value| (name.clone(), value.to_string()))
                .ok_or_else(|| "invalid_input".to_string())
        })
        .collect::<std::result::Result<BTreeMap<_, _>, _>>()?;
    let mut selected = compiled
        .fixture_profiles
        .iter()
        .filter(|profile| profile.integration_alias == integration_alias);
    let first = selected
        .next()
        .ok_or_else(|| "fixture.product_contract_invalid".to_string())?;
    let execute = |profile: &FixtureProfile| {
        relay_fixture.execute(OfflineFixtureRequest {
            profile: OfflineProfilePin {
                id: profile.id.clone(),
                version: profile
                    .version
                    .parse()
                    .map_err(|_| OfflineFixtureError::ProfileNotFound)?,
                contract_hash: profile.contract_hash.clone(),
            },
            input: input.clone(),
            source: source.clone(),
        })
    };
    let observation = execute(first).map_err(map_offline_relay_error)?;
    for profile in selected {
        let sibling = execute(profile).map_err(map_offline_relay_error)?;
        if sibling != observation {
            return Err("fixture.product_contract_invalid".to_string());
        }
    }
    calls.extend(observation.calls);
    let outcome = match observation.outcome {
        OfflineFixtureOutcome::Match => "match",
        OfflineFixtureOutcome::NoMatch => "no_match",
        OfflineFixtureOutcome::Ambiguous => "ambiguous",
    };
    Ok((observation.facts, outcome))
}

fn map_offline_relay_error(error: registry_relay::offline_fixture::OfflineFixtureError) -> String {
    use registry_relay::offline_fixture::OfflineFixtureError;
    match error {
        OfflineFixtureError::InvalidInput => "input.pattern_mismatch",
        OfflineFixtureError::UnknownSourceOperation => "fixture.source_operation_unknown",
        OfflineFixtureError::MissingSourceObservation => "source_unavailable",
        OfflineFixtureError::SourceDeadlineExceeded => "source.deadline_exceeded",
        OfflineFixtureError::SourceUnavailable => "source.unavailable",
        OfflineFixtureError::SourceStatusRejected => "source.status_rejected",
        OfflineFixtureError::SourceResponseTooLarge => "source.response_too_large",
        OfflineFixtureError::SourceResponseMalformed => "source.response_malformed",
        OfflineFixtureError::SourceCardinalityViolation => "source.cardinality_violation",
        OfflineFixtureError::ProfileNotFound => "fixture.profile_not_found",
        OfflineFixtureError::ExecutionContractViolation => "fixture.execution_contract_invalid",
    }
    .to_string()
}

fn validate_operation(
    operation: &OperationDeclaration,
    inputs: &BTreeMap<String, InputDeclaration>,
    prior: &BTreeSet<&str>,
) -> Result<()> {
    if operation.request.path.is_empty()
        || !operation.request.path.starts_with('/')
        || operation.request.path.contains("..")
        || operation.request.path.contains(['?', '#'])
    {
        bail!("operation path must be a fixed canonical absolute path");
    }
    let closed_credential_post = operation.role == OperationRole::Credential
        && operation.primitive.as_deref() == Some("oauth2_client_credentials")
        && operation.request.codec.as_deref() == Some("oauth2_client_credentials_json_v1");
    if operation.request.method == ReadMethod::Get && operation.request.body.is_some() {
        bail!("reviewed GET operations cannot carry a request body");
    }
    if operation.request.method == ReadMethod::Post
        && operation.request.body.is_none()
        && !closed_credential_post
    {
        bail!("reviewed read-only POST requires a fixed bounded body template");
    }
    match operation.role {
        OperationRole::Credential
            if operation.primitive.as_deref() == Some("oauth2_client_credentials")
                && operation.request.destination == "credential"
                && operation.request.codec.as_deref()
                    == Some("oauth2_client_credentials_json_v1")
                && operation.response.codec.as_deref() == Some("oauth2_token_v1")
                && operation.verification.is_none() => {}
        OperationRole::Verification
            if operation.primitive.as_deref() == Some("jwks_json_v1")
                && operation.request.method == ReadMethod::Get
                && operation.request.destination == "data"
                && operation.request.codec.is_none()
                && operation.request.authorization.is_none()
                && operation.response.codec.as_deref() == Some("jwks_json_v1")
                && operation.verification.is_none() => {}
        OperationRole::Data if operation.primitive.as_deref() == Some("dci_search_v1") => {
            let verification = operation
                .verification
                .as_ref()
                .ok_or_else(|| anyhow!("DCI search requires a closed JWS verification binding"))?;
            let (jwks_operation, jwks_output) = verification
                .jwks
                .split_once('.')
                .ok_or_else(|| anyhow!("DCI JWS verification must name a prior JWKS output"))?;
            let authorization = match operation.request.authorization.as_ref() {
                Some(ValueSource::Prior { prior }) => Some(prior.as_str()),
                _ => None,
            };
            let authorization_is_anchored = authorization
                .and_then(|authorization| authorization.split_once('.'))
                .is_some_and(|(operation, field)| {
                    field == "access_token" && prior.contains(operation)
                });
            if verification.primitive != "dci_jws_v1"
                || jwks_output != "keys"
                || !prior.contains(jwks_operation)
                || operation.request.codec.as_deref() != Some("dci_search_v1")
                || operation.request.destination != "data"
                || operation.response.codec.as_deref() != Some("dci_search_response_v1")
                || !authorization_is_anchored
            {
                bail!("DCI search uses an unsupported or unanchored verification shape");
            }
            validate_dci_exact_and(operation, inputs)?;
        }
        OperationRole::Data
            if operation.primitive.as_deref() == Some("fhir_r4_search_get")
                && operation.request.method == ReadMethod::Get
                && operation.request.destination == "data"
                && operation.request.codec.as_deref() == Some("fhir_r4_search_get")
                && operation.request.authorization.is_none()
                && operation.response.codec.as_deref() == Some("fhir_r4_searchset")
                && operation.verification.is_none()
                && operation
                    .response
                    .cardinality
                    .as_ref()
                    .is_some_and(|cardinality| {
                        cardinality.mode == CardinalityMode::ProbeTwo
                            && cardinality.records.is_none()
                    }) => {}
        OperationRole::Data
            if operation.primitive.is_none()
                && operation.verification.is_none()
                && operation.request.destination == "data"
                && operation.request.authorization.is_none()
                && operation.response.codec.is_none()
                && matches!(
                    (operation.request.method, operation.request.codec.as_deref()),
                    (ReadMethod::Get, None) | (ReadMethod::Post, Some("strict_json_v1"))
                ) => {}
        _ => bail!("operation role and reviewed primitive do not form a supported closed shape"),
    }
    if operation.request.path_parameters.len() > 1 {
        bail!("operation path supports at most one reviewed path parameter");
    }
    let mut fixed_path = operation.request.path.clone();
    for (parameter, source) in &operation.request.path_parameters {
        validate_stable_id(parameter, "path parameter")?;
        if is_sensitive_authored_name(parameter) {
            bail!("request path parameter names cannot carry credential material");
        }
        let marker = format!("{{{parameter}}}");
        if !operation.request.path.contains(&marker)
            || operation.request.path.matches(&marker).count() != 1
            || !operation.request.path.ends_with(&format!("/{marker}"))
        {
            bail!("path parameter must be the single final operation path segment");
        }
        fixed_path = fixed_path.replace(&marker, "");
        validate_operation_value_source(source, inputs, prior)?;
    }
    if fixed_path.contains(['{', '}']) {
        bail!("operation path contains an undeclared path parameter");
    }
    for (name, source) in &operation.request.query {
        if is_sensitive_authored_name(name) {
            bail!("request query names cannot carry credential material");
        }
        validate_operation_value_source(source, inputs, prior)?;
    }
    for (name, source) in &operation.request.headers {
        if !is_safe_authored_header_name(name) {
            bail!("request header is outside the closed non-credential allow-list");
        }
        if !matches!(
            source,
            ValueSource::Value {
                value: Value::String(_)
            }
        ) {
            bail!("request headers must use fixed bounded string values");
        }
        validate_operation_value_source(source, inputs, prior)?;
    }
    if let Some(authorization) = &operation.request.authorization {
        validate_operation_value_source(authorization, inputs, prior)?;
    }
    if let Some(body) = &operation.request.body {
        let mut nodes = 0_usize;
        validate_body_template_sources(body, inputs, prior, 1, &mut nodes)?;
    }
    if operation
        .depends_on
        .iter()
        .any(|dependency| !prior.contains(dependency.as_str()))
    {
        bail!("operation dependency is not an earlier operation");
    }
    if operation.response.statuses.is_empty()
        || operation.response.statuses.iter().any(|status| {
            !(200..300).contains(status)
                && operation
                    .response
                    .status_semantics
                    .as_ref()
                    .is_none_or(|semantics| {
                        !semantics.no_match.contains(status)
                            && !semantics.ambiguous.contains(status)
                    })
        })
        || operation.response.max_bytes == 0
        || operation.response.max_bytes > 256 * 1024
    {
        bail!("operation response bounds are invalid");
    }
    if let Some(semantics) = &operation.response.status_semantics {
        if semantics.no_match.is_empty() && semantics.ambiguous.is_empty() {
            bail!("status semantics must declare at least one non-success outcome");
        }
        let mut statuses = BTreeSet::new();
        for status in semantics.no_match.iter().chain(&semantics.ambiguous) {
            if (200..300).contains(status)
                || !operation.response.statuses.contains(status)
                || !statuses.insert(status)
            {
                bail!("status semantics must partition declared non-success statuses");
            }
        }
    }
    Ok(())
}

fn validate_dci_exact_and(
    operation: &OperationDeclaration,
    inputs: &BTreeMap<String, InputDeclaration>,
) -> Result<()> {
    let components = operation
        .request
        .body
        .as_ref()
        .and_then(|body| body.get("exact_and"))
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("DCI request must declare one exact_and selector map"))?;
    if components.keys().ne(inputs.keys()) {
        bail!("DCI exact_and keys must equal the integration input keys");
    }
    if operation
        .request
        .body
        .as_ref()
        .is_some_and(|body| body.get("identifier_type").is_some())
        && components.len() != 1
    {
        bail!("DCI identifier_type wire compatibility is limited to one exact component");
    }
    let record = operation_record_schema(operation)?;
    let mut fields = BTreeSet::new();
    let mut pointers = BTreeSet::new();
    for (input, component) in components {
        let component = component
            .as_object()
            .filter(|component| {
                component.len() == 2
                    && component.contains_key("field")
                    && component.contains_key("response_pointer")
            })
            .ok_or_else(|| {
                anyhow!("DCI exact_and component must contain only field and response_pointer")
            })?;
        let field = component["field"]
            .as_str()
            .ok_or_else(|| anyhow!("DCI exact_and field must be a string"))?;
        validate_stable_id(field, "DCI exact predicate field")?;
        let pointer = component["response_pointer"]
            .as_str()
            .ok_or_else(|| anyhow!("DCI exact_and response_pointer must be a string"))?;
        let response = resolve_schema_pointer(record, pointer)?;
        if !fields.insert(field) || !pointers.insert(pointer) {
            bail!("DCI exact_and fields and response pointers must be injective");
        }
        let same_type = matches!(
            (&inputs[input].input_type, response),
            (InputType::String, SchemaNode::String { .. })
                | (InputType::FullDate, SchemaNode::Date)
        );
        if !same_type {
            bail!("DCI exact_and response pointer type must match its consultation input");
        }
    }
    Ok(())
}

fn resolve_schema_pointer<'a>(mut schema: &'a SchemaNode, pointer: &str) -> Result<&'a SchemaNode> {
    if !pointer.starts_with('/') || pointer.len() > 1024 || pointer.contains('~') {
        bail!("DCI exact_and response pointer must be canonical and bounded");
    }
    for token in pointer[1..].split('/') {
        if token.is_empty() {
            bail!("DCI exact_and response pointer contains an empty token");
        }
        if matches!(schema, SchemaNode::Array { .. })
            && (!token.bytes().all(|byte| byte.is_ascii_digit())
                || (token != "0" && token.starts_with('0')))
        {
            bail!("DCI exact_and response pointer contains a noncanonical array index");
        }
        schema = match schema {
            SchemaNode::Object { fields, .. } => {
                let field = fields.get(token).ok_or_else(|| {
                    anyhow!("DCI exact_and response pointer is outside the signed record schema")
                })?;
                if !field.required {
                    bail!("DCI exact_and response pointer must traverse required fields");
                }
                &field.schema
            }
            SchemaNode::Array { items, .. }
                if token.bytes().all(|byte| byte.is_ascii_digit())
                    && (token == "0" || !token.starts_with('0')) =>
            {
                items
            }
            _ => bail!("DCI exact_and response pointer does not resolve to a scalar"),
        };
    }
    match schema {
        SchemaNode::String { .. } | SchemaNode::Date => Ok(schema),
        _ => bail!("DCI exact_and response pointer must resolve to a string or full-date scalar"),
    }
}

fn validate_operation_value_source(
    source: &ValueSource,
    inputs: &BTreeMap<String, InputDeclaration>,
    prior: &BTreeSet<&str>,
) -> Result<()> {
    if let ValueSource::Input { input } = source {
        if !inputs.contains_key(input) {
            bail!("operation references an undeclared consultation input");
        }
    }
    if let ValueSource::Value { value } = source {
        let valid = match value {
            Value::String(value) => {
                value.len() <= 4096
                    && !value.chars().any(char::is_control)
                    && !looks_like_credential_literal(value)
            }
            Value::Bool(_) => true,
            Value::Number(value) => value
                .as_i64()
                .is_some_and(|value| value.unsigned_abs() <= ((1_u64 << 53) - 1)),
            Value::Null | Value::Array(_) | Value::Object(_) => false,
        };
        if !valid {
            bail!("operation literal must be one bounded JSON-safe scalar");
        }
    }
    if let ValueSource::Prior { prior: output } = source {
        let operation = output
            .split_once('.')
            .map(|(operation, _)| operation)
            .ok_or_else(|| anyhow!("prior output must name operation.field"))?;
        if !prior.contains(operation) {
            bail!("operation references a non-prior output");
        }
    }
    Ok(())
}

fn validate_body_template_sources(
    value: &Value,
    inputs: &BTreeMap<String, InputDeclaration>,
    prior: &BTreeSet<&str>,
    depth: usize,
    nodes: &mut usize,
) -> Result<()> {
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| anyhow!("request body template node count overflowed"))?;
    if depth > 8 || *nodes > 256 {
        bail!("request body template exceeds its structural bound");
    }
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(value)
            if value
                .as_i64()
                .is_some_and(|value| value.unsigned_abs() <= ((1_u64 << 53) - 1)) =>
        {
            Ok(())
        }
        Value::Number(_) => bail!("request body numbers must be exact JSON-safe integers"),
        Value::String(value)
            if value.len() <= 4096
                && !value.chars().any(char::is_control)
                && !looks_like_credential_literal(value) =>
        {
            Ok(())
        }
        Value::String(_) => bail!("request body string exceeds its bound"),
        Value::Array(items) => {
            if items.len() > 32 {
                bail!("request body array exceeds its static bound");
            }
            for item in items {
                validate_body_template_sources(item, inputs, prior, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(object) if object.len() == 1 && object.contains_key("input") => {
            let input = object["input"]
                .as_str()
                .ok_or_else(|| anyhow!("request body input expression is invalid"))?;
            if !inputs.contains_key(input) {
                bail!("request body references an undeclared consultation input");
            }
            Ok(())
        }
        Value::Object(object) if object.len() == 1 && object.contains_key("prior") => {
            let prior_output = object["prior"]
                .as_str()
                .ok_or_else(|| anyhow!("request body prior expression is invalid"))?;
            let operation = prior_output
                .split_once('.')
                .map(|(operation, _)| operation)
                .ok_or_else(|| anyhow!("request body prior output is invalid"))?;
            if !prior.contains(operation) {
                bail!("request body references a non-prior output");
            }
            Ok(())
        }
        Value::Object(object) if object.len() == 1 && object.contains_key("value") => {
            validate_body_template_sources(&object["value"], inputs, prior, depth + 1, nodes)
        }
        Value::Object(object) => {
            if object.is_empty() || object.len() > 32 {
                bail!("request body object exceeds its static bound");
            }
            for (name, value) in object {
                if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                    bail!("request body field name is invalid");
                }
                if is_sensitive_authored_name(name) {
                    bail!("request body field names cannot carry credential material");
                }
                validate_body_template_sources(value, inputs, prior, depth + 1, nodes)?;
            }
            Ok(())
        }
    }
}

fn is_sensitive_authored_name(name: &str) -> bool {
    let normalized = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    [
        "authorization",
        "apikey",
        "password",
        "passwd",
        "secret",
        "token",
        "accesstoken",
        "refreshtoken",
        "credential",
        "clientsecret",
        "privatekey",
    ]
    .iter()
    .any(|sensitive| normalized.contains(sensitive))
}

fn is_safe_authored_header_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "accept"
            | "accept-language"
            | "content-type"
            | "data-purpose"
            | "x-locale"
            | "x-projection"
    )
}

fn looks_like_credential_literal(value: &str) -> bool {
    let trimmed = value.trim_start();
    trimmed.len() > 8192
        || trimmed.starts_with("Bearer ")
        || trimmed.starts_with("Basic ")
        || trimmed.contains("-----BEGIN PRIVATE KEY-----")
        || trimmed.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
}

fn validate_fact(
    declaration: &FactDeclaration,
    operations: &BTreeMap<String, OperationDeclaration>,
) -> Result<()> {
    let (operation, path) = declaration.from.split_once('.').ok_or_else(|| {
        anyhow!("fact mapping must name operation.presence or operation.record.path")
    })?;
    if !operations.contains_key(operation) {
        bail!("fact mapping references an unknown operation");
    }
    if path == "presence" {
        if !matches!(
            declaration.fact_type,
            FactType::Presence | FactType::Boolean
        ) || declaration.nullable
        {
            bail!("presence mapping must use a non-null Boolean or presence type");
        }
    } else if path.split('.').any(|segment| {
        segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-'))
    }) {
        bail!("fact mapping must use a static record path");
    }
    if declaration.fact_type == FactType::String
        && declaration
            .max_bytes
            .is_none_or(|bound| bound == 0 || bound > 64 * 1024)
    {
        bail!("string fact requires a positive bounded max_bytes");
    }
    if declaration.fact_type != FactType::String && declaration.max_bytes.is_some() {
        bail!("only string facts may declare max_bytes");
    }
    if declaration.fact_type == FactType::Presence && path != "presence" {
        bail!("presence facts must map an operation presence outcome");
    }
    if path != "presence" {
        let operation = operations
            .get(operation)
            .expect("fact operation presence was checked");
        let mut schema = operation_record_schema(operation)?;
        let path = path.strip_prefix("record.").unwrap_or(path);
        for segment in path.split('.') {
            schema = match schema {
                SchemaNode::Object { fields, .. } => {
                    let field = fields
                        .get(segment)
                        .ok_or_else(|| anyhow!("fact path is absent from the response schema"))?;
                    if !field.required {
                        bail!("fact paths must traverse required response fields");
                    }
                    &field.schema
                }
                _ => bail!("fact path traverses a non-object response schema"),
            };
        }
        let matches = match (declaration.fact_type, schema) {
            (FactType::Boolean, SchemaNode::Boolean) => true,
            (FactType::Integer, SchemaNode::Integer { .. }) => true,
            (FactType::String, SchemaNode::String { max_bytes }) => {
                declaration.max_bytes == Some(*max_bytes)
            }
            (FactType::Date, SchemaNode::Date) => true,
            (FactType::Presence, _) | (_, _) => false,
        };
        if !matches {
            bail!("fact type or bound does not exactly match its response schema field");
        }
    }
    Ok(())
}

fn validate_snapshot_fact(name: &str, declaration: &FactDeclaration) -> Result<()> {
    let (source, field) = declaration
        .from
        .split_once('.')
        .ok_or_else(|| anyhow!("snapshot fact mapping must name snapshot.field"))?;
    let field = field.strip_prefix("record.").unwrap_or(field);
    if source != "snapshot" || field.contains('.') {
        bail!("snapshot facts must use one flat logical snapshot field");
    }
    if field == "presence" {
        if name != "exists"
            || !matches!(
                declaration.fact_type,
                FactType::Boolean | FactType::Presence
            )
            || declaration.nullable
            || declaration.max_bytes.is_some()
        {
            bail!("snapshot presence must be the non-null exists fact");
        }
        return Ok(());
    }
    validate_stable_id(field, "snapshot logical field")?;
    if name != field {
        bail!("snapshot fact ids must equal their logical projected field names");
    }
    if declaration.fact_type == FactType::Presence {
        bail!("presence facts must map snapshot.presence");
    }
    if declaration.fact_type == FactType::String
        && declaration
            .max_bytes
            .is_none_or(|bound| bound == 0 || bound > 64 * 1024)
    {
        bail!("snapshot string fact requires a positive bounded max_bytes");
    }
    if declaration.fact_type != FactType::String && declaration.max_bytes.is_some() {
        bail!("only snapshot string facts may declare max_bytes");
    }
    Ok(())
}

fn integration_operations(
    integration: &IntegrationDocument,
) -> &BTreeMap<String, OperationDeclaration> {
    match &integration.capability {
        CapabilityDeclaration::BoundedHttp { bounded_http } => &bounded_http.operations,
        CapabilityDeclaration::SandboxedRhai { sandboxed_rhai } => &sandboxed_rhai.operations,
        CapabilityDeclaration::SnapshotExact { .. } => {
            static EMPTY: std::sync::LazyLock<BTreeMap<String, OperationDeclaration>> =
                std::sync::LazyLock::new(BTreeMap::new);
            &EMPTY
        }
    }
}

fn ordered_operations(
    operations: &BTreeMap<String, OperationDeclaration>,
) -> Result<Vec<(&String, &OperationDeclaration)>> {
    let mut ordered = Vec::with_capacity(operations.len());
    let mut emitted = BTreeSet::new();
    while ordered.len() < operations.len() {
        let before = ordered.len();
        for (id, operation) in operations {
            if emitted.contains(id)
                || !operation
                    .depends_on
                    .iter()
                    .all(|dependency| emitted.contains(dependency))
            {
                continue;
            }
            if operation
                .depends_on
                .iter()
                .any(|dependency| !operations.contains_key(dependency))
            {
                bail!("operation dependency references an unknown operation");
            }
            emitted.insert(id.clone());
            ordered.push((id, operation));
        }
        if ordered.len() == before {
            bail!("operation dependency graph contains a cycle");
        }
    }
    Ok(ordered)
}

fn credential_interface(integration: &IntegrationDocument) -> &CredentialInterface {
    match &integration.capability {
        CapabilityDeclaration::BoundedHttp { bounded_http } => &bounded_http.credential,
        CapabilityDeclaration::SandboxedRhai { sandboxed_rhai } => &sandboxed_rhai.credential,
        CapabilityDeclaration::SnapshotExact { .. } => {
            static NONE: CredentialInterface = CredentialInterface {
                credential_type: CredentialType::None,
                name: None,
                max_value_bytes: None,
            };
            &NONE
        }
    }
}

fn integration_script(integration: &IntegrationDocument) -> Option<&Path> {
    match &integration.capability {
        CapabilityDeclaration::SandboxedRhai { sandboxed_rhai } => {
            Some(sandboxed_rhai.script.as_path())
        }
        CapabilityDeclaration::BoundedHttp { .. } | CapabilityDeclaration::SnapshotExact { .. } => {
            None
        }
    }
}

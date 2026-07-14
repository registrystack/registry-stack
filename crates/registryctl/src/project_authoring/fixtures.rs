// SPDX-License-Identifier: Apache-2.0

fn preflight_project_rhai_scripts(loaded: &LoadedRegistryProject) -> Result<()> {
    for (alias, integration) in &loaded.integrations {
        let Some((script_path, _)) = integration.script.as_ref() else {
            continue;
        };
        let source = compiled_rhai_source(integration)?;
        let source =
            std::str::from_utf8(&source).context("compiled Rhai closure was not valid UTF-8")?;
        let diagnostic = match registry_relay::rhai_worker::probe_script_diagnostic(
            source,
            "consult",
            registry_relay::rhai_worker::WorkerLimits {
                max_operations: 100_000,
                max_call_levels: 16,
                max_expr_depth: 16,
                max_string_bytes: 64 * 1024,
                max_array_items: 1024,
                max_map_entries: 1024,
                max_output_bytes: 64 * 1024,
                max_ipc_frame_bytes: 256 * 1024,
                max_memory_bytes: 128 * 1024 * 1024,
                wall_time_ms: 250,
                max_source_calls: 16,
            },
        ) {
            Ok(()) => continue,
            Err(diagnostic) => diagnostic,
        };
        let (path, line, field) = rhai_diagnostic_source(integration, diagnostic.line())
            .unwrap_or((script_path.as_path(), None, "capability.script.file"));
        let relative = path.strip_prefix(&loaded.root).unwrap_or(path).display();
        let line = line.map_or_else(String::new, |line| format!(" line={line}"));
        let column = diagnostic
            .column()
            .map_or_else(String::new, |column| format!(" column={column}"));
        let function = diagnostic
            .function()
            .map_or_else(String::new, |function| format!(" function={function}"));
        let signatures = (!diagnostic.valid_signatures().is_empty())
            .then(|| {
                format!(
                    " valid_signatures=[{}]",
                    diagnostic.valid_signatures().join("|")
                )
            })
            .unwrap_or_default();
        bail!(
            "integration={alias} field={field} file={relative}{line}{column} cause={}{}{}",
            diagnostic.cause().as_str(),
            function,
            signatures,
        );
    }
    Ok(())
}

fn rhai_diagnostic_source<'a>(
    integration: &'a LoadedIntegration,
    compiled_line: Option<usize>,
) -> Option<(&'a Path, Option<usize>, &'static str)> {
    let (script_path, _) = integration.script.as_ref()?;
    let Some(compiled_line) = compiled_line else {
        return Some((script_path.as_path(), None, "capability.script.file"));
    };
    let mut next_line = 1_usize;
    for (module_path, module) in &integration.script_modules {
        next_line += 1; // registry-local-module marker
        let module_lines = module.iter().filter(|byte| **byte == b'\n').count() + 1;
        if (next_line..next_line + module_lines).contains(&compiled_line) {
            return Some((
                module_path.as_path(),
                Some(compiled_line - next_line + 1),
                "capability.script.modules",
            ));
        }
        // compiled_rhai_source appends one newline after every module. The
        // line-count expression includes that transition for both terminated
        // and unterminated module text.
        next_line += module_lines;
    }
    next_line += 1; // registry-entrypoint marker
    (compiled_line >= next_line).then_some((
        script_path.as_path(),
        Some(compiled_line - next_line + 1),
        "capability.script.file",
    ))
}

fn execute_all_fixtures(
    loaded: &LoadedRegistryProject,
    compiled: &CompiledProject,
    integration_filter: Option<&str>,
    fixture_filter: Option<&str>,
    trace: bool,
) -> Result<Vec<FixtureReport>> {
    if loaded.integrations.is_empty() {
        return Ok(Vec::new());
    }
    let relay_config = compiled
        .relay_private
        .get(Path::new("config/relay.yaml"))
        .ok_or_else(|| anyhow!("generated Relay config is absent"))?;
    let relay_fixture = compile_generated_relay_fixture(relay_config, &compiled.relay_private)?;
    let mut reports = Vec::new();
    for (alias, integration) in &loaded.integrations {
        if integration_filter.is_some_and(|selected| selected != alias) {
            continue;
        }
        for (fixture_path, fixture) in &integration.fixtures {
            if fixture_filter.is_some_and(|selected| selected != fixture.name) {
                continue;
            }
            let mut actual_calls = Vec::new();
            let relay = execute_fixture(
                compiled,
                &relay_fixture,
                alias,
                fixture,
                &mut actual_calls,
                trace,
            );
            let (result, evaluated_claims) = match relay {
                Ok((outputs, outcome))
                    if matches!(outcome, "match" | "no_match")
                        && !integration_has_product_claims(loaded, alias) =>
                {
                    (Ok((outputs, outcome)), Some(BTreeMap::new()))
                }
                Ok((outputs, outcome)) if matches!(outcome, "match" | "no_match") => {
                    match evaluate_product_claims(
                        loaded,
                        compiled,
                        alias,
                        fixture,
                        Some((&outputs, outcome)),
                        registry_notary_server::standalone::OfflineAuthentication::Valid,
                        false,
                    )
                    .with_context(|| {
                        format!(
                            "failed to evaluate product claims for fixture {}.{}",
                            alias, fixture.name
                        )
                    })? {
                        Ok(claims) => (Ok((outputs, outcome)), Some(claims)),
                        Err(error) => (Err(error), None),
                    }
                }
                Ok(result) => (Ok(result), None),
                Err(error) => (Err(error), None),
            };
            let passed = match (&result, &fixture.expect.error) {
                (Ok((outputs, _)), None) => {
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
                    } else {
                        evaluated_claims.as_ref() == Some(&fixture.expect.claims)
                    };
                    outputs == &fixture.expect.outputs && claims_match && outcome_matches
                }
                (Err(code), Some(expected)) => code == expected,
                _ => false,
            };
            let failure = (!passed).then(|| match (&result, &fixture.expect.error) {
                (Ok((outputs, _)), None) if outputs != &fixture.expect.outputs => format!(
                    "outputs_mismatch: fields={}",
                    mismatched_map_keys(outputs, &fixture.expect.outputs).join("|")
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
            let outputs = result
                .as_ref()
                .ok()
                .map(|(outputs, _)| outputs.keys().cloned().collect())
                .unwrap_or_default();
            reports.push(FixtureReport {
                integration: alias.clone(),
                fixture: fixture.name.clone(),
                inputs: fixture.input.keys().cloned().collect(),
                calls: actual_calls,
                outputs,
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
            reports.extend(derived_fixture_reports(
                loaded,
                compiled,
                &relay_fixture,
                alias,
                fixture,
                trace,
            )?);
        }
    }
    if reports.is_empty() && (integration_filter.is_some() || fixture_filter.is_some()) {
        bail!("the selected integration or fixture does not exist");
    }
    Ok(reports)
}

fn derived_fixture_reports(
    loaded: &LoadedRegistryProject,
    compiled: &CompiledProject,
    relay_fixture: &registry_relay::offline_fixture::OfflineRelayFixture,
    integration_alias: &str,
    fixture: &FixtureDocument,
    trace: bool,
) -> Result<Vec<FixtureReport>> {
    use registry_relay::offline_fixture::OfflineSourceResponse;

    let base = offline_fixture_interactions(fixture).map_err(|error| anyhow!(error))?;
    let input = offline_fixture_input(fixture).map_err(|error| anyhow!(error))?;
    let mut cases = Vec::<(
        &str,
        Vec<registry_relay::offline_fixture::OfflineInteraction>,
        &str,
    )>::new();

    let mut request_mismatch = base.clone();
    if let Some(interaction) = request_mismatch.first_mut() {
        interaction
            .request
            .path
            .push_str("/__registry_fixture_mismatch");
        cases.push((
            "request_authority",
            request_mismatch,
            "fixture.request_mismatch",
        ));
    }
    let mut malformed = base.clone();
    if let Some(interaction) = malformed.last_mut() {
        interaction.response = OfflineSourceResponse::Http {
            status: 200,
            headers: BTreeMap::new(),
            body: b"{".to_vec(),
        };
        cases.push(("malformed_decode", malformed, "source.response_malformed"));
    }
    let mut oversized = base.clone();
    if let Some(interaction) = oversized.last_mut() {
        interaction.response = OfflineSourceResponse::DeclaredBodyBytes {
            status: 200,
            body_bytes: u64::MAX,
        };
        cases.push(("byte_ceiling", oversized, "source.response_too_large"));
    }
    let mut timeout = base.clone();
    if let Some(interaction) = timeout.last_mut() {
        interaction.response = OfflineSourceResponse::Timeout;
        cases.push(("timeout", timeout, "source.deadline_exceeded"));
    }
    if fixture.interactions.iter().any(|interaction| {
        interaction
            .expect
            .body
            .as_ref()
            .is_some_and(contains_generated_fixture_matcher)
    }) {
        let mut protocol = base.clone();
        if let Some(registry_relay::offline_fixture::OfflineInteraction {
            response: OfflineSourceResponse::Http { body, .. },
            ..
        }) = protocol.last_mut()
        {
            if let Ok(Value::Object(mut object)) = serde_json::from_slice::<Value>(body) {
                object.insert("__registry_protocol_mutation".to_owned(), Value::Bool(true));
                *body = serde_json::to_vec(&Value::Object(object))?;
                cases.push((
                    "protocol_verification",
                    protocol,
                    "source.response_malformed",
                ));
            }
        }
    }

    let mut reports = cases
        .into_iter()
        .map(|(case, interactions, expected)| {
            let mut calls = Vec::new();
            let result = execute_offline_profiles(
                compiled,
                relay_fixture,
                integration_alias,
                input.clone(),
                interactions,
                trace,
            )
            .map(|mut observation| {
                calls = std::mem::take(&mut observation.calls);
                observation
            })
            .map_err(|error| error);
            let actual = result.as_ref().err().map(String::as_str);
            let passed = actual == Some(expected);
            FixtureReport {
                integration: integration_alias.to_owned(),
                fixture: format!("{}::derived/{case}", fixture.name),
                inputs: fixture.input.keys().cloned().collect(),
                calls,
                outputs: Vec::new(),
                claims: Vec::new(),
                outcome: None,
                expected_error: Some(expected.to_owned()),
                source_access: Some(error_implies_source_access(expected)),
                passed,
                failure: (!passed).then(|| {
                    format!(
                        "derived_error_mismatch: expected={expected}, actual={}",
                        actual.unwrap_or("success")
                    )
                }),
            }
        })
        .collect::<Vec<_>>();

    if integration_has_product_claims(loaded, integration_alias) {
        let authorization = evaluate_product_claims(
            loaded,
            compiled,
            integration_alias,
            fixture,
            None,
            registry_notary_server::standalone::OfflineAuthentication::WrongCredential,
            true,
        )?;
        let authorization_error = authorization.err();
        let authorization_passed = authorization_error.as_deref() == Some("authorization.denied");
        reports.push(FixtureReport {
            integration: integration_alias.to_owned(),
            fixture: format!("{}::derived/authorization_before_source", fixture.name),
            inputs: fixture.input.keys().cloned().collect(),
            calls: Vec::new(),
            outputs: Vec::new(),
            claims: Vec::new(),
            outcome: None,
            expected_error: Some("authorization.denied".to_owned()),
            source_access: Some(false),
            passed: authorization_passed,
            failure: (!authorization_passed).then(|| {
                format!(
                    "derived_authorization_mismatch: expected=authorization.denied, actual={}",
                    authorization_error.as_deref().unwrap_or("success")
                )
            }),
        });
    }

    let mut minimized = base;
    // Ignoring unselected upstream members is a declarative HTTP projection
    // guarantee. Snapshot rows are the reviewed materialization contract, so
    // injecting an undeclared field there must remain a malformed response.
    let is_declarative_http = matches!(
        loaded.integrations[integration_alias].document.capability,
        CapabilityDeclaration::Http { .. }
    );
    if is_declarative_http
        && !fixture.interactions.iter().any(|interaction| {
            interaction
                .expect
                .body
                .as_ref()
                .is_some_and(contains_generated_fixture_matcher)
        })
    {
        if let Some(registry_relay::offline_fixture::OfflineInteraction {
            response: OfflineSourceResponse::Http { body, .. },
            ..
        }) = minimized.last_mut()
        {
            if let Ok(Value::Object(mut object)) = serde_json::from_slice::<Value>(body) {
                object.insert(
                    "__registry_unselected_synthetic".to_owned(),
                    Value::String("ignored".to_owned()),
                );
                *body = serde_json::to_vec(&Value::Object(object))?;
                let result = execute_offline_profiles(
                    compiled,
                    relay_fixture,
                    integration_alias,
                    input,
                    minimized,
                    trace,
                );
                let (passed, calls, outputs, outcome, failure) = match result {
                    Ok(observation) => {
                        let outcome = match observation.outcome {
                            registry_relay::offline_fixture::OfflineFixtureOutcome::Match => {
                                "match"
                            }
                            registry_relay::offline_fixture::OfflineFixtureOutcome::NoMatch => {
                                "no_match"
                            }
                            registry_relay::offline_fixture::OfflineFixtureOutcome::Ambiguous => {
                                "ambiguous"
                            }
                        };
                        let passed = observation.outputs == fixture.expect.outputs
                            && fixture
                                .expect
                                .outcome
                                .as_deref()
                                .is_none_or(|expected| expected == outcome);
                        (
                            passed,
                            observation.calls,
                            observation.outputs.keys().cloned().collect(),
                            Some(outcome.to_owned()),
                            (!passed)
                                .then(|| "derived_output_minimization_changed_result".to_owned()),
                        )
                    }
                    Err(error) => (
                        false,
                        Vec::new(),
                        Vec::new(),
                        None,
                        Some(format!("derived_output_minimization_failed: {error}")),
                    ),
                };
                reports.push(FixtureReport {
                    integration: integration_alias.to_owned(),
                    fixture: format!("{}::derived/output_minimization", fixture.name),
                    inputs: fixture.input.keys().cloned().collect(),
                    calls,
                    outputs,
                    claims: Vec::new(),
                    outcome,
                    expected_error: None,
                    source_access: Some(true),
                    passed,
                    failure,
                });
            }
        }
    }
    Ok(reports)
}

fn integration_has_product_claims(loaded: &LoadedRegistryProject, integration_alias: &str) -> bool {
    loaded.project.services.values().any(|service| {
        service.kind == ServiceKind::Evidence
            && service.claims.values().any(|claim| {
                claim_consultation_name(service, claim).is_ok_and(|consultation| {
                    service.consultations[consultation].integration == integration_alias
                })
            })
    })
}

fn contains_generated_fixture_matcher(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(contains_generated_fixture_matcher),
        Value::Object(object) => {
            object.contains_key("generated")
                || object.values().any(contains_generated_fixture_matcher)
        }
        _ => false,
    }
}

fn invalid_fixture_input_field<'a>(
    integration: &'a IntegrationDocument,
    fixture: &FixtureDocument,
) -> Option<&'a str> {
    integration.input.iter().find_map(|(name, declaration)| {
        fixture
            .input
            .get(name)
            .filter(|value| validate_fixture_input_value(name, declaration, value).is_ok())
            .is_none()
            .then_some(name.as_str())
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

fn evaluate_product_claims(
    loaded: &LoadedRegistryProject,
    compiled: &CompiledProject,
    integration_alias: &str,
    fixture: &FixtureDocument,
    relay_result: Option<(&BTreeMap<String, Value>, &str)>,
    authentication: registry_notary_server::standalone::OfflineAuthentication,
    require_pre_source_denial: bool,
) -> Result<std::result::Result<BTreeMap<String, Value>, String>> {
    use registry_notary_core::{
        ClaimRef, EvaluateRequest, EvidenceEntity, EvidenceIdentifier, RequestVariables,
        FORMAT_CLAIM_RESULT_JSON,
    };
    use registry_notary_server::standalone::{
        OfflineNotaryHarness, OfflineNotaryRequest, OfflineRelayConsultation, OfflineRelayOutcome,
    };

    let empty_outputs = BTreeMap::new();
    let (outputs, outcome) = relay_result.unwrap_or((&empty_outputs, "no_match"));
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
            let value = match value {
                Value::Null => "null".to_owned(),
                Value::Bool(value) => value.to_string(),
                Value::Number(value) => value.to_string(),
                Value::String(value) => value.clone(),
                Value::Array(_) | Value::Object(_) => {
                    bail!("fixture input is not a bounded scalar")
                }
            };
            Ok((name.clone(), value))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let relay_evidence = compiled
        .fixture_profiles
        .iter()
        .map(|profile| {
            let purpose = &loaded.project.services[&profile.service_id].purpose;
            let is_fixture_integration = profile.integration_alias == integration_alias;
            OfflineRelayConsultation::decoded_inputs(
                profile.id.clone(),
                profile.contract_hash.clone(),
                purpose.clone(),
                relay_inputs.clone(),
                if is_fixture_integration {
                    relay_outcome
                } else {
                    OfflineRelayOutcome::NoMatch
                },
                if is_fixture_integration && relay_outcome == OfflineRelayOutcome::Match {
                    outputs.clone()
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
        OfflineNotaryHarness::compile(notary_config, relay_evidence, project_cel_worker_config()?)
            .context("production Notary offline harness did not compile")?;
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
        let purpose = service.purpose.as_str();
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
            if let Some(error) = evidence.error_class() {
                if require_pre_source_denial && evidence.relay_calls() != 0 {
                    bail!("derived authorization denial occurred after Relay access");
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
                    bail!("offline Notary returned a duplicate project claim id");
                }
            }
        }
    }
    if !evaluated_any {
        bail!("offline fixture does not select a project Notary service");
    }
    Ok(Ok(claims))
}

fn project_cel_worker_config() -> Result<registry_notary_server::cel_worker::CelWorkerConfig> {
    let mut config =
        registry_notary_server::cel_worker::CelWorkerConfig::for_current_exe_subcommand();
    config.command = project_registryctl_program()?;
    config.command_args = vec![std::ffi::OsString::from("__registryctl-cel-worker-v1")];
    config.command_envs.clear();
    config.current_dir = None;
    // Debug and sanitizer builds can take longer than the production worker's
    // evaluation deadline to cold-start the isolated subprocess. Project
    // conformance remains bounded, but must measure the rule rather than the
    // test binary's startup latency.
    config.request_timeout = std::time::Duration::from_secs(10);
    Ok(config)
}

fn project_registryctl_program() -> Result<PathBuf> {
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
    compiled: &CompiledProject,
    relay_fixture: &registry_relay::offline_fixture::OfflineRelayFixture,
    integration_alias: &str,
    fixture: &'a FixtureDocument,
    calls: &mut Vec<String>,
    trace: bool,
) -> std::result::Result<(BTreeMap<String, Value>, &'a str), String> {
    execute_compiled_relay_fixture(
        compiled,
        relay_fixture,
        integration_alias,
        fixture,
        calls,
        trace,
    )
}

fn execute_compiled_relay_fixture<'a>(
    compiled: &CompiledProject,
    relay_fixture: &registry_relay::offline_fixture::OfflineRelayFixture,
    integration_alias: &str,
    fixture: &'a FixtureDocument,
    calls: &mut Vec<String>,
    trace: bool,
) -> std::result::Result<(BTreeMap<String, Value>, &'a str), String> {
    use registry_relay::offline_fixture::OfflineFixtureOutcome;

    let interactions = offline_fixture_interactions(fixture)?;
    let input = offline_fixture_input(fixture)?;
    let observation = execute_offline_profiles(
        compiled,
        relay_fixture,
        integration_alias,
        input,
        interactions,
        trace,
    )?;
    calls.extend(observation.calls);
    let outcome = match observation.outcome {
        OfflineFixtureOutcome::Match => "match",
        OfflineFixtureOutcome::NoMatch => "no_match",
        OfflineFixtureOutcome::Ambiguous => "ambiguous",
    };
    Ok((observation.outputs, outcome))
}

fn offline_fixture_interactions(
    fixture: &FixtureDocument,
) -> std::result::Result<Vec<registry_relay::offline_fixture::OfflineInteraction>, String> {
    use registry_relay::offline_fixture::{
        OfflineExpectedRequest, OfflineInteraction, OfflineRequestMethod, OfflineSourceResponse,
    };

    fixture
        .interactions
        .iter()
        .map(|interaction| {
            let response = match &interaction.respond {
                FixtureSourceResponse::Http {
                    status,
                    headers,
                    body,
                } => OfflineSourceResponse::Http {
                    status: *status,
                    headers: headers.clone(),
                    body: serde_json::to_vec(body)
                        .map_err(|_| "source.response_malformed".to_string())?,
                },
                FixtureSourceResponse::Timeout { timeout } => {
                    parse_duration_ms(timeout)
                        .map_err(|_| "source.deadline_exceeded".to_string())?;
                    OfflineSourceResponse::Timeout
                }
            };
            Ok(OfflineInteraction {
                request: OfflineExpectedRequest {
                    method: match interaction.expect.method {
                        ReadMethod::Get => OfflineRequestMethod::Get,
                        ReadMethod::Post => OfflineRequestMethod::Post,
                    },
                    path: interaction.expect.path.clone(),
                    query: interaction.expect.query.clone(),
                    headers: interaction.expect.headers.clone(),
                    body: interaction.expect.body.clone(),
                },
                response,
            })
        })
        .collect()
}

fn offline_fixture_input(
    fixture: &FixtureDocument,
) -> std::result::Result<BTreeMap<String, String>, String> {
    fixture
        .input
        .iter()
        .map(|(name, value)| {
            let value = match value {
                Value::Null => "null".to_string(),
                Value::Bool(value) => value.to_string(),
                Value::Number(value) => value.to_string(),
                Value::String(value) => value.clone(),
                Value::Array(_) | Value::Object(_) => return Err("invalid_input".to_string()),
            };
            Ok((name.clone(), value))
        })
        .collect()
}

fn execute_offline_profiles(
    compiled: &CompiledProject,
    relay_fixture: &registry_relay::offline_fixture::OfflineRelayFixture,
    integration_alias: &str,
    input: BTreeMap<String, String>,
    interactions: Vec<registry_relay::offline_fixture::OfflineInteraction>,
    trace: bool,
) -> std::result::Result<registry_relay::offline_fixture::OfflineFixtureObservation, String> {
    use registry_relay::offline_fixture::{
        OfflineFixtureError, OfflineFixtureRequest, OfflineProfilePin,
    };

    let mut selected = compiled
        .fixture_profiles
        .iter()
        .filter(|profile| profile.integration_alias == integration_alias);
    let first = selected
        .next()
        .ok_or_else(|| "fixture.product_contract_invalid".to_string())?;
    let execute = |profile: &FixtureProfile| {
        let request = OfflineFixtureRequest {
            profile: OfflineProfilePin {
                id: profile.id.clone(),
                version: profile
                    .version
                    .parse()
                    .map_err(|_| OfflineFixtureError::ProfileNotFound)?,
                contract_hash: profile.contract_hash.clone(),
            },
            input: input.clone(),
            interactions: interactions.clone(),
        };
        if trace {
            relay_fixture.execute_with_trace(request)
        } else {
            relay_fixture.execute(request)
        }
    };
    let observation = execute(first).map_err(map_offline_relay_error)?;
    for profile in selected {
        let sibling = execute(profile).map_err(map_offline_relay_error)?;
        if sibling != observation {
            return Err("fixture.product_contract_invalid".to_string());
        }
    }
    Ok(observation)
}

fn map_offline_relay_error(error: registry_relay::offline_fixture::OfflineFixtureError) -> String {
    use registry_relay::offline_fixture::OfflineFixtureError;
    match error {
        OfflineFixtureError::InvalidInput => "input.pattern_mismatch",
        OfflineFixtureError::UnknownSourceOperation => "fixture.source_operation_unknown",
        OfflineFixtureError::MissingSourceObservation => "source_unavailable",
        OfflineFixtureError::RequestMismatch => "fixture.request_mismatch",
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
        && matches!(
            operation.request.codec.as_deref(),
            Some("oauth2_client_credentials_json_v1" | "oauth2_client_credentials_form_v1")
        );
    if operation.request.method == ReadMethod::Get && operation.request.body.is_some() {
        bail!("reviewed GET operations cannot carry a request body");
    }
    if operation.request.method == ReadMethod::Post
        && operation.request.body.is_none()
        && !closed_credential_post
        && operation.request.codec.is_some()
    {
        bail!("reviewed read-only POST codec requires a fixed bounded body template");
    }
    match operation.role {
        OperationRole::Credential
            if operation.primitive.as_deref() == Some("oauth2_client_credentials")
                && operation.request.destination == "credential"
                && matches!(
                    operation.request.codec.as_deref(),
                    Some("oauth2_client_credentials_json_v1" | "oauth2_client_credentials_form_v1")
                )
                && operation.response.codec.as_deref() == Some("oauth2_token_v1")
                && operation.verification.is_none() => {}
        OperationRole::Verification
            if operation.primitive.as_deref() == Some("jwks_json_v1")
                && operation.request.method == ReadMethod::Get
                && operation.request.destination == "verification"
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
            if operation.primitive.is_none()
                && operation.verification.is_none()
                && operation.request.destination == "data"
                && operation.request.authorization.is_none()
                && operation.response.codec.as_deref() == Some("json_v1")
                && matches!(
                    (operation.request.method, operation.request.codec.as_deref()),
                    (ReadMethod::Get, None) | (ReadMethod::Post, None | Some("strict_json_v1"))
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
        || operation.response.max_bytes > 8 * 1024 * 1024
    {
        bail!("operation response bounds are invalid");
    }
    if operation.role == OperationRole::Verification && operation.response.max_bytes > 64 * 1024 {
        bail!("verification response exceeds the 64 KiB bound");
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
    if components.keys().map(String::as_str).ne(inputs
        .iter()
        .filter(|(_, declaration)| declaration.role == AuthoredInputRole::Selector)
        .map(|(name, _)| name.as_str()))
    {
        bail!("DCI exact_and keys must equal the integration selector input keys");
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
                | (InputType::Boolean, SchemaNode::Boolean)
                | (InputType::Integer, SchemaNode::Integer { .. })
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

fn validate_output(
    declaration: &OutputDeclaration,
    operations: &BTreeMap<String, OperationDeclaration>,
) -> Result<()> {
    let Some(source) = declaration.from.as_deref() else {
        if declaration.output_type == FactType::Presence {
            bail!("script terminal outputs cannot use the internal presence type");
        }
        return Ok(());
    };
    let (operation, path) = source.split_once('.').ok_or_else(|| {
        anyhow!("output mapping must name operation.presence or operation.record.path")
    })?;
    if !operations.contains_key(operation) {
        bail!("output mapping references an unknown operation");
    }
    if path == "presence" {
        if !matches!(
            declaration.output_type,
            FactType::Presence | FactType::Boolean
        ) || declaration.nullable
        {
            bail!("presence mapping must use a non-null Boolean or presence type");
        }
    } else if declaration.source_pointer.is_none()
        && path.split('.').any(|segment| {
            segment.is_empty()
                || !segment.bytes().all(
                    |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-'),
                )
        })
    {
        bail!("output mapping must use a static record path");
    }
    if declaration.output_type == FactType::String
        && declaration
            .max_bytes
            .is_none_or(|bound| bound == 0 || bound > 64 * 1024)
    {
        bail!("string output requires a positive bounded max_bytes");
    }
    if declaration.output_type != FactType::String && declaration.max_bytes.is_some() {
        bail!("only string outputs may declare max_bytes");
    }
    if declaration.output_type == FactType::Presence && path != "presence" {
        bail!("presence outputs must map an operation presence outcome");
    }
    if path != "presence" {
        let operation = operations
            .get(operation)
            .expect("output operation presence was checked");
        let mut schema = operation_record_schema(operation)?;
        let segments = if let Some(pointer) = declaration.source_pointer.as_deref() {
            fixture_pointer_segments(pointer)?
        } else {
            path.strip_prefix("record.")
                .unwrap_or(path)
                .split('.')
                .map(str::to_string)
                .collect()
        };
        for (index, segment) in segments.iter().enumerate() {
            schema = match schema {
                SchemaNode::Object { fields, .. } => {
                    let field = fields
                        .get(segment)
                        .ok_or_else(|| anyhow!("output path is absent from the response schema"))?;
                    let nullable_leaf = index + 1 == segments.len() && declaration.nullable;
                    if !field.required && !nullable_leaf {
                        bail!("output paths must traverse required response fields");
                    }
                    &field.schema
                }
                _ => bail!("output path traverses a non-object response schema"),
            };
        }
        let matches = match (declaration.output_type, schema) {
            (FactType::Boolean, SchemaNode::Boolean) => true,
            (FactType::Integer, SchemaNode::Integer { .. }) => true,
            (FactType::String, SchemaNode::String { max_bytes }) => {
                declaration.max_bytes == Some(*max_bytes)
            }
            (FactType::Date, SchemaNode::Date) => true,
            (FactType::Presence, _) | (_, _) => false,
        };
        if !matches {
            bail!("output type or bound does not exactly match its response schema field");
        }
    }
    Ok(())
}

fn fixture_pointer_segments(pointer: &str) -> Result<Vec<String>> {
    let pointer = pointer
        .strip_prefix('/')
        .ok_or_else(|| anyhow!("HTTP output pointer must be absolute"))?;
    if pointer.is_empty() {
        bail!("HTTP output pointer cannot select the root");
    }
    pointer
        .split('/')
        .map(|segment| {
            let decoded = segment.replace("~1", "/").replace("~0", "~");
            (!decoded.is_empty())
                .then_some(decoded)
                .ok_or_else(|| anyhow!("HTTP output pointer contains an empty token"))
        })
        .collect()
}

fn validate_snapshot_output(name: &str, declaration: &OutputDeclaration) -> Result<()> {
    let (source, field) = declaration
        .from
        .as_deref()
        .ok_or_else(|| anyhow!("snapshot output source is absent"))?
        .split_once('.')
        .ok_or_else(|| anyhow!("snapshot output mapping must name snapshot.field"))?;
    let field = field.strip_prefix("record.").unwrap_or(field);
    if source != "snapshot" || field.contains('.') {
        bail!("snapshot outputs must use one flat logical snapshot field");
    }
    if field == "presence" {
        if name != "exists"
            || !matches!(
                declaration.output_type,
                FactType::Boolean | FactType::Presence
            )
            || declaration.nullable
            || declaration.max_bytes.is_some()
        {
            bail!("snapshot presence must be the non-null exists output");
        }
        return Ok(());
    }
    validate_stable_id(field, "snapshot logical field")?;
    if name != field {
        bail!("snapshot output ids must equal their logical projected field names");
    }
    if declaration.output_type == FactType::Presence {
        bail!("presence outputs must map snapshot.presence");
    }
    if declaration.output_type == FactType::String
        && declaration
            .max_bytes
            .is_none_or(|bound| bound == 0 || bound > 64 * 1024)
    {
        bail!("snapshot string output requires a positive bounded max_bytes");
    }
    if declaration.output_type != FactType::String && declaration.max_bytes.is_some() {
        bail!("only snapshot string outputs may declare max_bytes");
    }
    Ok(())
}

fn integration_operations(
    integration: &IntegrationDocument,
) -> &BTreeMap<String, OperationDeclaration> {
    match &integration.capability {
        CapabilityDeclaration::Http { http } => &http.operations,
        CapabilityDeclaration::Script { script } => &script.operations,
        CapabilityDeclaration::Snapshot { .. } => {
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
        CapabilityDeclaration::Http { http } => &http.credential,
        CapabilityDeclaration::Script { script } => &script.credential,
        CapabilityDeclaration::Snapshot { .. } => {
            static NONE: CredentialInterface = CredentialInterface {
                credential_type: CredentialType::None,
                name: None,
                max_value_bytes: None,
                request: None,
                response_profile: None,
                scope: None,
                audience: None,
                refresh_skew: None,
            };
            &NONE
        }
    }
}

fn integration_script(integration: &IntegrationDocument) -> Option<&Path> {
    match &integration.capability {
        CapabilityDeclaration::Script { script } => Some(script.script.as_path()),
        CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Snapshot { .. } => None,
    }
}

#[cfg(test)]
mod fixture_interface_tests {
    use super::*;

    fn rhai_project() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/project-authoring/dhis2-sandboxed-rhai")
    }

    fn compiled_project(
        loaded: &LoadedRegistryProject,
    ) -> Result<(
        CompiledProject,
        registry_relay::offline_fixture::OfflineRelayFixture,
    )> {
        let environment = offline_fixture_environment(loaded)?;
        let compiled =
            compile_project_for_environment(loaded, "offline-fixture", &environment, None)?;
        let relay_config = compiled
            .relay_private
            .get(Path::new("config/relay.yaml"))
            .ok_or_else(|| anyhow!("generated Relay config is absent"))?;
        let fixture = compile_generated_relay_fixture(relay_config, &compiled.relay_private)?;
        Ok((compiled, fixture))
    }

    #[test]
    fn trace_is_deterministic_material_and_value_free() {
        let loaded = load_registry_project(&rhai_project(), None).expect("Rhai project loads");
        let (compiled, relay_fixture) = compiled_project(&loaded).expect("Rhai project compiles");
        let (_, fixture) = loaded.integrations["health-record"]
            .fixtures
            .iter()
            .find(|(_, fixture)| fixture.name == "complete-health-match")
            .expect("match fixture exists");
        let input = offline_fixture_input(fixture).expect("fixture input is valid");
        let interactions =
            offline_fixture_interactions(fixture).expect("fixture interactions are valid");
        let ordinary = execute_offline_profiles(
            &compiled,
            &relay_fixture,
            "health-record",
            input.clone(),
            interactions.clone(),
            false,
        )
        .expect("ordinary fixture passes");
        assert_eq!(ordinary.calls, ["allow-1"]);

        let traced = execute_offline_profiles(
            &compiled,
            &relay_fixture,
            "health-record",
            input,
            interactions,
            true,
        )
        .expect("traced fixture passes");
        assert_eq!(traced.calls.len(), 1);
        assert_eq!(
            traced.calls[0],
            "call=1 operation=allow-1 method=GET path=/api/tracker/trackedEntities/* query=[fields] headers=[] body=none"
        );
        for sensitive in ["A0000000001", "Nia", "REF-0001"] {
            assert!(!traced.calls[0].contains(sensitive));
        }
    }

    #[test]
    fn rhai_preflight_addresses_the_script_file_and_safe_cause_once() {
        let mut loaded = load_registry_project(&rhai_project(), None).expect("Rhai project loads");
        let integration = loaded
            .integrations
            .get_mut("health-record")
            .expect("integration exists");
        integration.script.as_mut().expect("script exists").1 =
            b"fn consult(ctx) {\n  let marker = \"selector-marker\"; let broken = ;\n}"
                .to_vec()
                .into_boxed_slice();
        let error = preflight_project_rhai_scripts(&loaded)
            .expect_err("broken script rejects")
            .to_string();
        assert!(error.contains("integration=health-record"));
        assert!(error.contains("field=capability.script.file"));
        assert!(error.contains("file=integrations/health-record/adapter.rhai"));
        assert!(error.contains("line=2"));
        assert!(error.contains("cause=syntax_error"));
        assert!(!error.contains("selector-marker"));

        let integration = loaded
            .integrations
            .get_mut("health-record")
            .expect("integration exists");
        integration.script.as_mut().expect("script exists").1 =
            b"fn consult(left, right) { result.no_match() }"
                .to_vec()
                .into_boxed_slice();
        let error = preflight_project_rhai_scripts(&loaded)
            .expect_err("wrong signature rejects")
            .to_string();
        assert!(error.contains("cause=unsupported_function_signature"));
        assert!(error.contains("function=consult"));
        assert!(error.contains("valid_signatures=[consult(context)]"));

        let integration = loaded
            .integrations
            .get_mut("health-record")
            .expect("integration exists");
        integration.script.as_mut().expect("script exists").1 =
            b"fn other(ctx) { result.no_match() }"
                .to_vec()
                .into_boxed_slice();
        let error = preflight_project_rhai_scripts(&loaded)
            .expect_err("unknown entrypoint rejects")
            .to_string();
        assert!(error.contains("field=capability.script.file"));
        assert!(error.contains("file=integrations/health-record/adapter.rhai"));
        assert!(error.contains("cause=unknown_function"));
        assert!(error.contains("function=consult"));
        assert!(error.contains("valid_signatures=[consult(context)]"));

        let integration = loaded
            .integrations
            .get_mut("health-record")
            .expect("integration exists");
        integration.script.as_mut().expect("script exists").1 =
            b"fn consult(ctx) {\n  let value = xw.text.lowercase(\"argument-marker-8877\");\n  result.no_match()\n}"
                .to_vec()
                .into_boxed_slice();
        let error = preflight_project_rhai_scripts(&loaded)
            .expect_err("unknown xw helper rejects")
            .to_string();
        assert!(error.contains("field=capability.script.file"));
        assert!(error.contains("file=integrations/health-record/adapter.rhai"));
        assert!(error.contains("line=2"));
        assert!(error.contains("cause=unknown_function"));
        assert!(error.contains("function=xw.text.lowercase"));
        assert!(error.contains("valid_signatures=[xw.text.lower_ascii(value: string) -> string]"));
        assert!(!error.contains("argument-marker-8877"));
    }
}

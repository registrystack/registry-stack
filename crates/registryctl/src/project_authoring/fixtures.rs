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
        let signatures = if diagnostic.valid_signatures().is_empty() {
            String::new()
        } else {
            format!(
                " valid_signatures=[{}]",
                diagnostic.valid_signatures().join("|")
            )
        };
        bail!(
            "integration={alias} field={field} file={relative}{line}{column} cause={}{}{}",
            diagnostic.cause().as_str(),
            function,
            signatures,
        );
    }
    Ok(())
}

fn rhai_diagnostic_source(
    integration: &LoadedIntegration,
    compiled_line: Option<usize>,
) -> Option<(&Path, Option<usize>, &'static str)> {
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

type FixtureExecutionObservations = (
    Vec<FixtureReport>,
    Vec<GeneratedFixtureObservation>,
    Vec<AuthoredRequestBindingObservation>,
    Option<FixtureSafeCode>,
);

fn execute_all_fixtures_with_coverage_observations(
    loaded: &LoadedRegistryProject,
    compiled: &CompiledProject,
    integration_filter: Option<&str>,
    fixture_filter: Option<&str>,
    trace: bool,
    execution_context: &ProjectExecutionContext,
) -> Result<FixtureExecutionObservations> {
    let call_budget_actual =
        platform_call_budget_result(loaded, compiled, execution_context.worker_program())?;
    if loaded.integrations.is_empty() {
        return Ok((Vec::new(), Vec::new(), Vec::new(), call_budget_actual));
    }
    let relay_config = compiled
        .relay_private
        .get(Path::new("config/relay.yaml"))
        .ok_or_else(|| anyhow!("generated Relay config is absent"))?;
    let relay_fixture = compile_generated_relay_fixture(
        relay_config,
        &compiled.relay_private,
        Some(execution_context.worker_program()),
    )?;
    let mut reports = Vec::new();
    let mut generated_observations = Vec::new();
    let mut request_observations = Vec::new();
    for (alias, integration) in &loaded.integrations {
        if integration_filter.is_some_and(|selected| selected != alias) {
            continue;
        }
        for (fixture_path, fixture) in &integration.fixtures {
            if fixture_filter.is_some_and(|selected| selected != fixture.name) {
                continue;
            }
            if let Some(request) = fixture.request.as_ref() {
                if validate_governed_request(loaded, request, false).is_err() {
                    request_observations.push(AuthoredRequestBindingObservation {
                        integration: alias.clone(),
                        source_fixture_id: fixture.name.clone(),
                        pass_state: FixturePassState::Failed,
                        consultations: Vec::new(),
                        actual_safe_code: Some(FixtureSafeCode::RedactedUnclassifiedError),
                        actual_relay_consultations: Some(0),
                    });
                    reports.push(FixtureReport {
                        integration: alias.clone(),
                        fixture: fixture.name.clone(),
                        inputs: fixture.input.keys().cloned().collect(),
                        calls: Vec::new(),
                        outputs: Vec::new(),
                        claims: Vec::new(),
                        outcome: None,
                        expected_error: fixture.expect.error.clone(),
                        source_access: Some(false),
                        passed: false,
                        failure: Some(
                            "request_to_consultation_binding_invalid: relay_consultations=0"
                                .to_owned(),
                        ),
                    });
                    continue;
                }
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
                        execution_context.worker_program(),
                    )
                    .with_context(|| {
                        format!(
                            "failed to evaluate product claims for fixture {}.{}",
                            alias, fixture.name
                        )
                    })?
                    .result
                    {
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
            if let Some(request) = fixture.request.as_ref() {
                let binding = result.as_ref().map_err(|code| code.clone()).and_then(
                    |(outputs, outcome)| {
                        evaluate_authored_governed_request(
                            loaded,
                            compiled,
                            fixture,
                            request,
                            outputs,
                            outcome,
                            execution_context.worker_program(),
                        )
                        .map_err(|_| "request.binding_evaluation_failed".to_owned())
                    },
                );
                let (pass_state, consultations, actual_safe_code, actual_relay_consultations) =
                    match binding {
                    Ok(evaluation)
                        if evaluation.result.is_ok() && evaluation.relay_calls > 0 =>
                    {
                        (
                            FixturePassState::Passed,
                            evaluation.consultations,
                            None,
                            Some(u32::try_from(evaluation.relay_calls).unwrap_or(u32::MAX)),
                        )
                    }
                    Ok(evaluation) => (
                        FixturePassState::Failed,
                        Vec::new(),
                        evaluation
                            .result
                            .as_ref()
                            .err()
                            .map(|code| FixtureSafeCode::from_runtime_code(code)),
                        Some(u32::try_from(evaluation.relay_calls).unwrap_or(u32::MAX)),
                    ),
                    Err(_) => (
                        FixturePassState::Failed,
                        Vec::new(),
                        Some(FixtureSafeCode::RedactedUnclassifiedError),
                        Some(0),
                    ),
                };
                request_observations.push(AuthoredRequestBindingObservation {
                    integration: alias.clone(),
                    source_fixture_id: fixture.name.clone(),
                    pass_state,
                    consultations,
                    actual_safe_code,
                    actual_relay_consultations,
                });
                reports.push(FixtureReport {
                    integration: alias.clone(),
                    fixture: format!(
                        "{}::derived/request_to_consultation_binding",
                        fixture.name
                    ),
                    inputs: fixture.input.keys().cloned().collect(),
                    calls: if actual_relay_consultations.unwrap_or_default() > 0 {
                        vec!["notary-relay-consultation".to_owned()]
                    } else {
                        Vec::new()
                    },
                    outputs: Vec::new(),
                    claims: request
                        .claims
                        .iter()
                        .map(|claim| claim.id.clone())
                        .collect(),
                    outcome: None,
                    expected_error: None,
                    source_access: Some(actual_relay_consultations.unwrap_or_default() > 0),
                    passed: pass_state == FixturePassState::Passed,
                    failure: (pass_state != FixturePassState::Passed).then(|| {
                        format!(
                            "request_to_consultation_binding_failed: relay_consultations={}",
                            actual_relay_consultations.unwrap_or_default()
                        )
                    }),
                });
            }
            reports.extend(derived_fixture_reports(
                loaded,
                compiled,
                &relay_fixture,
                alias,
                fixture,
                trace,
                &mut generated_observations,
                execution_context.worker_program(),
            )?);
        }
    }
    if reports.is_empty() && (integration_filter.is_some() || fixture_filter.is_some()) {
        bail!("the selected integration or fixture does not exist");
    }
    Ok((
        reports,
        generated_observations,
        request_observations,
        call_budget_actual,
    ))
}

// The execution seam keeps each authority and observation channel explicit.
#[allow(clippy::too_many_arguments)]
fn derived_fixture_reports(
    loaded: &LoadedRegistryProject,
    compiled: &CompiledProject,
    relay_fixture: &registry_relay::offline_fixture::OfflineRelayFixture,
    integration_alias: &str,
    fixture: &FixtureDocument,
    trace: bool,
    generated_observations: &mut Vec<GeneratedFixtureObservation>,
    worker_program: &Path,
) -> Result<Vec<FixtureReport>> {
    use registry_relay::offline_fixture::OfflineSourceResponse;

    let base = offline_fixture_interactions(fixture).map_err(|error| anyhow!(error))?;
    let input = offline_fixture_input(fixture).map_err(|error| anyhow!(error))?;
    let mut cases = Vec::<(
        GeneratorRecipeId,
        Vec<registry_relay::offline_fixture::OfflineInteraction>,
        &str,
    )>::new();
    let supports_remote_source = matches!(
        loaded.integrations[integration_alias].document.capability,
        CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. }
    );
    if supports_remote_source {
        let mut request_mismatch = base.clone();
        if let Some(interaction) = request_mismatch.first_mut() {
            interaction
                .request
                .path
                .push_str("/__registry_fixture_mismatch");
            cases.push((
                GeneratorRecipeId::RequestAuthority,
                request_mismatch,
                "fixture.request_mismatch",
            ));
        }
        let mut request_order = base.clone();
        if let Some((left, right)) = distinguishable_request_pair(&request_order) {
            request_order.swap(left, right);
            cases.push((
                GeneratorRecipeId::RequestOrder,
                request_order,
                "fixture.request_mismatch",
            ));
        }
        let mut rejected_status = base.clone();
        if let Some(interaction) = rejected_status.last_mut() {
            interaction.response = OfflineSourceResponse::Http {
                status: 500,
                headers: BTreeMap::new(),
                // Keep the representation valid so script capabilities can
                // classify the rejected status before body decoding can mask it.
                body: b"{}".to_vec(),
            };
            cases.push((
                GeneratorRecipeId::StatusRejection,
                rejected_status,
                "source.status_rejected",
            ));
        }
        let mut malformed = base.clone();
        if let Some(interaction) = malformed.last_mut() {
            interaction.response = OfflineSourceResponse::Http {
                status: 200,
                headers: BTreeMap::new(),
                body: b"{".to_vec(),
            };
            cases.push((
                GeneratorRecipeId::MalformedDecode,
                malformed,
                "source.response_malformed",
            ));
        }
        let mut oversized = base.clone();
        if let Some(interaction) = oversized.last_mut() {
            interaction.response = OfflineSourceResponse::DeclaredBodyBytes {
                status: 200,
                body_bytes: u64::MAX,
            };
            cases.push((
                GeneratorRecipeId::ByteCeiling,
                oversized,
                "source.response_too_large",
            ));
        }
        let mut timeout = base.clone();
        if let Some(interaction) = timeout.last_mut() {
            interaction.response = OfflineSourceResponse::Timeout;
            cases.push((
                GeneratorRecipeId::Timeout,
                timeout,
                "source.deadline_exceeded",
            ));
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
                        GeneratorRecipeId::ProtocolVerification,
                        protocol,
                        "source.response_malformed",
                    ));
                }
            }
        }
    }

    cases.retain(|(recipe_id, _, _)| {
        matches!(
            generated_recipe_applicability(loaded, integration_alias, fixture, *recipe_id),
            GeneratedRecipeApplicability::Applicable {}
        )
    });

    let mut reports = cases
        .into_iter()
        .map(|(recipe_id, interactions, expected)| {
            let mut calls = Vec::new();
            let result = execute_offline_profiles(
                compiled,
                relay_fixture,
                integration_alias,
                input.clone(),
                interactions,
                trace,
                &mut calls,
            )
            .map(|mut observation| {
                if calls.is_empty() {
                    calls = std::mem::take(&mut observation.calls);
                }
                observation
            });
            let actual = result.as_ref().err().map(String::as_str);
            let passed = actual == Some(expected);
            generated_observations.push(GeneratedFixtureObservation {
                integration: integration_alias.to_owned(),
                source_fixture_id: fixture.name.clone(),
                recipe_id,
                actual_safe_code: actual.map(FixtureSafeCode::from_runtime_code),
                pass_state: if passed {
                    FixturePassState::Passed
                } else {
                    FixturePassState::Failed
                },
                actual_source_calls: Some(u32::try_from(calls.len()).unwrap_or(u32::MAX)),
            });
            FixtureReport {
                integration: integration_alias.to_owned(),
                fixture: format!(
                    "{}::derived/{}",
                    fixture.name,
                    generated_recipe_fixture_suffix(recipe_id)
                ),
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
            worker_program,
        )?;
        let authorization_error = authorization.result.err();
        let authorization_passed = authorization_error.as_deref() == Some("authorization.denied");
        let actual_source_calls = u32::try_from(authorization.relay_calls).unwrap_or(u32::MAX);
        let passed = authorization_passed && actual_source_calls == 0;
        generated_observations.push(GeneratedFixtureObservation {
            integration: integration_alias.to_owned(),
            source_fixture_id: fixture.name.clone(),
            recipe_id: GeneratorRecipeId::AuthorizationBeforeSource,
            actual_safe_code: authorization_error
                .as_deref()
                .map(FixtureSafeCode::from_runtime_code),
            pass_state: if passed {
                FixturePassState::Passed
            } else {
                FixturePassState::Failed
            },
            actual_source_calls: Some(actual_source_calls),
        });
        reports.push(FixtureReport {
            integration: integration_alias.to_owned(),
            fixture: format!("{}::derived/authorization_before_source", fixture.name),
            inputs: fixture.input.keys().cloned().collect(),
            calls: Vec::new(),
            outputs: Vec::new(),
            claims: Vec::new(),
            outcome: None,
            expected_error: Some("authorization.denied".to_owned()),
            source_access: Some(actual_source_calls != 0),
            passed,
            failure: (!passed).then(|| {
                format!(
                    "derived_authorization_mismatch: expected=authorization.denied, actual={}, source_calls={actual_source_calls}",
                    authorization_error.as_deref().unwrap_or("success"),
                )
            }),
        });
    }

    let mut minimized = base;
    // Ignoring unselected upstream members is a declarative HTTP projection
    // guarantee. Snapshot rows are the reviewed materialization contract, so
    // injecting an undeclared field there must remain a malformed response.
    if supports_remote_source
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
                let mut trace_calls = Vec::new();
                let result = execute_offline_profiles(
                    compiled,
                    relay_fixture,
                    integration_alias,
                    input,
                    minimized,
                    trace,
                    &mut trace_calls,
                );
                let evaluated = match result {
                    Ok(mut observation) => {
                        if trace_calls.is_empty() {
                            trace_calls = std::mem::take(&mut observation.calls);
                        }
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
                        let evaluated_claims = if matches!(outcome, "match" | "no_match")
                            && integration_has_product_claims(loaded, integration_alias)
                        {
                            evaluate_product_claims(
                                loaded,
                                compiled,
                                integration_alias,
                                fixture,
                                Some((&observation.outputs, outcome)),
                                registry_notary_server::standalone::OfflineAuthentication::Valid,
                                false,
                                worker_program,
                            )?
                            .result
                            .map(Some)
                        } else if matches!(outcome, "match" | "no_match") {
                            Ok(Some(BTreeMap::new()))
                        } else {
                            Ok(None)
                        };
                        evaluated_claims
                            .map(|claims| (observation.outputs, outcome.to_owned(), claims))
                    }
                    Err(error) => Err(error),
                };
                let passed = match (&evaluated, fixture.expect.error.as_deref()) {
                    (Ok((outputs, outcome, claims)), None) => {
                        let outcome_matches = fixture
                            .expect
                            .outcome
                            .as_deref()
                            .is_none_or(|expected| expected == outcome);
                        let claims_match = if outcome == "ambiguous" {
                            fixture.expect.claims.is_empty()
                        } else {
                            claims.as_ref() == Some(&fixture.expect.claims)
                        };
                        outputs == &fixture.expect.outputs && outcome_matches && claims_match
                    }
                    (Err(actual), Some(expected)) => actual == expected,
                    _ => false,
                };
                let actual_safe_code = evaluated
                    .as_ref()
                    .err()
                    .map(|code| FixtureSafeCode::from_runtime_code(code));
                let outputs = evaluated
                    .as_ref()
                    .ok()
                    .map(|(outputs, _, _)| outputs.keys().cloned().collect())
                    .unwrap_or_default();
                let claims = evaluated
                    .as_ref()
                    .ok()
                    .and_then(|(_, _, claims)| claims.as_ref())
                    .map(|claims| claims.keys().cloned().collect())
                    .unwrap_or_default();
                let outcome = evaluated
                    .as_ref()
                    .ok()
                    .map(|(_, outcome, _)| outcome.clone());
                let actual_source_calls = u32::try_from(trace_calls.len()).unwrap_or(u32::MAX);
                reports.push(FixtureReport {
                    integration: integration_alias.to_owned(),
                    fixture: format!("{}::derived/output_minimization", fixture.name),
                    inputs: fixture.input.keys().cloned().collect(),
                    calls: trace_calls,
                    outputs,
                    claims,
                    outcome,
                    expected_error: fixture.expect.error.clone(),
                    source_access: evaluated
                        .as_ref()
                        .err()
                        .map(|code| error_implies_source_access(code))
                        .or(Some(true)),
                    passed,
                    failure: (!passed)
                        .then(|| "derived_output_minimization_changed_result".to_owned()),
                });
                generated_observations.push(GeneratedFixtureObservation {
                    integration: integration_alias.to_owned(),
                    source_fixture_id: fixture.name.clone(),
                    recipe_id: GeneratorRecipeId::OutputMinimization,
                    actual_safe_code,
                    pass_state: if passed {
                        FixturePassState::Passed
                    } else {
                        FixturePassState::Failed
                    },
                    actual_source_calls: Some(actual_source_calls),
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

fn generated_recipe_fixture_suffix(recipe: GeneratorRecipeId) -> &'static str {
    match recipe {
        GeneratorRecipeId::RequestAuthority => "request_authority",
        GeneratorRecipeId::RequestOrder => "request_order",
        GeneratorRecipeId::StatusRejection => "status_rejection",
        GeneratorRecipeId::MalformedDecode => "malformed_decode",
        GeneratorRecipeId::ByteCeiling => "byte_ceiling",
        GeneratorRecipeId::Timeout => "timeout",
        GeneratorRecipeId::ProtocolVerification => "protocol_verification",
        GeneratorRecipeId::AuthorizationBeforeSource => "authorization_before_source",
        GeneratorRecipeId::OutputMinimization => "output_minimization",
    }
}

/// Builds the value-free v1 coverage report from the authoritative loaded
/// project and the observations produced by the existing offline executor.
///
/// Every integration is an isolated target with the same ordered requirement
/// matrix. The regular command has no baseline-to-candidate comparison, so the
/// four affected-fixture requirements remain honestly `not_evaluated`.
fn generate_fixture_coverage_report(
    loaded: &LoadedRegistryProject,
    fixture_reports: &[FixtureReport],
    generated_observations: &[GeneratedFixtureObservation],
    request_observations: &[AuthoredRequestBindingObservation],
    call_budget_actual: Option<FixtureSafeCode>,
) -> Result<ProjectFixtureCoverageReportV1> {
    generate_fixture_coverage_report_with_comparison(
        loaded,
        fixture_reports,
        generated_observations,
        request_observations,
        call_budget_actual,
        None,
    )
}

fn generate_fixture_coverage_report_with_comparison(
    loaded: &LoadedRegistryProject,
    fixture_reports: &[FixtureReport],
    generated_observations: &[GeneratedFixtureObservation],
    request_observations: &[AuthoredRequestBindingObservation],
    call_budget_actual: Option<FixtureSafeCode>,
    comparison_input: Option<&FixtureCoverageComparisonInput>,
) -> Result<ProjectFixtureCoverageReportV1> {
    validate_stable_id(
        &loaded.project.registry.id,
        "fixture coverage project identifier",
    )?;
    if let Some(environment) = loaded.environment_name.as_deref() {
        validate_stable_id(environment, "fixture coverage environment identifier")?;
    }
    if let Some(comparison_input) = comparison_input {
        comparison_input
            .validate()
            .map_err(|error| anyhow!(error))?;
    }

    let mut authored_report_index = BTreeMap::<(&str, &str), &FixtureReport>::new();
    for report in fixture_reports
        .iter()
        .filter(|report| !report.fixture.contains("::derived/"))
    {
        if authored_report_index
            .insert(
                (report.integration.as_str(), report.fixture.as_str()),
                report,
            )
            .is_some()
        {
            bail!("fixture coverage received a duplicate authored observation");
        }
    }
    let mut observation_index =
        BTreeMap::<(&str, &str, GeneratorRecipeId), &GeneratedFixtureObservation>::new();
    for observation in generated_observations {
        let key = (
            observation.integration.as_str(),
            observation.source_fixture_id.as_str(),
            observation.recipe_id,
        );
        if observation_index.insert(key, observation).is_some() {
            bail!("fixture coverage received a duplicate generated observation");
        }
    }
    let mut request_observation_index =
        BTreeMap::<(&str, &str), &AuthoredRequestBindingObservation>::new();
    for observation in request_observations {
        let key = (
            observation.integration.as_str(),
            observation.source_fixture_id.as_str(),
        );
        if request_observation_index.insert(key, observation).is_some() {
            bail!("fixture coverage received a duplicate governed request observation");
        }
    }

    let platform_case = call_budget_actual
        .map(build_platform_call_budget_case)
        .transpose()?;
    let mut targets = Vec::with_capacity(loaded.integrations.len());
    for (integration_alias, integration) in &loaded.integrations {
        let mut fixture_inventory = Vec::with_capacity(integration.fixtures.len());
        let mut generated_cases = Vec::with_capacity(
            integration
                .fixtures
                .len()
                .checked_mul(GeneratorRecipeId::ALL.len())
                .ok_or_else(|| anyhow!("fixture coverage generated record count overflowed"))?,
        );
        for (fixture_path, fixture) in &integration.fixtures {
            let source = fixture_coverage_source(integration_alias, fixture_path, fixture)?;
            let report = authored_report_index
                .get(&(integration_alias.as_str(), fixture.name.as_str()))
                .copied();
            let pass_state = report.map_or(FixturePassState::NotExecuted, |report| {
                if report.passed {
                    FixturePassState::Passed
                } else {
                    FixturePassState::Failed
                }
            });
            let expectation = authored_fixture_expectation(fixture)?;
            let fixture_evidence = fixture_coverage_evidence(
                FixtureCoverageEvidenceKind::AuthoredFixture,
                format!("target/{integration_alias}/fixture/{}", fixture.name),
                source.fixture_digest.clone(),
            )
            .map_err(|error| anyhow!(error))?;
            fixture_inventory.push(AuthoredSemanticFixtureCoverage {
                evidence: fixture_evidence,
                fixture_id: fixture.name.clone(),
                fixture_digest: source.fixture_digest.clone(),
                expectation,
                semantic_null: fixture_has_semantic_null(fixture),
                interaction_count: u32::try_from(fixture.interactions.len())
                    .map_err(|_| anyhow!("fixture interaction count exceeds the report range"))?,
                input_ids: fixture.input.keys().cloned().collect(),
                output_ids: fixture.expect.outputs.keys().cloned().collect(),
                claim_ids: fixture.expect.claims.keys().cloned().collect(),
                exercised_status_mappings: fixture_exercised_status_mappings_for_fixture(
                    &integration.document,
                    fixture,
                ),
                classification: FixtureCoverageClassification::Synthetic,
                pass_state,
                request_to_consultation_binding: match (
                    fixture.request.is_some(),
                    request_observation_index
                        .get(&(integration_alias.as_str(), fixture.name.as_str()))
                        .copied(),
                ) {
                    (false, None) => FixtureRequestBindingCoverage {
                        state: FixtureRequestBindingState::NotAuthored,
                        consultations: Vec::new(),
                        actual_relay_consultations: None,
                        safe_error_code: None,
                    },
                    (false, Some(_)) => {
                        bail!("fixture coverage observed a governed request that was not authored")
                    }
                    (true, None) => FixtureRequestBindingCoverage {
                        state: FixtureRequestBindingState::NotExecuted,
                        consultations: Vec::new(),
                        actual_relay_consultations: None,
                        safe_error_code: None,
                    },
                    (true, Some(observation)) => FixtureRequestBindingCoverage {
                        state: if observation.pass_state == FixturePassState::Passed {
                            FixtureRequestBindingState::Passed
                        } else {
                            FixtureRequestBindingState::Failed
                        },
                        consultations: observation.consultations.clone(),
                        actual_relay_consultations: observation.actual_relay_consultations,
                        safe_error_code: observation.actual_safe_code,
                    },
                },
            });

            for recipe_id in GeneratorRecipeId::ALL {
                let applicability =
                    generated_recipe_applicability(loaded, integration_alias, fixture, recipe_id);
                let observation = observation_index
                    .get(&(integration_alias.as_str(), fixture.name.as_str(), recipe_id))
                    .copied();
                if matches!(
                    applicability,
                    GeneratedRecipeApplicability::NotApplicable { .. }
                ) && observation.is_some()
                {
                    bail!(
                        "fixture coverage observed an inapplicable generated recipe {}",
                        generated_recipe_fixture_suffix(recipe_id)
                    );
                }
                let pass_state = if matches!(
                    applicability,
                    GeneratedRecipeApplicability::NotApplicable { .. }
                ) {
                    FixturePassState::NotExecuted
                } else {
                    observation.map_or(FixturePassState::NotExecuted, |value| value.pass_state)
                };
                let source_access_assertion = (recipe_id
                    == GeneratorRecipeId::AuthorizationBeforeSource
                    && matches!(applicability, GeneratedRecipeApplicability::Applicable {}))
                .then(|| {
                    let actual_source_calls =
                        observation.and_then(|value| value.actual_source_calls);
                    SourceAccessAssertion {
                        expected_source_calls: SourceCallExpectation::Zero,
                        actual_source_calls,
                        passed: actual_source_calls == Some(0),
                    }
                });
                let actual_safe_code = if recipe_id == GeneratorRecipeId::OutputMinimization {
                    None
                } else {
                    observation.and_then(|value| value.actual_safe_code)
                };
                let evidence_digest = fixture_coverage_digest(&(
                    recipe_id,
                    &source,
                    &applicability,
                    recipe_id.mutation_target(),
                    recipe_id.expected_safe_code(),
                    actual_safe_code,
                    pass_state,
                    &source_access_assertion,
                ))
                .map_err(|error| anyhow!(error))?;
                let evidence = fixture_coverage_evidence(
                    FixtureCoverageEvidenceKind::GeneratedCase,
                    format!(
                        "target/{integration_alias}/fixture/{}/generated/{}/v1",
                        fixture.name,
                        generated_recipe_fixture_suffix(recipe_id)
                    ),
                    evidence_digest,
                )
                .map_err(|error| anyhow!(error))?;
                generated_cases.push(GeneratedFixtureCoverage {
                    evidence,
                    recipe: GeneratorRecipe {
                        id: recipe_id,
                        version: GeneratorRecipeVersion::V1,
                    },
                    source_fixture: source.clone(),
                    applicability,
                    mutation_target_class: recipe_id.mutation_target(),
                    expected_safe_code: recipe_id.expected_safe_code(),
                    actual_safe_code,
                    pass_state,
                    source_access_assertion,
                });
            }
        }

        fixture_inventory.sort_by(|left, right| left.fixture_id.cmp(&right.fixture_id));
        generated_cases.sort_by(|left, right| {
            (&left.source_fixture.fixture_id, left.recipe.id)
                .cmp(&(&right.source_fixture.fixture_id, right.recipe.id))
        });
        let target_platform_cases = if matches!(
            integration.document.capability,
            CapabilityDeclaration::Script { .. }
        ) {
            platform_case.clone().into_iter().collect()
        } else {
            Vec::new()
        };
        let declared = fixture_target_declared_dimensions(loaded, integration_alias, integration);
        let exercised = fixture_target_exercised_dimensions(
            integration,
            &fixture_inventory,
            &generated_cases,
            &target_platform_cases,
        );
        let identity = FixtureCoverageTargetIdentity {
            integration: integration_alias.clone(),
            capability: fixture_coverage_capability(&integration.document.capability),
        };
        let contract =
            fixture_coverage_target_contract(loaded, integration_alias, integration)?;
        let compiled_contract = target_compiled_contract_evidence(&identity, &contract, &declared)
            .map_err(|error| anyhow!(error))?;
        let mut target = FixtureCoverageTarget {
            identity,
            contract,
            fixture_set_state: if fixture_inventory.is_empty() {
                FixtureSetState::Fixtureless
            } else {
                FixtureSetState::FixtureBearing
            },
            compiled_contract,
            fixture_inventory,
            generated_cases,
            platform_cases: target_platform_cases,
            declared,
            exercised,
            comparison: None,
            requirements: Vec::new(),
        };
        target.requirements = derive_fixture_coverage_requirements(
            &target,
            FixtureCoverageNotEvaluatedReason::ComparisonInputAbsent,
        );
        targets.push(target);
    }
    targets.sort_by(|left, right| left.identity.integration.cmp(&right.identity.integration));
    let report = ProjectFixtureCoverageReportV1::from_targets(
        loaded.project.registry.id.clone(),
        loaded.environment_name.clone(),
        targets,
    )
    .map_err(|error| anyhow!(error))?;
    match comparison_input {
        Some(input) => report
            .with_comparison(input)
            .map_err(|error| anyhow!(error)),
        None => Ok(report),
    }
}

fn build_platform_call_budget_case(
    actual_safe_code: FixtureSafeCode,
) -> Result<PlatformGeneratedFixtureCoverage> {
    let pass_state = if actual_safe_code == FixtureSafeCode::SourceCallBudgetExceeded {
        FixturePassState::Passed
    } else {
        FixturePassState::Failed
    };
    let evidence_digest = fixture_coverage_digest(&(
        PlatformGeneratedCaseId::RelayScriptCallBudget,
        GeneratorRecipeVersion::V1,
        PlatformCoverageComponent::RelayScriptWorker,
        FixtureMutationTargetClass::SourceCallBudget,
        FixtureSafeCode::SourceCallBudgetExceeded,
        actual_safe_code,
        pass_state,
    ))
    .map_err(|error| anyhow!(error))?;
    Ok(PlatformGeneratedFixtureCoverage {
        evidence: fixture_coverage_evidence(
            FixtureCoverageEvidenceKind::PlatformCase,
            "platform/relay-script-worker/call-budget/v1".to_owned(),
            evidence_digest,
        )
        .map_err(|error| anyhow!(error))?,
        case_id: PlatformGeneratedCaseId::RelayScriptCallBudget,
        version: GeneratorRecipeVersion::V1,
        component: PlatformCoverageComponent::RelayScriptWorker,
        mutation_target_class: FixtureMutationTargetClass::SourceCallBudget,
        expected_safe_code: FixtureSafeCode::SourceCallBudgetExceeded,
        actual_safe_code,
        pass_state,
    })
}

fn fixture_coverage_source(
    integration_alias: &str,
    fixture_path: &Path,
    fixture: &FixtureDocument,
) -> Result<GeneratedSourceFixture> {
    validate_stable_id(integration_alias, "fixture coverage integration identifier")?;
    validate_stable_id(&fixture.name, "fixture coverage fixture identifier")?;
    let bytes =
        fs::read(fixture_path).context("failed to read a fixture for coverage digesting")?;
    Ok(GeneratedSourceFixture {
        fixture_id: fixture.name.clone(),
        fixture_digest: Sha256Digest::new(sha256_uri(&bytes)).map_err(|error| anyhow!(error))?,
    })
}

fn fixture_coverage_capability(capability: &CapabilityDeclaration) -> FixtureCapability {
    match capability {
        CapabilityDeclaration::Http { .. } => FixtureCapability::DeclarativeHttp,
        CapabilityDeclaration::Script { .. } => FixtureCapability::Script,
        CapabilityDeclaration::Snapshot { .. } => FixtureCapability::Snapshot,
    }
}

fn fixture_coverage_target_contract(
    loaded: &LoadedRegistryProject,
    integration_alias: &str,
    integration: &LoadedIntegration,
) -> Result<FixtureCoverageTargetContract> {
    let source_operation_count = match &integration.document.capability {
        CapabilityDeclaration::Http { http } => Some(
            u32::try_from(http.operations.len())
                .map_err(|_| anyhow!("compiled HTTP operation count exceeds report range"))?,
        ),
        CapabilityDeclaration::Script { .. } | CapabilityDeclaration::Snapshot { .. } => None,
    };
    let mut reviewed_not_applicable = Vec::new();
    if integration.document.not_applicable.ambiguity.is_some() {
        reviewed_not_applicable.push(FixtureCoverageReviewedNotApplicable::SemanticAmbiguity);
    }
    if integration
        .document
        .not_applicable
        .subject_mismatch
        .is_some()
    {
        reviewed_not_applicable.push(FixtureCoverageReviewedNotApplicable::SubjectMismatch);
    }
    Ok(FixtureCoverageTargetContract {
        source_operation_count,
        reviewed_not_applicable,
        registry_backed_consultations: fixture_target_registry_backed_consultations(
            loaded,
            integration_alias,
        )?,
    })
}

fn fixture_target_registry_backed_consultations(
    loaded: &LoadedRegistryProject,
    integration_alias: &str,
) -> Result<Vec<FixtureConsultationIdentity>> {
    let mut identities = BTreeSet::new();
    for (service_id, service) in &loaded.project.services {
        if service.kind != ServiceKind::Evidence {
            continue;
        }
        for claim in service.claims.values() {
            if inferred_claim_evidence(service, claim)? != ClaimEvidence::RegistryBacked {
                continue;
            }
            let consultation_id = claim_consultation_name(service, claim)?;
            let consultation = service
                .consultations
                .get(consultation_id)
                .ok_or_else(|| anyhow!("registry-backed claim consultation is absent"))?;
            if consultation.integration == integration_alias {
                identities.insert(FixtureConsultationIdentity {
                    service_id: service_id.clone(),
                    consultation_id: consultation_id.to_owned(),
                });
            }
        }
    }
    Ok(identities.into_iter().collect())
}

fn distinguishable_request_pair(
    interactions: &[registry_relay::offline_fixture::OfflineInteraction],
) -> Option<(usize, usize)> {
    for left in 0..interactions.len() {
        for right in left + 1..interactions.len() {
            if interactions[left].request != interactions[right].request {
                return Some((left, right));
            }
        }
    }
    None
}

fn authored_fixture_expectation(fixture: &FixtureDocument) -> Result<FixtureSemanticExpectation> {
    if let Some(code) = fixture.expect.error.as_deref() {
        let code = FixtureSafeCode::from_runtime_code(code);
        if code == FixtureSafeCode::RedactedUnclassifiedError {
            bail!("authored fixture expects an unreportable error class");
        }
        return Ok(FixtureSemanticExpectation::SafeErrorCode { code });
    }
    let outcome = match fixture.expect.outcome.as_deref() {
        Some("match") => FixtureSemanticOutcome::Match,
        Some("no_match") => FixtureSemanticOutcome::NoMatch,
        Some("ambiguous") => FixtureSemanticOutcome::Ambiguous,
        None => FixtureSemanticOutcome::Successful,
        Some(_) => bail!("authored fixture has an unreportable semantic expectation"),
    };
    Ok(FixtureSemanticExpectation::Outcome { outcome })
}

fn generated_recipe_applicability(
    loaded: &LoadedRegistryProject,
    integration_alias: &str,
    fixture: &FixtureDocument,
    recipe_id: GeneratorRecipeId,
) -> GeneratedRecipeApplicability {
    let has_interaction = !fixture.interactions.is_empty();
    let has_protocol_matcher = fixture.interactions.iter().any(|interaction| {
        interaction
            .expect
            .body
            .as_ref()
            .is_some_and(contains_generated_fixture_matcher)
    });
    let final_json_object = matches!(
        fixture
            .interactions
            .last()
            .map(|interaction| &interaction.respond),
        Some(FixtureSourceResponse::Http {
            body: Value::Object(_),
            ..
        })
    );
    match recipe_id {
        GeneratorRecipeId::RequestAuthority
        | GeneratorRecipeId::RequestOrder
        | GeneratorRecipeId::StatusRejection
        | GeneratorRecipeId::ProtocolVerification
        | GeneratorRecipeId::MalformedDecode
        | GeneratorRecipeId::ByteCeiling
        | GeneratorRecipeId::Timeout
            if matches!(
                loaded.integrations[integration_alias].document.capability,
                CapabilityDeclaration::Snapshot { .. }
            ) =>
        {
            GeneratedRecipeApplicability::NotApplicable {
                reason: GeneratedNotApplicableReason::NoRemoteSourceCapability,
                invariant: CoverageInvariant::RemoteMutationRequiresRemoteSourceCapability,
            }
        }
        GeneratorRecipeId::RequestAuthority
        | GeneratorRecipeId::StatusRejection
        | GeneratorRecipeId::MalformedDecode
        | GeneratorRecipeId::ByteCeiling
        | GeneratorRecipeId::Timeout
            if !has_interaction =>
        {
            GeneratedRecipeApplicability::NotApplicable {
                reason: GeneratedNotApplicableReason::NoSourceInteraction,
                invariant: CoverageInvariant::MutationRequiresSourceInteraction,
            }
        }
        GeneratorRecipeId::RequestOrder if fixture.interactions.len() < 2 => {
            GeneratedRecipeApplicability::NotApplicable {
                reason: GeneratedNotApplicableReason::SingleSourceInteraction,
                invariant: CoverageInvariant::OrderMutationRequiresMultipleSourceInteractions,
            }
        }
        GeneratorRecipeId::RequestOrder
            if offline_fixture_interactions(fixture)
                .ok()
                .and_then(|interactions| distinguishable_request_pair(&interactions))
                .is_none() =>
        {
            GeneratedRecipeApplicability::NotApplicable {
                reason: GeneratedNotApplicableReason::NoDistinguishableRequestPair,
                invariant:
                    CoverageInvariant::OrderMutationRequiresDistinguishableSourceInteractions,
            }
        }
        GeneratorRecipeId::ProtocolVerification if !has_protocol_matcher => {
            GeneratedRecipeApplicability::NotApplicable {
                reason: GeneratedNotApplicableReason::NoGeneratedRequestMatcher,
                invariant: CoverageInvariant::ProtocolMutationRequiresGeneratedRequestMatcher,
            }
        }
        GeneratorRecipeId::ProtocolVerification if !final_json_object => {
            GeneratedRecipeApplicability::NotApplicable {
                reason: GeneratedNotApplicableReason::FinalResponseIsNotJsonObject,
                invariant: CoverageInvariant::MutationRequiresFinalJsonObjectResponse,
            }
        }
        GeneratorRecipeId::AuthorizationBeforeSource
            if !integration_has_product_claims(loaded, integration_alias) =>
        {
            GeneratedRecipeApplicability::NotApplicable {
                reason: GeneratedNotApplicableReason::IntegrationHasNoProductClaims,
                invariant: CoverageInvariant::AuthorizationCheckRequiresProductClaimEvaluation,
            }
        }
        GeneratorRecipeId::OutputMinimization
            if !matches!(
                loaded.integrations[integration_alias].document.capability,
                CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. }
            ) =>
        {
            GeneratedRecipeApplicability::NotApplicable {
                reason: GeneratedNotApplicableReason::SnapshotUsesClosedMaterialization,
                invariant: CoverageInvariant::SnapshotOutputUsesClosedMaterializationProjection,
            }
        }
        GeneratorRecipeId::OutputMinimization if has_protocol_matcher => {
            GeneratedRecipeApplicability::NotApplicable {
                reason: GeneratedNotApplicableReason::ProtocolMatcherOwnsResponseMutation,
                invariant: CoverageInvariant::ProtocolMatcherFixtureUsesProtocolVerificationInstead,
            }
        }
        GeneratorRecipeId::OutputMinimization if !final_json_object => {
            GeneratedRecipeApplicability::NotApplicable {
                reason: GeneratedNotApplicableReason::FinalResponseIsNotJsonObject,
                invariant: CoverageInvariant::MutationRequiresFinalJsonObjectResponse,
            }
        }
        _ => GeneratedRecipeApplicability::Applicable {},
    }
}

fn fixture_target_declared_dimensions(
    loaded: &LoadedRegistryProject,
    integration_alias: &str,
    integration: &LoadedIntegration,
) -> FixtureCoverageDimensions {
    let (claim_ids, disclosure_modes) =
        fixture_target_claims_and_disclosures(loaded, integration_alias);
    FixtureCoverageDimensions {
        input_ids: integration.document.input.keys().cloned().collect(),
        output_ids: integration.document.outputs.keys().cloned().collect(),
        claim_ids,
        disclosure_modes,
        status_mappings: fixture_status_mappings(&integration.document),
        protocol_helpers: fixture_protocol_helpers(&integration.document),
        limits: fixture_declared_limits(&integration.document),
        script_branch_ids: Vec::new(),
    }
}

fn fixture_target_exercised_dimensions(
    integration: &LoadedIntegration,
    inventory: &[AuthoredSemanticFixtureCoverage],
    generated: &[GeneratedFixtureCoverage],
    platform: &[PlatformGeneratedFixtureCoverage],
) -> FixtureCoverageDimensions {
    let passed = inventory
        .iter()
        .filter(|fixture| fixture.pass_state == FixturePassState::Passed)
        .collect::<Vec<_>>();
    let input_ids = passed
        .iter()
        .flat_map(|fixture| fixture.input_ids.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let output_ids = passed
        .iter()
        .flat_map(|fixture| fixture.output_ids.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let claim_ids = passed
        .iter()
        .flat_map(|fixture| fixture.claim_ids.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let protocol_helpers =
        if generated_recipe_complete(generated, GeneratorRecipeId::ProtocolVerification).0 {
            fixture_protocol_helpers(&integration.document)
        } else {
            Vec::new()
        };
    let mut limits = BTreeSet::new();
    if !matches!(
        integration.document.capability,
        CapabilityDeclaration::Snapshot { .. }
    ) {
        if generated_recipe_complete(generated, GeneratorRecipeId::ByteCeiling).0 {
            limits.insert(FixtureLimit::ResponseBytes);
        }
        if generated_recipe_complete(generated, GeneratorRecipeId::Timeout).0 {
            limits.insert(FixtureLimit::Deadline);
        }
    }
    if platform
        .iter()
        .any(|case| case.pass_state == FixturePassState::Passed)
    {
        limits.insert(FixtureLimit::CallCount);
    }
    FixtureCoverageDimensions {
        input_ids,
        output_ids,
        claim_ids,
        // Claim evaluation does not exercise disclosure selection.
        disclosure_modes: Vec::new(),
        status_mappings: fixture_exercised_status_mappings(integration, inventory),
        protocol_helpers,
        limits: limits.into_iter().collect(),
        // Semantic outcomes are not implementation branch identifiers.
        script_branch_ids: Vec::new(),
    }
}

fn fixture_target_claims_and_disclosures(
    loaded: &LoadedRegistryProject,
    integration_alias: &str,
) -> (Vec<String>, Vec<FixtureDisclosureMode>) {
    let mut claim_ids = BTreeSet::new();
    let mut modes = BTreeSet::new();
    for service in loaded.project.services.values() {
        if service.kind != ServiceKind::Evidence {
            continue;
        }
        for (claim_id, claim) in &service.claims {
            let belongs_to_target = claim_consultation_name(service, claim)
                .ok()
                .and_then(|consultation| service.consultations.get(consultation))
                .is_some_and(|consultation| consultation.integration == integration_alias);
            if !belongs_to_target {
                continue;
            }
            claim_ids.insert(claim_id.clone());
            match &claim.disclosure {
                DisclosureDeclaration::Mode(mode) => {
                    modes.insert(fixture_disclosure_mode(*mode));
                }
                DisclosureDeclaration::Policy { default, allowed } => {
                    modes.insert(fixture_disclosure_mode(*default));
                    modes.extend(allowed.iter().copied().map(fixture_disclosure_mode));
                }
            }
        }
    }
    (claim_ids.into_iter().collect(), modes.into_iter().collect())
}

fn fixture_disclosure_mode(mode: DisclosureMode) -> FixtureDisclosureMode {
    match mode {
        DisclosureMode::Value => FixtureDisclosureMode::Value,
        DisclosureMode::Predicate => FixtureDisclosureMode::Predicate,
        DisclosureMode::Redacted => FixtureDisclosureMode::Redacted,
    }
}

fn fixture_status_mappings(integration: &IntegrationDocument) -> Vec<FixtureStatusMapping> {
    let CapabilityDeclaration::Http { http } = &integration.capability else {
        return Vec::new();
    };
    let mut no_match = BTreeSet::new();
    let mut ambiguous = BTreeSet::new();
    for operation in http.operations.values() {
        let Some(statuses) = operation.response.status_semantics.as_ref() else {
            continue;
        };
        no_match.extend(statuses.no_match.iter().copied());
        ambiguous.extend(statuses.ambiguous.iter().copied());
    }
    [
        (FixtureStatusOutcome::Ambiguous, ambiguous),
        (FixtureStatusOutcome::NoMatch, no_match),
    ]
    .into_iter()
    .filter(|(_, statuses)| !statuses.is_empty())
    .map(|(outcome, statuses)| FixtureStatusMapping {
        outcome,
        statuses: statuses.into_iter().collect(),
    })
    .collect()
}

fn fixture_exercised_status_mappings(
    integration: &LoadedIntegration,
    inventory: &[AuthoredSemanticFixtureCoverage],
) -> Vec<FixtureStatusMapping> {
    let declared = fixture_status_mappings(&integration.document);
    declared
        .into_iter()
        .filter_map(|mapping| {
            let statuses = mapping
                .statuses
                .iter()
                .copied()
                .filter(|status| {
                    inventory.iter().any(|fixture| {
                        fixture.pass_state == FixturePassState::Passed
                            && fixture.exercised_status_mappings.iter().any(|exercised| {
                                exercised.outcome == mapping.outcome
                                    && exercised.statuses.binary_search(status).is_ok()
                            })
                    })
                })
                .collect::<Vec<_>>();
            (!statuses.is_empty()).then_some(FixtureStatusMapping {
                outcome: mapping.outcome,
                statuses,
            })
        })
        .collect()
}

fn fixture_exercised_status_mappings_for_fixture(
    integration: &IntegrationDocument,
    fixture: &FixtureDocument,
) -> Vec<FixtureStatusMapping> {
    fixture_status_mappings(integration)
        .into_iter()
        .filter_map(|mapping| {
            let outcome_matches = matches!(
                (mapping.outcome, fixture.expect.outcome.as_deref()),
                (FixtureStatusOutcome::NoMatch, Some("no_match"))
                    | (FixtureStatusOutcome::Ambiguous, Some("ambiguous"))
            );
            let statuses = if outcome_matches {
                mapping
                    .statuses
                    .into_iter()
                    .filter(|status| {
                        fixture.interactions.iter().any(|interaction| {
                            matches!(
                                interaction.respond,
                                FixtureSourceResponse::Http { status: actual, .. }
                                    if actual == *status
                            )
                        })
                    })
                    .collect()
            } else {
                Vec::new()
            };
            (!statuses.is_empty()).then_some(FixtureStatusMapping {
                outcome: mapping.outcome,
                statuses,
            })
        })
        .collect()
}

fn fixture_protocol_helpers(integration: &IntegrationDocument) -> Vec<FixtureProtocolHelper> {
    let mut helpers = BTreeSet::new();
    match &integration.capability {
        CapabilityDeclaration::Http { http } => {
            for operation in http.operations.values() {
                if operation.primitive.is_some() || operation.request.primitive.is_some() {
                    helpers.insert(FixtureProtocolHelper::RequestPrimitive);
                }
                if operation
                    .response
                    .codec
                    .as_deref()
                    .is_some_and(|codec| codec != "json_v1")
                {
                    helpers.insert(FixtureProtocolHelper::ResponseCodec);
                }
                if operation.verification.is_some() {
                    helpers.insert(FixtureProtocolHelper::Verification);
                }
            }
        }
        CapabilityDeclaration::Script { script } => {
            if script.signed_dci.is_some() {
                helpers.insert(FixtureProtocolHelper::SignedDci);
            }
        }
        CapabilityDeclaration::Snapshot { .. } => {}
    }
    helpers.into_iter().collect()
}

fn fixture_declared_limits(integration: &IntegrationDocument) -> Vec<FixtureLimit> {
    match integration.capability {
        CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. } => vec![
            FixtureLimit::AggregateSourceBytes,
            FixtureLimit::CallCount,
            FixtureLimit::Deadline,
            FixtureLimit::OutputBytes,
            FixtureLimit::RequestBytes,
            FixtureLimit::ResponseBytes,
        ],
        CapabilityDeclaration::Snapshot { .. } => vec![
            FixtureLimit::AggregateSourceBytes,
            FixtureLimit::OutputBytes,
        ],
    }
}

fn fixture_has_semantic_null(fixture: &FixtureDocument) -> bool {
    fixture
        .input
        .values()
        .chain(fixture.expect.outputs.values())
        .chain(fixture.expect.claims.values())
        .any(Value::is_null)
}

fn generated_recipe_complete(
    generated: &[GeneratedFixtureCoverage],
    recipe_id: GeneratorRecipeId,
) -> (bool, Vec<FixtureCoverageEvidence>) {
    let applicable = generated
        .iter()
        .filter(|case| {
            case.recipe.id == recipe_id
                && matches!(
                    case.applicability,
                    GeneratedRecipeApplicability::Applicable {}
                )
        })
        .collect::<Vec<_>>();
    let mut evidence = applicable
        .iter()
        .filter(|case| {
            case.pass_state == FixturePassState::Passed
                && case
                    .source_access_assertion
                    .as_ref()
                    .is_none_or(|assertion| assertion.passed)
        })
        .map(|case| case.evidence.clone())
        .collect::<Vec<_>>();
    evidence.sort();
    evidence.dedup();
    (
        !applicable.is_empty() && evidence.len() == applicable.len(),
        evidence,
    )
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
    code.starts_with("source.") || code == "failure.subject_mismatch"
}

struct ProductClaimsFixtureEvaluation {
    result: std::result::Result<BTreeMap<String, Value>, String>,
    relay_calls: u64,
    consultations: Vec<FixtureConsultationIdentity>,
}

/// Execute the independently authored governed request through the production
/// Notary request planner. The fixture input remains a separate oracle for the
/// exact Relay consultation key, so this path cannot derive a passing request
/// from the consultation mapping it is intended to verify.
fn evaluate_authored_governed_request(
    loaded: &LoadedRegistryProject,
    compiled: &CompiledProject,
    fixture: &FixtureDocument,
    request: &GovernedLiveRequest,
    outputs: &BTreeMap<String, Value>,
    outcome: &str,
    worker_program: &Path,
) -> Result<ProductClaimsFixtureEvaluation> {
    use registry_notary_server::standalone::{
        OfflineAuthentication, OfflineNotaryHarness, OfflineNotaryRequest,
        OfflineRelayConsultation, OfflineRelayOutcome,
    };

    let expected_consultations = governed_request_consultation_identities(loaded, request)?;
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
            let is_selected = loaded.project.services[&profile.service_id].purpose == request.purpose;
            OfflineRelayConsultation::decoded_inputs(
                profile.id.clone(),
                profile.contract_hash.clone(),
                loaded.project.services[&profile.service_id].purpose.clone(),
                relay_inputs.clone(),
                if is_selected {
                    relay_outcome
                } else {
                    OfflineRelayOutcome::NoMatch
                },
                if is_selected && relay_outcome == OfflineRelayOutcome::Match {
                    outputs.clone()
                } else {
                    BTreeMap::new()
                },
            )
        })
        .collect::<Vec<_>>();
    if relay_evidence.is_empty() {
        bail!("offline governed request has no exact Relay consultation profile");
    }
    let notary_config = compiled
        .notary_private
        .get(Path::new("config/notary.yaml"))
        .ok_or_else(|| anyhow!("generated Notary config is absent"))?;
    let notary_config: StandaloneRegistryNotaryConfig = serde_norway::from_slice(notary_config)
        .context("generated Notary config did not parse for offline governed request")?;
    let harness = OfflineNotaryHarness::compile(
        notary_config,
        relay_evidence,
        project_cel_worker_config(worker_program),
    )
    .context("production Notary offline harness did not compile")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build the offline governed request runtime")?;
    let evidence = runtime.block_on(harness.evaluate(
        OfflineNotaryRequest::new(OfflineAuthentication::Valid, request.to_evaluate_request())
            .with_header_purpose(request.purpose.as_str()),
    ));
    let relay_calls = evidence.relay_calls();
    if let Some(error) = evidence.error_class() {
        return Ok(ProductClaimsFixtureEvaluation {
            result: Err(error.as_str().to_owned()),
            relay_calls,
            consultations: Vec::new(),
        });
    }
    let verified = (|| -> Result<_> {
        if relay_calls != evidence.consultation_count() as u64 {
            bail!("offline Notary did not reuse each governed consultation exactly once");
        }
        let consultations =
            runtime_consultation_identities(compiled, evidence.relay_profile_ids())?;
        if evidence.consultation_count() != consultations.len() {
            bail!("offline Notary selected a different governed consultation cardinality");
        }
        if consultations != expected_consultations {
            bail!("offline Notary selected a different governed consultation set");
        }
        let mut claims = BTreeMap::new();
        for claim in evidence.claims() {
            if claims
                .insert(claim.claim_id().to_owned(), Value::Null)
                .is_some()
            {
                bail!("offline governed request returned a duplicate claim id");
            }
        }
        let requested = request
            .claims
            .iter()
            .map(|claim| claim.id.as_str())
            .collect::<BTreeSet<_>>();
        if claims.keys().map(String::as_str).collect::<BTreeSet<_>>() != requested {
            bail!("offline governed request did not return the exact selected claim set");
        }
        Ok((claims, consultations))
    })();
    Ok(match verified {
        Ok((claims, consultations)) => ProductClaimsFixtureEvaluation {
            result: Ok(claims),
            relay_calls,
            consultations,
        },
        Err(_) => ProductClaimsFixtureEvaluation {
            result: Err("request.binding_evaluation_failed".to_owned()),
            relay_calls,
            consultations: Vec::new(),
        },
    })
}

fn runtime_consultation_identities(
    compiled: &CompiledProject,
    relay_profile_ids: &[String],
) -> Result<Vec<FixtureConsultationIdentity>> {
    let mut identities = BTreeSet::new();
    for profile_id in relay_profile_ids {
        let profile = compiled
            .fixture_profiles
            .iter()
            .find(|profile| profile.id == *profile_id)
            .ok_or_else(|| anyhow!("offline Notary selected an unknown Relay profile"))?;
        if !identities.insert(FixtureConsultationIdentity {
            service_id: profile.service_id.clone(),
            consultation_id: profile.consultation_id.clone(),
        }) {
            bail!("offline Notary selected a duplicate governed consultation");
        }
    }
    Ok(identities.into_iter().collect())
}

fn governed_request_consultation_identities(
    loaded: &LoadedRegistryProject,
    request: &GovernedLiveRequest,
) -> Result<Vec<FixtureConsultationIdentity>> {
    let mut identities = BTreeSet::new();
    for requested_claim in &request.claims {
        let (service_id, service) = loaded
            .project
            .services
            .iter()
            .find(|(_, service)| {
                service.kind == ServiceKind::Evidence
                    && service.purpose == request.purpose
                    && service.claims.contains_key(&requested_claim.id)
            })
            .ok_or_else(|| anyhow!("governed request claim has no selected evidence service"))?;
        let claim = service
            .claims
            .get(&requested_claim.id)
            .ok_or_else(|| anyhow!("selected governed request claim is absent"))?;
        if inferred_claim_evidence(service, claim)? != ClaimEvidence::RegistryBacked {
            bail!("governed request claim is not registry-backed");
        }
        let consultation_id = claim_consultation_name(service, claim)?;
        identities.insert(FixtureConsultationIdentity {
            service_id: service_id.clone(),
            consultation_id: consultation_id.to_owned(),
        });
    }
    if identities.is_empty() {
        bail!("governed request selected no registry-backed consultation");
    }
    Ok(identities.into_iter().collect())
}

// Authentication and pre-source denial are independent security inputs and
// remain explicit at this offline product boundary.
#[allow(clippy::too_many_arguments)]
fn evaluate_product_claims(
    loaded: &LoadedRegistryProject,
    compiled: &CompiledProject,
    integration_alias: &str,
    fixture: &FixtureDocument,
    relay_result: Option<(&BTreeMap<String, Value>, &str)>,
    authentication: registry_notary_server::standalone::OfflineAuthentication,
    require_pre_source_denial: bool,
    worker_program: &Path,
) -> Result<ProductClaimsFixtureEvaluation> {
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
    let notary_config: StandaloneRegistryNotaryConfig = serde_norway::from_slice(notary_config)
        .context("generated Notary config did not parse for offline evaluation")?;
    let harness = OfflineNotaryHarness::compile(
        notary_config,
        relay_evidence,
        project_cel_worker_config(worker_program),
    )
    .context("production Notary offline harness did not compile")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build the offline Notary evaluation runtime")?;
    let mut claims = BTreeMap::new();
    let mut evaluated_any = false;
    let mut relay_calls = 0_u64;
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
        let mut attributes = BTreeMap::new();
        for consultation in service
            .consultations
            .values()
            .filter(|consultation| consultation.integration == integration_alias)
        {
            for (name, request_path) in &consultation.input {
                let value = fixture
                    .input
                    .get(name)
                    .ok_or_else(|| anyhow!("fixture omitted a compiled consultation input"))?;
                if request_path == "request.target.id" {
                    target.id = Some(
                        value
                            .as_str()
                            .ok_or_else(|| anyhow!("target id fixture input must be a String"))?
                            .to_string(),
                    );
                } else if let Some(scheme) =
                    request_path.strip_prefix("request.target.identifiers.")
                {
                    identifiers.insert(
                        scheme.to_string(),
                        value
                            .as_str()
                            .ok_or_else(|| {
                                anyhow!("target identifier fixture input must be a String")
                            })?
                            .to_string(),
                    );
                } else if let Some(name) = request_path.strip_prefix("request.target.attributes.") {
                    attributes.insert(name.to_string(), value.clone());
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
        target.attributes = attributes;
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
            relay_calls = relay_calls.saturating_add(evidence.relay_calls());
            if let Some(error) = evidence.error_class() {
                if require_pre_source_denial && evidence.relay_calls() != 0 {
                    bail!("derived authorization denial occurred after Relay access");
                }
                return Ok(ProductClaimsFixtureEvaluation {
                    result: Err(error.as_str().to_string()),
                    relay_calls,
                    consultations: Vec::new(),
                });
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
    Ok(ProductClaimsFixtureEvaluation {
        result: Ok(claims),
        relay_calls,
        consultations: Vec::new(),
    })
}

fn project_cel_worker_config(
    worker_program: &Path,
) -> registry_notary_server::cel_worker::CelWorkerConfig {
    let mut config =
        registry_notary_server::cel_worker::CelWorkerConfig::for_current_exe_subcommand();
    config.command = worker_program.to_path_buf();
    config.command_args = vec![std::ffi::OsString::from("__registryctl-cel-worker-v1")];
    config.command_envs.clear();
    config.current_dir = None;
    // Debug and sanitizer builds can take longer than the production worker's
    // evaluation deadline to cold-start the isolated subprocess. Project
    // conformance remains bounded, but must measure the rule rather than the
    // test binary's startup latency.
    config.request_timeout = std::time::Duration::from_secs(10);
    config
}

struct CallBudgetCoverageHost;

#[async_trait::async_trait]
impl registry_relay::rhai_worker::SourceHost for CallBudgetCoverageHost {
    async fn call(
        &mut self,
        _call: registry_relay::rhai_worker::SourceCall,
    ) -> std::result::Result<
        registry_relay::rhai_worker::SourceResponse,
        registry_relay::rhai_worker::HostFailure,
    > {
        Ok(registry_relay::rhai_worker::SourceResponse {
            status: 200,
            body: Value::Object(Map::new()),
            headers: BTreeMap::new(),
        })
    }
}

fn platform_call_budget_result(
    loaded: &LoadedRegistryProject,
    compiled: &CompiledProject,
    worker_program: &Path,
) -> Result<Option<FixtureSafeCode>> {
    use registry_relay::rhai_worker::{WorkerError, WorkerLimits, WorkerProcess, WorkerRequest};

    let authored_script_call_bounds = loaded
        .integrations
        .iter()
        .filter_map(|(alias, integration)| {
            matches!(
                integration.document.capability,
                CapabilityDeclaration::Script { .. }
            )
            .then_some((alias.clone(), u32::from(integration.document.bounds.calls)))
        })
        .collect::<BTreeMap<_, _>>();
    if authored_script_call_bounds.is_empty() {
        return Ok(None);
    }
    let compiled_script_call_bounds = compiled
        .relay_private
        .iter()
        .filter(|(path, _)| path.to_string_lossy().contains("private-bindings"))
        .filter_map(|(_, bytes)| serde_json::from_slice::<Value>(bytes).ok())
        .filter_map(|binding| {
            let source_instance = binding.get("source_instance")?.as_str()?.to_owned();
            let call_bound = binding
                .pointer("/capabilities/script/max_calls")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())?;
            Some((source_instance, call_bound))
        })
        .fold(
            BTreeMap::<String, BTreeSet<u32>>::new(),
            |mut bounds, (source_instance, call_bound)| {
                bounds
                    .entry(source_instance)
                    .or_default()
                    .insert(call_bound);
                bounds
            },
        );
    if !compiled_script_call_bounds_match(
        &authored_script_call_bounds,
        &compiled_script_call_bounds,
    ) {
        bail!("compiled private bindings did not preserve every authored Script limits.calls");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build the generated call-budget fixture runtime")?;
    let all_bounds_enforced = authored_script_call_bounds
        .values()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .all(|compiled_call_bound| {
            let source_calls = (0..=compiled_call_bound)
                .map(|index| format!("source.get(\"/__registry_call_budget_{index}\");"))
                .collect::<String>();
            let script = format!("fn consult(ctx) {{ {source_calls} result.no_match() }}");
            let request = WorkerRequest::v1(
                &script,
                "consult",
                WorkerLimits {
                    wall_time_ms: 5_000,
                    max_source_calls: compiled_call_bound,
                    ..WorkerLimits::default()
                },
            );
            matches!(
                runtime.block_on(
                    WorkerProcess::with_program(worker_program)
                        .evaluate_with_host(&request, &mut CallBudgetCoverageHost),
                ),
                Err(WorkerError::BudgetExceeded)
            )
        });
    Ok(Some(if all_bounds_enforced {
        FixtureSafeCode::SourceCallBudgetExceeded
    } else {
        FixtureSafeCode::RedactedUnclassifiedError
    }))
}

fn compiled_script_call_bounds_match(
    authored: &BTreeMap<String, u32>,
    compiled: &BTreeMap<String, BTreeSet<u32>>,
) -> bool {
    authored.iter().all(|(alias, authored_bound)| {
        compiled.get(&format!("{alias}-source")) == Some(&BTreeSet::from([*authored_bound]))
    })
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
        calls,
    )?;
    if calls.is_empty() {
        calls.extend(observation.calls);
    }
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
    calls: &mut Vec<String>,
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
    let execute = |profile: &FixtureProfile, calls: &mut Vec<String>| {
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
            let report = relay_fixture.execute_with_trace_report(request);
            calls.extend(report.calls);
            report.result
        } else {
            relay_fixture.execute(request)
        }
    };
    let observation = execute(first, calls).map_err(map_offline_relay_error)?;
    for profile in selected {
        let mut sibling_calls = Vec::new();
        let sibling = execute(profile, &mut sibling_calls).map_err(map_offline_relay_error)?;
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
        OfflineFixtureError::SubjectMismatch => "failure.subject_mismatch",
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
        if declaration.output_type == OutputType::Presence {
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
            OutputType::Presence | OutputType::Boolean
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
    if declaration.output_type == OutputType::String
        && declaration
            .max_bytes
            .is_none_or(|bound| bound == 0 || bound > 64 * 1024)
    {
        bail!("string output requires a positive bounded max_bytes");
    }
    if declaration.output_type != OutputType::String && declaration.max_bytes.is_some() {
        bail!("only string outputs may declare max_bytes");
    }
    if declaration.output_type == OutputType::Presence && path != "presence" {
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
            (OutputType::Boolean, SchemaNode::Boolean) => true,
            (OutputType::Integer, SchemaNode::Integer { .. }) => true,
            (OutputType::String, SchemaNode::String { max_bytes }) => {
                declaration.max_bytes == Some(*max_bytes)
            }
            (OutputType::Date, SchemaNode::Date) => true,
            (OutputType::Presence, _) | (_, _) => false,
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
                OutputType::Boolean | OutputType::Presence
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
    if declaration.output_type == OutputType::Presence {
        bail!("presence outputs must map snapshot.presence");
    }
    if declaration.output_type == OutputType::String
        && declaration
            .max_bytes
            .is_none_or(|bound| bound == 0 || bound > 64 * 1024)
    {
        bail!("snapshot string output requires a positive bounded max_bytes");
    }
    if declaration.output_type != OutputType::String && declaration.max_bytes.is_some() {
        bail!("only snapshot string outputs may declare max_bytes");
    }
    Ok(())
}

fn integration_operations(
    integration: &IntegrationDocument,
) -> &BTreeMap<String, OperationDeclaration> {
    match &integration.capability {
        CapabilityDeclaration::Http { http } => &http.operations,
        CapabilityDeclaration::Script { .. } | CapabilityDeclaration::Snapshot { .. } => {
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
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/project-authoring/dhis2-script")
    }

    #[test]
    fn compiled_call_budget_evidence_requires_every_script_integration_bound() {
        let authored = BTreeMap::from([("first".to_owned(), 1_u32), ("second".to_owned(), 3_u32)]);
        let complete = BTreeMap::from([
            ("first-source".to_owned(), BTreeSet::from([1_u32])),
            ("second-source".to_owned(), BTreeSet::from([3_u32])),
        ]);
        assert!(compiled_script_call_bounds_match(&authored, &complete));

        let missing = BTreeMap::from([("first-source".to_owned(), BTreeSet::from([1_u32]))]);
        assert!(!compiled_script_call_bounds_match(&authored, &missing));

        let wrong = BTreeMap::from([
            ("first-source".to_owned(), BTreeSet::from([1_u32])),
            ("second-source".to_owned(), BTreeSet::from([1_u32])),
        ]);
        assert!(!compiled_script_call_bounds_match(&authored, &wrong));
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

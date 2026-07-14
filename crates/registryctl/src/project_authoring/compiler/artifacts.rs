// SPDX-License-Identifier: Apache-2.0

fn compile_project(
    loaded: &LoadedRegistryProject,
    baseline: Option<&VerifiedBaseline>,
) -> Result<CompiledProject> {
    let environment = loaded
        .environment
        .as_ref()
        .ok_or_else(|| anyhow!("project build requires an explicit environment"))?;
    let environment_name = loaded
        .environment_name
        .as_deref()
        .ok_or_else(|| anyhow!("project build requires an explicit environment"))?;
    compile_project_for_environment(loaded, environment_name, environment, baseline)
}

fn compile_project_for_environment(
    loaded: &LoadedRegistryProject,
    environment_name: &str,
    environment: &EnvironmentDocument,
    baseline: Option<&VerifiedBaseline>,
) -> Result<CompiledProject> {
    validate_entity_generation_changes(loaded, environment, baseline)?;
    let mut reviewable = BTreeMap::new();
    let mut relay_private = BTreeMap::new();
    let mut packs = BTreeMap::new();

    for (id, entity) in &loaded.entities {
        reviewable.insert(
            PathBuf::from(format!("entities/{id}.json")),
            canonical_json_line(&serde_json::to_value(&entity.document)?)?.into_boxed_slice(),
        );
    }

    for (alias, integration) in &loaded.integrations {
        let evidence = generate_evidence(alias, integration)?;
        let pack_document =
            integration_pack_document(loaded, environment, alias, integration, &evidence)?;
        let authored =
            compile_integration_pack(&canonical_json_line(&pack_document)?).map_err(|error| {
                anyhow!("generated integration pack {alias} did not compile: {error:?}")
            })?;
        let path = PathBuf::from(format!("config/artifacts/integration-packs/{alias}.json"));
        let review_path = PathBuf::from(format!("integration-packs/{alias}.json"));
        reviewable.insert(review_path, authored.canonical_json().into());
        relay_private.insert(path, authored.canonical_json().into());
        for artifact in &evidence {
            relay_private.insert(
                PathBuf::from("config").join(&artifact.path),
                artifact.bytes.clone(),
            );
        }
        if integration.script.is_some() {
            let script_path = canonical_rhai_script_path(loaded, alias)?;
            relay_private.insert(
                PathBuf::from("config").join(script_path),
                compiled_rhai_source(integration)?,
            );
        }
        let id = pack_document["id"]
            .as_str()
            .ok_or_else(|| anyhow!("generated integration pack id is absent"))?
            .to_string();
        let version = pack_document["version"]
            .as_str()
            .ok_or_else(|| anyhow!("generated integration pack version is absent"))?
            .to_string();
        packs.insert(
            alias.clone(),
            GeneratedPack {
                alias: alias.clone(),
                id,
                version,
                artifact: authored,
                evidence,
            },
        );
    }

    let mut profiles = Vec::new();
    for (service_id, service) in &loaded.project.services {
        if service.kind != ServiceKind::Evidence {
            continue;
        }
        for (consultation_name, consultation) in &service.consultations {
            let pack = packs
                .get(&consultation.integration)
                .ok_or_else(|| anyhow!("generated consultation lacks its integration pack"))?;
            let (profile_id, profile_version) =
                generated_profile_identity(loaded, service_id, consultation_name, pack)?;
            let contract_document = consultation_contract_document(
                loaded,
                environment,
                (service_id, service),
                (consultation_name, consultation),
                pack,
                (&profile_id, &profile_version),
            )?;
            let contract = compile_consultation_contract(&canonical_json_line(&contract_document)?)
                .map_err(|error| anyhow!(
                    "generated consultation contract {service_id}.{consultation_name} did not compile: {error:?}"
                ))?;
            let binding_document = private_binding_document(
                loaded,
                environment,
                consultation,
                pack,
                &profile_id,
                &profile_version,
            )?;
            let binding = compile_private_binding(&canonical_json_line(&binding_document)?)
                .map_err(|error| anyhow!(
                    "generated private binding {service_id}.{consultation_name} did not compile: {error:?}"
                ))?;
            let contract_path = PathBuf::from(format!(
                "config/artifacts/consultation-contracts/{service_id}-{consultation_name}.json"
            ));
            let review_path = PathBuf::from(format!(
                "consultation-contracts/{service_id}-{consultation_name}.json"
            ));
            let binding_path = PathBuf::from(format!(
                "config/artifacts/private-bindings/{service_id}-{consultation_name}.json"
            ));
            reviewable.insert(review_path, contract.artifact().canonical_json().into());
            relay_private.insert(contract_path, contract.artifact().canonical_json().into());
            relay_private.insert(binding_path, binding.canonical_json().into());
            profiles.push(GeneratedProfile {
                service_id: service_id.clone(),
                consultation_name: consultation_name.clone(),
                integration_alias: consultation.integration.clone(),
                id: profile_id,
                version: profile_version,
                contract,
                binding,
            });
        }
    }

    if let Some(relay_service) = &environment.deployment.relay {
        let relay_config =
            generated_relay_config(loaded, environment_name, environment, &packs, &profiles)?;
        relay_private.insert(
            PathBuf::from("config/relay.yaml"),
            serde_yaml::to_string(&relay_config)?
                .into_bytes()
                .into_boxed_slice(),
        );
        relay_private.insert(
            PathBuf::from("descriptors/operations.json"),
            canonical_json_line(&operational_descriptor(
                "registry-relay",
                &relay_service.service,
                environment.deployment.profile,
                profiles.len(),
            ))?
            .into_boxed_slice(),
        );
        relay_private.insert(
            PathBuf::from("descriptors/secret-consumers.json"),
            canonical_json_line(&secret_consumer_descriptor("registry-relay", &relay_config))?
                .into_boxed_slice(),
        );
    }
    let mut notary_private = BTreeMap::new();
    if let Some(notary_service) = &environment.deployment.notary {
        let notary_config =
            generated_notary_config(loaded, environment_name, environment, &profiles)?;
        notary_private.insert(
            PathBuf::from("config/notary.yaml"),
            serde_yaml::to_string(&notary_config)?
                .into_bytes()
                .into_boxed_slice(),
        );
        notary_private.insert(
            PathBuf::from("descriptors/operations.json"),
            canonical_json_line(&operational_descriptor(
                "registry-notary",
                &notary_service.service,
                environment.deployment.profile,
                profiles.len(),
            ))?
            .into_boxed_slice(),
        );
        notary_private.insert(
            PathBuf::from("descriptors/secret-consumers.json"),
            canonical_json_line(&secret_consumer_descriptor(
                "registry-notary",
                &notary_config,
            ))?
            .into_boxed_slice(),
        );
    }

    let reviewable_digest = closure_digest(&reviewable)?;
    let relay_digest = (!relay_private.is_empty())
        .then(|| closure_digest(&relay_private))
        .transpose()?;
    let notary_digest = (!notary_private.is_empty())
        .then(|| closure_digest(&notary_private))
        .transpose()?;
    let closure_digests = json!({
        "reviewable": reviewable_digest,
        "relay": relay_digest,
        "notary": notary_digest,
    });
    let disclosure_profiles = disclosure_review_profiles(&loaded.project);
    let disclosure_digest = digest_json(
        &serde_json::to_value(&disclosure_profiles)
            .context("failed to serialize disclosure review profiles")?,
    )?;
    let semantic_changes = semantic_change_records(
        loaded,
        baseline.map(|baseline| &baseline.approval_state),
        &disclosure_digest,
    );
    let entity_materializations = generated_entity_materialization_review(loaded, environment)?;
    let review = json!({
        "schema": REVIEW_SCHEMA,
        "registry": loaded.project.registry.id,
        "compiler_version": env!("CARGO_PKG_VERSION"),
        "baseline": if baseline.is_some() { "verified_signed_bundle" } else { "initial_without_baseline" },
        "disclosure_profiles": disclosure_profiles,
        "semantic_changes": semantic_changes,
        "environment": environment_name,
        "entity_materializations": entity_materializations,
        "consultations": profiles.iter().map(|profile| (
            format!("{}.{}", profile.service_id, profile.consultation_name),
            json!({
                "profile_id": profile.id,
                "integration": profile.integration_alias,
                "contract_hash": profile.contract.artifact().typed_hash(),
            }),
        )).collect::<Map<String, Value>>(),
    });
    let approval_state = json!({
        "schema": APPROVAL_STATE_SCHEMA,
        "registry": loaded.project.registry.id,
        "environment": environment_name,
        "compiler_version": env!("CARGO_PKG_VERSION"),
        "report_digest": sha256_uri(&canonical_json_line(&review)?),
        "authored_input_digest": loaded.authored_hash,
        "semantic_digests": loaded.semantic_digests,
        "disclosure_digest": disclosure_digest,
        "generated_closure_digests": closure_digests,
        "baseline": baseline.map(|baseline| json!({
            "verified_manifest": baseline.verified_manifest,
        })),
        "entity_materializations": entity_materializations,
    });
    let explanation = generated_explanation(loaded, environment_name, &profiles);
    let fixture_profiles = profiles
        .iter()
        .map(|profile| FixtureProfile {
            service_id: profile.service_id.clone(),
            integration_alias: profile.integration_alias.clone(),
            id: profile.id.clone(),
            version: profile.version.clone(),
            contract_hash: profile.contract.artifact().typed_hash().to_string(),
        })
        .collect();
    // The human review and internal approval state are deliberately excluded from
    // the closure digests above. Both become signed payload members when the
    // existing product Config Bundle command runs, avoiding a digest cycle.
    Ok(CompiledProject {
        reviewable,
        relay_private,
        notary_private,
        review,
        approval_state,
        explanation,
        fixture_profiles,
        semantic_changes,
    })
}

fn operational_descriptor(
    product: &str,
    service: &str,
    profile: DeploymentProfile,
    consultation_profiles: usize,
) -> Value {
    let config = match product {
        "registry-relay" => "config/relay.yaml",
        "registry-notary" => "config/notary.yaml",
        _ => "config.yaml",
    };
    json!({
        "schema": "registry.project.operations.v1",
        "product": product,
        "service": service,
        "deployment_profile": profile,
        "config": config,
        "health": "/healthz",
        "readiness": "/ready",
        "restart_required": true,
        "consultation_profiles": consultation_profiles,
    })
}

fn secret_consumer_descriptor(product: &str, config: &Value) -> Value {
    let mut consumers = Vec::new();
    collect_secret_consumers(config, "", &mut consumers);
    consumers.sort_by(|left, right| {
        left.get("config_pointer")
            .and_then(Value::as_str)
            .cmp(&right.get("config_pointer").and_then(Value::as_str))
            .then_with(|| {
                left.get("kind")
                    .and_then(Value::as_str)
                    .cmp(&right.get("kind").and_then(Value::as_str))
            })
    });
    json!({
        "schema": "registry.project.secret-consumers.v1",
        "product": product,
        "consumers": consumers,
    })
}

fn collect_secret_consumers(value: &Value, pointer: &str, output: &mut Vec<Value>) {
    match value {
        Value::Object(object) => {
            if object
                .get("provider")
                .and_then(Value::as_str)
                .is_some_and(|provider| matches!(provider, "env" | "environment"))
            {
                if let Some(locator) = object.get("name").and_then(Value::as_str) {
                    output.push(json!({
                        "kind": "environment",
                        "locator": locator,
                        "config_pointer": format!("{pointer}/name"),
                    }));
                }
            }
            for (name, value) in object {
                let next = format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1"));
                let kind = if name.ends_with("_env") {
                    Some("environment")
                } else if matches!(
                    name.as_str(),
                    "token_file" | "workload_token_file" | "private_key_file" | "secret_file"
                ) {
                    Some("file")
                } else {
                    None
                };
                if let (Some(kind), Some(locator)) = (kind, value.as_str()) {
                    output.push(json!({
                        "kind": kind,
                        "locator": locator,
                        "config_pointer": next,
                    }));
                }
                collect_secret_consumers(value, &next, output);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_secret_consumers(value, &format!("{pointer}/{index}"), output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn closure_digest(files: &BTreeMap<PathBuf, Box<[u8]>>) -> Result<String> {
    let entries = files
        .iter()
        .map(|(path, bytes)| {
            Ok(json!({
                "path": path
                    .to_str()
                    .ok_or_else(|| anyhow!("generated path is not Unicode"))?,
                "sha256": sha256_uri(bytes),
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    digest_json(&Value::Array(entries))
}

fn generate_evidence(
    alias: &str,
    integration: &LoadedIntegration,
) -> Result<Vec<GeneratedEvidence>> {
    let conformance = integration
        .fixtures
        .iter()
        .filter(|(_, fixture)| fixture.expect.error.is_none())
        .map(|(_, fixture)| fixture)
        .collect::<Vec<_>>();
    let negative_security = integration
        .fixtures
        .iter()
        .filter(|(_, fixture)| fixture.expect.error.is_some())
        .map(|(_, fixture)| fixture)
        .collect::<Vec<_>>();
    let classes = [
        (
            EvidenceClass::Conformance,
            "conformance",
            json!({
                "schema": "registry.project.integration-evidence.v1",
                "class": "conformance",
                "integration": integration.document.id,
                "fixtures": conformance,
            }),
        ),
        (
            EvidenceClass::NegativeSecurity,
            "negative-security",
            json!({
                "schema": "registry.project.integration-evidence.v1",
                "class": "negative_security",
                "integration": integration.document.id,
                "fixtures": negative_security,
            }),
        ),
        (
            EvidenceClass::Minimization,
            "minimization",
            json!({
                "schema": "registry.project.integration-evidence.v1",
                "class": "minimization",
                "integration": integration.document.id,
                "outputs": integration.document.outputs,
                "operations": integration_operations(&integration.document)
                    .iter()
                    .map(|(id, operation)| (id, json!({
                        "request": operation.request,
                        "response_schema": operation.response.schema,
                    })))
                    .collect::<BTreeMap<_, _>>(),
            }),
        ),
    ];
    classes
        .into_iter()
        .map(|(class, name, value)| {
            let bytes = canonical_json_line(&value)?.into_boxed_slice();
            Ok(GeneratedEvidence {
                class,
                path: PathBuf::from(format!("artifacts/evidence/{alias}/{name}.json")),
                sha256: sha256_uri(&bytes),
                bytes,
            })
        })
        .collect()
}

fn integration_pack_document(
    loaded: &LoadedRegistryProject,
    _environment: &EnvironmentDocument,
    alias: &str,
    integration: &LoadedIntegration,
    evidence: &[GeneratedEvidence],
) -> Result<Value> {
    let pack_id = bounded_join_id(&[
        loaded.project.registry.id.as_str(),
        integration.document.id.as_str(),
    ])?;
    let version = integration.document.revision.to_string();
    let input_slots = integration
        .document
        .input
        .iter()
        .map(|(name, input)| Ok((name.clone(), relay_input_slot(input)?)))
        .collect::<Result<Map<String, Value>>>()?;
    let (acquisition, reviewed, output, plan, limits, _materialization) =
        generated_pack_semantics(loaded, alias, integration, evidence)?;
    let evidence_manifest = evidence_manifest(evidence);
    let specification = json!({
        "product_family": integration.document.source.product,
        "supported_version_evidence": integration.document.source.versions.tested.iter()
            .map(|version| format!("tested:{version}"))
            .chain(integration.document.source.versions.unverified.iter().map(|version| format!("unverified:{version}")))
            .collect::<Vec<_>>(),
        "logical_operation": integration.document.id,
        "input_slots": input_slots,
        "acquisition": acquisition,
        "source_provenance": {
            "source_observed_at": { "type": "absent" },
            "source_revision": { "type": "absent" },
        },
        "reviewed_acquisition": reviewed,
        "output": output,
        "plan": plan,
        "bounds": limits,
        "deployment_parameters": {},
        "evidence": evidence_manifest,
    });
    Ok(json!({
        "schema": "registry.relay.integration-pack.v1",
        "id": pack_id,
        "version": version,
        "spec": specification,
    }))
}

fn relay_input_slot(input: &InputDeclaration) -> Result<Value> {
    let scalar = match input.input_type {
        InputType::String | InputType::FullDate => "string",
        InputType::Boolean => "boolean",
        InputType::Integer => "integer",
    };
    let schema_type = if input.nullable {
        json!([scalar, "null"])
    } else {
        json!(scalar)
    };
    let mut slot = json!({
        "role": match input.role {
            AuthoredInputRole::Selector => "selector",
            AuthoredInputRole::Parameter => "parameter",
        },
        "type": schema_type,
        "x-registry-canonicalization": match input.canonicalization {
            Canonicalization::Identity => "identity",
            Canonicalization::AsciiLowercase => "ascii_lowercase",
        },
    });
    match input.input_type {
        InputType::String => {
            slot["maxLength"] = json!(input.max_length);
            slot["x-registry-max-bytes"] = json!(input.bytes);
            if let Some(pattern) = &input.pattern {
                slot["pattern"] = json!(relay_input_pattern(pattern)?);
            }
        }
        InputType::FullDate => {
            slot["format"] = json!("date");
            slot["maxLength"] = json!(10);
            slot["x-registry-max-bytes"] = json!(10);
        }
        InputType::Boolean => {}
        InputType::Integer => {
            slot["minimum"] = json!(input.minimum);
            slot["maximum"] = json!(input.maximum);
        }
    }
    Ok(slot)
}

fn relay_input_pattern(pattern: &str) -> Result<String> {
    let bytes = pattern.as_bytes();
    let mut output = String::with_capacity(pattern.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'[' {
            if bytes[index] == b'{' || bytes[index] == b'}' {
                bail!("input pattern uses an unsupported repetition shape");
            }
            output.push(char::from(bytes[index]));
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && bytes[index] != b']' {
            index += 1;
        }
        if index == bytes.len() {
            bail!("input pattern contains an unterminated character class");
        }
        index += 1;
        let atom = &pattern[start..index];
        let repetitions = if bytes.get(index) == Some(&b'{') {
            let count_start = index + 1;
            let Some(relative_end) = bytes[count_start..].iter().position(|byte| *byte == b'}')
            else {
                bail!("input pattern contains an unterminated repetition");
            };
            let count_end = count_start + relative_end;
            let count = pattern[count_start..count_end].parse::<usize>()?;
            if count == 0 || count > 64 {
                bail!("input pattern fixed repetition is outside the supported bound");
            }
            index = count_end + 1;
            count
        } else {
            1
        };
        for _ in 0..repetitions {
            output.push_str(atom);
        }
    }
    Ok(output)
}

fn evidence_manifest(evidence: &[GeneratedEvidence]) -> Value {
    let hashes = |class| {
        evidence
            .iter()
            .filter(|artifact| artifact.class == class)
            .map(|artifact| Value::String(artifact.sha256.clone()))
            .collect::<Vec<_>>()
    };
    json!({
        "conformance": hashes(EvidenceClass::Conformance),
        "negative_security": hashes(EvidenceClass::NegativeSecurity),
        "minimization": hashes(EvidenceClass::Minimization),
    })
}

fn bounded_join_id(parts: &[&str]) -> Result<String> {
    let id = parts.join(".");
    validate_stable_id(&id, "generated artifact id")?;
    Ok(id)
}

fn bounded_scope(parts: &[&str]) -> Result<String> {
    let scope = parts.join(":");
    validate_token(&scope, "generated scope", 256)?;
    Ok(scope)
}

type PackSemantics = (Value, Value, Value, Value, Value, Option<Value>);

fn generated_pack_semantics(
    loaded: &LoadedRegistryProject,
    alias: &str,
    integration: &LoadedIntegration,
    evidence: &[GeneratedEvidence],
) -> Result<PackSemantics> {
    match &integration.document.capability {
        CapabilityDeclaration::Http { .. } => {
            generated_http_pack_semantics(alias, integration, evidence)
        }
        CapabilityDeclaration::Script { script } => {
            generated_script_pack_semantics(alias, integration, script)
        }
        CapabilityDeclaration::Snapshot { snapshot } => {
            let entity = &loaded.entities[&snapshot.entity].document;
            generated_snapshot_pack_semantics(alias, integration, snapshot, entity)
        }
    }
}

fn generated_script_pack_semantics(
    alias: &str,
    integration: &LoadedIntegration,
    script: &ScriptDeclaration,
) -> Result<PackSemantics> {
    let acquisition_fields = integration
        .document
        .outputs
        .iter()
        .map(|(name, output)| Ok((name.clone(), relay_acquisition_schema_for_output(output)?)))
        .collect::<Result<Map<String, Value>>>()?;
    let output = integration
        .document
        .outputs
        .iter()
        .map(|(name, output)| {
            let output_type = match output.output_type {
                OutputType::Boolean | OutputType::Presence => "boolean",
                OutputType::Integer => "integer",
                OutputType::String => "string",
                OutputType::Date => "date",
            };
            let mut declaration = json!({ "type": output_type, "nullable": output.nullable });
            match output.output_type {
                OutputType::String => declaration["max_bytes"] = json!(output.max_bytes),
                OutputType::Integer => {
                    declaration["minimum"] = json!(output.minimum);
                    declaration["maximum"] = json!(output.maximum);
                }
                OutputType::Date => declaration["max_bytes"] = json!(10),
                OutputType::Boolean | OutputType::Presence => {}
            }
            (name.clone(), declaration)
        })
        .collect::<Map<String, Value>>();
    let signed_dci = script.signed_dci.as_ref().map(|protocol| {
        json!({
            "protocol_version": "1.0.0",
            "sender_id": protocol.sender,
            "receiver_id": protocol.receiver,
            "registry_type": protocol.registry_type,
            "registry_event_type": protocol.record_type,
            "record_type": protocol.record_type,
            "exact_and": protocol.selectors.iter().map(|(name, binding)| (name.clone(), json!({
                "field": binding.field,
                "response_pointer": binding.response_pointer,
            }))).collect::<Map<String, Value>>(),
            "locale": protocol.locale,
            "page_number": 1,
            "jwks_operation": "jwks",
            "response_verifier": "dci_jws_v1",
        })
    });
    let operation_timeout_ms = parse_duration_ms(&integration.document.bounds.deadline)?.min(10_000);
    let verification_operations = script.signed_dci.as_ref().map_or_else(Vec::new, |_| {
        vec![json!({
            "id": "jwks",
            "primitive": "jwks_v1",
            "destination_slot": format!("{alias}-verification"),
            "method": "GET",
            "path": "/",
            "step_limits": {
                "max_request_bytes": integration.document.bounds.request_bytes,
                "timeout_ms": operation_timeout_ms,
                "max_in_flight": 1,
            },
            "max_response_bytes": 64 * 1024,
            "accepted_statuses": [200],
        })]
    });
    let credential_operation = generated_credential_operation(alias, &integration.document)?;
    let response_format = match script.response.format {
        AuthoredResponseFormat::Json => "json",
        AuthoredResponseFormat::Text => "text",
    };
    let plan = json!({
        "kind": "script",
        "data_destination_slot": format!("{alias}-data"),
        "credential_destination_slot": credential_operation.as_ref().map(|_| format!("{alias}-credential")),
        "verification_destination_slot": (!verification_operations.is_empty()).then(|| format!("{alias}-verification")),
        "verification_operations": verification_operations,
        "credential_operation": credential_operation,
        "snapshot": null,
        "rhai": generated_rhai_template(alias, integration)?,
        "script_authority": {
            "allow": script.allow.iter().map(|rule| json!({
                "method": match rule.method { ReadMethod::Get => "GET", ReadMethod::Post => "READ_ONLY_POST" },
                "path": rule.path,
                "semantics": rule.semantics.map(|_| "read_only"),
            })).collect::<Vec<_>>(),
            "request_headers": script.request_headers,
            "response_headers": script.response_headers,
            "response": { "format": response_format, "max_bytes": script.response.max_bytes },
            "auth": relay_source_auth(&script.credential),
            "request_max_bytes": integration.document.bounds.request_bytes,
            "signed_dci": signed_dci,
        },
    });
    let ambiguous = true;
    let acquisition = json!({ "class": "bounded_full_record", "fields": acquisition_fields });
    let reviewed = json!({
        "class": "bounded_full_record",
        "fields": acquisition_fields,
        "control_fields": {},
        "selector": null,
        "cardinality": if ambiguous { "probe_two" } else { "source_enforced_singleton" },
        "reject_unknown_fields": true,
    });
    let limits = json!({
        "max_source_matches": if ambiguous { 2 } else { 1 },
        "max_disclosed_records": 1,
        "max_data_exchanges": integration
            .document
            .bounds
            .calls
            .checked_add(u8::from(script.signed_dci.is_some()))
            .context("Script protocol exchange bound exceeds the platform maximum")?,
        "max_credential_exchanges": usize::from(credential_operation.is_some()),
        "max_data_destinations": 1,
        "max_source_bytes": integration.document.bounds.source_bytes,
        "timeout_ms": parse_duration_ms(&integration.document.bounds.deadline)?,
        "max_in_flight": integration.document.bounds.concurrency,
        "quota_per_minute": 60,
        "quota_burst": integration.document.bounds.concurrency.min(60),
    });
    Ok((acquisition, reviewed, Value::Object(output), plan, limits, None))
}

fn generated_http_pack_semantics(
    alias: &str,
    integration: &LoadedIntegration,
    evidence: &[GeneratedEvidence],
) -> Result<PackSemantics> {
    let ordered = ordered_operations(integration_operations(&integration.document))?;
    let data_operations = ordered
        .iter()
        .copied()
        .filter(|(_, operation)| operation.role == OperationRole::Data)
        .collect::<Vec<_>>();
    if data_operations.is_empty() {
        bail!("HTTP integration must declare at least one data operation");
    }
    let mut acquired_fields = Map::new();
    let mut reviewed_fields = Map::new();
    let mut reviewed_controls = Map::new();
    let control_fields = referenced_prior_fields(&integration.document)?;
    let is_script = matches!(
        integration.document.capability,
        CapabilityDeclaration::Script { .. }
    );
    if is_script {
        for (name, output) in &integration.document.outputs {
            let schema = relay_acquisition_schema_for_output(output)?;
            acquired_fields.insert(name.clone(), schema.clone());
            reviewed_fields.insert(name.clone(), schema);
        }
    }
    let is_declarative_http = matches!(
        integration.document.capability,
        CapabilityDeclaration::Http { .. }
    );
    for (operation_id, operation) in &data_operations {
        if is_script {
            continue;
        }
        let record = operation_record_schema(operation)?;
        if operation.primitive.as_deref() == Some("dci_search_v1") {
            let SchemaNode::Object { .. } = record else {
                bail!("DCI post-codec record schema must be an object");
            };
            let compiled = relay_schema_node(record, false);
            acquired_fields.insert("record".to_string(), compiled.clone());
            reviewed_fields.insert("record".to_string(), compiled);
            continue;
        }
        let SchemaNode::Object { fields, .. } = record else {
            bail!("operation normalized record schema must be an object");
        };
        for (field, schema) in fields {
            let compiled = if is_declarative_http && operation.primitive.is_none() {
                relay_retained_projection_schema_node(&schema.schema, !schema.required)
            } else {
                relay_schema_node(&schema.schema, !schema.required)
            };
            if acquired_fields
                .insert(field.clone(), compiled.clone())
                .is_some_and(|prior| prior != compiled)
            {
                bail!("duplicate acquired field has conflicting closed schemas");
            }
            if control_fields
                .get(operation_id.as_str())
                .is_some_and(|controls| controls.contains(field))
            {
                reviewed_controls.insert(field.clone(), compiled);
            } else {
                reviewed_fields.insert(field.clone(), compiled);
            }
        }
    }
    let output = integration
        .document
        .outputs
        .iter()
        .map(|(name, output)| {
            let output_type = if output
                .from
                .as_deref()
                .is_some_and(|source| source.ends_with(".presence"))
            {
                "presence"
            } else {
                match output.output_type {
                    OutputType::Boolean | OutputType::Presence => "boolean",
                    OutputType::Integer => "integer",
                    OutputType::String => "string",
                    OutputType::Date => "date",
                }
            };
            let mut declaration = json!({ "type": output_type, "nullable": output.nullable });
            match output.output_type {
                OutputType::String => {
                    declaration["max_bytes"] = json!(output.max_bytes);
                }
                OutputType::Integer => {
                    declaration["minimum"] = json!(output.minimum);
                    declaration["maximum"] = json!(output.maximum);
                }
                OutputType::Date => declaration["max_bytes"] = json!(10),
                OutputType::Boolean | OutputType::Presence => {}
            }
            (name.clone(), declaration)
        })
        .collect::<Map<String, Value>>();
    let root_operation_id = data_operations[0].0;
    let operations = data_operations
        .iter()
        .map(|(id, operation)| {
            generated_http_operation(
                alias,
                &integration.document,
                id,
                operation,
                *id == root_operation_id,
                &control_fields,
                evidence,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let step_conditions = if matches!(
        integration.document.capability,
        CapabilityDeclaration::Script { .. }
    ) {
        Map::new()
    } else {
        generated_step_conditions(&integration.document)?
    };
    let verification_operations = generated_verification_operations(alias, &integration.document)?;
    let first = data_operations[0];
    let selector = if matches!(
        integration.document.capability,
        CapabilityDeclaration::Script { .. }
    ) && first.1.primitive.as_deref() != Some("dci_search_v1")
    {
        Value::Null
    } else {
        exact_selector(&integration.document.input, first.0, first.1)?
    };
    let any_probe_two = data_operations.iter().any(|(_, operation)| {
        operation
            .response
            .cardinality
            .as_ref()
            .is_some_and(|cardinality| cardinality.mode == CardinalityMode::ProbeTwo)
            || operation
                .response
                .status_semantics
                .as_ref()
                .is_some_and(|semantics| !semantics.ambiguous.is_empty())
    });
    let acquisition = json!({
        "class": "bounded_full_record",
        "fields": acquired_fields,
    });
    let reviewed = json!({
        "class": "bounded_full_record",
        "fields": reviewed_fields,
        "control_fields": reviewed_controls,
        "selector": selector,
        "cardinality": if any_probe_two { "probe_two" } else { "source_enforced_singleton" },
        "reject_unknown_fields": true,
    });
    let plan_kind = match integration.document.capability {
        CapabilityDeclaration::Http { .. } => "bounded_http",
        CapabilityDeclaration::Script { .. } => "script",
        CapabilityDeclaration::Snapshot { .. } => unreachable!(),
    };
    let steps = if matches!(
        integration.document.capability,
        CapabilityDeclaration::Script { .. }
    ) {
        Vec::new()
    } else {
        data_operations
            .iter()
            .map(|(id, _)| id.to_string())
            .collect::<Vec<_>>()
    };
    let credential_operation = generated_credential_operation(alias, &integration.document)?;
    let credential_slot = credential_operation
        .as_ref()
        .map(|_| format!("{alias}-credential"));
    let rhai = generated_rhai_template(alias, integration)?;
    let plan = json!({
        "kind": plan_kind,
        "data_destination_slot": format!("{alias}-data"),
        "credential_destination_slot": credential_slot,
        "verification_destination_slot": (!verification_operations.is_empty())
            .then(|| format!("{alias}-verification")),
        "operations": operations,
        "verification_operations": verification_operations,
        "steps": steps,
        "step_conditions": step_conditions,
        "credential_operation": credential_operation,
        "snapshot": null,
        "rhai": rhai,
    });
    let credential_exchanges = usize::from(credential_operation.is_some());
    let limits = json!({
        "max_source_matches": if any_probe_two { 2 } else { 1 },
        "max_disclosed_records": 1,
        "max_data_exchanges": if matches!(integration.document.capability, CapabilityDeclaration::Script { .. }) {
            usize::from(integration.document.bounds.calls)
        } else {
            1
        },
        "max_credential_exchanges": credential_exchanges,
        "max_data_destinations": 1,
        "max_source_bytes": integration.document.bounds.source_bytes,
        "timeout_ms": parse_duration_ms(&integration.document.bounds.deadline)?,
        "max_in_flight": integration.document.bounds.concurrency,
        "quota_per_minute": 60,
        "quota_burst": integration.document.bounds.concurrency.min(60),
    });
    Ok((
        acquisition,
        reviewed,
        Value::Object(output),
        plan,
        limits,
        None,
    ))
}

fn relay_acquisition_schema_for_output(output: &OutputDeclaration) -> Result<Value> {
    Ok(match output.output_type {
        OutputType::String => json!({
            "type": "string",
            "nullable": output.nullable,
            "max_bytes": output.max_bytes.context("string output max_bytes is absent")?,
        }),
        OutputType::Date => json!({
            "type": "string",
            "nullable": output.nullable,
            "max_bytes": 10,
        }),
        OutputType::Boolean | OutputType::Presence => json!({
            "type": "boolean",
            "nullable": output.nullable,
        }),
        OutputType::Integer => json!({
            "type": "integer",
            "nullable": output.nullable,
            "minimum": output.minimum.context("integer output minimum is absent")?,
            "maximum": output.maximum.context("integer output maximum is absent")?,
        }),
    })
}

fn generated_snapshot_pack_semantics(
    _alias: &str,
    integration: &LoadedIntegration,
    snapshot: &SnapshotDeclaration,
    entity: &EntityDefinition,
) -> Result<PackSemantics> {
    let mut fields = Map::new();
    let mut output = Map::new();
    for (output_name, output_declaration) in &integration.document.outputs {
        let (_, path) = output_declaration
            .from
            .as_deref()
            .ok_or_else(|| anyhow!("snapshot output source is absent"))?
            .split_once('.')
            .ok_or_else(|| anyhow!("snapshot output path is invalid"))?;
        let field = path.strip_prefix("record.").unwrap_or(path);
        let entity_field = entity
            .schema
            .properties
            .get(field)
            .ok_or_else(|| anyhow!("snapshot output is not an entity property"))?;
        let (scalar, nullable) = schema_type_parts(&entity_field.field_type)?;
        let schema = match (scalar, entity_field.format) {
            (AuthoredScalarType::Boolean, None) => {
                json!({ "type": "boolean", "nullable": nullable })
            }
            (AuthoredScalarType::Integer, None) => json!({
                "type": "integer",
                "nullable": nullable,
                "minimum": entity_field.minimum,
                "maximum": entity_field.maximum,
            }),
            (AuthoredScalarType::String, None) => json!({
                "type": "string",
                "nullable": nullable,
                "max_bytes": entity_field.max_length.and_then(|value| value.checked_mul(4)).ok_or_else(|| anyhow!("snapshot String entity bound is absent"))?,
            }),
            (AuthoredScalarType::String, Some(AuthoredStringFormat::Date)) => {
                json!({ "type": "string", "nullable": nullable, "max_bytes": 10 })
            }
            _ => bail!("snapshot entity field has an unsupported scalar contract"),
        };
        fields.insert(field.to_string(), schema);
        output.insert(output_name.clone(), {
            let mut declaration = json!({
            "type": match (scalar, entity_field.format) {
                (AuthoredScalarType::Boolean, None) => "boolean",
                (AuthoredScalarType::Integer, None) => "integer",
                (AuthoredScalarType::String, None) => "string",
                (AuthoredScalarType::String, Some(AuthoredStringFormat::Date)) => "date",
                _ => unreachable!("entity field validation rejects unsupported scalar contracts"),
            },
            "nullable": nullable,
            });
            match (scalar, entity_field.format) {
                (AuthoredScalarType::String, None) => {
                    declaration["max_bytes"] = json!(entity_field
                        .max_length
                        .and_then(|value| value.checked_mul(4)));
                }
                (AuthoredScalarType::Integer, None) => {
                    declaration["minimum"] = json!(entity_field.minimum);
                    declaration["maximum"] = json!(entity_field.maximum);
                }
                (AuthoredScalarType::String, Some(AuthoredStringFormat::Date)) => {
                    declaration["max_bytes"] = json!(10)
                }
                (AuthoredScalarType::Boolean, None) => {}
                _ => unreachable!("entity field validation rejects unsupported scalar contracts"),
            }
            declaration
        });
    }
    let max_matches = match snapshot.cardinality {
        CardinalityMode::Singleton => 1,
        CardinalityMode::ProbeTwo => 2,
    };
    let freshness = u64::from(parse_duration_ms_with_max(
        &snapshot.freshness,
        31 * 24 * 60 * 60 * 1_000,
        "snapshot freshness",
    )?);
    let acquisition = json!({
        "class": "materialized_snapshot",
        "fields": fields,
    });
    let reviewed = json!({
        "class": "materialized_snapshot",
        "fields": fields,
        "control_fields": {},
        "selector": {
            "type": "snapshot_exact_and",
            "components": integration.document.input.keys().map(|input| {
                (input.clone(), json!("snapshot_key"))
            }).collect::<Map<String, Value>>(),
        },
        "cardinality": if max_matches == 2 { "probe_two" } else { "source_enforced_singleton" },
        "reject_unknown_fields": true,
    });
    let plan = json!({
        "kind": "snapshot_exact",
        "data_destination_slot": null,
        "credential_destination_slot": null,
        "operations": [],
        "steps": [],
        "credential_operation": null,
        "snapshot": {
            "max_snapshot_age_ms": freshness,
            "unavailable": "unavailable",
            "immutable_generation": true,
        },
        "rhai": null,
    });
    let limits = json!({
        "max_source_matches": max_matches,
        "max_disclosed_records": 1,
        "max_data_exchanges": 0,
        "max_credential_exchanges": 0,
        "max_data_destinations": 0,
        "max_source_bytes": integration.document.bounds.source_bytes,
        "timeout_ms": parse_duration_ms(&integration.document.bounds.deadline)?,
        "max_in_flight": integration.document.bounds.concurrency,
        "quota_per_minute": 60,
        "quota_burst": integration.document.bounds.concurrency.min(60),
    });
    let materialization = json!({
        "max_snapshot_age_ms": freshness,
        "stale_behavior": "unavailable",
        "footprint": {
            "fields": fields.keys().collect::<Vec<_>>(),
            "max_source_records": snapshot.materialization.max_source_records,
            "max_source_bytes": snapshot.materialization.max_source_bytes,
            "max_data_exchanges": 1,
            "max_credential_exchanges": 0,
            "max_data_destinations": 1,
        },
        "refresh_class": if entity.materialization.refresh == "manual" { "operator_triggered" } else { "scheduled" },
        "snapshot_retention_generations": entity.materialization.retain_generations,
        "immutable_generation": true,
        "digest_bound_active_pointer": true,
    });
    Ok((
        acquisition,
        reviewed,
        Value::Object(output),
        plan,
        limits,
        Some(materialization),
    ))
}

fn operation_record_schema(operation: &OperationDeclaration) -> Result<&SchemaNode> {
    let Some(cardinality) = &operation.response.cardinality else {
        return Ok(&operation.response.schema);
    };
    let Some(path) = cardinality.records.as_deref() else {
        return Ok(&operation.response.schema);
    };
    let mut current = &operation.response.schema;
    for segment in path.split('.') {
        current = match current {
            SchemaNode::Object { fields, .. } => fields
                .get(segment)
                .map(|field| &field.schema)
                .ok_or_else(|| anyhow!("cardinality record path is not in the response schema"))?,
            _ => bail!("cardinality record path traverses a non-object schema"),
        };
    }
    match current {
        SchemaNode::Array { items, .. } => Ok(items),
        _ => bail!("cardinality record path must resolve to an array"),
    }
}

fn relay_schema_node(schema: &SchemaNode, nullable: bool) -> Value {
    match schema {
        SchemaNode::Object {
            additional_fields,
            fields,
        } => json!({
            "type": "object",
            "nullable": nullable,
            "reject_unknown_fields": *additional_fields == AdditionalFields::Reject,
            "fields": fields.iter().map(|(name, field)| (name.clone(), json!({
                "required": field.required,
                "schema": relay_schema_node(&field.schema, !field.required),
            }))).collect::<Map<String, Value>>(),
        }),
        SchemaNode::Array { max_items, items } => json!({
            "type": "array",
            "nullable": nullable,
            "max_items": max_items,
            "items": relay_schema_node(items, false),
        }),
        SchemaNode::String { max_bytes } => {
            json!({ "type": "string", "nullable": nullable, "max_bytes": max_bytes })
        }
        SchemaNode::Integer { min, max } => json!({
            "type": "integer",
            "nullable": nullable,
            "minimum": min,
            "maximum": max,
        }),
        SchemaNode::Boolean => json!({ "type": "boolean", "nullable": nullable }),
        SchemaNode::Date => {
            json!({ "type": "string", "nullable": nullable, "max_bytes": 10 })
        }
    }
}

fn relay_projection_schema_node(schema: &SchemaNode, nullable: bool) -> Value {
    // This validates the selected projection, not an exhaustive upstream
    // object. Ignored members remain structurally bounded and are never
    // projected by Relay's response decoder.
    match schema {
        SchemaNode::Object {
            additional_fields,
            fields,
        } => json!({
            "type": "object",
            "nullable": nullable,
            "reject_unknown_fields": *additional_fields == AdditionalFields::Reject,
            "fields": fields.iter().map(|(name, field)| (name.clone(), json!({
                "required": field.required,
                "schema": relay_projection_schema_node(&field.schema, !field.required),
            }))).collect::<Map<String, Value>>(),
        }),
        SchemaNode::Array { max_items, items } => json!({
            "type": "array",
            "nullable": nullable,
            "max_items": max_items,
            "items": relay_projection_schema_node(items, false),
        }),
        SchemaNode::String { max_bytes } => {
            json!({ "type": "string", "nullable": nullable, "max_bytes": max_bytes })
        }
        SchemaNode::Integer { min, max } => json!({
            "type": "integer",
            "nullable": nullable,
            "minimum": min,
            "maximum": max,
        }),
        SchemaNode::Boolean => json!({ "type": "boolean", "nullable": nullable }),
        SchemaNode::Date => {
            json!({ "type": "string", "nullable": nullable, "max_bytes": 10 })
        }
    }
}

fn relay_retained_projection_schema_node(schema: &SchemaNode, nullable: bool) -> Value {
    match schema {
        SchemaNode::Object { fields, .. } => json!({
            "type": "object",
            "nullable": nullable,
            "reject_unknown_fields": true,
            "fields": fields.iter().map(|(name, field)| (name.clone(), json!({
                "required": field.required,
                "schema": relay_retained_projection_schema_node(&field.schema, !field.required),
            }))).collect::<Map<String, Value>>(),
        }),
        SchemaNode::Array { max_items, items } => json!({
            "type": "array",
            "nullable": nullable,
            "max_items": max_items,
            "items": relay_retained_projection_schema_node(items, false),
        }),
        SchemaNode::String { max_bytes } => {
            json!({ "type": "string", "nullable": nullable, "max_bytes": max_bytes })
        }
        SchemaNode::Integer { min, max } => json!({
            "type": "integer",
            "nullable": nullable,
            "minimum": min,
            "maximum": max,
        }),
        SchemaNode::Boolean => json!({ "type": "boolean", "nullable": nullable }),
        SchemaNode::Date => {
            json!({ "type": "string", "nullable": nullable, "max_bytes": 10 })
        }
    }
}

fn referenced_prior_fields(
    integration: &IntegrationDocument,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut fields = BTreeMap::<String, BTreeSet<String>>::new();
    for operation in integration_operations(integration).values() {
        for source in operation
            .request
            .query
            .values()
            .chain(operation.request.headers.values())
            .chain(operation.request.path_parameters.values())
        {
            if let ValueSource::Prior { prior: output } = source {
                record_prior_field(output, &mut fields)?;
            }
        }
        if let Some(body) = &operation.request.body {
            collect_body_prior_fields(body, &mut fields)?;
        }
    }
    Ok(fields)
}

fn record_prior_field(path: &str, fields: &mut BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    let (operation, path) = path
        .split_once('.')
        .ok_or_else(|| anyhow!("prior field path is invalid"))?;
    let path = path.strip_prefix("record.").unwrap_or(path);
    let field = path
        .split('.')
        .next()
        .ok_or_else(|| anyhow!("prior field path is empty"))?;
    if field != "presence" {
        fields
            .entry(operation.to_string())
            .or_default()
            .insert(field.to_string());
    }
    Ok(())
}

fn collect_body_prior_fields(
    value: &Value,
    fields: &mut BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if let Some(path) = object.get("prior").and_then(Value::as_str) {
                record_prior_field(path, fields)?;
            }
            for value in object.values() {
                collect_body_prior_fields(value, fields)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_body_prior_fields(value, fields)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn generated_http_operation(
    alias: &str,
    integration: &IntegrationDocument,
    operation_id: &str,
    operation: &OperationDeclaration,
    is_root: bool,
    control_fields: &BTreeMap<String, BTreeSet<String>>,
    evidence: &[GeneratedEvidence],
) -> Result<Value> {
    let is_dci = operation.primitive.as_deref() == Some("dci_search_v1");
    let is_rhai = matches!(integration.capability, CapabilityDeclaration::Script { .. });
    let is_generic_script = is_rhai && !is_dci;
    let record = operation_record_schema(operation)?;
    let SchemaNode::Object { fields, .. } = record else {
        bail!("normalized operation record must be an object");
    };
    let operation_outputs = integration
        .outputs
        .iter()
        .filter_map(|(name, output)| {
            output.from
                .as_deref()
                .and_then(|source| source.split_once('.'))
                .is_some_and(|(source, _)| source == operation_id)
                .then_some((name, output))
        })
        .collect::<Vec<_>>();
    let acquisition_fields = if is_dci {
        BTreeSet::from(["record".to_string()])
    } else {
        operation_outputs
            .iter()
            .filter_map(|(_, output)| {
                output.source_pointer
                    .as_deref()
                    .and_then(|pointer| pointer_segments(pointer).ok())
                    .and_then(|segments| segments.into_iter().next())
            })
            .collect::<BTreeSet<_>>()
    };
    let controls = control_fields
        .get(operation_id)
        .cloned()
        .unwrap_or_default();
    let output_mapping = if is_rhai {
        Map::new()
    } else {
        operation_outputs
            .iter()
            .filter_map(|(name, output)| {
                output.source_pointer
                    .as_ref()
                    .map(|pointer| ((*name).clone(), Value::String(pointer.clone())))
            })
            .collect::<Map<String, Value>>()
    };
    let prior_fields = if is_rhai {
        BTreeSet::new()
    } else {
        controls.clone()
    };
    let prior_outputs = prior_fields
        .iter()
        .map(|field| {
            let schema = fields
                .get(field)
                .ok_or_else(|| anyhow!("prior output field is absent from its response schema"))?;
            Ok((
                field.clone(),
                prior_output_document(&schema.schema, &format!("/{field}"))?,
            ))
        })
        .collect::<Result<Map<String, Value>>>()?;
    let response_cardinality = if is_generic_script {
        json!({ "mechanism": "script_managed" })
    } else if is_dci {
        json!({ "mechanism": "dci_probe_two" })
    } else {
        generated_cardinality(operation, evidence)?
    };
    let cardinality = operation.response.cardinality.as_ref();
    let (normalization, records_field, max_records) = if is_generic_script {
        ("script_body", None, 1)
    } else if is_dci {
        ("json_array_probe_two", None, 2)
    } else {
        match cardinality {
            Some(CardinalityDeclaration {
                records: Some(path),
                mode: CardinalityMode::ProbeTwo,
            }) => ("json_object_array_probe_two", Some(path.clone()), 2),
            Some(CardinalityDeclaration {
                records: None,
                mode: CardinalityMode::Singleton,
            })
            | None => ("json_object", None, 1),
            Some(CardinalityDeclaration {
                records: Some(_),
                mode: CardinalityMode::Singleton,
            }) => (
                "json_object_array_singleton",
                cardinality.and_then(|item| item.records.clone()),
                1,
            ),
            Some(CardinalityDeclaration {
                records: None,
                mode: CardinalityMode::ProbeTwo,
            }) => bail!(
                "probe-two response requires a reviewed record collection or status semantics"
            ),
        }
    };
    let response_schema = if is_generic_script {
        json!({ "type": "script_body" })
    } else if is_dci {
        json!({
            "type": "array",
            "nullable": false,
            "max_items": 2,
            "items": {
                "type": "object",
                "nullable": false,
                "reject_unknown_fields": true,
                "fields": {
                    "record": {
                        "required": true,
                        "schema": relay_schema_node(record, false),
                    },
                },
            },
        })
    } else {
        relay_projection_schema_node(&operation.response.schema, false)
    };
    let mut response = json!({
        "max_bytes": operation.response.max_bytes,
        "max_records": max_records,
        "normalization": normalization,
        "cardinality": response_cardinality,
        "schema": response_schema,
        "output_mapping": output_mapping,
        "prior_outputs": prior_outputs,
    });
    if !is_generic_script {
        response["accepted_statuses"] = json!(operation.response.statuses);
    }
    if let Some(records_field) = records_field {
        response["records_field"] = Value::String(records_field);
    }
    if let Some(statuses) = &operation.response.status_semantics {
        response["status_outcomes"] = json!({
            "no_match": statuses.no_match,
            "ambiguous": statuses.ambiguous,
        });
    }
    let request_codec = match operation.request.codec.as_deref() {
        None => "none",
        Some("strict_json_v1") => "json",
        Some("dci_search_v1") => "dci_exact_v1",
        Some(other) => bail!("unsupported reviewed request codec {other}"),
    };
    let request_signer: Option<&str> = None;
    let relation_selector = relation_selector(operation)?;
    let input_selector = if !is_root && relation_selector.is_none() {
        let input = integration
            .input
            .first_key_value()
            .map(|(input, _)| input.as_str())
            .ok_or_else(|| anyhow!("integration input is absent"))?;
        selector_location(operation, input).transpose()?
    } else {
        None
    };
    let query = operation
        .request
        .query
        .iter()
        .map(|(name, source)| Ok((name.clone(), relay_value_expression(source)?)))
        .collect::<Result<Map<String, Value>>>()?;
    let headers = operation
        .request
        .headers
        .iter()
        .map(|(name, source)| Ok((name.clone(), relay_value_expression(source)?)))
        .collect::<Result<Map<String, Value>>>()?;
    let path_parameters = operation
        .request
        .path_parameters
        .iter()
        .map(|(name, source)| Ok((name.clone(), relay_value_expression(source)?)))
        .collect::<Result<Map<String, Value>>>()?;
    let body = if is_dci {
        None
    } else {
        operation
            .request
            .body
            .as_ref()
            .map(relay_body_template)
            .transpose()?
    };
    let mut document = json!({
        "id": operation_id,
        "method": match operation.request.method { ReadMethod::Get => "GET", ReadMethod::Post => "READ_ONLY_POST" },
        "destination_slot": match operation.request.destination.as_str() {
            "data" => format!("{alias}-data"),
            "credential" => format!("{alias}-credential"),
            _ => bail!("operation destination must be data or credential"),
        },
        "path": operation.request.path,
        "query": query,
        "headers": headers,
        "body": body,
        "relation_selector": relation_selector,
        "input_selector": input_selector,
        "request_codec": request_codec,
        "request_signer": request_signer,
        "step_limits": {
            "max_request_bytes": integration.bounds.request_bytes,
            "timeout_ms": parse_duration_ms(&integration.bounds.deadline)?.min(10_000),
            "max_in_flight": 1,
        },
        "auth": relay_source_auth(credential_interface(integration)),
        "acquisition_fields": acquisition_fields,
        "control_fields": controls,
        "projection": { "mechanism": "bounded_full_record" },
        "response": response,
    });
    if is_dci {
        document["dci"] = generated_dci_document(operation)?;
    }
    if !path_parameters.is_empty() {
        document["path_parameters"] = Value::Object(path_parameters);
    }
    Ok(document)
}

fn prior_output_document(schema: &SchemaNode, pointer: &str) -> Result<Value> {
    let value = match schema {
        SchemaNode::String { max_bytes } => json!({
            "pointer": pointer,
            "type": "string",
            "nullable": false,
            "max_bytes": u16::try_from(*max_bytes).context("prior string output is too large")?,
        }),
        SchemaNode::Integer { min, max } => json!({
            "pointer": pointer,
            "type": "integer",
            "nullable": false,
            "minimum": min,
            "maximum": max,
        }),
        SchemaNode::Boolean => json!({
            "pointer": pointer,
            "type": "boolean",
            "nullable": false,
        }),
        SchemaNode::Date => json!({
            "pointer": pointer,
            "type": "date",
            "nullable": false,
            "max_bytes": 10,
        }),
        SchemaNode::Object { .. } | SchemaNode::Array { .. } => {
            bail!("prior step outputs must be bounded string, integer, or Boolean scalars")
        }
    };
    Ok(value)
}

fn relay_value_expression(source: &ValueSource) -> Result<Value> {
    Ok(match source {
        ValueSource::Input { input } => {
            json!({ "source": "consultation_input", "name": input })
        }
        ValueSource::Value { value } => {
            let value = match value {
                Value::String(value) => value.clone(),
                Value::Bool(value) => value.to_string(),
                Value::Number(value) => value.to_string(),
                Value::Null | Value::Array(_) | Value::Object(_) => {
                    bail!("query, header, and path literals must be bounded scalars")
                }
            };
            json!({ "source": "literal", "value": value })
        }
        ValueSource::Prior { prior: output } => {
            let (step, output) = split_prior_output(output)?;
            json!({ "source": "prior_step_output", "step": step, "output": output })
        }
    })
}

fn split_prior_output(value: &str) -> Result<(&str, &str)> {
    let (step, path) = value
        .split_once('.')
        .ok_or_else(|| anyhow!("prior output path is invalid"))?;
    let path = path.strip_prefix("record.").unwrap_or(path);
    let output = path
        .split('.')
        .next()
        .ok_or_else(|| anyhow!("prior output path is empty"))?;
    Ok((step, output))
}

fn relay_body_template(value: &Value) -> Result<Value> {
    match value {
        Value::Null => Ok(json!({ "kind": "null" })),
        Value::Bool(value) => Ok(json!({ "kind": "boolean", "value": value })),
        Value::Number(value) => value
            .as_i64()
            .map(|value| json!({ "kind": "integer", "value": value }))
            .ok_or_else(|| anyhow!("request body numbers must be exact integers")),
        Value::String(value) => Ok(json!({ "kind": "string_literal", "value": value })),
        Value::Array(values) => Ok(json!({
            "kind": "array",
            "items": values.iter().map(relay_body_template).collect::<Result<Vec<_>>>()?,
        })),
        Value::Object(object) if object.len() == 1 && object.contains_key("input") => {
            let input = object["input"]
                .as_str()
                .ok_or_else(|| anyhow!("request input expression is invalid"))?;
            Ok(json!({
                "kind": "expression",
                "value": { "source": "consultation_input", "name": input },
            }))
        }
        Value::Object(object) if object.len() == 1 && object.contains_key("prior") => {
            let prior = object["prior"]
                .as_str()
                .ok_or_else(|| anyhow!("request prior expression is invalid"))?;
            let (step, output) = split_prior_output(prior)?;
            Ok(json!({
                "kind": "expression",
                "value": { "source": "prior_step_output", "step": step, "output": output },
            }))
        }
        Value::Object(object) if object.len() == 1 && object.contains_key("value") => {
            relay_body_template(&object["value"])
        }
        Value::Object(object) => Ok(json!({
            "kind": "object",
            "fields": object.iter().map(|(name, value)| Ok((name.clone(), relay_body_template(value)?))).collect::<Result<Map<String, Value>>>()?,
        })),
    }
}

fn generated_cardinality(
    operation: &OperationDeclaration,
    evidence: &[GeneratedEvidence],
) -> Result<Value> {
    let conformance = evidence
        .iter()
        .find(|artifact| artifact.class == EvidenceClass::Conformance)
        .map(|artifact| artifact.sha256.as_str())
        .ok_or_else(|| anyhow!("conformance evidence is absent"))?;
    match operation.response.cardinality.as_ref() {
        Some(CardinalityDeclaration {
            mode: CardinalityMode::ProbeTwo,
            ..
        }) => {
            if let Some(parameter) = operation.request.query.iter().find_map(|(name, source)| {
                matches!(source, ValueSource::Value { value }
                    if value.as_u64() == Some(2) || value.as_str() == Some("2"))
                .then_some(name)
            }) {
                return Ok(json!({
                    "mechanism": "probe_query_parameter",
                    "parameter": parameter,
                }));
            }
            if let Some(body) = &operation.request.body {
                if let Some(pointer) = find_body_literal_pointer(body, 2, "") {
                    return Ok(json!({
                        "mechanism": "probe_body_integer",
                        "pointer": pointer,
                    }));
                }
            }
            bail!("probe-two operation must carry a fixed reviewed limit of two")
        }
        Some(CardinalityDeclaration {
            mode: CardinalityMode::Singleton,
            ..
        })
        | None => Ok(json!({
            "mechanism": "source_enforced_singleton",
            "conformance_evidence": conformance,
        })),
    }
}

fn find_body_literal_pointer(value: &Value, expected: i64, pointer: &str) -> Option<String> {
    match value {
        Value::Object(object)
            if object.len() == 1
                && object
                    .get("value")
                    .and_then(Value::as_i64)
                    .is_some_and(|value| value == expected) =>
        {
            Some(pointer.to_string())
        }
        Value::Object(object) => object.iter().find_map(|(name, value)| {
            find_body_literal_pointer(
                value,
                expected,
                &format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1")),
            )
        }),
        Value::Array(values) => values.iter().enumerate().find_map(|(index, value)| {
            find_body_literal_pointer(value, expected, &format!("{pointer}/{index}"))
        }),
        _ => None,
    }
}

fn exact_selector(
    inputs: &BTreeMap<String, InputDeclaration>,
    operation_id: &str,
    operation: &OperationDeclaration,
) -> Result<Value> {
    let components = inputs
        .iter()
        .filter(|(_, declaration)| declaration.role == AuthoredInputRole::Selector)
        .map(|(input, _)| {
            let location = if operation.primitive.as_deref() == Some("dci_search_v1")
                && operation.request.body.as_ref().is_some_and(|body| {
                    body.get("exact_and")
                        .and_then(Value::as_object)
                        .is_some_and(|components| components.contains_key(input))
                }) {
                json!({ "type": "codec", "role": "dci_exact_predicate" })
            } else {
                selector_location(operation, input)
                    .transpose()?
                    .ok_or_else(|| {
                        anyhow!("root operation must bind every exact consultation input")
                    })?
            };
            Ok((input.clone(), location))
        })
        .collect::<Result<Map<String, Value>>>()?;
    Ok(json!({
        "type": "http_exact_and",
        "operation": operation_id,
        "components": components,
    }))
}

fn selector_location(operation: &OperationDeclaration, input: &str) -> Option<Result<Value>> {
    if let Some(parameter) = operation.request.query.iter().find_map(|(name, source)| {
        matches!(source, ValueSource::Input { input: candidate } if candidate == input)
            .then_some(name)
    }) {
        return Some(Ok(json!({ "type": "query", "parameter": parameter })));
    }
    if let Some(parameter) = operation
        .request
        .path_parameters
        .iter()
        .find_map(|(name, source)| {
            matches!(source, ValueSource::Input { input: candidate } if candidate == input)
                .then_some(name)
        })
    {
        return Some(Ok(json!({ "type": "path", "parameter": parameter })));
    }
    operation.request.body.as_ref().and_then(|body| {
        find_body_input_pointer(body, input, "")
            .map(|pointer| Ok(json!({ "type": "body", "pointer": pointer })))
    })
}

fn find_body_input_pointer(value: &Value, input: &str, pointer: &str) -> Option<String> {
    match value {
        Value::Object(object)
            if object.len() == 1 && object.get("input").and_then(Value::as_str) == Some(input) =>
        {
            Some(pointer.to_string())
        }
        Value::Object(object) => object.iter().find_map(|(name, value)| {
            find_body_input_pointer(
                value,
                input,
                &format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1")),
            )
        }),
        Value::Array(values) => values.iter().enumerate().find_map(|(index, value)| {
            find_body_input_pointer(value, input, &format!("{pointer}/{index}"))
        }),
        _ => None,
    }
}

fn relation_selector(operation: &OperationDeclaration) -> Result<Option<Value>> {
    for (parameter, source) in &operation.request.query {
        if let ValueSource::Prior { prior: output } = source {
            let (step, output) = split_prior_output(output)?;
            return Ok(Some(json!({
                "step": step,
                "output": output,
                "location": { "type": "query", "parameter": parameter },
            })));
        }
    }
    for (parameter, source) in &operation.request.path_parameters {
        if let ValueSource::Prior { prior: output } = source {
            let (step, output) = split_prior_output(output)?;
            return Ok(Some(json!({
                "step": step,
                "output": output,
                "location": { "type": "path", "parameter": parameter },
            })));
        }
    }
    if let Some(body) = &operation.request.body {
        if let Some((pointer, prior)) = find_body_prior_pointer(body, "") {
            let (step, output) = split_prior_output(prior)?;
            return Ok(Some(json!({
                "step": step,
                "output": output,
                "location": { "type": "body", "pointer": pointer },
            })));
        }
    }
    Ok(None)
}

fn find_body_prior_pointer<'a>(value: &'a Value, pointer: &str) -> Option<(String, &'a str)> {
    match value {
        Value::Object(object) if object.len() == 1 => object
            .get("prior")
            .and_then(Value::as_str)
            .map(|prior| (pointer.to_string(), prior)),
        Value::Object(object) => object.iter().find_map(|(name, value)| {
            find_body_prior_pointer(
                value,
                &format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1")),
            )
        }),
        Value::Array(values) => values.iter().enumerate().find_map(|(index, value)| {
            find_body_prior_pointer(value, &format!("{pointer}/{index}"))
        }),
        _ => None,
    }
}

fn generated_step_conditions(integration: &IntegrationDocument) -> Result<Map<String, Value>> {
    integration_operations(integration)
        .iter()
        .filter_map(|(operation_id, operation)| {
            operation.when.as_ref().map(|condition| {
                let (step, path) = condition
                    .prior
                    .split_once('.')
                    .ok_or_else(|| anyhow!("step condition path is invalid"))?;
                let condition = if path == "presence" {
                    let output = integration
                        .outputs
                        .iter()
                        .find_map(|(name, output)| {
                            (output.from.as_deref() == Some(format!("{step}.presence").as_str()))
                                .then_some(name)
                        })
                        .ok_or_else(|| anyhow!("presence condition requires a declared presence output"))?;
                    json!({ "predicate": "exists", "step": step, "output": output })
                } else {
                    let output = path.strip_prefix("record.").unwrap_or(path);
                    let output = output.split('.').next().unwrap_or(output);
                    match &condition.equals {
                        Value::String(value) => json!({ "predicate": "string_equals", "step": step, "output": output, "value": value }),
                        Value::Bool(value) => json!({ "predicate": "boolean_equals", "step": step, "output": output, "value": value }),
                        Value::Number(value) if value.as_i64().is_some() => json!({ "predicate": "integer_equals", "step": step, "output": output, "value": value }),
                        _ => bail!("step condition value must be a bounded scalar"),
                    }
                };
                Ok((operation_id.clone(), condition))
            })
        })
        .collect()
}

fn relay_source_auth(interface: &CredentialInterface) -> Value {
    match interface.credential_type {
        CredentialType::None => json!({ "mode": "none" }),
        CredentialType::Basic => json!({ "mode": "basic", "max_value_bytes": 1024 }),
        CredentialType::StaticBearer => {
            json!({ "mode": "static_bearer", "max_value_bytes": 1024 })
        }
        CredentialType::Oauth2ClientCredentials => {
            json!({ "mode": "oauth_client_credentials" })
        }
        CredentialType::ApiKeyHeader => json!({
            "mode": "api_key_header",
            "name": interface.name.as_deref().unwrap_or_default(),
            "max_value_bytes": interface.max_value_bytes.unwrap_or_default(),
        }),
        CredentialType::ApiKeyQuery => json!({
            "mode": "api_key_query",
            "name": interface.name.as_deref().unwrap_or_default(),
            "max_value_bytes": interface.max_value_bytes.unwrap_or_default(),
        }),
    }
}

fn generated_credential_operation(
    alias: &str,
    integration: &IntegrationDocument,
) -> Result<Option<Value>> {
    let interface = credential_interface(integration);
    if interface.credential_type != CredentialType::Oauth2ClientCredentials {
        return Ok(None);
    }
    let format = match interface
        .request
        .ok_or_else(|| anyhow!("OAuth request format is absent"))?
    {
        OAuthRequestFormat::Form => "form_client_secret_body",
        OAuthRequestFormat::Json => "json_client_secret_body",
    };
    let scopes = interface
        .scope
        .as_deref()
        .map(|scope| scope.split_ascii_whitespace().collect::<Vec<_>>())
        .unwrap_or_default();
    let expiry_safety_skew_ms = interface
        .refresh_skew
        .as_deref()
        .map(parse_duration_ms)
        .transpose()?
        .unwrap_or(30_000);
    Ok(Some(json!({
        "id": "oauth",
        "kind": "oauth2_client_credentials",
        "destination_slot": format!("{alias}-credential"),
        "path": "/",
        "request": {
            "format": format,
            "max_client_id_bytes": 256,
            "max_client_secret_bytes": 512,
            "max_body_bytes": integration.bounds.request_bytes.min(8192),
            "max_request_bytes": integration.bounds.request_bytes,
            "timeout_ms": parse_duration_ms(&integration.bounds.deadline)?.min(10_000),
            "audience": interface.audience,
            "scopes": scopes,
        },
        "response": {
            "max_bytes": 8 * 1024,
            "accepted_statuses": [200],
            "schema": "strict_access_token_bearer_expires_in",
            "access_token_max_bytes": 4096,
            "token_type": "Bearer",
            "expires_in_min_seconds": 60,
            "expires_in_max_seconds": 3600,
            "max_token_lifetime_ms": 3600000,
            "expiry_safety_skew_ms": expiry_safety_skew_ms,
            "cache_mode": "expiry_bound",
        },
        "failure_policy": "fail_closed_source_unavailable_no_retry_no_stale_no_data_dispatch",
    })))
}

fn generated_verification_operations(
    alias: &str,
    integration: &IntegrationDocument,
) -> Result<Vec<Value>> {
    integration_operations(integration)
        .iter()
        .filter(|(_, operation)| operation.role == OperationRole::Verification)
        .map(|(id, operation)| {
            if operation.primitive.as_deref() != Some("jwks_json_v1")
                || operation.request.method != ReadMethod::Get
                || operation.response.statuses != [200]
            {
                bail!("verification operation must use the closed JWKS GET primitive");
            }
            Ok(json!({
                "id": id,
                "primitive": "jwks_v1",
                "destination_slot": format!("{alias}-verification"),
                "method": "GET",
                "path": operation.request.path,
                "step_limits": {
                    "max_request_bytes": integration.bounds.request_bytes,
                    "timeout_ms": parse_duration_ms(&integration.bounds.deadline)?.min(10_000),
                    "max_in_flight": 1,
                },
                "max_response_bytes": operation.response.max_bytes,
                "accepted_statuses": operation.response.statuses,
            }))
        })
        .collect()
}

fn generated_dci_document(operation: &OperationDeclaration) -> Result<Value> {
    let body = operation
        .request
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("DCI authored parameters must be one fixed body object"))?;
    let literal_string = |name: &str| -> Result<String> {
        body.get(name)
            .and_then(Value::as_object)
            .and_then(|value| value.get("value"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("DCI authored parameter {name} must be one fixed string"))
    };
    let page_number = body
        .get("page_number")
        .and_then(Value::as_object)
        .and_then(|value| value.get("value"))
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| anyhow!("DCI page_number must be one fixed positive integer"))?;
    if page_number == 0 || page_number > u64::from(u16::MAX) {
        bail!("DCI page_number is outside its fixed bound");
    }
    let verification = operation
        .verification
        .as_ref()
        .ok_or_else(|| anyhow!("DCI verification binding is absent"))?;
    let jwks_operation = verification
        .jwks
        .split_once('.')
        .map(|(operation, _)| operation)
        .ok_or_else(|| anyhow!("DCI JWKS binding is invalid"))?;
    let exact_and = body
        .get("exact_and")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("DCI exact selector map is absent"))?;
    let mut document = json!({
        "protocol_version": literal_string("protocol_version")?,
        "sender_id": literal_string("sender")?,
        "receiver_id": literal_string("receiver")?,
        "registry_type": literal_string("registry_type")?,
        "registry_event_type": literal_string("registry_event_type")?,
        "record_type": literal_string("record_type")?,
        "exact_and": exact_and,
        "locale": literal_string("locale")?,
        "page_number": page_number,
        "jwks_operation": jwks_operation,
        "response_verifier": verification.primitive,
    });
    if body.contains_key("identifier_type") {
        document["identifier_type"] = Value::String(literal_string("identifier_type")?);
    }
    Ok(document)
}

fn generated_rhai_template(_alias: &str, integration: &LoadedIntegration) -> Result<Option<Value>> {
    let CapabilityDeclaration::Script { .. } = integration.document.capability else {
        return Ok(None);
    };
    let script = compiled_rhai_source(integration)?;
    let source = std::str::from_utf8(&script).context("Script closure is not UTF-8")?;
    Ok(Some(json!({
        "script": source,
        "script_hash": sha256_uri(&script),
        "abi": registry_relay::rhai_worker::xw::XW_ABI_VERSION,
        "entrypoint": "consult",
        "memory_bytes": 128 * 1024 * 1024,
        "cpu_ms": 250,
        "ipc_frame_bytes": 256 * 1024,
        "instructions": 100_000,
        "call_depth": 16,
        "string_bytes": 64 * 1024,
        "array_items": 1024,
        "map_entries": 1024,
        "output_bytes": 64 * 1024,
        "concurrency": 1,
    })))
}

fn compiled_rhai_source(integration: &LoadedIntegration) -> Result<Box<[u8]>> {
    const MAX_COMPILED_RHAI_BYTES: usize = 64 * 1024;

    let (script_path, script) = integration
        .script
        .as_ref()
        .ok_or_else(|| anyhow!("Script script is absent"))?;
    let mut source = Vec::new();
    for (module_path, module) in &integration.script_modules {
        let module_path = module_path
            .strip_prefix(integration_root(script_path, &integration.document)?)
            .unwrap_or(module_path)
            .to_string_lossy();
        std::str::from_utf8(module).context("Script module is not UTF-8")?;
        source.extend_from_slice(format!("// registry-local-module:{module_path}\n").as_bytes());
        source.extend_from_slice(module);
        source.extend_from_slice(b"\n");
    }
    std::str::from_utf8(script).context("Script script is not UTF-8")?;
    let script_name = script_path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| anyhow!("Script script name is not Unicode"))?;
    source.extend_from_slice(format!("// registry-entrypoint:{script_name}\n").as_bytes());
    source.extend_from_slice(script);
    if source.is_empty() || source.len() > MAX_COMPILED_RHAI_BYTES || source.contains(&0) {
        bail!("Script script and local modules must form a non-empty 64 KiB closure");
    }
    Ok(source.into_boxed_slice())
}

fn integration_root<'a>(
    script_path: &'a Path,
    _integration: &IntegrationDocument,
) -> Result<&'a Path> {
    script_path
        .parent()
        .ok_or_else(|| anyhow!("Script script has no integration directory"))
}

fn generated_profile_identity(
    loaded: &LoadedRegistryProject,
    service_id: &str,
    consultation_name: &str,
    pack: &GeneratedPack,
) -> Result<(String, String)> {
    let id = bounded_join_id(&[
        loaded.project.registry.id.as_str(),
        service_id,
        consultation_name,
    ])?;
    let service = &loaded.project.services[service_id];
    let _ = (service, consultation_name, pack);
    Ok((id, "1".to_string()))
}

fn consultation_contract_document(
    loaded: &LoadedRegistryProject,
    environment: &EnvironmentDocument,
    service: (&str, &ServiceDeclaration),
    consultation: (&str, &ConsultationDeclaration),
    pack: &GeneratedPack,
    profile: (&str, &str),
) -> Result<Value> {
    let (service_id, service) = service;
    let (consultation_name, consultation) = consultation;
    let (profile_id, profile_version) = profile;
    let pack_value = parse_json_strict(pack.artifact.canonical_json())
        .context("generated integration pack is not strict JSON")?;
    let pack_spec = pack_value
        .get("spec")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("generated integration pack spec is absent"))?;
    let input = pack_spec
        .get("input_slots")
        .cloned()
        .ok_or_else(|| anyhow!("generated integration pack input is absent"))?;
    let bounds = pack_spec
        .get("bounds")
        .cloned()
        .ok_or_else(|| anyhow!("generated integration pack bounds are absent"))?;
    let policy_id = bounded_join_id(&["relay", service_id, consultation_name])?;
    let integration = loaded
        .integrations
        .get(&consultation.integration)
        .ok_or_else(|| anyhow!("consultation integration is absent"))?;
    let runtime = match &integration.document.capability {
        CapabilityDeclaration::Http { .. } => json!({
            "platform_profile": "registry-stack.consultation.v1",
            "source_capability": "http",
            "script_abi": null,
        }),
        CapabilityDeclaration::Script { .. } => json!({
            "platform_profile": "registry-stack.consultation.v1",
            "source_capability": "script",
            "script_abi": registry_relay::rhai_worker::xw::XW_ABI_VERSION,
        }),
        CapabilityDeclaration::Snapshot { .. } => json!({
            "platform_profile": "registry-stack.consultation.v1",
            "source_capability": "snapshot",
            "script_abi": null,
        }),
    };
    let mut specification = json!({
        "runtime": runtime,
        "subject": {
            "mode": "single_subject",
            "selector_provenance": { "type": "workload_selected" },
        },
        "inputs": input,
        "integration_pack": {
            "id": pack.id,
            "version": pack.version,
            "hash": pack.artifact.typed_hash(),
        },
        "acquisition": pack_spec.get("acquisition"),
        "source_provenance": pack_spec.get("source_provenance"),
        "output": pack_spec.get("output"),
        "authorization": {
            "workload": environment
                .notary_relay
                .as_ref()
                .ok_or_else(|| anyhow!("Notary-to-Relay workload binding is absent"))?
                .workload_client_id,
            "required_scope": bounded_scope(&["registry", "consult", service_id])?,
            "purposes": [service.purpose.as_str()],
            "legal_basis": service.legal_basis,
            "policy": {
                "id": policy_id,
                "hash": format!("sha256:{}", "0".repeat(64)),
                "decision_cache": "disabled",
                "max_decision_age_ms": 1000,
                "unavailable": "deny",
            },
            "consent": { "required": false },
            "mandatory_obligations": [],
        },
        "bounds": bounds,
        "public_behavior": {
            "outcomes": ["match", "no_match", "ambiguous"],
            "denial_code": "consultation.denied",
            "denial_timing_profile": "measured-uniform-v1",
        },
    });
    let (_, _, _, _, _, materialization) = generated_pack_semantics(
        loaded,
        &consultation.integration,
        integration,
        &pack.evidence,
    )?;
    if let Some(materialization) = materialization {
        specification["materialization"] = materialization;
    }
    Ok(json!({
        "schema": "registry.relay.consultation-contract.v1",
        "id": profile_id,
        "version": profile_version,
        "spec": specification,
    }))
}

fn private_binding_document(
    loaded: &LoadedRegistryProject,
    environment: &EnvironmentDocument,
    consultation: &ConsultationDeclaration,
    pack: &GeneratedPack,
    profile_id: &str,
    profile_version: &str,
) -> Result<Value> {
    let integration = &loaded.integrations[&consultation.integration];
    let binding = environment.integrations.get(&consultation.integration);
    let data_destination = binding.map(|binding| &binding.source).map(|source| {
        json!({
            "id": format!("{}-data", consultation.integration),
            "origin": source.origin,
            "allowed_private_cidrs": source.allowed_private_cidrs,
            "ca": source.ca,
            "mtls": source.mtls,
        })
    });
    let credential_destination = binding
        .and_then(|binding| binding.source.oauth.as_ref())
        .map(|endpoint| {
            json!({
                "id": format!("{}-credential", consultation.integration),
                "origin": endpoint.origin,
                "application_base_path": endpoint.path,
                "allowed_private_cidrs": endpoint.allowed_private_cidrs,
                "ca": endpoint.ca,
                "mtls": endpoint.mtls,
            })
        });
    let verification_destination = binding
        .and_then(|binding| binding.source.jwks.as_ref())
        .map(|endpoint| {
            json!({
                "id": format!("{}-verification", consultation.integration),
                "origin": endpoint.origin,
                "application_base_path": endpoint.path,
                "allowed_private_cidrs": endpoint.allowed_private_cidrs,
                "ca": endpoint.ca,
                "mtls": endpoint.mtls,
            })
        });
    let credential = binding
        .and_then(|binding| binding.source.credential.as_ref())
        .map(|credential| {
            Ok::<Value, anyhow::Error>(json!({
                "ref": source_credential_reference(
                    loaded,
                    environment,
                    &consultation.integration,
                )?
                .ok_or_else(|| anyhow!("credential reference disappeared"))?,
                "generation": credential.generation,
            }))
        })
        .transpose()?;
    let allow_rhai = matches!(
        integration.document.capability,
        CapabilityDeclaration::Script { .. }
    );
    let rhai = allow_rhai.then(|| {
        json!({
            "max_calls": integration.document.bounds.calls,
            "memory_bytes": 128 * 1024 * 1024,
            "cpu_ms": 250,
            "ipc_frame_bytes": 256 * 1024,
            "instructions": 100_000,
            "call_depth": 16,
            "string_bytes": 64 * 1024,
            "array_items": 1024,
            "map_entries": 1024,
            "output_bytes": 64 * 1024,
            "concurrency": 1,
            "isolation": "one_shot_worker_v1",
        })
    });
    let materialization = match &integration.document.capability {
        CapabilityDeclaration::Snapshot { snapshot } => {
            let entity_definition = &loaded
                .entities
                .get(&snapshot.entity)
                .ok_or_else(|| anyhow!("snapshot entity definition is absent"))?
                .document;
            let entity = environment
                .entities
                .get(&snapshot.entity)
                .ok_or_else(|| anyhow!("snapshot environment entity is absent"))?;
            let keys = snapshot
                .exact
                .iter()
                .map(|(logical, input)| {
                    let physical = entity
                        .columns
                        .get(logical)
                        .ok_or_else(|| anyhow!("snapshot input has no private physical mapping"))?;
                    Ok((
                        input.clone(),
                        json!({
                            "input": input,
                            "physical_field": physical,
                            "physical_type": "utf8",
                            "comparison": "binary_equality",
                        }),
                    ))
                })
                .collect::<Result<Map<String, Value>>>()?;
            let projection = integration
                .document
                .outputs
                .values()
                .filter_map(|output| {
                    let (_, path) = output.from.as_deref()?.split_once('.')?;
                    let field = path.strip_prefix("record.").unwrap_or(path);
                    (field != "presence").then_some(field)
                })
                .map(|field| {
                    let physical = entity
                        .columns
                        .get(field)
                        .ok_or_else(|| anyhow!("environment entity omits a logical field"))?;
                    Ok((field.to_string(), Value::String(physical.clone())))
                })
                .collect::<Result<Map<String, Value>>>()?;
            Some(json!({
                "table_provider": entity_table_provider(entity_definition, entity)?,
                "mapping": {
                    "keys": keys,
                    "projection": projection,
                },
            }))
        }
        CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. } => None,
    };
    let source_instance = match &integration.document.capability {
        CapabilityDeclaration::Snapshot { snapshot } => {
            let entity_definition = &loaded.entities[&snapshot.entity].document;
            let entity = &environment.entities[&snapshot.entity];
            entity_materialization_resource_id(entity_definition, entity)?
        }
        CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. } => {
            format!("{}-source", consultation.integration)
        }
    };
    Ok(json!({
        "profile": { "id": profile_id, "version": profile_version },
        "integration_pack": {
            "id": pack.id,
            "version": pack.version,
            "hash": pack.artifact.typed_hash(),
        },
        "tenant": loaded.project.registry.id,
        "registry_instance": loaded.project.registry.id,
        "source_instance": source_instance,
        "data_destination": data_destination,
        "credential_destination": credential_destination,
        "verification_destination": verification_destination,
        "credential": credential,
        "deployment_parameters": {},
        "limits": {
            "max_source_bytes": integration.document.bounds.source_bytes,
            "timeout_ms": binding
                .and_then(|binding| binding.source.timeout.as_deref())
                .map(parse_duration_ms)
                .transpose()?
                .unwrap_or(parse_duration_ms(&integration.document.bounds.deadline)?)
                .min(parse_duration_ms(&integration.document.bounds.deadline)?),
            "max_in_flight": binding
                .and_then(|binding| binding.source.concurrency)
                .unwrap_or(integration.document.bounds.concurrency)
                .min(integration.document.bounds.concurrency),
            "quota_per_minute": binding
                .and_then(|binding| binding.source.rate.as_ref())
                .map_or(60, |rate| rate.per_minute),
            "quota_burst": binding
                .and_then(|binding| binding.source.rate.as_ref())
                .map_or(integration.document.bounds.concurrency.min(60), |rate| rate.burst),
            "max_public_response_bytes": 64 * 1024,
            "max_token_lifetime_ms": credential_destination.as_ref().map(|_| 3_600_000),
        },
        "capabilities": {
            "allow_script": allow_rhai,
            "script": rhai,
        },
        "materialization": materialization,
    }))
}

#[cfg(test)]
mod artifact_projection_tests {
    use super::*;

    #[test]
    fn raw_projection_schema_preserves_recursive_additional_field_policy() {
        let schema = SchemaNode::Object {
            additional_fields: AdditionalFields::Ignore,
            fields: BTreeMap::from([(
                "record".to_string(),
                SchemaField {
                    required: true,
                    schema: SchemaNode::Object {
                        additional_fields: AdditionalFields::Ignore,
                        fields: BTreeMap::from([
                            (
                                "status".to_string(),
                                SchemaField {
                                    required: true,
                                    schema: SchemaNode::String { max_bytes: 24 },
                                },
                            ),
                            (
                                "metadata".to_string(),
                                SchemaField {
                                    required: false,
                                    schema: SchemaNode::Object {
                                        additional_fields: AdditionalFields::Reject,
                                        fields: BTreeMap::from([(
                                            "source".to_string(),
                                            SchemaField {
                                                required: true,
                                                schema: SchemaNode::String { max_bytes: 32 },
                                            },
                                        )]),
                                    },
                                },
                            ),
                        ]),
                    },
                },
            )]),
        };

        let compiled = relay_projection_schema_node(&schema, false);
        assert_eq!(
            compiled.pointer("/reject_unknown_fields"),
            Some(&json!(false))
        );
        assert_eq!(
            compiled.pointer("/fields/record/schema/reject_unknown_fields"),
            Some(&json!(false))
        );
        assert_eq!(
            compiled.pointer("/fields/record/schema/fields/metadata/schema/reject_unknown_fields"),
            Some(&json!(true))
        );
    }

    #[test]
    fn retained_projection_schema_closes_every_object_boundary() {
        let schema = SchemaNode::Object {
            additional_fields: AdditionalFields::Ignore,
            fields: BTreeMap::from([(
                "record".to_string(),
                SchemaField {
                    required: true,
                    schema: SchemaNode::Object {
                        additional_fields: AdditionalFields::Ignore,
                        fields: BTreeMap::from([(
                            "status".to_string(),
                            SchemaField {
                                required: true,
                                schema: SchemaNode::String { max_bytes: 24 },
                            },
                        )]),
                    },
                },
            )]),
        };

        let compiled = relay_retained_projection_schema_node(&schema, false);
        assert_eq!(
            compiled.pointer("/reject_unknown_fields"),
            Some(&json!(true))
        );
        assert_eq!(
            compiled.pointer("/fields/record/schema/reject_unknown_fields"),
            Some(&json!(true))
        );
    }
}

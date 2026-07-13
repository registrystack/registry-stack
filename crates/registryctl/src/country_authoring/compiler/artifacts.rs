// SPDX-License-Identifier: Apache-2.0

fn compile_country(
    loaded: &LoadedCountryProject,
    baseline: Option<&VerifiedBaseline>,
) -> Result<CompiledCountry> {
    let environment = loaded
        .environment
        .as_ref()
        .ok_or_else(|| anyhow!("country build requires an explicit environment"))?;
    let environment_name = loaded
        .environment_name
        .as_deref()
        .ok_or_else(|| anyhow!("country build requires an explicit environment"))?;
    compile_country_for_environment(loaded, environment_name, environment, baseline)
}

fn compile_country_for_environment(
    loaded: &LoadedCountryProject,
    environment_name: &str,
    environment: &EnvironmentDocument,
    baseline: Option<&VerifiedBaseline>,
) -> Result<CompiledCountry> {
    validate_entity_generation_changes(loaded, environment, baseline)?;
    let mut reviewable = BTreeMap::new();
    let mut relay_private = BTreeMap::new();
    let mut packs = BTreeMap::new();

    for (id, records) in &loaded.records {
        reviewable.insert(
            PathBuf::from(format!("records/{id}.json")),
            canonical_json_line(&serde_json::to_value(&records.document)?)?.into_boxed_slice(),
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
        if let Some((_, script)) = &integration.script {
            relay_private.insert(
                PathBuf::from(format!("config/artifacts/rhai/{alias}.rhai")),
                script.clone(),
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

    let relay_config =
        generated_relay_config(loaded, environment_name, environment, &packs, &profiles)?;
    relay_private.insert(
        PathBuf::from("config/relay.yaml"),
        serde_yaml::to_string(&relay_config)?
            .into_bytes()
            .into_boxed_slice(),
    );
    let notary_config = generated_notary_config(loaded, environment_name, environment, &profiles)?;
    relay_private.insert(
        PathBuf::from("descriptors/operations.json"),
        canonical_json_line(&operational_descriptor(
            "registry-relay",
            &environment.deployment.relay.service,
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
    let mut notary_private = BTreeMap::from([(
        PathBuf::from("config/notary.yaml"),
        serde_yaml::to_string(&notary_config)?
            .into_bytes()
            .into_boxed_slice(),
    )]);
    notary_private.insert(
        PathBuf::from("descriptors/operations.json"),
        canonical_json_line(&operational_descriptor(
            "registry-notary",
            &environment.deployment.notary.service,
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

    let reviewable_digest = closure_digest(&reviewable)?;
    let relay_digest = closure_digest(&relay_private)?;
    let notary_digest = closure_digest(&notary_private)?;
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
        baseline.map(|baseline| &baseline.review),
        &disclosure_digest,
    );
    let reviews = required_reviews(loaded, baseline.map(|baseline| &baseline.review));
    let semantic_unchanged = reviews.is_empty();
    let mut reviews = reviews;
    if let Some(baseline) = baseline {
        let compiler_changed = baseline
            .review
            .get("compiler_version")
            .and_then(Value::as_str)
            != Some(env!("CARGO_PKG_VERSION"));
        let generated_changed =
            baseline.review.get("generated_closure_digests") != Some(&closure_digests);
        if compiler_changed || (semantic_unchanged && generated_changed) {
            reviews.extend([
                ReviewClass::Claim,
                ReviewClass::Integration,
                ReviewClass::CountryPolicy,
                ReviewClass::OperatorSecurity,
            ]);
        }
    }
    let baseline_record = baseline
        .map(|baseline| {
            Ok::<Value, anyhow::Error>(json!({
                "review_digest": digest_json(&baseline.review)?,
                "review_digests": baseline.review.get("review_digests").cloned()
                    .unwrap_or_else(null_review_digests),
                "authored_input_digest": baseline.review.get("authored_input_digest"),
                "verified_manifest": baseline.verified_manifest,
            }))
        })
        .transpose()?;
    let review_digests = current_review_digests(
        &loaded.semantic_digests,
        &disclosure_digest,
        &reviews,
    )?;
    let review = json!({
        "schema": REVIEW_SCHEMA,
        "registry": loaded.project.registry.id,
        "source_revision": loaded.authored_hash,
        "compiler_version": env!("CARGO_PKG_VERSION"),
        "baseline": baseline_record,
        "authored_input_digest": loaded.authored_hash,
        "semantic_digests": loaded.semantic_digests,
        "disclosure_profiles": disclosure_profiles,
        "disclosure_digest": disclosure_digest,
        "generated_closure_digests": closure_digests,
        "semantic_changes": semantic_changes,
        "required_reviews": reviews,
        "review_digests": review_digests,
        "environment": environment_name,
        "entity_materializations": generated_entity_materialization_review(loaded, environment)?,
    });
    let explanation = generated_explanation(loaded, environment_name, &packs, &profiles);
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
    // The review record itself is deliberately excluded from the digests above.
    // It becomes a signed payload member only when the existing bundle command runs.
    Ok(CompiledCountry {
        reviewable,
        relay_private,
        notary_private,
        review,
        explanation,
        fixture_profiles,
        semantic_changes,
        required_reviews: reviews,
    })
}

fn current_review_digests(
    semantic: &SemanticDigests,
    disclosure_digest: &str,
    required: &BTreeSet<ReviewClass>,
) -> Result<Value> {
    let claim = digest_json(&json!({
        "semantic": semantic.claim,
        "disclosure": disclosure_digest,
    }))?;
    let country_policy = digest_json(&json!({
        "semantic": semantic.country_policy,
        "disclosure": disclosure_digest,
    }))?;
    Ok(json!({
        "claim": required.contains(&ReviewClass::Claim).then_some(claim),
        "integration": required.contains(&ReviewClass::Integration)
            .then_some(semantic.integration.as_str()),
        "country_policy": required.contains(&ReviewClass::CountryPolicy)
            .then_some(country_policy),
        "operator_security": required.contains(&ReviewClass::OperatorSecurity)
            .then_some(semantic.operator_security.as_str()),
    }))
}

fn operational_descriptor(
    product: &str,
    service: &str,
    profile: CountryDeploymentProfile,
    consultation_profiles: usize,
) -> Value {
    let config = match product {
        "registry-relay" => "config/relay.yaml",
        "registry-notary" => "config/notary.yaml",
        _ => "config.yaml",
    };
    json!({
        "schema": "registry.country.operations.v1",
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
        "schema": "registry.country.secret-consumers.v1",
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
                    "token_file" | "notary_token_file" | "private_key_file" | "secret_file"
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
                "schema": "registry.country.integration-evidence.v1",
                "class": "conformance",
                "integration": integration.document.id,
                "fixtures": conformance,
            }),
        ),
        (
            EvidenceClass::NegativeSecurity,
            "negative-security",
            json!({
                "schema": "registry.country.integration-evidence.v1",
                "class": "negative_security",
                "integration": integration.document.id,
                "fixtures": negative_security,
            }),
        ),
        (
            EvidenceClass::Minimization,
            "minimization",
            json!({
                "schema": "registry.country.integration-evidence.v1",
                "class": "minimization",
                "integration": integration.document.id,
                "facts": integration.document.facts,
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
    loaded: &LoadedCountryProject,
    environment: &EnvironmentDocument,
    alias: &str,
    integration: &LoadedIntegration,
    evidence: &[GeneratedEvidence],
) -> Result<Value> {
    let binding = environment
        .integrations
        .get(alias)
        .ok_or_else(|| anyhow!("integration environment binding is absent"))?;
    let pack_id = bounded_join_id(&[
        loaded.project.registry.id.as_str(),
        integration.document.id.as_str(),
    ])?;
    let version_seed = json!({
        "integration": integration.document,
        "fixtures": integration.fixtures.iter().map(|(_, fixture)| fixture).collect::<Vec<_>>(),
        "script": integration.script.as_ref().map(|(_, bytes)| sha256_uri(bytes)),
        "source_version": binding.source_version,
    });
    let version = numeric_artifact_version(&digest_json(&version_seed)?)?;
    let input_slots = integration
        .document
        .input
        .iter()
        .map(|(name, input)| {
            Ok((
                name.clone(),
                json!({
                    "type": match input.input_type {
                        InputType::String => "string",
                        InputType::FullDate => "full_date",
                    },
                    "max_bytes": input.bytes,
                    "pattern": relay_input_pattern(&input.pattern)?,
                    "canonicalization": match input.canonicalization {
                        Canonicalization::Identity => "identity",
                        Canonicalization::AsciiLowercase => "ascii_lowercase",
                    },
                }),
            ))
        })
        .collect::<Result<Map<String, Value>>>()?;
    let (acquisition, reviewed, output, plan, limits, _materialization) =
        generated_pack_semantics(alias, integration, evidence)?;
    let evidence_manifest = evidence_manifest(evidence);
    let specification = json!({
        "product_family": integration.document.source.product,
        "supported_version_evidence": [format!("{}:{}", source_version_class(&integration.document, &binding.source_version), binding.source_version)],
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

fn source_version_class(integration: &IntegrationDocument, version: &str) -> &'static str {
    if integration
        .source
        .versions
        .tested
        .iter()
        .any(|item| item == version)
    {
        "tested"
    } else if integration
        .source
        .versions
        .supported
        .iter()
        .any(|item| item == version)
    {
        "supported"
    } else {
        "unverified"
    }
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

fn numeric_artifact_version(digest: &str) -> Result<String> {
    let hexadecimal = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("semantic digest has an invalid shape"))?;
    let value = u64::from_str_radix(&hexadecimal[..12], 16)? % 9_000_000_000;
    Ok((value + 1_000_000_000).to_string())
}

type PackSemantics = (Value, Value, Value, Value, Value, Option<Value>);

fn generated_pack_semantics(
    alias: &str,
    integration: &LoadedIntegration,
    evidence: &[GeneratedEvidence],
) -> Result<PackSemantics> {
    match &integration.document.capability {
        CapabilityDeclaration::BoundedHttp { .. } | CapabilityDeclaration::SandboxedRhai { .. } => {
            generated_http_pack_semantics(alias, integration, evidence)
        }
        CapabilityDeclaration::SnapshotExact { snapshot_exact } => {
            generated_snapshot_pack_semantics(alias, integration, snapshot_exact)
        }
    }
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
    for (operation_id, operation) in &data_operations {
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
            let compiled = relay_schema_node(&schema.schema, false);
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
        .facts
        .iter()
        .map(|(name, fact)| {
            let output_type = if fact.from.ends_with(".presence") {
                "presence"
            } else {
                match fact.fact_type {
                    FactType::Boolean | FactType::Presence => "boolean",
                    FactType::Integer => "integer",
                    FactType::String => "string",
                    FactType::Date => "date",
                }
            };
            let mut declaration = json!({ "type": output_type, "nullable": fact.nullable });
            match fact.fact_type {
                FactType::String => {
                    declaration["max_bytes"] = json!(fact.max_bytes);
                }
                FactType::Integer => {
                    let schema = fact_source_schema(&integration.document, fact)
                        .expect("validated integer fact source schema");
                    if let SchemaNode::Integer { min, max } = schema {
                        declaration["minimum"] = json!(min);
                        declaration["maximum"] = json!(max);
                    }
                }
                FactType::Date => declaration["max_bytes"] = json!(10),
                FactType::Boolean | FactType::Presence => {}
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
        CapabilityDeclaration::SandboxedRhai { .. }
    ) {
        Map::new()
    } else {
        generated_step_conditions(&integration.document)?
    };
    let verification_operations = generated_verification_operations(alias, &integration.document)?;
    let first = data_operations[0];
    let selector = exact_selector(&integration.document.input, first.0, first.1)?;
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
        CapabilityDeclaration::BoundedHttp { .. } => "bounded_http",
        CapabilityDeclaration::SandboxedRhai { .. } => "sandboxed_rhai",
        CapabilityDeclaration::SnapshotExact { .. } => unreachable!(),
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
        "operations": operations,
        "verification_operations": verification_operations,
        "steps": data_operations.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
        "step_conditions": step_conditions,
        "credential_operation": credential_operation,
        "snapshot": null,
        "rhai": rhai,
    });
    let credential_exchanges = usize::from(credential_operation.is_some());
    let limits = json!({
        "max_source_matches": if any_probe_two { 2 } else { 1 },
        "max_disclosed_records": 1,
        "max_data_exchanges": data_operations.len() + verification_operations.len(),
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

fn generated_snapshot_pack_semantics(
    _alias: &str,
    integration: &LoadedIntegration,
    snapshot: &SnapshotExactDeclaration,
) -> Result<PackSemantics> {
    let mut fields = Map::new();
    let mut output = Map::new();
    for (fact_name, fact) in &integration.document.facts {
        let (_, path) = fact
            .from
            .split_once('.')
            .ok_or_else(|| anyhow!("snapshot fact path is invalid"))?;
        let field = path.strip_prefix("record.").unwrap_or(path);
        if field == "presence" {
            output.insert(
                fact_name.clone(),
                json!({ "type": "presence", "nullable": false }),
            );
            continue;
        }
        let schema = match fact.fact_type {
            FactType::Boolean | FactType::Presence => {
                json!({ "type": "boolean", "nullable": fact.nullable })
            }
            FactType::Integer => json!({
                "type": "integer",
                "nullable": fact.nullable,
                "minimum": -((1_i64 << 53) - 1),
                "maximum": (1_i64 << 53) - 1,
            }),
            FactType::String => json!({
                "type": "string",
                "nullable": fact.nullable,
                "max_bytes": fact.max_bytes.ok_or_else(|| anyhow!("snapshot string fact bound is absent"))?,
            }),
            FactType::Date => {
                json!({ "type": "string", "nullable": fact.nullable, "max_bytes": 10 })
            }
        };
        fields.insert(field.to_string(), schema);
        output.insert(fact_name.clone(), {
            let mut declaration = json!({
            "type": match fact.fact_type {
                FactType::Boolean | FactType::Presence => "boolean",
                FactType::Integer => "integer",
                FactType::String => "string",
                FactType::Date => "date",
            },
            "nullable": fact.nullable,
            });
            match fact.fact_type {
                FactType::String => declaration["max_bytes"] = json!(fact.max_bytes),
                FactType::Integer => {
                    declaration["minimum"] = json!(-((1_i64 << 53) - 1));
                    declaration["maximum"] = json!((1_i64 << 53) - 1);
                }
                FactType::Date => declaration["max_bytes"] = json!(10),
                FactType::Boolean | FactType::Presence => {}
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
        "refresh_class": "operator_triggered",
        "snapshot_retention_generations": 2,
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
    if operation.primitive.as_deref() == Some("fhir_r4_search_get") {
        return Ok(&operation.response.schema);
    }
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
        SchemaNode::Object { fields, .. } => json!({
            "type": "object",
            "nullable": nullable,
            "reject_unknown_fields": true,
            "fields": fields.iter().map(|(name, field)| (name.clone(), json!({
                "required": field.required,
                "schema": relay_schema_node(&field.schema, false),
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
    let is_fhir = operation.primitive.as_deref() == Some("fhir_r4_search_get");
    let is_rhai = matches!(
        integration.capability,
        CapabilityDeclaration::SandboxedRhai { .. }
    );
    let record = operation_record_schema(operation)?;
    let SchemaNode::Object { fields, .. } = record else {
        bail!("normalized operation record must be an object");
    };
    let operation_facts = integration
        .facts
        .iter()
        .filter_map(|(name, fact)| {
            fact.from
                .split_once('.')
                .is_some_and(|(source, _)| source == operation_id)
                .then_some((name, fact))
        })
        .collect::<Vec<_>>();
    let acquisition_fields = if is_dci {
        BTreeSet::from(["record"])
    } else {
        operation_facts
            .iter()
            .filter_map(|(_, fact)| {
                let (_, path) = fact.from.split_once('.')?;
                (!path.ends_with("presence"))
                    .then(|| path.strip_prefix("record.").unwrap_or(path))
                    .and_then(|path| path.split('.').next())
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
        operation_facts
            .iter()
            .filter_map(|(name, fact)| {
                let (_, path) = fact.from.split_once('.')?;
                if path == "presence" {
                    None
                } else {
                    let path = path.strip_prefix("record.").unwrap_or(path);
                    let pointer = if is_dci {
                        format!("record.{path}")
                    } else {
                        path.to_string()
                    };
                    Some(((*name).clone(), static_json_pointer(&pointer)))
                }
            })
            .collect::<Map<String, Value>>()
    };
    let presence_outputs = if is_rhai {
        Vec::new()
    } else {
        operation_facts
            .iter()
            .filter_map(|(name, fact)| fact.from.ends_with(".presence").then_some((*name).clone()))
            .collect::<Vec<_>>()
    };
    let prior_fields = if matches!(
        integration.capability,
        CapabilityDeclaration::SandboxedRhai { .. }
    ) {
        fields.keys().cloned().collect::<BTreeSet<_>>()
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
    let response_cardinality = if is_dci {
        json!({ "mechanism": "dci_probe_two" })
    } else {
        generated_cardinality(operation, evidence)?
    };
    let cardinality = operation.response.cardinality.as_ref();
    let (normalization, records_field, max_records) = if is_dci || is_fhir {
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
    let response_schema = if is_dci {
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
    } else if is_fhir {
        json!({
            "type": "array",
            "nullable": false,
            "max_items": 2,
            "items": relay_schema_node(record, false),
        })
    } else {
        relay_schema_node(&operation.response.schema, false)
    };
    let mut response = json!({
        "max_bytes": operation.response.max_bytes,
        "max_records": max_records,
        "normalization": normalization,
        "cardinality": response_cardinality,
        "schema": response_schema,
        "output_mapping": output_mapping,
        "presence_outputs": presence_outputs,
        "prior_outputs": prior_outputs,
        "accepted_statuses": operation.response.statuses,
    });
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
        Some("fhir_r4_search_get") => "fhir_r4_search",
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
    if is_fhir {
        let resource_type = operation
            .request
            .path
            .rsplit('/')
            .next()
            .filter(|resource| !resource.is_empty())
            .ok_or_else(|| anyhow!("FHIR operation path must end with its resource type"))?;
        document["fhir"] = json!({ "resource_type": resource_type });
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

fn static_json_pointer(path: &str) -> Value {
    Value::String(format!(
        "/{}",
        path.split('.')
            .map(|token| token.replace('~', "~0").replace('/', "~1"))
            .collect::<Vec<_>>()
            .join("/")
    ))
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
        .keys()
        .map(|input| {
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
                        .facts
                        .iter()
                        .find_map(|(name, fact)| {
                            (fact.from == format!("{step}.presence")).then_some(name)
                        })
                        .ok_or_else(|| anyhow!("presence condition requires a declared presence fact"))?;
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
    let operation = integration_operations(integration)
        .iter()
        .find(|(_, operation)| operation.role == OperationRole::Credential);
    let Some((id, operation)) = operation else {
        return Ok(None);
    };
    if operation.primitive.as_deref() != Some("oauth2_client_credentials") {
        bail!("unsupported credential operation primitive");
    }
    let SchemaNode::Object { fields, .. } = &operation.response.schema else {
        bail!("OAuth response schema must be a closed object");
    };
    let access_token_max_bytes = match fields.get("access_token").map(|field| &field.schema) {
        Some(SchemaNode::String { max_bytes }) => *max_bytes,
        _ => bail!("OAuth response schema must bound access_token"),
    };
    Ok(Some(json!({
        "id": id,
        "kind": "oauth2_client_credentials",
        "destination_slot": format!("{alias}-credential"),
        "path": operation.request.path,
        "request": {
            "format": "json_client_secret_body",
            "max_client_id_bytes": 256,
            "max_client_secret_bytes": 512,
            "max_body_bytes": integration.bounds.request_bytes.min(8192),
            "max_request_bytes": integration.bounds.request_bytes,
            "timeout_ms": parse_duration_ms(&integration.bounds.deadline)?.min(10_000),
        },
        "response": {
            "max_bytes": operation.response.max_bytes,
            "accepted_statuses": operation.response.statuses,
            "schema": "strict_access_token_bearer_no_expiry",
            "access_token_max_bytes": access_token_max_bytes,
            "token_type": "Bearer",
            "cache_mode": "disabled",
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
                "destination_slot": format!("{alias}-data"),
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
        .and_then(Value::as_u64)
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
    let CapabilityDeclaration::SandboxedRhai { .. } = integration.document.capability else {
        return Ok(None);
    };
    let (_, script) = integration
        .script
        .as_ref()
        .ok_or_else(|| anyhow!("sandboxed Rhai script is absent"))?;
    let source = std::str::from_utf8(script).context("sandboxed Rhai script is not UTF-8")?;
    Ok(Some(json!({
        "script": source,
        "script_hash": sha256_uri(script),
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

fn generated_profile_identity(
    loaded: &LoadedCountryProject,
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
    let version = numeric_artifact_version(&digest_json(&json!({
        "service": service,
        "consultation": consultation_name,
        "pack_hash": pack.artifact.typed_hash(),
    }))?)?;
    Ok((id, version))
}

fn consultation_contract_document(
    loaded: &LoadedCountryProject,
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
    let max_matches = bounds
        .get("max_source_matches")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("generated integration pack cardinality is absent"))?;
    let policy_id = bounded_join_id(&["relay", service_id, consultation_name])?;
    let mut specification = json!({
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
            "workload": environment.relay_trust.notary_client_id,
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
            "outcomes": if max_matches == 2 { vec!["match", "no_match", "ambiguous"] } else { vec!["match", "no_match"] },
            "denial_code": "consultation.denied",
            "denial_timing_profile": "measured-uniform-v1",
        },
    });
    let integration = loaded
        .integrations
        .get(&consultation.integration)
        .ok_or_else(|| anyhow!("consultation integration is absent"))?;
    let (_, _, _, _, _, materialization) =
        generated_pack_semantics(&consultation.integration, integration, &pack.evidence)?;
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
    loaded: &LoadedCountryProject,
    environment: &EnvironmentDocument,
    consultation: &ConsultationDeclaration,
    pack: &GeneratedPack,
    profile_id: &str,
    profile_version: &str,
) -> Result<Value> {
    let integration = &loaded.integrations[&consultation.integration];
    let binding = &environment.integrations[&consultation.integration];
    let data_destination = binding.data_destination.as_ref().map(|destination| {
        json!({
            "id": format!("{}-data", consultation.integration),
            "origin": destination.origin,
            "allowed_private_cidrs": [],
        })
    });
    let credential_destination = binding.credential_destination.as_ref().map(|destination| {
        json!({
            "id": format!("{}-credential", consultation.integration),
            "origin": destination.origin,
            "allowed_private_cidrs": [],
        })
    });
    let credential = binding.credential.as_ref().map(|credential| {
        json!({
            "ref": format!("{}-credential", consultation.integration),
            "generation": credential.generation,
        })
    });
    let allow_rhai = matches!(
        integration.document.capability,
        CapabilityDeclaration::SandboxedRhai { .. }
    );
    let rhai = allow_rhai.then(|| {
        json!({
            "callable_operations": integration_operations(&integration.document).keys().collect::<Vec<_>>(),
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
    let materialization =
        match &integration.document.capability {
            CapabilityDeclaration::SnapshotExact { snapshot_exact } => {
                let records = &loaded
                    .records
                    .get(&snapshot_exact.entity)
                    .ok_or_else(|| anyhow!("snapshot records definition is absent"))?
                    .document;
                let entity = environment
                    .entities
                    .get(&snapshot_exact.entity)
                    .ok_or_else(|| anyhow!("snapshot environment entity is absent"))?;
                let keys = integration
                    .document
                    .input
                    .keys()
                    .map(|input| {
                        let physical = entity.columns.get(input).ok_or_else(|| {
                            anyhow!("snapshot input has no private physical mapping")
                        })?;
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
                    .facts
                    .values()
                    .filter_map(|fact| {
                        let (_, path) = fact.from.split_once('.')?;
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
                    "table_provider": records_table_provider(records, entity)?,
                    "mapping": {
                        "keys": keys,
                        "projection": projection,
                    },
                }))
            }
            CapabilityDeclaration::BoundedHttp { .. }
            | CapabilityDeclaration::SandboxedRhai { .. } => None,
        };
    let source_instance = match &integration.document.capability {
        CapabilityDeclaration::SnapshotExact { snapshot_exact } => {
            let records = &loaded.records[&snapshot_exact.entity].document;
            let entity = &environment.entities[&snapshot_exact.entity];
            records_materialization_resource_id(records, entity)?
        }
        CapabilityDeclaration::BoundedHttp { .. } | CapabilityDeclaration::SandboxedRhai { .. } => {
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
        "credential": credential,
        "deployment_parameters": {},
        "limits": {
            "max_source_bytes": integration.document.bounds.source_bytes,
            "timeout_ms": parse_duration_ms(&integration.document.bounds.deadline)?,
            "max_in_flight": integration.document.bounds.concurrency,
            "quota_per_minute": 60,
            "quota_burst": integration.document.bounds.concurrency.min(60),
            "max_public_response_bytes": 64 * 1024,
        },
        "capabilities": {
            "allow_sandboxed_rhai": allow_rhai,
            "sandboxed_rhai": rhai,
        },
        "materialization": materialization,
    }))
}

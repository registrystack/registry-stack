// SPDX-License-Identifier: Apache-2.0

fn generated_notary_config(
    loaded: &LoadedRegistryProject,
    environment_name: &str,
    environment: &EnvironmentDocument,
    profiles: &[GeneratedProfile],
) -> Result<Value> {
    let notary_service = environment
        .deployment
        .notary
        .as_ref()
        .ok_or_else(|| anyhow!("Notary deployment binding is absent"))?;
    let issuance = environment
        .issuance
        .as_ref()
        .ok_or_else(|| anyhow!("Notary issuance binding is absent"))?;
    let mut variables = Map::new();
    let mut claims = Vec::new();
    let mut credential_profiles = Map::new();
    let mut allowed_purposes = BTreeSet::new();
    let mut seen_claims = BTreeSet::new();
    let mut max_validity_seconds = 600_u64;
    for (service_id, service) in &loaded.project.services {
        if service.kind != ServiceKind::Evidence {
            continue;
        }
        allowed_purposes.insert(service.purpose.clone());
        for (name, variable) in &service.variables {
            let declaration = json!({ "from": variable.from, "type": "date" });
            if variables
                .insert(name.clone(), declaration.clone())
                .is_some_and(|prior| prior != declaration)
            {
                bail!("request variable has conflicting service declarations");
            }
        }
        for (credential_id, credential) in &service.credentials {
            let profile_id = bounded_join_id(&[service_id, credential_id])?;
            let validity_seconds = parse_validity_seconds(&credential.validity)?;
            max_validity_seconds = max_validity_seconds.max(validity_seconds);
            credential_profiles.insert(
                profile_id,
                json!({
                    "format": normalize_credential_format(&credential.format),
                    "issuer": issuance.issuer,
                    "signing_key": "project-issuer",
                    "vct": credential.credential_type,
                    "validity_seconds": validity_seconds,
                    "allowed_claims": credential.claims,
                    "disclosure": { "allowed": ["value", "predicate", "redacted"] },
                }),
            );
        }
        for (claim_id, claim) in &service.claims {
            if !seen_claims.insert(claim_id) {
                bail!("Notary claim ids must be unique across project services");
            }
            let claim_credential_profiles = service
                .credentials
                .iter()
                .filter(|(_, credential)| credential.claims.iter().any(|id| id == claim_id))
                .map(|(credential, _)| bounded_join_id(&[service_id, credential]))
                .collect::<Result<Vec<_>>>()?;
            let mut formats = vec!["application/vnd.registry-notary.claim-result+json".to_string()];
            formats.extend(
                service
                    .credentials
                    .values()
                    .filter(|credential| credential.claims.iter().any(|id| id == claim_id))
                    .map(|credential| normalize_credential_format(&credential.format)),
            );
            formats.sort();
            formats.dedup();
            let (default_disclosure, allowed_disclosures) = expanded_disclosure(&claim.disclosure);
            let (evidence_mode, value_type, nullable, rule) = match claim.evidence {
                ClaimEvidence::RegistryBacked => {
                    let consultation_name = claim_consultation_name(service, claim)?;
                    let consultation = &service.consultations[consultation_name];
                    let integration = &loaded.integrations[&consultation.integration];
                    let profile = profiles
                        .iter()
                        .find(|profile| {
                            profile.service_id == *service_id
                                && profile.consultation_name == consultation_name
                        })
                        .ok_or_else(|| anyhow!("claim consultation profile is absent"))?;
                    let facts = generated_notary_fact_contracts(&integration.document)?;
                    let (value_type, nullable, rule) = generated_notary_claim_rule(
                        claim_id,
                        claim,
                        consultation_name,
                        &integration.document,
                        integration,
                    )?;
                    let inputs = consultation
                        .input
                        .iter()
                        .map(|(name, source)| {
                            (
                                name.clone(),
                                Value::String(if source == "request.target.id" {
                                    "target.id".to_string()
                                } else {
                                    source.clone()
                                }),
                            )
                        })
                        .collect::<Map<String, Value>>();
                    let consultation_config = json!({
                        "profile": {
                            "id": profile.id,
                            "version": profile.version,
                            "contract_hash": profile.contract.artifact().typed_hash(),
                        },
                        "inputs": inputs,
                        "facts": facts,
                    });
                    let consultations =
                        Map::from_iter([(consultation_name.to_string(), consultation_config)]);
                    (
                        json!({ "type": "registry_backed", "consultations": consultations }),
                        value_type,
                        nullable,
                        rule,
                    )
                }
                ClaimEvidence::SelfAttested => {
                    let value = claim
                        .value
                        .as_ref()
                        .ok_or_else(|| anyhow!("self-attested claim value contract is absent"))?;
                    let expression = claim
                        .cel
                        .as_ref()
                        .ok_or_else(|| anyhow!("self-attested claim CEL rule is absent"))?;
                    (
                        json!({ "type": "self_attested" }),
                        claim_value_type(value)?.to_string(),
                        value.nullable,
                        json!({ "type": "cel", "expression": expression, "bindings": {} }),
                    )
                }
            };
            claims.push(json!({
                "id": claim_id,
                "title": claim_id.replace('-', " "),
                "version": service.version.to_string(),
                "subject_type": "person",
                "evidence_mode": evidence_mode,
                "value": { "type": value_type, "nullable": nullable },
                "purpose": service.purpose,
                "required_scopes": service.access.scopes,
                "rule": rule,
                "disclosure": {
                    "default": default_disclosure,
                    "allowed": allowed_disclosures,
                    "downgrade": "deny",
                },
                "formats": formats,
                "credential_profiles": claim_credential_profiles,
            }));
        }
    }
    let api_keys = environment
        .callers
        .iter()
        .map(|(id, caller)| {
            json!({
                "id": id,
                "fingerprint": {
                    "provider": "env",
                    "name": caller.api_key_fingerprint.secret,
                },
                "scopes": caller.scopes,
            })
        })
        .collect::<Vec<_>>();
    let mut evidence = json!({
        "enabled": true,
        "service_id": notary_service.service,
        "max_credential_validity_seconds": max_validity_seconds,
        "allowed_purposes": allowed_purposes,
        "variables": variables,
        "claims": claims,
        "signing_keys": {
            "project-issuer": {
                "provider": "local_jwk_env",
                "private_jwk_env": issuance.signing_key.secret,
                "alg": "EdDSA",
                "kid": issuance.signing_kid,
                "status": "active",
            },
        },
        "credential_profiles": credential_profiles,
    });
    if let (Some(relay), Some(connection)) = (&environment.relay, &environment.notary_relay) {
        evidence["relay"] = json!({
            "base_url": relay.origin,
            "token_file": connection.token_file,
            "allowed_private_cidrs": [],
        });
    }
    Ok(json!({
        "instance": {
            "id": notary_service.service,
            "environment": environment_name,
        },
        "server": { "bind": "127.0.0.1:8081", "request_timeout": "30s" },
        "auth": { "mode": "api_key", "api_keys": api_keys },
        "audit": {
            "sink": "stdout",
            "hash_secret_env": "REGISTRY_NOTARY_AUDIT_HASH_SECRET",
        },
        "evidence": evidence,
        "deployment": { "profile": environment.deployment.profile.as_str() },
    }))
}

fn claim_value_type(value: &ClaimValueDeclaration) -> Result<&'static str> {
    match value.value_type {
        FactType::Boolean => Ok("boolean"),
        FactType::Integer => Ok("integer"),
        FactType::String => Ok("string"),
        FactType::Date => Ok("date"),
        FactType::Presence => bail!("claim value contracts cannot use presence"),
    }
}

fn generated_notary_fact_contracts(integration: &IntegrationDocument) -> Result<Value> {
    let facts = integration
        .outputs
        .iter()
        .map(|(name, fact)| {
            let contract = if fact.from.ends_with(".presence") {
                json!({ "type": "presence" })
            } else {
                match fact.output_type {
                    FactType::Boolean | FactType::Presence => {
                        json!({ "type": "boolean", "nullable": fact.nullable })
                    }
                    FactType::Integer => {
                        if matches!(
                            integration.capability,
                            CapabilityDeclaration::Snapshot { .. }
                        ) {
                            json!({
                                "type": "integer",
                                "nullable": fact.nullable,
                                "minimum": -((1_i64 << 53) - 1),
                                "maximum": (1_i64 << 53) - 1,
                            })
                        } else {
                            let schema = output_source_schema(integration, fact)?;
                            let SchemaNode::Integer { min, max } = schema else {
                                bail!("integer fact must resolve to an integer response field");
                            };
                            json!({ "type": "integer", "nullable": fact.nullable, "minimum": min, "maximum": max })
                        }
                    }
                    FactType::String => json!({
                        "type": "string",
                        "nullable": fact.nullable,
                        "max_bytes": fact.max_bytes.ok_or_else(|| anyhow!("string fact bound is absent"))?,
                    }),
                    FactType::Date => {
                        json!({ "type": "date", "nullable": fact.nullable })
                    }
                }
            };
            Ok((name.clone(), contract))
        })
        .collect::<Result<Map<String, Value>>>()?;
    Ok(Value::Object(facts))
}

fn output_source_schema<'a>(
    integration: &'a IntegrationDocument,
    fact: &OutputDeclaration,
) -> Result<&'a SchemaNode> {
    let (operation, path) = fact
        .from
        .split_once('.')
        .ok_or_else(|| anyhow!("fact path is invalid"))?;
    let operation = integration_operations(integration)
        .get(operation)
        .ok_or_else(|| anyhow!("fact operation is absent"))?;
    let mut schema = operation_record_schema(operation)?;
    let path = path.strip_prefix("record.").unwrap_or(path);
    for segment in path.split('.') {
        schema = match schema {
            SchemaNode::Object { fields, .. } => fields
                .get(segment)
                .map(|field| &field.schema)
                .ok_or_else(|| anyhow!("fact path is absent from the response schema"))?,
            _ => bail!("fact path traverses a non-object response schema"),
        };
    }
    Ok(schema)
}

fn generated_notary_claim_rule(
    claim_id: &str,
    claim: &ClaimDeclaration,
    consultation_name: &str,
    integration: &IntegrationDocument,
    loaded: &LoadedIntegration,
) -> Result<(String, bool, Value)> {
    if let Some(fact_path) = &claim.output {
        let (consultation, fact_name) = fact_path
            .split_once('.')
            .ok_or_else(|| anyhow!("direct claim output path is invalid"))?;
        if consultation != consultation_name {
            bail!("direct claim output path names the wrong consultation");
        }
        let fact = integration
            .outputs
            .get(fact_name)
            .ok_or_else(|| anyhow!("direct claim references an unknown output"))?;
        let (value_type, nullable) = if fact.from.ends_with(".presence") {
            ("boolean", false)
        } else {
            (
                match fact.output_type {
                    FactType::Boolean | FactType::Presence => "boolean",
                    FactType::Integer => "integer",
                    FactType::String => "string",
                    FactType::Date => "date",
                },
                fact.nullable,
            )
        };
        let rule = if fact.from.ends_with(".presence") {
            json!({ "type": "exists", "source": consultation_name })
        } else {
            json!({ "type": "extract", "source": consultation_name, "field": fact_name })
        };
        return Ok((value_type.to_string(), nullable, rule));
    }
    let expression = claim
        .cel
        .as_ref()
        .ok_or_else(|| anyhow!("claim source is absent"))?;
    let (value_type, nullable) = infer_fixture_claim_type(claim_id, loaded)?;
    Ok((
        value_type,
        nullable,
        json!({ "type": "cel", "expression": expression, "bindings": {} }),
    ))
}

fn infer_fixture_claim_type(
    claim_id: &str,
    integration: &LoadedIntegration,
) -> Result<(String, bool)> {
    let mut value_type = None;
    let mut nullable = false;
    for (_, fixture) in &integration.fixtures {
        let Some(value) = fixture.expect.claims.get(claim_id) else {
            continue;
        };
        if value.is_null() {
            nullable = true;
            continue;
        }
        let candidate = if value.is_boolean() {
            "boolean"
        } else if value.as_i64().is_some() {
            "integer"
        } else if value
            .as_str()
            .is_some_and(|value| validate_full_date(value).is_ok())
        {
            "date"
        } else if value.is_string() {
            "string"
        } else {
            bail!("CEL fixture claim must be a scalar v1 value");
        };
        match value_type {
            Some(previous) if previous != candidate => {
                bail!("CEL fixture claim has inconsistent result types")
            }
            None => value_type = Some(candidate),
            Some(_) => {}
        }
    }
    Ok((
        value_type
            .ok_or_else(|| anyhow!("CEL claim lacks a typed fixture result"))?
            .to_string(),
        nullable,
    ))
}

fn claim_consultation_name<'a>(
    service: &'a ServiceDeclaration,
    claim: &'a ClaimDeclaration,
) -> Result<&'a str> {
    if let Some(fact) = &claim.output {
        let (consultation, _) = fact
            .split_once('.')
            .ok_or_else(|| anyhow!("direct claim output path is invalid"))?;
        if service.consultations.contains_key(consultation) {
            return Ok(consultation);
        }
    }
    let roots = claim
        .cel
        .as_deref()
        .map(cel_member_roots)
        .transpose()?
        .unwrap_or_default();
    let referenced = service
        .consultations
        .keys()
        .filter(|name| roots.contains(name.as_str()))
        .map(String::as_str)
        .collect::<Vec<_>>();
    match referenced.as_slice() {
        [name] => Ok(name),
        [] if service.consultations.len() == 1 => Ok(service
            .consultations
            .first_key_value()
            .expect("one consultation was checked")
            .0),
        _ => bail!("v1 claim must depend on exactly one consultation"),
    }
}

fn cel_member_roots(expression: &str) -> Result<BTreeSet<String>> {
    let bytes = expression.as_bytes();
    let mut roots = BTreeSet::new();
    let mut index = 0;
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'"') {
            let quote = bytes[index];
            index += 1;
            let mut escaped = false;
            let mut closed = false;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == quote {
                    closed = true;
                    break;
                }
            }
            if !closed {
                bail!("CEL expression contains an unterminated string literal");
            }
            continue;
        }
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            if bytes.get(index) == Some(&b'.') {
                roots.insert(expression[start..index].to_string());
            }
            continue;
        }
        index += 1;
    }
    Ok(roots)
}

fn expanded_disclosure(disclosure: &DisclosureDeclaration) -> (&str, Vec<&str>) {
    match disclosure {
        DisclosureDeclaration::Mode(DisclosureMode::Value) => ("value", vec!["value", "redacted"]),
        DisclosureDeclaration::Mode(DisclosureMode::Predicate) => {
            ("predicate", vec!["predicate", "redacted"])
        }
        DisclosureDeclaration::Mode(DisclosureMode::Redacted) => ("redacted", vec!["redacted"]),
        DisclosureDeclaration::Policy { default, allowed } => (
            match default {
                DisclosureMode::Value => "value",
                DisclosureMode::Predicate => "predicate",
                DisclosureMode::Redacted => "redacted",
            },
            allowed
                .iter()
                .map(|mode| match mode {
                    DisclosureMode::Value => "value",
                    DisclosureMode::Predicate => "predicate",
                    DisclosureMode::Redacted => "redacted",
                })
                .collect(),
        ),
    }
}

fn disclosure_review_profiles(project: &RegistryProject) -> DisclosureReviewProfiles {
    project
        .services
        .iter()
        .filter(|(_, service)| service.kind == ServiceKind::Evidence)
        .map(|(service_id, service)| {
            let claims = service
                .claims
                .iter()
                .map(|(claim_id, claim)| {
                    let (default, allowed) = expanded_disclosure(&claim.disclosure);
                    let default = match default {
                        "value" => DisclosureMode::Value,
                        "predicate" => DisclosureMode::Predicate,
                        "redacted" => DisclosureMode::Redacted,
                        _ => unreachable!("expanded disclosure uses a closed mode set"),
                    };
                    let allowed = allowed
                        .into_iter()
                        .map(|mode| match mode {
                            "value" => DisclosureMode::Value,
                            "predicate" => DisclosureMode::Predicate,
                            "redacted" => DisclosureMode::Redacted,
                            _ => unreachable!("expanded disclosure uses a closed mode set"),
                        })
                        .collect();
                    (
                        claim_id.clone(),
                        DisclosureReviewProfile { default, allowed },
                    )
                })
                .collect();
            (service_id.clone(), claims)
        })
        .collect()
}

fn disclosure_rank(mode: DisclosureMode) -> u8 {
    match mode {
        DisclosureMode::Redacted => 0,
        DisclosureMode::Predicate => 1,
        DisclosureMode::Value => 2,
    }
}

fn disclosure_change_classes(
    current: &DisclosureReviewProfiles,
    baseline: Option<&Value>,
) -> (bool, bool) {
    let Some(baseline) = baseline.and_then(|review| review.get("disclosure_profiles")) else {
        return (true, true);
    };
    let Ok(previous) = serde_json::from_value::<DisclosureReviewProfiles>(baseline.clone()) else {
        return (true, true);
    };
    let mut narrowing = false;
    let mut widening = false;
    let service_ids = current
        .keys()
        .chain(previous.keys())
        .collect::<BTreeSet<_>>();
    for service_id in service_ids {
        let current_claims = current.get(service_id);
        let previous_claims = previous.get(service_id);
        let claim_ids = current_claims
            .into_iter()
            .flat_map(BTreeMap::keys)
            .chain(previous_claims.into_iter().flat_map(BTreeMap::keys))
            .collect::<BTreeSet<_>>();
        for claim_id in claim_ids {
            match (
                current_claims.and_then(|claims| claims.get(claim_id)),
                previous_claims.and_then(|claims| claims.get(claim_id)),
            ) {
                (Some(current), Some(previous)) => {
                    let current_no_wider = disclosure_profile_no_wider(current, previous);
                    let previous_no_wider = disclosure_profile_no_wider(previous, current);
                    narrowing |= current_no_wider && !previous_no_wider;
                    widening |= previous_no_wider && !current_no_wider;
                    if !current_no_wider && !previous_no_wider {
                        narrowing = true;
                        widening = true;
                    }
                }
                (Some(current), None) => {
                    if current.default == DisclosureMode::Redacted
                        && current.allowed == BTreeSet::from([DisclosureMode::Redacted])
                    {
                        narrowing = true;
                    } else {
                        widening = true;
                    }
                }
                (None, Some(_)) => narrowing = true,
                (None, None) => unreachable!("claim id came from one disclosure map"),
            }
        }
    }
    (narrowing, widening)
}

fn disclosure_profile_no_wider(
    candidate: &DisclosureReviewProfile,
    reference: &DisclosureReviewProfile,
) -> bool {
    disclosure_rank(candidate.default) <= disclosure_rank(reference.default)
        && candidate.allowed.iter().all(|candidate_mode| {
            reference.allowed.iter().any(|reference_mode| {
                disclosure_rank(*candidate_mode) <= disclosure_rank(*reference_mode)
            })
        })
}

fn normalize_credential_format(format: &str) -> String {
    match format {
        "dc+sd-jwt" => "application/dc+sd-jwt".to_string(),
        value => value.to_string(),
    }
}

fn parse_validity_seconds(value: &str) -> Result<u64> {
    let (number, multiplier) = if let Some(value) = value.strip_suffix('s') {
        (value, 1)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60)
    } else if let Some(value) = value.strip_suffix('h') {
        (value, 3600)
    } else {
        bail!("credential validity must use s, m, or h")
    };
    number
        .parse::<u64>()?
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("credential validity overflows"))
}

fn generated_explanation(
    loaded: &LoadedRegistryProject,
    environment_name: &str,
    packs: &BTreeMap<String, GeneratedPack>,
    profiles: &[GeneratedProfile],
) -> Value {
    json!({
        "schema": "registry.project.explanation.v1",
        "registry": loaded.project.registry.id,
        "environment": environment_name,
        "integrations": loaded.integrations.iter().map(|(alias, integration)| {
            (alias.clone(), json!({
                "source_product": integration.document.source.product,
                "source_versions": integration.document.source.versions,
                "input": integration.document.input,
                "capability": match integration.document.capability {
                    CapabilityDeclaration::Http { .. } => "http",
                    CapabilityDeclaration::Snapshot { .. } => "snapshot",
                    CapabilityDeclaration::Script { .. } => "script",
                },
                "operations": integration_operations(&integration.document).iter().map(|(id, operation)| {
                    json!({
                        "id": id,
                        "role": match operation.role {
                            OperationRole::Data => "data",
                            OperationRole::Credential => "credential",
                            OperationRole::Verification => "verification",
                        },
                        "method": match operation.request.method { ReadMethod::Get => "GET", ReadMethod::Post => "READ_ONLY_POST" },
                        "primitive": operation.primitive,
                        "depends_on": operation.depends_on,
                        "when": operation.when,
                        "destination": operation.request.destination,
                        "path": operation.request.path,
                        "path_parameters": operation.request.path_parameters,
                        "query": operation.request.query,
                        "headers": operation.request.headers,
                        "body": operation.request.body,
                        "request_codec": operation.request.codec,
                        "authorization": operation.request.authorization,
                        "response_bytes": operation.response.max_bytes,
                        "response_codec": operation.response.codec,
                        "response_statuses": operation.response.statuses,
                        "response_schema": operation.response.schema,
                        "cardinality": operation.response.cardinality,
                    })
                }).collect::<Vec<_>>(),
                "outputs": integration.document.outputs,
                "bounds": integration.document.bounds,
                "generated_pack": packs.get(alias).map(|pack| json!({
                    "id": pack.id,
                    "version": pack.version,
                    "hash": pack.artifact.typed_hash(),
                })),
            }))
        }).collect::<Map<String, Value>>(),
        "services": loaded.project.services.iter().map(|(id, service)| {
            (id.clone(), json!({
                "kind": service.kind,
                "definition": service.definition,
                "entity": service.entity,
                "purpose": service.purpose,
                "legal_basis": service.legal_basis,
                "consent": service.consent,
                "required_scopes": service.access.scopes,
                "variables": service.variables,
                "consultations": service.consultations,
                "claims": service.claims.iter().map(|(claim, declaration)| (claim, json!({
                    "output": declaration.output,
                    "cel": declaration.cel,
                    "disclosure": declaration.disclosure,
                }))).collect::<BTreeMap<_, _>>(),
                "credentials": service.credentials,
                "profiles": profiles.iter().filter(|profile| profile.service_id == *id).map(|profile| json!({
                    "consultation": profile.consultation_name,
                    "integration": profile.integration_alias,
                    "id": profile.id,
                    "version": profile.version,
                    "contract_hash": profile.contract.artifact().typed_hash(),
                    "policy_hash": profile.contract.policy_hash(),
                })).collect::<Vec<_>>(),
            }))
        }).collect::<Map<String, Value>>(),
        "environment_binding": loaded.environment.as_ref().map(|environment| json!({
            "deployment_profile": environment.deployment.profile,
            "integrations": environment.integrations.iter().map(|(alias, binding)| (alias.clone(), json!({
                "source_version": binding.source_version,
                "data_origin": binding.data_destination.as_ref().map(|destination| &destination.origin),
                "credential_origin": binding.credential_destination.as_ref().map(|destination| &destination.origin),
                "credential_interface": binding.credential.as_ref().map(|credential| credential.credential_type),
                "snapshot_entity": match &loaded.integrations[alias].document.capability {
                    CapabilityDeclaration::Snapshot { snapshot } => Some(snapshot.entity.as_str()),
                    CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. } => None,
                },
                "rhai_enabled": binding.advanced_capabilities.as_ref().is_some_and(|advanced| advanced.script.enabled),
            }))).collect::<Map<String, Value>>(),
            "entities": environment.entities.iter().map(|(id, binding)| (id.clone(), json!({
                "source_revision": binding.source_revision,
                "generation": binding.generation,
                "materialization_identity": loaded.records.get(id).and_then(|records| records_materialization_resource_id(&records.document, binding).ok()),
            }))).collect::<Map<String, Value>>(),
            "callers": environment.callers.iter().map(|(caller, binding)| (caller.clone(), json!({
                "scopes": binding.scopes,
            }))).collect::<Map<String, Value>>(),
            "relay_workload": {
                "client_id": environment.relay.as_ref().map(|relay| relay.workload_client_id.as_str()),
                "audience": environment.relay.as_ref().map(|relay| relay.audience.as_str()),
            },
        })),
    })
}

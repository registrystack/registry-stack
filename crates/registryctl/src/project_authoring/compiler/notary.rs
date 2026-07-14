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
        let notary_consultation_aliases = generated_notary_consultation_aliases(
            service.consultations.keys().map(String::as_str),
        );
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
        for (credential_id, credential) in &service.credential_profiles {
            let issuance = environment
                .issuance
                .as_ref()
                .ok_or_else(|| anyhow!("Notary issuance binding is absent"))?;
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
                .credential_profiles
                .iter()
                .filter(|(_, credential)| credential.claims.iter().any(|id| id == claim_id))
                .map(|(credential, _)| bounded_join_id(&[service_id, credential]))
                .collect::<Result<Vec<_>>>()?;
            let mut formats = vec!["application/vnd.registry-notary.claim-result+json".to_string()];
            formats.extend(
                service
                    .credential_profiles
                    .values()
                    .filter(|credential| credential.claims.iter().any(|id| id == claim_id))
                    .map(|credential| normalize_credential_format(&credential.format)),
            );
            formats.sort();
            formats.dedup();
            let (default_disclosure, allowed_disclosures) = expanded_disclosure(&claim.disclosure);
            let (evidence_mode, value_type, nullable, rule) =
                match inferred_claim_evidence(service, claim)? {
                    ClaimEvidence::RegistryBacked => {
                        let consultation_name = claim_consultation_name(service, claim)?;
                        let notary_consultation_name = notary_consultation_aliases
                            .get(consultation_name)
                            .ok_or_else(|| anyhow!("generated Notary consultation alias is absent"))?;
                        let consultation = &service.consultations[consultation_name];
                        let integration = &loaded.integrations[&consultation.integration];
                        let profile = profiles
                            .iter()
                            .find(|profile| {
                                profile.service_id == *service_id
                                    && profile.consultation_name == consultation_name
                            })
                            .ok_or_else(|| anyhow!("claim consultation profile is absent"))?;
                        let outputs = generated_notary_output_contracts(&integration.document)?;
                        let (value_type, nullable, rule) = generated_notary_claim_rule(
                            claim_id,
                            claim,
                            consultation_name,
                            notary_consultation_name,
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
                                "contract_hash": profile.contract.artifact().typed_hash(),
                            },
                            "inputs": inputs,
                            "outputs": outputs,
                        });
                        let consultations = Map::from_iter([(
                            notary_consultation_name.clone(),
                            consultation_config,
                        )]);
                        (
                            json!({ "type": "registry_backed", "consultations": consultations }),
                            value_type,
                            nullable,
                            rule,
                        )
                    }
                    ClaimEvidence::SelfAttested => {
                        let value = claim.value.as_ref().ok_or_else(|| {
                            anyhow!("self-attested claim value contract is absent")
                        })?;
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
        "credential_profiles": credential_profiles,
    });
    if let Some(issuance) = &environment.issuance {
        evidence["signing_keys"] = json!({
            "project-issuer": {
                "provider": "local_jwk_env",
                "private_jwk_env": issuance.signing_key.secret,
                "alg": "EdDSA",
                "kid": issuance.signing_kid,
                "status": "active",
            },
        });
    }
    if let (Some(relay), Some(connection)) = (&environment.relay, &environment.notary_relay) {
        evidence["relay"] = json!({
            "base_url": relay.origin,
            "workload_client_id": connection.workload_client_id,
            "token_file": connection.token_file,
            "allowed_private_cidrs": [],
            "max_in_flight": 8,
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

fn generated_notary_output_contracts(integration: &IntegrationDocument) -> Result<Value> {
    let outputs = integration
        .outputs
        .iter()
        .map(|(name, output)| {
            let contract = match output.output_type {
                FactType::Boolean => {
                    json!({ "type": "boolean", "nullable": output.nullable })
                }
                FactType::Integer => {
                    if let (Some(minimum), Some(maximum)) = (output.minimum, output.maximum) {
                        json!({
                            "type": "integer",
                            "nullable": output.nullable,
                            "minimum": minimum,
                            "maximum": maximum,
                        })
                    } else {
                        let schema = output_source_schema(integration, output)?;
                        let SchemaNode::Integer { min, max } = schema else {
                            bail!("integer output must resolve to an integer response field");
                        };
                        json!({ "type": "integer", "nullable": output.nullable, "minimum": min, "maximum": max })
                    }
                }
                FactType::String => json!({
                    "type": "string",
                    "nullable": output.nullable,
                    "max_bytes": output.max_bytes.ok_or_else(|| anyhow!("string output bound is absent"))?,
                }),
                FactType::Date => {
                    json!({ "type": "date", "nullable": output.nullable })
                }
                FactType::Presence => bail!("presence is an outcome, not a declared output"),
            };
            Ok((name.clone(), contract))
        })
        .collect::<Result<Map<String, Value>>>()?;
    Ok(Value::Object(outputs))
}

fn output_source_schema<'a>(
    integration: &'a IntegrationDocument,
    fact: &OutputDeclaration,
) -> Result<&'a SchemaNode> {
    let (operation, _) = fact
        .from
        .as_deref()
        .ok_or_else(|| anyhow!("output path is absent"))?
        .split_once('.')
        .ok_or_else(|| anyhow!("output path is invalid"))?;
    let operation = integration_operations(integration)
        .get(operation)
        .ok_or_else(|| anyhow!("output operation is absent"))?;
    let mut schema = operation_record_schema(operation)?;
    let pointer = fact
        .source_pointer
        .as_deref()
        .ok_or_else(|| anyhow!("HTTP output pointer is absent"))?;
    for segment in output_pointer_segments(pointer)? {
        schema = match schema {
            SchemaNode::Object { fields, .. } => fields
                .get(&segment)
                .map(|field| &field.schema)
                .ok_or_else(|| anyhow!("output path is absent from the response schema"))?,
            _ => bail!("output path traverses a non-object response schema"),
        };
    }
    Ok(schema)
}

fn output_pointer_segments(pointer: &str) -> Result<Vec<String>> {
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

fn generated_notary_claim_rule(
    claim_id: &str,
    claim: &ClaimDeclaration,
    consultation_name: &str,
    notary_consultation_name: &str,
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
        let value_type = match fact.output_type {
            FactType::Boolean => "boolean",
            FactType::Integer => "integer",
            FactType::String => "string",
            FactType::Date => "date",
            FactType::Presence => bail!("presence cannot be referenced as an output"),
        };
        let nullable = true;
        let rule = json!({
            "type": "consultation_output",
            "consultation": notary_consultation_name,
            "output": fact_name
        });
        return Ok((value_type.to_string(), nullable, rule));
    }
    let expression = claim
        .cel
        .as_ref()
        .ok_or_else(|| anyhow!("claim source is absent"))?;
    let expression = rewrite_notary_consultation_root(
        expression,
        consultation_name,
        notary_consultation_name,
        integration.outputs.keys().map(String::as_str),
    );
    let (value_type, nullable) = infer_fixture_claim_type(claim_id, loaded)?;
    Ok((
        value_type,
        nullable,
        json!({ "type": "cel", "expression": expression, "bindings": {} }),
    ))
}

// Crosswalk lowers these namespace-qualified helper calls before evaluating
// CEL. Authored consultation names remain product-neutral, so collisions are
// lowered only inside the generated Notary contract rather than rejected.
const CROSSWALK_CEL_HELPER_NAMESPACES: &[&str] = &[
    "address", "code", "date", "email", "geo", "id", "json", "list", "map", "name",
    "num", "person", "phone", "privacy", "text", "type", "validate",
];

fn generated_notary_consultation_aliases<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> BTreeMap<String, String> {
    let names = names.into_iter().collect::<BTreeSet<_>>();
    let mut aliases = BTreeMap::new();
    let mut used = BTreeSet::new();
    for name in &names {
        let base = if CROSSWALK_CEL_HELPER_NAMESPACES.contains(name) {
            format!("relay_{name}")
        } else {
            (*name).to_string()
        };
        let mut alias = base.clone();
        let mut suffix = 2_u8;
        while used.contains(alias.as_str())
            || (alias.as_str() != *name && names.contains(alias.as_str()))
        {
            alias = format!("{base}_{suffix}");
            suffix = suffix.saturating_add(1);
        }
        used.insert(alias.clone());
        aliases.insert((*name).to_string(), alias);
    }
    aliases
}

fn rewrite_notary_consultation_root<'a>(
    expression: &str,
    authored_name: &str,
    notary_name: &str,
    output_names: impl IntoIterator<Item = &'a str>,
) -> String {
    if authored_name == notary_name {
        return expression.to_string();
    }
    // Only typed consultation members move to the internal alias. This keeps
    // real helper calls such as date.age_on(...) intact when an author also
    // chose a helper namespace as the consultation name.
    let mut members = output_names.into_iter().collect::<BTreeSet<_>>();
    members.extend(["matched", "outcome"]);
    let bytes = expression.as_bytes();
    let mut rewritten = Vec::with_capacity(expression.len() + notary_name.len());
    let mut index = 0;
    let mut quote = None;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(active_quote) = quote {
            rewritten.push(byte);
            index += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active_quote {
                quote = None;
            }
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
            rewritten.push(byte);
            index += 1;
            continue;
        }
        if !is_cel_identifier_start_byte(byte) {
            rewritten.push(byte);
            index += 1;
            continue;
        }

        let start = index;
        index += 1;
        while index < bytes.len() && is_cel_identifier_continue_byte(bytes[index]) {
            index += 1;
        }
        let token = &expression[start..index];
        let previous = bytes[..start]
            .iter()
            .rfind(|byte| !byte.is_ascii_whitespace())
            .copied();
        let mut dot = index;
        while dot < bytes.len() && bytes[dot].is_ascii_whitespace() {
            dot += 1;
        }
        let mut member_start = dot.saturating_add(1);
        while member_start < bytes.len() && bytes[member_start].is_ascii_whitespace() {
            member_start += 1;
        }
        let mut member_end = member_start;
        if bytes.get(dot) == Some(&b'.')
            && bytes
                .get(member_start)
                .is_some_and(|byte| is_cel_identifier_start_byte(*byte))
        {
            member_end += 1;
            while member_end < bytes.len()
                && is_cel_identifier_continue_byte(bytes[member_end])
            {
                member_end += 1;
            }
        }
        let member = expression.get(member_start..member_end);
        if token == authored_name
            && previous != Some(b'.')
            && member.is_some_and(|member| members.contains(member))
        {
            rewritten.extend_from_slice(notary_name.as_bytes());
        } else {
            rewritten.extend_from_slice(token.as_bytes());
        }
    }
    String::from_utf8(rewritten).expect("CEL root rewriting preserves UTF-8")
}

fn is_cel_identifier_start_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_cel_identifier_continue_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
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

#[cfg(test)]
fn disclosure_rank(mode: DisclosureMode) -> u8 {
    match mode {
        DisclosureMode::Redacted => 0,
        DisclosureMode::Predicate => 1,
        DisclosureMode::Value => 2,
    }
}

#[cfg(test)]
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

#[cfg(test)]
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
    profiles: &[GeneratedProfile],
) -> Value {
    json!({
        "schema": "registry.project.explanation.v1",
        "registry": loaded.project.registry.id,
        "environment": environment_name,
        "starter": starter_explanation(loaded),
        "platform": {
            "defaults_release": env!("CARGO_PKG_VERSION"),
            "script_runtime": "rhai_v1",
            "script_abi": registry_relay::rhai_worker::xw::XW_ABI_VERSION,
        },
        "integrations": loaded.integrations.iter().map(|(alias, integration)| {
            (alias.clone(), json!({
                "authoring_version": integration.document.version,
                "revision": integration.document.revision,
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
            }))
        }).collect::<Map<String, Value>>(),
        "services": loaded.project.services.iter().map(|(id, service)| {
            (id.clone(), json!({
                "kind": service.kind,
                "entity": service.entity,
                "api": service.api,
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
                "credential_profiles": service.credential_profiles,
                "profiles": profiles.iter().filter(|profile| profile.service_id == *id).map(|profile| json!({
                    "consultation": profile.consultation_name,
                    "integration": profile.integration_alias,
                    "contract_hash": profile.contract.artifact().typed_hash(),
                })).collect::<Vec<_>>(),
            }))
        }).collect::<Map<String, Value>>(),
        "environment_binding": loaded.environment.as_ref().map(|environment| json!({
            "deployment_profile": environment.deployment.profile,
            "integrations": environment.integrations.iter().map(|(alias, binding)| (alias.clone(), json!({
                "source_origin": binding.source.origin,
                "allowed_private_cidrs": binding.source.allowed_private_cidrs,
                "source_auth_type": credential_interface(&loaded.integrations[alias].document).credential_type,
                "credential_generation": binding.source.credential.as_ref().map(|credential| credential.generation),
                "oauth_endpoint": binding.source.oauth.as_ref().map(|endpoint| json!({
                    "origin": endpoint.origin,
                    "path": endpoint.path,
                    "generation": endpoint.generation,
                })),
                "jwks_endpoint": binding.source.jwks.as_ref().map(|endpoint| json!({
                    "origin": endpoint.origin,
                    "path": endpoint.path,
                    "generation": endpoint.generation,
                })),
                "ca_generation": binding.source.ca.as_ref().map(|ca| ca.generation),
                "mtls_generation": binding.source.mtls.as_ref().map(|mtls| mtls.generation),
                "rate": binding.source.rate,
                "concurrency": binding.source.concurrency,
                "timeout": binding.source.timeout,
                "script_runtime": match &loaded.integrations[alias].document.capability {
                    CapabilityDeclaration::Script { script } => Some(script.runtime),
                    CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Snapshot { .. } => None,
                },
            }))).collect::<Map<String, Value>>(),
            "entities": environment.entities.iter().map(|(id, binding)| (id.clone(), json!({
                "source_revision": binding.source_revision,
                "generation": binding.generation,
                "materialization_identity": loaded.entities.get(id).and_then(|entity| entity_materialization_resource_id(&entity.document, binding).ok()),
            }))).collect::<Map<String, Value>>(),
            "callers": environment.callers.iter().map(|(caller, binding)| (caller.clone(), json!({
                "scopes": binding.scopes,
            }))).collect::<Map<String, Value>>(),
            "relay_oidc": {
                "allowed_clients": environment.relay.as_ref().map(|relay| &relay.allowed_clients),
                "audience": environment.relay.as_ref().map(|relay| relay.audience.as_str()),
            },
            "notary_relay_workload": environment.notary_relay.as_ref().map(|connection| json!({
                "client_id": connection.workload_client_id,
            })),
        })),
    })
}

#[cfg(test)]
mod notary_compiler_tests {
    use super::*;

    #[test]
    fn crosswalk_helper_namespaces_receive_unique_internal_aliases() {
        let mut names = CROSSWALK_CEL_HELPER_NAMESPACES.to_vec();
        names.extend(["relay_person", "relay_person_2", "household"]);
        let aliases = generated_notary_consultation_aliases(names.iter().copied());

        assert_eq!(aliases["person"], "relay_person_3");
        assert_eq!(aliases["relay_person"], "relay_person");
        assert_eq!(aliases["relay_person_2"], "relay_person_2");
        assert_eq!(aliases["household"], "household");
        assert!(CROSSWALK_CEL_HELPER_NAMESPACES
            .iter()
            .all(|name| aliases[*name] != *name));
        assert_eq!(
            aliases.values().collect::<BTreeSet<_>>().len(),
            aliases.len()
        );
    }

    #[test]
    fn consultation_root_rewrite_is_token_and_string_literal_aware() {
        let expression = r#"person.matched
            && person . status == "person.status"
            && 'escaped \' person.matched'
            && `person.status`
            && payload.person.status == "active"
            && person.age(person.birth_date, today) > 17"#;
        let rewritten = rewrite_notary_consultation_root(
            expression,
            "person",
            "relay_person",
            ["status", "birth_date"],
        );

        assert_eq!(
            rewritten,
            r#"relay_person.matched
            && relay_person . status == "person.status"
            && 'escaped \' person.matched'
            && `person.status`
            && payload.person.status == "active"
            && person.age(relay_person.birth_date, today) > 17"#
        );
    }

    #[test]
    fn consultation_root_rewrite_leaves_unrelated_identifiers_unchanged() {
        let expression = "person_id == 'person.matched' && other.matched";
        assert_eq!(
            rewrite_notary_consultation_root(
                expression,
                "person",
                "relay_person",
                ["person_id"]
            ),
            expression
        );
        assert_eq!(
            rewrite_notary_consultation_root(
                "household.matched",
                "household",
                "household",
                std::iter::empty()
            ),
            "household.matched"
        );
    }
}

// SPDX-License-Identifier: Apache-2.0

fn generated_relay_config(
    loaded: &LoadedRegistryProject,
    environment_name: &str,
    environment: &EnvironmentDocument,
    packs: &BTreeMap<String, GeneratedPack>,
    profiles: &[GeneratedProfile],
) -> Result<Value> {
    let relay = environment
        .relay
        .as_ref()
        .ok_or_else(|| anyhow!("Relay environment binding is absent"))?;
    let relay_service = environment
        .deployment
        .relay
        .as_ref()
        .ok_or_else(|| anyhow!("Relay deployment binding is absent"))?;
    let public_contracts = profiles
        .iter()
        .map(|profile| {
            json!({
                "path": format!("artifacts/consultation-contracts/{}-{}.json", profile.service_id, profile.consultation_name),
                "hash": profile.contract.artifact().typed_hash(),
                "sha256": profile.contract.artifact().raw_sha256(),
            })
        })
        .collect::<Vec<_>>();
    let integration_packs = packs
        .values()
        .map(|pack| {
            json!({
                "path": format!("artifacts/integration-packs/{}.json", pack.alias),
                "hash": pack.artifact.typed_hash(),
                "sha256": pack.artifact.raw_sha256(),
            })
        })
        .collect::<Vec<_>>();
    let private_bindings = profiles
        .iter()
        .map(|profile| {
            json!({
                "path": format!("artifacts/private-bindings/{}-{}.json", profile.service_id, profile.consultation_name),
                "hash": profile.binding.typed_hash(),
                "sha256": profile.binding.raw_sha256(),
            })
        })
        .collect::<Vec<_>>();
    let evidence = packs
        .values()
        .flat_map(|pack| &pack.evidence)
        .map(|artifact| {
            json!({
                "class": match artifact.class {
                    EvidenceClass::Conformance => "conformance",
                    EvidenceClass::NegativeSecurity => "negative_security",
                    EvidenceClass::Minimization => "minimization",
                },
                "path": artifact.path,
                "sha256": artifact.sha256,
            })
        })
        .collect::<Vec<_>>();
    let rhai_scripts = loaded
        .integrations
        .iter()
        .filter_map(|(alias, integration)| {
            integration.script.as_ref().map(|(_, script)| {
                json!({
                    "path": format!("artifacts/rhai/{alias}.rhai"),
                    "sha256": sha256_uri(script),
                })
            })
        })
        .collect::<Vec<_>>();
    let source_credentials = environment
        .integrations
        .iter()
        .filter(|(_, binding)| binding.credential.is_some())
        .map(|(alias, binding)| {
            let credential = binding
                .credential
                .as_ref()
                .ok_or_else(|| anyhow!("credential binding disappeared"))?;
            let reference = format!("{alias}-credential");
            match credential.credential_type {
                CredentialType::None => bail!("none credential must not have an environment binding"),
                CredentialType::Basic => Ok(json!({
                    "type": "basic",
                    "ref": reference,
                    "generation": credential.generation,
                    "username_env": required_secret_name(credential.username.as_ref(), "basic username")?,
                    "password_env": required_secret_name(credential.password.as_ref(), "basic password")?,
                })),
                CredentialType::StaticBearer => Ok(json!({
                    "type": "static_bearer",
                    "ref": reference,
                    "generation": credential.generation,
                    "token_env": required_secret_name(credential.token.as_ref(), "bearer token")?,
                })),
                CredentialType::Oauth2ClientCredentials => Ok(json!({
                    "type": "oauth_client_credentials",
                    "ref": reference,
                    "generation": credential.generation,
                    "client_id_env": required_secret_name(credential.client_id.as_ref(), "OAuth client id")?,
                    "client_secret_env": required_secret_name(credential.client_secret.as_ref(), "OAuth client secret")?,
                })),
                CredentialType::ApiKeyHeader => Ok(json!({
                    "type": "api_key_header",
                    "ref": reference,
                    "generation": credential.generation,
                    "value_env": required_secret_name(credential.value.as_ref(), "API-key value")?,
                })),
                CredentialType::ApiKeyQuery => Ok(json!({
                    "type": "api_key_query",
                    "ref": reference,
                    "generation": credential.generation,
                    "value_env": required_secret_name(credential.value.as_ref(), "API-key value")?,
                })),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let datasets = generated_records_datasets(loaded, environment)?;
    let standards = generated_records_standards(loaded)?;
    let mut config = json!({
        "instance": {
            "id": relay_service.service,
            "environment": environment_name,
        },
        "server": { "bind": "127.0.0.1:8080" },
        "catalog": {
            "title": format!("{} governed Registry Relay", loaded.project.registry.id),
            "base_url": relay.origin,
            "publisher": loaded.project.registry.id,
        },
        "auth": {
            "mode": "oidc",
            "oidc": {
                "issuer": relay.issuer,
                "audiences": [relay.audience.as_str()],
                "jwks_url": relay.jwks_url,
                "allowed_clients": [relay.workload_client_id.as_str()],
            },
        },
        "audit": {
            "sink": "stdout",
            "hash_secret_env": "REGISTRY_RELAY_AUDIT_HASH_SECRET",
        },
        "datasets": datasets,
        "standards": standards,
        "deployment": { "profile": environment.deployment.profile.as_str() },
    });
    if !profiles.is_empty() && !packs.is_empty() {
        config["consultation"] = json!({
            "authorized_workload": {
                "audience": relay.audience,
                "client_claim_selector": "azp",
                "client_value": relay.workload_client_id,
                "principal_id": relay.workload_client_id,
            },
            "state_plane": {
                "database_url_env": "REGISTRY_RELAY_CONSULTATION_DATABASE_URL",
                "chain_key_epoch_id": "project-consultation-chain-1",
                "serving_fence_lock_key": deterministic_lock_key(&loaded.project.registry.id, 0),
                "audit_pseudonym_keyring_lock_key": deterministic_lock_key(&loaded.project.registry.id, 1),
            },
            "audit_pseudonym_materials": [{
                "key_id": "epoch-1",
                "source": { "provider": "environment", "name": "REGISTRY_RELAY_AUDIT_PSEUDONYM_EPOCH_1" },
            }],
            "source_credentials": source_credentials,
            "artifacts": {
                "public_contracts": public_contracts,
                "integration_packs": integration_packs,
                "private_bindings": private_bindings,
                "evidence": evidence,
                "rhai_scripts": rhai_scripts,
            },
        });
    }
    Ok(config)
}

fn generated_records_datasets(
    loaded: &LoadedRegistryProject,
    environment: &EnvironmentDocument,
) -> Result<Vec<Value>> {
    loaded
        .records
        .values()
        .map(|loaded_records| {
            let records = &loaded_records.document;
            let binding = environment
                .entities
                .get(&records.id)
                .ok_or_else(|| anyhow!("generated records entity binding is absent"))?;
            let resource_id = records_materialization_resource_id(records, binding)?;
            let source = match &binding.provider {
                RecordProvider::Csv {
                    path,
                    header_row,
                    delimiter,
                    quote,
                } => json!({
                    "type": "file",
                    "path": path,
                    "format": { "csv": {
                        "header_row": header_row,
                        "delimiter": delimiter,
                        "quote": quote,
                    }},
                }),
                RecordProvider::Xlsx {
                    path,
                    sheet,
                    header_row,
                    data_range,
                } => json!({
                    "type": "file",
                    "path": path,
                    "format": { "xlsx": {
                        "sheet": sheet,
                        "header_row": header_row,
                        "data_range": data_range,
                    }},
                }),
                RecordProvider::Parquet { path } => json!({
                    "type": "file",
                    "path": path,
                    "format": { "parquet": {} },
                }),
            };
            let fields = records
                .fields
                .iter()
                .map(|(logical, field)| {
                    json!({
                        "name": binding.columns[logical],
                        "type": field.field_type,
                        "nullable": field.nullable,
                        "sensitive": field.sensitive,
                        "concept_uri": field.concept_uri,
                        "codelist": field.codelist,
                        "unit": field.unit,
                        "language": field.language,
                    })
                })
                .collect::<Vec<_>>();
            let public_fields = records
                .fields
                .iter()
                .map(|(logical, field)| {
                    json!({
                        "name": logical,
                        "from": binding.columns[logical],
                        "sensitive": field.sensitive,
                        "concept_uri": field.concept_uri,
                        "codelist": field.codelist,
                        "unit": field.unit,
                        "language": field.language,
                    })
                })
                .collect::<Vec<_>>();
            let allowed_filters = records
                .api
                .filters
                .iter()
                .map(|(field, ops)| json!({ "field": field, "ops": ops }))
                .collect::<Vec<_>>();
            let required_filter_bindings = records
                .api
                .required_principal_filters
                .iter()
                .map(|field| json!({ "field": field, "source": "principal_id" }))
                .collect::<Vec<_>>();
            let relationships = records
                .api
                .relationships
                .iter()
                .map(|(name, relationship)| {
                    json!({
                        "name": name,
                        "kind": relationship.kind,
                        "target": relationship.target,
                        "foreign_key": binding.columns[&relationship.foreign_key],
                        "concept_uri": relationship.concept_uri,
                    })
                })
                .collect::<Vec<_>>();
            let aggregates = records
                .api
                .aggregates
                .iter()
                .map(|(id, aggregate)| {
                    let allowed_filters = aggregate
                        .allowed_filters
                        .iter()
                        .map(|(field, ops)| json!({ "field": field, "ops": ops }))
                        .collect::<Vec<_>>();
                    let required_filter_bindings = aggregate
                        .required_principal_filters
                        .iter()
                        .map(|field| json!({ "field": field, "source": "principal_id" }))
                        .collect::<Vec<_>>();
                    json!({
                        "id": id,
                        "title": aggregate.title,
                        "description": aggregate.description,
                        "source_entity": records.id,
                        "default_group_by": aggregate.default_group_by,
                        "dimensions": aggregate.dimensions,
                        "indicators": aggregate.indicators,
                        "allowed_filters": allowed_filters,
                        "required_filters": aggregate.required_principal_filters,
                        "required_filter_bindings": required_filter_bindings,
                        "temporal_field": aggregate.temporal_field,
                        "access": aggregate.access,
                        "spatial": aggregate.spatial,
                        "joins": aggregate.joins.iter().map(|relationship| json!({ "relationship": relationship })).collect::<Vec<_>>(),
                        "group_by": aggregate.group_by,
                        "measures": aggregate.measures,
                        "disclosure_control": {
                            "min_group_size": aggregate.disclosure_control.min_group_size,
                            "suppression": aggregate.disclosure_control.suppression,
                        },
                    })
                })
                .collect::<Vec<_>>();
            let aggregate_scope = records
                .api
                .scopes
                .aggregate
                .clone()
                .unwrap_or_else(|| format!("{}:aggregate", records.id));
            let governed_policy = (!records.api.purposes.is_empty()).then(|| {
                json!({
                    "permitted_purposes": records.api.purposes,
                    "permitted_jurisdictions": [],
                    "allowed_assurance": [],
                    "require_legal_basis": false,
                    "require_consent": false,
                    "redaction_fields": [],
                    "trusted_context": {},
                })
            });
            let spatial = match &records.api.standards.ogc_features {
                RecordStandard::Enabled(spatial) => Some(serde_json::to_value(spatial)?),
                RecordStandard::Disabled(_) => None,
            };
            Ok(json!({
                "id": records.id,
                "title": records.title.clone().unwrap_or_else(|| records.id.clone()),
                "description": records.description.clone().unwrap_or_else(|| format!("Governed {} records", records.id)),
                "owner": records.owner.clone().unwrap_or_else(|| loaded.project.registry.id.clone()),
                "sensitivity": records.sensitivity.unwrap_or(RecordSensitivity::Personal),
                "access_rights": records.access_rights.unwrap_or(RecordAccessRights::Restricted),
                "update_frequency": records.update_frequency.unwrap_or(RecordUpdateFrequency::AsNeeded),
                "conforms_to": records.conforms_to,
                "defaults": { "refresh": { "mode": "manual" }, "materialization": "snapshot" },
                "tables": [{
                    "id": resource_id,
                    "source": source,
                    "refresh": { "mode": "manual" },
                    "materialization": "snapshot",
                    "primary_key": binding.columns[&records.primary_key],
                    "schema": { "strict": true, "fields": fields },
                    "access": {
                        "metadata_scope": records.api.scopes.metadata,
                        "aggregate_scope": aggregate_scope,
                    },
                    "api": {
                        "default_limit": records.api.pagination.default_limit,
                        "max_limit": records.api.pagination.max_limit,
                        "require_purpose_header": !records.api.purposes.is_empty(),
                        "allowed_filters": [],
                    },
                    "aggregates": [],
                }],
                "entities": [{
                    "name": records.id,
                    "title": records.title,
                    "description": records.description,
                    "table": resource_id,
                    "fields": public_fields,
                    "relationships": relationships,
                    "access": {
                        "metadata_scope": records.api.scopes.metadata,
                        "aggregate_scope": aggregate_scope,
                        "read_scope": records.api.scopes.rows,
                        "evidence_verification_scope": records.api.scopes.evidence_verification.clone().unwrap_or_default(),
                    },
                    "api": {
                        "default_limit": records.api.pagination.default_limit,
                        "max_limit": records.api.pagination.max_limit,
                        "require_purpose_header": !records.api.purposes.is_empty(),
                        "governed_policy": governed_policy,
                        "required_filters": records.api.required_principal_filters,
                        "required_filter_bindings": required_filter_bindings,
                        "allowed_filters": allowed_filters,
                        "allowed_expansions": records.api.relationships.keys().collect::<Vec<_>>(),
                    },
                    "aggregates": aggregates,
                    "spatial": spatial,
                }],
                "aggregates": [],
            }))
        })
        .collect()
}

fn generated_records_standards(loaded: &LoadedRegistryProject) -> Result<Value> {
    let mut registries = Map::new();
    for records in loaded.records.values().map(|loaded| &loaded.document) {
        let RecordStandard::Enabled(spdci) = &records.api.standards.sp_dci else {
            continue;
        };
        if registries
            .insert(
                spdci.registry.clone(),
                json!({
                    "dataset": records.id,
                    "entity": records.id,
                    "registry_type": spdci.registry_type,
                    "record_type": spdci.record_type,
                    "identifiers": spdci.identifiers,
                    "expression_fields": spdci.expression_fields,
                    "response_fields": spdci.response_fields,
                }),
            )
            .is_some()
        {
            bail!("SP DCI registry ids must be unique across records definitions");
        }
    }
    Ok(if registries.is_empty() {
        json!({})
    } else {
        json!({ "spdci": { "registries": registries } })
    })
}

fn required_secret_name<'a>(
    reference: Option<&'a SecretReference>,
    label: &str,
) -> Result<&'a str> {
    reference
        .map(|reference| reference.secret.as_str())
        .ok_or_else(|| anyhow!("environment is missing the required {label} secret reference"))
}

fn deterministic_lock_key(registry: &str, lane: u8) -> i64 {
    let digest = Sha256::digest([registry.as_bytes(), &[lane]].concat());
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(bytes) & i64::MAX
}

fn records_materialization_resource_id(
    records: &RecordsDefinition,
    binding: &EnvironmentEntityBinding,
) -> Result<String> {
    let digest = digest_json(&json!({
        "entity_definition": records,
        "provider": binding.provider,
        "columns": binding.columns,
        "source_revision": binding.source_revision,
        "generation": binding.generation,
    }))?;
    let hexadecimal = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("materialization identity digest is invalid"))?;
    Ok(format!("materialization_{hexadecimal}"))
}

fn records_table_provider(
    records: &RecordsDefinition,
    binding: &EnvironmentEntityBinding,
) -> Result<String> {
    Ok(format!(
        "{}__{}",
        records.id,
        records_materialization_resource_id(records, binding)?
    ))
}

fn generated_entity_materialization_review(
    loaded: &LoadedRegistryProject,
    environment: &EnvironmentDocument,
) -> Result<Map<String, Value>> {
    loaded
        .records
        .iter()
        .map(|(id, loaded_records)| {
            let binding = &environment.entities[id];
            let provider_digest = digest_json(&json!({
                "provider": binding.provider,
                "columns": binding.columns,
            }))?;
            Ok((
                id.clone(),
                json!({
                    "provider_digest": provider_digest,
                    "source_revision": binding.source_revision,
                    "generation": binding.generation,
                    "materialization_identity": records_materialization_resource_id(&loaded_records.document, binding)?,
                    "table_provider": records_table_provider(&loaded_records.document, binding)?,
                }),
            ))
        })
        .collect()
}

fn validate_entity_generation_changes(
    loaded: &LoadedRegistryProject,
    environment: &EnvironmentDocument,
    baseline: Option<&VerifiedBaseline>,
) -> Result<()> {
    let Some(previous) = baseline
        .and_then(|baseline| baseline.review.get("entity_materializations"))
        .and_then(Value::as_object)
    else {
        return Ok(());
    };
    let current = generated_entity_materialization_review(loaded, environment)?;
    for (id, materialization) in &current {
        let Some(prior) = previous.get(id) else {
            continue;
        };
        if prior.get("provider_digest") != materialization.get("provider_digest")
            && prior.get("generation") == materialization.get("generation")
        {
            bail!("records provider or physical mapping changed without a new generation");
        }
    }
    Ok(())
}

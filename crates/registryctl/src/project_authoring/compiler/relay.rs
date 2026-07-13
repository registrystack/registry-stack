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
    let mut evidence_by_hash = BTreeMap::new();
    for artifact in packs.values().flat_map(|pack| &pack.evidence) {
        evidence_by_hash
            .entry(artifact.sha256.clone())
            .or_insert_with(|| {
                json!({
                "class": match artifact.class {
                    EvidenceClass::Conformance => "conformance",
                    EvidenceClass::NegativeSecurity => "negative_security",
                    EvidenceClass::Minimization => "minimization",
                },
                "path": artifact.path,
                "sha256": artifact.sha256,
            })
            });
    }
    let evidence = evidence_by_hash.into_values().collect::<Vec<_>>();
    let mut rhai_scripts_by_hash = BTreeMap::new();
    for (alias, integration) in &loaded.integrations {
        if integration.script.is_some() {
            let script = compiled_rhai_source(integration)?;
            let hash = sha256_uri(&script);
            rhai_scripts_by_hash.entry(hash.clone()).or_insert(json!({
                "path": canonical_rhai_script_path(loaded, alias)?,
                "sha256": hash,
            }));
        }
    }
    let rhai_scripts = rhai_scripts_by_hash.into_values().collect::<Vec<_>>();
    let mut source_credentials = Vec::new();
    let mut emitted_credential_references = BTreeSet::new();
    for (alias, binding) in &environment.integrations {
        if binding.source.credential.is_some() {
            let credential = binding
                .source
                .credential
                .as_ref()
                .ok_or_else(|| anyhow!("credential binding disappeared"))?;
            let interface = credential_interface(&loaded.integrations[alias].document);
            let reference = source_credential_reference(loaded, environment, alias)?
                .ok_or_else(|| anyhow!("credential reference disappeared"))?;
            if !emitted_credential_references.insert(reference.clone()) {
                continue;
            }
            let entry = match interface.credential_type {
                CredentialType::None => bail!("none credential must not have an environment binding"),
                CredentialType::Basic => json!({
                    "type": "basic",
                    "ref": reference,
                    "generation": credential.generation,
                    "username_env": required_secret_name(credential.username.as_ref(), "basic username")?,
                    "password_env": required_secret_name(credential.password.as_ref(), "basic password")?,
                }),
                CredentialType::StaticBearer => json!({
                    "type": "static_bearer",
                    "ref": reference,
                    "generation": credential.generation,
                    "token_env": required_secret_name(credential.token.as_ref(), "bearer token")?,
                }),
                CredentialType::Oauth2ClientCredentials => json!({
                    "type": "oauth_client_credentials",
                    "ref": reference,
                    "generation": credential.generation,
                    "client_id_env": required_secret_name(credential.client_id.as_ref(), "OAuth client id")?,
                    "client_secret_env": required_secret_name(credential.client_secret.as_ref(), "OAuth client secret")?,
                }),
                CredentialType::ApiKeyHeader => json!({
                    "type": "api_key_header",
                    "ref": reference,
                    "generation": credential.generation,
                    "value_env": required_secret_name(credential.value.as_ref(), "API-key value")?,
                }),
                CredentialType::ApiKeyQuery => json!({
                    "type": "api_key_query",
                    "ref": reference,
                    "generation": credential.generation,
                    "value_env": required_secret_name(credential.value.as_ref(), "API-key value")?,
                }),
            };
            source_credentials.push(entry);
        }
    }
    let datasets = generated_records_datasets(loaded, environment)?;
    let standards = generated_records_standards(loaded)?;
    let mut allowed_clients = relay.allowed_clients.clone();
    if let Some(connection) = &environment.notary_relay {
        allowed_clients.push(connection.workload_client_id.clone());
    }
    allowed_clients.sort();
    allowed_clients.dedup();
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
                "allowed_clients": allowed_clients,
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
        let workload = environment
            .notary_relay
            .as_ref()
            .ok_or_else(|| anyhow!("Notary-to-Relay workload binding is absent"))?;
        config["consultation"] = json!({
            "authorized_workload": {
                "audience": relay.audience,
                "client_claim_selector": "azp",
                "client_value": workload.workload_client_id,
                "principal_id": workload.workload_client_id,
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

fn source_credential_reference(
    loaded: &LoadedRegistryProject,
    environment: &EnvironmentDocument,
    alias: &str,
) -> Result<Option<String>> {
    let Some(target_binding) = environment.integrations.get(alias) else {
        return Ok(None);
    };
    let Some(target_credential) = target_binding.source.credential.as_ref() else {
        return Ok(None);
    };
    let target = json!({
        "interface": credential_interface(&loaded.integrations[alias].document).credential_type,
        "binding": target_credential,
    });
    for (candidate_alias, candidate_binding) in &environment.integrations {
        let Some(candidate_credential) = candidate_binding.source.credential.as_ref() else {
            continue;
        };
        let candidate = json!({
            "interface": credential_interface(&loaded.integrations[candidate_alias].document).credential_type,
            "binding": candidate_credential,
        });
        if candidate == target {
            return Ok(Some(format!("{candidate_alias}-credential")));
        }
    }
    bail!("environment credential has no integration owner")
}

fn canonical_rhai_script_path(
    loaded: &LoadedRegistryProject,
    alias: &str,
) -> Result<PathBuf> {
    let target = compiled_rhai_source(
        loaded
            .integrations
            .get(alias)
            .ok_or_else(|| anyhow!("script integration is absent"))?,
    )?;
    for (candidate_alias, candidate) in &loaded.integrations {
        if candidate.script.is_some() && compiled_rhai_source(candidate)? == target {
            return Ok(PathBuf::from(format!(
                "artifacts/rhai/{candidate_alias}.rhai"
            )));
        }
    }
    bail!("compiled Rhai script has no integration owner")
}

fn generated_records_datasets(
    loaded: &LoadedRegistryProject,
    environment: &EnvironmentDocument,
) -> Result<Vec<Value>> {
    loaded
        .entities
        .values()
        .map(|loaded_entity| {
            let entity = &loaded_entity.document;
            let publication = records_service_for_entity(loaded, &entity.id);
            let api = publication.and_then(|service| service.api.as_ref());
            let binding = environment
                .entities
                .get(&entity.id)
                .ok_or_else(|| anyhow!("generated entity binding is absent"))?;
            let resource_id = entity_materialization_resource_id(entity, binding)?;
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
                RecordProvider::Postgres {
                    connection,
                    schema,
                    table,
                } => json!({
                    "type": "postgres",
                    "connection_env": connection.secret,
                    "table": { "schema": schema, "name": table },
                }),
            };
            let fields = entity
                .schema
                .properties
                .iter()
                .map(|(logical, field)| {
                    let record_field = entity_record_field(logical, field)?;
                    Ok(json!({
                        "name": binding.columns[logical],
                        "type": record_field.field_type,
                        "nullable": record_field.nullable,
                        "sensitive": false,
                    }))
                })
                .collect::<Result<Vec<_>>>()?;
            let public_fields = entity
                .schema
                .properties
                .iter()
                .filter(|(logical, _)| {
                    api.is_some_and(|api| api.projection.contains(*logical))
                })
                .map(|(logical, _)| {
                    json!({
                        "name": logical,
                        "from": binding.columns[logical],
                        "sensitive": false,
                    })
                })
                .collect::<Vec<_>>();
            let allowed_filters = api
                .into_iter()
                .flat_map(|api| api.filters.iter())
                .map(|(field, ops)| json!({ "field": field, "ops": ops }))
                .collect::<Vec<_>>();
            let required_filter_bindings = api
                .into_iter()
                .flat_map(|api| api.required_principal_filters.iter())
                .map(|field| json!({ "field": field, "source": "principal_id" }))
                .collect::<Vec<_>>();
            let relationships = api
                .into_iter()
                .flat_map(|api| api.relationships.iter())
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
            let aggregates = api
                .into_iter()
                .flat_map(|api| api.aggregates.iter())
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
                        "source_entity": entity.id,
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
            let aggregate_scope = api
                .and_then(|api| api.scopes.aggregate.clone())
                .unwrap_or_else(|| format!("{}:aggregate", entity.id));
            let governed_policy = api.filter(|api| !api.purposes.is_empty()).map(|api| {
                json!({
                    "permitted_purposes": api.purposes,
                    "permitted_jurisdictions": [],
                    "allowed_assurance": [],
                    "require_legal_basis": false,
                    "require_consent": false,
                    "redaction_fields": [],
                    "trusted_context": {},
                })
            });
            let spatial = match api.map(|api| &api.standards.ogc_features) {
                Some(RecordStandard::Enabled(spatial)) => Some(serde_json::to_value(spatial)?),
                Some(RecordStandard::Disabled(_)) | None => None,
            };
            let refresh = entity_refresh_config(&entity.materialization.refresh)?;
            let metadata_scope = api
                .map(|api| api.scopes.metadata.as_str())
                .unwrap_or("registry-internal:materialization");
            let publication_entities = publication
                .map(|service| {
                    let api = service.api.as_ref().expect("records service was validated");
                    json!({
                        "name": entity.id,
                        "title": service.title,
                        "description": service.description,
                        "table": resource_id,
                        "fields": public_fields,
                        "relationships": relationships,
                        "access": {
                            "metadata_scope": api.scopes.metadata,
                            "aggregate_scope": aggregate_scope,
                            "read_scope": api.scopes.rows,
                            "evidence_verification_scope": api.scopes.evidence_verification.clone().unwrap_or_default(),
                        },
                        "api": {
                            "default_limit": api.pagination.default_limit,
                            "max_limit": api.pagination.max_limit,
                            "require_purpose_header": !api.purposes.is_empty(),
                            "governed_policy": governed_policy,
                            "required_filters": api.required_principal_filters,
                            "required_filter_bindings": required_filter_bindings,
                            "allowed_filters": allowed_filters,
                            "allowed_expansions": api.relationships.keys().collect::<Vec<_>>(),
                        },
                        "aggregates": aggregates,
                        "spatial": spatial,
                    })
                })
                .into_iter()
                .collect::<Vec<_>>();
            Ok(json!({
                "id": entity.id,
                "title": publication.and_then(|service| service.title.clone()).unwrap_or_else(|| entity.id.clone()),
                "description": publication.and_then(|service| service.description.clone()).unwrap_or_else(|| format!("Materialized {} entity", entity.id)),
                "owner": publication.and_then(|service| service.owner.clone()).unwrap_or_else(|| loaded.project.registry.id.clone()),
                "sensitivity": publication.and_then(|service| service.sensitivity).unwrap_or(RecordSensitivity::Personal),
                "access_rights": publication.and_then(|service| service.access_rights).unwrap_or(RecordAccessRights::Restricted),
                "update_frequency": publication.and_then(|service| service.update_frequency).unwrap_or(RecordUpdateFrequency::AsNeeded),
                "conforms_to": publication.map(|service| &service.conforms_to).into_iter().flatten().collect::<Vec<_>>(),
                "defaults": { "refresh": refresh, "materialization": "snapshot" },
                "tables": [{
                    "id": resource_id,
                    "source": source,
                    "refresh": refresh,
                    "materialization": "snapshot",
                    "primary_key": binding.columns[&entity.primary_key],
                    "schema": { "strict": true, "fields": fields },
                    "access": {
                        "metadata_scope": metadata_scope,
                        "aggregate_scope": aggregate_scope,
                    },
                    "api": {
                        "default_limit": api.map(|api| api.pagination.default_limit).unwrap_or(1),
                        "max_limit": api.map(|api| api.pagination.max_limit).unwrap_or(1),
                        "require_purpose_header": api.is_some_and(|api| !api.purposes.is_empty()),
                        "allowed_filters": [],
                    },
                    "aggregates": [],
                }],
                "entities": publication_entities,
                "aggregates": [],
            }))
        })
        .collect()
}

fn generated_records_standards(loaded: &LoadedRegistryProject) -> Result<Value> {
    let mut registries = Map::new();
    for service in loaded
        .project
        .services
        .values()
        .filter(|service| service.kind == ServiceKind::RecordsApi)
    {
        let entity = service
            .entity
            .as_deref()
            .expect("records service was validated");
        let api = service.api.as_ref().expect("records service was validated");
        let RecordStandard::Enabled(spdci) = &api.standards.sp_dci else {
            continue;
        };
        if registries
            .insert(
                spdci.registry.clone(),
                json!({
                    "dataset": entity,
                    "entity": entity,
                    "registry_type": spdci.registry_type,
                    "record_type": spdci.record_type,
                    "identifiers": spdci.identifiers,
                    "expression_fields": spdci.expression_fields,
                    "response_fields": spdci.response_fields,
                }),
            )
            .is_some()
        {
            bail!("SP DCI registry ids must be unique across records services");
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

fn records_service_for_entity<'a>(
    loaded: &'a LoadedRegistryProject,
    entity: &str,
) -> Option<&'a ServiceDeclaration> {
    loaded.project.services.values().find(|service| {
        service.kind == ServiceKind::RecordsApi && service.entity.as_deref() == Some(entity)
    })
}

fn entity_record_field(name: &str, field: &EntityFieldSchema) -> Result<RecordField> {
    let (scalar, nullable) = schema_type_parts(&field.field_type)?;
    let field_type = match (scalar, field.format) {
        (AuthoredScalarType::String, Some(AuthoredStringFormat::Date)) => RecordFieldType::Date,
        (AuthoredScalarType::String, None) => RecordFieldType::String,
        (AuthoredScalarType::Boolean, None) => RecordFieldType::Boolean,
        (AuthoredScalarType::Integer, None) => RecordFieldType::Integer,
        (AuthoredScalarType::Null, _) => bail!("entity field {name} cannot have only null type"),
        (_, Some(_)) => bail!("entity field {name} format is valid only for String"),
    };
    Ok(RecordField {
        field_type,
        nullable,
        sensitive: false,
        concept_uri: None,
        codelist: None,
        unit: None,
        language: None,
    })
}

fn entity_refresh_config(refresh: &str) -> Result<Value> {
    if refresh == "manual" {
        Ok(json!({ "mode": "manual" }))
    } else {
        parse_duration_ms(refresh).context("entity materialization refresh is invalid")?;
        Ok(json!({ "mode": "interval", "interval": refresh }))
    }
}

fn entity_materialization_resource_id(
    entity: &EntityDefinition,
    binding: &EnvironmentEntityBinding,
) -> Result<String> {
    let refresh_ms = (entity.materialization.refresh != "manual")
        .then(|| parse_duration_ms(&entity.materialization.refresh))
        .transpose()?;
    let digest = digest_json(&json!({
        "entity": {
            "version": entity.version,
            "id": entity.id,
            "revision": entity.revision,
            "primary_key": entity.primary_key,
            "schema": entity.schema,
        },
        "acquisition_policy": {
            "max_records": entity.materialization.max_records,
            "max_bytes": entity.materialization.max_bytes.bytes("entity.materialization.max_bytes")?,
            "refresh_ms": refresh_ms,
            "retain_generations": entity.materialization.retain_generations,
        },
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

fn entity_table_provider(
    entity: &EntityDefinition,
    binding: &EnvironmentEntityBinding,
) -> Result<String> {
    Ok(format!(
        "{}__{}",
        entity.id,
        entity_materialization_resource_id(entity, binding)?
    ))
}

fn generated_entity_materialization_review(
    loaded: &LoadedRegistryProject,
    environment: &EnvironmentDocument,
) -> Result<Map<String, Value>> {
    loaded
        .entities
        .iter()
        .map(|(id, loaded_entity)| {
            let binding = &environment.entities[id];
            Ok((
                id.clone(),
                json!({
                    "provider": entity_provider_review(&binding.provider),
                    "columns": binding.columns,
                    "source_revision": binding.source_revision,
                    "generation": binding.generation,
                    "stored_fields": loaded_entity.document.schema.properties,
                    "materialization_policy": loaded_entity.document.materialization,
                    "materialization_identity": entity_materialization_resource_id(&loaded_entity.document, binding)?,
                    "table_provider": entity_table_provider(&loaded_entity.document, binding)?,
                }),
            ))
        })
        .collect()
}

fn entity_provider_review(provider: &RecordProvider) -> Value {
    match provider {
        RecordProvider::Csv {
            path,
            header_row,
            delimiter,
            quote,
        } => json!({
            "type": "csv",
            "path": path,
            "header_row": header_row,
            "delimiter": delimiter,
            "quote": quote,
        }),
        RecordProvider::Xlsx {
            path,
            sheet,
            header_row,
            data_range,
        } => json!({
            "type": "xlsx",
            "path": path,
            "sheet": sheet,
            "header_row": header_row,
            "data_range": data_range,
        }),
        RecordProvider::Parquet { path } => json!({
            "type": "parquet",
            "path": path,
        }),
        RecordProvider::Postgres { schema, table, .. } => json!({
            "type": "postgres",
            "connection": "configured_secret",
            "schema": schema,
            "table": table,
        }),
    }
}

fn validate_entity_generation_changes(
    loaded: &LoadedRegistryProject,
    environment: &EnvironmentDocument,
    baseline: Option<&VerifiedBaseline>,
) -> Result<()> {
    let Some(previous) = baseline
        .and_then(|baseline| baseline.approval_state.get("entity_materializations"))
        .and_then(Value::as_object)
    else {
        return Ok(());
    };
    let current = generated_entity_materialization_review(loaded, environment)?;
    for (id, materialization) in &current {
        let Some(prior) = previous.get(id) else {
            continue;
        };
        if prior.get("materialization_identity") != materialization.get("materialization_identity")
            && prior.get("generation") == materialization.get("generation")
        {
            bail!("entity materialization changed without a new generation");
        }
    }
    Ok(())
}

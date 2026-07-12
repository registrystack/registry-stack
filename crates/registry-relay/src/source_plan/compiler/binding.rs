//! Private-binding validation and runtime capability compilation.

use super::*;
pub(super) fn validate_materialization_binding(
    contract: &PublicContractArtifact,
    pack: &IntegrationPackArtifact,
    binding: &PrivateBindingArtifact,
) -> Result<(), SourcePlanCompileError> {
    match pack.document.spec.plan.kind {
        SourcePlanKind::SnapshotExact => {
            let public = contract
                .document
                .spec
                .materialization
                .as_ref()
                .ok_or(SourcePlanCompileError::ContractMismatch)?;
            let reviewed = pack
                .document
                .spec
                .plan
                .snapshot
                .as_ref()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let private = binding
                .document
                .materialization
                .as_ref()
                .ok_or(SourcePlanCompileError::MissingBinding)?;
            let narrowed = reviewed.max_snapshot_age_ms == public.max_snapshot_age_ms
                && reviewed.unavailable == public.stale_behavior
                && reviewed.immutable_generation == public.immutable_generation
                && private
                    .max_snapshot_age_ms
                    .is_none_or(|value| value > 0 && value <= public.max_snapshot_age_ms)
                && private
                    .max_source_records
                    .is_none_or(|value| value > 0 && value <= public.footprint.max_source_records)
                && private
                    .max_source_bytes
                    .is_none_or(|value| value > 0 && value <= public.footprint.max_source_bytes)
                && private
                    .max_data_exchanges
                    .is_none_or(|value| value > 0 && value <= public.footprint.max_data_exchanges)
                && private
                    .max_credential_exchanges
                    .is_none_or(|value| value <= public.footprint.max_credential_exchanges)
                && private.max_data_destinations.is_none_or(|value| {
                    value == 1 && value <= public.footprint.max_data_destinations
                })
                && private.snapshot_retention_generations.is_none_or(|value| {
                    value > 0 && value <= public.snapshot_retention_generations
                })
                && public.immutable_generation
                && public.digest_bound_active_pointer;
            narrowed
                .then_some(())
                .ok_or(SourcePlanCompileError::BindingWidening)
        }
        SourcePlanKind::BoundedHttp | SourcePlanKind::SandboxedRhai => {
            if contract.document.spec.materialization.is_some()
                || binding.document.materialization.is_some()
            {
                Err(SourcePlanCompileError::ContractMismatch)
            } else {
                Ok(())
            }
        }
    }
}

pub(super) fn compile_snapshot_binding(
    contract: &PublicContractArtifact,
    pack: &IntegrationPackArtifact,
    binding: &PrivateBindingArtifact,
) -> Result<Option<CompiledSnapshotBinding>, SourcePlanCompileError> {
    if pack.document.spec.plan.kind != SourcePlanKind::SnapshotExact {
        return Ok(None);
    }
    let public = contract
        .document
        .spec
        .materialization
        .as_ref()
        .ok_or(SourcePlanCompileError::CompilerInvariant)?;
    let private = binding
        .document
        .materialization
        .as_ref()
        .ok_or(SourcePlanCompileError::CompilerInvariant)?;
    pack.document
        .spec
        .plan
        .snapshot
        .as_ref()
        .ok_or(SourcePlanCompileError::CompilerInvariant)?;
    let mapping = &private.mapping;
    let keys = mapping
        .key
        .iter()
        .map(|key| (key.input.as_str(), key))
        .chain(mapping.keys.iter().map(|(name, key)| (name.as_str(), key)))
        .collect::<Vec<_>>();
    let acquisition_fields = pack
        .document
        .spec
        .acquisition
        .fields
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if keys.iter().map(|(name, _)| *name).collect::<BTreeSet<_>>()
        != pack
            .document
            .spec
            .input_slots
            .keys()
            .map(String::as_str)
            .collect()
        || mapping
            .projection
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != acquisition_fields
    {
        return Err(SourcePlanCompileError::ContractMismatch);
    }
    let refresh_class = match public.refresh_class {
        MaterializationRefreshClassDocument::OperatorTriggered => {
            CompiledSnapshotRefreshClass::OperatorTriggered
        }
        MaterializationRefreshClassDocument::Scheduled => CompiledSnapshotRefreshClass::Scheduled,
    };
    let projection = mapping
        .projection
        .iter()
        .map(|(logical, physical)| (logical.as_str().into(), physical.as_str().into()))
        .collect::<Box<[_]>>();
    let physical_for = |logical: &str| {
        mapping
            .projection
            .get(logical)
            .map(|physical| physical.as_str().into())
            .ok_or(SourcePlanCompileError::CompilerInvariant)
    };
    let source_observed_at = match &pack.document.spec.source_provenance.source_observed_at {
        SourceObservedAtDocument::Absent => None,
        SourceObservedAtDocument::AcquiredRfc3339 { field } => {
            Some((field.as_str().into(), physical_for(field)?))
        }
    };
    let source_revision = match &pack.document.spec.source_provenance.source_revision {
        SourceRevisionDocument::Absent => None,
        SourceRevisionDocument::AcquiredString { field, max_bytes } => {
            Some((field.as_str().into(), physical_for(field)?, *max_bytes))
        }
    };
    Ok(Some(CompiledSnapshotBinding {
        table_provider: private.table_provider.as_str().into(),
        max_snapshot_age_ms: private
            .max_snapshot_age_ms
            .unwrap_or(public.max_snapshot_age_ms),
        max_source_records: private
            .max_source_records
            .unwrap_or(public.footprint.max_source_records),
        max_source_bytes: private
            .max_source_bytes
            .unwrap_or(public.footprint.max_source_bytes),
        max_refresh_data_exchanges: private
            .max_data_exchanges
            .unwrap_or(public.footprint.max_data_exchanges),
        max_refresh_credential_exchanges: private
            .max_credential_exchanges
            .unwrap_or(public.footprint.max_credential_exchanges),
        max_refresh_data_destinations: private
            .max_data_destinations
            .unwrap_or(public.footprint.max_data_destinations),
        snapshot_retention_generations: private
            .snapshot_retention_generations
            .unwrap_or(public.snapshot_retention_generations),
        refresh_class,
        immutable_generation: public.immutable_generation,
        digest_bound_active_pointer: public.digest_bound_active_pointer,
        keys: keys
            .into_iter()
            .map(|(name, key)| (name.into(), key.physical_field.as_str().into()))
            .collect(),
        projection,
        source_observed_at,
        source_revision,
    }))
}

pub(super) fn validate_capabilities(
    pack: &IntegrationPackArtifact,
    binding: &PrivateBindingArtifact,
    rhai_workers: &[RhaiWorkerCapability],
) -> Result<Option<RhaiWorkerLimits>, SourcePlanCompileError> {
    let capabilities = &binding.document.capabilities;
    match pack.document.spec.plan.kind {
        SourcePlanKind::SnapshotExact | SourcePlanKind::BoundedHttp => {
            if capabilities.allow_sandboxed_rhai || capabilities.sandboxed_rhai.is_some() {
                Err(SourcePlanCompileError::CapabilityMismatch)
            } else {
                Ok(None)
            }
        }
        SourcePlanKind::SandboxedRhai if !capabilities.allow_sandboxed_rhai => {
            Err(SourcePlanCompileError::RhaiNotEnabled)
        }
        SourcePlanKind::SandboxedRhai => {
            let binding = capabilities
                .sandboxed_rhai
                .as_ref()
                .ok_or(SourcePlanCompileError::RhaiNotEnabled)?;
            let reviewed = pack
                .document
                .spec
                .plan
                .rhai
                .as_ref()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let callable = binding
                .callable_operations
                .iter()
                .map(|value| value.as_str())
                .collect::<BTreeSet<_>>();
            let reviewed_operations = pack
                .document
                .spec
                .plan
                .operations
                .iter()
                .map(|operation| operation.id.as_str())
                .collect::<BTreeSet<_>>();
            let limits_narrow = binding.max_calls > 0
                && binding.max_calls <= pack.document.spec.bounds.max_data_exchanges
                && binding.memory_bytes > 0
                && binding.memory_bytes <= reviewed.memory_bytes
                && binding.cpu_ms > 0
                && binding.cpu_ms <= reviewed.cpu_ms
                && binding.ipc_frame_bytes > 0
                && binding.ipc_frame_bytes <= reviewed.ipc_frame_bytes
                && binding.instructions > 0
                && binding.instructions <= reviewed.instructions
                && binding.call_depth > 0
                && Some(binding.call_depth) <= reviewed.call_depth
                && binding.string_bytes > 0
                && Some(binding.string_bytes) <= reviewed.string_bytes
                && binding.array_items > 0
                && Some(binding.array_items) <= reviewed.array_items
                && binding.map_entries > 0
                && Some(binding.map_entries) <= reviewed.map_entries
                && binding.output_bytes > 0
                && Some(binding.output_bytes) <= reviewed.output_bytes
                && binding.concurrency == 1
                && Some(binding.concurrency) <= reviewed.concurrency;
            if callable.len() != binding.callable_operations.len()
                || callable != reviewed_operations
                || !limits_narrow
            {
                return Err(SourcePlanCompileError::BindingWidening);
            }
            let mut matching = rhai_workers.iter().filter(|worker| {
                worker.integration_pack_hash.as_ref() == pack.identity().hash().as_str()
            });
            let worker = matching
                .next()
                .ok_or(SourcePlanCompileError::RhaiWorkerUnavailable)?;
            if matching.next().is_some() {
                return Err(SourcePlanCompileError::RhaiWorkerMismatch);
            }
            let worker_operations = worker
                .callable_operations
                .iter()
                .map(AsRef::as_ref)
                .collect::<BTreeSet<&str>>();
            let expected_limits = RhaiWorkerLimits {
                max_calls: binding.max_calls,
                memory_bytes: binding.memory_bytes,
                cpu_ms: binding.cpu_ms,
                ipc_frame_bytes: binding.ipc_frame_bytes,
                instructions: binding.instructions,
                call_depth: binding.call_depth,
                string_bytes: binding.string_bytes,
                array_items: binding.array_items,
                map_entries: binding.map_entries,
                output_bytes: binding.output_bytes,
                concurrency: binding.concurrency,
            };
            if worker_operations != callable || worker.limits != expected_limits {
                Err(SourcePlanCompileError::RhaiWorkerMismatch)
            } else {
                Ok(Some(expected_limits))
            }
        }
    }
}

pub(super) fn validate_effective_source_bytes(
    pack: &IntegrationPackArtifact,
    effective_limits: SourcePlanLimits,
) -> Result<(), SourcePlanCompileError> {
    let data_response_bytes = match pack.document.spec.plan.kind {
        SourcePlanKind::SnapshotExact => 0,
        SourcePlanKind::BoundedHttp => {
            let declared = pack
                .document
                .spec
                .plan
                .operations
                .iter()
                .try_fold(0_u64, |total, operation| {
                    total.checked_add(u64::from(operation.response.max_bytes))
                })
                .ok_or(SourcePlanCompileError::BindingWidening)?;
            pack.document
                .spec
                .plan
                .verification_operations
                .iter()
                .try_fold(declared, |total, operation| {
                    total.checked_add(u64::from(operation.max_response_bytes))
                })
                .ok_or(SourcePlanCompileError::BindingWidening)?
        }
        SourcePlanKind::SandboxedRhai => {
            let maximum_data_response_bytes = pack
                .document
                .spec
                .plan
                .operations
                .iter()
                .map(|operation| u64::from(operation.response.max_bytes))
                .max()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            maximum_data_response_bytes
                .checked_mul(u64::from(effective_limits.operation().max_data_exchanges))
                .ok_or(SourcePlanCompileError::BindingWidening)?
        }
    };
    let credential_response_bytes = pack
        .document
        .spec
        .plan
        .credential_operation
        .as_ref()
        .map_or(0, |operation| u64::from(operation.response.max_bytes));
    let worst_case = data_response_bytes
        .checked_add(credential_response_bytes)
        .ok_or(SourcePlanCompileError::BindingWidening)?;
    if worst_case > effective_limits.operation().max_source_bytes {
        return Err(SourcePlanCompileError::BindingWidening);
    }
    Ok(())
}

pub(super) fn validate_cross_references(
    contract: &PublicContractArtifact,
    pack: &IntegrationPackArtifact,
    binding: &PrivateBindingArtifact,
) -> Result<(), SourcePlanCompileError> {
    let profile_matches = binding.profile_id == *contract.identity().id()
        && binding.profile_version == contract.identity().version();
    let contract_pack_matches = identities_equal(contract.integration_pack(), pack.identity());
    let binding_pack_matches = identities_equal(&binding.pack_identity, pack.identity());
    if profile_matches && contract_pack_matches && binding_pack_matches {
        Ok(())
    } else {
        Err(SourcePlanCompileError::ReferenceMismatch)
    }
}

pub(super) fn identities_equal(
    left: &IntegrationPackIdentity,
    right: &IntegrationPackIdentity,
) -> bool {
    left.id() == right.id() && left.version() == right.version() && left.hash() == right.hash()
}

pub(super) fn validate_contract_implementation(
    contract: &PublicContractArtifact,
    pack: &IntegrationPackArtifact,
) -> Result<(), SourcePlanCompileError> {
    let contract_spec = &contract.document.spec;
    let pack_spec = &pack.document.spec;
    let pack_can_ambiguous = pack_spec.bounds.max_source_matches == 2
        || pack_spec
            .plan
            .operations
            .iter()
            .any(|operation| !operation.response.status_outcomes.ambiguous.is_empty());
    let contract_can_ambiguous = contract_spec
        .public_behavior
        .outcomes
        .contains(&OutcomeDocument::Ambiguous);
    let exact = pack_spec.input_slots == contract_spec.inputs
        && pack_spec.acquisition == contract_spec.acquisition
        && pack_spec.source_provenance == contract_spec.source_provenance
        && pack_spec.output_mode == contract_spec.output_mode
        && pack_spec.output == contract_spec.output
        && pack_spec.bounds == contract_spec.bounds
        && pack_can_ambiguous == contract_can_ambiguous;
    exact
        .then_some(())
        .ok_or(SourcePlanCompileError::ContractMismatch)
}

pub(super) fn validate_binding_narrowing(
    contract: &PublicContractArtifact,
    pack: &IntegrationPackArtifact,
    binding: &PrivateBindingArtifact,
) -> Result<SourcePlanLimits, SourcePlanCompileError> {
    let public = contract.document.spec.bounds;
    let reviewed = pack.document.spec.bounds;
    if public != reviewed {
        return Err(SourcePlanCompileError::ContractMismatch);
    }
    SourcePlanLimits::from_documents(public, binding.document.limits)
        .map_err(|_| SourcePlanCompileError::BindingWidening)
}

pub(super) fn validate_parameters(
    pack: &IntegrationPackArtifact,
    binding: &PrivateBindingArtifact,
) -> Result<(), SourcePlanCompileError> {
    let declarations = &pack.document.spec.deployment_parameters;
    let values = &binding.document.deployment_parameters;
    if declarations.len() != values.len() || declarations.keys().ne(values.keys()) {
        return Err(SourcePlanCompileError::InvalidDeploymentParameter);
    }
    for (name, value) in values {
        if declarations
            .get(name)
            .is_none_or(|declaration| declaration.allowed_values.binary_search(value).is_err())
        {
            return Err(SourcePlanCompileError::InvalidDeploymentParameter);
        }
    }
    Ok(())
}

pub(super) fn validate_credential_shape(
    pack: &IntegrationPackArtifact,
    binding: &PrivateBindingArtifact,
) -> Result<(), SourcePlanCompileError> {
    let uses_oauth = pack
        .document
        .spec
        .plan
        .operations
        .iter()
        .any(|operation| matches!(operation.auth, SourceAuthDocument::OAuthClientCredentials));
    let uses_bound_credential = pack
        .document
        .spec
        .plan
        .operations
        .iter()
        .any(|operation| operation.auth != SourceAuthDocument::None);
    let reviewed = pack.document.spec.plan.credential_operation.is_some();
    let destination = binding.document.credential_destination.is_some();
    let credential = binding.document.credential.is_some();
    let data_destination_matches = binding.document.data_destination.is_some()
        == (pack.document.spec.plan.kind != SourcePlanKind::SnapshotExact);
    let credential_slot_matches = binding.document.credential_destination.is_some()
        == pack
            .document
            .spec
            .plan
            .credential_destination_slot
            .is_some();
    if reviewed == uses_oauth
        && destination == uses_oauth
        && credential == uses_bound_credential
        && data_destination_matches
        && credential_slot_matches
    {
        Ok(())
    } else {
        Err(SourcePlanCompileError::InvalidCredentialBinding)
    }
}

pub(super) fn effective_token_lifetime_ms(
    pack: &IntegrationPackArtifact,
    binding: &PrivateBindingArtifact,
) -> Result<Option<u32>, SourcePlanCompileError> {
    let private = binding
        .document
        .limits
        .and_then(|limits| limits.max_token_lifetime_ms);
    let Some(operation) = &pack.document.spec.plan.credential_operation else {
        return if private.is_none() {
            Ok(None)
        } else {
            Err(SourcePlanCompileError::BindingWidening)
        };
    };
    match operation.response.cache_mode {
        OAuth2TokenCacheModeDocument::Disabled => {
            if private.is_none()
                && operation.response.schema
                    == OAuth2TokenResponseSchemaDocument::StrictAccessTokenBearerNoExpiry
            {
                Ok(None)
            } else {
                Err(SourcePlanCompileError::BindingWidening)
            }
        }
        OAuth2TokenCacheModeDocument::ExpiryBound => {
            let reviewed = operation
                .response
                .max_token_lifetime_ms
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let effective = private.unwrap_or(reviewed);
            if effective == 0 || effective > reviewed {
                Err(SourcePlanCompileError::BindingWidening)
            } else {
                Ok(Some(effective))
            }
        }
    }
}

pub(super) fn compile_data_destination(
    destination: &DestinationDocument,
) -> Result<DataDestinationPolicy, SourcePlanCompileError> {
    let cidrs = destination
        .allowed_private_cidrs
        .iter()
        .map(|cidr| cidr.parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SourcePlanCompileError::UnsafeDestination)?;
    DataDestinationPolicy::new_with_dns_family(
        &destination.id,
        &destination.origin,
        DestinationProfile::ProductionHttps,
        &cidrs,
        compile_destination_dns_family(destination.dns_family),
    )
    .map_err(|_| SourcePlanCompileError::UnsafeDestination)
}

pub(super) fn compile_credential_destination(
    destination: &DestinationDocument,
) -> Result<CredentialDestinationPolicy, SourcePlanCompileError> {
    let cidrs = destination
        .allowed_private_cidrs
        .iter()
        .map(|cidr| cidr.parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SourcePlanCompileError::UnsafeDestination)?;
    CredentialDestinationPolicy::new_with_dns_family(
        &destination.id,
        &destination.origin,
        DestinationProfile::ProductionHttps,
        &cidrs,
        compile_destination_dns_family(destination.dns_family),
    )
    .map_err(|_| SourcePlanCompileError::UnsafeDestination)
}

const fn compile_destination_dns_family(
    family: DestinationDnsFamilyDocument,
) -> DestinationDnsFamily {
    match family {
        DestinationDnsFamilyDocument::DualStackStrict => DestinationDnsFamily::DualStackStrict,
        DestinationDnsFamilyDocument::Ipv4Only => DestinationDnsFamily::Ipv4Only,
    }
}

pub(super) fn compile_credential_operation(
    pack: &IntegrationPackArtifact,
    effective_token_lifetime_ms: Option<u32>,
    application_base_path: &str,
) -> Result<Option<CompiledCredentialOperation>, SourcePlanCompileError> {
    let Some(operation) = &pack.document.spec.plan.credential_operation else {
        return Ok(None);
    };
    let id = OperationId::try_from(operation.id.as_str())
        .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;
    let (format, transport_format) = match operation.request.format {
        OAuth2ClientCredentialsRequestFormatDocument::JsonClientSecretBody => (
            CompiledOAuth2RequestFormat::JsonClientSecretBody,
            OAuth2ClientCredentialsBodyFormat::JsonClientSecretBody,
        ),
        OAuth2ClientCredentialsRequestFormatDocument::FormClientSecretBody => (
            CompiledOAuth2RequestFormat::FormClientSecretBody,
            OAuth2ClientCredentialsBodyFormat::FormClientSecretBody,
        ),
    };
    let fixed_path = destination_fixed_path(application_base_path, &operation.path);
    let transport_template = CredentialDestinationRequestTemplate::oauth2_client_credentials(
        &fixed_path,
        transport_format,
        operation.request.max_body_bytes as usize,
        operation.request.max_request_bytes as usize,
    )
    .map_err(|_| {
        if application_base_path == "/" {
            SourcePlanCompileError::CompilerInvariant
        } else {
            SourcePlanCompileError::BindingWidening
        }
    })?;
    if operation.response.token_type != OAuth2TokenTypeDocument::Bearer {
        return Err(SourcePlanCompileError::CompilerInvariant);
    }
    let (token_schema, cache_mode) = match (
        operation.response.schema,
        operation.response.cache_mode,
        effective_token_lifetime_ms,
    ) {
        (
            OAuth2TokenResponseSchemaDocument::StrictAccessTokenBearerExpiresIn,
            OAuth2TokenCacheModeDocument::ExpiryBound,
            Some(_),
        ) => (
            CompiledOAuth2TokenSchema::StrictAccessTokenBearerExpiresIn,
            CompiledOAuth2CacheMode::ExpiryBound,
        ),
        (
            OAuth2TokenResponseSchemaDocument::StrictAccessTokenBearerNoExpiry,
            OAuth2TokenCacheModeDocument::Disabled,
            None,
        ) => (
            CompiledOAuth2TokenSchema::StrictAccessTokenBearerNoExpiry,
            CompiledOAuth2CacheMode::Disabled,
        ),
        _ => return Err(SourcePlanCompileError::CompilerInvariant),
    };
    let failure_policy = match operation.failure_policy {
        CredentialFailurePolicyDocument::FailClosedSourceUnavailableNoRetryNoStaleNoDataDispatch => {
            CompiledCredentialFailurePolicy::FailClosedSourceUnavailableNoRetryNoStaleNoDataDispatch
        }
    };
    let scope = (!operation.request.scopes.is_empty())
        .then(|| operation.request.scopes.join(" ").into_boxed_str());
    Ok(Some(CompiledCredentialOperation {
        id,
        format,
        transport_template,
        max_client_id_bytes: operation.request.max_client_id_bytes,
        max_client_secret_bytes: operation.request.max_client_secret_bytes,
        max_body_bytes: operation.request.max_body_bytes,
        timeout_ms: operation.request.timeout_ms,
        audience: operation.request.audience.as_deref().map(Into::into),
        scope,
        resource: operation.request.resource.as_deref().map(Into::into),
        parser: CompiledOAuth2TokenParser {
            max_response_bytes: operation.response.max_bytes,
            accepted_statuses: operation
                .response
                .accepted_statuses
                .clone()
                .into_boxed_slice(),
            access_token_max_bytes: operation.response.access_token_max_bytes,
            schema: token_schema,
            expires_in_min_seconds: operation.response.expires_in_min_seconds,
            expires_in_max_seconds: operation.response.expires_in_max_seconds,
            max_token_lifetime_ms: effective_token_lifetime_ms,
            expiry_safety_skew_ms: operation.response.expiry_safety_skew_ms,
        },
        cache_mode,
        failure_policy,
    }))
}

pub(super) fn reject_destination_overlap(
    pack: &IntegrationPackArtifact,
    binding: &PrivateBindingArtifact,
) -> Result<(), SourcePlanCompileError> {
    let Some(credential) = &binding.document.credential_destination else {
        return Ok(());
    };
    let data = binding
        .document
        .data_destination
        .as_ref()
        .ok_or(SourcePlanCompileError::UnsafeDestination)?;
    let data_origin =
        Url::parse(&data.origin).map_err(|_| SourcePlanCompileError::UnsafeDestination)?;
    let credential_origin =
        Url::parse(&credential.origin).map_err(|_| SourcePlanCompileError::UnsafeDestination)?;
    let signed_dci = pack.document.spec.plan.operations.len() == 1
        && pack.document.spec.plan.verification_operations.len() == 1
        && pack.document.spec.plan.operations[0].dci.is_some();
    if data.id == credential.id || (data_origin == credential_origin && !signed_dci) {
        Err(SourcePlanCompileError::UnsafeDestination)
    } else {
        Ok(())
    }
}

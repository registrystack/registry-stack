//! Strict JSON/YAML parsing, normalization, and domain-separated hashing.

use super::validation::*;
use super::*;
pub(in super::super) fn parse_public_contract(
    bytes: &[u8],
    expected_hash: &str,
) -> Result<PublicContractArtifact, SourcePlanArtifactError> {
    parse_public_contract_inner(bytes, Some(expected_hash), false)
}

pub(in super::super) fn author_public_contract(
    bytes: &[u8],
) -> Result<PublicContractArtifact, SourcePlanArtifactError> {
    parse_public_contract_inner(bytes, None, true)
}

fn parse_public_contract_inner(
    bytes: &[u8],
    expected_hash: Option<&str>,
    rewrite_policy_hash: bool,
) -> Result<PublicContractArtifact, SourcePlanArtifactError> {
    let mut document: PublicContractDocument = parse_document(bytes)?;
    if document.schema != CONTRACT_SCHEMA {
        return Err(SourcePlanArtifactError::UnsupportedSchema);
    }

    let id = ProfileId::try_from(document.id.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let version = ProfileVersion::try_from(document.version.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let pack_identity = parse_pack_reference(&document.spec.integration_pack)?;
    let selector_provenance = validate_subject(&document.spec.subject)?;
    validate_inputs(&document.spec.inputs)?;
    let acquired_fields = validate_acquisition(&document.spec.acquisition)?;
    validate_source_provenance(
        &document.spec.source_provenance,
        document.spec.acquisition.class,
        &document.spec.acquisition.fields,
    )?;
    document.spec.bounds = document
        .spec
        .bounds
        .validate_for_acquisition(document.spec.acquisition.class)?;
    validate_runtime_requirements(&document.spec)?;
    validate_output(&document.spec.output, &acquired_fields)?;
    let mut authorization = validate_authorization(&mut document.spec.authorization)?;
    let cardinality = cardinality_from_bounds(document.spec.bounds)?;
    validate_public_behavior(&mut document.spec.public_behavior, cardinality)?;
    validate_materialization_contract(&mut document.spec, &acquired_fields)?;

    // The policy is a compiler-generated commitment over this normalized
    // contract, not a separately supplied or runtime-selected artifact. Verify
    // it before hashing the contract so the contract hash binds the verified
    // digest rather than an arbitrary well-formed declaration.
    let derived_policy = derive_consultation_policy(&document)?;
    if rewrite_policy_hash {
        document.spec.authorization.policy.hash = derived_policy.hash.as_str().to_owned();
        authorization = validate_authorization(&mut document.spec.authorization)?;
    } else if authorization.policy_identity.hash() != &derived_policy.hash {
        return Err(SourcePlanArtifactError::PolicyHashMismatch);
    }

    let (canonical_json, digest) = hash_document(CONTRACT_HASH_DOMAIN, &document)?;
    if expected_hash.is_some_and(|expected| digest != expected) {
        return Err(SourcePlanArtifactError::HashMismatch);
    }
    let contract_hash = ProfileContractHash::try_from(digest.as_str())
        .map_err(|_| SourcePlanArtifactError::Canonicalization)?;
    let identity = ProfileIdentity::new(id, version, contract_hash);
    let acquisition_class = document.spec.acquisition.class.into();
    let public_limits = document.spec.bounds;

    Ok(PublicContractArtifact {
        document,
        identity,
        pack_identity,
        acquisition_class,
        acquired_fields,
        cardinality,
        public_limits,
        workload_id: authorization.workload_id,
        required_scope: authorization.required_scope,
        policy_identity: authorization.policy_identity,
        consent_verifier: authorization.consent_verifier,
        purposes: authorization.purposes,
        legal_basis: authorization.legal_basis,
        selector_provenance,
        canonical_json: canonical_json.into_boxed_slice(),
    })
}

pub(in super::super) fn parse_integration_pack(
    bytes: &[u8],
    expected_hash: &str,
) -> Result<IntegrationPackArtifact, SourcePlanArtifactError> {
    parse_integration_pack_inner(bytes, Some(expected_hash))
}

pub(in super::super) fn author_integration_pack(
    bytes: &[u8],
) -> Result<IntegrationPackArtifact, SourcePlanArtifactError> {
    parse_integration_pack_inner(bytes, None)
}

fn parse_integration_pack_inner(
    bytes: &[u8],
    expected_hash: Option<&str>,
) -> Result<IntegrationPackArtifact, SourcePlanArtifactError> {
    let mut document: IntegrationPackDocument = parse_document(bytes)?;
    if document.schema != PACK_SCHEMA {
        return Err(SourcePlanArtifactError::UnsupportedSchema);
    }

    let id = IntegrationPackId::try_from(document.id.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let version = ProfileVersion::try_from(document.version.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    if let Some(product_family) = &document.spec.product_family {
        validate_bounded_text(product_family, MAX_STABLE_TEXT_BYTES)?;
    }
    if !document.spec.supported_version_evidence.is_empty() {
        normalize_bounded_set(
            &mut document.spec.supported_version_evidence,
            MAX_STABLE_TEXT_BYTES,
        )?;
    }
    if document.spec.supported_version_evidence.len() > MAX_SUPPORTED_VERSIONS {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    let logical_operation = OperationId::try_from(document.spec.logical_operation.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    validate_inputs(&document.spec.input_slots)?;
    let acquired_fields = validate_acquisition(&document.spec.acquisition)?;
    validate_source_provenance(
        &document.spec.source_provenance,
        document.spec.acquisition.class,
        &document.spec.acquisition.fields,
    )?;
    validate_output(&document.spec.output, &acquired_fields)?;
    validate_parameter_declarations(&mut document.spec.deployment_parameters)?;
    validate_evidence_manifest(&mut document.spec.evidence)?;
    validate_plan(&mut document.spec, &acquired_fields)?;
    validate_reviewed_acquisition(&document.spec, &acquired_fields)?;
    document.spec.bounds = document
        .spec
        .bounds
        .validate_for_acquisition(document.spec.acquisition.class)?;

    let (canonical_json, digest) = hash_document(PACK_HASH_DOMAIN, &document)?;
    if expected_hash.is_some_and(|expected| digest != expected) {
        return Err(SourcePlanArtifactError::HashMismatch);
    }
    let hash = IntegrationPackHash::try_from(digest.as_str())
        .map_err(|_| SourcePlanArtifactError::Canonicalization)?;
    let identity = IntegrationPackIdentity::new(id, version, hash);
    Ok(IntegrationPackArtifact {
        document,
        identity,
        logical_operation,
        canonical_json: canonical_json.into_boxed_slice(),
    })
}

fn validate_evidence_manifest(
    manifest: &mut EvidenceManifestDocument,
) -> Result<(), SourcePlanArtifactError> {
    for hashes in [
        &mut manifest.conformance,
        &mut manifest.negative_security,
        &mut manifest.minimization,
    ] {
        normalize_hash_set(hashes)?;
        if hashes.len() > MAX_EVIDENCE_FILES_PER_CLASS {
            return Err(SourcePlanArtifactError::InvalidSet);
        }
    }
    let mut globally_unique = BTreeSet::new();
    if manifest
        .conformance
        .iter()
        .chain(&manifest.negative_security)
        .chain(&manifest.minimization)
        .any(|hash| !globally_unique.insert(hash.as_str()))
    {
        return Err(SourcePlanArtifactError::InvalidSet);
    }
    Ok(())
}

pub(in super::super) fn parse_private_binding(
    bytes: &[u8],
) -> Result<PrivateBindingArtifact, SourcePlanArtifactError> {
    let mut document: PrivateBindingDocument = parse_document(bytes)?;
    let profile_id = ProfileId::try_from(document.profile.id.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let profile_version = ProfileVersion::try_from(document.profile.version.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let pack_identity = parse_pack_reference(&document.integration_pack)?;
    let tenant = TenantId::try_from(document.tenant.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    let registry_instance = RegistryInstanceId::try_from(document.registry_instance.as_str())
        .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
    validate_stable_text(&document.source_instance)?;
    let data_destination_id = document
        .data_destination
        .as_ref()
        .map(|destination| {
            SourceDestinationId::try_from(destination.id.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)
        })
        .transpose()?;
    if let Some(destination) = &mut document.data_destination {
        validate_destination_document(destination)?;
    }
    let credential_destination_id = document
        .credential_destination
        .as_ref()
        .map(|destination| {
            SourceDestinationId::try_from(destination.id.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)
        })
        .transpose()?;
    if let Some(destination) = &mut document.credential_destination {
        validate_destination_document(destination)?;
    }
    let verification_destination_id = document
        .verification_destination
        .as_ref()
        .map(|destination| {
            SourceDestinationId::try_from(destination.id.as_str())
                .map_err(|_| SourcePlanArtifactError::InvalidIdentity)
        })
        .transpose()?;
    if let Some(destination) = &mut document.verification_destination {
        validate_destination_document(destination)?;
    }
    let credential_reference = if let Some(credential) = &document.credential {
        let reference = CredentialReferenceId::try_from(credential.reference.as_str())
            .map_err(|_| SourcePlanArtifactError::InvalidIdentity)?;
        if credential.generation == 0 || credential.generation > MAX_JSON_INTEROPERABLE_INTEGER {
            return Err(SourcePlanArtifactError::InvalidLimits);
        }
        Some(reference)
    } else {
        None
    };
    if let Some(materialization) = &document.materialization {
        validate_stable_text(&materialization.table_provider)?;
        let mapping = &materialization.mapping;
        if mapping.key.is_some() != mapping.keys.is_empty() {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
        let keys = mapping
            .key
            .iter()
            .map(|key| (key.input.as_str(), key))
            .chain(mapping.keys.iter().map(|(name, key)| (name.as_str(), key)))
            .collect::<Vec<_>>();
        if !(1..=MAX_SELECTOR_INPUTS).contains(&keys.len()) {
            return Err(SourcePlanArtifactError::InvalidAcquisition);
        }
        let mut physical_fields = BTreeSet::new();
        for (name, key) in &keys {
            validate_stable_text(name)?;
            validate_stable_text(&key.input)?;
            validate_stable_text(&key.physical_field)?;
            if *name != key.input || !physical_fields.insert(key.physical_field.as_str()) {
                return Err(SourcePlanArtifactError::InvalidAcquisition);
            }
        }
        for (logical, physical) in &materialization.mapping.projection {
            validate_stable_text(logical)?;
            validate_stable_text(physical)?;
            if !physical_fields.insert(physical.as_str()) {
                return Err(SourcePlanArtifactError::InvalidAcquisition);
            }
        }
        for value in [
            materialization.max_snapshot_age_ms,
            materialization.max_source_records,
            materialization.max_source_bytes,
        ]
        .into_iter()
        .flatten()
        {
            if value == 0 || value > MAX_JSON_INTEROPERABLE_INTEGER {
                return Err(SourcePlanArtifactError::InvalidLimits);
            }
        }
        if materialization.max_data_exchanges == Some(0)
            || materialization.max_data_destinations == Some(0)
            || materialization.snapshot_retention_generations == Some(0)
        {
            return Err(SourcePlanArtifactError::InvalidLimits);
        }
    }
    validate_parameter_bindings(&document.deployment_parameters)?;
    let (_, digest) = hash_document(BINDING_HASH_DOMAIN, &document)?;
    Ok(PrivateBindingArtifact {
        document,
        profile_id,
        profile_version,
        pack_identity,
        tenant,
        registry_instance,
        data_destination_id,
        credential_destination_id,
        verification_destination_id,
        credential_reference,
        hash: PrivateBindingHash::from_digest(digest),
    })
}

fn parse_document<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, SourcePlanArtifactError> {
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(SourcePlanArtifactError::InputTooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| SourcePlanArtifactError::StrictJson)?;
    let value = if matches!(
        text.trim_start().as_bytes().first(),
        Some(b'{') | Some(b'[')
    ) {
        parse_json_strict(bytes).map_err(|_| SourcePlanArtifactError::StrictJson)?
    } else {
        reject_ambiguous_yaml(text)?;
        serde_saphyr::from_str::<StrictValue>(text)
            .map_err(|_| SourcePlanArtifactError::StrictJson)?
            .0
    };
    serde_json::from_value(value).map_err(|_| SourcePlanArtifactError::ClosedSchema)
}

struct StrictValue(serde_json::Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

struct StrictStringKey(String);

impl<'de> Deserialize<'de> for StrictStringKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(StrictStringKeyVisitor)
    }
}

struct StrictStringKeyVisitor;

impl Visitor<'_> for StrictStringKeyVisitor {
    type Value = StrictStringKey;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a YAML string mapping key")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictStringKey(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictStringKey(value))
    }
}

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON-compatible YAML value without duplicate mapping keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(value.into()))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.unsigned_abs() > MAX_JSON_INTEROPERABLE_INTEGER {
            return Err(E::custom(
                "YAML integer exceeds the interoperable JSON range",
            ));
        }
        Ok(StrictValue(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value > MAX_JSON_INTEROPERABLE_INTEGER {
            return Err(E::custom(
                "YAML integer exceeds the interoperable JSON range",
            ));
        }
        Ok(StrictValue(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.fract() == 0.0 && value.abs() >= 9_007_199_254_740_992.0_f64 {
            return Err(E::custom(
                "YAML integer exceeds the interoperable JSON range",
            ));
        }
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("YAML number is not a finite binary64 value"))?;
        Ok(StrictValue(serde_json::Value::Number(number)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(value.into()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(value.into()))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut mapping: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(StrictStringKey(key)) = mapping.next_key::<StrictStringKey>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate YAML mapping key"));
            }
            let value = mapping.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(serde_json::Value::Object(values)))
    }
}

fn reject_ambiguous_yaml(text: &str) -> Result<(), SourcePlanArtifactError> {
    if text.contains('\t') {
        return Err(SourcePlanArtifactError::StrictJson);
    }
    for line in text.lines() {
        let mut single_quoted = false;
        let mut double_quoted = false;
        let mut escaped = false;
        let mut visible = String::with_capacity(line.len());
        for character in line.chars() {
            if escaped {
                escaped = false;
                continue;
            }
            if double_quoted && character == '\\' {
                escaped = true;
                continue;
            }
            match character {
                '\'' if !double_quoted => single_quoted = !single_quoted,
                '"' if !single_quoted => double_quoted = !double_quoted,
                '#' if !single_quoted && !double_quoted => break,
                '&' | '*' | '!' | '|' | '>' if !single_quoted && !double_quoted => {
                    return Err(SourcePlanArtifactError::StrictJson);
                }
                _ if !single_quoted && !double_quoted => visible.push(character),
                _ => {}
            }
        }
        if single_quoted || double_quoted {
            return Err(SourcePlanArtifactError::StrictJson);
        }
        let visible = visible.trim();
        if visible.contains("<<:")
            || visible == "---"
            || visible.starts_with("--- ")
            || visible == "..."
            || visible.starts_with("... ")
            || visible.starts_with('%')
        {
            return Err(SourcePlanArtifactError::StrictJson);
        }
        let mapping = visible.strip_prefix("- ").unwrap_or(visible);
        if let Some((plain_key, _)) = mapping.split_once(':') {
            let plain_key = plain_key.trim();
            if !plain_key.is_empty()
                && serde_json::from_str::<serde_json::Value>(plain_key)
                    .is_ok_and(|value| !value.is_string())
            {
                return Err(SourcePlanArtifactError::StrictJson);
            }
        }
        for chunk in visible.split(|character: char| {
            character.is_whitespace() || matches!(character, '[' | ']' | '{' | '}' | ',')
        }) {
            let chunk = chunk.trim_matches(|character| matches!(character, '?' | '-'));
            if chunk.is_empty() {
                continue;
            }
            if looks_like_sexagesimal(chunk) {
                return Err(SourcePlanArtifactError::StrictJson);
            }
            for scalar in chunk.split(':') {
                reject_ambiguous_yaml_scalar(scalar.trim())?;
            }
        }
    }
    Ok(())
}

fn reject_ambiguous_yaml_scalar(scalar: &str) -> Result<(), SourcePlanArtifactError> {
    if scalar.is_empty() {
        return Ok(());
    }
    let lowercase = scalar.to_ascii_lowercase();
    let ambiguous_word = matches!(
        lowercase.as_str(),
        "y" | "n"
            | "yes"
            | "no"
            | "on"
            | "off"
            | "~"
            | ".inf"
            | "+.inf"
            | "-.inf"
            | ".nan"
            | "+.nan"
            | "-.nan"
    ) || (matches!(lowercase.as_str(), "true" | "false" | "null")
        && scalar != lowercase)
        || lowercase.starts_with(".inf")
        || lowercase.starts_with(".nan");
    let unsigned = scalar
        .strip_prefix('+')
        .or_else(|| scalar.strip_prefix('-'))
        .unwrap_or(scalar);
    let numeric_like =
        unsigned.as_bytes().first().is_some_and(u8::is_ascii_digit) || unsigned.starts_with('.');
    let lowercase_unsigned = unsigned.to_ascii_lowercase();
    let ambiguous_number = scalar.starts_with('+')
        || lowercase_unsigned.starts_with("0x")
        || lowercase_unsigned.starts_with("0o")
        || lowercase_unsigned.starts_with("0b")
        || (unsigned.len() > 1
            && unsigned.starts_with('0')
            && unsigned.as_bytes()[1].is_ascii_digit())
        || (numeric_like
            && (scalar.contains('_') || scalar.starts_with('.') || scalar.ends_with('.')));
    if ambiguous_word || ambiguous_number || looks_like_yaml_date(scalar) {
        Err(SourcePlanArtifactError::StrictJson)
    } else {
        Ok(())
    }
}

fn looks_like_sexagesimal(value: &str) -> bool {
    let value = value
        .strip_prefix('+')
        .or_else(|| value.strip_prefix('-'))
        .unwrap_or(value);
    let mut segments = value.split(':');
    let Some(first) = segments.next() else {
        return false;
    };
    let remaining = segments.collect::<Vec<_>>();
    !remaining.is_empty()
        && first.chars().all(|character| character.is_ascii_digit())
        && remaining.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .trim_end_matches(|character: char| {
                        character == '.' || character.is_ascii_digit()
                    })
                    .is_empty()
                && segment
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_digit())
        })
}

fn looks_like_yaml_date(value: &str) -> bool {
    let date = value.split(['T', 't', ' ']).next().unwrap_or(value);
    let parts = date.split('-').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0].len() == 4
        && (1..=2).contains(&parts[1].len())
        && (1..=2).contains(&parts[2].len())
        && parts
            .iter()
            .all(|part| part.chars().all(|character| character.is_ascii_digit()))
}

pub(super) fn hash_document<T: Serialize>(
    domain: &[u8],
    document: &T,
) -> Result<(Vec<u8>, String), SourcePlanArtifactError> {
    let value =
        serde_json::to_value(document).map_err(|_| SourcePlanArtifactError::Canonicalization)?;
    let canonical =
        canonicalize_json(&value).map_err(|_| SourcePlanArtifactError::Canonicalization)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(&canonical);
    Ok((canonical, encode_digest(hasher.finalize())))
}

pub(in super::super) fn sha256_label(bytes: &[u8]) -> String {
    encode_digest(Sha256::digest(bytes))
}

fn encode_digest(digest: impl AsRef<[u8]>) -> String {
    let digest = digest.as_ref();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(7 + digest.len() * 2);
    encoded.push_str("sha256:");
    for &byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

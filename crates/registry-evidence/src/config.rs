//! Typed Evidence Version 1 deployment configuration.
//!
//! Configuration is trusted deployment data, but it is still parsed as a
//! closed contract. Secret-bearing fields contain only [`SecretRef`] values;
//! this module never resolves them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Component, Path};
use std::str::FromStr;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_norway::Value as YamlValue;
use thiserror::Error;
use url::{Host, Url};

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum ConfigError {
    #[error("configuration YAML does not match the Evidence Version 1 schema: {0}")]
    InvalidYaml(SchemaFault),
    #[error("configuration exceeds the Evidence Version 1 size limit")]
    TooLarge,
    #[error("configuration violates the Evidence Version 1 contract: {0}")]
    Invalid(&'static str),
}

impl ConfigError {
    /// The value-free diagnostic for this failure.
    ///
    /// Deployment tooling reports this instead of the error itself so that
    /// every configuration failure carries the same safe shape.
    pub fn fault(&self) -> SchemaFault {
        match self {
            Self::InvalidYaml(fault) => fault.clone(),
            Self::TooLarge => SchemaFault::because("document exceeds the Version 1 size limit"),
            Self::Invalid(cause) => SchemaFault::because(cause),
        }
    }
}

/// A one-based text position inside a deployment artifact.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TextLocation {
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for TextLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "line {} column {}", self.line, self.column)
    }
}

/// A value-free reason one deployment document was rejected.
///
/// Only three things are kept: a schema path built from mapping keys and
/// sequence indices, a text location, and one static cause. The decoder's own
/// message is classified and then discarded, because it quotes scalars, and a
/// deployment scalar can be a selector value, a secret reference, or a source
/// identifier.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SchemaFault {
    location: Option<TextLocation>,
    path: Option<String>,
    cause: &'static str,
}

/// The longest schema path a diagnostic will carry.
const MAX_SCHEMA_PATH_BYTES: usize = 256;

/// Decoder message prefixes mapped to their value-free cause.
///
/// The prefixes are the fixed leading text of `serde` and `serde_norway`
/// messages. Everything after a prefix can quote document content and is
/// never read.
const DECODE_CAUSES: [(&str, &str); 13] = [
    ("unknown field", "unknown field"),
    ("missing field", "required field is missing"),
    ("duplicate field", "duplicate field"),
    ("duplicate entry", "duplicate mapping key"),
    ("invalid type", "field has the wrong type"),
    ("invalid value", "field value is not accepted"),
    ("invalid length", "field has the wrong length"),
    (
        "unknown variant",
        "field value is not one of the accepted variants",
    ),
    (
        "data did not match any variant",
        "field value is not one of the accepted variants",
    ),
    (
        "EOF while parsing",
        "document ends before a value is complete",
    ),
    ("recursion limit exceeded", "document nests too deeply"),
    (
        "repetition limit exceeded",
        "document repeats an alias too often",
    ),
    (
        "deserializing from YAML containing more than one document",
        "document contains more than one YAML document",
    ),
];

impl SchemaFault {
    /// A fault that names only its cause.
    pub fn because(cause: &'static str) -> Self {
        Self {
            location: None,
            path: None,
            cause,
        }
    }

    pub fn cause(&self) -> &'static str {
        self.cause
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn location(&self) -> Option<TextLocation> {
        self.location
    }

    /// Reduce a decoder error to a location, a safe schema path, and a cause.
    fn from_yaml_error(error: &serde_norway::Error, fallback: &'static str) -> Self {
        let rendered = error.to_string();
        let (path, message) = split_schema_path(&rendered);
        Self {
            location: error.location().map(|location| TextLocation {
                line: location.line(),
                column: location.column(),
            }),
            path,
            cause: classify_decode_cause(message, fallback),
        }
    }
}

impl fmt::Display for SchemaFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.cause)?;
        if let Some(path) = &self.path {
            write!(formatter, " at {path}")?;
        }
        if let Some(location) = self.location {
            write!(formatter, " ({location})")?;
        }
        Ok(())
    }
}

/// Split a rendered decoder error into its schema path and its message.
///
/// `serde_norway` prefixes a message with the path to the offending value when
/// it knows one. The candidate prefix is accepted only when it matches the
/// path grammar, which no message text can satisfy, so a message that merely
/// contains a colon never becomes a path.
fn split_schema_path(rendered: &str) -> (Option<String>, &str) {
    match rendered.split_once(": ") {
        Some((candidate, message)) if is_safe_schema_path(candidate) => {
            (Some(candidate.to_owned()), message)
        }
        _ => (None, rendered),
    }
}

/// Accept only paths built from mapping keys and numeric sequence indices.
///
/// Mapping keys are structural names in a reviewed bundle, never values, and
/// this grammar admits no whitespace, quoting, or punctuation that a quoted
/// scalar would carry.
fn is_safe_schema_path(candidate: &str) -> bool {
    if candidate.is_empty() || candidate.len() > MAX_SCHEMA_PATH_BYTES {
        return false;
    }
    let mut index_digits: Option<usize> = None;
    for character in candidate.chars() {
        match index_digits {
            Some(digits) => match character {
                '0'..='9' => index_digits = Some(digits + 1),
                ']' if digits > 0 => index_digits = None,
                _ => return false,
            },
            None => match character {
                '[' => index_digits = Some(0),
                '.' | '-' | '_' | '?' => {}
                _ if character.is_ascii_alphanumeric() => {}
                _ => return false,
            },
        }
    }
    index_digits.is_none()
}

/// Map a decoder message to one static cause, reading only its fixed prefix.
fn classify_decode_cause(message: &str, fallback: &'static str) -> &'static str {
    DECODE_CAUSES
        .iter()
        .find(|(prefix, _)| message.starts_with(prefix))
        .map_or(fallback, |(_, cause)| cause)
}

/// Decode one YAML document into a closed typed schema.
///
/// The bytes are parsed as untyped YAML first so that a syntax failure is
/// reported as a syntax failure rather than as a schema mismatch.
fn decode_yaml<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, ConfigError> {
    if let Err(error) = serde_norway::from_str::<YamlValue>(text) {
        return Err(ConfigError::InvalidYaml(SchemaFault::from_yaml_error(
            &error,
            "document is not well-formed YAML",
        )));
    }
    serde_norway::from_str(text).map_err(|error| {
        ConfigError::InvalidYaml(SchemaFault::from_yaml_error(
            &error,
            "document does not match the closed schema",
        ))
    })
}

/// A mapping that rejects duplicate keys and preserves declaration order.
///
/// Selector declaration order is part of canonical selector encoding, so a
/// sorted map is not sufficient for this contract.
#[derive(Clone, Eq, PartialEq)]
pub struct OrderedMap<T>(Vec<(String, T)>);

impl<T> Default for OrderedMap<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> OrderedMap<T> {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, key: &str) -> Option<&T> {
        self.0
            .iter()
            .find_map(|(candidate, value)| (candidate == key).then_some(value))
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &T)> {
        self.0.iter().map(|(key, value)| (key.as_str(), value))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(key, _)| key.as_str())
    }
}

impl<T: fmt::Debug> fmt::Debug for OrderedMap<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_map()
            .entries(self.0.iter().map(|(key, value)| (key, value)))
            .finish()
    }
}

impl<'de, T> Deserialize<'de> for OrderedMap<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OrderedMapVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T> Visitor<'de> for OrderedMapVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = OrderedMap<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a mapping with unique string keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries = Vec::with_capacity(map.size_hint().unwrap_or(0));
                let mut seen = BTreeSet::new();
                while let Some((key, value)) = map.next_entry::<String, T>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate mapping key"));
                    }
                    entries.push((key, value));
                }
                Ok(OrderedMap(entries))
            }
        }

        deserializer.deserialize_map(OrderedMapVisitor(std::marker::PhantomData))
    }
}

impl<T: Serialize> Serialize for OrderedMap<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceConfig {
    pub version: u8,
    /// The governed assurance boundary for this immutable bundle.
    pub assurance_profile: AssuranceProfile,
    pub service: ServiceConfig,
    pub issuer: IssuerConfig,
    pub authentication: AuthenticationConfig,
    pub audit: AuditConfig,
    pub subject_binding: SubjectBindingConfig,
    pub rate_limits: RateLimitConfig,
    pub signing: SigningConfig,
    /// Closed enabled response formats for the whole immutable bundle. Signed
    /// flattened JWS is mandatory and the default; unsigned JSON must be
    /// enabled here and permitted by the complete matched grant.
    #[serde(default = "default_response_formats")]
    pub response_formats: Vec<ResponseFormat>,
    pub selector_profiles: OrderedMap<SelectorProfile>,
    pub sources: OrderedMap<SourceConfig>,
    pub authority_profiles: OrderedMap<AuthorityProfile>,
    /// Acquisition kinds this bundle opts in to beyond the single fixed call.
    /// A kind absent from this list cannot be served, so an existing bundle
    /// keeps serving exactly what it served before. The list is omitted when
    /// empty because the projected configuration is what a requirement's
    /// `configurationRevision` digests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acquisition_capabilities: Vec<String>,
    pub requirements: Vec<RequirementConfig>,
}

/// The declared assurance boundary travels with every response, so the
/// portable `registry-evidence-verifier` crate owns it and configuration serves
/// it at the runtime's own path.
pub use registry_evidence_verifier::AssuranceProfile;

pub type SourceSelectorSet = Vec<(String, String)>;

impl EvidenceConfig {
    pub fn requirement_acquisition_posture(
        &self,
        requirement_id: &str,
    ) -> Option<AcquisitionPosture> {
        let requirement = self
            .requirements
            .iter()
            .find(|requirement| requirement.id == requirement_id)?;
        requirement
            .acquisition
            .source_ids()
            .into_iter()
            .filter_map(|source_id| self.sources.get(source_id).map(|source| source.posture))
            .reduce(AcquisitionPosture::weakest)
    }

    pub fn parse_yaml(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ConfigError::InvalidYaml(SchemaFault::because("document is not UTF-8")))?;
        let config: Self = decode_yaml(text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return invalid("version must equal 1");
        }
        validate_uri(&self.service.provider_id)?;
        validate_uri(&self.service.trust_domain)?;
        validate_uri(&self.issuer.id)?;
        self.authentication.validate(self.assurance_profile)?;
        self.audit.validate()?;
        self.subject_binding.validate()?;
        if self.audit.hash_secret_ref == self.subject_binding.secret_ref {
            return invalid("audit and subject-binding secret references must be distinct");
        }
        self.rate_limits.validate()?;
        self.signing.validate()?;
        validate_response_formats(&self.response_formats, "bundle response formats")?;
        if self.assurance_profile != AssuranceProfile::Local
            && self.response_formats.contains(&ResponseFormat::SdJwtVc)
        {
            validate_https_origin(&self.service.provider_id)?;
        }
        validate_named_map(&self.selector_profiles, 1, 128, |profile| {
            profile.validate()
        })?;
        validate_named_map(&self.sources, 1, 128, |source| {
            source.validate(self.assurance_profile)
        })?;
        validate_named_map(&self.authority_profiles, 1, 128, |profile| {
            profile.validate()
        })?;
        validate_len(self.requirements.len(), 1, 128, "requirements")?;

        let mut requirement_ids = BTreeSet::new();
        let mut evidence_types = BTreeSet::new();
        let mut concept_ids = BTreeSet::new();
        let mut disclosure_families = BTreeSet::new();
        // One artifact carries one schema role for the whole bundle: reviewing
        // it as a response contract must not silently also accept it as a fact
        // or adapter-parameter contract somewhere else.
        let response_schemas = self
            .sources
            .iter()
            .map(|(_, source)| source.response_schema.as_str())
            .collect::<BTreeSet<_>>();
        let fact_schemas = self
            .sources
            .iter()
            .map(|(_, source)| source.fact_schema.as_str())
            .collect::<BTreeSet<_>>();
        let parameter_schemas = self
            .sources
            .iter()
            .map(|(_, source)| source.request.adapter_parameters_schema.as_str())
            .collect::<BTreeSet<_>>();
        if !fact_schemas.is_disjoint(&parameter_schemas)
            || !response_schemas.is_disjoint(&fact_schemas)
            || !response_schemas.is_disjoint(&parameter_schemas)
        {
            return invalid("source schema roles must not overlap across sources");
        }
        for requirement in &self.requirements {
            requirement.validate()?;
            if self.assurance_profile.requires_fixtures() && requirement.fixtures.is_none() {
                return invalid("production and evidence-grade requirements must declare fixtures");
            }
            if !requirement_ids.insert(requirement.id.as_str()) {
                return invalid("requirement identifiers must be unique");
            }
            if !evidence_types.insert(requirement.evidence_type.as_str()) {
                return invalid("Evidence Type identifiers must be unique");
            }
            for concept in &requirement.concepts {
                if !concept_ids.insert(concept.id.as_str()) {
                    return invalid("concept identifiers must be unique");
                }
            }
            for family in &requirement.disclosure_guard.families {
                if !disclosure_families.insert(family.as_str()) {
                    return invalid("enabled requirements share a disclosure family");
                }
            }
        }

        self.validate_acquisition_capabilities()?;
        self.validate_cross_references()
    }

    /// A bundle serves the fetch-set acquisition only where it declared it, so
    /// adding the form to the runtime cannot widen what an already-deployed
    /// bundle does. The forms that predate the declaration keep serving
    /// without one.
    fn validate_acquisition_capabilities(&self) -> Result<(), ConfigError> {
        let declared = declared_acquisition_capabilities(
            &self.acquisition_capabilities,
            "bundle acquisition capabilities name an unknown acquisition kind",
            "bundle acquisition capabilities must be unique",
            "bundle acquisition capabilities",
        )?;
        for requirement in &self.requirements {
            if requirement
                .acquisition
                .required_capability()
                .is_some_and(|capability| !declared.contains(capability))
            {
                return invalid("requirement acquisition kind is not a declared bundle capability");
            }
        }
        Ok(())
    }

    /// Return the complete selector tuple sets that an authorized request may
    /// activate for one source. The configuration has already proven that
    /// every grant is complete and references the named requirement source.
    pub fn source_selector_sets(&self, source_id: &str) -> Vec<SourceSelectorSet> {
        let Some(source) = self.sources.get(source_id) else {
            return Vec::new();
        };
        let requirement_sources = self
            .requirements
            .iter()
            .filter(|requirement| requirement.acquisition.uses_source(source_id))
            .map(|requirement| requirement.id.as_str())
            .collect::<BTreeSet<_>>();
        let mut sets = BTreeSet::new();
        for (_, authority) in self.authority_profiles.iter() {
            for grant in &authority.grants {
                if !requirement_sources.contains(grant.requirement.as_str()) {
                    continue;
                }
                let mut set = grant
                    .subjects
                    .iter()
                    .filter(|subject| {
                        source.request.selector_inputs.iter().any(|input| {
                            input.role == subject.role
                                && input.alternatives.iter().any(|alternative| {
                                    alternative.profile == subject.selector_profile
                                })
                        })
                    })
                    .map(|subject| (subject.role.clone(), subject.selector_profile.clone()))
                    .collect::<SourceSelectorSet>();
                if set.is_empty() && !source.request.selector_inputs.is_empty() {
                    continue;
                }
                set.sort();
                sets.insert(set);
            }
        }
        sets.into_iter().collect()
    }

    fn validate_cross_references(&self) -> Result<(), ConfigError> {
        for (_, source) in self.sources.iter() {
            for input in &source.request.selector_inputs {
                for alternative in &input.alternatives {
                    let profile = self.selector_profiles.get(&alternative.profile).ok_or(
                        ConfigError::Invalid(
                            "source selector input references an unknown selector profile",
                        ),
                    )?;
                    if alternative
                        .fields
                        .iter()
                        .any(|field| !profile.fields.contains_key(field))
                    {
                        return invalid(
                            "source selector input references an unknown selector field",
                        );
                    }
                }
            }
            for (_, binding) in source.request.path_bindings.iter() {
                if let PathBindingConfig::Selector {
                    role,
                    profile,
                    field,
                } = binding
                {
                    let profile_config =
                        self.selector_profiles
                            .get(profile)
                            .ok_or(ConfigError::Invalid(
                                "source path binding references an unknown selector profile",
                            ))?;
                    if !profile_config.fields.contains_key(field) {
                        return invalid("source path binding references an unknown selector field");
                    }
                    if !source.request.selector_inputs.iter().any(|input| {
                        input.role == *role
                            && input.alternatives.iter().any(|alternative| {
                                alternative.profile == *profile
                                    && alternative.fields.contains(field)
                            })
                    }) {
                        return invalid("source path binding is not declared as a selector input");
                    }
                }
            }
        }

        let initial_sources = self
            .requirements
            .iter()
            .map(|requirement| requirement.acquisition.initial_source())
            .collect::<BTreeSet<_>>();
        let fetch_sources = self
            .requirements
            .iter()
            .flat_map(|requirement| requirement.acquisition.fetch_sources())
            .collect::<BTreeSet<_>>();
        for (source_id, source) in self.sources.iter() {
            if initial_sources.contains(source_id) && source.request.selector_inputs.is_empty() {
                return invalid("single and search sources must declare selector inputs");
            }
            if source
                .request
                .path_bindings
                .iter()
                .map(|(_, binding)| binding)
                .any(PathBindingConfig::is_prior_fact)
                && (!fetch_sources.contains(source_id) || initial_sources.contains(source_id))
            {
                return invalid("prior-fact path bindings are permitted only on fetch sources");
            }
        }

        for requirement in &self.requirements {
            for source_id in requirement.acquisition.source_ids() {
                if !self.sources.contains_key(source_id) {
                    return invalid("requirement acquisition references an unknown source");
                }
            }
            if requirement.validity_seconds > self.signing.maximum_assertion_validity_seconds {
                return invalid("requirement validity exceeds signing maximum validity");
            }
            for role in &requirement.subject_roles {
                for profile_id in &role.selector_profiles {
                    self.selector_profiles
                        .get(profile_id)
                        .ok_or(ConfigError::Invalid(
                            "requirement references an unknown selector profile",
                        ))?;
                }
            }
            validate_derivation_selector_inputs(requirement, &self.selector_profiles)?;
        }

        let requirements = self
            .requirements
            .iter()
            .map(|requirement| (requirement.id.as_str(), requirement))
            .collect::<BTreeMap<_, _>>();
        let mut authorized_combinations = BTreeSet::new();
        let mut source_selector_sets: BTreeMap<String, BTreeSet<SourceSelectorSet>> =
            BTreeMap::new();
        for (_, authority) in self.authority_profiles.iter() {
            for grant in &authority.grants {
                let requirement =
                    requirements
                        .get(grant.requirement.as_str())
                        .ok_or(ConfigError::Invalid(
                            "authority grant references an unknown requirement",
                        ))?;
                if !requirement
                    .purposes
                    .iter()
                    .any(|purpose| purpose == &grant.purpose)
                {
                    return invalid("authority grant references an unauthorized purpose");
                }
                if grant.subjects.len() != requirement.subject_roles.len() {
                    return invalid("authority grant must bind the complete subject-role set");
                }
                let mut seen_roles = BTreeSet::new();
                for subject in &grant.subjects {
                    if !seen_roles.insert(subject.role.as_str()) {
                        return invalid("authority grant subject roles must be unique");
                    }
                    let role = requirement
                        .subject_roles
                        .iter()
                        .find(|role| role.role == subject.role)
                        .ok_or(ConfigError::Invalid(
                            "authority grant references an unknown subject role",
                        ))?;
                    if !role
                        .selector_profiles
                        .iter()
                        .any(|profile| profile == &subject.selector_profile)
                    {
                        return invalid("authority grant selector profile is not allowed for role");
                    }
                    let profile = self
                        .selector_profiles
                        .get(&subject.selector_profile)
                        .ok_or(ConfigError::Invalid(
                            "authority grant references an unknown selector profile",
                        ))?;
                    subject.validate_value_claims(profile)?;
                    authorized_combinations.insert((
                        grant.requirement.as_str(),
                        grant.purpose.as_str(),
                        subject.role.as_str(),
                        subject.selector_profile.as_str(),
                    ));
                }
                if requirement
                    .subject_roles
                    .iter()
                    .any(|role| !seen_roles.contains(role.role.as_str()))
                {
                    return invalid("authority grant omits a required subject role");
                }
                for source_id in requirement.acquisition.source_ids() {
                    let source = self.sources.get(source_id).ok_or(ConfigError::Invalid(
                        "requirement acquisition references an unknown source",
                    ))?;
                    let mut source_selector_set = grant
                        .subjects
                        .iter()
                        .filter(|subject| {
                            source.request.selector_inputs.iter().any(|input| {
                                input.role == subject.role
                                    && input.alternatives.iter().any(|alternative| {
                                        alternative.profile == subject.selector_profile
                                    })
                            })
                        })
                        .map(|subject| (subject.role.clone(), subject.selector_profile.clone()))
                        .collect::<SourceSelectorSet>();
                    if source_selector_set.is_empty() && !source.request.selector_inputs.is_empty()
                    {
                        return invalid(
                            "authority path does not activate any declared source selector input",
                        );
                    }
                    source_selector_set.sort();
                    source_selector_sets
                        .entry(source_id.to_owned())
                        .or_default()
                        .insert(source_selector_set);
                }
            }
        }

        for requirement in &self.requirements {
            for purpose in &requirement.purposes {
                for role in &requirement.subject_roles {
                    for profile in &role.selector_profiles {
                        if !authorized_combinations.contains(&(
                            requirement.id.as_str(),
                            purpose.as_str(),
                            role.role.as_str(),
                            profile.as_str(),
                        )) {
                            return invalid(
                                "requirement role and selector profile lack an authority path",
                            );
                        }
                    }
                }
            }
        }
        self.validate_source_selector_sets(&source_selector_sets)?;
        Ok(())
    }

    fn validate_source_selector_sets(
        &self,
        allowed: &BTreeMap<String, BTreeSet<SourceSelectorSet>>,
    ) -> Result<(), ConfigError> {
        for (source_id, source) in self.sources.iter() {
            let sets = allowed.get(source_id).ok_or(ConfigError::Invalid(
                "configured source is unreachable from every authority grant",
            ))?;
            let reachable = sets
                .iter()
                .flatten()
                .map(|(role, profile)| (role.as_str(), profile.as_str()))
                .collect::<BTreeSet<_>>();
            if source.request.selector_inputs.iter().any(|input| {
                input.alternatives.iter().any(|alternative| {
                    !reachable.contains(&(input.role.as_str(), alternative.profile.as_str()))
                })
            }) {
                return invalid(
                    "source selector input is unreachable from every complete authority path",
                );
            }
        }
        Ok(())
    }
}

fn validate_https_origin(value: &str) -> Result<(), ConfigError> {
    let url = Url::parse(value)
        .map_err(|_| ConfigError::Invalid("service providerId is not a stable HTTPS origin"))?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || value.ends_with('/')
    {
        return invalid("SD-JWT VC requires service.providerId to be a stable HTTPS origin");
    }
    Ok(())
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceConfig {
    pub provider_id: String,
    pub trust_domain: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    pub id: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub version: u8,
    pub bundle_directory: String,
    pub listener: ListenerConfig,
    /// Optional operator-only metrics listener. Absent means the deployment
    /// serves no metrics endpoint at all, which is the default posture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_listener: Option<MetricsListenerConfig>,
    pub secret_providers: RuntimeSecretProviders,
    /// Process-local binding to the signer that controls the governed active
    /// public key. This cannot change the governed key set or algorithm.
    pub signer: RuntimeSignerConfig,
    pub audit_storage: AuditStorageConfig,
    pub outbound_tls: OutboundTlsConfig,
    /// Acquisition kinds this deployment enables beyond the frozen Version 1
    /// forms. Absent enables none of them, which is what every runtime file
    /// written before a gated form existed says, so adopting a form is a
    /// deliberate operator decision rather than a consequence of the bundle
    /// that arrived. A bundle requiring a kind absent here is refused before
    /// the deployment serves anything.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acquisition_capabilities: Vec<String>,
}

impl RuntimeConfig {
    pub fn parse_yaml(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ConfigError::InvalidYaml(SchemaFault::because("document is not UTF-8")))?;
        let config: Self = decode_yaml(text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return invalid("runtime version must equal 1");
        }
        validate_absolute_path(&self.bundle_directory)?;
        self.listener.validate()?;
        if let Some(metrics) = &self.metrics_listener {
            metrics.validate(&self.listener)?;
        }
        self.secret_providers.validate()?;
        self.signer.validate()?;
        self.audit_storage.validate()?;
        self.outbound_tls.validate()?;
        declared_acquisition_capabilities(
            &self.acquisition_capabilities,
            "runtime acquisition capabilities name an unknown acquisition kind",
            "runtime acquisition capabilities must be unique",
            "runtime acquisition capabilities",
        )?;
        Ok(())
    }

    /// Whether the operator enabled one gated acquisition kind on this
    /// deployment. The answer is read only through the enabled list, so a
    /// deployment that says nothing enables nothing.
    pub fn enables_acquisition_capability(&self, capability: &str) -> bool {
        self.acquisition_capabilities
            .iter()
            .any(|enabled| enabled == capability)
    }
}

/// Closed process-local signer binding. Production deployments reach Transit
/// only over a workload-local Unix socket and never receive a provider token.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeSignerConfig {
    LocalJwk {
        #[serde(rename = "privateKeyRef")]
        private_key_ref: SecretRef,
    },
    Transit {
        #[serde(rename = "unixSocketPath")]
        unix_socket_path: String,
        mount: String,
        #[serde(rename = "keyName")]
        key_name: String,
        #[serde(rename = "keyVersion")]
        key_version: u32,
        #[serde(rename = "timeoutMilliseconds")]
        timeout_milliseconds: u64,
    },
}

impl RuntimeSignerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::LocalJwk { .. } => Ok(()),
            Self::Transit {
                unix_socket_path,
                mount,
                key_name,
                key_version,
                timeout_milliseconds,
            } => {
                validate_absolute_path(unix_socket_path)?;
                if !valid_local_id(mount) || !valid_local_id(key_name) {
                    return invalid("Transit signer mount and keyName must be local identifiers");
                }
                if *key_version == 0 {
                    return invalid("Transit signer keyVersion must be positive");
                }
                validate_range(
                    *timeout_milliseconds,
                    1,
                    30_000,
                    "Transit signer timeoutMilliseconds",
                )
            }
        }
    }

    pub fn is_local_jwk(&self) -> bool {
        matches!(self, Self::LocalJwk { .. })
    }

    pub fn is_transit(&self) -> bool {
        matches!(self, Self::Transit { .. })
    }

    pub fn private_key_ref(&self) -> Option<&SecretRef> {
        match self {
            Self::LocalJwk { private_key_ref } => Some(private_key_ref),
            Self::Transit { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSecretProviders {
    pub file: FileSecretProvider,
}

impl RuntimeSecretProviders {
    fn validate(&self) -> Result<(), ConfigError> {
        self.file.validate()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileSecretProvider {
    pub root: String,
}

impl FileSecretProvider {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_absolute_path(&self.root)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditStorageConfig {
    pub path: String,
    pub maximum_file_bytes: u64,
}

impl AuditStorageConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_absolute_path(&self.path)?;
        validate_range(
            self.maximum_file_bytes,
            1_048_576,
            1_099_511_627_776,
            "audit maximumFileBytes",
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutboundTlsConfig {
    pub system_roots: bool,
    pub trust_profiles: OrderedMap<TrustProfileBinding>,
}

impl OutboundTlsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.system_roots {
            return invalid("outbound TLS system roots must remain enabled");
        }
        validate_named_map(&self.trust_profiles, 0, 64, TrustProfileBinding::validate)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustProfileBinding {
    pub ca_bundle_file: String,
}

impl TrustProfileBinding {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_absolute_path(&self.ca_bundle_file)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerConfig {
    pub bind_host: String,
    pub port: u16,
    pub tls_termination: TlsTermination,
    pub trust_proxy_identity_headers: bool,
    pub maximum_request_bytes: u64,
    pub maximum_concurrent_requests: u32,
    pub request_timeout_milliseconds: u64,
    pub shutdown_grace_milliseconds: u64,
}

impl ListenerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_private_bind_host(&self.bind_host)?;
        validate_listener_port(self.port)?;
        if self.trust_proxy_identity_headers {
            return invalid("proxy identity headers must not be trusted");
        }
        validate_range(
            self.maximum_request_bytes,
            1_024,
            1_048_576,
            "maximumRequestBytes",
        )?;
        validate_range(
            u64::from(self.maximum_concurrent_requests),
            1,
            4_096,
            "maximumConcurrentRequests",
        )?;
        validate_range(
            self.request_timeout_milliseconds,
            1,
            30_000,
            "requestTimeoutMilliseconds",
        )?;
        validate_range(
            self.shutdown_grace_milliseconds,
            1,
            120_000,
            "shutdownGraceMilliseconds",
        )
    }
}

/// Operator-only telemetry listener.
///
/// It is a separate binding rather than a route on the evidence listener so
/// that reaching the counters requires reaching a different socket. It carries
/// no request limits of its own: it serves one static rendering of in-process
/// counters, reads no request body, and touches no source or signing material.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricsListenerConfig {
    pub bind_host: String,
    pub port: u16,
}

impl MetricsListenerConfig {
    fn validate(&self, evidence_listener: &ListenerConfig) -> Result<(), ConfigError> {
        validate_private_bind_host(&self.bind_host)?;
        validate_listener_port(self.port)?;
        // Sharing the evidence binding would publish the counters on the
        // listener the public contract describes, which is the separation this
        // block exists to enforce.
        if self.bind_host == evidence_listener.bind_host && self.port == evidence_listener.port {
            return invalid("metricsListener must not share the evidence listener binding");
        }
        Ok(())
    }
}

/// Refuse port 0, which asks the kernel for an arbitrary ephemeral port rather
/// than naming one.
///
/// Every listener here is an operator-network binding that something upstream
/// firewalls, health-checks, or terminates TLS for, and none of that can follow
/// a port that is chosen at bind time and changes on every restart. The
/// published runtime schema already states the bound, so this is the loader
/// agreeing with the contract an operator validated against.
fn validate_listener_port(port: u16) -> Result<(), ConfigError> {
    validate_range(u64::from(port), 1, 65_535, "port")
}

/// Accept only numeric loopback, RFC 1918 private IPv4, and RFC 4193
/// unique-local IPv6 bindings. Every listener this service opens is an
/// operator-network listener; TLS and exposure are upstream concerns.
fn validate_private_bind_host(bind_host: &str) -> Result<(), ConfigError> {
    if bind_host.len() < 2 || bind_host.len() > 64 {
        return invalid("listener bindHost length is invalid");
    }
    let ip: IpAddr = bind_host
        .parse()
        .map_err(|_| ConfigError::Invalid("listener bindHost must be a private numeric IP"))?;
    let private = match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback() || is_unique_local(ip),
    };
    if !private || ip.is_unspecified() || ip.is_multicast() {
        return invalid("listener bindHost must be loopback or private");
    }
    Ok(())
}

fn is_unique_local(ip: Ipv6Addr) -> bool {
    ip.octets()[0] & 0xfe == 0xfc
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsTermination {
    OperatorControlledUpstream,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticationConfig {
    pub kind: AuthenticationKind,
    pub issuer: String,
    pub audiences: Vec<String>,
    pub token_types: Vec<AccessTokenType>,
    pub algorithms: Vec<AccessTokenAlgorithm>,
    pub jwks_uri: String,
    pub principal_claim: String,
    pub requester_tags_claim: String,
    pub evidence_audience_claim: String,
    pub grant_id_claim: String,
    pub grant_authority_claim: String,
    /// Maximum lifetime accepted for inbound access tokens. The verifier
    /// requires `iat`, requires `exp > iat`, and applies this bound.
    pub maximum_token_lifetime_seconds: u64,
    /// Emergency denylist applied before JWKS cache selection.
    pub revoked_key_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_claim: Option<String>,
}

impl AuthenticationConfig {
    fn validate(&self, assurance_profile: AssuranceProfile) -> Result<(), ConfigError> {
        let issuer = Url::parse(&self.issuer)
            .map_err(|_| ConfigError::Invalid("authentication issuer is invalid"))?;
        let jwks_uri = Url::parse(&self.jwks_uri)
            .map_err(|_| ConfigError::Invalid("authentication JWKS URI is invalid"))?;
        if issuer.scheme() == "http" || jwks_uri.scheme() == "http" {
            if assurance_profile != AssuranceProfile::Local {
                return invalid("production and evidence-grade authentication requires HTTPS");
            }
            let origin = validate_local_mint_origin(&self.issuer)?;
            if self.jwks_uri != format!("{origin}{LOCAL_MINT_JWKS_PATH}") {
                return invalid(
                    "local authentication JWKS URI must use the issuer origin and Mint JWKS path",
                );
            }
        } else {
            validate_https_issuer(&self.issuer)?;
            validate_https_url(&self.jwks_uri, false)?;
        }
        validate_unique_strings(&self.audiences, 1, 16, 1, 512, "authentication audiences")?;
        validate_unique(&self.token_types, 1, 4, "authentication tokenTypes")?;
        validate_unique(&self.algorithms, 1, 3, "authentication algorithms")?;
        validate_range(
            self.maximum_token_lifetime_seconds,
            1,
            86_400,
            "authentication maximumTokenLifetimeSeconds",
        )?;
        validate_unique_strings(
            &self.revoked_key_ids,
            0,
            32,
            1,
            256,
            "authentication revokedKeyIds",
        )?;
        if self
            .revoked_key_ids
            .iter()
            .any(|kid| kid.chars().any(char::is_control))
        {
            return invalid("authentication revokedKeyIds contain a control character");
        }
        // Ordered principal first, because `sub` is legitimate for that claim
        // alone and the shadowing check below reads the rest of the list.
        let claims = [
            Some(&self.principal_claim),
            Some(&self.requester_tags_claim),
            Some(&self.evidence_audience_claim),
            Some(&self.grant_id_claim),
            Some(&self.grant_authority_claim),
            self.actor_claim.as_ref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        for claim in &claims {
            validate_claim_name(claim)?;
        }
        // Two claims naming one member means the same value is read as two
        // different things: requester tags read as a principal, or a grant id
        // read as the authority that granted it.
        if claims.iter().collect::<BTreeSet<_>>().len() != claims.len() {
            return invalid("authority claim names must be distinct");
        }
        // These are defined by the token itself, so reading authority out of one
        // reads something the issuer wrote for another purpose. `aud` is the
        // sharpest: Evidence validates it against its own configured audiences,
        // so a grant authority read from `aud` is Evidence's own name.
        //
        // `sub` is the exception, and only for the principal. It carries the
        // principal already, so naming it there reads the same value; naming it
        // anywhere else reads the principal as something it is not.
        if claims
            .iter()
            .any(|claim| REGISTERED_JWT_CLAIMS.contains(&claim.as_str()))
            || claims.iter().skip(1).any(|claim| claim.as_str() == "sub")
        {
            return invalid("authority claim names must not shadow registered JWT claims");
        }
        Ok(())
    }

    pub(crate) fn uses_local_mint_http(&self, assurance_profile: AssuranceProfile) -> bool {
        assurance_profile == AssuranceProfile::Local
            && validate_local_mint_origin(&self.issuer).is_ok()
            && self.jwks_uri == format!("{}{}", self.issuer, LOCAL_MINT_JWKS_PATH)
    }
}

/// Registered JWT claims no authority claim may be read from. `sub` is handled
/// separately, because the principal claim may legitimately name it.
///
/// Mint refuses to write these when it mints. Evidence refuses to read them,
/// which is the check that still applies when the issuer is not Mint.
///
/// `cnf` is reserved for a second reason: the authenticator denies any token
/// carrying it, because Version 1 validates no proof of possession and will not
/// downgrade a sender-constrained token to a bearer one. Naming it here would
/// otherwise produce a deployment that loads and checks clean but answers 401 to
/// every authenticated request.
const REGISTERED_JWT_CLAIMS: [&str; 8] =
    ["iss", "aud", "exp", "iat", "nbf", "jti", "client_id", "cnf"];

const LOCAL_MINT_JWKS_PATH: &str = "/.well-known/jwks.json";

fn validate_local_mint_origin(value: &str) -> Result<&str, ConfigError> {
    let port = value
        .strip_prefix("http://127.0.0.1:")
        .filter(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .filter(|port| !port.starts_with('0'))
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or(ConfigError::Invalid(
            "local authentication issuer must be a canonical 127.0.0.1 HTTP origin with an explicit non-zero port",
        ))?;
    if value != format!("http://127.0.0.1:{port}") {
        return invalid(
            "local authentication issuer must be a canonical 127.0.0.1 HTTP origin with an explicit non-zero port",
        );
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticationKind {
    OidcAccessToken,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum AccessTokenType {
    #[serde(rename = "at+jwt")]
    AtJwt,
    #[serde(rename = "application/at+jwt")]
    ApplicationAtJwt,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum AccessTokenAlgorithm {
    EdDSA,
    ES256,
    RS256,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretProvider {
    Environment,
    File,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct SecretRef(String);

impl SecretRef {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        if let Some(name) = value.strip_prefix("secret:file/") {
            if valid_file_secret_name(name) {
                return Ok(Self(value.to_owned()));
            }
        }
        invalid("secret reference does not use an exact permitted grammar")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn provider(&self) -> SecretProvider {
        SecretProvider::File
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SecretRef").field(&self.0).finish()
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

impl Serialize for SecretRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

fn valid_file_secret_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 128
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    pub format: AuditFormat,
    pub hash_secret_ref: SecretRef,
    pub hash_key_version: u32,
    pub fail_closed: bool,
}

impl AuditConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.hash_key_version == 0 || !self.fail_closed {
            return invalid("audit must be versioned and fail closed");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditFormat {
    KeyedJsonl,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectBindingConfig {
    pub secret_ref: SecretRef,
    pub key_version: u32,
}

impl SubjectBindingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.key_version == 0 {
            return invalid("subject binding keyVersion must be positive");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitConfig {
    pub requests_per_principal_per_minute: u64,
    pub burst_per_principal: u64,
    pub failed_selector_attempts_per_principal_authority_per_minute: u64,
}

impl RateLimitConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_range(
            self.requests_per_principal_per_minute,
            1,
            1_000_000,
            "request rate limit",
        )?;
        validate_range(self.burst_per_principal, 1, 100_000, "burst rate limit")?;
        validate_range(
            self.failed_selector_attempts_per_principal_authority_per_minute,
            1,
            100_000,
            "failed-selector rate limit",
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigningConfig {
    pub format: SigningFormat,
    pub algorithm: SigningAlgorithm,
    pub active_public_jwk_file: PublicJwkPath,
    pub published_public_jwk_files: Vec<PublicJwkPath>,
    pub revoked_key_ids: Vec<String>,
    pub jwks_path: String,
    pub maximum_assertion_validity_seconds: u64,
    pub verifier_clock_skew_seconds: u64,
}

impl SigningConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_unique(
            &self.published_public_jwk_files,
            0,
            32,
            "published public JWK paths",
        )?;
        if self
            .published_public_jwk_files
            .iter()
            .any(|path| path == &self.active_public_jwk_file)
        {
            return invalid("the active public JWK file must not also be published");
        }
        validate_key_identifiers(&self.revoked_key_ids, 33, "signing revokedKeyIds")?;
        if self.jwks_path != "/.well-known/evidence/jwks.json" {
            return invalid("JWKS path is not the Version 1 discovery path");
        }
        validate_range(
            self.maximum_assertion_validity_seconds,
            1,
            31_536_000,
            "maximum assertion validity",
        )?;
        // The same bound the relying party's `clockSkewSeconds` carries: an
        // advertised skew a conformant verification policy cannot express would
        // be unusable advice. Widening either one alone is a contract change.
        validate_range(
            self.verifier_clock_skew_seconds,
            0,
            300,
            "verifier clock skew",
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningFormat {
    FlattenedJwsJson,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum SigningAlgorithm {
    ES256,
}

fn validate_key_identifiers(
    identifiers: &[String],
    maximum: usize,
    label: &'static str,
) -> Result<(), ConfigError> {
    validate_unique_strings(identifiers, 0, maximum, 43, 43, label)?;
    if identifiers.iter().any(|identifier| {
        let alphabet_is_valid = identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
        let encoding_is_canonical = URL_SAFE_NO_PAD.decode(identifier).is_ok_and(|decoded| {
            decoded.len() == 32 && URL_SAFE_NO_PAD.encode(&decoded) == *identifier
        });
        !alphabet_is_valid || !encoding_is_canonical
    }) {
        return invalid("key identifiers must be RFC 7638 SHA-256 thumbprints");
    }
    Ok(())
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct PublicJwkPath(String);

impl PublicJwkPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PublicJwkPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PublicJwkPath")
            .field(&self.0)
            .finish()
    }
}

impl<'de> Deserialize<'de> for PublicJwkPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if is_public_jwk_path(&value) {
            Ok(Self(value))
        } else {
            Err(de::Error::custom("invalid public JWK path"))
        }
    }
}

impl Serialize for PublicJwkPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

fn is_public_jwk_path(value: &str) -> bool {
    let Some(name) = value.strip_prefix("public-keys/") else {
        return false;
    };
    let Some(stem) = name.strip_suffix(".jwk.json") else {
        return false;
    };
    !stem.is_empty()
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectorProfile {
    pub maximum_aggregate_bytes: u64,
    pub fields: OrderedMap<SelectorField>,
}

impl SelectorProfile {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_range(
            self.maximum_aggregate_bytes,
            1,
            8_192,
            "selector maximumAggregateBytes",
        )?;
        validate_len(self.fields.len(), 1, 16, "selector fields")?;
        for (name, field) in self.fields.iter() {
            if !valid_field_name(name) {
                return invalid("selector field name is invalid");
            }
            field.validate(self.maximum_aggregate_bytes)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SelectorField {
    String {
        #[serde(rename = "minimumBytes")]
        minimum_bytes: u64,
        #[serde(rename = "maximumBytes")]
        maximum_bytes: u64,
    },
    Date,
    Integer {
        minimum: i64,
        maximum: i64,
    },
    Boolean,
    ControlledCode {
        codelist: ArtifactPath,
        #[serde(rename = "codelistVersion")]
        codelist_version: String,
        #[serde(rename = "maximumBytes")]
        maximum_bytes: u64,
    },
}

impl SelectorField {
    fn validate(&self, aggregate_maximum: u64) -> Result<(), ConfigError> {
        match self {
            Self::String {
                minimum_bytes,
                maximum_bytes,
            } => {
                validate_range(*minimum_bytes, 1, 8_192, "selector string minimumBytes")?;
                validate_range(*maximum_bytes, 1, 8_192, "selector string maximumBytes")?;
                if minimum_bytes > maximum_bytes || maximum_bytes > &aggregate_maximum {
                    return invalid("selector string byte bounds are inconsistent");
                }
            }
            Self::Integer { minimum, maximum } => {
                if minimum > maximum || *minimum < -MAX_SAFE_INTEGER || *maximum > MAX_SAFE_INTEGER
                {
                    return invalid("selector integer bounds are inconsistent");
                }
            }
            Self::ControlledCode {
                codelist,
                codelist_version,
                maximum_bytes,
            } => {
                require_artifact_prefix(codelist, "codelists/")?;
                validate_string(codelist_version, 1, 128, "selector codelist version")?;
                validate_range(*maximum_bytes, 1, 8_192, "selector code maximumBytes")?;
                if maximum_bytes > &aggregate_maximum {
                    return invalid("selector code exceeds aggregate byte bound");
                }
            }
            Self::Date | Self::Boolean => {}
        }
        Ok(())
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct ArtifactPath(String);

impl ArtifactPath {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        if !valid_artifact_path(value) {
            return invalid("artifact path is invalid");
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ArtifactPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ArtifactPath")
            .field(&self.0)
            .finish()
    }
}

impl<'de> Deserialize<'de> for ArtifactPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

impl Serialize for ArtifactPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

fn valid_artifact_path(value: &str) -> bool {
    const ROOTS: [&str; 5] = [
        "adapters/",
        "derivations/",
        "schemas/",
        "codelists/",
        "fixtures/",
    ];
    ROOTS.iter().any(|root| value.starts_with(root))
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceConfig {
    pub transport: SourceTransport,
    pub base_url: String,
    pub posture: AcquisitionPosture,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_trust_profile: Option<String>,
    pub authentication: SourceAuthentication,
    pub request: FixedRequest,
    /// Shape contract for the projected response, validated by Rust before
    /// extraction runs, so the script maps a response it can rely on.
    pub response_schema: ArtifactPath,
    pub extract_script: ArtifactPath,
    pub fact_schema: ArtifactPath,
}

impl SourceConfig {
    fn validate(&self, assurance_profile: AssuranceProfile) -> Result<(), ConfigError> {
        validate_source_origin(&self.base_url)?;
        if self
            .tls_trust_profile
            .as_deref()
            .is_some_and(|profile| !valid_local_id(profile))
        {
            return invalid("source TLS trust profile identifier is invalid");
        }
        if matches!(self.authentication, SourceAuthentication::None {}) {
            if assurance_profile != AssuranceProfile::Local {
                return invalid(
                    "unauthenticated sources are permitted only by the local assurance profile",
                );
            }
            validate_local_unauthenticated_source_origin(&self.base_url)?;
            if self.tls_trust_profile.is_some() {
                return invalid(
                    "an unauthenticated local HTTP source cannot use a TLS trust profile",
                );
            }
        }
        self.authentication.validate()?;
        self.request.validate()?;
        require_artifact_prefix(&self.extract_script, "adapters/")?;
        if !self.extract_script.as_str().ends_with(".rhai") {
            return invalid("source extraction script must be a Rhai file");
        }
        let adapter_id = Path::new(self.extract_script.as_str())
            .file_stem()
            .and_then(|value| value.to_str())
            .filter(|value| valid_local_id(value))
            .ok_or(ConfigError::Invalid(
                "source adapter name must be a local identifier",
            ))?;
        debug_assert!(!adapter_id.is_empty());
        require_artifact_prefix(&self.response_schema, "schemas/")?;
        require_artifact_prefix(&self.fact_schema, "schemas/")?;
        let roles = [
            self.response_schema.as_str(),
            self.fact_schema.as_str(),
            self.request.adapter_parameters_schema.as_str(),
        ];
        let distinct = roles.iter().collect::<BTreeSet<_>>();
        if distinct.len() != roles.len() {
            return invalid("source schema roles must be distinct artifacts");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceTransport {
    HttpJson,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcquisitionPosture {
    SourceDerived,
    FieldProjected,
    RecordTransformed,
}

impl AcquisitionPosture {
    /// Return the least-minimized posture in a bounded acquisition. A chained
    /// requirement may claim no stronger posture than either of its sources.
    pub fn weakest(self, other: Self) -> Self {
        use AcquisitionPosture::{FieldProjected, RecordTransformed, SourceDerived};
        match (self, other) {
            (RecordTransformed, _) | (_, RecordTransformed) => RecordTransformed,
            (FieldProjected, _) | (_, FieldProjected) => FieldProjected,
            (SourceDerived, SourceDerived) => SourceDerived,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SourceAuthentication {
    /// No outbound credential is sent.
    ///
    /// The containing bundle validator admits this only for the local
    /// assurance profile and a canonical numeric-loopback HTTP origin with an
    /// explicit non-zero port. It is not a production authentication mode.
    None {},
    Basic {
        #[serde(rename = "usernameRef")]
        username_ref: SecretRef,
        #[serde(rename = "passwordRef")]
        password_ref: SecretRef,
    },
    StaticAuthorization {
        #[serde(rename = "tokenRef")]
        token_ref: SecretRef,
        /// Authentication scheme the resolved token is presented under.
        ///
        /// RFC 9110 section 11.1 lets the origin choose the scheme, and
        /// `static-api-key` cannot reach the Authorization header because its
        /// header name is refused by the collision denylist. Absent, the
        /// runtime sends `Bearer`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
    },
    StaticApiKey {
        #[serde(rename = "headerName")]
        header_name: String,
        #[serde(rename = "valueRef")]
        value_ref: SecretRef,
    },
    Oauth2ClientCredentials {
        #[serde(rename = "tokenEndpoint")]
        token_endpoint: String,
        #[serde(rename = "clientIdRef")]
        client_id_ref: SecretRef,
        /// Shared client secret, for the RFC 6749 section 2.3.1 form.
        ///
        /// Present with `credentialPlacement` and without
        /// `clientAssertionKeyRef`, or absent with both.
        #[serde(
            rename = "clientSecretRef",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        client_secret_ref: Option<SecretRef>,
        /// Private JWK the client assertion is signed with, for the RFC 7523
        /// section 2.2 form.
        ///
        /// Its presence selects assertion authentication, which is the form
        /// SMART on FHIR Backend Services requires.
        #[serde(
            rename = "clientAssertionKeyRef",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        client_assertion_key_ref: Option<SecretRef>,
        /// Audience claim of the signed assertion; set only with
        /// `clientAssertionKeyRef`, and defaulting to `tokenEndpoint`.
        ///
        /// RFC 7523 section 3 asks only that the value identify the
        /// authorization server and leaves the exact string to out-of-band
        /// agreement, so a server reached through a proxy, or one naming its
        /// issuer identifier, expects a value the client never dials. The
        /// server compares it by Simple String Comparison, so it is an opaque
        /// identifier rather than a URL and travels to the claim byte for byte.
        #[serde(
            rename = "clientAssertionAudience",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        client_assertion_audience: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        /// Fixed `audience` form parameter.
        ///
        /// An authorization server may key the issued token to an audience the
        /// scope cannot express and return a token usable against nothing when
        /// it is absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
        /// Where the shared client secret travels; set only with
        /// `clientSecretRef`.
        #[serde(
            rename = "credentialPlacement",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        credential_placement: Option<CredentialPlacement>,
        #[serde(rename = "maximumCacheSeconds")]
        maximum_cache_seconds: u64,
        /// Lifetime assumed when the provider omits `expires_in`.
        ///
        /// RFC 6749 section 5.1 makes `expires_in` recommended rather than
        /// required, so a compliant provider may return only `access_token`
        /// and `token_type`. The operator states the lifetime here rather than
        /// the runtime inferring one from the token, and the cache is still
        /// clamped to `maximumCacheSeconds`.
        #[serde(
            rename = "assumedLifetimeSeconds",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        assumed_lifetime_seconds: Option<u64>,
    },
}

impl SourceAuthentication {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::None {} => Ok(()),
            Self::Basic {
                username_ref: _,
                password_ref: _,
            } => Ok(()),
            Self::StaticAuthorization {
                token_ref: _,
                scheme,
            } => {
                if let Some(scheme) = scheme {
                    validate_authorization_scheme(scheme)?;
                }
                Ok(())
            }
            Self::StaticApiKey {
                header_name,
                value_ref: _,
            } => validate_configurable_header_name(header_name),
            Self::Oauth2ClientCredentials {
                token_endpoint,
                client_secret_ref,
                client_assertion_key_ref,
                client_assertion_audience,
                scope,
                audience,
                credential_placement,
                maximum_cache_seconds,
                assumed_lifetime_seconds,
                ..
            } => {
                let token_endpoint = validate_source_url(token_endpoint, false)?;
                if token_endpoint.query().is_some() {
                    return invalid("OAuth token endpoint must not contain a query");
                }
                if client_secret_ref.is_some() == client_assertion_key_ref.is_some() {
                    return invalid(
                        "OAuth client authentication must declare either a client secret or a client assertion key",
                    );
                }
                if credential_placement.is_some() != client_secret_ref.is_some() {
                    return invalid(
                        "OAuth credential placement is required with a client secret and forbidden without one",
                    );
                }
                if client_assertion_audience.is_some() && client_assertion_key_ref.is_none() {
                    return invalid(
                        "OAuth client assertion audience is set without a client assertion key",
                    );
                }
                if let Some(client_assertion_audience) = client_assertion_audience {
                    validate_string(
                        client_assertion_audience,
                        1,
                        512,
                        "OAuth client assertion audience",
                    )?;
                    // Signing refuses a whitespace-only audience, so a bundle
                    // that carried one would satisfy its own contract and then
                    // fail at the first token request as a credential error
                    // naming nothing the operator can act on.
                    if client_assertion_audience.trim().is_empty() {
                        return invalid("OAuth client assertion audience is blank");
                    }
                }
                if let Some(scope) = scope {
                    validate_string(scope, 1, 512, "OAuth scope")?;
                }
                if let Some(audience) = audience {
                    validate_string(audience, 1, 512, "OAuth audience")?;
                }
                if let Some(assumed_lifetime_seconds) = assumed_lifetime_seconds {
                    validate_range(
                        *assumed_lifetime_seconds,
                        1,
                        86_400,
                        "OAuth assumed token lifetime",
                    )?;
                }
                validate_range(
                    *maximum_cache_seconds,
                    0,
                    86_400,
                    "OAuth maximum cache lifetime",
                )
            }
        }
    }

    pub fn secret_refs(&self) -> Vec<&SecretRef> {
        match self {
            Self::None {} => Vec::new(),
            Self::Basic {
                username_ref,
                password_ref,
            } => vec![username_ref, password_ref],
            Self::StaticAuthorization { token_ref, .. } => vec![token_ref],
            Self::StaticApiKey { value_ref, .. } => vec![value_ref],
            Self::Oauth2ClientCredentials {
                client_id_ref,
                client_secret_ref,
                client_assertion_key_ref,
                ..
            } => [
                Some(client_id_ref),
                client_secret_ref.as_ref(),
                client_assertion_key_ref.as_ref(),
            ]
            .into_iter()
            .flatten()
            .collect(),
        }
    }
}

/// Accept an authentication scheme the runtime may prefix to a static token.
///
/// RFC 9110 section 11.1 defines the scheme as a token, so the byte set is the
/// same one field names use. Holding to it keeps a configured value from
/// carrying a space, a separator, or a line break into the header the runtime
/// writes.
fn validate_authorization_scheme(scheme: &str) -> Result<(), ConfigError> {
    validate_string(scheme, 1, 32, "authentication scheme")?;
    if !scheme.bytes().all(is_http_token_byte) {
        return invalid("authentication scheme must be an HTTP token");
    }
    Ok(())
}

/// Where the token request carries the client credentials.
///
/// RFC 6749 section 2.3.1 defines Basic authentication and the request-body
/// parameters and states that those parameters must not be placed in the
/// request URI, so Version 1 offers no query-string placement.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialPlacement {
    BasicHeader,
    FormBody,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixedRequest {
    pub method: HttpMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_template: Option<String>,
    #[serde(default, skip_serializing_if = "OrderedMap::is_empty")]
    pub path_bindings: OrderedMap<PathBindingConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixed_headers: Vec<FixedHeader>,
    pub selector_inputs: Vec<SelectorInput>,
    pub prepare_script: ArtifactPath,
    pub adapter_parameters: OrderedMap<AdapterParameterValue>,
    pub adapter_parameters_schema: ArtifactPath,
    pub preparation_limits: PreparationLimits,
    pub projection: Vec<String>,
    pub redirects: RedirectPolicy,
    pub timeout_milliseconds: u64,
    pub maximum_response_bytes: u64,
    pub concurrency_limit: u16,
}

impl FixedRequest {
    fn validate(&self) -> Result<(), ConfigError> {
        match (&self.path, &self.path_template) {
            (Some(path), None) => {
                validate_normalized_request_path(path)?;
                if !self.path_bindings.is_empty() {
                    return invalid("fixed source path must not define pathBindings");
                }
            }
            (None, Some(template)) => validate_path_template(template, &self.path_bindings)?,
            _ => return invalid("source request must define exactly one of path or pathTemplate"),
        }
        validate_fixed_headers(&self.fixed_headers)?;
        validate_selector_inputs(&self.selector_inputs)?;
        require_artifact_prefix(&self.prepare_script, "adapters/")?;
        if !self.prepare_script.as_str().ends_with(".rhai") {
            return invalid("source preparation script must be a Rhai file");
        }
        validate_len(self.adapter_parameters.len(), 0, 64, "adapter parameters")?;
        for (name, value) in self.adapter_parameters.iter() {
            if !valid_parameter_key(name) {
                return invalid("adapter parameter name is invalid");
            }
            value.validate(0)?;
        }
        require_artifact_prefix(&self.adapter_parameters_schema, "schemas/")?;
        self.preparation_limits.validate()?;
        if self.method == HttpMethod::GET
            && self.preparation_limits.json_body != PreparationChannelPolicy::Forbidden
        {
            return invalid("GET source requests must forbid the JSON body channel");
        }
        validate_projection(&self.projection)?;
        validate_range(self.timeout_milliseconds, 1, 30_000, "source timeout")?;
        validate_range(
            self.maximum_response_bytes,
            1,
            1_048_576,
            "source response size",
        )?;
        validate_range(
            u64::from(self.concurrency_limit),
            1,
            256,
            "source concurrency",
        )?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum HttpMethod {
    GET,
    POST,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RedirectPolicy {
    Deny,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixedHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectorInput {
    pub role: String,
    pub alternatives: Vec<SelectorInputAlternative>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorInputAlternative {
    pub profile: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "from", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PathBindingConfig {
    Selector {
        role: String,
        profile: String,
        field: String,
    },
    PriorFact {
        field: String,
    },
}

impl PathBindingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Selector {
                role,
                profile,
                field,
            } => {
                if !valid_local_id(role) || !valid_local_id(profile) || !valid_field_name(field) {
                    return invalid("source selector binding identifier is invalid");
                }
            }
            Self::PriorFact { field } => {
                if !valid_field_name(field) {
                    return invalid("source prior-fact binding identifier is invalid");
                }
            }
        }
        Ok(())
    }

    pub fn is_prior_fact(&self) -> bool {
        matches!(self, Self::PriorFact { .. })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AdapterParameterValue {
    Boolean(bool),
    Integer(i64),
    String(String),
    Array(Vec<AdapterParameterValue>),
    Object(OrderedMap<AdapterParameterValue>),
}

impl AdapterParameterValue {
    fn validate(&self, depth: usize) -> Result<(), ConfigError> {
        if depth > 32 {
            return invalid("adapter parameter nesting exceeds Version 1 bounds");
        }
        match self {
            Self::Boolean(_) | Self::Integer(_) => Ok(()),
            Self::String(value) => validate_string(value, 0, 16_384, "adapter parameter string"),
            Self::Array(values) => {
                validate_len(values.len(), 0, 256, "adapter parameter array")?;
                for value in values {
                    value.validate(depth + 1)?;
                }
                Ok(())
            }
            Self::Object(values) => {
                validate_len(values.len(), 0, 256, "adapter parameter object")?;
                for (name, value) in values.iter() {
                    if !valid_parameter_key(name) {
                        return invalid("adapter parameter object key is invalid");
                    }
                    value.validate(depth + 1)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparationLimits {
    pub query: PreparationChannelPolicy,
    pub json_body: PreparationChannelPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_query_pairs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_query_name_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_query_value_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_json_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_collection_items: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_string_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_normalized_bytes: Option<u64>,
}

impl PreparationLimits {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.query == PreparationChannelPolicy::Forbidden
            && self.json_body == PreparationChannelPolicy::Forbidden
        {
            return invalid("at least one preparation output channel must be usable");
        }
        validate_optional_range(self.maximum_query_pairs, 1, 64)?;
        validate_optional_range(self.maximum_query_name_bytes, 1, 64)?;
        validate_optional_range(self.maximum_query_value_bytes, 1, 4_096)?;
        validate_optional_range(self.maximum_json_depth, 1, 32)?;
        validate_optional_range(self.maximum_collection_items, 1, 256)?;
        validate_optional_range(self.maximum_string_bytes, 1, 16_384)?;
        validate_optional_range(self.maximum_normalized_bytes, 1, 65_536)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PreparationChannelPolicy {
    Required,
    Allowed,
    Forbidden,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityProfile {
    pub kind: AuthorityKind,
    pub requester_tags: Vec<String>,
    pub grants: Vec<AuthorityGrant>,
}

impl AuthorityProfile {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_unique_strings(&self.requester_tags, 1, 32, 1, 128, "requester tags")?;
        if self.requester_tags.iter().any(|tag| !valid_local_id(tag)) {
            return invalid("requester tag is invalid");
        }
        validate_len(self.grants.len(), 1, 128, "authority grants")?;
        for grant in &self.grants {
            grant.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityKind {
    Statutory,
    Organizational,
    Consent,
    Delegated,
    ExplicitRequest,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityGrant {
    pub requirement: String,
    pub purpose: String,
    pub audience_from: AudienceFrom,
    /// Closed response formats this complete grant permits. Selection through
    /// the API creates no permission; the bundle formats and this grant must
    /// both allow the requested format. Formats are never unioned across
    /// grants.
    #[serde(default = "default_response_formats")]
    pub response_formats: Vec<ResponseFormat>,
    pub subjects: Vec<GrantedSubject>,
}

impl AuthorityGrant {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_uri(&self.requirement)?;
        validate_purpose(&self.purpose)?;
        validate_response_formats(&self.response_formats, "authority grant response formats")?;
        validate_len(self.subjects.len(), 1, 8, "authority grant subjects")
    }
}

/// Closed Version 1 response-format vocabulary.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseFormat {
    SignedJws,
    UnsignedJson,
    /// Audience-scoped SD-JWT VC serialization of the same assertion.
    SdJwtVc,
}

fn default_response_formats() -> Vec<ResponseFormat> {
    vec![ResponseFormat::SignedJws]
}

fn validate_response_formats(
    formats: &[ResponseFormat],
    description: &'static str,
) -> Result<(), ConfigError> {
    validate_len(formats.len(), 1, 3, description)?;
    let mut seen = BTreeSet::new();
    for format in formats {
        if !seen.insert(format_discriminant(*format)) {
            return invalid("response formats must be unique");
        }
    }
    if !formats.contains(&ResponseFormat::SignedJws) {
        return invalid("signed JWS must remain an enabled response format");
    }
    Ok(())
}

fn format_discriminant(format: ResponseFormat) -> u8 {
    match format {
        ResponseFormat::SignedJws => 0,
        ResponseFormat::UnsignedJson => 1,
        ResponseFormat::SdJwtVc => 2,
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AudienceFrom {
    AuthenticatedRequester,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantedSubject {
    pub role: String,
    pub selector_profile: String,
    pub value_origin: ValueOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_claims: Option<OrderedMap<String>>,
}

impl GrantedSubject {
    fn validate_value_claims(&self, profile: &SelectorProfile) -> Result<(), ConfigError> {
        if !valid_local_id(&self.role) || !valid_local_id(&self.selector_profile) {
            return invalid("authority subject identifier is invalid");
        }
        match self.value_origin {
            ValueOrigin::Request => {
                if self.value_claims.is_some() {
                    return invalid("request-derived subject must not define valueClaims");
                }
            }
            ValueOrigin::AuthenticatedContext | ValueOrigin::AuthenticatedGrant => {
                let claims = self.value_claims.as_ref().ok_or(ConfigError::Invalid(
                    "context-derived subject requires valueClaims",
                ))?;
                if claims.len() != profile.fields.len()
                    || profile
                        .fields
                        .keys()
                        .any(|field| !claims.contains_key(field))
                    || claims
                        .keys()
                        .any(|field| !profile.fields.contains_key(field))
                {
                    return invalid("valueClaims must exactly equal selector profile fields");
                }
                let mut targets = BTreeSet::new();
                for (_, claim) in claims.iter() {
                    validate_claim_path(claim)?;
                    if !targets.insert(claim.as_str()) {
                        return invalid("valueClaims targets must be unique");
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValueOrigin {
    AuthenticatedContext,
    AuthenticatedGrant,
    Request,
}

/// The closed set of acquisition kinds a bundle must opt in to before a
/// deployment serves them, in the order the forms were added.
///
/// The Version 1 forms are deliberately absent: `single` and `search-then-fetch`
/// are the frozen acquisition surface every bundle already had, so declaring
/// them would say nothing, and omitting them would have to mean something. A
/// capability list therefore names only the forms added after that surface
/// froze, and a bundle written before any of them existed keeps serving exactly
/// what it served before without carrying a list at all.
const GATED_ACQUISITION_KINDS: [&str; 1] = ["search-then-fetch-set"];

/// The gated acquisition kinds one document declares, as a set.
///
/// The gate has two halves written by two people in two files: the bundle
/// author names the kinds the bundle needs, and the operator names the kinds
/// this deployment may serve. Both halves read the same closed vocabulary
/// through this one derivation, so neither can drift into naming a kind the
/// other cannot. Each half supplies its own sentences, because an operator
/// fixes a runtime file and a bundle author fixes a bundle.
fn declared_acquisition_capabilities<'a>(
    capabilities: &'a [String],
    unknown: &'static str,
    duplicate: &'static str,
    field: &'static str,
) -> Result<BTreeSet<&'a str>, ConfigError> {
    // Entry by entry before the collection bound: with one gated kind the
    // bound would otherwise answer a duplicate with generic cardinality
    // where a naming sentence says what to change.
    let mut declared = BTreeSet::new();
    for capability in capabilities {
        if !GATED_ACQUISITION_KINDS.contains(&capability.as_str()) {
            return invalid(unknown);
        }
        if !declared.insert(capability.as_str()) {
            return invalid(duplicate);
        }
    }
    validate_len(capabilities.len(), 0, GATED_ACQUISITION_KINDS.len(), field)?;
    Ok(declared)
}

const MINIMUM_FETCH_SET_MEMBERS: usize = 2;
const MAXIMUM_FETCH_SET_MEMBERS: usize = 4;
const MAXIMUM_FETCH_SET_FACT_INPUTS: usize = 16;
/// The ceiling on the whole fetch-set acquisition, matching the ceiling one
/// source request already carries.
const MAXIMUM_ACQUISITION_MILLISECONDS: u64 = 30_000;

/// The complete bounded evidence-data acquisition profile for one requirement.
///
/// Each named source remains one immutable HTTP request. `search-then-fetch`
/// and `search-then-fetch-set` are the only multi-call forms, and each names
/// every call it may make in configuration, so the acquisition ceiling stays
/// fixed at read time without introducing a general workflow or
/// source-planning model.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AcquisitionConfig {
    Single {
        source: String,
    },
    SearchThenFetch {
        search: String,
        fetch: String,
    },
    SearchThenFetchSet {
        search: String,
        fetch: Vec<FetchSetMember>,
        #[serde(rename = "maximumAcquisitionMilliseconds")]
        maximum_acquisition_milliseconds: u64,
    },
}

impl AcquisitionConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Single { source } => {
                if !valid_local_id(source) {
                    return invalid("requirement acquisition source identifier is invalid");
                }
            }
            Self::SearchThenFetch { search, fetch } => {
                if !valid_local_id(search) || !valid_local_id(fetch) || search == fetch {
                    return invalid("search-then-fetch source identifiers are invalid");
                }
            }
            Self::SearchThenFetchSet {
                search,
                fetch,
                maximum_acquisition_milliseconds,
            } => {
                if fetch.len() < MINIMUM_FETCH_SET_MEMBERS {
                    return invalid("requirement acquisition declares too few fetch members");
                }
                if fetch.len() > MAXIMUM_FETCH_SET_MEMBERS {
                    return invalid("requirement acquisition declares too many fetch members");
                }
                if !valid_local_id(search)
                    || fetch.iter().any(|member| !valid_local_id(&member.source))
                {
                    return invalid("search-then-fetch-set source identifiers are invalid");
                }
                let mut members = BTreeSet::new();
                for member in fetch {
                    if !members.insert(member.source.as_str()) {
                        return invalid("requirement acquisition fetch members must be distinct");
                    }
                    if &member.source == search {
                        return invalid(
                            "requirement acquisition fetch member repeats the search source",
                        );
                    }
                    member.validate()?;
                }
                if !(1..=MAXIMUM_ACQUISITION_MILLISECONDS)
                    .contains(maximum_acquisition_milliseconds)
                {
                    return invalid("requirement acquisition budget is outside Version 1 bounds");
                }
            }
        }
        Ok(())
    }

    pub fn source_ids(&self) -> Vec<&str> {
        match self {
            Self::Single { source } => vec![source.as_str()],
            Self::SearchThenFetch { search, fetch } => {
                vec![search.as_str(), fetch.as_str()]
            }
            Self::SearchThenFetchSet { search, fetch, .. } => std::iter::once(search.as_str())
                .chain(fetch.iter().map(|member| member.source.as_str()))
                .collect(),
        }
    }

    pub fn uses_source(&self, source_id: &str) -> bool {
        self.source_ids().contains(&source_id)
    }

    pub fn initial_source(&self) -> &str {
        match self {
            Self::Single { source } => source,
            Self::SearchThenFetch { search, .. } | Self::SearchThenFetchSet { search, .. } => {
                search
            }
        }
    }

    /// The sources this acquisition reaches after its search has resolved, and
    /// therefore the only sources that may bind a prior fact into a request.
    pub fn fetch_sources(&self) -> Vec<&str> {
        match self {
            Self::Single { .. } => Vec::new(),
            Self::SearchThenFetch { fetch, .. } => vec![fetch.as_str()],
            Self::SearchThenFetchSet { fetch, .. } => {
                fetch.iter().map(|member| member.source.as_str()).collect()
            }
        }
    }

    /// The ordered acquisition this requirement performs, read from
    /// configuration alone: no request, no response, and no clock take part.
    /// Every form describes itself the same way, so the runtime, the offline
    /// fixture harness, and adopter tooling read one derivation of the order
    /// and of what each stage may carry, rather than three that can drift.
    pub fn plan(&self) -> AcquisitionPlan {
        let stage = |source: &String, role, inputs| PlannedStage {
            source: source.clone(),
            role,
            inputs,
        };
        match self {
            Self::Single { source } => AcquisitionPlan {
                stages: vec![stage(source, StageRole::Search, StageInputs::None)],
                budget_milliseconds: None,
            },
            Self::SearchThenFetch { search, fetch } => AcquisitionPlan {
                stages: vec![
                    stage(search, StageRole::Search, StageInputs::None),
                    stage(fetch, StageRole::Member, StageInputs::EveryPriorFact),
                ],
                budget_milliseconds: None,
            },
            Self::SearchThenFetchSet {
                search,
                fetch,
                maximum_acquisition_milliseconds,
            } => AcquisitionPlan {
                stages: std::iter::once(stage(search, StageRole::Search, StageInputs::None))
                    .chain(fetch.iter().map(|member| {
                        stage(
                            &member.source,
                            StageRole::Member,
                            StageInputs::Declared(member.fact_inputs.clone()),
                        )
                    }))
                    .collect(),
                budget_milliseconds: Some(*maximum_acquisition_milliseconds),
            },
        }
    }

    /// The acquisition capability a bundle must declare before a deployment
    /// may serve this requirement, or `None` for the frozen Version 1 forms,
    /// which every bundle already carried and so declare nothing.
    pub fn required_capability(&self) -> Option<&'static str> {
        match self {
            Self::Single { .. } | Self::SearchThenFetch { .. } => None,
            Self::SearchThenFetchSet { .. } => Some("search-then-fetch-set"),
        }
    }
}

/// One declared member of a fetch set: a source, and the closed allowlist of
/// search facts that member's request may read.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FetchSetMember {
    pub source: String,
    pub fact_inputs: Vec<String>,
}

impl FetchSetMember {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.fact_inputs.is_empty() {
            return invalid("requirement acquisition fetch member declares no fact inputs");
        }
        if self.fact_inputs.len() > MAXIMUM_FETCH_SET_FACT_INPUTS {
            return invalid("requirement acquisition fetch member declares too many fact inputs");
        }
        let mut names = BTreeSet::new();
        for name in &self.fact_inputs {
            if !valid_field_name(name) {
                return invalid("requirement acquisition fetch member fact input is invalid");
            }
            if !names.insert(name.as_str()) {
                return invalid("requirement acquisition fetch member fact inputs must be unique");
            }
        }
        Ok(())
    }
}

/// The complete ordered acquisition one requirement performs, as a value that
/// can be printed, compared, and tested without executing anything.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcquisitionPlan {
    pub stages: Vec<PlannedStage>,
    /// The ceiling on the whole acquisition, where the form declares one. The
    /// forms that predate the declaration bound each call on its own.
    pub budget_milliseconds: Option<u64>,
}

/// One planned source call: which source, why it is called, and what an
/// earlier stage's facts may contribute to its request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PlannedStage {
    pub source: String,
    pub role: StageRole,
    pub inputs: StageInputs,
}

/// Whether a stage resolves the subject or reads a resolved reference.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum StageRole {
    Search,
    Member,
}

/// What an earlier stage's facts may contribute to one stage's request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StageInputs {
    /// Nothing, because no stage has run yet.
    None,
    /// Every fact the preceding stage produced. This is `search-then-fetch` as
    /// Version 1 froze it, and the reason that form stops at one fetch.
    EveryPriorFact,
    /// Only the named search facts, in the order the member declared them.
    Declared(Vec<String>),
}

impl StageInputs {
    /// Narrow the facts an earlier stage produced to what this stage declared.
    /// For a declared allowlist every name is a required search fact, proven
    /// when the bundle validated its fact schemas, so a missing name is
    /// impossible here rather than tolerated: the projection carries no
    /// failure mode of its own.
    pub fn project(
        &self,
        prior_facts: &BTreeMap<String, serde_json::Value>,
    ) -> BTreeMap<String, serde_json::Value> {
        match self {
            Self::None => BTreeMap::new(),
            Self::EveryPriorFact => prior_facts.clone(),
            Self::Declared(names) => names
                .iter()
                .filter_map(|name| {
                    prior_facts
                        .get(name)
                        .map(|value| (name.clone(), value.clone()))
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequirementConfig {
    pub id: String,
    pub kind: RequirementKind,
    pub acquisition: AcquisitionConfig,
    pub purposes: Vec<String>,
    pub subject_roles: Vec<SubjectRole>,
    pub reference_frameworks: Vec<String>,
    pub evidence_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_timezone: Option<String>,
    pub validity_seconds: u64,
    pub derivation: DerivationConfig,
    pub concepts: Vec<ConceptConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixtures: Option<ArtifactPath>,
    pub disclosure_guard: DisclosureGuard,
    pub existence_disclosure: ExistenceDisclosure,
}

impl RequirementConfig {
    pub fn initial_source(&self) -> &str {
        self.acquisition.initial_source()
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_uri(&self.id)?;
        self.acquisition.validate()?;
        validate_unique_strings(&self.purposes, 1, 32, 1, 128, "requirement purposes")?;
        for purpose in &self.purposes {
            validate_purpose(purpose)?;
        }
        validate_len(self.subject_roles.len(), 1, 8, "requirement subject roles")?;
        let mut roles = BTreeSet::new();
        for role in &self.subject_roles {
            role.validate()?;
            if !roles.insert(role.role.as_str()) {
                return invalid("requirement subject roles must be unique");
            }
        }
        validate_unique_strings(
            &self.reference_frameworks,
            1,
            16,
            1,
            512,
            "reference frameworks",
        )?;
        for reference in &self.reference_frameworks {
            validate_uri(reference)?;
        }
        validate_uri(&self.evidence_type)?;
        if let Some(timezone) = &self.observation_timezone {
            validate_string(timezone, 1, 128, "observation timezone")?;
            chrono_tz::Tz::from_str(timezone).map_err(|_| {
                ConfigError::Invalid("observation timezone is not an IANA timezone")
            })?;
        }
        validate_range(self.validity_seconds, 1, 31_536_000, "requirement validity")?;
        self.derivation.validate()?;
        validate_len(self.concepts.len(), 1, 16, "requirement concepts")?;
        let mut concepts = BTreeSet::new();
        let mut sd_jwt_claims = BTreeSet::new();
        for concept in &self.concepts {
            concept.validate()?;
            if !concepts.insert(concept.id.as_str()) {
                return invalid("requirement concepts must be unique");
            }
            if let Some(projection) = &concept.sd_jwt_vc {
                if !sd_jwt_claims.insert(projection.claim.as_str()) {
                    return invalid("requirement SD-JWT VC claim names must be unique");
                }
            }
        }
        if let Some(fixtures) = &self.fixtures {
            require_artifact_prefix(fixtures, "fixtures/")?;
        }
        self.disclosure_guard.validate()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementKind {
    Criterion,
    InformationRequirement,
    Constraint,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectRole {
    pub role: String,
    pub cardinality: SubjectCardinality,
    pub selector_profiles: Vec<String>,
}

impl SubjectRole {
    fn validate(&self) -> Result<(), ConfigError> {
        if !valid_local_id(&self.role) {
            return invalid("subject role identifier is invalid");
        }
        validate_unique_strings(
            &self.selector_profiles,
            1,
            16,
            1,
            128,
            "role selector profiles",
        )?;
        if self
            .selector_profiles
            .iter()
            .any(|profile| !valid_local_id(profile))
        {
            return invalid("role selector profile identifier is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectCardinality {
    One,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DerivationConfig {
    pub script: ArtifactPath,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selector_inputs: Vec<SelectorInput>,
    pub parameters: OrderedMap<ParameterValue>,
}

impl DerivationConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        require_artifact_prefix(&self.script, "derivations/")?;
        if !self.script.as_str().ends_with(".rhai") {
            return invalid("derivation script must be a Rhai file");
        }
        validate_derivation_input_shape(&self.selector_inputs)?;
        validate_len(self.parameters.len(), 0, 32, "derivation parameters")?;
        for (name, value) in self.parameters.iter() {
            if !valid_field_name(name) {
                return invalid("derivation parameter name is invalid");
            }
            value.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ParameterValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Decimal(DecimalValue),
    BucketBoundaries(Vec<BucketBoundary>),
}

impl ParameterValue {
    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::String(value) => validate_string(value, 0, 1_024, "derivation string parameter"),
            Self::Integer(value) => {
                if value.unsigned_abs() > MAX_SAFE_INTEGER as u64 {
                    invalid("derivation integer parameter exceeds safe bounds")
                } else {
                    Ok(())
                }
            }
            Self::Boolean(_) => Ok(()),
            Self::Decimal(value) => value.validate(),
            Self::BucketBoundaries(boundaries) => validate_bucket_boundaries(boundaries),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecimalValue {
    #[serde(rename = "type")]
    pub value_type: DecimalMarker,
    pub value: String,
}

impl DecimalValue {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_decimal(&self.value)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DecimalMarker {
    Decimal,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BucketBoundary {
    pub minimum_inclusive: DecimalValue,
    pub maximum_exclusive: DecimalValue,
    pub code: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConceptConfig {
    pub id: String,
    pub form: ConceptForm,
    pub required: bool,
    #[serde(default)]
    pub constraints: OrderedMap<YamlValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sd_jwt_vc: Option<SdJwtVcConceptProjection>,
}

impl ConceptConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_uri(&self.id)?;
        validate_len(self.constraints.len(), 0, 32, "concept constraints")?;
        validate_concept_constraints(self)?;
        if let Some(projection) = &self.sd_jwt_vc {
            if self.form != ConceptForm::ReviewedStructuredValue {
                return invalid("SD-JWT VC field projection requires a reviewed structured value");
            }
            projection.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SdJwtVcConceptProjection {
    pub claim: String,
    pub disclosure: SdJwtVcDisclosureMode,
}

impl SdJwtVcConceptProjection {
    fn validate(&self) -> Result<(), ConfigError> {
        if !valid_sd_jwt_claim_name(&self.claim) {
            return invalid("SD-JWT VC structured claim name is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SdJwtVcDisclosureMode {
    TopLevel,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConceptForm {
    Boolean,
    ControlledCode,
    ControlledCategory,
    BoundedInteger,
    BoundedDecimal,
    DateBucket,
    TimeBucket,
    AudienceScopedEntityReference,
    ControlledCodeList,
    EntityReferenceList,
    ReviewedStructuredValue,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureGuard {
    pub families: Vec<String>,
}

impl DisclosureGuard {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_unique_strings(&self.families, 1, 16, 1, 512, "disclosure families")?;
        for family in &self.families {
            validate_uri(family)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExistenceDisclosure {
    CollapseUnresolved,
}

fn validate_named_map<T>(
    map: &OrderedMap<T>,
    minimum: usize,
    maximum: usize,
    validate: impl Fn(&T) -> Result<(), ConfigError>,
) -> Result<(), ConfigError> {
    validate_len(map.len(), minimum, maximum, "named configuration map")?;
    for (name, value) in map.iter() {
        if !valid_local_id(name) {
            return invalid("local identifier is invalid");
        }
        validate(value)?;
    }
    Ok(())
}

fn require_artifact_prefix(path: &ArtifactPath, prefix: &'static str) -> Result<(), ConfigError> {
    if path.as_str().starts_with(prefix) {
        Ok(())
    } else {
        invalid("artifact path has the wrong bundle directory")
    }
}

fn validate_selector_inputs(inputs: &[SelectorInput]) -> Result<(), ConfigError> {
    validate_len(inputs.len(), 0, 8, "source selector inputs")?;
    validate_derivation_input_shape(inputs)
}

fn validate_derivation_input_shape(inputs: &[SelectorInput]) -> Result<(), ConfigError> {
    validate_len(inputs.len(), 0, 8, "selector inputs")?;
    let mut roles = BTreeSet::new();
    for input in inputs {
        if !valid_local_id(&input.role) || !roles.insert(input.role.as_str()) {
            return invalid("selector-input roles must be valid and unique");
        }
        validate_len(
            input.alternatives.len(),
            1,
            16,
            "selector-input alternatives",
        )?;
        let mut profiles = BTreeSet::new();
        for alternative in &input.alternatives {
            if !valid_local_id(&alternative.profile)
                || !profiles.insert(alternative.profile.as_str())
            {
                return invalid("selector-input profiles must be valid and unique per role");
            }
            validate_unique_strings(&alternative.fields, 1, 16, 1, 64, "selector-input fields")?;
            if alternative
                .fields
                .iter()
                .any(|field| !valid_field_name(field))
            {
                return invalid("selector-input field name is invalid");
            }
        }
    }
    Ok(())
}

fn validate_derivation_selector_inputs(
    requirement: &RequirementConfig,
    profiles: &OrderedMap<SelectorProfile>,
) -> Result<(), ConfigError> {
    for input in &requirement.derivation.selector_inputs {
        let role = requirement
            .subject_roles
            .iter()
            .find(|role| role.role == input.role)
            .ok_or(ConfigError::Invalid(
                "derivation selector input references an unknown requirement role",
            ))?;
        for alternative in &input.alternatives {
            if !role.selector_profiles.contains(&alternative.profile) {
                return invalid(
                    "derivation selector input profile is not allowed for the requirement role",
                );
            }
            let profile = profiles
                .get(&alternative.profile)
                .ok_or(ConfigError::Invalid(
                    "derivation selector input references an unknown selector profile",
                ))?;
            if alternative
                .fields
                .iter()
                .any(|field| !profile.fields.contains_key(field))
            {
                return invalid("derivation selector input references an unknown selector field");
            }
        }
    }
    Ok(())
}

fn validate_fixed_headers(headers: &[FixedHeader]) -> Result<(), ConfigError> {
    validate_len(headers.len(), 0, 32, "fixed headers")?;
    let mut names = BTreeSet::new();
    for header in headers {
        validate_configurable_header_name(&header.name)?;
        if !names.insert(header.name.to_ascii_lowercase()) {
            return invalid("fixed header names must be unique ignoring ASCII case");
        }
        validate_string(&header.value, 0, 4_096, "fixed header value")?;
        if header.value.chars().any(char::is_control) {
            return invalid("fixed header value contains a control character");
        }
    }
    Ok(())
}

fn validate_configurable_header_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || name.len() > 64
        || !name.bytes().all(is_http_token_byte)
        || is_reserved_header_name(name)
    {
        return invalid("configured header name is prohibited");
    }
    Ok(())
}

pub(crate) fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// The complete closed set of header names no bundle may configure.
///
/// Authentication, host and routing, cookie, framing, hop-by-hop, forwarding,
/// proxy, and tracing headers are owned by Rust or by the operator's network
/// path. A bundle that could set them could redirect a source request, forge a
/// client identity, or smuggle a second request past the reviewed contract.
const RESERVED_HEADER_NAMES: [&str; 38] = [
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "proxy-authenticate",
    "host",
    "cookie",
    "set-cookie",
    "content-length",
    "content-type",
    "transfer-encoding",
    "expect",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-connection",
    "forwarded",
    "via",
    "x-real-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "x-appengine-user-ip",
    "x-azure-clientip",
    "traceparent",
    "tracestate",
    "baggage",
    "b3",
    "x-cloud-trace-context",
    "x-request-id",
    "x-correlation-id",
    "x-amzn-trace-id",
    "x-original-url",
    "x-rewrite-url",
    "x-original-method",
];

/// The complete closed set of reserved header-name prefix families.
///
/// A prefix family is denied before any exact name so that a new vendor
/// forwarding or tracing member cannot be configured before this contract
/// learns its exact name.
const RESERVED_HEADER_PREFIXES: [&str; 7] = [
    "x-forwarded-",
    "proxy-",
    "sec-",
    "x-b3-",
    "x-envoy-",
    "x-datadog-",
    "x-http-method",
];

/// Representative reserved names, case variants, and prefix-family members.
///
/// Both the startup configuration contract and the source plan compiler are
/// tested against this one list, which is how their shared classifier is
/// proven to be a single closed deny set rather than two drifting copies.
pub const RESERVED_HEADER_CONTRACT_CASES: [&str; 51] = [
    "Authorization",
    "authorization",
    "AUTHORIZATION",
    "Proxy-Authorization",
    "Proxy-Authenticate",
    "WWW-Authenticate",
    "Host",
    "Cookie",
    "Set-Cookie",
    "Content-Length",
    "Content-Type",
    "Transfer-Encoding",
    "Expect",
    "Connection",
    "Keep-Alive",
    "TE",
    "Trailer",
    "Upgrade",
    "Proxy-Connection",
    "Forwarded",
    "Via",
    "X-Real-IP",
    "X-Client-IP",
    "x-client-ip",
    "X-Cluster-Client-IP",
    "True-Client-IP",
    "true-client-ip",
    "CF-Connecting-IP",
    "cf-connecting-ip",
    "Fastly-Client-IP",
    "X-Appengine-User-IP",
    "X-Azure-ClientIP",
    "TraceParent",
    "Tracestate",
    "Baggage",
    "b3",
    "B3",
    "X-Cloud-Trace-Context",
    "X-Request-ID",
    "X-Correlation-ID",
    "X-Amzn-Trace-ID",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-HTTP-Method-Override",
    "X-Original-Method",
    "X-Forwarded-For",
    "X-Forwarded-Proto",
    "X-B3-TraceId",
    "X-Envoy-External-Address",
    "X-Datadog-Trace-Id",
    "Sec-Fetch-Mode",
];

/// The one closed reserved-header classifier.
///
/// `name` may be in any ASCII case. Configuration validation rejects a
/// reserved name at startup and source plan compilation rejects it again
/// before any credential is resolved, so both call sites share this function
/// rather than duplicating the deny set.
pub(crate) fn is_reserved_header_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    RESERVED_HEADER_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || RESERVED_HEADER_NAMES.contains(&name.as_str())
}

fn validate_path_template(
    template: &str,
    bindings: &OrderedMap<PathBindingConfig>,
) -> Result<(), ConfigError> {
    validate_string(template, 2, 2_048, "source path template")?;
    if !template.starts_with('/')
        || template.starts_with("//")
        || template.contains(['?', '#', '\\'])
        || !template.is_ascii()
    {
        return invalid("source path template is invalid");
    }
    let mut placeholders = BTreeSet::new();
    let mut normalized = String::new();
    for segment in template.split('/').skip(1) {
        if segment.is_empty() || matches!(segment, "." | "..") {
            return invalid("source path template contains an empty or dot segment");
        }
        normalized.push('/');
        if let Some(name) = segment
            .strip_prefix('{')
            .and_then(|segment| segment.strip_suffix('}'))
        {
            if !valid_field_name(name) || !placeholders.insert(name) {
                return invalid("source path-template placeholders must be valid and unique");
            }
            normalized.push('x');
        } else {
            if segment.contains(['{', '}']) {
                return invalid("source path-template placeholder must occupy a complete segment");
            }
            normalized.push_str(segment);
        }
    }
    validate_normalized_request_path(&normalized)?;
    if placeholders.is_empty() || placeholders != bindings.keys().collect::<BTreeSet<_>>() {
        return invalid("pathBindings must exactly match path-template placeholders");
    }
    for (_, binding) in bindings.iter() {
        binding.validate()?;
    }
    Ok(())
}

fn validate_projection(projection: &[String]) -> Result<(), ConfigError> {
    validate_unique_strings(projection, 1, 64, 2, 256, "source projection")?;
    let paths = projection
        .iter()
        .map(|path| parse_projection_pointer(path))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, left) in paths.iter().enumerate() {
        for right in paths.iter().skip(index + 1) {
            if projection_paths_overlap(left, right) {
                return invalid("source projection paths must not duplicate or overlap");
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ProjectionSegment {
    Wildcard,
    Key(String),
}

fn parse_projection_pointer(pointer: &str) -> Result<Vec<ProjectionSegment>, ConfigError> {
    if !pointer.starts_with('/')
        || pointer.starts_with("//")
        || pointer.chars().any(char::is_control)
    {
        return invalid("source projection is not an extended JSON Pointer");
    }
    pointer[1..]
        .split('/')
        .map(|raw| {
            if raw.is_empty() {
                return invalid("source projection contains an empty segment");
            }
            if raw == "*" {
                return Ok(ProjectionSegment::Wildcard);
            }
            let mut decoded = String::with_capacity(raw.len());
            let mut chars = raw.chars();
            while let Some(character) = chars.next() {
                if character == '~' {
                    match chars.next() {
                        Some('0') => decoded.push('~'),
                        Some('1') => decoded.push('/'),
                        _ => return invalid("source projection contains an invalid escape"),
                    }
                } else {
                    decoded.push(character);
                }
            }
            Ok(ProjectionSegment::Key(decoded))
        })
        .collect()
}

fn projection_paths_overlap(left: &[ProjectionSegment], right: &[ProjectionSegment]) -> bool {
    let common = left.len().min(right.len());
    left.iter().zip(right).take(common).all(|(left, right)| {
        left == right
            || matches!(left, ProjectionSegment::Wildcard)
            || matches!(right, ProjectionSegment::Wildcard)
    })
}

fn validate_optional_range(
    value: Option<u64>,
    minimum: u64,
    maximum: u64,
) -> Result<(), ConfigError> {
    value.map_or(Ok(()), |value| {
        validate_range(value, minimum, maximum, "optional bound")
    })
}

fn validate_source_origin(value: &str) -> Result<(), ConfigError> {
    let url = validate_source_url(value, true)?;
    if url.path() != "/" || url.query().is_some() {
        return invalid("source baseUrl must contain only scheme, host, and optional port");
    }
    Ok(())
}

/// Validate the only credential-free source boundary.
///
/// This is deliberately narrower than the numeric-loopback exception used by
/// authenticated deterministic source mocks. The unauthenticated local mode
/// requires one exact origin spelling and an explicit port so a tutorial
/// bundle cannot silently inherit a default port, path, alias, or userinfo.
pub(crate) fn validate_local_unauthenticated_source_origin(value: &str) -> Result<(), ConfigError> {
    let url = validate_source_url(value, true)?;
    let port = url.port_or_known_default().ok_or(ConfigError::Invalid(
        "unauthenticated local source origin requires an explicit non-zero port",
    ))?;
    let canonical = match url.host() {
        Some(Host::Ipv4(ip)) if ip.is_loopback() => format!("http://{ip}:{port}"),
        Some(Host::Ipv6(ip)) if ip.is_loopback() => format!("http://[{ip}]:{port}"),
        _ => {
            return invalid(
                "unauthenticated local source origin must use a numeric loopback HTTP host",
            )
        }
    };
    if url.scheme() != "http" || value != canonical {
        return invalid(
            "unauthenticated local source origin must be a canonical numeric loopback HTTP origin with an explicit non-zero port",
        );
    }
    Ok(())
}

fn validate_source_url(value: &str, origin_only: bool) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::Invalid("source URL is invalid"))?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return invalid("source URL contains prohibited authority or fragment data");
    }
    if origin_only && url.query().is_some() {
        return invalid("source origin must not contain a query");
    }
    match url.scheme() {
        "https" => {}
        "http" => {
            match url.host() {
                Some(Host::Ipv4(ip)) if ip.is_loopback() => {}
                Some(Host::Ipv6(ip)) if ip.is_loopback() => {}
                _ => return invalid("insecure source URL must use a numeric loopback host"),
            }
            if !has_canonical_loopback_authority(value) {
                return invalid("insecure source URL host syntax is ambiguous");
            }
        }
        _ => return invalid("source URL scheme is not permitted"),
    }
    Ok(url)
}

fn has_canonical_loopback_authority(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    if let Some(suffix) = authority.strip_prefix("[::1]") {
        return suffix.is_empty() || valid_port_suffix(suffix);
    }
    let (host, port) = authority
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if port.is_some_and(|port| !valid_port(port)) {
        return false;
    }
    let octets = host.split('.').collect::<Vec<_>>();
    octets.len() == 4
        && octets[0] == "127"
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && (octet == &"0" || !octet.starts_with('0'))
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && octet.parse::<u8>().is_ok()
        })
}

fn valid_port_suffix(value: &str) -> bool {
    value.strip_prefix(':').is_some_and(valid_port)
}

fn valid_port(value: &str) -> bool {
    !value.starts_with('0') && value.parse::<u16>().is_ok_and(|port| port != 0)
}

fn validate_https_url(value: &str, origin_only: bool) -> Result<(), ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::Invalid("HTTPS URL is invalid"))?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (origin_only && (url.path() != "/" || url.query().is_some()))
    {
        return invalid("HTTPS URL violates the strict origin contract");
    }
    Ok(())
}

fn validate_https_issuer(value: &str) -> Result<(), ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::Invalid("HTTPS issuer is invalid"))?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return invalid("HTTPS issuer violates the exact issuer contract");
    }
    Ok(())
}

fn validate_normalized_request_path(value: &str) -> Result<(), ConfigError> {
    if value.len() < 2
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains(['?', '#', '\\'])
        || !value.is_ascii()
    {
        return invalid("source request path is invalid");
    }
    let mut index = 0;
    let bytes = value.as_bytes();
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
                || bytes[index + 1].is_ascii_lowercase()
                || bytes[index + 2].is_ascii_lowercase()
            {
                return invalid("source request path contains a non-canonical escape");
            }
            let decoded = u8::from_str_radix(&value[index + 1..index + 3], 16)
                .map_err(|_| ConfigError::Invalid("source request path escape is invalid"))?;
            if decoded.is_ascii_alphanumeric()
                || matches!(decoded, b'-' | b'.' | b'_' | b'~' | b'/' | b'\\')
            {
                return invalid("source request path contains an ambiguous escape");
            }
            index += 3;
            continue;
        }
        if !(byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'-'
            ))
        {
            return invalid("source request path contains a prohibited character");
        }
        index += 1;
    }
    if value
        .split('/')
        .skip(1)
        .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return invalid("source request path contains a dot segment");
    }
    Ok(())
}

fn validate_bucket_boundaries(boundaries: &[BucketBoundary]) -> Result<(), ConfigError> {
    validate_len(boundaries.len(), 1, 64, "bucket boundaries")?;
    let mut codes = BTreeSet::new();
    let mut previous_maximum: Option<&str> = None;
    for boundary in boundaries {
        boundary.minimum_inclusive.validate()?;
        boundary.maximum_exclusive.validate()?;
        if compare_decimal_text(
            &boundary.minimum_inclusive.value,
            &boundary.maximum_exclusive.value,
        ) != std::cmp::Ordering::Less
        {
            return invalid("bucket interval must be non-empty");
        }
        if previous_maximum.is_some_and(|previous| {
            compare_decimal_text(previous, &boundary.minimum_inclusive.value)
                != std::cmp::Ordering::Equal
        }) {
            return invalid("bucket intervals must be ordered and contiguous");
        }
        if !valid_code(&boundary.code) || !codes.insert(boundary.code.as_str()) {
            return invalid("bucket code is invalid or duplicated");
        }
        previous_maximum = Some(&boundary.maximum_exclusive.value);
    }
    Ok(())
}

fn validate_concept_constraints(concept: &ConceptConfig) -> Result<(), ConfigError> {
    let required: &[&str] = match concept.form {
        ConceptForm::Boolean => &[],
        ConceptForm::ControlledCode => &["codelist", "codelistVersion", "maximumBytes"],
        ConceptForm::ControlledCategory => &[
            "categoryScheme",
            "schemeVersion",
            "maximumBytes",
            "codelist",
        ],
        ConceptForm::BoundedInteger => &["minimum", "maximum"],
        ConceptForm::BoundedDecimal => &["minimum", "maximum", "maximumScale"],
        ConceptForm::DateBucket | ConceptForm::TimeBucket => &["bucketScheme", "schemeVersion"],
        ConceptForm::AudienceScopedEntityReference => &["maximumBytes"],
        ConceptForm::ControlledCodeList => &[
            "codelist",
            "codelistVersion",
            "minimumItems",
            "maximumItems",
            "unique",
        ],
        ConceptForm::EntityReferenceList => &["minimumItems", "maximumItems", "unique"],
        ConceptForm::ReviewedStructuredValue => &["schema", "maximumSerializedBytes"],
    };
    if concept.constraints.len() != required.len()
        || required
            .iter()
            .any(|name| !concept.constraints.contains_key(name))
    {
        return invalid("concept constraints do not exactly match the declared value form");
    }

    match concept.form {
        ConceptForm::Boolean => {}
        ConceptForm::ControlledCode => {
            validate_codelist_constraints(&concept.constraints, "codelistVersion")?;
        }
        ConceptForm::ControlledCategory => {
            validate_uri(yaml_string(&concept.constraints, "categoryScheme")?)?;
            validate_string(
                yaml_string(&concept.constraints, "schemeVersion")?,
                1,
                128,
                "scheme version",
            )?;
            validate_codelist_path(yaml_string(&concept.constraints, "codelist")?)?;
            validate_constraint_u64(&concept.constraints, "maximumBytes", 1, 8_192)?;
        }
        ConceptForm::BoundedInteger => {
            let minimum = yaml_i64(&concept.constraints, "minimum")?;
            let maximum = yaml_i64(&concept.constraints, "maximum")?;
            if minimum > maximum || minimum < -MAX_SAFE_INTEGER || maximum > MAX_SAFE_INTEGER {
                return invalid("bounded integer constraints are invalid");
            }
        }
        ConceptForm::BoundedDecimal => {
            let minimum = yaml_string(&concept.constraints, "minimum")?;
            let maximum = yaml_string(&concept.constraints, "maximum")?;
            validate_decimal(minimum)?;
            validate_decimal(maximum)?;
            if compare_decimal_text(minimum, maximum) == std::cmp::Ordering::Greater {
                return invalid("bounded decimal constraints are invalid");
            }
            validate_constraint_u64(&concept.constraints, "maximumScale", 0, 9)?;
        }
        ConceptForm::DateBucket | ConceptForm::TimeBucket => {
            validate_uri(yaml_string(&concept.constraints, "bucketScheme")?)?;
            validate_string(
                yaml_string(&concept.constraints, "schemeVersion")?,
                1,
                128,
                "scheme version",
            )?;
        }
        ConceptForm::AudienceScopedEntityReference => {
            validate_constraint_u64(&concept.constraints, "maximumBytes", 1, 8_192)?;
        }
        ConceptForm::ControlledCodeList => {
            validate_codelist_path(yaml_string(&concept.constraints, "codelist")?)?;
            validate_string(
                yaml_string(&concept.constraints, "codelistVersion")?,
                1,
                128,
                "codelist version",
            )?;
            validate_collection_constraints(&concept.constraints)?;
        }
        ConceptForm::EntityReferenceList => validate_collection_constraints(&concept.constraints)?,
        ConceptForm::ReviewedStructuredValue => {
            validate_uri(yaml_string(&concept.constraints, "schema")?)?;
            validate_constraint_u64(&concept.constraints, "maximumSerializedBytes", 1, 65_536)?;
        }
    }
    Ok(())
}

fn validate_codelist_constraints(
    constraints: &OrderedMap<YamlValue>,
    version_key: &str,
) -> Result<(), ConfigError> {
    validate_codelist_path(yaml_string(constraints, "codelist")?)?;
    validate_string(
        yaml_string(constraints, version_key)?,
        1,
        128,
        "codelist version",
    )?;
    validate_constraint_u64(constraints, "maximumBytes", 1, 8_192).map(|_| ())
}

fn validate_collection_constraints(constraints: &OrderedMap<YamlValue>) -> Result<(), ConfigError> {
    let minimum = validate_constraint_u64(constraints, "minimumItems", 1, 64)?;
    let maximum = validate_constraint_u64(constraints, "maximumItems", 1, 64)?;
    if minimum > maximum || !yaml_bool(constraints, "unique")? {
        return invalid("collection constraints are invalid");
    }
    Ok(())
}

fn validate_codelist_path(value: &str) -> Result<(), ConfigError> {
    let path = ArtifactPath::parse(value)?;
    require_artifact_prefix(&path, "codelists/")
}

fn yaml_string<'a>(map: &'a OrderedMap<YamlValue>, key: &str) -> Result<&'a str, ConfigError> {
    map.get(key)
        .and_then(YamlValue::as_str)
        .ok_or(ConfigError::Invalid(
            "concept constraint has the wrong scalar type",
        ))
}

fn yaml_i64(map: &OrderedMap<YamlValue>, key: &str) -> Result<i64, ConfigError> {
    map.get(key)
        .and_then(YamlValue::as_i64)
        .ok_or(ConfigError::Invalid(
            "concept constraint has the wrong integer type",
        ))
}

fn yaml_bool(map: &OrderedMap<YamlValue>, key: &str) -> Result<bool, ConfigError> {
    map.get(key)
        .and_then(YamlValue::as_bool)
        .ok_or(ConfigError::Invalid(
            "concept constraint has the wrong boolean type",
        ))
}

fn validate_constraint_u64(
    map: &OrderedMap<YamlValue>,
    key: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, ConfigError> {
    let value = map
        .get(key)
        .and_then(YamlValue::as_u64)
        .ok_or(ConfigError::Invalid(
            "concept constraint has the wrong integer type",
        ))?;
    validate_range(value, minimum, maximum, "concept constraint")?;
    Ok(value)
}

fn validate_decimal(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.starts_with('+')
        || value == "-0"
        || value.starts_with("-0.")
        || value.contains(['e', 'E'])
    {
        return invalid("decimal text is not canonical");
    }
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    let mut parts = unsigned.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || (integer.len() > 1 && integer.starts_with('0'))
        || fraction.is_some_and(|fraction| {
            fraction.is_empty()
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
                || fraction.ends_with('0')
        })
    {
        return invalid("decimal text is not canonical");
    }
    let scale = fraction.map_or(0, str::len);
    let precision = integer.len() + scale;
    if precision > 28 || scale > 9 {
        return invalid("decimal precision or scale exceeds Version 1 bounds");
    }
    Ok(())
}

fn compare_decimal_text(left: &str, right: &str) -> std::cmp::Ordering {
    fn parts(value: &str) -> (bool, &str, &str) {
        let negative = value.starts_with('-');
        let unsigned = value.strip_prefix('-').unwrap_or(value);
        let (integer, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
        (negative, integer, fraction)
    }
    let (left_negative, left_integer, left_fraction) = parts(left);
    let (right_negative, right_integer, right_fraction) = parts(right);
    if left_negative != right_negative {
        return if left_negative {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        };
    }
    let magnitude = left_integer
        .len()
        .cmp(&right_integer.len())
        .then_with(|| left_integer.cmp(right_integer))
        .then_with(|| {
            let width = left_fraction.len().max(right_fraction.len());
            left_fraction
                .bytes()
                .chain(std::iter::repeat(b'0'))
                .take(width)
                .cmp(
                    right_fraction
                        .bytes()
                        .chain(std::iter::repeat(b'0'))
                        .take(width),
                )
        });
    if left_negative {
        magnitude.reverse()
    } else {
        magnitude
    }
}

fn validate_uri(value: &str) -> Result<(), ConfigError> {
    validate_string(value, 1, 512, "URI")?;
    let url = Url::parse(value).map_err(|_| ConfigError::Invalid("URI is invalid"))?;
    if url.scheme().is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return invalid("URI is invalid");
    }
    Ok(())
}

fn validate_absolute_path(value: &str) -> Result<(), ConfigError> {
    let path = Path::new(value);
    if value.len() > 512
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return invalid("absolute operator path is invalid");
    }
    Ok(())
}

fn validate_claim_name(value: &str) -> Result<(), ConfigError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !matches!(bytes.first(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return invalid("claim name is invalid");
    }
    Ok(())
}

fn validate_claim_path(value: &str) -> Result<(), ConfigError> {
    if value.len() > 512 {
        return invalid("claim path is too long");
    }
    for segment in value.split('.') {
        let bytes = segment.as_bytes();
        if bytes.is_empty()
            || !matches!(bytes.first(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
            || !bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return invalid("claim path is invalid");
        }
    }
    Ok(())
}

fn validate_purpose(value: &str) -> Result<(), ConfigError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !matches!(bytes.first(), Some(b'a'..=b'z'))
        || !bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
    {
        return invalid("purpose code is invalid");
    }
    Ok(())
}

fn valid_local_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_sd_jwt_claim_name(value: &str) -> bool {
    const RESERVED: [&str; 24] = [
        "iss",
        "sub",
        "aud",
        "iat",
        "nbf",
        "exp",
        "vct",
        "id",
        "jti",
        "_sd",
        "_sd_alg",
        "cnf",
        "status",
        "issuedBy",
        "providedBy",
        "supportsRequirement",
        "purpose",
        "audience",
        "assuranceProfile",
        "observedAt",
        "configurationRevision",
        "requestNonce",
        "subjects",
        "structuredValues",
    ];
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && matches!(bytes.first(), Some(b'A'..=b'Z' | b'a'..=b'z'))
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        && !RESERVED.contains(&value)
}

fn valid_field_name(value: &str) -> bool {
    value.len() <= 64 && valid_local_id(value)
}

fn valid_parameter_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && matches!(bytes.first(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn validate_len(
    length: usize,
    minimum: usize,
    maximum: usize,
    _field: &'static str,
) -> Result<(), ConfigError> {
    if (minimum..=maximum).contains(&length) {
        Ok(())
    } else {
        invalid("collection cardinality is outside Version 1 bounds")
    }
}

fn validate_range(
    value: u64,
    minimum: u64,
    maximum: u64,
    _field: &'static str,
) -> Result<(), ConfigError> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        invalid("numeric value is outside Version 1 bounds")
    }
}

fn validate_string(
    value: &str,
    minimum: usize,
    maximum: usize,
    _field: &'static str,
) -> Result<(), ConfigError> {
    if (minimum..=maximum).contains(&value.len()) && !value.contains('\0') {
        Ok(())
    } else {
        invalid("string length is outside Version 1 bounds")
    }
}

fn validate_unique<T: Ord>(
    values: &[T],
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), ConfigError> {
    validate_len(values.len(), minimum, maximum, field)?;
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return invalid("collection values must be unique");
    }
    Ok(())
}

fn validate_unique_strings(
    values: &[String],
    minimum_items: usize,
    maximum_items: usize,
    minimum_bytes: usize,
    maximum_bytes: usize,
    field: &'static str,
) -> Result<(), ConfigError> {
    validate_len(values.len(), minimum_items, maximum_items, field)?;
    let mut seen = BTreeSet::new();
    for value in values {
        validate_string(value, minimum_bytes, maximum_bytes, field)?;
        if !seen.insert(value.as_str()) {
            return invalid("collection values must be unique");
        }
    }
    Ok(())
}

fn invalid<T>(reason: &'static str) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assurance_profile_is_explicit_and_strict_profiles_require_fixtures() {
        let strict = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");

        let omitted_profile = strict.replace("assuranceProfile: evidence-grade\n", "");
        assert_ne!(omitted_profile, strict, "profile mutation must apply");
        assert!(EvidenceConfig::parse_yaml(omitted_profile.as_bytes()).is_err());

        let without_fixtures = strict
            .lines()
            .filter(|line| !line.trim_start().starts_with("fixtures:"))
            .collect::<Vec<_>>()
            .join("\n");
        for profile in ["production", "evidence-grade"] {
            let candidate = without_fixtures.replace("evidence-grade", profile);
            assert!(
                EvidenceConfig::parse_yaml(candidate.as_bytes()).is_err(),
                "{profile} accepted a requirement without fixtures"
            );
        }

        let local = without_fixtures.replace("evidence-grade", "local");
        let parsed = EvidenceConfig::parse_yaml(local.as_bytes())
            .expect("local authoring accepts an omitted fixture reference");
        assert_eq!(parsed.assurance_profile, AssuranceProfile::Local);
        assert!(parsed.requirements[0].fixtures.is_none());
    }

    #[test]
    fn only_local_assurance_accepts_the_exact_loopback_mint_identity() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        config.assurance_profile = AssuranceProfile::Local;
        config.authentication.issuer = "http://127.0.0.1:8081".to_owned();
        config.authentication.jwks_uri = "http://127.0.0.1:8081/.well-known/jwks.json".to_owned();
        config
            .validate()
            .expect("local profile accepts the supervised Mint identity");

        for invalid in [
            "http://localhost:8081",
            "http://127.0.0.2:8081",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:08081",
            "http://127.0.0.1:65536",
            "http://user@127.0.0.1:8081",
            "http://127.0.0.1:8081/",
        ] {
            let mut candidate = config.clone();
            candidate.authentication.issuer = invalid.to_owned();
            assert!(
                candidate.validate().is_err(),
                "local assurance accepted issuer {invalid}"
            );
        }
        for invalid in [
            "http://127.0.0.1:8081/.well-known/keys.json",
            "http://127.0.0.1:8082/.well-known/jwks.json",
            "http://localhost:8081/.well-known/jwks.json",
            "https://127.0.0.1:8081/.well-known/jwks.json",
        ] {
            let mut candidate = config.clone();
            candidate.authentication.jwks_uri = invalid.to_owned();
            assert!(
                candidate.validate().is_err(),
                "local assurance accepted JWKS URI {invalid}"
            );
        }

        for profile in [
            AssuranceProfile::Production,
            AssuranceProfile::EvidenceGrade,
        ] {
            let mut candidate = config.clone();
            candidate.assurance_profile = profile;
            assert!(
                candidate.validate().is_err(),
                "{profile:?} inherited the local HTTP exception"
            );
        }
    }

    /// Two authority claims naming one JWT member, or naming a member the token
    /// already defines, is a configuration the verifier must refuse.
    ///
    /// Mint refuses the same shapes when it mints (`ClaimNames::validate`), but
    /// Mint is one possible issuer. Evidence is documented against any OIDC
    /// issuer, and no other issuer enforces Mint's rules, so the deployment with
    /// no issuer-side check is exactly the one where this is the only check.
    /// `grantAuthorityClaim: aud` would read Evidence's own audience as the
    /// authority that granted the request.
    #[test]
    fn authority_claim_names_must_be_distinct_and_must_not_shadow_registered_claims() {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        config
            .validate()
            .expect("the fixture claim names are sound");

        let mut duplicate = config.clone();
        duplicate
            .authentication
            .grant_id_claim
            .clone_from(&config.authentication.grant_authority_claim);
        assert_eq!(
            duplicate.validate(),
            invalid("authority claim names must be distinct"),
            "one member read as both the grant id and the granting authority"
        );

        let mut duplicate_actor = config.clone();
        duplicate_actor.authentication.actor_claim =
            Some(config.authentication.requester_tags_claim.clone());
        assert_eq!(
            duplicate_actor.validate(),
            invalid("authority claim names must be distinct"),
            "one member read as both the actor and the requester tags"
        );

        // `cnf` is here for a different reason than the rest. The others would
        // read a member the issuer owns; `cnf` would name one the authenticator
        // refuses outright, because Version 1 validates no proof of possession
        // and denies a sender-constrained token rather than downgrading it. A
        // deployment naming it would load, pass `evidence check`, and then answer
        // 401 to every authenticated request, with nothing in the configuration
        // to explain why.
        for reserved in ["iss", "aud", "exp", "iat", "nbf", "jti", "client_id", "cnf"] {
            let mut candidate = config.clone();
            candidate.authentication.grant_authority_claim = reserved.to_owned();
            assert_eq!(
                candidate.validate(),
                invalid("authority claim names must not shadow registered JWT claims"),
                "grant authority read from the registered claim {reserved}"
            );
        }

        // `sub` carries the principal, so the principal claim may name it and
        // the fixture does. Any other claim naming it would read the principal.
        let mut principal_is_subject = config.clone();
        principal_is_subject.authentication.principal_claim = "sub".to_owned();
        principal_is_subject
            .validate()
            .expect("the principal may be read from sub");
        // Moved off `sub` first, so this proves the shadowing rule rather than
        // colliding with the principal and tripping distinctness instead.
        let mut authority_is_subject = config.clone();
        authority_is_subject.authentication.principal_claim = "evidence_principal".to_owned();
        authority_is_subject.authentication.grant_authority_claim = "sub".to_owned();
        assert_eq!(
            authority_is_subject.validate(),
            invalid("authority claim names must not shadow registered JWT claims"),
            "the granting authority read from the principal member"
        );

        let mut distinct = config.clone();
        distinct.authentication.actor_claim = Some("evidence_actor".to_owned());
        distinct
            .validate()
            .expect("distinct, unreserved claim names load");
    }

    #[test]
    fn unauthenticated_source_is_local_loopback_only_and_matches_the_bundle_schema() {
        let mut local = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("strict fixture validates");
        local.assurance_profile = AssuranceProfile::Local;
        local.sources.0[0].1.authentication = SourceAuthentication::None {};

        for origin in [
            "http://127.0.0.1:80",
            "http://127.0.0.1:18081",
            "http://127.42.5.9:1",
            "http://[::1]:65535",
        ] {
            let mut candidate = local.clone();
            candidate.sources.0[0].1.base_url = origin.to_owned();
            candidate
                .validate()
                .unwrap_or_else(|_| panic!("local assurance rejected {origin}"));
            assert!(candidate.sources.0[0]
                .1
                .authentication
                .secret_refs()
                .is_empty());
        }

        for origin in [
            "https://127.0.0.1:18081",
            "http://localhost:18081",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:018081",
            "http://127.0.0.1:65536",
            "http://127.00.0.1:18081",
            "http://127.0.0.1:18081/",
            "http://127.0.0.1:18081/data",
            "http://127.0.0.1:18081?query=true",
            "http://127.0.0.1:18081#fragment",
            "http://user@127.0.0.1:18081",
            "http://192.168.1.2:18081",
        ] {
            let mut candidate = local.clone();
            candidate.sources.0[0].1.base_url = origin.to_owned();
            assert!(
                candidate.validate().is_err(),
                "local assurance accepted unauthenticated origin {origin}"
            );
        }

        let mut with_tls_profile = local.clone();
        with_tls_profile.sources.0[0].1.base_url = "http://127.0.0.1:18081".to_owned();
        with_tls_profile.sources.0[0].1.tls_trust_profile = Some("unused-local-ca".to_owned());
        assert!(with_tls_profile.validate().is_err());

        for profile in [
            AssuranceProfile::Production,
            AssuranceProfile::EvidenceGrade,
        ] {
            let mut candidate = local.clone();
            candidate.assurance_profile = profile;
            candidate.sources.0[0].1.base_url = "http://127.0.0.1:18081".to_owned();
            assert!(
                candidate.validate().is_err(),
                "{profile:?} accepted an unauthenticated source"
            );
        }

        let validator = bundle_contract_validator();
        let mut instance = bundle_contract_instance(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ));
        instance["assuranceProfile"] = serde_json::json!("local");
        instance["sources"]["source-a"]["baseUrl"] = serde_json::json!("http://127.0.0.1:18081");
        instance["sources"]["source-a"]["authentication"] = serde_json::json!({"kind": "none"});
        assert!(
            validator.is_valid(&instance),
            "schema accepts the local form"
        );
        instance["assuranceProfile"] = serde_json::json!("production");
        assert!(
            !validator.is_valid(&instance),
            "schema rejects the local exception in a deployable profile"
        );

        assert!(
            serde_json::from_value::<SourceAuthentication>(
                serde_json::json!({"kind": "none", "tokenRef": "secret:file/unexpected"})
            )
            .is_err(),
            "the none variant is closed"
        );
    }

    fn bundle_contract_validator() -> jsonschema::JSONSchema {
        let schema: serde_norway::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/contracts/bundle.schema.yaml"
        ))
        .expect("bundle contract is YAML");
        let schema = serde_json::to_value(schema).expect("bundle contract converts to JSON");
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .should_validate_formats(true)
            .compile(&schema)
            .expect("bundle contract compiles")
    }

    fn runtime_contract_validator() -> jsonschema::JSONSchema {
        let schema: serde_norway::Value = serde_norway::from_slice(include_bytes!(
            "../../../products/evidence/contracts/runtime.schema.yaml"
        ))
        .expect("runtime contract is YAML");
        let schema = serde_json::to_value(schema).expect("runtime contract converts to JSON");
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .should_validate_formats(true)
            .compile(&schema)
            .expect("runtime contract compiles")
    }

    fn bundle_contract_instance(yaml: &[u8]) -> serde_json::Value {
        let value: serde_norway::Value =
            serde_norway::from_slice(yaml).expect("bundle instance is YAML");
        serde_json::to_value(value).expect("bundle instance converts to JSON")
    }

    /// Canary scalars planted in a malformed document.
    ///
    /// A diagnostic that ever reproduces one of these has leaked a deployment
    /// value, which is exactly what the safe-diagnostic contract forbids.
    const CANARY_VALUES: [&str; 4] = [
        "s3cr3t-selector-value",
        "urn:gov:example:canary:subject:9910",
        "secret:file/canary-private-key",
        "https://canary.internal.example",
    ];

    #[test]
    fn decode_failures_report_a_safe_path_a_location_and_a_value_free_cause() {
        let reference = include_str!("../../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle/evidence.yaml");
        let unknown_nested = reference.replacen(
            "      timeoutMilliseconds: 3000",
            "      timeoutMilliseconds: 3000\n      surprise: s3cr3t-selector-value",
            1,
        );
        assert_ne!(unknown_nested, reference, "nested mutation applies");
        let cases: [(&str, String, &str, Option<&str>, bool); 6] = [
            (
                "malformed YAML",
                format!("version: 1\nbroken: [{}\n", CANARY_VALUES[0]),
                "document is not well-formed YAML",
                None,
                true,
            ),
            (
                "unknown top-level field",
                format!("version: 1\nbogusField: {}\n", CANARY_VALUES[1]),
                "unknown field",
                None,
                true,
            ),
            (
                "unknown nested field",
                unknown_nested,
                "unknown field",
                Some("sources.registered-birth-date.request"),
                true,
            ),
            (
                "wrong type",
                format!("version: {}\n", CANARY_VALUES[2]),
                "field has the wrong type",
                Some("version"),
                true,
            ),
            (
                "missing field",
                "version: 1\n".to_owned(),
                "required field is missing",
                None,
                true,
            ),
            (
                "more than one document",
                format!("version: 1\n---\nversion: {}\n", CANARY_VALUES[3]),
                "document contains more than one YAML document",
                None,
                false,
            ),
        ];
        for (label, document, expected_cause, expected_path, expects_location) in cases {
            let error = EvidenceConfig::parse_yaml(document.as_bytes())
                .err()
                .unwrap_or_else(|| panic!("{label} was accepted"));
            let ConfigError::InvalidYaml(fault) = &error else {
                panic!("{label} was not reported as a decode failure: {error}");
            };
            assert_eq!(fault.cause(), expected_cause, "{label} cause");
            assert_eq!(fault.path(), expected_path, "{label} path");
            assert_eq!(
                fault.location().is_some(),
                expects_location,
                "{label} location presence"
            );
            let rendered = error.to_string();
            for canary in CANARY_VALUES {
                assert!(
                    !rendered.contains(canary),
                    "{label} diagnostic leaked a document value: {rendered}"
                );
            }
        }
    }

    #[test]
    fn schema_paths_are_accepted_only_when_they_carry_no_document_value() {
        for safe in [
            "version",
            "sources.registered-birth-date.request",
            "sources.a.request.fixedHeaders[0].name",
            "requirements[12].concepts[3].id",
            "sources.a.?",
        ] {
            assert!(is_safe_schema_path(safe), "{safe} is a schema path");
        }
        for unsafe_candidate in [
            "",
            "invalid type",
            "invalid value",
            "sources.urn:gov:example",
            "sources.\"quoted key\"",
            "sources.a[]",
            "sources.a[x]",
            "sources.a[0",
            "sources.a/b",
            &"a".repeat(MAX_SCHEMA_PATH_BYTES + 1),
        ] {
            assert!(
                !is_safe_schema_path(unsafe_candidate),
                "{unsafe_candidate} is not a schema path"
            );
        }
    }

    #[test]
    fn exact_secret_reference_grammars_are_closed() {
        for valid in ["secret:file/a", "secret:file/source-token_v2.json"] {
            assert!(SecretRef::parse(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "secret:env/",
            "secret:env/SOURCE_2_PASSWORD",
            "secret:env/lower",
            "secret:env/A-B",
            "secret:file/Upper",
            "secret:file/../token",
            "secret:file/.token",
            "plain-value",
        ] {
            assert!(SecretRef::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn decimal_comparison_is_exact() {
        assert_eq!(
            compare_decimal_text("-10.5", "-2"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_decimal_text("1.2", "1.20"),
            std::cmp::Ordering::Equal
        );
        assert_eq!(compare_decimal_text("10", "2"), std::cmp::Ordering::Greater);
    }

    #[test]
    fn all_coequal_acceptance_definitions_use_the_same_typed_config() {
        for yaml in [
            include_bytes!("../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/residence-region/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/professional-licence/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/legal-parent-relationship/evidence.yaml").as_slice(),
        ] {
            EvidenceConfig::parse_yaml(yaml).expect("acceptance definition must validate");
        }
    }

    #[test]
    fn requirement_validity_cannot_exceed_the_signing_maximum() {
        // Startup validation is the enforcement point: runtime construction
        // derives validUntil from the validated requirement validity, so no
        // constructed assertion can exceed the bundle signing maximum and no
        // redundant signing-time check exists.
        let yaml = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );
        assert!(EvidenceConfig::parse_yaml(yaml.as_bytes()).is_ok());
        let shrunk_maximum = yaml.replace(
            "maximumAssertionValiditySeconds: 300",
            "maximumAssertionValiditySeconds: 299",
        );
        assert_ne!(
            shrunk_maximum, yaml,
            "fixture mutation must remain effective"
        );
        assert!(matches!(
            EvidenceConfig::parse_yaml(shrunk_maximum.as_bytes()),
            Err(ConfigError::Invalid(
                "requirement validity exceeds signing maximum validity"
            ))
        ));
    }

    #[test]
    fn the_advertised_verifier_skew_stays_within_what_a_policy_may_express() {
        // A deployment advertises `verifierClockSkewSeconds` so a relying party
        // can adopt it, and a relying party expresses what it adopted as
        // `clockSkewSeconds`. An advertised value no conformant policy can hold
        // would be unusable advice, so the two bounds are one bound. Both are
        // read from the contracts here rather than restated, so moving either
        // one alone fails.
        let bundle: serde_json::Value = serde_json::to_value(
            serde_norway::from_slice::<serde_norway::Value>(include_bytes!(
                "../../../products/evidence/contracts/bundle.schema.yaml"
            ))
            .expect("bundle contract is YAML"),
        )
        .expect("bundle contract converts to JSON");
        let policy: serde_json::Value = serde_json::to_value(
            serde_norway::from_slice::<serde_norway::Value>(include_bytes!(
                "../../../products/evidence/contracts/verification-policy.schema.yaml"
            ))
            .expect("verification policy contract is YAML"),
        )
        .expect("verification policy contract converts to JSON");
        let advertised = bundle["properties"]["signing"]["properties"]["verifierClockSkewSeconds"]
            ["maximum"]
            .as_u64()
            .expect("the advertised skew declares an integer maximum");
        let expressible = policy["properties"]["clockSkewSeconds"]["maximum"]
            .as_u64()
            .expect("the expressible skew declares an integer maximum");
        assert_eq!(
            advertised, expressible,
            "a deployment may advertise a skew no conformant verification policy can express"
        );

        // Startup validation is the enforcement point, and it must agree with
        // the contract rather than carry its own bound.
        let yaml = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );
        assert!(EvidenceConfig::parse_yaml(yaml.as_bytes()).is_ok());
        let validator = bundle_contract_validator();
        for (skew, accepted) in [(expressible, true), (expressible + 1, false)] {
            let mutated = yaml.replace(
                "verifierClockSkewSeconds: 30",
                &format!("verifierClockSkewSeconds: {skew}"),
            );
            assert_ne!(mutated, yaml, "{skew}");
            assert_eq!(
                EvidenceConfig::parse_yaml(mutated.as_bytes()).is_ok(),
                accepted,
                "startup validation disagrees with the contract at {skew}"
            );
            assert_eq!(
                validator
                    .validate(&bundle_contract_instance(mutated.as_bytes()))
                    .is_ok(),
                accepted,
                "the bundle contract disagrees with startup validation at {skew}"
            );
        }
    }

    #[test]
    fn response_formats_are_closed_unique_and_keep_signed_mandatory() {
        let yaml = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );
        for (from, to) in [
            // The bundle cannot drop the mandatory signed format.
            (
                "\nresponseFormats: [signed-jws, unsigned-json]",
                "\nresponseFormats: [unsigned-json]",
            ),
            // Formats must be unique.
            (
                "\nresponseFormats: [signed-jws, unsigned-json]",
                "\nresponseFormats: [signed-jws, signed-jws]",
            ),
            // A grant cannot drop the mandatory signed format either.
            (
                "        responseFormats: [signed-jws, unsigned-json]\n        subjects:\n          - {role: subject, selectorProfile: person-demographics-v1, valueOrigin: request}",
                "        responseFormats: [unsigned-json]\n        subjects:\n          - {role: subject, selectorProfile: person-demographics-v1, valueOrigin: request}",
            ),
            // The vocabulary is closed.
            (
                "\nresponseFormats: [signed-jws, unsigned-json]",
                "\nresponseFormats: [signed-jws, jws-detached]",
            ),
        ] {
            let mutated = yaml.replace(from, to);
            assert_ne!(mutated, yaml, "{to}");
            assert!(
                EvidenceConfig::parse_yaml(mutated.as_bytes()).is_err(),
                "{to}"
            );
        }
    }

    #[test]
    fn bundle_contract_accepts_every_complete_version_one_bundle() {
        let validator = bundle_contract_validator();
        for yaml in [
            include_bytes!("../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/legal-parent-relationship/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/professional-licence/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/acceptance/residence-region/evidence.yaml").as_slice(),
            // A profile bundle rather than a fifth coequal acceptance
            // definition, so it belongs here, where the claim is only that a
            // complete bundle satisfies the published contract, and not in the
            // coequal-definition list next door.
            include_bytes!("../../../products/evidence/fixtures/acceptance/surviving-spouse-status/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/conformance/selectors/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/fixtures/conformance/supported-values/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/reference/request-adapter/deployment-projects/dhis2-tracker-evidence/bundle/evidence.yaml").as_slice(),
            include_bytes!("../../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle/evidence.yaml").as_slice(),
        ] {
            assert!(validator.is_valid(&bundle_contract_instance(yaml)));
        }
    }

    #[test]
    fn bundle_contract_closes_concept_constraints_by_form() {
        let validator = bundle_contract_validator();
        let valid = bundle_contract_instance(include_bytes!(
            "../../../products/evidence/fixtures/conformance/supported-values/evidence.yaml"
        ));
        assert!(validator.is_valid(&valid));

        let mut misspelled = valid.clone();
        let constraints = misspelled["requirements"][0]["concepts"][1]["constraints"]
            .as_object_mut()
            .expect("controlled-code constraints are an object");
        let version = constraints
            .remove("codelistVersion")
            .expect("canonical constraint exists");
        constraints.insert("codelist_version".to_owned(), version);
        assert!(!validator.is_valid(&misspelled));

        let mut unsupported = valid;
        unsupported["requirements"][0]["concepts"][0]["constraints"]["maximumBytes"] =
            serde_json::json!(32);
        assert!(!validator.is_valid(&unsupported));

        let mut structured_projection = bundle_contract_instance(include_bytes!(
            "../../../products/evidence/fixtures/conformance/supported-values/evidence.yaml"
        ));
        structured_projection["requirements"][0]["concepts"][10]["sdJwtVc"] =
            serde_json::json!({"claim": "birthCertificate", "disclosure": "top-level"});
        assert!(validator.is_valid(&structured_projection));
        structured_projection["requirements"][0]["concepts"][10]
            .as_object_mut()
            .expect("concept is an object")
            .remove("sdJwtVc");
        structured_projection["requirements"][0]["concepts"][0]["sdJwtVc"] =
            serde_json::json!({"claim": "birthCertificate", "disclosure": "top-level"});
        assert!(!validator.is_valid(&structured_projection));
    }

    #[test]
    fn structured_sd_jwt_claim_projection_is_generic_unique_and_non_reserved() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/conformance/supported-values/evidence.yaml"
        ))
        .expect("supported values fixture validates");
        let structured_index = config.requirements[0]
            .concepts
            .iter()
            .position(|concept| concept.form == ConceptForm::ReviewedStructuredValue)
            .expect("fixture has a structured concept");
        config.requirements[0].concepts[structured_index].sd_jwt_vc =
            Some(SdJwtVcConceptProjection {
                claim: "anyReviewedRecord".to_owned(),
                disclosure: SdJwtVcDisclosureMode::TopLevel,
            });
        config.validate().expect("generic claim name is accepted");

        config.requirements[0].concepts[structured_index]
            .sd_jwt_vc
            .as_mut()
            .expect("projection exists")
            .claim = "iss".to_owned();
        assert!(
            config.validate().is_err(),
            "profile claim names are reserved"
        );

        config.requirements[0].concepts[structured_index]
            .sd_jwt_vc
            .as_mut()
            .expect("projection exists")
            .claim = "duplicateClaim".to_owned();
        let mut duplicate = config.requirements[0].concepts[structured_index].clone();
        duplicate.id = "urn:example:fixture:concept:another-structured-value".to_owned();
        config.requirements[0].concepts.push(duplicate);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Invalid(
                "requirement SD-JWT VC claim names must be unique"
            ))
        ));

        config.requirements[0].concepts.pop();
        let projection = config.requirements[0].concepts[structured_index]
            .sd_jwt_vc
            .take();
        config.requirements[0].concepts[0].sd_jwt_vc = projection;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Invalid(
                "SD-JWT VC field projection requires a reviewed structured value"
            ))
        ));
    }

    #[test]
    fn typed_config_rejects_noncanonical_constraint_names() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/residence-region/evidence.yaml"
        ))
        .expect("fixture is UTF-8");
        let misspelled = valid.replacen("codelistVersion", "codelist_version", 1);
        assert_ne!(misspelled, valid, "fixture mutation must remain effective");
        assert!(EvidenceConfig::parse_yaml(misspelled.as_bytes()).is_err());
    }

    #[test]
    fn source_schema_roles_are_mandatory_distinct_and_directory_scoped() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");
        assert!(EvidenceConfig::parse_yaml(valid.as_bytes()).is_ok());

        for (from, to) in [
            // The response contract is mandatory, so extraction never runs
            // behind an undeclared response shape.
            ("    responseSchema: schemas/response.schema.yaml\n", ""),
            // Every schema artifact is directory-scoped like the other roles.
            (
                "responseSchema: schemas/response.schema.yaml",
                "responseSchema: adapters/response.schema.yaml",
            ),
            // One artifact cannot carry two schema roles inside one source.
            (
                "responseSchema: schemas/response.schema.yaml",
                "responseSchema: schemas/facts.schema.yaml",
            ),
            (
                "responseSchema: schemas/response.schema.yaml",
                "responseSchema: schemas/adapter-parameters.schema.yaml",
            ),
        ] {
            let mutated = valid.replace(from, to);
            assert_ne!(mutated, valid, "fixture mutation must remain effective");
            assert!(
                EvidenceConfig::parse_yaml(mutated.as_bytes()).is_err(),
                "{to}"
            );
        }
    }

    #[test]
    fn schema_roles_do_not_overlap_across_sources() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .expect("fixture is UTF-8");
        assert!(EvidenceConfig::parse_yaml(valid.as_bytes()).is_ok());

        // One artifact validating a response for one source and facts for
        // another would make a single review cover two different contracts.
        let crossed = valid.replacen(
            "responseSchema: schemas/adult-status-response.schema.yaml",
            "responseSchema: schemas/residence-region-facts.schema.yaml",
            1,
        );
        assert_ne!(crossed, valid, "fixture mutation must remain effective");
        assert!(matches!(
            EvidenceConfig::parse_yaml(crossed.as_bytes()),
            Err(ConfigError::Invalid(
                "source schema roles must not overlap across sources"
            ))
        ));
    }

    #[test]
    fn yaml_names_and_secret_references_are_strict() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");
        assert!(
            EvidenceConfig::parse_yaml(valid.replace("providerId", "provider_id").as_bytes())
                .is_err()
        );
        let unexpected = valid.replacen(
            "service: {providerId: urn:example:fixture:provider:evidence, trustDomain: urn:example:fixture:trust-domain:acceptance}",
            "service: {providerId: urn:example:fixture:provider:evidence, trustDomain: urn:example:fixture:trust-domain:acceptance, unexpected: true}",
            1,
        );
        assert_ne!(unexpected, valid, "fixture mutation must remain effective");
        assert!(EvidenceConfig::parse_yaml(unexpected.as_bytes()).is_err());
        let literal_secret = valid.replacen(
            "hashSecretRef: secret:file/audit-hash-key",
            "hashSecretRef: literal-audit-key",
            1,
        );
        assert_ne!(
            literal_secret, valid,
            "fixture mutation must remain effective"
        );
        assert!(EvidenceConfig::parse_yaml(literal_secret.as_bytes(),).is_err());
        let invalid_revocation = valid.replacen(
            "revokedKeyIds: []",
            "revokedKeyIds: [\"invalid\\u000Akey\"]",
            1,
        );
        assert_ne!(
            invalid_revocation, valid,
            "fixture mutation must remain effective"
        );
        assert!(EvidenceConfig::parse_yaml(invalid_revocation.as_bytes()).is_err());

        let external_revocation = valid.replacen(
            "revokedKeyIds: []",
            "revokedKeyIds: [external-issuer-key-v7]",
            1,
        );
        assert_ne!(
            external_revocation, valid,
            "fixture mutation must remain effective"
        );
        assert!(EvidenceConfig::parse_yaml(external_revocation.as_bytes()).is_ok());
    }

    #[test]
    fn context_and_grant_claim_maps_are_exact_and_non_aliasing() {
        let profile: SelectorProfile = serde_norway::from_str(
            "maximumAggregateBytes: 32\nfields:\n  alpha: {type: string, minimumBytes: 1, maximumBytes: 16}\n  beta: {type: boolean}\n",
        )
        .expect("selector profile parses");
        let exact: GrantedSubject = serde_norway::from_str(
            "role: subject\nselectorProfile: opaque-v1\nvalueOrigin: authenticated-context\nvalueClaims: {alpha: claims.alpha, beta: claims.beta}\n",
        )
        .expect("subject parses");
        assert!(exact.validate_value_claims(&profile).is_ok());

        for invalid_subject in [
            "role: subject\nselectorProfile: opaque-v1\nvalueOrigin: authenticated-context\nvalueClaims: {alpha: claims.alpha}\n",
            "role: subject\nselectorProfile: opaque-v1\nvalueOrigin: authenticated-grant\nvalueClaims: {alpha: claims.same, beta: claims.same}\n",
            "role: subject\nselectorProfile: opaque-v1\nvalueOrigin: request\nvalueClaims: {alpha: claims.alpha, beta: claims.beta}\n",
        ] {
            let subject: GrantedSubject =
                serde_norway::from_str(invalid_subject).expect("subject shape parses");
            assert!(subject.validate_value_claims(&profile).is_err());
        }
    }

    #[test]
    fn complete_authority_paths_cannot_be_unioned_across_partial_grants() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/legal-parent-relationship/evidence.yaml"
        ))
        .expect("fixture validates");
        config.authority_profiles.0[0].1.grants[0].subjects.pop();
        assert_eq!(
            config.validate(),
            Err(ConfigError::Invalid(
                "authority grant must bind the complete subject-role set"
            ))
        );
    }

    #[test]
    fn active_source_role_sets_reject_unreachable_inputs_at_startup() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/legal-parent-relationship/evidence.yaml"
        ))
        .expect("fixture validates");
        config.sources.0[0].1.request.selector_inputs[0]
            .alternatives
            .push(SelectorInputAlternative {
                profile: "person-reference-v1".to_owned(),
                fields: vec!["person_reference".to_owned()],
            });
        assert_eq!(
            config.validate(),
            Err(ConfigError::Invalid(
                "source selector input is unreachable from every complete authority path"
            ))
        );
    }

    #[test]
    fn one_source_may_serve_mutually_exclusive_complete_role_sets() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("adult fixture validates");

        let mut alternative = config.requirements[0].clone();
        alternative.id = "urn:example:fixture:requirement:adult-status-alternative:v1".to_owned();
        alternative.subject_roles[0].role = "alternate-subject".to_owned();
        alternative.evidence_type =
            "urn:example:fixture:evidence-type:adult-status-alternative:v1".to_owned();
        alternative.derivation.script =
            ArtifactPath::parse("derivations/adult-status-alternative.rhai")
                .expect("alternative derivation path");
        alternative.concepts[0].id =
            "urn:example:fixture:concept:adult-status-alternative".to_owned();
        alternative.disclosure_guard.families[0] =
            "urn:example:fixture:disclosure-family:adult-status-alternative".to_owned();

        let mut grant = config.authority_profiles.0[0].1.grants[0].clone();
        grant.requirement = alternative.id.clone();
        grant.subjects[0].role = "alternate-subject".to_owned();
        config.authority_profiles.0[0].1.grants.push(grant);

        let alternative_inputs = config.sources.0[0]
            .1
            .request
            .selector_inputs
            .iter()
            .cloned()
            .map(|mut input| {
                input.role = "alternate-subject".to_owned();
                input
            })
            .collect::<Vec<_>>();
        config.sources.0[0]
            .1
            .request
            .selector_inputs
            .extend(alternative_inputs);
        config.requirements.push(alternative);

        config
            .validate()
            .expect("mutually exclusive role sets may reuse fixed placements");
        assert_eq!(
            config.source_selector_sets("source-a"),
            vec![
                vec![(
                    "alternate-subject".to_owned(),
                    "person-demographics-v1".to_owned()
                )],
                vec![("subject".to_owned(), "person-demographics-v1".to_owned())]
            ]
        );
    }

    #[test]
    fn one_trust_domain_and_native_token_identity_are_closed_configuration() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");
        let invalid = valid.replacen(
            "service: {providerId: urn:example:fixture:provider:evidence, trustDomain: urn:example:fixture:trust-domain:acceptance}",
            "service: {providerId: urn:example:fixture:provider:evidence, trustDomains: [urn:example:fixture:trust-domain:a, urn:example:fixture:trust-domain:b]}",
            1,
        );
        assert_ne!(invalid, valid, "fixture mutation must remain effective");
        assert!(EvidenceConfig::parse_yaml(invalid.as_bytes()).is_err());
    }

    #[test]
    fn source_urls_reject_insecure_aliases_and_ambiguous_numeric_hosts() {
        for valid in [
            "https://source.invalid",
            "http://127.0.0.1:18081",
            "http://127.42.5.9",
            "http://[::1]:18083",
        ] {
            assert!(validate_source_origin(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "http://localhost:18081",
            "http://127.1:18081",
            "http://127.00.0.1:18081",
            "http://192.168.1.2",
            "https://user@source.invalid",
            "https://source.invalid/path",
            "https://source.invalid#fragment",
        ] {
            assert!(validate_source_origin(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn source_adapter_name_is_audit_safe_and_oauth_endpoint_has_no_query() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");

        let uppercase_adapter = valid.replace(
            "extractScript: adapters/source-a.rhai",
            "extractScript: adapters/Source-a.rhai",
        );
        assert_eq!(
            EvidenceConfig::parse_yaml(uppercase_adapter.as_bytes()),
            Err(ConfigError::Invalid(
                "source adapter name must be a local identifier"
            ))
        );

        for query in [
            "?client_secret=plaintext",
            "?client_id=duplicate",
            "?fixed=true",
        ] {
            let mut oauth =
                EvidenceConfig::parse_yaml(valid.as_bytes()).expect("fixture validates");
            oauth.sources.0[0].1.authentication = SourceAuthentication::Oauth2ClientCredentials {
                token_endpoint: format!("https://source.invalid/token{query}"),
                client_id_ref: SecretRef::parse("secret:file/oauth-client-id").expect("secret ref"),
                client_secret_ref: Some(
                    SecretRef::parse("secret:file/oauth-client-secret").expect("secret ref"),
                ),
                client_assertion_key_ref: None,
                client_assertion_audience: None,
                scope: None,
                audience: None,
                credential_placement: Some(CredentialPlacement::FormBody),
                maximum_cache_seconds: 60,
                assumed_lifetime_seconds: None,
            };
            assert_eq!(
                oauth.validate(),
                Err(ConfigError::Invalid(
                    "OAuth token endpoint must not contain a query"
                )),
                "{query}"
            );
        }
    }

    /// The assumed lifetime is a governed positive duration, so a zero or
    /// oversized value is a configuration error rather than a silent clamp.
    #[test]
    fn oauth_assumed_token_lifetime_is_a_bounded_positive_duration() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");

        for (assumed_lifetime_seconds, expected) in [
            (
                Some(0),
                Err(ConfigError::Invalid(
                    "numeric value is outside Version 1 bounds",
                )),
            ),
            (Some(1), Ok(())),
            (Some(86_400), Ok(())),
            (
                Some(86_401),
                Err(ConfigError::Invalid(
                    "numeric value is outside Version 1 bounds",
                )),
            ),
            (None, Ok(())),
        ] {
            let mut oauth =
                EvidenceConfig::parse_yaml(valid.as_bytes()).expect("fixture validates");
            oauth.sources.0[0].1.authentication = SourceAuthentication::Oauth2ClientCredentials {
                token_endpoint: "https://source.invalid/token".to_owned(),
                client_id_ref: SecretRef::parse("secret:file/oauth-client-id").expect("secret ref"),
                client_secret_ref: Some(
                    SecretRef::parse("secret:file/oauth-client-secret").expect("secret ref"),
                ),
                client_assertion_key_ref: None,
                client_assertion_audience: None,
                scope: None,
                audience: None,
                credential_placement: Some(CredentialPlacement::FormBody),
                maximum_cache_seconds: 60,
                assumed_lifetime_seconds,
            };
            assert_eq!(oauth.validate(), expected, "{assumed_lifetime_seconds:?}");
        }
    }

    /// Query-string placement puts the client id and secret in a URL that
    /// authorization-server, proxy, and ingress logs capture, and RFC 6749
    /// section 2.3.1 requires those parameters to travel in the request body.
    /// Version 1 accepts only the two placements the specification defines,
    /// and the runtime and the published contract must agree on that.
    #[test]
    fn oauth_credential_placement_rejects_the_query_string_placement() {
        let validator = bundle_contract_validator();
        for (placement, accepted) in [
            ("basic-header", true),
            ("form-body", true),
            ("query-string", false),
        ] {
            let authentication = serde_json::json!({
                "kind": "oauth2-client-credentials",
                "tokenEndpoint": "https://source.invalid/token",
                "clientIdRef": "secret:file/oauth-client-id",
                "clientSecretRef": "secret:file/oauth-client-secret",
                "credentialPlacement": placement,
                "maximumCacheSeconds": 60,
            });
            assert_eq!(
                serde_json::from_value::<SourceAuthentication>(authentication.clone()).is_ok(),
                accepted,
                "{placement} runtime deserialization"
            );

            let mut instance = bundle_contract_instance(include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            ));
            instance["sources"]["source-a"]["authentication"] = authentication;
            assert_eq!(
                validator.is_valid(&instance),
                accepted,
                "{placement} bundle contract"
            );
        }
    }

    /// The kind writes the Authorization header, and RFC 9110 section 11.1
    /// makes the scheme a token the origin chooses. Deployed sources ask for
    /// schemes other than Bearer, and `static-api-key` cannot serve them
    /// because it refuses the Authorization header by name, so the scheme has
    /// to be statable here. It stays a token so no configured value can inject
    /// a second header field.
    #[test]
    fn static_authorization_scheme_is_an_optional_http_token() {
        let validator = bundle_contract_validator();
        for (scheme, accepted) in [
            (Some("Bearer"), true),
            (Some("Token"), true),
            (Some("SSWS"), true),
            (Some("A"), true),
            (Some("x".repeat(32).as_str()), true),
            (Some(""), false),
            (Some("x".repeat(33).as_str()), false),
            (Some("Bearer token"), false),
            (Some("Bear\ner"), false),
            (Some("Bearer:"), false),
            (None, true),
        ] {
            let mut authentication = serde_json::json!({
                "kind": "static-authorization",
                "tokenRef": "secret:file/source-a-token",
            });
            if let Some(scheme) = scheme {
                authentication["scheme"] = serde_json::json!(scheme);
            }

            let parsed = serde_json::from_value::<SourceAuthentication>(authentication.clone())
                .expect("the member set is closed but every scheme string parses");
            assert_eq!(parsed.validate().is_ok(), accepted, "{scheme:?} validation");

            let mut instance = bundle_contract_instance(include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            ));
            instance["sources"]["source-a"]["authentication"] = authentication;
            assert_eq!(
                validator.is_valid(&instance),
                accepted,
                "{scheme:?} bundle contract"
            );
        }
    }

    /// RFC 7523 section 2.2 authenticates the client with a signed assertion
    /// instead of a shared secret, and SMART on FHIR Backend Services requires
    /// that form. The two forms are alternatives, not a spectrum: a bundle that
    /// declares both leaves the runtime to guess which credential the operator
    /// meant, and one that declares neither cannot authenticate at all. Both
    /// fail closed at startup rather than at the first token request.
    #[test]
    fn oauth_client_authentication_declares_exactly_one_credential_form() {
        let validator = bundle_contract_validator();
        for (secret_ref, placement, key_ref, accepted) in [
            (
                Some("secret:file/oauth-client-secret"),
                Some("basic-header"),
                None,
                true,
            ),
            (
                Some("secret:file/oauth-client-secret"),
                Some("form-body"),
                None,
                true,
            ),
            (None, None, Some("secret:file/oauth-client-key"), true),
            // A secret with no placement leaves the runtime to pick where the
            // credential travels, which RFC 6749 section 2.3.1 makes the
            // operator's decision.
            (Some("secret:file/oauth-client-secret"), None, None, false),
            // A placement with no secret names a channel for a credential that
            // does not exist.
            (
                None,
                Some("basic-header"),
                Some("secret:file/oauth-client-key"),
                false,
            ),
            (None, Some("basic-header"), None, false),
            // Both forms at once, with and without a placement for the secret.
            // The placement is what makes these two distinct presence shapes
            // rather than one: dropping it must not turn a two-credential
            // bundle into an accepted assertion-only one.
            (
                Some("secret:file/oauth-client-secret"),
                Some("basic-header"),
                Some("secret:file/oauth-client-key"),
                false,
            ),
            (
                Some("secret:file/oauth-client-secret"),
                None,
                Some("secret:file/oauth-client-key"),
                false,
            ),
            // Neither form.
            (None, None, None, false),
        ] {
            let mut authentication = serde_json::json!({
                "kind": "oauth2-client-credentials",
                "tokenEndpoint": "https://source.invalid/token",
                "clientIdRef": "secret:file/oauth-client-id",
                "maximumCacheSeconds": 60,
            });
            if let Some(secret_ref) = secret_ref {
                authentication["clientSecretRef"] = serde_json::json!(secret_ref);
            }
            if let Some(placement) = placement {
                authentication["credentialPlacement"] = serde_json::json!(placement);
            }
            if let Some(key_ref) = key_ref {
                authentication["clientAssertionKeyRef"] = serde_json::json!(key_ref);
            }
            let label = format!("{secret_ref:?}/{placement:?}/{key_ref:?}");

            let parsed = serde_json::from_value::<SourceAuthentication>(authentication.clone())
                .expect("every combination is inside the closed member set");
            assert_eq!(parsed.validate().is_ok(), accepted, "{label} validation");

            let mut instance = bundle_contract_instance(include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            ));
            instance["sources"]["source-a"]["authentication"] = authentication;
            assert_eq!(
                validator.is_valid(&instance),
                accepted,
                "{label} bundle contract"
            );
        }
    }

    /// The assertion key is a credential like any other, so bundle validation
    /// has to see it. `secret_refs` is what reports the set a bundle depends
    /// on, and a form whose only credential is invisible there would look
    /// credential-free.
    #[test]
    fn the_client_assertion_key_is_reported_as_a_bundle_secret() {
        let key_form = serde_json::from_value::<SourceAuthentication>(serde_json::json!({
            "kind": "oauth2-client-credentials",
            "tokenEndpoint": "https://source.invalid/token",
            "clientIdRef": "secret:file/oauth-client-id",
            "clientAssertionKeyRef": "secret:file/oauth-client-key",
            "maximumCacheSeconds": 60,
        }))
        .expect("the key form parses");
        assert_eq!(
            key_form
                .secret_refs()
                .iter()
                .map(|reference| reference.as_str())
                .collect::<Vec<_>>(),
            [
                "secret:file/oauth-client-id",
                "secret:file/oauth-client-key"
            ]
        );
    }

    /// Some authorization servers key the issued token to an audience the
    /// scope cannot express, and return a token usable against nothing when it
    /// is absent. The value is a fixed bundle string, never derived per
    /// request.
    #[test]
    fn oauth_audience_is_a_bounded_optional_string() {
        let validator = bundle_contract_validator();
        for (audience, accepted) in [
            (Some("https://api.invalid/"), true),
            (Some("a"), true),
            (Some("a".repeat(512).as_str()), true),
            (Some(""), false),
            (Some("a".repeat(513).as_str()), false),
            (None, true),
        ] {
            let mut authentication = serde_json::json!({
                "kind": "oauth2-client-credentials",
                "tokenEndpoint": "https://source.invalid/token",
                "clientIdRef": "secret:file/oauth-client-id",
                "clientSecretRef": "secret:file/oauth-client-secret",
                "credentialPlacement": "basic-header",
                "maximumCacheSeconds": 60,
            });
            if let Some(audience) = audience {
                authentication["audience"] = serde_json::json!(audience);
            }
            let label = audience.map(str::len);

            let parsed = serde_json::from_value::<SourceAuthentication>(authentication.clone())
                .expect("the member set is closed but every audience string parses");
            assert_eq!(parsed.validate().is_ok(), accepted, "{label:?} validation");

            let mut instance = bundle_contract_instance(include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            ));
            instance["sources"]["source-a"]["authentication"] = authentication;
            assert_eq!(
                validator.is_valid(&instance),
                accepted,
                "{label:?} bundle contract"
            );
        }
    }

    /// RFC 7523 section 3 asks only that the audience identify the
    /// authorization server and leaves the exact string to out-of-band
    /// agreement, so this is an opaque identifier rather than a URL. It is
    /// bounded like the sibling `audience` and validated by the same rule.
    #[test]
    fn the_client_assertion_audience_is_a_bounded_optional_string() {
        let validator = bundle_contract_validator();
        for (audience, accepted) in [
            (Some("https://issuer.invalid/"), true),
            // An issuer identifier that shares no origin with the token
            // endpoint is the case the key exists for, so it has to pass.
            (Some("https://elsewhere.invalid/oauth2"), true),
            (Some("a"), true),
            (Some("a".repeat(512).as_str()), true),
            (Some(""), false),
            // Blank is refused here rather than at the first token request,
            // where signing rejects a whitespace-only audience as empty. A
            // bundle that passes its own contract and then fails as a
            // credential error names nothing the operator can act on.
            (Some("   "), false),
            (Some("a".repeat(513).as_str()), false),
            (None, true),
        ] {
            let mut authentication = serde_json::json!({
                "kind": "oauth2-client-credentials",
                "tokenEndpoint": "https://source.invalid/token",
                "clientIdRef": "secret:file/oauth-client-id",
                "clientAssertionKeyRef": "secret:file/oauth-client-key",
                "maximumCacheSeconds": 60,
            });
            if let Some(audience) = audience {
                authentication["clientAssertionAudience"] = serde_json::json!(audience);
            }
            let label = audience.map(str::len);

            let parsed = serde_json::from_value::<SourceAuthentication>(authentication.clone())
                .expect("the member set is closed but every audience string parses");
            assert_eq!(parsed.validate().is_ok(), accepted, "{label:?} validation");

            let mut instance = bundle_contract_instance(include_bytes!(
                "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
            ));
            instance["sources"]["source-a"]["authentication"] = authentication;
            assert_eq!(
                validator.is_valid(&instance),
                accepted,
                "{label:?} bundle contract"
            );
        }
    }

    /// Only a signed assertion carries an `aud` claim. Beside a shared secret
    /// the key names an audience nothing will ever send, so accepting it would
    /// leave an operator believing an authorization server was addressed that
    /// never was.
    #[test]
    fn a_client_assertion_audience_without_an_assertion_key_is_refused() {
        let validator = bundle_contract_validator();
        let authentication = serde_json::json!({
            "kind": "oauth2-client-credentials",
            "tokenEndpoint": "https://source.invalid/token",
            "clientIdRef": "secret:file/oauth-client-id",
            "clientSecretRef": "secret:file/oauth-client-secret",
            "credentialPlacement": "basic-header",
            "clientAssertionAudience": "https://issuer.invalid/",
            "maximumCacheSeconds": 60,
        });

        let parsed = serde_json::from_value::<SourceAuthentication>(authentication.clone())
            .expect("the combination is inside the closed member set");
        assert!(
            parsed.validate().is_err(),
            "an assertion audience was accepted beside a client secret"
        );

        let mut instance = bundle_contract_instance(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ));
        instance["sources"]["source-a"]["authentication"] = authentication;
        assert!(
            !validator.is_valid(&instance),
            "the bundle contract accepted an assertion audience beside a client secret"
        );
    }

    #[test]
    fn get_sources_must_forbid_the_json_body_channel() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture validates");
        config.sources.0[0].1.request.method = HttpMethod::GET;
        assert_eq!(
            config.validate(),
            Err(ConfigError::Invalid(
                "GET source requests must forbid the JSON body channel"
            ))
        );

        let validator = bundle_contract_validator();
        let mut instance = bundle_contract_instance(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ));
        instance["sources"]["source-a"]["request"]["method"] = serde_json::json!("GET");
        assert!(!validator.is_valid(&instance));
    }

    #[test]
    fn a_shared_disclosure_family_rejects_the_complete_bundle() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture validates");
        let mut duplicate = config.requirements[0].clone();
        duplicate.id = "urn:example:fixture:requirement:other:v1".to_owned();
        duplicate.evidence_type = "urn:example:fixture:evidence-type:other:v1".to_owned();
        duplicate.derivation.script =
            ArtifactPath::parse("derivations/other.rhai").expect("artifact path");
        duplicate.concepts[0].id = "urn:example:fixture:concept:other".to_owned();
        config.requirements.push(duplicate);
        assert_eq!(
            config.validate(),
            Err(ConfigError::Invalid(
                "enabled requirements share a disclosure family"
            ))
        );
    }

    #[test]
    fn runtime_document_is_closed_and_contains_no_governed_override_surface() {
        let valid = br#"
version: 1
bundleDirectory: /etc/registry-evidence/bundle
listener:
  bindHost: 127.0.0.1
  port: 8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file: {root: /run/secrets/registry-evidence}
signer:
  kind: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  timeoutMilliseconds: 2000
auditStorage:
  path: /var/lib/registry-evidence/audit/evidence.jsonl
  maximumFileBytes: 1073741824
outboundTls:
  systemRoots: true
  trustProfiles:
    internal-pki: {caBundleFile: /etc/registry-evidence/ca/internal.pem}
"#;
        RuntimeConfig::parse_yaml(valid).expect("closed runtime parses");
        let validator = runtime_contract_validator();
        assert!(validator.is_valid(&bundle_contract_instance(valid)));
        for reference in [
            include_bytes!("../../../products/evidence/reference/request-adapter/deployment-projects/dhis2-tracker-evidence/runtime.yaml").as_slice(),
            include_bytes!("../../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/runtime.yaml").as_slice(),
        ] {
            assert!(validator.is_valid(&bundle_contract_instance(reference)));
            RuntimeConfig::parse_yaml(reference).expect("reference runtime matches Rust contract");
        }
        for rejected_host in ["evidence.internal", "0.0.0.0", "8.8.8.8", "ff02::1"] {
            let candidate = String::from_utf8(valid.to_vec())
                .expect("runtime fixture is UTF-8")
                .replace("bindHost: 127.0.0.1", &format!("bindHost: {rejected_host}"));
            assert!(
                RuntimeConfig::parse_yaml(candidate.as_bytes()).is_err(),
                "runtime accepted prohibited bindHost {rejected_host}"
            );
        }
        for governed_key in [
            "service",
            "issuer",
            "authentication",
            "audit",
            "subjectBinding",
            "rateLimits",
            "signing",
            "selectorProfiles",
            "sources",
            "authorityProfiles",
            "requirements",
        ] {
            let mut candidate = valid.to_vec();
            candidate.extend_from_slice(format!("{governed_key}: {{}}\n").as_bytes());
            let rejection = RuntimeConfig::parse_yaml(&candidate)
                .expect_err("runtime accepted governed bundle key {governed_key}");
            let ConfigError::InvalidYaml(fault) = &rejection else {
                panic!("runtime accepted governed bundle key {governed_key}: {rejection}");
            };
            assert_eq!(
                fault.cause(),
                "unknown field",
                "governed bundle key {governed_key} was rejected for the wrong reason"
            );
            assert!(
                fault.location().is_some(),
                "governed bundle key {governed_key} was rejected without a location"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(&candidate)),
                "runtime schema accepted governed bundle key {governed_key}"
            );
        }
    }

    /// The metrics listener is opt-in operator surface. It must be absent
    /// unless an operator asks for it, must obey the same private-address rule
    /// as the evidence listener, and must not be able to reuse the evidence
    /// binding, which would publish counters on the contract listener.
    #[test]
    fn the_optional_metrics_listener_is_absent_by_default_and_stays_operator_private() {
        let base = r#"
version: 1
bundleDirectory: /etc/registry-evidence/bundle
listener:
  bindHost: 127.0.0.1
  port: 8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file: {root: /run/secrets/registry-evidence}
signer:
  kind: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  timeoutMilliseconds: 2000
auditStorage:
  path: /var/lib/registry-evidence/audit/evidence.jsonl
  maximumFileBytes: 1073741824
outboundTls:
  systemRoots: true
  trustProfiles: {}
"#;
        let validator = runtime_contract_validator();
        let default = RuntimeConfig::parse_yaml(base.as_bytes()).expect("closed runtime parses");
        assert!(
            default.metrics_listener.is_none(),
            "a deployment that asked for no metrics listener must not get one"
        );

        let configured = format!("{base}metricsListener:\n  bindHost: 127.0.0.1\n  port: 9090\n");
        assert!(validator.is_valid(&bundle_contract_instance(configured.as_bytes())));
        let parsed =
            RuntimeConfig::parse_yaml(configured.as_bytes()).expect("metrics listener parses");
        let metrics = parsed
            .metrics_listener
            .expect("the configured metrics listener is retained");
        assert_eq!(metrics.bind_host, "127.0.0.1");
        assert_eq!(metrics.port, 9090);

        for rejected_host in ["evidence.internal", "0.0.0.0", "8.8.8.8", "ff02::1"] {
            let candidate =
                format!("{base}metricsListener:\n  bindHost: {rejected_host}\n  port: 9090\n");
            assert!(
                RuntimeConfig::parse_yaml(candidate.as_bytes()).is_err(),
                "metrics listener accepted prohibited bindHost {rejected_host}"
            );
        }

        // Reusing the evidence binding would put the counters on the listener
        // the public contract describes.
        let shared = format!("{base}metricsListener:\n  bindHost: 127.0.0.1\n  port: 8080\n");
        assert!(matches!(
            RuntimeConfig::parse_yaml(shared.as_bytes()),
            Err(ConfigError::Invalid(
                "metricsListener must not share the evidence listener binding"
            ))
        ));

        // The block is closed like every other level of the document.
        let unknown = format!(
            "{base}metricsListener:\n  bindHost: 127.0.0.1\n  port: 9090\n  path: /telemetry\n"
        );
        assert!(RuntimeConfig::parse_yaml(unknown.as_bytes()).is_err());
        assert!(!validator.is_valid(&bundle_contract_instance(unknown.as_bytes())));
    }

    /// The operator half of the acquisition gate. A capability list a bundle
    /// author writes beside the requirement that uses it gates nothing, so the
    /// deployment states separately which gated kinds it may serve. Absent
    /// enables none of them, which is what every runtime file written before a
    /// gated form existed says.
    #[test]
    fn the_optional_operator_acquisition_capabilities_enable_nothing_by_default() {
        let base = r#"
version: 1
bundleDirectory: /etc/registry-evidence/bundle
listener:
  bindHost: 127.0.0.1
  port: 8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file: {root: /run/secrets/registry-evidence}
signer:
  kind: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  timeoutMilliseconds: 2000
auditStorage:
  path: /var/lib/registry-evidence/audit/evidence.jsonl
  maximumFileBytes: 1073741824
outboundTls:
  systemRoots: true
  trustProfiles: {}
"#;
        let validator = runtime_contract_validator();
        let default = RuntimeConfig::parse_yaml(base.as_bytes()).expect("closed runtime parses");
        assert!(
            default.acquisition_capabilities.is_empty(),
            "a deployment that enabled no gated acquisition kind must not get one"
        );
        assert!(!default.enables_acquisition_capability("search-then-fetch-set"));
        assert!(
            !serde_json::to_string(&default)
                .expect("the runtime configuration projects")
                .contains("acquisitionCapabilities"),
            "an absent capability list must serialize to nothing at all"
        );

        // Writing the list out and enabling nothing says what silence says, so
        // both halves of the closed surface have to read it the same way. The
        // loader accepts it, so the published contract must too: a schema
        // stricter than the loader refuses a file the deployment would load.
        let empty = format!("{base}acquisitionCapabilities: []\n");
        assert!(
            validator.is_valid(&bundle_contract_instance(empty.as_bytes())),
            "the contract refused an empty list startup accepts"
        );
        let parsed = RuntimeConfig::parse_yaml(empty.as_bytes()).expect("an empty list parses");
        assert!(!parsed.enables_acquisition_capability("search-then-fetch-set"));
        assert!(
            !serde_json::to_string(&parsed)
                .expect("the runtime configuration projects")
                .contains("acquisitionCapabilities"),
            "an empty capability list must project as the absent one does"
        );

        for declaration in [
            "acquisitionCapabilities: [search-then-fetch-set]\n",
            // The same declaration in block form, which is what an operator
            // editing the file by hand is most likely to write.
            "acquisitionCapabilities:\n  - search-then-fetch-set\n",
        ] {
            let enabled = format!("{base}{declaration}");
            assert!(
                validator.is_valid(&bundle_contract_instance(enabled.as_bytes())),
                "the contract refused a declaration startup accepts: {declaration}"
            );
            let parsed = RuntimeConfig::parse_yaml(enabled.as_bytes())
                .expect("the enabled capability parses");
            assert_eq!(parsed.acquisition_capabilities, ["search-then-fetch-set"]);
            assert!(parsed.enables_acquisition_capability("search-then-fetch-set"));
            assert!(!parsed.enables_acquisition_capability("search-then-fetch"));
        }

        for (declaration, expected) in [
            (
                "acquisitionCapabilities: [search-then-fetch-sets]\n",
                "runtime acquisition capabilities name an unknown acquisition kind",
            ),
            // The frozen Version 1 forms are not nameable here. Every
            // deployment already serves them, so naming one would say nothing
            // and leaving one out would have to mean something.
            (
                "acquisitionCapabilities: [single]\n",
                "runtime acquisition capabilities name an unknown acquisition kind",
            ),
            (
                "acquisitionCapabilities: [search-then-fetch]\n",
                "runtime acquisition capabilities name an unknown acquisition kind",
            ),
            (
                "acquisitionCapabilities: [search-then-fetch-set, search-then-fetch-set]\n",
                "runtime acquisition capabilities must be unique",
            ),
        ] {
            let candidate = format!("{base}{declaration}");
            assert_eq!(
                RuntimeConfig::parse_yaml(candidate.as_bytes()).err(),
                Some(ConfigError::Invalid(expected)),
                "{declaration}"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(candidate.as_bytes())),
                "the contract accepted a declaration startup refuses: {declaration}"
            );
        }

        // The list is a list of names, and the document stays closed around it.
        for malformed in [
            "acquisitionCapabilities: search-then-fetch-set\n",
            "acquisitionCapabilities: {searchThenFetchSet: true}\n",
            "acquisitionCapabilitie: [search-then-fetch-set]\n",
        ] {
            let candidate = format!("{base}{malformed}");
            assert!(
                RuntimeConfig::parse_yaml(candidate.as_bytes()).is_err(),
                "{malformed}"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(candidate.as_bytes())),
                "{malformed}"
            );
        }
    }

    /// Port 0 is not a port. The kernel picks an arbitrary one, so the socket an
    /// operator firewalls, health-checks, and puts behind their TLS terminator
    /// is not the socket the service opens, and it changes on every restart.
    /// The published runtime schema already forbids it on both listeners; the
    /// loader accepting it meant a deployment could pass the documented contract
    /// check and still come up on an address nobody configured. On the metrics
    /// listener it also defeats the binding-collision refusal, which compares
    /// configured ports rather than bound ones.
    #[test]
    fn a_listener_port_of_zero_is_refused_on_both_listeners() {
        let base = r#"
version: 1
bundleDirectory: /etc/registry-evidence/bundle
listener:
  bindHost: 127.0.0.1
  port: 8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file: {root: /run/secrets/registry-evidence}
signer:
  kind: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  timeoutMilliseconds: 2000
auditStorage:
  path: /var/lib/registry-evidence/audit/evidence.jsonl
  maximumFileBytes: 1073741824
outboundTls:
  systemRoots: true
  trustProfiles: {}
"#;
        let validator = runtime_contract_validator();
        RuntimeConfig::parse_yaml(base.as_bytes()).expect("the configured ports load");

        let ephemeral_evidence = base.replace("port: 8080", "port: 0");
        assert!(
            RuntimeConfig::parse_yaml(ephemeral_evidence.as_bytes()).is_err(),
            "the evidence listener accepted an ephemeral port"
        );
        assert!(
            !validator.is_valid(&bundle_contract_instance(ephemeral_evidence.as_bytes())),
            "the published schema must already refuse this, so Rust is matching it"
        );

        let ephemeral_metrics =
            format!("{base}metricsListener:\n  bindHost: 127.0.0.1\n  port: 0\n");
        assert!(
            RuntimeConfig::parse_yaml(ephemeral_metrics.as_bytes()).is_err(),
            "the metrics listener accepted an ephemeral port"
        );
        assert!(!validator.is_valid(&bundle_contract_instance(ephemeral_metrics.as_bytes())));

        // Both at zero would compare equal and trip the collision rule instead,
        // so the port rule has to be the one that fires.
        let both = format!(
            "{}metricsListener:\n  bindHost: 127.0.0.1\n  port: 0\n",
            base.replace("port: 8080", "port: 0")
        );
        assert!(RuntimeConfig::parse_yaml(both.as_bytes()).is_err());
    }

    #[test]
    fn path_templates_headers_and_projection_fail_closed() {
        let bindings: OrderedMap<PathBindingConfig> = serde_norway::from_str(
            "record_reference: {from: selector, role: subject, profile: record-reference-v1, field: record_reference}\n",
        )
        .expect("path binding parses");
        assert!(validate_path_template("/records/{record_reference}", &bindings).is_ok());
        for invalid_template in [
            "/records/{record_reference}/",
            "/records/prefix-{record_reference}",
            "/records/{missing}",
            "/records/../{record_reference}",
            "/records/{record_reference}/{record_reference}",
        ] {
            assert!(validate_path_template(invalid_template, &bindings).is_err());
        }

        assert!(validate_configurable_header_name("X-API-Version").is_ok());
        for forbidden in RESERVED_HEADER_CONTRACT_CASES {
            assert!(
                validate_configurable_header_name(forbidden).is_err(),
                "{forbidden}"
            );
        }

        assert!(validate_projection(&[
            "/total".to_owned(),
            "/results/*/status".to_owned(),
            "/declaration/mother.personReference".to_owned(),
        ])
        .is_ok());
        for paths in [
            vec!["/results".to_owned(), "/results/*/status".to_owned()],
            vec![
                "/results/*/status".to_owned(),
                "/results/0/status".to_owned(),
            ],
            vec!["/bad/~2escape".to_owned()],
        ] {
            assert!(validate_projection(&paths).is_err());
        }
    }

    #[test]
    fn path_based_https_oidc_issuer_is_preserved_exactly() {
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture validates");
        config.authentication.issuer = "https://identity.example.test/realms/registry".to_owned();
        assert!(config.validate().is_ok());
        config.authentication.issuer.push_str("?tenant=wrong");
        assert!(config.validate().is_err());
    }

    #[test]
    fn file_secret_references_are_the_only_governed_secret_form() {
        assert!(SecretRef::parse("secret:file/source-token").is_ok());
        assert!(SecretRef::parse("secret:env/SOURCE_TOKEN").is_err());
        assert!(SecretRef::parse("literal-token").is_err());
    }

    #[test]
    fn service_revoked_key_ids_require_canonical_sha256_thumbprints() {
        let canonical = "A".repeat(43);
        assert!(validate_key_identifiers(&[canonical], 33, "revoked keys").is_ok());

        let noncanonical = format!("{}B", "A".repeat(42));
        assert_eq!(noncanonical.len(), 43);
        assert!(validate_key_identifiers(&[noncanonical], 33, "revoked keys").is_err());
    }

    /// Two declared fetch members, each the ordinary fixed request every
    /// Version 1 source already is, bound to the reference the search resolved.
    const MEMBER_SOURCES: &str = r#"  source-e:
    transport: http-json
    baseUrl: https://source.invalid
    posture: field-projected
    authentication: {kind: static-authorization, tokenRef: secret:file/source-e-token}
    request:
      method: GET
      pathTemplate: /v1/first/{record_id}
      pathBindings:
        record_id: {from: prior-fact, field: record_id}
      fixedHeaders: [{name: Accept, value: application/json}]
      selectorInputs: []
      prepareScript: adapters/first-member-prepare.rhai
      adapterParameters: {profile: first}
      adapterParametersSchema: schemas/first-member-adapter-parameters.schema.yaml
      preparationLimits: {query: allowed, jsonBody: forbidden, maximumNormalizedBytes: 4096}
      projection: [/total]
      redirects: deny
      timeoutMilliseconds: 3000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    responseSchema: schemas/first-member-response.schema.yaml
    extractScript: adapters/first-member-source.rhai
    factSchema: schemas/first-member-facts.schema.yaml
  source-f:
    transport: http-json
    baseUrl: https://source.invalid
    posture: field-projected
    authentication: {kind: static-authorization, tokenRef: secret:file/source-f-token}
    request:
      method: GET
      pathTemplate: /v1/second/{record_id}
      pathBindings:
        record_id: {from: prior-fact, field: record_id}
      fixedHeaders: [{name: Accept, value: application/json}]
      selectorInputs: []
      prepareScript: adapters/second-member-prepare.rhai
      adapterParameters: {profile: second}
      adapterParametersSchema: schemas/second-member-adapter-parameters.schema.yaml
      preparationLimits: {query: allowed, jsonBody: forbidden, maximumNormalizedBytes: 4096}
      projection: [/total]
      redirects: deny
      timeoutMilliseconds: 3000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    responseSchema: schemas/second-member-response.schema.yaml
    extractScript: adapters/second-member-source.rhai
    factSchema: schemas/second-member-facts.schema.yaml
  source-b:
"#;

    const DECLARED_ACQUISITION: &str = "    acquisition:\n      kind: search-then-fetch-set\n      search: source-a\n      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n      maximumAcquisitionMilliseconds: 8000\n";

    const DECLARED_MEMBERS: &str = "      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n";

    const FIRST_MEMBER: &str = "        - {source: source-e, factInputs: [record_id]}\n";

    /// One acceptance bundle rewritten into the declared fetch-set profile: the
    /// bundle declares the capability, and the first requirement resolves one
    /// reference through its search and reads that reference through two
    /// declared members.
    fn fetch_set_bundle() -> String {
        let yaml = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );
        let declared = yaml.replace(
            "\nselectorProfiles:\n",
            "\nacquisitionCapabilities: [search-then-fetch-set]\n\nselectorProfiles:\n",
        );
        assert_ne!(declared, yaml, "the capability declaration applies");
        let acquired = declared.replace(
            "    acquisition:\n      kind: single\n      source: source-a\n",
            DECLARED_ACQUISITION,
        );
        assert_ne!(acquired, declared, "the fetch-set acquisition applies");
        let members = acquired.replace("  source-b:\n", MEMBER_SOURCES);
        assert_ne!(members, acquired, "the declared members apply");
        members
    }

    #[test]
    fn fetch_set_acquisition_requires_two_to_four_distinct_configured_members() {
        let yaml = fetch_set_bundle();
        let validator = bundle_contract_validator();
        EvidenceConfig::parse_yaml(yaml.as_bytes()).expect("the declared fetch set validates");
        assert!(
            validator.is_valid(&bundle_contract_instance(yaml.as_bytes())),
            "the contract rejects the declared fetch set"
        );

        // The contract closes the shape and the width; the identity relations
        // between the declared members and the search belong to the parser,
        // which is the only side that can read one identifier against another.
        for (members, expected, contract_accepts) in [
            (
                "      fetch:\n        - {source: source-e, factInputs: [record_id]}\n",
                "requirement acquisition declares too few fetch members",
                false,
            ),
            (
                "      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n        - {source: source-g, factInputs: [record_id]}\n        - {source: source-h, factInputs: [record_id]}\n        - {source: source-i, factInputs: [record_id]}\n",
                "requirement acquisition declares too many fetch members",
                false,
            ),
            (
                "      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-e, factInputs: [record_namespace]}\n",
                "requirement acquisition fetch members must be distinct",
                true,
            ),
            (
                "      fetch:\n        - {source: source-a, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n",
                "requirement acquisition fetch member repeats the search source",
                true,
            ),
            (
                "      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n        - {source: source-z, factInputs: [record_id]}\n",
                "requirement acquisition references an unknown source",
                true,
            ),
            (
                "      fetch:\n        - {source: Source-E, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n",
                "search-then-fetch-set source identifiers are invalid",
                false,
            ),
        ] {
            let mutated = yaml.replace(DECLARED_MEMBERS, members);
            assert_ne!(mutated, yaml, "{expected}");
            assert_eq!(
                EvidenceConfig::parse_yaml(mutated.as_bytes()).err(),
                Some(ConfigError::Invalid(expected)),
                "{expected}"
            );
            assert_eq!(
                validator.is_valid(&bundle_contract_instance(mutated.as_bytes())),
                contract_accepts,
                "{expected}"
            );
        }
    }

    #[test]
    fn fetch_set_acquisition_requires_a_budget_inside_the_declared_range() {
        let yaml = fetch_set_bundle();
        let validator = bundle_contract_validator();
        for (budget, accepted) in [(0, false), (1, true), (30_000, true), (30_001, false)] {
            let mutated = yaml.replace(
                "      maximumAcquisitionMilliseconds: 8000\n",
                &format!("      maximumAcquisitionMilliseconds: {budget}\n"),
            );
            assert_ne!(mutated, yaml, "{budget}");
            let parsed = EvidenceConfig::parse_yaml(mutated.as_bytes());
            if accepted {
                parsed.unwrap_or_else(|_| panic!("the budget {budget} is inside the range"));
            } else {
                assert_eq!(
                    parsed.err(),
                    Some(ConfigError::Invalid(
                        "requirement acquisition budget is outside Version 1 bounds"
                    )),
                    "{budget}"
                );
            }
            assert_eq!(
                validator.is_valid(&bundle_contract_instance(mutated.as_bytes())),
                accepted,
                "the contract disagrees with startup validation at {budget}"
            );
        }
    }

    #[test]
    fn fetch_set_acquisition_requires_a_non_empty_fact_input_allowlist() {
        let yaml = fetch_set_bundle();
        let validator = bundle_contract_validator();
        let excessive = (0..17)
            .map(|index| format!("input_{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        for (member, expected) in [
            (
                "        - {source: source-e, factInputs: []}\n".to_owned(),
                "requirement acquisition fetch member declares no fact inputs",
            ),
            (
                format!("        - {{source: source-e, factInputs: [{excessive}]}}\n"),
                "requirement acquisition fetch member declares too many fact inputs",
            ),
            (
                "        - {source: source-e, factInputs: [record_id, record_id]}\n".to_owned(),
                "requirement acquisition fetch member fact inputs must be unique",
            ),
            (
                "        - {source: source-e, factInputs: [Record_Id]}\n".to_owned(),
                "requirement acquisition fetch member fact input is invalid",
            ),
        ] {
            let mutated = yaml.replace(FIRST_MEMBER, &member);
            assert_ne!(mutated, yaml, "{expected}");
            assert_eq!(
                EvidenceConfig::parse_yaml(mutated.as_bytes()).err(),
                Some(ConfigError::Invalid(expected)),
                "{expected}"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(mutated.as_bytes())),
                "the contract accepted an allowlist startup validation refuses: {expected}"
            );
        }
    }

    #[test]
    fn fetch_set_acquisition_must_be_declared_in_bundle_acquisition_capabilities() {
        let yaml = fetch_set_bundle();
        let validator = bundle_contract_validator();
        for (capabilities, expected, contract_accepts) in [
            (
                "",
                Some("requirement acquisition kind is not a declared bundle capability"),
                false,
            ),
            // Writing the list out and declaring nothing says what silence
            // says, and the contract refuses both for the same reason it
            // refuses silence. The published contract is what an author
            // validates against before deploying, so a document it certifies
            // has to be one startup can serve; a gated kind whose capability
            // is undeclared is the one cross-declaration relation a schema can
            // state, and leaving it to the loader alone would certify a bundle
            // that cannot serve.
            (
                "acquisitionCapabilities: []\n",
                Some("requirement acquisition kind is not a declared bundle capability"),
                false,
            ),
            (
                "acquisitionCapabilities: [search-then-fetch-sets]\n",
                Some("bundle acquisition capabilities name an unknown acquisition kind"),
                false,
            ),
            (
                "acquisitionCapabilities: [search-then-fetch-set, search-then-fetch-set]\n",
                Some("bundle acquisition capabilities must be unique"),
                false,
            ),
            (
                "acquisitionCapabilities: [single, search-then-fetch-set]\n",
                Some("bundle acquisition capabilities name an unknown acquisition kind"),
                false,
            ),
            // The same declaration in block form: valid, and textually
            // distinct from the bundle's own flow-sequence spelling.
            (
                "acquisitionCapabilities:\n  - search-then-fetch-set\n",
                None,
                true,
            ),
        ] {
            let mutated = yaml.replace(
                "acquisitionCapabilities: [search-then-fetch-set]\n",
                capabilities,
            );
            assert_ne!(mutated, yaml, "{capabilities}");
            assert_eq!(
                EvidenceConfig::parse_yaml(mutated.as_bytes())
                    .err()
                    .map(|error| match error {
                        ConfigError::Invalid(cause) => cause,
                        other => panic!("{capabilities} failed for another reason: {other}"),
                    }),
                expected,
                "{capabilities}"
            );
            assert_eq!(
                validator.is_valid(&bundle_contract_instance(mutated.as_bytes())),
                contract_accepts,
                "{capabilities}"
            );
        }
    }

    #[test]
    fn bundle_contract_closes_the_fetch_set_acquisition_form() {
        let yaml = fetch_set_bundle();
        let validator = bundle_contract_validator();
        for (acquisition, reason) in [
            (
                "    acquisition:\n      kind: search-then-fetch-set\n      search: source-a\n      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n",
                "the budget is required",
            ),
            (
                "    acquisition:\n      kind: search-then-fetch-set\n      search: source-a\n      fetch:\n        - {source: source-e, factInputs: [record_id], order: 1}\n        - {source: source-f, factInputs: [record_id]}\n      maximumAcquisitionMilliseconds: 8000\n",
                "a member declares only its source and its fact inputs",
            ),
            (
                "    acquisition:\n      kind: search-then-fetch-set\n      search: source-a\n      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n      maximumAcquisitionMilliseconds: 8000\n      concurrent: true\n",
                "the acquisition form is closed",
            ),
            (
                "    acquisition:\n      kind: search-then-fetch-sets\n      search: source-a\n      fetch:\n        - {source: source-e, factInputs: [record_id]}\n        - {source: source-f, factInputs: [record_id]}\n      maximumAcquisitionMilliseconds: 8000\n",
                "the kind vocabulary is closed",
            ),
        ] {
            let mutated = yaml.replace(DECLARED_ACQUISITION, acquisition);
            assert_ne!(mutated, yaml, "{reason}");
            assert!(
                EvidenceConfig::parse_yaml(mutated.as_bytes()).is_err(),
                "{reason}"
            );
            assert!(
                !validator.is_valid(&bundle_contract_instance(mutated.as_bytes())),
                "{reason}"
            );
        }
    }

    #[test]
    fn fetch_set_members_are_the_acquisitions_fetch_sources() {
        let yaml = fetch_set_bundle();
        let config =
            EvidenceConfig::parse_yaml(yaml.as_bytes()).expect("the declared fetch set validates");
        let requirement = &config.requirements[0];
        assert_eq!(requirement.acquisition.initial_source(), "source-a");
        assert_eq!(
            requirement.acquisition.source_ids(),
            vec!["source-a", "source-e", "source-f"]
        );
        assert_eq!(
            requirement.acquisition.fetch_sources(),
            vec!["source-e", "source-f"]
        );
        assert!(requirement.acquisition.uses_source("source-f"));
        assert!(!requirement.acquisition.uses_source("source-b"));
        assert_eq!(
            config.requirement_acquisition_posture(&requirement.id),
            Some(AcquisitionPosture::FieldProjected)
        );

        // The members are the only sources this bundle fetches, so returning
        // the requirement to one call leaves their prior-fact bindings on
        // sources nothing fetches, which is the refusal that proves members
        // carry the fetch-source rule rather than escaping it.
        let unfetched = yaml.replace(
            DECLARED_ACQUISITION,
            "    acquisition:\n      kind: single\n      source: source-a\n",
        );
        assert_ne!(unfetched, yaml, "the single-call rewrite applies");
        assert_eq!(
            EvidenceConfig::parse_yaml(unfetched.as_bytes()).err(),
            Some(ConfigError::Invalid(
                "prior-fact path bindings are permitted only on fetch sources"
            ))
        );
    }

    #[test]
    fn a_fetch_set_member_receives_only_its_declared_fact_inputs() {
        let search_facts = BTreeMap::from([
            (
                "record_id".to_owned(),
                serde_json::json!("urn:example:fixture:record:1"),
            ),
            (
                "record_namespace".to_owned(),
                serde_json::json!("urn:example:fixture:namespace"),
            ),
        ]);
        let declared = StageInputs::Declared(vec!["record_id".to_owned()]);
        assert_eq!(
            declared.project(&search_facts),
            BTreeMap::from([(
                "record_id".to_owned(),
                serde_json::json!("urn:example:fixture:record:1")
            )])
        );

        // The forms that predate the allowlist keep the inputs they froze: one
        // call reads no prior fact, and the single fetch reads all of them.
        assert!(StageInputs::None.project(&search_facts).is_empty());
        assert_eq!(
            StageInputs::EveryPriorFact.project(&search_facts),
            search_facts
        );
    }

    /// Every acquisition form describes itself as the same ordered value, so
    /// the runtime, the offline fixture harness, and adopter tooling read one
    /// derivation of the call order rather than three that can drift.
    #[test]
    fn every_acquisition_form_plans_its_stages_in_declared_order() {
        let single = AcquisitionConfig::Single {
            source: "source-a".to_owned(),
        };
        assert_eq!(
            single.plan(),
            AcquisitionPlan {
                stages: vec![PlannedStage {
                    source: "source-a".to_owned(),
                    role: StageRole::Search,
                    inputs: StageInputs::None,
                }],
                budget_milliseconds: None,
            }
        );

        let chained = AcquisitionConfig::SearchThenFetch {
            search: "source-a".to_owned(),
            fetch: "source-b".to_owned(),
        };
        assert_eq!(
            chained.plan(),
            AcquisitionPlan {
                stages: vec![
                    PlannedStage {
                        source: "source-a".to_owned(),
                        role: StageRole::Search,
                        inputs: StageInputs::None,
                    },
                    PlannedStage {
                        source: "source-b".to_owned(),
                        role: StageRole::Member,
                        inputs: StageInputs::EveryPriorFact,
                    },
                ],
                budget_milliseconds: None,
            }
        );

        let config = EvidenceConfig::parse_yaml(fetch_set_bundle().as_bytes())
            .expect("the fetch set parses");
        let plan = config.requirements[0].acquisition.plan();
        assert_eq!(
            plan,
            AcquisitionPlan {
                stages: vec![
                    PlannedStage {
                        source: "source-a".to_owned(),
                        role: StageRole::Search,
                        inputs: StageInputs::None,
                    },
                    PlannedStage {
                        source: "source-e".to_owned(),
                        role: StageRole::Member,
                        inputs: StageInputs::Declared(vec!["record_id".to_owned()]),
                    },
                    PlannedStage {
                        source: "source-f".to_owned(),
                        role: StageRole::Member,
                        inputs: StageInputs::Declared(vec!["record_id".to_owned()]),
                    },
                ],
                budget_milliseconds: Some(8000),
            }
        );

        // The planned sources are the configured sources, in the order the
        // requirement declared them, for every form.
        for acquisition in [&single, &chained, &config.requirements[0].acquisition] {
            assert_eq!(
                acquisition
                    .plan()
                    .stages
                    .iter()
                    .map(|stage| stage.source.as_str())
                    .collect::<Vec<_>>(),
                acquisition.source_ids()
            );
        }
    }

    /// A requirement's `configurationRevision` is a digest of the projected
    /// configuration, so a member every bundle serialized would move every
    /// revision an existing deployment has already published.
    #[test]
    fn an_undeclared_acquisition_capability_stays_out_of_the_projected_configuration() {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .expect("the acceptance bundle validates");
        assert!(config.acquisition_capabilities.is_empty());
        let projected = serde_json::to_value(&config).expect("the configuration projects");
        assert!(
            projected.get("acquisitionCapabilities").is_none(),
            "an undeclared capability list moves every existing configuration revision"
        );

        let declared = EvidenceConfig::parse_yaml(fetch_set_bundle().as_bytes())
            .expect("the declared fetch set validates");
        assert_eq!(
            serde_json::to_value(&declared).expect("the configuration projects")
                ["acquisitionCapabilities"],
            serde_json::json!(["search-then-fetch-set"])
        );
    }
}

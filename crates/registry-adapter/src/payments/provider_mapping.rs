// SPDX-License-Identifier: Apache-2.0
//! Pure provider-wire mappings for the fixed-role payment HTTP connector.
//!
//! Pack scripts are reviewed, digest-pinned implementation code. They receive
//! plain payment intent, non-secret settings and retained acceptance data, and
//! return closed data shapes. They never receive an origin or credential and
//! cannot select a method, endpoint role, retry policy, or additional effect.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use http::{HeaderName, HeaderValue};
use registry_adapter_core::RhaiExpression;
use registry_platform_script::rhai::{
    build_engine, call_with_fresh_scope, classify_failure, compile_entrypoint,
    entrypoint_parameters, RhaiBaseEngine, RhaiCompileError, RhaiFailureCategory, RhaiLimits,
    RhaiProfile,
};
use rhai::{Dynamic, EvalAltResult, AST};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::pack::{
    provider_path_parameters, ConnectorKind, PaymentMappingCall, PaymentOperationMapping,
    PaymentProviderPack, ProviderPackPin,
};

const MAXIMUM_SCRIPT_SOURCE_BYTES: usize = 65_536;
const MAXIMUM_INPUT_BYTES: usize = 65_536;
const MAXIMUM_REQUEST_BODY_BYTES: usize = 65_536;
const MAXIMUM_SCRIPT_OUTPUT_BYTES: usize = 131_072;
const MAXIMUM_REFERENCES: usize = 16;
const MAXIMUM_PARTIES: usize = 16;
const MAXIMUM_REQUEST_MEMBERS: usize = 32;
const MAXIMUM_TEXT_BYTES: usize = 512;
const MAXIMUM_MAPPING_PROGRAMS: usize = 32;
const CALL_DEADLINE: Duration = Duration::from_secs(2);

const SCRIPT_PROFILE: RhaiProfile = RhaiProfile {
    limits: RhaiLimits {
        operations: 100_000,
        call_levels: 32,
        expression_depth: 64,
        modules: 0,
        string_bytes: 262_144,
        array_items: 1_024,
        map_entries: 1_024,
    },
    base: RhaiBaseEngine::Deterministic,
    disabled_symbols: &["import", "export", "eval", "print", "debug"],
    allow_anonymous_fn: false,
    maximum_source_bytes: MAXIMUM_SCRIPT_SOURCE_BYTES,
};

/// The four endpoint roles the host may bind. A script cannot create another
/// role or change its HTTP method.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentEndpointRole {
    CollectionSubmit,
    CollectionStatus,
    DisbursementSubmit,
    DisbursementStatus,
}

impl PaymentEndpointRole {
    #[must_use]
    pub const fn method(self) -> PaymentHttpMethod {
        match self {
            Self::CollectionSubmit | Self::DisbursementSubmit => PaymentHttpMethod::Post,
            Self::CollectionStatus | Self::DisbursementStatus => PaymentHttpMethod::Get,
        }
    }

    #[must_use]
    pub const fn is_submit(self) -> bool {
        matches!(self, Self::CollectionSubmit | Self::DisbursementSubmit)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaymentHttpMethod {
    Get,
    Post,
}

/// The exact non-secret request plan produced before transport credential
/// injection. Its role fixes the endpoint and its method fixes mutation
/// behavior.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedProviderRequest {
    /// Exact pack identity. Its digest covers the script inventory and every
    /// operation entrypoint used to produce this request.
    pub provider_pack: ProviderPackPin,
    pub role: PaymentEndpointRole,
    pub method: PaymentHttpMethod,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    /// Exact RFC 8785 JSON bytes to persist before dispatch and send without
    /// evaluating the mapping again. Credentials are injected later.
    pub body: Option<Vec<u8>>,
}

impl PreparedProviderRequest {
    /// Revalidate a retained request before dispatch. The expected role and
    /// pack come from the enclosing attempt, not from the serialized request.
    /// Failures never include retained values. This checks the closed request
    /// shape; the caller remains responsible for authenticating the enclosing
    /// attempt and binding its intent to these retained bytes.
    pub fn validate_restored(
        &self,
        expected_role: PaymentEndpointRole,
        expected_pack: &ProviderPackPin,
    ) -> Result<(), PaymentMappingError> {
        self.validate_integrity(expected_role, expected_pack)
            .map_err(|_| PaymentMappingError::RestoredRequestInvalid)
    }

    fn validate_integrity(
        &self,
        expected_role: PaymentEndpointRole,
        expected_pack: &ProviderPackPin,
    ) -> Result<(), PaymentMappingError> {
        if self.role != expected_role
            || self.method != expected_role.method()
            || &self.provider_pack != expected_pack
            || self.query.len() > MAXIMUM_REQUEST_MEMBERS
            || self.headers.len() > MAXIMUM_REQUEST_MEMBERS
            || !valid_final_path(&self.path)
        {
            return Err(PaymentMappingError::OutputInvalid);
        }
        validate_pairs(&self.query, 128, 2_048)?;
        if validate_headers(self.headers.clone())? != self.headers {
            return Err(PaymentMappingError::OutputInvalid);
        }
        match (self.method, self.body.as_deref()) {
            (PaymentHttpMethod::Post, Some(body)) => validate_canonical_body(body),
            (PaymentHttpMethod::Get, None) => Ok(()),
            _ => Err(PaymentMappingError::OutputInvalid),
        }
    }
}

/// The only provider response material exposed to a response mapping. The raw
/// body is retained until the mapping boundary so JSON number spellings are
/// not rounded through a host floating-point representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Provider acknowledgement retained for a later status request. Reference
/// names are provider-profile data, while correlation remains host-owned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderAcceptance {
    pub correlation_id: String,
    pub references: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderObservationState {
    Pending,
    ProviderRejected,
    ProviderConfirmed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderObservedMoney {
    /// Canonical decimal digits. A response script must normalize the
    /// provider's exact amount representation into minor units without using
    /// floating-point arithmetic.
    pub minor_units: String,
    pub currency: String,
    pub scale: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderObservedParty {
    pub role: ProviderPartyRole,
    pub key: String,
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderPartyRole {
    Payer,
    Funding,
    Recipient,
}

/// A provider observation, deliberately not a paid, settled, or credited
/// result. The payment host decides whether the exact retained intent matches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderObservation {
    pub correlation_id: String,
    pub provider_reference: String,
    pub state: ProviderObservationState,
    pub money: ProviderObservedMoney,
    pub parties: Vec<ProviderObservedParty>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MappedProviderResponse {
    Acceptance(ProviderAcceptance),
    Observation(ProviderObservation),
}

/// Value-free failures. Script text, input, provider content and credentials
/// never enter an error or log boundary through this API.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PaymentMappingError {
    #[error("the payment provider pack does not carry a valid pure mapping")]
    Pack,
    #[error("a pinned payment provider script is unavailable")]
    ArtifactUnavailable,
    #[error("a pinned payment provider script digest does not match")]
    ArtifactDigest,
    #[error("a payment provider mapping does not compile under its ABI")]
    ScriptCompile,
    #[error("payment provider mapping input exceeds its bound")]
    InputBound,
    #[error("the payment provider mapping exhausted its resource bound")]
    ResourceExhausted,
    #[error("the payment provider mapping exceeded its deadline")]
    Deadline,
    #[error("the payment provider mapping failed")]
    ScriptFailed,
    #[error("the payment provider mapping returned an invalid closed output")]
    OutputInvalid,
    #[error("the retained payment provider request is invalid")]
    RestoredRequestInvalid,
}

struct CompiledCall {
    path: String,
    request_file: String,
    request_entrypoint: String,
    request: AST,
    response_file: String,
    response_entrypoint: String,
    response: AST,
}

/// Bounded in-memory authority for exact compiled provider packs. Retained
/// attempts select by the full immutable pin; a digest key is only the index,
/// never sufficient authority by itself.
#[derive(Clone, Default)]
pub struct PaymentMappingRegistry {
    programs: BTreeMap<String, std::sync::Arc<PaymentMappingProgram>>,
}

impl PaymentMappingRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, program: PaymentMappingProgram) -> Result<(), PaymentMappingError> {
        let digest = program.provider_pack.digest.clone();
        if self.programs.contains_key(&digest) {
            return Err(PaymentMappingError::Pack);
        }
        if self.programs.len() >= MAXIMUM_MAPPING_PROGRAMS {
            return Err(PaymentMappingError::InputBound);
        }
        self.programs.insert(digest, std::sync::Arc::new(program));
        Ok(())
    }

    pub fn select(
        &self,
        pin: &ProviderPackPin,
    ) -> Result<std::sync::Arc<PaymentMappingProgram>, PaymentMappingError> {
        self.programs
            .get(&pin.digest)
            .filter(|program| program.provider_pack() == pin)
            .cloned()
            .ok_or(PaymentMappingError::ArtifactUnavailable)
    }
}

/// One immutable program compiled from the complete digest-pinned mapping
/// closure. It contains no transport client, endpoint origin, or credential.
pub struct PaymentMappingProgram {
    provider_pack: ProviderPackPin,
    calls: BTreeMap<PaymentEndpointRole, CompiledCall>,
}

impl PaymentMappingProgram {
    /// Compile all and only the scripts inventoried by `pack`. `artifacts` is
    /// an in-memory authority supplied by the host, keyed by exact pack path.
    pub fn compile(
        pack: &PaymentProviderPack,
        pack_bytes: &[u8],
        artifacts: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, PaymentMappingError> {
        let decoded =
            PaymentProviderPack::from_yaml(pack_bytes).map_err(|_| PaymentMappingError::Pack)?;
        if &decoded != pack {
            return Err(PaymentMappingError::Pack);
        }
        pack.validate().map_err(|_| PaymentMappingError::Pack)?;
        if pack.connector != ConnectorKind::AdapterPaymentHttpV1 {
            return Err(PaymentMappingError::Pack);
        }
        let mapping = pack.mapping.as_ref().ok_or(PaymentMappingError::Pack)?;
        let inventory = mapping
            .scripts
            .iter()
            .map(|script| (script.path.as_str(), script.digest.as_str()))
            .collect::<BTreeMap<_, _>>();
        if artifacts.len() != inventory.len()
            || artifacts
                .keys()
                .any(|path| !inventory.contains_key(path.as_str()))
        {
            return Err(PaymentMappingError::ArtifactUnavailable);
        }
        let mut sources = BTreeMap::new();
        for (path, digest) in inventory {
            let bytes = artifacts
                .get(path)
                .ok_or(PaymentMappingError::ArtifactUnavailable)?;
            if bytes.len() > MAXIMUM_SCRIPT_SOURCE_BYTES {
                return Err(PaymentMappingError::ScriptCompile);
            }
            if registry_platform_config::sha256_uri(bytes) != digest {
                return Err(PaymentMappingError::ArtifactDigest);
            }
            let source =
                std::str::from_utf8(bytes).map_err(|_| PaymentMappingError::ScriptCompile)?;
            sources.insert(path, source);
        }

        let mut calls = BTreeMap::new();
        if let Some(operation) = &mapping.collection {
            compile_operation(
                &mut calls,
                PaymentEndpointRole::CollectionSubmit,
                PaymentEndpointRole::CollectionStatus,
                operation,
                &sources,
            )?;
        }
        if let Some(operation) = &mapping.disbursement {
            compile_operation(
                &mut calls,
                PaymentEndpointRole::DisbursementSubmit,
                PaymentEndpointRole::DisbursementStatus,
                operation,
                &sources,
            )?;
        }
        Ok(Self {
            provider_pack: ProviderPackPin {
                id: pack.id.clone(),
                version: pack.version.clone(),
                digest: registry_platform_config::sha256_uri(pack_bytes),
            },
            calls,
        })
    }

    /// Run the request mapping for one fixed endpoint role.
    pub fn prepare(
        &self,
        role: PaymentEndpointRole,
        intent: &Value,
        settings: &Value,
        acceptance: Option<&ProviderAcceptance>,
    ) -> Result<PreparedProviderRequest, PaymentMappingError> {
        validate_context(role, intent, settings, acceptance)?;
        let call = self.calls.get(&role).ok_or(PaymentMappingError::Pack)?;
        let acceptance = acceptance
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| PaymentMappingError::InputBound)?
            .unwrap_or(Value::Null);
        let output = run(
            &call.request,
            &call.request_entrypoint,
            &[intent.clone(), settings.clone(), acceptance],
        )?;
        let mapped: MappedRequest =
            serde_json::from_value(output).map_err(|_| PaymentMappingError::OutputInvalid)?;
        mapped.finish(role, &call.path, &self.provider_pack)
    }

    /// Run the response mapping and decode its result by endpoint role.
    pub fn interpret(
        &self,
        role: PaymentEndpointRole,
        intent: &Value,
        settings: &Value,
        acceptance: Option<&ProviderAcceptance>,
        response: &ProviderHttpResponse,
    ) -> Result<MappedProviderResponse, PaymentMappingError> {
        validate_context(role, intent, settings, acceptance)?;
        if !(100..=599).contains(&response.status) {
            return Err(PaymentMappingError::InputBound);
        }
        let body = exact_provider_json(&response.body)?;
        let call = self.calls.get(&role).ok_or(PaymentMappingError::Pack)?;
        let acceptance = acceptance
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| PaymentMappingError::InputBound)?
            .unwrap_or(Value::Null);
        let response = serde_json::json!({"status": response.status, "body": body});
        let output = run_bounded(
            &call.response,
            &call.response_entrypoint,
            &[intent.clone(), settings.clone(), acceptance, response],
            MAXIMUM_SCRIPT_OUTPUT_BYTES,
        )?;
        if role.is_submit() {
            let acceptance: ProviderAcceptance =
                serde_json::from_value(output).map_err(|_| PaymentMappingError::OutputInvalid)?;
            acceptance.validate()?;
            Ok(MappedProviderResponse::Acceptance(acceptance))
        } else {
            let observation: ProviderObservation =
                serde_json::from_value(output).map_err(|_| PaymentMappingError::OutputInvalid)?;
            observation.validate(role)?;
            Ok(MappedProviderResponse::Observation(observation))
        }
    }

    /// The exact script identity used for one role, for attempt and audit
    /// correlation without exposing the script source.
    #[must_use]
    pub fn script_identity(&self, role: PaymentEndpointRole) -> Option<(&str, &str)> {
        self.calls.get(&role).map(|call| {
            // The pair names request and response compilation units. A caller
            // already retains the pack digest as the authority over both.
            (call.request_file.as_str(), call.response_file.as_str())
        })
    }

    #[must_use]
    pub fn provider_pack(&self) -> &ProviderPackPin {
        &self.provider_pack
    }
}

fn compile_operation(
    calls: &mut BTreeMap<PaymentEndpointRole, CompiledCall>,
    submit_role: PaymentEndpointRole,
    status_role: PaymentEndpointRole,
    operation: &PaymentOperationMapping,
    sources: &BTreeMap<&str, &str>,
) -> Result<(), PaymentMappingError> {
    calls.insert(submit_role, compile_call(&operation.submit, sources)?);
    if let Some(status) = &operation.status {
        calls.insert(status_role, compile_call(status, sources)?);
    }
    Ok(())
}

fn compile_call(
    call: &PaymentMappingCall,
    sources: &BTreeMap<&str, &str>,
) -> Result<CompiledCall, PaymentMappingError> {
    let request = compile_expression(
        &call.request,
        sources,
        &["intent", "settings", "acceptance"],
    )?;
    let response = compile_expression(
        &call.response,
        sources,
        &["intent", "settings", "acceptance", "response"],
    )?;
    Ok(CompiledCall {
        path: call.path.clone(),
        request_file: call.request.file.clone(),
        request_entrypoint: call.request.entrypoint.clone(),
        request,
        response_file: call.response.file.clone(),
        response_entrypoint: call.response.entrypoint.clone(),
        response,
    })
}

fn compile_expression(
    expression: &RhaiExpression,
    sources: &BTreeMap<&str, &str>,
    parameters: &[&str],
) -> Result<AST, PaymentMappingError> {
    let source = sources
        .get(expression.file.as_str())
        .ok_or(PaymentMappingError::ArtifactUnavailable)?;
    let ast = compile_entrypoint(
        &SCRIPT_PROFILE,
        source,
        &expression.entrypoint,
        &[parameters.len()],
    )
    .map_err(|error| match error {
        RhaiCompileError::SourceBound
        | RhaiCompileError::Parse(_)
        | RhaiCompileError::Entrypoint => PaymentMappingError::ScriptCompile,
    })?;
    if entrypoint_parameters(&ast, &expression.entrypoint) != parameters {
        return Err(PaymentMappingError::ScriptCompile);
    }
    Ok(ast)
}

fn validate_context(
    role: PaymentEndpointRole,
    intent: &Value,
    settings: &Value,
    acceptance: Option<&ProviderAcceptance>,
) -> Result<(), PaymentMappingError> {
    bounded_json(intent, MAXIMUM_INPUT_BYTES)?;
    bounded_json(settings, MAXIMUM_INPUT_BYTES)?;
    match (role.is_submit(), acceptance) {
        (true, None) => Ok(()),
        (false, Some(acceptance)) => acceptance.validate(),
        _ => Err(PaymentMappingError::InputBound),
    }
}

fn run(ast: &AST, entrypoint: &str, arguments: &[Value]) -> Result<Value, PaymentMappingError> {
    run_bounded(ast, entrypoint, arguments, MAXIMUM_INPUT_BYTES)
}

fn run_bounded(
    ast: &AST,
    entrypoint: &str,
    arguments: &[Value],
    maximum_argument_bytes: usize,
) -> Result<Value, PaymentMappingError> {
    for argument in arguments {
        bounded_json(argument, maximum_argument_bytes)?;
    }
    let dynamic = arguments
        .iter()
        .map(rhai::serde::to_dynamic)
        .collect::<Result<Vec<Dynamic>, _>>()
        .map_err(|_| PaymentMappingError::InputBound)?;
    let deadline = Instant::now() + CALL_DEADLINE;
    let engine = build_engine(&SCRIPT_PROFILE, Some(deadline), |_| {});
    let result = match dynamic.as_slice() {
        [one, two, three] => call_with_fresh_scope(
            &engine,
            ast,
            entrypoint,
            (one.clone(), two.clone(), three.clone()),
        ),
        [one, two, three, four] => call_with_fresh_scope(
            &engine,
            ast,
            entrypoint,
            (one.clone(), two.clone(), three.clone(), four.clone()),
        ),
        _ => return Err(PaymentMappingError::ScriptFailed),
    }
    .map_err(|error| script_failure(&error, deadline))?;
    let output = rhai::serde::from_dynamic::<Value>(&result)
        .map_err(|_| PaymentMappingError::OutputInvalid)?;
    bounded_json(&output, MAXIMUM_SCRIPT_OUTPUT_BYTES)?;
    Ok(output)
}

/// Validate one bounded JSON document, then expose its body numbers to Rhai as
/// strings containing their exact source lexemes. The validation remains with
/// the shared duplicate-rejecting parser. This scanner only finds already
/// validated number tokens, and does not implement or relax JSON syntax.
fn exact_provider_json(bytes: &[u8]) -> Result<Value, PaymentMappingError> {
    if bytes.len() > MAXIMUM_INPUT_BYTES {
        return Err(PaymentMappingError::InputBound);
    }
    registry_platform_canonical_json::parse_json_preserving_integers(bytes)
        .map_err(|_| PaymentMappingError::InputBound)?;

    let mut quoted = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            quoted.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            quoted.push(byte);
            in_string = true;
            index += 1;
            continue;
        }
        if byte.is_ascii_digit()
            || (byte == b'-' && bytes.get(index + 1).is_some_and(u8::is_ascii_digit))
        {
            quoted.push(b'"');
            while index < bytes.len()
                && matches!(bytes[index], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
            {
                quoted.push(bytes[index]);
                index += 1;
            }
            quoted.push(b'"');
            continue;
        }
        quoted.push(byte);
        index += 1;
    }
    if quoted.len() > MAXIMUM_SCRIPT_OUTPUT_BYTES {
        return Err(PaymentMappingError::InputBound);
    }
    registry_platform_canonical_json::parse_json_preserving_integers(&quoted)
        .map_err(|_| PaymentMappingError::InputBound)
}

fn script_failure(error: &EvalAltResult, deadline: Instant) -> PaymentMappingError {
    if matches!(error, EvalAltResult::ErrorTerminated(..)) && Instant::now() >= deadline {
        return PaymentMappingError::Deadline;
    }
    match classify_failure(error) {
        RhaiFailureCategory::ResourceExhausted => PaymentMappingError::ResourceExhausted,
        RhaiFailureCategory::Other => PaymentMappingError::ScriptFailed,
    }
}

fn bounded_json(value: &Value, maximum: usize) -> Result<(), PaymentMappingError> {
    let encoded = serde_json::to_vec(value).map_err(|_| PaymentMappingError::InputBound)?;
    if encoded.len() > maximum {
        Err(PaymentMappingError::InputBound)
    } else {
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MappedRequest {
    #[serde(default)]
    path_parameters: BTreeMap<String, String>,
    #[serde(default)]
    query: BTreeMap<String, String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<Value>,
}

impl MappedRequest {
    fn finish(
        self,
        role: PaymentEndpointRole,
        template: &str,
        provider_pack: &ProviderPackPin,
    ) -> Result<PreparedProviderRequest, PaymentMappingError> {
        if self.path_parameters.len() > MAXIMUM_REQUEST_MEMBERS
            || self.query.len() > MAXIMUM_REQUEST_MEMBERS
            || self.headers.len() > MAXIMUM_REQUEST_MEMBERS
        {
            return Err(PaymentMappingError::OutputInvalid);
        }
        let expected = provider_path_parameters(template).map_err(|_| PaymentMappingError::Pack)?;
        if expected
            != self
                .path_parameters
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
        {
            return Err(PaymentMappingError::OutputInvalid);
        }
        let mut path = template.to_owned();
        for (name, value) in self.path_parameters {
            if value.is_empty() || value.len() > MAXIMUM_TEXT_BYTES {
                return Err(PaymentMappingError::OutputInvalid);
            }
            path = path.replace(&format!("{{{{{name}}}}}"), &encode_path_segment(&value));
        }
        if !valid_final_path(&path) {
            return Err(PaymentMappingError::OutputInvalid);
        }
        validate_pairs(&self.query, 128, 2_048)?;
        let headers = validate_headers(self.headers)?;
        let body = match (role.method(), self.body) {
            (PaymentHttpMethod::Post, Some(body)) => {
                bounded_json(&body, MAXIMUM_REQUEST_BODY_BYTES)?;
                let canonical = registry_platform_canonical_json::canonicalize_json(&body)
                    .map_err(|_| PaymentMappingError::OutputInvalid)?;
                if canonical.len() > MAXIMUM_REQUEST_BODY_BYTES {
                    return Err(PaymentMappingError::OutputInvalid);
                }
                Some(canonical)
            }
            (PaymentHttpMethod::Get, None) => None,
            _ => return Err(PaymentMappingError::OutputInvalid),
        };
        let request = PreparedProviderRequest {
            provider_pack: provider_pack.clone(),
            role,
            method: role.method(),
            path,
            query: self.query,
            headers,
            body,
        };
        request.validate_integrity(role, provider_pack)?;
        Ok(request)
    }
}

fn valid_final_path(path: &str) -> bool {
    path.len() <= 4_096
        && provider_path_parameters(path).is_ok_and(|parameters| parameters.is_empty())
}

fn validate_canonical_body(body: &[u8]) -> Result<(), PaymentMappingError> {
    if body.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(PaymentMappingError::OutputInvalid);
    }
    let value = registry_platform_canonical_json::parse_json_strict(body)
        .map_err(|_| PaymentMappingError::OutputInvalid)?;
    let canonical = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| PaymentMappingError::OutputInvalid)?;
    if canonical.as_slice() == body {
        Ok(())
    } else {
        Err(PaymentMappingError::OutputInvalid)
    }
}

fn validate_pairs(
    pairs: &BTreeMap<String, String>,
    maximum_name: usize,
    maximum_value: usize,
) -> Result<(), PaymentMappingError> {
    if pairs.iter().any(|(name, value)| {
        name.is_empty()
            || name.len() > maximum_name
            || value.len() > maximum_value
            || name.bytes().any(|byte| byte.is_ascii_control())
            || value.bytes().any(|byte| byte.is_ascii_control())
    }) {
        Err(PaymentMappingError::OutputInvalid)
    } else {
        Ok(())
    }
}

fn validate_headers(
    headers: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, PaymentMappingError> {
    let mut admitted = BTreeMap::new();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| PaymentMappingError::OutputInvalid)?;
        let lowered = name.as_str();
        if forbidden_header(lowered)
            || HeaderValue::from_str(&value).is_err()
            || value.len() > 4_096
            || admitted.insert(lowered.to_owned(), value).is_some()
        {
            return Err(PaymentMappingError::OutputInvalid);
        }
    }
    Ok(admitted)
}

fn forbidden_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "upgrade"
            | "x-api-key"
            | "api-key"
            | "x-auth-token"
            | "x-access-token"
            | "traceparent"
            | "tracestate"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-http-method-override"
            | "x-method-override"
            | "x-original-url"
            | "x-rewrite-url"
    )
}

fn encode_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

impl ProviderAcceptance {
    fn validate(&self) -> Result<(), PaymentMappingError> {
        if !bounded_text(&self.correlation_id, MAXIMUM_TEXT_BYTES)
            || self.references.is_empty()
            || self.references.len() > MAXIMUM_REFERENCES
            || self.references.iter().any(|(key, value)| {
                !bounded_identifier(key, 64) || !bounded_text(value, MAXIMUM_TEXT_BYTES)
            })
        {
            Err(PaymentMappingError::OutputInvalid)
        } else {
            Ok(())
        }
    }
}

impl ProviderObservation {
    fn validate(&self, role: PaymentEndpointRole) -> Result<(), PaymentMappingError> {
        let payer_count = self
            .parties
            .iter()
            .filter(|party| party.role == ProviderPartyRole::Payer)
            .count();
        let funding_count = self
            .parties
            .iter()
            .filter(|party| party.role == ProviderPartyRole::Funding)
            .count();
        let recipient_count = self
            .parties
            .iter()
            .filter(|party| party.role == ProviderPartyRole::Recipient)
            .count();
        let distinct_party_keys = self
            .parties
            .iter()
            .map(|party| party.key.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == self.parties.len();
        let roles_match = match role {
            PaymentEndpointRole::CollectionStatus => {
                payer_count == 2 && funding_count == 0 && recipient_count == 0
            }
            PaymentEndpointRole::DisbursementStatus => {
                payer_count == 0 && funding_count == 1 && recipient_count == 1
            }
            PaymentEndpointRole::CollectionSubmit | PaymentEndpointRole::DisbursementSubmit => {
                false
            }
        };
        if !bounded_text(&self.correlation_id, MAXIMUM_TEXT_BYTES)
            || !bounded_text(&self.provider_reference, MAXIMUM_TEXT_BYTES)
            || !valid_minor_units(&self.money.minor_units)
            || self.money.currency.len() != 3
            || !self
                .money
                .currency
                .bytes()
                .all(|byte| byte.is_ascii_uppercase())
            || self.money.scale > 6
            || !roles_match
            || !distinct_party_keys
            || self.parties.len() > MAXIMUM_PARTIES
            || self.parties.iter().any(|party| {
                !bounded_text(&party.key, 128) || !bounded_text(&party.value, MAXIMUM_TEXT_BYTES)
            })
        {
            Err(PaymentMappingError::OutputInvalid)
        } else {
            Ok(())
        }
    }
}

fn valid_minor_units(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
        && value
            .parse::<u64>()
            .is_ok_and(|minor_units| minor_units > 0)
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn bounded_identifier(value: &str, maximum: usize) -> bool {
    bounded_text(value, maximum)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn registry_holds_missing_old_pack_and_selects_each_exact_retained_pin() {
        let pin_a = pin("provider-a", 'a');
        let pin_b = pin("provider-b", 'b');
        let mut registry = PaymentMappingRegistry::default();

        assert!(matches!(
            registry.select(&pin_a),
            Err(PaymentMappingError::ArtifactUnavailable)
        ));
        registry.insert(program(pin_b.clone())).unwrap();
        assert_eq!(registry.select(&pin_b).unwrap().provider_pack(), &pin_b);
        assert!(matches!(
            registry.select(&pin_a),
            Err(PaymentMappingError::ArtifactUnavailable)
        ));

        registry.insert(program(pin_a.clone())).unwrap();
        assert_eq!(registry.select(&pin_a).unwrap().provider_pack(), &pin_a);
        assert_eq!(registry.select(&pin_b).unwrap().provider_pack(), &pin_b);

        let forged = ProviderPackPin {
            id: "forged-provider".to_owned(),
            version: pin_a.version.clone(),
            digest: pin_a.digest.clone(),
        };
        assert!(matches!(
            registry.select(&forged),
            Err(PaymentMappingError::ArtifactUnavailable)
        ));
        assert!(matches!(
            registry.insert(program(pin_a)),
            Err(PaymentMappingError::Pack)
        ));
    }

    #[test]
    fn registry_refuses_more_than_the_bounded_pack_set() {
        let mut registry = PaymentMappingRegistry::new();
        for index in 0..MAXIMUM_MAPPING_PROGRAMS {
            let digest = format!("sha256:{index:064x}");
            registry
                .insert(program(ProviderPackPin {
                    id: format!("provider-{index}"),
                    version: "1".to_owned(),
                    digest,
                }))
                .unwrap();
        }
        assert!(matches!(
            registry.insert(program(ProviderPackPin {
                id: "one-too-many".to_owned(),
                version: "1".to_owned(),
                digest: format!("sha256:{}", "f".repeat(64)),
            })),
            Err(PaymentMappingError::InputBound)
        ));
    }

    fn program(provider_pack: ProviderPackPin) -> PaymentMappingProgram {
        PaymentMappingProgram {
            provider_pack,
            calls: BTreeMap::new(),
        }
    }

    fn pin(id: &str, digest: char) -> ProviderPackPin {
        ProviderPackPin {
            id: id.to_owned(),
            version: "1".to_owned(),
            digest: format!("sha256:{}", digest.to_string().repeat(64)),
        }
    }
}

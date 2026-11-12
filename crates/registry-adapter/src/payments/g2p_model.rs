// SPDX-License-Identifier: Apache-2.0
//! Exact G2P instruction and attempt custody.
//!
//! G2P attempts are deliberately separate from fee-bill collection attempts.
//! BReg owns an immutable disbursement instruction, the provider owns its
//! execution, and this module retains only the exact bridge facts required to
//! prevent a second send and to report one correlated provider confirmation.

use super::{
    pack::{PaymentProviderAuth, ProviderPackPin},
    provider_mapping::{
        PaymentEndpointRole, PaymentHttpMethod, PreparedProviderRequest, ProviderAcceptance,
        ProviderObservation, ProviderObservationState, ProviderPartyRole,
    },
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use registry_platform_yaml::SecretReference;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_TEXT: usize = 128;
const MAX_MINOR_UNITS: u64 = 9_007_199_254_740_991;

/// Value-free failures suitable for conversion at the HTTP boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum G2pError {
    #[error("the G2P request is invalid")]
    InvalidRequest,
    #[error("the G2P instruction or attempt conflicts with retained custody")]
    Conflict,
    #[error("the G2P instruction or attempt was not found")]
    NotFound,
    #[error("the G2P dependency is unavailable")]
    Unavailable,
    #[error("the G2P mutation outcome is unknown")]
    OutcomeUnknown,
    #[error("the G2P attempt is held for read-only recovery")]
    RecoveryHeld,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisbursementInstruction {
    pub record_id: Uuid,
    pub instruction_id: Uuid,
    pub instruction_version: u64,
    pub instruction_digest: String,
    pub institution_id: String,
    pub service_id: String,
    pub programme_id: String,
    pub cycle_id: String,
    pub beneficiary_id: String,
    pub beneficiary_destination: String,
    pub funding_account_id: String,
    pub amount_minor: u64,
    pub currency: String,
    pub currency_scale: u8,
}

impl DisbursementInstruction {
    pub fn validate(&self) -> Result<(), G2pError> {
        if self.record_id.is_nil()
            || self.instruction_id.is_nil()
            || self.instruction_version == 0
            || self.instruction_version > MAX_MINOR_UNITS
            || !digest_text(&self.instruction_digest)
            || !text(&self.institution_id, MAX_TEXT)
            || !text(&self.service_id, MAX_TEXT)
            || !text(&self.programme_id, MAX_TEXT)
            || !text(&self.cycle_id, MAX_TEXT)
            || !text(&self.beneficiary_id, MAX_TEXT)
            || !text(&self.beneficiary_destination, MAX_TEXT)
            || !text(&self.funding_account_id, MAX_TEXT)
            || self.amount_minor == 0
            || self.amount_minor > MAX_MINOR_UNITS
            || self.currency.len() != 3
            || !self.currency.bytes().all(|byte| byte.is_ascii_uppercase())
            || self.currency_scale > 6
        {
            return Err(G2pError::Unavailable);
        }
        Ok(())
    }

    pub fn amount(&self) -> String {
        let factor = 10_u64.pow(u32::from(self.currency_scale));
        if self.currency_scale == 0 {
            self.amount_minor.to_string()
        } else {
            format!(
                "{}.{:0width$}",
                self.amount_minor / factor,
                self.amount_minor % factor,
                width = usize::from(self.currency_scale)
            )
        }
    }

    pub fn digest(&self) -> Result<String, G2pError> {
        canonical_digest(self)
    }
}

/// Closed, host-owned authentication profile. Mapping scripts never receive
/// these credentials or choose an authentication mechanism.
#[derive(Clone)]
pub enum G2pHttpAuth {
    Bearer,
    MifosLegacySignature {
        signing_key_identity: String,
        signing_key_ref: SecretReference,
        response_key_identity: String,
        response_key_ref: SecretReference,
    },
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
enum G2pHttpAuthReader {
    Bearer {},
    MifosLegacySignature {
        signing_key_identity: String,
        signing_key_ref: SecretReference,
        response_key_identity: String,
        response_key_ref: SecretReference,
    },
}
registry_platform_yaml::tagged_union!(G2pHttpAuthReader);

impl<'de> Deserialize<'de> for G2pHttpAuth {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <G2pHttpAuthReader as Deserialize>::deserialize(deserializer).map(|reader| match reader {
            G2pHttpAuthReader::Bearer {} => Self::Bearer,
            G2pHttpAuthReader::MifosLegacySignature {
                signing_key_identity,
                signing_key_ref,
                response_key_identity,
                response_key_ref,
            } => Self::MifosLegacySignature {
                signing_key_identity,
                signing_key_ref,
                response_key_identity,
                response_key_ref,
            },
        })
    }
}

#[derive(Serialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum G2pHttpAuthWire<'a> {
    Bearer {},
    MifosLegacySignature {
        signing_key_identity: &'a str,
        signing_key_ref: &'a SecretReference,
        response_key_identity: &'a str,
        response_key_ref: &'a SecretReference,
    },
}

impl Serialize for G2pHttpAuth {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Bearer => G2pHttpAuthWire::Bearer {},
            Self::MifosLegacySignature {
                signing_key_identity,
                signing_key_ref,
                response_key_identity,
                response_key_ref,
            } => G2pHttpAuthWire::MifosLegacySignature {
                signing_key_identity,
                signing_key_ref,
                response_key_identity,
                response_key_ref,
            },
        }
        .serialize(serializer)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for G2pHttpAuth {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "G2pHttpAuth".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        G2pHttpAuthReader::json_schema(generator)
    }
}

impl G2pHttpAuth {
    pub const fn profile(&self) -> PaymentProviderAuth {
        match self {
            Self::Bearer => PaymentProviderAuth::Bearer,
            Self::MifosLegacySignature { .. } => PaymentProviderAuth::MifosLegacySignature,
        }
    }

    fn validate(&self) -> Result<(), G2pError> {
        match self {
            Self::Bearer => Ok(()),
            Self::MifosLegacySignature {
                signing_key_identity,
                response_key_identity,
                ..
            } if text(signing_key_identity, 256) && text(response_key_identity, 256) => Ok(()),
            Self::MifosLegacySignature { .. } => Err(G2pError::Unavailable),
        }
    }

    fn identity(&self) -> Value {
        match self {
            Self::Bearer => serde_json::json!({"type": "bearer"}),
            Self::MifosLegacySignature {
                signing_key_identity,
                response_key_identity,
                ..
            } => serde_json::json!({
                "type": "mifos-legacy-signature",
                "signingKeyIdentity": signing_key_identity,
                "responseKeyIdentity": response_key_identity,
            }),
        }
    }
}

/// Deployment-owned provider facts frozen into every attempt.
#[derive(Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum G2pProviderBinding {
    Http {
        revision: String,
        #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
        submit_base_url: String,
        #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
        status_base_url: String,
        credential_identity: String,
        credential_ref: SecretReference,
        auth: G2pHttpAuth,
        settings: Value,
    },
}
registry_platform_yaml::tagged_union!(G2pProviderBinding);

#[derive(Serialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum G2pProviderBindingWire<'a> {
    Http {
        revision: &'a str,
        submit_base_url: &'a str,
        status_base_url: &'a str,
        credential_identity: &'a str,
        credential_ref: &'a SecretReference,
        auth: &'a G2pHttpAuth,
        settings: &'a Value,
    },
}

impl Serialize for G2pProviderBinding {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Http {
                revision,
                submit_base_url,
                status_base_url,
                credential_identity,
                credential_ref,
                auth,
                settings,
            } => G2pProviderBindingWire::Http {
                revision,
                submit_base_url,
                status_base_url,
                credential_identity,
                credential_ref,
                auth,
                settings,
            },
        }
        .serialize(serializer)
    }
}

impl G2pProviderBinding {
    pub fn validate(&self) -> Result<(), G2pError> {
        match self {
            Self::Http {
                revision,
                submit_base_url,
                status_base_url,
                credential_identity,
                auth,
                settings,
                ..
            } => {
                if !text(revision, 256)
                    || !text(credential_identity, 256)
                    || !provider_base_url(submit_base_url)
                    || !provider_base_url(status_base_url)
                    || !non_secret_settings(settings)
                {
                    return Err(G2pError::Unavailable);
                }
                auth.validate()
            }
        }
    }

    pub fn settings(&self) -> &Value {
        match self {
            Self::Http { settings, .. } => settings,
        }
    }

    pub fn credential_ref(&self) -> &SecretReference {
        match self {
            Self::Http { credential_ref, .. } => credential_ref,
        }
    }

    pub fn auth(&self) -> &G2pHttpAuth {
        match self {
            Self::Http { auth, .. } => auth,
        }
    }

    pub const fn auth_profile(&self) -> PaymentProviderAuth {
        match self {
            Self::Http { auth, .. } => auth.profile(),
        }
    }

    pub fn base_url(&self, role: PaymentEndpointRole) -> Result<&str, G2pError> {
        match (self, role) {
            (
                Self::Http {
                    submit_base_url, ..
                },
                PaymentEndpointRole::DisbursementSubmit,
            ) => Ok(submit_base_url),
            (
                Self::Http {
                    status_base_url, ..
                },
                PaymentEndpointRole::DisbursementStatus,
            ) => Ok(status_base_url),
            _ => Err(G2pError::Unavailable),
        }
    }

    fn identity(&self) -> Result<Value, G2pError> {
        self.validate()?;
        match self {
            Self::Http {
                revision,
                submit_base_url,
                status_base_url,
                credential_identity,
                auth,
                settings,
                ..
            } => Ok(serde_json::json!({
                "type": "http",
                "revision": revision,
                "submitOrigin": canonical_origin(submit_base_url)?,
                "statusOrigin": canonical_origin(status_base_url)?,
                "credentialIdentity": credential_identity,
                "auth": auth.identity(),
                "settings": settings,
            })),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct G2pProviderMoney {
    pub minor_units: String,
    pub currency: String,
    pub scale: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct G2pProviderParty {
    pub scheme: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct G2pProviderIntent {
    pub correlation_id: String,
    pub instruction_id: Uuid,
    pub instruction_version: u64,
    pub institution_id: String,
    pub service_id: String,
    pub programme_id: String,
    pub cycle_id: String,
    pub beneficiary_id: String,
    pub funding: G2pProviderParty,
    pub recipient: G2pProviderParty,
    pub money: G2pProviderMoney,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum G2pObservationState {
    Pending,
    ProviderRejected,
    ProviderConfirmed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct G2pProviderObservation {
    pub correlation_id: String,
    pub provider_reference: Option<String>,
    pub state: G2pObservationState,
    pub money: G2pProviderMoney,
    pub funding: G2pProviderParty,
    pub recipient: G2pProviderParty,
}

/// BReg route and exact Action authority frozen into an attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct G2pRegistryBinding {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub base_url: String,
    pub credential_identity: String,
    pub credential_ref: SecretReference,
    pub record_route: String,
    pub record_type: String,
    pub read_profile: String,
    pub bind_action: String,
    pub bind_profile: String,
    pub report_action: String,
    pub report_profile: String,
}

impl G2pRegistryBinding {
    pub fn validate(&self) -> Result<(), G2pError> {
        let origin = url::Url::parse(&self.base_url).map_err(|_| G2pError::Unavailable)?;
        if origin.scheme() != "https"
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(G2pError::Unavailable);
        }
        for value in [
            &self.credential_identity,
            &self.record_route,
            &self.record_type,
            &self.read_profile,
            &self.bind_action,
            &self.bind_profile,
            &self.report_action,
            &self.report_profile,
        ] {
            if !text(value, 256) {
                return Err(G2pError::Unavailable);
            }
        }
        Ok(())
    }

    /// Stable authority namespace for disbursement uniqueness. Credential and
    /// access-profile rotation, and public connection renames, do not create a
    /// new authoritative instruction source.
    pub fn source_namespace(&self) -> Result<String, G2pError> {
        self.validate()?;
        canonical_digest(&serde_json::json!({
            "domain": "registry-adapter/g2p-source-namespace/v1",
            "origin": canonical_registry_origin(&self.base_url)?,
            "recordRoute": self.record_route,
            "recordType": self.record_type,
        }))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct G2pConnectionSnapshot {
    pub institution_id: String,
    pub service_id: String,
    pub programme_id: String,
    pub funding_account_id: String,
    pub currency: String,
    #[serde(deserialize_with = "currency_scale")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<0, 6>")
    )]
    pub currency_scale: u8,
    pub provider_pack: ProviderPackPin,
    pub funding_party_key: String,
    pub recipient_party_key: String,
    pub provider: G2pProviderBinding,
    pub registry: G2pRegistryBinding,
}

impl G2pConnectionSnapshot {
    pub fn validate(&self) -> Result<(), G2pError> {
        if !text(&self.institution_id, MAX_TEXT)
            || !text(&self.service_id, MAX_TEXT)
            || !text(&self.programme_id, MAX_TEXT)
            || !text(&self.funding_account_id, MAX_TEXT)
            || self.currency.len() != 3
            || !self.currency.bytes().all(|byte| byte.is_ascii_uppercase())
            || self.currency_scale > 6
            || !provider_pack_pin(&self.provider_pack)
            || !text(&self.funding_party_key, MAX_TEXT)
            || !text(&self.recipient_party_key, MAX_TEXT)
            || self.funding_party_key == self.recipient_party_key
        {
            return Err(G2pError::Unavailable);
        }
        self.provider.validate()?;
        self.registry.validate()
    }

    pub fn validate_instruction(
        &self,
        instruction: &DisbursementInstruction,
    ) -> Result<(), G2pError> {
        instruction.validate()?;
        if instruction.institution_id != self.institution_id
            || instruction.service_id != self.service_id
            || instruction.programme_id != self.programme_id
            || instruction.funding_account_id != self.funding_account_id
            || instruction.currency != self.currency
            || instruction.currency_scale != self.currency_scale
        {
            return Err(G2pError::Conflict);
        }
        Ok(())
    }

    pub fn revision(&self) -> Result<String, G2pError> {
        canonical_digest(self)
    }

    pub fn provider_intent(
        &self,
        instruction: &DisbursementInstruction,
    ) -> Result<G2pProviderIntent, G2pError> {
        self.validate()?;
        self.validate_instruction(instruction)?;
        let funding = G2pProviderParty {
            scheme: self.funding_party_key.clone(),
            value: instruction.funding_account_id.clone(),
        };
        let recipient = G2pProviderParty {
            scheme: self.recipient_party_key.clone(),
            value: instruction.beneficiary_destination.clone(),
        };
        let money = G2pProviderMoney {
            minor_units: instruction.amount_minor.to_string(),
            currency: instruction.currency.clone(),
            scale: instruction.currency_scale,
        };
        let identity = serde_json::json!({
            "domain": "registry-adapter/g2p-correlation/v3",
            "source": {
                "origin": canonical_origin(&self.registry.base_url)?,
                "credentialIdentity": self.registry.credential_identity,
                "recordRoute": self.registry.record_route,
                "recordType": self.registry.record_type,
                "readProfile": self.registry.read_profile,
                "bindAction": self.registry.bind_action,
                "bindProfile": self.registry.bind_profile,
                "reportAction": self.registry.report_action,
                "reportProfile": self.registry.report_profile,
            },
            "instruction": instruction,
            "providerPack": self.provider_pack,
            "provider": self.provider.identity()?,
            "exactTuple": {
                "funding": funding,
                "recipient": recipient,
                "money": money,
            },
        });
        let canonical = registry_platform_canonical_json::canonicalize_json(&identity)
            .map_err(|_| G2pError::Unavailable)?;
        let correlation_id = format!("g2p_{}", URL_SAFE_NO_PAD.encode(Sha256::digest(canonical)));
        Ok(G2pProviderIntent {
            correlation_id,
            instruction_id: instruction.instruction_id,
            instruction_version: instruction.instruction_version,
            institution_id: instruction.institution_id.clone(),
            service_id: instruction.service_id.clone(),
            programme_id: instruction.programme_id.clone(),
            cycle_id: instruction.cycle_id.clone(),
            beneficiary_id: instruction.beneficiary_id.clone(),
            funding,
            recipient,
            money,
        })
    }

    pub fn attempt_revision(
        &self,
        prepared_submit: &PreparedProviderRequest,
    ) -> Result<String, G2pError> {
        canonical_digest(&serde_json::json!({
            "domain": "registry-adapter/g2p-attempt-binding/v1",
            "binding": self,
            "preparedSubmitDigest": canonical_digest(prepared_submit)?,
        }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedG2pRegistryAction {
    pub action: String,
    pub key: String,
    pub inputs: Map<String, Value>,
    pub evidence: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum G2pAttemptState {
    BindPrepared,
    Bound,
    DispatchStarted,
    ProviderAccepted,
    ProviderPending,
    ProviderUnknown,
    ProviderConfirmed,
    ProviderFailed,
    ConfirmationPrepared,
    ConfirmationRecorded,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct G2pAttempt {
    pub id: Uuid,
    pub connection: String,
    pub principal: String,
    pub source_namespace: String,
    pub instruction: DisbursementInstruction,
    pub instruction_snapshot_digest: String,
    pub binding: G2pConnectionSnapshot,
    pub binding_revision: String,
    pub provider_intent: G2pProviderIntent,
    pub prepared_submit: PreparedProviderRequest,
    pub prepared_submit_digest: String,
    pub state: G2pAttemptState,
    pub bind_action: PreparedG2pRegistryAction,
    pub first_send_at_unix_seconds: Option<i64>,
    pub provider_acceptance: Option<ProviderAcceptance>,
    pub provider_observation: Option<G2pProviderObservation>,
    pub confirmation_action: Option<PreparedG2pRegistryAction>,
    pub provider_result_digest: Option<String>,
}

impl G2pAttempt {
    pub fn new(
        id: Uuid,
        connection: String,
        principal: String,
        instruction: DisbursementInstruction,
        binding: G2pConnectionSnapshot,
        prepared_submit: PreparedProviderRequest,
        bind_action: PreparedG2pRegistryAction,
    ) -> Result<Self, G2pError> {
        if id.is_nil() || !text(&connection, MAX_TEXT) || !text(&principal, MAX_TEXT) {
            return Err(G2pError::InvalidRequest);
        }
        instruction.validate()?;
        binding.validate()?;
        binding.validate_instruction(&instruction)?;
        let source_namespace = binding.registry.source_namespace()?;
        let instruction_snapshot_digest = instruction.digest()?;
        let provider_intent = binding.provider_intent(&instruction)?;
        validate_prepared_submit(&binding, &prepared_submit)?;
        let prepared_submit_digest = canonical_digest(&prepared_submit)?;
        let binding_revision = binding.attempt_revision(&prepared_submit)?;
        let attempt = Self {
            id,
            connection,
            principal,
            source_namespace,
            instruction,
            instruction_snapshot_digest,
            binding,
            binding_revision,
            provider_intent,
            prepared_submit,
            prepared_submit_digest,
            state: G2pAttemptState::BindPrepared,
            bind_action,
            first_send_at_unix_seconds: None,
            provider_acceptance: None,
            provider_observation: None,
            confirmation_action: None,
            provider_result_digest: None,
        };
        attempt.validate_integrity()?;
        Ok(attempt)
    }

    pub fn status_state(&self) -> G2pObservationState {
        match self.state {
            G2pAttemptState::ProviderAccepted | G2pAttemptState::ProviderPending => {
                G2pObservationState::Pending
            }
            G2pAttemptState::ProviderConfirmed
            | G2pAttemptState::ConfirmationPrepared
            | G2pAttemptState::ConfirmationRecorded => G2pObservationState::ProviderConfirmed,
            G2pAttemptState::ProviderFailed => G2pObservationState::ProviderRejected,
            G2pAttemptState::BindPrepared
            | G2pAttemptState::Bound
            | G2pAttemptState::DispatchStarted
            | G2pAttemptState::ProviderUnknown => G2pObservationState::Pending,
        }
    }

    pub fn validate_integrity(&self) -> Result<(), G2pError> {
        self.instruction.validate()?;
        self.binding.validate()?;
        self.binding.validate_instruction(&self.instruction)?;
        if self.binding.registry.source_namespace()? != self.source_namespace
            || self.instruction.digest()? != self.instruction_snapshot_digest
            || self.binding.provider_intent(&self.instruction)? != self.provider_intent
            || canonical_digest(&self.prepared_submit)? != self.prepared_submit_digest
            || self.binding.attempt_revision(&self.prepared_submit)? != self.binding_revision
            || validate_prepared_submit(&self.binding, &self.prepared_submit).is_err()
            || self.bind_action.action != self.binding.registry.bind_action
        {
            return Err(G2pError::Unavailable);
        }
        let dispatched = self.first_send_at_unix_seconds.is_some();
        let accepted = self.provider_acceptance.is_some();
        let observed = self.provider_observation.is_some();
        let confirmation = self.confirmation_action.is_some();
        let result_digest = self.provider_result_digest.is_some();
        let valid_shape = match self.state {
            G2pAttemptState::BindPrepared | G2pAttemptState::Bound => {
                !dispatched && !accepted && !observed && !confirmation && !result_digest
            }
            G2pAttemptState::DispatchStarted => {
                dispatched && !accepted && !observed && !confirmation && !result_digest
            }
            G2pAttemptState::ProviderAccepted => {
                dispatched && accepted && !observed && !confirmation && !result_digest
            }
            G2pAttemptState::ProviderPending
            | G2pAttemptState::ProviderUnknown
            | G2pAttemptState::ProviderConfirmed
            | G2pAttemptState::ProviderFailed => {
                dispatched && accepted && observed && !confirmation && result_digest
            }
            G2pAttemptState::ConfirmationPrepared | G2pAttemptState::ConfirmationRecorded => {
                dispatched && accepted && observed && confirmation && result_digest
            }
        };
        if !valid_shape {
            return Err(G2pError::Unavailable);
        }
        if let (Some(accepted), Some(observation)) =
            (&self.provider_acceptance, &self.provider_observation)
        {
            self.validate_observation(accepted, observation)?;
            let expected = canonical_digest(observation)?;
            if self.provider_result_digest.as_deref() != Some(&expected) {
                return Err(G2pError::Unavailable);
            }
            let expected_state = match observation.state {
                G2pObservationState::Pending => G2pAttemptState::ProviderPending,
                G2pObservationState::ProviderConfirmed => G2pAttemptState::ProviderConfirmed,
                G2pObservationState::ProviderRejected => G2pAttemptState::ProviderFailed,
            };
            if !matches!(
                self.state,
                G2pAttemptState::ConfirmationPrepared | G2pAttemptState::ConfirmationRecorded
            ) && self.state != expected_state
            {
                return Err(G2pError::Unavailable);
            }
            if matches!(
                self.state,
                G2pAttemptState::ConfirmationPrepared | G2pAttemptState::ConfirmationRecorded
            ) && observation.state != G2pObservationState::ProviderConfirmed
            {
                return Err(G2pError::Unavailable);
            }
        }
        if let Some(action) = &self.confirmation_action {
            if action.action != self.binding.registry.report_action {
                return Err(G2pError::Unavailable);
            }
        }
        Ok(())
    }

    pub fn validate_acceptance(&self, accepted: &ProviderAcceptance) -> Result<(), G2pError> {
        if accepted.correlation_id != self.provider_intent.correlation_id
            || accepted.references.is_empty()
            || accepted.references.len() > 16
            || accepted
                .references
                .iter()
                .any(|(key, value)| !text(key, 64) || !text(value, 512))
        {
            return Err(G2pError::Conflict);
        }
        Ok(())
    }

    pub fn validate_mapped_observation(
        &self,
        accepted: &ProviderAcceptance,
        observation: &ProviderObservation,
    ) -> Result<G2pProviderObservation, G2pError> {
        self.validate_acceptance(accepted)?;
        let funding = observation
            .parties
            .iter()
            .find(|party| party.role == ProviderPartyRole::Funding)
            .ok_or(G2pError::Conflict)?;
        let recipient = observation
            .parties
            .iter()
            .find(|party| party.role == ProviderPartyRole::Recipient)
            .ok_or(G2pError::Conflict)?;
        if observation.correlation_id != accepted.correlation_id
            || observation.correlation_id != self.provider_intent.correlation_id
            || funding.key != self.provider_intent.funding.scheme
            || funding.value != self.provider_intent.funding.value
            || recipient.key != self.provider_intent.recipient.scheme
            || recipient.value != self.provider_intent.recipient.value
            || observation.money.minor_units != self.provider_intent.money.minor_units
            || observation.money.currency != self.provider_intent.money.currency
            || observation.money.scale != self.provider_intent.money.scale
            || !text(&observation.provider_reference, 512)
        {
            return Err(G2pError::Conflict);
        }
        Ok(G2pProviderObservation {
            correlation_id: observation.correlation_id.clone(),
            provider_reference: Some(observation.provider_reference.clone()),
            state: match observation.state {
                ProviderObservationState::Pending => G2pObservationState::Pending,
                ProviderObservationState::ProviderRejected => G2pObservationState::ProviderRejected,
                ProviderObservationState::ProviderConfirmed => {
                    G2pObservationState::ProviderConfirmed
                }
            },
            money: self.provider_intent.money.clone(),
            funding: self.provider_intent.funding.clone(),
            recipient: self.provider_intent.recipient.clone(),
        })
    }

    pub fn validate_observation(
        &self,
        accepted: &ProviderAcceptance,
        observation: &G2pProviderObservation,
    ) -> Result<(), G2pError> {
        self.validate_acceptance(accepted)?;
        if observation.correlation_id != accepted.correlation_id
            || observation.correlation_id != self.provider_intent.correlation_id
            || observation.funding != self.provider_intent.funding
            || observation.recipient != self.provider_intent.recipient
            || observation.money != self.provider_intent.money
            || observation
                .provider_reference
                .as_deref()
                .is_none_or(|value| !text(value, 512))
        {
            return Err(G2pError::Conflict);
        }
        Ok(())
    }
}

pub fn canonical_digest(value: &impl Serialize) -> Result<String, G2pError> {
    let value = serde_json::to_value(value).map_err(|_| G2pError::Unavailable)?;
    let bytes = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| G2pError::Unavailable)?;
    let digest = Sha256::digest(bytes);
    Ok(hex_lower(&digest))
}

fn validate_prepared_submit(
    binding: &G2pConnectionSnapshot,
    request: &PreparedProviderRequest,
) -> Result<(), G2pError> {
    if request.provider_pack != binding.provider_pack
        || request.role != PaymentEndpointRole::DisbursementSubmit
        || request.method != PaymentHttpMethod::Post
        || request.path.is_empty()
        || !request.path.starts_with('/')
        || request.path.len() > 4_096
        || request.body.is_none()
        || request
            .body
            .as_ref()
            .is_some_and(|body| body.len() > 65_536)
    {
        return Err(G2pError::Unavailable);
    }
    Ok(())
}

fn provider_pack_pin(pin: &ProviderPackPin) -> bool {
    text(&pin.id, 128)
        && text(&pin.version, 64)
        && pin.digest.len() == 71
        && pin.digest.starts_with("sha256:")
        && pin.digest[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn provider_base_url(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    if url.scheme() == "https" {
        return true;
    }
    if url.scheme() != "http" {
        return false;
    }
    match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(_)) | None => false,
    }
}

fn non_secret_settings(value: &Value) -> bool {
    let Ok(bytes) = serde_json::to_vec(value) else {
        return false;
    };
    if bytes.len() > 65_536 || !value.is_object() {
        return false;
    }
    fn safe(value: &Value) -> bool {
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) => true,
            Value::String(value) => {
                value.len() <= 4_096
                    && !value.chars().any(char::is_control)
                    && !value.starts_with("secret:")
            }
            Value::Array(values) => values.len() <= 256 && values.iter().all(safe),
            Value::Object(values) => {
                values.len() <= 256
                    && values.iter().all(|(key, value)| {
                        text(key, 128)
                            && !matches!(
                                key.to_ascii_lowercase().as_str(),
                                "authorization"
                                    | "credential"
                                    | "password"
                                    | "secret"
                                    | "token"
                                    | "x-api-key"
                            )
                            && safe(value)
                    })
            }
        }
    }
    safe(value)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn digest_text(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn canonical_origin(value: &str) -> Result<String, G2pError> {
    url::Url::parse(value)
        .map(|origin| origin.to_string())
        .map_err(|_| G2pError::Unavailable)
}

fn canonical_registry_origin(value: &str) -> Result<String, G2pError> {
    url::Url::parse(value)
        .map(|url| url.origin().ascii_serialization())
        .map_err(|_| G2pError::Unavailable)
}

fn currency_scale<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
    registry_platform_yaml::BoundedU32::<0, 6>::deserialize(deserializer)
        .map(|value| u8::try_from(value.get()).expect("the bounded scale fits in u8"))
}

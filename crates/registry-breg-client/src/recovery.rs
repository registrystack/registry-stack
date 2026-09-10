// SPDX-License-Identifier: Apache-2.0

//! Inert, bounded recovery evidence. These bytes grant no authority: recovery
//! requires a newly fetched caller-filtered binding from the owning client.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::*;

const MAXIMUM_PREPARED_BYTES: usize = 16 * 1024 * 1024;

fn refusal() -> BaseRegistryClientError {
    BaseRegistryClientError::invalid_request("the Base Registry Engine prepared operation is invalid or does not match current authority")
}

macro_rules! capsule {
    ($name:ident, $data:ident) => {
        /// Inert original request evidence for explicit, exact recovery. Contains
        /// record values and idempotency material; store in an owner-only file.
        /// Parsing performs no I/O and does not create executable authority.
        pub struct $name(Zeroizing<Vec<u8>>);

        impl $name {
            pub fn from_slice(bytes: &[u8]) -> Result<Self, BaseRegistryClientError> {
                if bytes.len() > MAXIMUM_PREPARED_BYTES {
                    return Err(refusal());
                }
                let value = crate::strict_json::from_slice(bytes).map_err(|_| refusal())?;
                let _: $data = serde_json::from_value(value).map_err(|_| refusal())?;
                Ok(Self(Zeroizing::new(bytes.to_vec())))
            }

            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            fn encode(value: &$data) -> Result<Self, BaseRegistryClientError> {
                let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| refusal())?);
                Self::from_slice(&bytes)
            }

            fn decode(&self) -> Result<$data, BaseRegistryClientError> {
                serde_json::from_slice(&self.0).map_err(|_| refusal())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateEvidence {
    version: u8,
    source: String,
    binding: Value,
    body: String,
    idempotency_key: String,
    format: BRegRecordFormat,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleEvidence {
    version: u8,
    source: String,
    registry_revision: String,
    record: Value,
    href: String,
    body: String,
    if_match: String,
    idempotency_key: String,
}

capsule!(BRegPreparedCreate, CreateEvidence);
capsule!(BRegPreparedLifecycle, LifecycleEvidence);

fn create_identity(binding: &BRegCreateBinding) -> Value {
    serde_json::json!({
        "registry": binding.registry_identifier(),
        "dataset": binding.dataset_identifier(),
        "revision": binding.registry_revision(),
        "operation": binding.operation_identifier(),
        "profile": binding.access_profile(),
        "entity": binding.entity_identifier(),
        "path": binding.path(),
        "schema": binding.request_schema(),
        "writable": binding.writable_api_names(),
        "required": binding.required_api_names(),
    })
}

impl BaseRegistryClient {
    /// Prepare inert create evidence before sending. No token acquisition or I/O.
    pub fn prepare_create(
        &self,
        binding: &BRegCreateBinding,
        request: &BRegCreateRequest,
        key: &BRegIdempotencyKey,
        format: BRegRecordFormat,
    ) -> Result<BRegPreparedCreate, BaseRegistryClientError> {
        self.validate_create_binding(binding, request)?;
        if !request.matches_recovery_execution(binding, key, format) {
            return Err(refusal());
        }
        BRegPreparedCreate::encode(&CreateEvidence {
            version: 1,
            source: self.source_binding(),
            binding: create_identity(binding),
            body: String::from_utf8(request.body().to_vec()).map_err(|_| refusal())?,
            idempotency_key: key.as_str().to_owned(),
            format,
        })
    }

    /// Revalidate original create evidence against a freshly fetched binding.
    /// Send the returned request with that binding and the returned key/format.
    /// The caller owns principal, input, package and database-generation binding.
    pub fn recover_create(
        &self,
        binding: &BRegCreateBinding,
        prepared: &BRegPreparedCreate,
    ) -> Result<(BRegCreateRequest, BRegIdempotencyKey, BRegRecordFormat), BaseRegistryClientError>
    {
        let evidence = prepared.decode()?;
        if evidence.version != 1
            || evidence.source != self.source_binding()
            || evidence.binding != create_identity(binding)
        {
            return Err(refusal());
        }
        let mut body = crate::strict_json::from_slice(evidence.body.as_bytes())
            .map_err(|_| refusal())?
            .as_object()
            .cloned()
            .ok_or_else(refusal)?;
        let data = body.remove("data").ok_or_else(refusal)?;
        if !body.is_empty() {
            return Err(refusal());
        }
        let mut request = BRegCreateRequest::new(data.as_object().cloned().ok_or_else(refusal)?)
            .map_err(|_| refusal())?;
        // Only canonical bytes emitted by prepare_create are accepted. Never
        // silently rewrite persisted bytes under the original idempotency key.
        if request.body() != evidence.body.as_bytes() {
            return Err(refusal());
        }
        let key = BRegIdempotencyKey::parse(evidence.idempotency_key).map_err(|_| refusal())?;
        self.validate_create_binding(binding, &request)?;
        request.bind_recovery(binding, &key, evidence.format);
        Ok((request, key, evidence.format))
    }

    /// Prepare the exact promoted action plus its original record evidence.
    /// No token acquisition or I/O occurs; persist before executing the action.
    pub fn prepare_lifecycle_action(
        &self,
        authority: &BRegLifecycleAuthority,
        record: &RegistryRecordSingleResponse,
        action: &BRegLifecycleAction,
        key: &BRegIdempotencyKey,
    ) -> Result<BRegPreparedLifecycle, BaseRegistryClientError> {
        let reason = action.body().to_value().get("reason").cloned();
        let candidates = self
            .lifecycle_actions(authority, record)
            .map_err(|_| refusal())?;
        if !candidates.into_iter().any(|candidate| {
            let candidate = match reason.as_ref() {
                Some(Value::String(reason)) => candidate.with_reason(reason),
                None => Ok(candidate),
                _ => return false,
            };
            candidate.is_ok_and(|candidate| candidate == *action)
        }) {
            return Err(refusal());
        }
        BRegPreparedLifecycle::encode(&LifecycleEvidence {
            version: 1,
            source: self.source_binding(),
            registry_revision: action.registry_revision().to_owned(),
            record: serde_json::to_value(record).map_err(|_| refusal())?,
            href: action.href().to_owned(),
            body: serde_json::to_string(action.body()).map_err(|_| refusal())?,
            if_match: action.if_match().as_str().to_owned(),
            idempotency_key: key.as_str().to_owned(),
        })
    }

    /// Revalidate the *original* action against freshly fetched caller-filtered
    /// metadata, even when the committed operation no longer appears on today's
    /// record. Never substitute a newly advertised action or precondition.
    ///
    /// The server still enforces current authorization and exact idempotency
    /// replay. The caller must retain the original principal and database
    /// generation; these cannot be inferred from a token provider.
    pub fn recover_lifecycle_action(
        &self,
        authority: &BRegLifecycleAuthority,
        prepared: &BRegPreparedLifecycle,
    ) -> Result<(BRegLifecycleAction, BRegIdempotencyKey), BaseRegistryClientError> {
        let evidence = prepared.decode()?;
        if evidence.version != 1
            || evidence.source != self.source_binding()
            || evidence.registry_revision != authority.registry_revision()
        {
            return Err(refusal());
        }
        let representation = if evidence.record.get("@context").is_some() {
            RegistryRecordRepresentation::JsonLdSharedContext
        } else {
            RegistryRecordRepresentation::Json
        };
        let RegistryRecordResponse::Single(record) =
            RegistryRecordResponse::from_value(evidence.record, representation)
                .map_err(|_| refusal())?
        else {
            return Err(refusal());
        };
        let mut matches = self
            .lifecycle_actions(authority, &record)
            .map_err(|_| refusal())?
            .into_iter()
            .filter(|action| action.href() == evidence.href);
        let action = matches
            .next()
            .filter(|_| matches.next().is_none())
            .ok_or_else(refusal)?;
        let body =
            crate::strict_json::from_slice(evidence.body.as_bytes()).map_err(|_| refusal())?;
        let action = match body.get("reason") {
            Some(Value::String(reason)) => action.with_reason(reason).map_err(|_| refusal())?,
            Some(_) => return Err(refusal()),
            None => action,
        };
        if action.if_match().as_str() != evidence.if_match
            || serde_json::to_string(action.body()).map_err(|_| refusal())? != evidence.body
        {
            return Err(refusal());
        }
        let key = BRegIdempotencyKey::parse(evidence.idempotency_key).map_err(|_| refusal())?;
        Ok((action, key))
    }
}

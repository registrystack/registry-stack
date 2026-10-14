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

capsule!(BRegPreparedCreate, CreateEvidence);

fn create_identity(binding: &BRegCreateBinding) -> Value {
    serde_json::json!({
        "registry": binding.registry_identifier(),
        "dataset": binding.dataset_identifier(),
        "revision": binding.registry_revision(),
        "operation": binding.operation_identifier(),
        "profile": binding.access_profile(),
        "entity": binding.record_type_identifier(),
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
}

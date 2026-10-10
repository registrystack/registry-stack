// SPDX-License-Identifier: Apache-2.0
//! Product-owned key custody and contextual encryption over Platform Crypto.

use crate::{CoordinatorError, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use registry_platform_crypto::{
    mac::hmac_sha256,
    sealed_value::{self, Context},
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct StateKeys {
    active: u32,
    keys: Arc<BTreeMap<u32, Zeroizing<[u8; 32]>>>,
    admission: Arc<Zeroizing<[u8; 32]>>,
}

fn invalid() -> CoordinatorError {
    CoordinatorError::new(
        "coordinator.command.protected-state-unavailable",
        "protected state could not be authenticated with the configured keys",
    )
}

impl StateKeys {
    /// Payload keys rotate independently of the stable admission commitment key.
    /// Keep retained read keys and the admission key with the backup's key custody.
    pub fn new(
        active: u32,
        keys: BTreeMap<u32, [u8; 32]>,
        admission_key: [u8; 32],
    ) -> Result<Self> {
        if active == 0
            || keys.len() > 16
            || keys.is_empty()
            || keys.contains_key(&0)
            || !keys.contains_key(&active)
            || keys.values().any(|key| key == &[0; 32])
            || admission_key == [0; 32]
        {
            return Err(CoordinatorError::new("coordinator.command.state-keys-invalid", "configure one active nonzero key version, retained read keys and a separate stable admission key"));
        }
        if keys.values().any(|key| key == &admission_key) {
            return Err(CoordinatorError::new(
                "coordinator.command.state-keys-invalid",
                "use separate payload encryption and admission commitment keys",
            ));
        }
        Ok(Self {
            active,
            keys: Arc::new(
                keys.into_iter()
                    .map(|(v, k)| (v, Zeroizing::new(k)))
                    .collect(),
            ),
            admission: Arc::new(Zeroizing::new(admission_key)),
        })
    }

    pub(crate) fn custody_markers(&self, database: &str) -> Value {
        let values = self
            .keys
            .iter()
            .map(|(version, key)| {
                let mut input = b"registry-coordinator/payload-key-custody/v1".to_vec();
                input.extend_from_slice(&(database.len() as u64).to_be_bytes());
                input.extend_from_slice(database.as_bytes());
                input.extend_from_slice(&version.to_be_bytes());
                (
                    version.to_string(),
                    Value::String(hex::encode(hmac_sha256(key.as_ref(), &input))),
                )
            })
            .collect::<serde_json::Map<String, Value>>();
        Value::Object(values)
    }
    pub(crate) fn verify_custody(
        &self,
        database: &str,
        registered: &Value,
        allow_new: bool,
    ) -> Result<()> {
        let registered = registered
            .as_object()
            .filter(|v| !v.is_empty() && v.len() <= 16)
            .ok_or_else(invalid)?;
        let configured = self.custody_markers(database);
        for (version, marker) in registered {
            if configured.get(version) != Some(marker) {
                return Err(CoordinatorError::new("coordinator.command.state-key-custody","retain the registered payload key bytes and versions; recover missing keys from deployment custody"));
            }
        }
        if !allow_new
            && registered.get(&self.active.to_string()) != configured.get(self.active.to_string())
        {
            return Err(CoordinatorError::new(
                "coordinator.command.state-key-custody",
                "apply the new payload key version before starting the service",
            ));
        }
        Ok(())
    }

    pub(crate) fn commitment(&self, purpose: &str, parts: &[&[u8]]) -> String {
        let mut bytes = b"registry-coordinator/commitment/v1".to_vec();
        for part in std::iter::once(purpose.as_bytes()).chain(parts.iter().copied()) {
            bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
            bytes.extend_from_slice(part);
        }
        hex::encode(hmac_sha256(self.admission.as_ref().as_ref(), &bytes))
    }

    pub(crate) fn seal<T: Serialize>(
        &self,
        database: &str,
        run: &str,
        purpose: &str,
        step: &str,
        value: &T,
    ) -> Result<Value> {
        let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| invalid())?);
        let envelope = sealed_value::seal(
            &self.keys[&self.active],
            &Context {
                domain: "registry-coordinator/state/v1",
                scope: &[database, run, purpose, step],
                key_version: self.active,
            },
            &bytes,
        )
        .map_err(|_| invalid())?;
        Ok(json!({"sealedCoordinatorV1":STANDARD.encode(envelope)}))
    }

    pub(crate) fn open<T: DeserializeOwned>(
        &self,
        database: &str,
        run: &str,
        purpose: &str,
        step: &str,
        value: &Value,
    ) -> Result<T> {
        let object = value
            .as_object()
            .filter(|o| o.len() == 1)
            .ok_or_else(invalid)?;
        let encoded = object
            .get("sealedCoordinatorV1")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        if encoded.len() > (sealed_value::MAX_PLAINTEXT_BYTES + 64) * 4 / 3 + 8 {
            return Err(invalid());
        }
        let envelope = STANDARD.decode(encoded).map_err(|_| invalid())?;
        let version = sealed_value::key_version(&envelope).map_err(|_| invalid())?;
        let key = self.keys.get(&version).ok_or_else(invalid)?;
        let bytes = sealed_value::open(
            key,
            &Context {
                domain: "registry-coordinator/state/v1",
                scope: &[database, run, purpose, step],
                key_version: version,
            },
            &envelope,
        )
        .map_err(|_| invalid())?;
        serde_json::from_slice(&bytes).map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_preserves_commitments_and_retained_read_keys() {
        let a = StateKeys::new(1, BTreeMap::from([(1, [1; 32])]), [3; 32]).unwrap();
        let b = StateKeys::new(2, BTreeMap::from([(1, [1; 32]), (2, [2; 32])]), [3; 32]).unwrap();
        let old = a
            .seal("db", "run", "input", "", &json!({"private":"canary"}))
            .unwrap();
        assert_eq!(
            a.commitment("start", &[b"owner", b"key"]),
            b.commitment("start", &[b"owner", b"key"])
        );
        assert!(!old.to_string().contains("canary"));
        assert_eq!(
            b.open::<Value>("db", "run", "input", "", &old).unwrap(),
            json!({"private":"canary"})
        );
        for context in [
            ("other", "run", "input", ""),
            ("db", "other", "input", ""),
            ("db", "run", "output", ""),
            ("db", "run", "input", "step"),
        ] {
            assert!(b
                .open::<Value>(context.0, context.1, context.2, context.3, &old)
                .is_err());
        }
        let without = StateKeys::new(2, BTreeMap::from([(2, [2; 32])]), [3; 32]).unwrap();
        assert!(without
            .open::<Value>("db", "run", "input", "", &old)
            .is_err());
    }
}

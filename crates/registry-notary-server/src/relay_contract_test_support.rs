// SPDX-License-Identifier: Apache-2.0
//! Cross-product test adapter for Relay consultation contracts.

use std::collections::BTreeMap;

use registry_notary_core::RelayOutputContract;
use registry_platform_httputil::destination::json::decode_typed_hash_envelope_as;
use registry_platform_httputil::destination::DataDestinationBody;

use crate::relay_contract::{verify_contract, RelayPublicContract, CONTRACT_HASH_DOMAIN};

/// Decode and verify one exact compiler-produced Relay contract artifact with
/// the same closed decoder and semantic verifier used during Notary startup.
#[must_use]
pub fn verifies_contract_artifact(
    contract_bytes: &[u8],
    expected_hash: &str,
    profile_id: &str,
    workload_client_id: &str,
    purpose: &str,
    input_names: &[String],
    expected_outputs: &BTreeMap<String, RelayOutputContract>,
) -> bool {
    // Production Relay serves this artifact in a typed-hash envelope. The
    // project compiler emits the canonical contract and its independently
    // pinned hash as separate product inputs, so this test-only adapter joins
    // those exact inputs before exercising Notary's production decoder.
    let mut envelope_bytes = Vec::with_capacity(contract_bytes.len().saturating_add(128));
    envelope_bytes.extend_from_slice(b"{\"contract_hash\":\"");
    envelope_bytes.extend_from_slice(expected_hash.as_bytes());
    envelope_bytes.extend_from_slice(b"\",\"contract\":");
    envelope_bytes.extend_from_slice(contract_bytes);
    envelope_bytes.push(b'}');
    let Ok(envelope) = decode_typed_hash_envelope_as::<RelayPublicContract>(
        DataDestinationBody::from_test_bytes(&envelope_bytes),
        CONTRACT_HASH_DOMAIN,
    ) else {
        return false;
    };
    if envelope.advertised_hash() != expected_hash || envelope.computed_hash() != expected_hash {
        return false;
    }
    verify_contract(
        envelope.into_contract(),
        profile_id,
        workload_client_id,
        purpose,
        input_names,
        expected_outputs,
    )
    .is_ok()
}

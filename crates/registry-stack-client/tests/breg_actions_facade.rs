// SPDX-License-Identifier: Apache-2.0

//! The Base Registry Engine immediate-action surface, reached only through the
//! facade.
//!
//! A caller who depends on this crate alone must be able to name every type an
//! immediate-action method takes and returns, and every prepared value it
//! persists before sending so it can recover after a lost response. The
//! signatures below are compiled, never run: a type the facade does not
//! re-export cannot be named here, so the build fails rather than the
//! caller's. The BReg client publishes its action surface through a glob, so
//! this test names each type rather than comparing re-export lists.

use std::collections::BTreeMap;
use std::error::Error;

use registry_stack_client::breg::{
    BRegActionInvocationRequest, BRegActionReceipt, BRegActionResultReference,
    BRegActionTargetConditions, BRegActionTargetConditionsRequest, BRegComplete, BRegCreateBinding,
    BRegCreateRequest, BRegIdempotencyKey, BRegImmediateActionBinding, BRegImmediateActionError,
    BRegLifecycleAction, BRegLifecycleAuthority, BRegMetadata, BRegMetadataSelectionError,
    BRegPreparedAction, BRegPreparedCreate, BRegPreparedLifecycle, BRegRecordFormat,
    BaseRegistryClient, BaseRegistryClientError, Uuid,
};
use serde_json::{Map, Value};

/// Every immediate-action step, from selection through recovery, with its
/// parameter and return types named through the facade alone.
async fn every_action_method_names_its_types(
    client: &BaseRegistryClient,
    metadata: &BRegMetadata,
    profile: &str,
    target_inputs: Map<String, Value>,
    inputs: Map<String, Value>,
    key: &BRegIdempotencyKey,
) -> Result<(), Box<dyn Error>> {
    let selected: Result<BRegImmediateActionBinding, BRegMetadataSelectionError> =
        metadata.select_immediate_action("action", profile);
    let action = selected?;

    let target: Result<BRegActionTargetConditionsRequest, BRegImmediateActionError> =
        BRegActionTargetConditionsRequest::new(&action, target_inputs);
    let conditions: BRegComplete<BRegActionTargetConditions> =
        client.action_target_conditions(&action, &target?).await?;

    let invocation: Result<BRegActionInvocationRequest, BRegImmediateActionError> =
        BRegActionInvocationRequest::new(&action, inputs.clone(), Some(&conditions.value));
    let request = invocation?;
    let prepared: Result<BRegPreparedAction, BaseRegistryClientError> =
        client.prepare_action(&action, &request, key);
    let persisted = prepared?.as_bytes().to_vec();

    let restored = BRegPreparedAction::from_slice(&persisted)?;
    let recovered: Result<BRegActionInvocationRequest, BaseRegistryClientError> =
        client.recover_action(&action, &restored, &inputs, key);
    let receipt: BRegComplete<BRegActionReceipt> =
        client.invoke_action(&action, &recovered?, key).await?;
    let results: &BTreeMap<String, BRegActionResultReference> = receipt.value.results();
    for reference in results.values() {
        let _: (&str, Uuid, u64) = (
            reference.entity_identifier(),
            reference.record_identifier(),
            reference.revision(),
        );
    }
    Ok(())
}

/// The prepared Create and lifecycle values a caller persists beside a
/// prepared action, named through the facade alone.
fn every_prepared_write_names_its_types(
    client: &BaseRegistryClient,
    binding: &BRegCreateBinding,
    create: &BRegCreateRequest,
    authority: &BRegLifecycleAuthority,
    key: &BRegIdempotencyKey,
) -> Result<(), BaseRegistryClientError> {
    let prepared: BRegPreparedCreate =
        client.prepare_create(binding, create, key, BRegRecordFormat::Json)?;
    let restored = BRegPreparedCreate::from_slice(prepared.as_bytes())?;
    let _: (BRegCreateRequest, BRegIdempotencyKey, BRegRecordFormat) =
        client.recover_create(binding, &restored)?;

    let lifecycle = BRegPreparedLifecycle::from_slice(&[])?;
    let _: (BRegLifecycleAction, BRegIdempotencyKey) =
        client.recover_lifecycle_action(authority, &lifecycle)?;
    Ok(())
}

#[test]
fn the_facade_names_every_action_type() {
    // Naming the functions is what keeps the signatures above compiled;
    // calling one would need a Base Registry Engine.
    let _ = every_action_method_names_its_types;
    let _ = every_prepared_write_names_its_types;
}

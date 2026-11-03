// SPDX-License-Identifier: Apache-2.0

//! Compatibility proof for the engine crate extraction. Existing facade and
//! job consumers may keep using `registry_adapter::engine` while new hosts link
//! `registry-adapter-engine` directly.

#[test]
fn adapter_engine_is_the_extracted_engine_crate() {
    let through_facade = registry_adapter::engine::EngineProfileKind::Job;
    let direct: registry_adapter_engine::EngineProfileKind = through_facade;
    assert_eq!(direct, registry_adapter_engine::EngineProfileKind::Job);
}

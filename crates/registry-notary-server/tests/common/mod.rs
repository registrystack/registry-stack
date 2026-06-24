// SPDX-License-Identifier: Apache-2.0
//! Shared test helpers for the registry-notary-server integration tests.

use std::sync::{Mutex, MutexGuard};

/// Serialises tests that write `REGISTRY_NOTARY_ISSUER_JWK`.
///
/// Multiple integration-test binaries run in parallel under `cargo test`. Both
/// `demo_config` and `decentralized_cross_source_cel` set this env var and
/// read it back through the server config. Acquiring this lock before calling
/// `std::env::set_var("REGISTRY_NOTARY_ISSUER_JWK", …)` ensures the two tests
/// do not interfere.
static ISSUER_JWK_LOCK: Mutex<()> = Mutex::new(());

pub fn issuer_jwk_guard() -> MutexGuard<'static, ()> {
    // Recover from a previous test panic so the lock is never permanently
    // poisoned.
    ISSUER_JWK_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// Independently signed and activated generated product inputs.
///
/// Arrays of these closed values are used instead of combined product labels so
/// reports cannot conflate the public and consultation Relay instances.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredProductAction {
    RelayPublic,
    RelayConsultation,
    Notary,
}

// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// Independently signed and activated generated product inputs.
///
/// Arrays of these closed values are used instead of combined product labels so
/// reports cannot conflate the public and consultation Relay instances.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequiredProductAction {
    RelayPublic,
    RelayConsultation,
    Notary,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_action_lanes_serialize_with_canonical_names() {
        assert_eq!(
            serde_json::to_value([
                RequiredProductAction::RelayPublic,
                RequiredProductAction::RelayConsultation,
                RequiredProductAction::Notary,
            ])
            .expect("product action lanes serialize"),
            serde_json::json!(["relay-public", "relay-consultation", "notary"])
        );
    }
}

// SPDX-License-Identifier: Apache-2.0

//! The facade profile artifact (`AdapterProfile`): the operation set by id,
//! with methods, paths, envelopes, parameterized parts, and problem codes.
//! The facade contract is an artifact, not engine code
//! (`products/adapter/CONCEPT.md` section 7). First: `breg-records` v1.

use std::collections::BTreeMap;

use registry_platform_yaml::{LocalId, UniqueList};
use serde::{Deserialize, Serialize};

use crate::model::{Envelope, FacadeOperation, HttpMethod};
use crate::problem::ProblemCode;

/// The authored facade profile: a maintained, versioned artifact. Its
/// operations mirror the Base Registry Engine's public surface, with
/// responses in Registry Record v1 shape.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterProfile {
    /// The profile's identifier, the plain string a project references.
    pub id: LocalId,
    /// The profile's own version; projects pin it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The operation set by id. A set, not an ordered list: an id-keyed
    /// mapping (CFG-ID-5).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub operations: BTreeMap<FacadeOperationKey, ProfileOperation>,
}

/// The id-keyed mapping key type for profile operations. It serializes as
/// the bare operation id (`records.search`), so the authored document reads
/// `operations: {records.search: {...}}`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct FacadeOperationKey(pub FacadeOperation);

impl serde::Serialize for FacadeOperationKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.id())
    }
}

impl<'de> serde::Deserialize<'de> for FacadeOperationKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        FacadeOperation::deserialize(deserializer).map(Self)
    }
}

impl From<FacadeOperation> for FacadeOperationKey {
    fn from(operation: FacadeOperation) -> Self {
        Self(operation)
    }
}

/// One facade operation declaration: its method and parameterized path, the
/// envelope it answers in, the path parts a deployment parameterizes, and
/// the closed problem set the operation can return.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileOperation {
    /// The HTTP method the facade route answers.
    pub method: HttpMethod,
    /// The facade path template; braces name the parameterized parts, such
    /// as `/v1/records/{type}/{record_id}`.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = crate::naming::MAX_UPSTREAM_PATH_CHARACTERS)))]
    pub path: String,
    /// The envelope this operation answers in.
    pub envelope: Envelope,
    /// The path parts the deployment parameterizes: the brace names in
    /// `path`.
    #[serde(default)]
    pub parameterized_parts: UniqueList<LocalId>,
    /// The closed problem codes this operation can return.
    #[serde(default)]
    pub problem_codes: UniqueList<ProblemCode>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_serializes_operations_by_id() {
        let mut operations = BTreeMap::new();
        operations.insert(
            FacadeOperationKey(FacadeOperation::RecordsSearch),
            ProfileOperation {
                method: HttpMethod::Get,
                path: "/v1/records/{type}".to_string(),
                envelope: Envelope::RestJson,
                parameterized_parts: UniqueList::new(vec![LocalId::new("type").expect("id")])
                    .expect("unique"),
                problem_codes: UniqueList::new(vec![ProblemCode::RequestInvalid]).expect("unique"),
            },
        );
        let profile = AdapterProfile {
            id: LocalId::new("breg-records").expect("id"),
            version: "v1".to_string(),
            operations,
        };
        let json = serde_json::to_value(&profile).expect("serialize");
        assert_eq!(json["id"], "breg-records");
        assert_eq!(json["operations"]["records.search"]["method"], "GET");
        let round: AdapterProfile = serde_json::from_value(json).expect("deserialize");
        assert_eq!(round, profile);
    }

    #[test]
    fn an_unknown_operation_id_is_refused() {
        let error = serde_json::from_value::<AdapterProfile>(serde_json::json!({
            "id": "breg-records",
            "operations": { "records.import": { "method": "GET", "path": "/x", "envelope": "rest-json" } }
        }))
        .expect_err("an unknown operation must be refused");
        assert!(error.to_string().contains("records.search"));
    }
}

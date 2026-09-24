// SPDX-License-Identifier: Apache-2.0

//! The authored package document.
//!
//! A package is the directory `package.root` names, holding `messaging.yaml`.
//! The document declares who may call the runtime, as `accessProfiles[]`, so
//! a reviewer reads the callers next to what they may send. Sender profiles,
//! templates, and providers join this document as the product grows; every
//! member is closed, so an unknown key is refused rather than ignored.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::access::{AccessProfile, AccessProfileError, AccessProfiles};
use crate::naming::{MESSAGING_PACKAGE_API_VERSION, MESSAGING_PACKAGE_KIND};

/// The package document as authored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MessagingPackage {
    pub api_version: String,
    pub kind: String,
    pub access_profiles: Vec<AccessProfile>,
}

/// Why a parsed package document cannot be used.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PackageError {
    #[error("unsupported Messaging package apiVersion; expected {MESSAGING_PACKAGE_API_VERSION}")]
    InvalidApiVersion,
    #[error("unsupported Messaging package kind; expected {MESSAGING_PACKAGE_KIND}")]
    InvalidKind,
    #[error("the Messaging package declares no access profile")]
    NoAccessProfiles,
    #[error(transparent)]
    AccessProfile(#[from] AccessProfileError),
}

impl MessagingPackage {
    /// Check the envelope and the access profiles, returning the profiles
    /// indexed for caller resolution.
    pub fn check(&self) -> Result<AccessProfiles, PackageError> {
        if self.api_version != MESSAGING_PACKAGE_API_VERSION {
            return Err(PackageError::InvalidApiVersion);
        }
        if self.kind != MESSAGING_PACKAGE_KIND {
            return Err(PackageError::InvalidKind);
        }
        if self.access_profiles.is_empty() {
            return Err(PackageError::NoAccessProfiles);
        }
        Ok(AccessProfiles::new(self.access_profiles.clone())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn package(value: serde_json::Value) -> Result<MessagingPackage, serde_json::Error> {
        serde_json::from_value(value)
    }

    fn valid() -> serde_json::Value {
        json!({
            "apiVersion": MESSAGING_PACKAGE_API_VERSION,
            "kind": MESSAGING_PACKAGE_KIND,
            "accessProfiles": [{
                "id": "case-notices",
                "principalClaim": "sub",
                "requiredScopes": ["messaging:send"],
                "requesterClients": ["case-system"],
                "role": "sender",
                "senderProfiles": ["transactional"],
                "templates": ["appointment-reminder"],
                "requestsPerMinute": 60,
                "burst": 10
            }]
        })
    }

    #[test]
    fn a_valid_package_yields_its_profiles() {
        let profiles = package(valid()).unwrap().check().unwrap();
        assert!(profiles.get("case-notices").is_some());
    }

    #[test]
    fn an_unknown_member_is_refused() {
        let mut value = valid();
        value["templatez"] = json!([]);
        assert!(package(value).is_err());
        let mut value = valid();
        value["accessProfiles"][0]["allowEverything"] = json!(true);
        assert!(package(value).is_err());
    }

    #[test]
    fn the_envelope_and_the_profile_list_are_checked() {
        let mut value = valid();
        value["apiVersion"] = json!("registry.registrystack.org/messaging-package/v0");
        assert_eq!(
            package(value).unwrap().check(),
            Err(PackageError::InvalidApiVersion)
        );
        let mut value = valid();
        value["kind"] = json!("SchedulingPolicyPackage");
        assert_eq!(
            package(value).unwrap().check(),
            Err(PackageError::InvalidKind)
        );
        let mut value = valid();
        value["accessProfiles"] = json!([]);
        assert_eq!(
            package(value).unwrap().check(),
            Err(PackageError::NoAccessProfiles)
        );
    }
}

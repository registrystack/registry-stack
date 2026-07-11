// SPDX-License-Identifier: Apache-2.0
//! Registry Notary configuration model.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use registry_platform_authcommon::CredentialFingerprintRef;
use registry_platform_config::DeprecatedConfigField;
use registry_platform_crypto::validate_did_web_https_issuer_binding;
use registry_platform_crypto::PublicJwk;
pub use registry_platform_crypto::{
    KeyProviderKind as SigningKeyProviderConfig, KeyStatus as SigningKeyStatus,
};
use registry_platform_oid4vci::{
    CREDENTIAL_SIGNING_ALG_EDDSA, CRYPTOGRAPHIC_BINDING_METHOD_DID_JWK,
    SD_JWT_VC_FORMAT as OID4VCI_SD_JWT_VC_FORMAT,
};
use serde::{Deserialize, Serialize};

use crate::deployment::DeploymentConfig;
use crate::model::{
    DisclosureProfile, EvidenceAuthorizationDetails, FORMAT_CCCEV_JSONLD, FORMAT_CLAIM_RESULT_JSON,
    FORMAT_SD_JWT_VC, SD_JWT_VC_HOLDER_BINDING_METHOD, SD_JWT_VC_SIGNING_ALG,
};

mod audit;
mod auth;
mod cel;
mod credential_status;
mod errors;
mod evidence;
mod federation;
mod http;
mod oid4vci;
mod replay;
mod root;
mod self_attestation;

pub use audit::*;
pub use auth::*;
pub use cel::*;
pub use credential_status::*;
pub use errors::*;
pub use evidence::*;
pub use federation::*;
pub use http::*;
pub use oid4vci::*;
pub use replay::*;
pub use root::*;
pub use self_attestation::*;

#[cfg(test)]
mod tests;

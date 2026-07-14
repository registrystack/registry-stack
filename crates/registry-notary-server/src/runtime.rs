// SPDX-License-Identifier: Apache-2.0
//! Registry Notary evaluation runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

#[cfg(feature = "registry-notary-cel")]
use crosswalk_core::{
    ErrorSeverity, MappingRuntime, RuntimeOptions, SecurityLimits, StandaloneExpressionInput,
};
#[cfg(test)]
use registry_notary_core::RelayConsultationInput;
use registry_notary_core::{
    is_rfc3339_full_date, AccessMode, BatchClaimResultView, BatchEvaluateRequest,
    BatchEvaluateResponse, BatchItemError, BatchItemResponse, BatchItemStatus, BatchStatus,
    BatchSummary, BoundedClaimId, BoundedCorrelationId, CelBindingsConfig, ClaimDefinition,
    ClaimEvidenceMode, ClaimProvenance, ClaimRef, ClaimResultView, CredentialProfileConfig,
    DisclosureDowngrade, DisclosureProfile, EvaluateRequest, EvaluationCapability, EvidenceConfig,
    EvidenceEntity, EvidenceEntityRef, EvidenceError, EvidenceFormat, EvidencePrincipal,
    EvidenceRequestContext, ProvenanceUsed, RegistryNotaryCelConfig, RenderRequest, RuleConfig,
    SelfAttestationConfig, SelfAttestationDenialCode, StoredSelfAttestationMetadata,
    SubjectRequest, TargetRefView, FORMAT_CCCEV_JSONLD, FORMAT_CLAIM_RESULT_JSON, FORMAT_SD_JWT_VC,
    MAX_CLAIM_DEPENDENCY_EDGES_V1, MAX_CLAIM_DEPENDENCY_NODES_V1, SD_JWT_VC_HOLDER_BINDING_METHOD,
    SD_JWT_VC_ISSUER_KEY_TYPE, SD_JWT_VC_JWT_TYP, SD_JWT_VC_SIGNING_ALG,
};
use registry_platform_audit::AuditKeyHasher;
#[cfg(feature = "registry-notary-cel")]
use serde_json::Map;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Semaphore;

const SD_JWT_VC_RSA_ISSUER_KEY_TYPE: &str = "RSA";
const SD_JWT_VC_P256_ISSUER_KEY_TYPE: &str = "EC/P-256";
use tokio::task::JoinSet;
use ulid::Ulid;
use zeroize::Zeroizing;

#[cfg(feature = "registry-notary-cel")]
use crate::cel_worker::{cel_expression_uses_regex, CelWorker, CelWorkerError};
use crate::digest::hex_encode;
use crate::json_path::get_json_path;
use crate::problem::evidence_title;
use crate::request_context::with_request_correlation_id;
use crate::self_attestation_rate_limit::SelfAttestationRateLimitKeys;

#[cfg(feature = "registry-notary-cel")]
const MAX_CEL_CLAIM_BINDINGS: usize = 64;
#[cfg(feature = "registry-notary-cel")]
const MAX_CEL_VAR_BINDINGS: usize = 64;

mod access;
mod catalog;
mod cel;
pub(crate) mod consultation;
mod disclosure;
mod evaluation;
mod render;
mod store;
mod types;

use access::*;
pub use catalog::*;
#[cfg(feature = "registry-notary-cel")]
pub(crate) use cel::validate_cel_claims_for_startup;
pub(crate) use consultation::ConsultationGroupKeyV1;
pub(crate) use consultation::{
    ActivatedRelayClientSet, ActivatedRelayConsultations, EvaluationAuditSnapshot,
    RelayClientSelectionV1, RelayProfileReadiness, RuntimeRelayConsultationResult,
    RuntimeRelayExpectedResult,
};
use consultation::{
    EvaluationAuditCollector, RequestScopedRelayPlan, RuntimeRelayOutcome,
    MAX_BATCH_CONSULTATION_GROUPS_V1,
};
#[cfg(test)]
use consultation::{RuntimeRelayMatchData, RuntimeRelayOutputMap};
use disclosure::*;
pub use evaluation::*;
pub use render::*;
pub use store::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::cel::*;
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use std::sync::atomic::{AtomicU64, Ordering};

    include!("runtime/tests/support.rs");
    include!("runtime/tests/catalog.rs");
    include!("runtime/tests/evaluation.rs");
    include!("runtime/tests/render.rs");
    include!("runtime/tests/disclosure.rs");
    include!("runtime/tests/access.rs");
    include!("runtime/tests/cel.rs");
}

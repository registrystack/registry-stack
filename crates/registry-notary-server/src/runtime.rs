// SPDX-License-Identifier: Apache-2.0
//! Registry Notary evaluation runtime.

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(feature = "registry-notary-cel")]
use crosswalk_core::{
    ErrorSeverity, MappingRuntime, RuntimeOptions, SecurityLimits, StandaloneExpressionInput,
};
use registry_notary_core::{
    detect_dependency_cycle, missing_context_error, parse_source_lookup_reference, AccessMode,
    BatchClaimResultView, BatchEvaluateRequest, BatchEvaluateResponse, BatchItemError,
    BatchItemResponse, BatchItemStatus, BatchStatus, BatchSummary, BoundedClaimId,
    BoundedCorrelationId, BulkMode, CelBindingsConfig, ClaimDefinition, ClaimProvenance, ClaimRef,
    ClaimResultView, CredentialProfileConfig, DisclosureDowngrade, DisclosureProfile,
    EvaluateRequest, EvidenceAuthorizationDetails, EvidenceConfig, EvidenceEntity,
    EvidenceEntityRef, EvidenceError, EvidenceFormat, EvidencePrincipal, EvidenceRequestContext,
    MatchingMetadata, ProvenanceUsed, RegistryNotaryCelConfig, RenderRequest, RuleConfig,
    SelfAttestationConfig, SelfAttestationDenialCode, SourceBindingConfig, SourceCapability,
    SourceLookupReference, SourceRuntimeSummary, StoredSelfAttestationMetadata, SubjectRequest,
    TargetRefView, FORMAT_CCCEV_JSONLD, FORMAT_CLAIM_RESULT_JSON, FORMAT_SD_JWT_VC,
    SD_JWT_VC_HOLDER_BINDING_METHOD, SD_JWT_VC_ISSUER_KEY_TYPE, SD_JWT_VC_JWT_TYP,
    SD_JWT_VC_SIGNING_ALG,
};
use registry_platform_audit::AuditKeyHasher;
use registry_platform_pdp::{
    decide as pdp_decide, known_stable_code, rule_ids_by_gate as pdp_rule_ids_by_gate,
    Decision as PdpDecision, DecisionAudit as PdpDecisionAudit,
    EvidenceRequestContext as PdpRequestContext, PolicyInput as PdpPolicyInput,
    RelationshipPurposeConstraint as PdpRelationshipPurposeConstraint,
};
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
mod disclosure;
mod evaluation;
mod matching;
mod memo;
mod render;
mod source_loading;
mod source_reader;
mod store;
mod types;

use access::*;
pub use catalog::*;
#[cfg(feature = "registry-notary-cel")]
pub(crate) use cel::validate_cel_claims_for_startup;
use disclosure::*;
pub use evaluation::*;
pub(crate) use matching::*;
pub use memo::*;
pub use render::*;
use source_loading::*;
pub use source_reader::*;
pub use store::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::cel::*;
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use registry_notary_core::Hashed;
    use registry_notary_core::SOURCE_RUNTIME_KIND_SOURCE_ADAPTER_SIDECAR;

    include!("runtime/tests/support.rs");
    include!("runtime/tests/catalog.rs");
    include!("runtime/tests/evaluation.rs");
    include!("runtime/tests/source_loading.rs");
    include!("runtime/tests/render.rs");
    include!("runtime/tests/disclosure.rs");
    include!("runtime/tests/matching.rs");
    include!("runtime/tests/access.rs");
    include!("runtime/tests/cel.rs");
}

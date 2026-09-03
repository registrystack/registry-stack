// SPDX-License-Identifier: Apache-2.0
//! Bounded Registry Discovery client and inert exact selection artifact.

mod client;
mod error;
mod selection;

pub use client::{DiscoveryClient, DiscoveryClientConfig, EvidenceServiceQuery, RelayServiceQuery};
pub use error::{DiscoveryClientError, DiscoveryProblem};
pub use registry_discovery::{
    EvidenceTypeResolveRequest, EvidenceTypeResolveResponse, ResolvedAlternative, ServiceFilters,
    ServiceKind, ServiceRecord, ServiceSearchResponse,
};
pub use selection::{
    accept_service_selection, renew_unchanged_service_selection,
    validate_service_selection_structure, AcceptedServiceSelection, EvidenceResolutionContext,
    EvidenceSelectionRequest, EvidenceServiceSelection, EvidenceTypeResolveSelectionExt,
    MatchedCapability, RelayCapabilityMatch, RelaySelectionRequest, RelayServiceSelection,
    SelectionRequest, ServiceSearchSelectionExt, ServiceSelection,
};

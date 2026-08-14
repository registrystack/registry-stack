// SPDX-License-Identifier: Apache-2.0
//! Bounded Registry Discovery client and inert exact selection artifact.

mod client;
mod error;
mod selection;

pub use client::{DiscoveryClient, DiscoveryClientConfig};
pub use error::{DiscoveryClientError, DiscoveryProblem};
pub use registry_discovery::{
    EvidenceTypeResolveRequest, EvidenceTypeResolveResponse, ResolvedAlternative, ServiceFilters,
    ServiceKind, ServiceRecord, ServiceSearchResponse,
};
pub use selection::{
    MatchedCapability, SelectionRequest, ServiceSearchSelectionExt, ServiceSelection,
};

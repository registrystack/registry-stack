// SPDX-License-Identifier: Apache-2.0

//! Product-neutral MCP transport, authentication, delegation, audit, and dispatch.
//!
//! Product providers retain operation semantics and downstream authorization.
//! This crate verifies the inbound caller, keeps its bearer private, creates an
//! opaque authorization for the selected provider binding, brackets invocation
//! with fail-closed audit, and serves the MCP edge.

#![deny(unsafe_code)]

mod audit;
mod authorization;
pub mod config;
mod core;
mod handler;
mod inbound;
mod provider;
mod server;

pub use audit::{AuditOptions, AuditOptionsError, ToolAuditLog};
pub use authorization::{
    AuthorizationError, AuthorizationFactory, Delegation, DelegationOptions,
    FixedAuthorizationFactory, ProviderAuthorization,
};
pub use core::{
    CatalogError, GatewayBuildError, GatewayCore, GatewayInfo, ProviderBinding,
    ProviderBindingError,
};
pub use inbound::{
    token_verifier, AccessTokenAlgorithm, CallerContext, RateLimitOptions, ResourceServer,
    ResourceServerError, ResourceServerOptions, TokenBucketOptions, VerifiedCaller,
    VerifiedIdentity,
};
pub use provider::{
    EffectCertainty, Invocation, Provider, ProviderFailure, ProviderOutcome, ResolvedTool,
    ToolIdentityError,
};
pub use server::{router, ServerOptions, MCP_PATH, METADATA_PREFIX};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod compatibility_tests;

// SPDX-License-Identifier: Apache-2.0
//! Payment-specific attempt custody at the Adapter host boundary. The generic
//! route engine has no payment state, provider semantics, or receipt authority.
pub mod config;
pub mod g2p_config;
pub mod g2p_model;
pub mod g2p_registry;
pub mod g2p_service;
pub mod g2p_store;
pub mod http;
pub mod model;
pub mod pack;
pub mod provider_mapping;
pub mod registry;
pub mod service;
pub mod store;

//! Shared bounded secret resolution used by Evidence.
//!
//! The implementation lives in `registry-platform-config` so Evidence applies
//! the shared anchored, no-follow, owner-only file policy.

pub use registry_platform_config::{
    ProtectedSecret, SecretError, SecretProvider, SecretResolver, MAX_SECRET_BYTES,
};

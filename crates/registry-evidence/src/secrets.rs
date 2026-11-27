//! Shared bounded secret resolution used by Evidence.
//!
//! The implementation lives in `registry-platform-config` so Evidence applies
//! the shared anchored secret-file rule: relative links below the root only,
//! one hard link, and the owner and mode checks of `SecretFileCheck`.

pub use registry_platform_config::{
    ProtectedSecret, SecretError, SecretProvider, SecretResolver, MAX_SECRET_BYTES,
};

//! Registry Mint: a minimal OAuth 2.0 token issuer for RegistryStack services.
//!
//! Mint exists to answer one question that a JWKS alone cannot answer: *which
//! principal signed this token, and what is that principal allowed to assert?*
//!
//! A resource server such as Evidence Gateway or Registry Relay verifies an
//! access token by selecting a key from a JWKS using the token's own `kid`
//! header, then reading the authority claims out of the payload. Nothing in
//! that flow binds a key to a permitted claim set, so every key published in a
//! JWKS is equally authoritative for every claim. Distributing signing keys
//! directly to callers therefore makes each caller an issuer able to speak as
//! any other.
//!
//! Mint keeps that binding server-side. Callers hold their own private keys and
//! authenticate with an RFC 7523 `private_key_jwt` client assertion. Mint
//! verifies that assertion against **only the keys registered for the asserted
//! client**, then mints an access token whose authority claims are read from
//! the server-side client registry and never from the assertion. A caller can
//! prove who it is; it cannot choose what it is allowed to say.
//!
//! # Trust split
//!
//! - Issuer identity, signing and audit keys, listener, and token policy are startup-only
//!   and immutable for the process lifetime.
//! - The client registry is reloadable, so onboarding, offboarding, and key
//!   rotation for callers never require restarting a resource server.
//!
//! That split is the point of running Mint as a separate process: resource
//! servers keep their immutable governed contracts while the caller population
//! changes.
//!
//! # Naming
//!
//! "Issuer" here means OAuth token issuance. It is unrelated to the verifiable
//! credential issuance performed by Registry Notary.

#[cfg(not(unix))]
compile_error!(
    "registry-mint requires a Unix target for owner-only signing and audit file guarantees"
);

pub mod assertion;
pub mod audit;
pub mod caller;
pub mod clients;
pub mod config;
pub mod error;
pub mod replay;
pub mod secretfile;
pub mod server;
pub mod token;

/// RFC 7523 client assertion type for `private_key_jwt` authentication.
pub const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The only grant type Mint issues tokens for.
pub const GRANT_TYPE_CLIENT_CREDENTIALS: &str = "client_credentials";

/// Media type of the minted access tokens.
pub const ACCESS_TOKEN_TYP: &str = "at+jwt";

/// The client assertion member naming the actor and subject a delegated token
/// is requested for.
///
/// This is Mint's own member, not RFC 8693 `act`: token exchange presents a
/// subject's own credential, which is precisely what a deployment without an
/// identity provider does not have.
pub const ON_BEHALF_OF_CLAIM: &str = "on_behalf_of";

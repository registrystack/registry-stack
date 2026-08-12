//! Wallet delivery for Evidence credentials.
//!
//! Evidence returns a signed, minimum-disclosure assertion from a fixed request
//! to an authoritative source. It deliberately speaks no wallet protocol. A
//! stock holder wallet, on the other hand, accepts a credential over exactly one
//! protocol, so something has to speak it. This crate is that something: a
//! delivery front end that runs beside Evidence the way Registry Mint runs
//! beside it, as a supporting service rather than a third pattern.
//!
//! Three properties define the service, and none of them is negotiable.
//!
//! 1. **It never signs a credential.** Evidence signs. This process holds no
//!    Evidence signing key and has no code path that could use one.
//! 2. **It never holds a holder private key.** It receives holder public keys
//!    inside wallet-signed proofs and passes them to Evidence unchanged.
//! 3. **It adds no Evidence semantics.** It is a protocol adapter. Every
//!    authorization decision, every source acquisition, and every signature
//!    stays behind the Evidence runtime contract.
//!
//! The service is both a resource server, for the adopter-facing endpoint that
//! creates an offer, and a client, to Evidence. Those two identities never share
//! a code path.
//!
//! # State
//!
//! Everything the service remembers lives in [`store`], in memory, bounded, and
//! for minutes. There is no database here and none anywhere beneath this
//! service. A restart therefore invalidates every offer outstanding in a
//! minutes-wide window, and single use is enforced per process. Both are
//! documented limits of a single-replica deployment rather than defects.

#[cfg(not(unix))]
compile_error!(
    "registry-evidence-oid4vci requires a Unix target for owner-only client key guarantees"
);

pub mod authorizer;
#[doc(hidden)]
pub mod cli;
pub mod config;
pub mod contracts;
pub mod issuer;
pub mod metadata;
mod observability;
pub mod offer;
pub mod secretfile;
pub mod service;
pub mod store;

pub use cli::command;

#[cfg(test)]
mod testing;

/// The credential format this service delivers, as OID4VCI 1.0 Final names it.
///
/// Final renamed the draft's `vc+sd-jwt` to `dc+sd-jwt`. This service pins
/// Final and carries no draft compatibility mode: supporting both wire shapes
/// doubles the surface to chase an ecosystem that is migrating anyway.
pub const CREDENTIAL_FORMAT: &str = "dc+sd-jwt";

/// The only grant type this service serves.
///
/// Note the member name in the offer object: a hyphen before "authorized" and
/// an underscore before "code". It is a reliable typo.
pub const PRE_AUTHORIZED_CODE_GRANT_TYPE: &str =
    "urn:ietf:params:oauth:grant-type:pre-authorized_code";

/// How many digits a transaction code carries.
///
/// Six is what a person can read off one screen and type into another, and the
/// offer's own attempt ceiling is what makes six enough: the code bounds a
/// shoulder-surfing window, not an offline search.
pub const TRANSACTION_CODE_LENGTH: usize = 6;

/// The input mode a wallet is told to present, from the OpenID4VCI 1.0
/// vocabulary. Digits only, so a numeric keypad is the whole keyboard a holder
/// needs.
pub const TRANSACTION_CODE_INPUT_MODE: &str = "numeric";

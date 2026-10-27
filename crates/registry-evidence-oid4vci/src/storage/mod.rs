//! Where a delivery flow's state lives between its steps.
//!
//! [`Store`] is everything the service asks of that state: remember an offer,
//! redeem it (on its own or for an access token), bind and claim an access
//! token, purge what has expired, and report the counts the metrics read. Two
//! backends answer it.
//!
//! - [`crate::store::OfferStore`] holds everything in one process, behind one
//!   mutex. It is what the service runs on unless it is handed another store,
//!   and its module header states the properties it keeps.
//! - [`postgres::PostgresStore`] holds the same state in a PostgreSQL schema,
//!   so that more than one replica can serve one exchange. Its module header
//!   states how it keeps the same properties across processes.
//!
//! Both backends are constructed with their keys rather than reading them from
//! anywhere: see [`KeyRing`]. Both bind every exchange to the
//! [`CatalogGeneration`] it was prepared under and refuse to hand a prepared
//! request back under another one.
//!
//! Neither backend is selected by configuration. The service builds the
//! memory backend; choosing PostgreSQL, and supplying its keys and connection,
//! belongs to the reviewed `oid4vci-profile/v2` that replaces the single
//! replica limits of the current profile.

use async_trait::async_trait;
use thiserror::Error;

use crate::store::{PreparedRequest, StoreError};

mod keys;
mod memory;
pub mod postgres;
mod sealing;

pub use keys::{refuse_shared_keys, KeyError, KeyRing, VersionedKey, KEY_LENGTH};
pub(crate) use keys::{tag, transaction_code_tag};

/// The value a deployment names its backing Evidence catalog by.
///
/// An offer is prepared against one catalog: the credential configuration it
/// names and the batch ceiling it captures come from it. If the catalog
/// changes before the exchange completes, the prepared request may no longer
/// mean what it meant, so every exchange carries the generation it was
/// prepared under and a redemption or claim under any other generation is
/// refused as unknown, without spending the offer or counting an attempt.
///
/// The catalog Evidence publishes carries no identifier of its own, so the
/// value is supplied by whoever builds the service. A deployment that supplies
/// none runs under [`CatalogGeneration::default`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogGeneration(String);

#[derive(Debug, Error, Eq, PartialEq)]
#[error(
    "a catalog generation is 1 to {} visible ASCII characters",
    CatalogGeneration::MAXIMUM_LENGTH
)]
pub struct InvalidCatalogGeneration;

impl CatalogGeneration {
    pub const MAXIMUM_LENGTH: usize = 128;

    /// Accept 1 to [`Self::MAXIMUM_LENGTH`] visible ASCII characters. The
    /// value is stored beside every exchange and bound into its seal, so it is
    /// kept short and free of separators and control characters.
    pub fn new(value: &str) -> Result<Self, InvalidCatalogGeneration> {
        if value.is_empty()
            || value.len() > Self::MAXIMUM_LENGTH
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(InvalidCatalogGeneration);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for CatalogGeneration {
    /// The generation of a deployment that names none.
    fn default() -> Self {
        Self("unversioned".to_owned())
    }
}

/// Everything the service asks of the state a delivery flow carries.
///
/// Every method that hands a prepared request back, or spends an offer or a
/// token, is given the catalog generation the caller is serving under. Every
/// refusal is one of the [`StoreError`] values the service already maps to a
/// response, so the backend behind it changes no status code or body.
#[async_trait]
pub trait Store: Send + Sync + std::fmt::Debug {
    /// Remember a prepared request against a fresh pre-authorized code.
    ///
    /// A full store refuses with [`StoreError::Saturated`] rather than evicting
    /// a live offer.
    async fn remember_offer(
        &self,
        code: &str,
        transaction_code: Option<&str>,
        generation: &CatalogGeneration,
        prepared: PreparedRequest,
        now: i64,
    ) -> Result<(), StoreError>;

    /// Redeem a pre-authorized code once, handing back the request it was
    /// created for. A wrong or missing transaction code counts toward the
    /// offer's lockout.
    async fn redeem_offer(
        &self,
        code: &str,
        transaction_code: Option<&str>,
        generation: &CatalogGeneration,
        now: i64,
    ) -> Result<PreparedRequest, StoreError>;

    /// Redeem a pre-authorized code and carry its request forward under the
    /// access token it was exchanged for, as one step. A full token key-space
    /// refuses having spent nothing.
    async fn redeem_offer_for_access_token(
        &self,
        code: &str,
        transaction_code: Option<&str>,
        access_token: &str,
        generation: &CatalogGeneration,
        now: i64,
    ) -> Result<(), StoreError>;

    /// Carry a prepared request forward under an access token.
    async fn bind_access_token(
        &self,
        access_token: &str,
        generation: &CatalogGeneration,
        prepared: PreparedRequest,
        now: i64,
    ) -> Result<(), StoreError>;

    /// Claim an access token once, handing back the request it carries.
    async fn claim_access_token(
        &self,
        access_token: &str,
        generation: &CatalogGeneration,
        now: i64,
    ) -> Result<PreparedRequest, StoreError>;

    /// Drop everything that has expired, returning how many entries went.
    async fn sweep(&self, now: i64) -> usize;

    /// How many entries the store holds, across every key-space.
    async fn len(&self) -> usize;

    async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// The fullest bounded key-space, for operational saturation pressure, or
    /// no sample when the store cannot answer truthfully.
    async fn maximum_keyspace_len(&self) -> Option<usize>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_catalog_generation_is_short_visible_ascii() {
        for refused in ["", " ", "catalog 1", "catalog\u{0}1", "katalog-ä"] {
            assert_eq!(
                CatalogGeneration::new(refused),
                Err(InvalidCatalogGeneration),
                "{refused:?}"
            );
        }
        assert_eq!(
            CatalogGeneration::new(&"a".repeat(CatalogGeneration::MAXIMUM_LENGTH + 1)),
            Err(InvalidCatalogGeneration)
        );
        let accepted = CatalogGeneration::new("2026-10-27.catalog/3").expect("a generation");
        assert_eq!(accepted.as_str(), "2026-10-27.catalog/3");
        assert_ne!(accepted, CatalogGeneration::default());
    }
}

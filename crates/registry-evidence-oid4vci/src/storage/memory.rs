//! The memory backend: [`OfferStore`] behind [`Store`].
//!
//! Every call takes the store's one mutex and returns without waiting on
//! anything else, so the futures here complete on their first poll and the
//! store behaves exactly as it does when called directly.

use async_trait::async_trait;

use super::{CatalogGeneration, Store};
use crate::store::{OfferStore, PreparedRequest, StoreError};

#[async_trait]
impl Store for OfferStore {
    async fn remember_offer(
        &self,
        code: &str,
        transaction_code: Option<&str>,
        generation: &CatalogGeneration,
        prepared: PreparedRequest,
        now: i64,
    ) -> Result<(), StoreError> {
        self.remember_offer_under(code, transaction_code, generation, prepared, now)
    }

    async fn redeem_offer(
        &self,
        code: &str,
        transaction_code: Option<&str>,
        generation: &CatalogGeneration,
        now: i64,
    ) -> Result<PreparedRequest, StoreError> {
        self.redeem_offer_under(code, transaction_code, generation, now)
    }

    async fn redeem_offer_for_access_token(
        &self,
        code: &str,
        transaction_code: Option<&str>,
        access_token: &str,
        generation: &CatalogGeneration,
        now: i64,
    ) -> Result<(), StoreError> {
        self.redeem_offer_for_access_token_under(
            code,
            transaction_code,
            access_token,
            generation,
            now,
        )
    }

    async fn bind_access_token(
        &self,
        access_token: &str,
        generation: &CatalogGeneration,
        prepared: PreparedRequest,
        now: i64,
    ) -> Result<(), StoreError> {
        self.bind_access_token_under(access_token, generation, prepared, now)
    }

    async fn claim_access_token(
        &self,
        access_token: &str,
        generation: &CatalogGeneration,
        now: i64,
    ) -> Result<PreparedRequest, StoreError> {
        self.claim_access_token_under(access_token, generation, now)
    }

    async fn sweep(&self, now: i64) -> usize {
        OfferStore::sweep(self, now)
    }

    async fn len(&self) -> usize {
        OfferStore::len(self)
    }

    async fn maximum_keyspace_len(&self) -> Option<usize> {
        OfferStore::maximum_keyspace_len(self)
    }
}

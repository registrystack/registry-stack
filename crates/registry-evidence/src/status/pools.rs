//! The two connection pools the ledger draws on.
//!
//! Status-required issuance holds its connection across signing, so it has a
//! pool of its own. Hook intake, operator routes, the status list publisher
//! and the scheduler use the reserved pool, so a signer stall that exhausts
//! the issuance pool fails only status-required requests. Every store call
//! takes the pool it uses.

use std::fmt;

use deadpool_postgres::{Object, Pool};

use super::error::StatusError;

/// Default size of the issuance pool, per process.
pub const DEFAULT_ISSUANCE_POOL_SIZE: usize = 8;

/// Default size of the reserved pool, per process.
pub const DEFAULT_RESERVED_POOL_SIZE: usize = 4;

/// The pool status-required issuance transactions draw on.
#[derive(Clone)]
pub struct IssuancePool(Pool);

impl IssuancePool {
    #[must_use]
    pub const fn new(pool: Pool) -> Self {
        Self(pool)
    }

    pub(crate) const fn pool(&self) -> &Pool {
        &self.0
    }
}

/// The pool every other ledger operation draws on.
#[derive(Clone)]
pub struct ReservedPool(Pool);

impl ReservedPool {
    #[must_use]
    pub const fn new(pool: Pool) -> Self {
        Self(pool)
    }

    pub(crate) async fn client(&self) -> Result<Object, StatusError> {
        self.0.get().await.map_err(|_| StatusError::Unavailable)
    }
}

impl fmt::Debug for IssuancePool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuancePool")
            .field("max_size", &self.0.status().max_size)
            .finish()
    }
}

impl fmt::Debug for ReservedPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReservedPool")
            .field("max_size", &self.0.status().max_size)
            .finish()
    }
}

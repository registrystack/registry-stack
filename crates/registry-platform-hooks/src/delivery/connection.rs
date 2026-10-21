// SPDX-License-Identifier: Apache-2.0

//! Connection and handler seams every product fills the same way: a pooled
//! client framed as the worker's connection, and the uninhabited handler a
//! product that runs no local hook program names.

use std::ops::{Deref, DerefMut};
use std::time::Duration;

use super::seams::{DeliveryConnection, HandlerRunFailure, HookHandler};

/// One pooled client framed for the delivery worker's connection seam. The
/// pool receives the client back when this wrapper is dropped.
pub struct PooledConnection(pub deadpool_postgres::Client);

impl PooledConnection {
    /// Box `client` as the worker's connection.
    #[must_use]
    pub fn boxed(client: deadpool_postgres::Client) -> DeliveryConnection {
        Box::new(Self(client))
    }
}

impl Deref for PooledConnection {
    type Target = tokio_postgres::Client;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// The handler seam of a product whose capability set runs no local hook
/// program. It has no value, so a product naming it cannot resolve a local
/// handler, and a row that binds one is refused as a handler binding.
#[derive(Clone, Copy, Debug)]
pub enum NoLocalHandler {}

#[async_trait::async_trait]
impl HookHandler for NoLocalHandler {
    fn handler_digest(&self) -> &str {
        match *self {}
    }

    fn attempt_timeout(&self) -> Duration {
        match *self {}
    }

    fn maximum_attempts(&self) -> u8 {
        match *self {}
    }

    async fn run(
        &self,
        _envelope: &[u8],
        _remaining: Duration,
    ) -> Result<Vec<u8>, HandlerRunFailure> {
        match *self {}
    }
}

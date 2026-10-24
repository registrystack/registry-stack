// SPDX-License-Identifier: Apache-2.0

use std::ops::{Deref, DerefMut};

use super::store::DispatchConnection;

/// One pooled client framed for the core's connection seam. The pool receives
/// the client back when this wrapper is dropped.
pub struct PooledClient(pub deadpool_postgres::Client);

impl PooledClient {
    /// Box `client` as the connection a [`DispatchStore`](super::DispatchStore)
    /// lends the core.
    #[must_use]
    pub fn boxed(client: deadpool_postgres::Client) -> DispatchConnection {
        Box::new(Self(client))
    }
}

impl Deref for PooledClient {
    type Target = tokio_postgres::Client;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PooledClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

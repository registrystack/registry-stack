// SPDX-License-Identifier: Apache-2.0

//! The handler seam every product fills the same way: the uninhabited
//! handler a product that runs no local hook program names.

use std::time::Duration;

use super::seams::{HandlerRunFailure, HookHandler};

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

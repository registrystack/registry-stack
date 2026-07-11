// SPDX-License-Identifier: Apache-2.0
//! Request-scoped correlation identifiers shared across server components.

use std::future::Future;

use registry_notary_core::BoundedCorrelationId;
use ulid::Ulid;

tokio::task_local! {
    static REQUEST_CORRELATION_ID: BoundedCorrelationId;
}

pub(crate) async fn with_request_correlation_id<F>(
    correlation_id: BoundedCorrelationId,
    future: F,
) -> F::Output
where
    F: Future,
{
    REQUEST_CORRELATION_ID.scope(correlation_id, future).await
}

pub(crate) fn current_request_correlation_id() -> Option<BoundedCorrelationId> {
    REQUEST_CORRELATION_ID
        .try_with(BoundedCorrelationId::clone)
        .ok()
}

pub(crate) fn new_request_correlation_id() -> BoundedCorrelationId {
    BoundedCorrelationId::new(Ulid::new().to_string()).expect("generated correlation id is bounded")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scopes_correlation_id_without_leaking_after_completion() {
        let correlation_id =
            BoundedCorrelationId::new("request-1").expect("test correlation id is bounded");

        assert_eq!(current_request_correlation_id(), None);
        let observed = with_request_correlation_id(correlation_id.clone(), async {
            current_request_correlation_id()
        })
        .await;

        assert_eq!(observed, Some(correlation_id));
        assert_eq!(current_request_correlation_id(), None);
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use registry_adapter_engine::component::rabbitmq::{
    RabbitMqMessage, RabbitMqReadFault, RabbitMqReadRequest, RabbitMqSettlement,
    RabbitMqSettlementFault, RabbitMqSource, MAXIMUM_RABBITMQ_SOURCE_IDENTITY_BYTES,
};

struct AcceptedSettlement;

impl RabbitMqSettlement for AcceptedSettlement {
    fn accept(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RabbitMqSettlementFault>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }

    fn refuse(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RabbitMqSettlementFault>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

struct IdleSource;

impl RabbitMqSource for IdleSource {
    fn read<'a>(
        &'a self,
        _request: &'a RabbitMqReadRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RabbitMqMessage>, RabbitMqReadFault>> + Send + 'a>>
    {
        Box::pin(async { Ok(None) })
    }
}

#[tokio::test]
async fn an_empty_bounded_poll_is_normal_idle() {
    let request = RabbitMqReadRequest::new(1_024, Duration::from_millis(250))
        .expect("the read bounds are finite");

    assert!(IdleSource
        .read(&request)
        .await
        .expect("the poll runs")
        .is_none());
}

#[test]
fn source_identity_is_mandatory_and_bounded() {
    let settlement: Arc<dyn RabbitMqSettlement> = Arc::new(AcceptedSettlement);

    assert_eq!(
        RabbitMqMessage::new(None, false, Vec::new(), Arc::clone(&settlement))
            .expect_err("a delivery without source identity refuses"),
        RabbitMqReadFault::MissingIdentity
    );
    assert_eq!(
        RabbitMqMessage::new(Some(""), false, Vec::new(), Arc::clone(&settlement))
            .expect_err("an empty source identity refuses"),
        RabbitMqReadFault::MissingIdentity
    );
    assert_eq!(
        RabbitMqMessage::new(
            Some(&"i".repeat(MAXIMUM_RABBITMQ_SOURCE_IDENTITY_BYTES + 1)),
            false,
            Vec::new(),
            settlement,
        )
        .expect_err("an over-bound source identity refuses"),
        RabbitMqReadFault::IdentityBound
    );
}

#[test]
fn debug_output_redacts_identity_and_body() {
    let identity = "source-message-private";
    let body = br#"{"private":"answer"}"#.to_vec();
    let message = RabbitMqMessage::new(
        Some(identity),
        true,
        body.clone(),
        Arc::new(AcceptedSettlement),
    )
    .expect("the bounded delivery is valid");

    let debug = format!("{message:?}");
    assert!(!debug.contains(identity));
    assert!(!debug.contains("private"));
    assert!(!debug.contains("answer"));
    assert!(debug.contains(&format!("source_identity_bytes: {}", identity.len())));
    assert!(debug.contains(&format!("body_bytes: {}", body.len())));
    assert!(debug.contains("redelivered: true"));
}

#[test]
fn read_bounds_must_be_nonzero() {
    assert_eq!(
        RabbitMqReadRequest::new(0, Duration::from_secs(1))
            .expect_err("an unbounded body limit refuses"),
        RabbitMqReadFault::InvalidBounds
    );
    assert_eq!(
        RabbitMqReadRequest::new(1, Duration::ZERO).expect_err("an unbounded deadline refuses"),
        RabbitMqReadFault::InvalidBounds
    );
}

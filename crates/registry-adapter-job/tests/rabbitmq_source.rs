// SPDX-License-Identifier: Apache-2.0

//! Real synthetic-broker tests for the RabbitMQ source transport. These do
//! not stand in for a product destination or the job pass: settlement is
//! driven explicitly here so each broker outcome is observable in isolation.

use std::sync::Arc;
use std::time::Duration;

use lapin::types::ShortString;
use registry_adapter_engine::component::rabbitmq::{
    RabbitMqReadFault, RabbitMqReadRequest, RabbitMqSettlementFault, RabbitMqSource,
};
use registry_adapter_job::rabbitmq_source::{
    LapinRabbitMqSource, RabbitMqSourceConfig, RabbitMqTls,
};
use registry_platform_config::{SecretProvider, SecretResolver};

#[path = "support/rabbitmq_broker.rs"]
mod shared_broker;

use shared_broker::{
    build_source, fixture_connection, next_dead_letter, next_message, publish,
    publish_nonpersistent, source_with_principal, source_with_tls, BrokerFixture, TopologyNames,
    BROKER_MAXIMUM_MESSAGE_BYTES,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn least_privileged_principal_can_verify_topology_read_and_dead_letter() {
    let broker = BrokerFixture::start();
    drop(
        fixture_connection(&broker)
            .await
            .expect("the synthetic broker becomes ready"),
    );
    let names = TopologyNames::new();
    let principal = broker.provision_least_privileged(&names);
    assert_eq!(
        principal.configure,
        format!(
            "^({}|{}|{})$",
            names.queue.replace('.', "\\."),
            names.dead_letter_exchange.replace('.', "\\."),
            names.dead_letter_queue.replace('.', "\\.")
        )
    );
    assert_eq!(
        principal.write,
        format!(
            "^({}|{})$",
            names.dead_letter_exchange.replace('.', "\\."),
            names.dead_letter_queue.replace('.', "\\.")
        )
    );
    assert_eq!(
        principal.read,
        format!(
            "^({}|{})$",
            names.queue.replace('.', "\\."),
            names.dead_letter_exchange.replace('.', "\\.")
        )
    );
    let source = source_with_principal(
        &broker,
        &names,
        RabbitMqTls::PlaintextTest,
        Duration::from_secs(5),
        principal.username,
        principal.password,
    )
    .expect("the least-privileged source configuration is valid");
    let request = RabbitMqReadRequest::new(4_096, Duration::from_secs(5))
        .expect("the least-privileged read is bounded");
    assert!(source
        .read(&request)
        .await
        .expect("the least-privileged principal declares and verifies topology")
        .is_none());

    publish(&broker, &names.queue, Some("least-refused-1"), b"refused")
        .await
        .expect("the broad fixture publisher confirms the message");
    let message = next_message(&source, &request).await;
    message
        .settlement()
        .refuse()
        .await
        .expect("the least-privileged source rejects without requeue");
    drop(message);
    assert_eq!(
        next_dead_letter(&broker, &names.dead_letter_queue)
            .await
            .properties
            .message_id()
            .as_ref()
            .map(ShortString::as_str),
        Some("least-refused-1")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_broker_manual_settlement_and_failure_contract() {
    let broker = BrokerFixture::start();
    drop(
        fixture_connection(&broker)
            .await
            .expect("the synthetic broker becomes ready"),
    );
    let names = TopologyNames::new();
    let source = Arc::new(build_source(&broker, &names));
    let ordinary =
        RabbitMqReadRequest::new(4_096, Duration::from_secs(5)).expect("the test read is bounded");

    assert!(source
        .read(&ordinary)
        .await
        .expect("topology and idle poll")
        .is_none());

    let mut mismatched_names = TopologyNames::new();
    mismatched_names.queue.clone_from(&names.queue);
    let mismatched_source = build_source(&broker, &mismatched_names);
    assert_eq!(
        mismatched_source
            .read(&ordinary)
            .await
            .expect_err("the broker refuses a different DLX on the fixed source queue"),
        RabbitMqReadFault::Topology
    );

    let oversized_private_ca = source_with_tls(
        &broker,
        &TopologyNames::new(),
        RabbitMqTls::PrivateCa {
            pem: "x".repeat(1_048_577),
        },
        Duration::from_secs(5),
    )
    .expect_err("the private CA bundle is bounded before a TLS client is built");
    assert_eq!(oversized_private_ca, RabbitMqReadFault::InvalidBounds);

    let subsecond_heartbeat = source_with_tls(
        &broker,
        &TopologyNames::new(),
        RabbitMqTls::PlaintextTest,
        Duration::from_millis(500),
    )
    .expect_err("a heartbeat that AMQP would encode as disabled is refused");
    assert_eq!(subsecond_heartbeat, RabbitMqReadFault::InvalidBounds);

    publish(&broker, &names.queue, Some("accepted-1"), b"accepted")
        .await
        .expect("the broker confirms the fixture publish");
    let accepted = next_message(&source, &ordinary).await;
    assert_eq!(accepted.source_identity(), "accepted-1");
    accepted
        .settlement()
        .accept()
        .await
        .expect("explicit acceptance acknowledges the delivery");
    assert_eq!(
        accepted
            .settlement()
            .accept()
            .await
            .expect_err("lapin's false one-shot result is a failure"),
        RabbitMqSettlementFault::Uncertain
    );
    drop(accepted);
    assert!(source
        .read(&ordinary)
        .await
        .expect("empty after ack")
        .is_none());

    publish_nonpersistent(&broker, &names.queue, "nonpersistent-1", b"not-recoverable")
        .await
        .expect("the broker confirms the nonpersistent fixture publish");
    assert_eq!(
        source
            .read(&ordinary)
            .await
            .expect_err("a nonpersistent delivery is refused before the route"),
        RabbitMqReadFault::NonPersistent
    );
    assert_eq!(
        next_dead_letter(&broker, &names.dead_letter_queue)
            .await
            .properties
            .message_id()
            .as_ref()
            .map(ShortString::as_str),
        Some("nonpersistent-1")
    );

    publish(
        &broker,
        &names.queue,
        Some("crash-1"),
        b"private-redelivery",
    )
    .await
    .expect("the broker confirms the crash fixture");
    // Pending, stopped, crashed, and held items all use this same unsettled
    // channel-drop path. A held revision is not durable acceptance.
    let before_crash = next_message(&source, &ordinary).await;
    assert!(!before_crash.redelivered());
    drop(before_crash);
    let after_crash = next_message(&source, &ordinary).await;
    assert_eq!(after_crash.source_identity(), "crash-1");
    assert!(after_crash.redelivered());
    assert_eq!(after_crash.body(), b"private-redelivery");
    after_crash
        .settlement()
        .accept()
        .await
        .expect("the redelivery settles once accepted");
    drop(after_crash);

    publish(&broker, &names.queue, Some("refused-1"), b"item-refused")
        .await
        .expect("the broker confirms the refusal fixture");
    let refused = next_message(&source, &ordinary).await;
    refused
        .settlement()
        .refuse()
        .await
        .expect("item refusal rejects without requeue");
    drop(refused);
    assert_eq!(
        next_dead_letter(&broker, &names.dead_letter_queue)
            .await
            .properties
            .message_id()
            .as_ref()
            .map(ShortString::as_str),
        Some("refused-1")
    );

    publish(&broker, &names.queue, Some("retained-bound-1"), &[b'x'; 64])
        .await
        .expect("the broker admits a message below its hard ceiling");
    let tight = RabbitMqReadRequest::new(16, Duration::from_secs(5))
        .expect("the retained-body test is bounded");
    assert_eq!(
        source
            .read(&tight)
            .await
            .expect_err("the post-allocation retained byte ceiling refuses"),
        RabbitMqReadFault::Oversized
    );
    assert_eq!(
        next_dead_letter(&broker, &names.dead_letter_queue)
            .await
            .properties
            .message_id()
            .as_ref()
            .map(ShortString::as_str),
        Some("retained-bound-1")
    );

    publish(&broker, &names.queue, None, b"missing-identity")
        .await
        .expect("the broker admits the missing-identity fixture");
    assert_eq!(
        source
            .read(&ordinary)
            .await
            .expect_err("a missing message-id refuses"),
        RabbitMqReadFault::MissingIdentity
    );
    assert_eq!(
        next_dead_letter(&broker, &names.dead_letter_queue)
            .await
            .data,
        b"missing-identity"
    );

    // Body syntax belongs to the reviewed engine decoder. The raw transport
    // keeps malformed bytes private, then the decoder's explicit refusal uses
    // the same source-owned dead-letter settlement.
    publish(&broker, &names.queue, Some("malformed-1"), b"not-json")
        .await
        .expect("the broker confirms the malformed fixture");
    let malformed = next_message(&source, &ordinary).await;
    assert_eq!(malformed.body(), b"not-json");
    malformed
        .settlement()
        .refuse()
        .await
        .expect("the simulated reviewed decoder refusal dead-letters");
    drop(malformed);
    assert_eq!(
        next_dead_letter(&broker, &names.dead_letter_queue)
            .await
            .properties
            .message_id()
            .as_ref()
            .map(ShortString::as_str),
        Some("malformed-1")
    );

    publish(&broker, &names.queue, Some("bounded-1"), b"one")
        .await
        .expect("the broker confirms bounded fixture one");
    publish(&broker, &names.queue, Some("bounded-2"), b"two")
        .await
        .expect("the broker confirms bounded fixture two");
    let first = next_message(&source, &ordinary).await;
    let blocked = RabbitMqReadRequest::new(4_096, Duration::from_millis(100))
        .expect("the concurrent read has a finite deadline");
    assert_eq!(
        source
            .read(&blocked)
            .await
            .expect_err("the one-delivery semaphore, not basic.qos, caps concurrency"),
        RabbitMqReadFault::Timeout
    );
    first
        .settlement()
        .accept()
        .await
        .expect("the first bounded delivery settles");
    drop(first);
    let second = next_message(&source, &ordinary).await;
    second
        .settlement()
        .accept()
        .await
        .expect("the second bounded delivery settles");
    drop(second);

    publish(&broker, &names.queue, Some("disconnect-1"), b"uncertain")
        .await
        .expect("the broker confirms the disconnect fixture");
    let disconnected = next_message(&source, &ordinary).await;
    source
        .disconnect_for_test()
        .await
        .expect("the synthetic connection closes");
    assert_eq!(
        disconnected
            .settlement()
            .accept()
            .await
            .expect_err("settlement on the ended channel is uncertain"),
        RabbitMqSettlementFault::Uncertain
    );
    drop(disconnected);
    let recovered = next_message(&source, &ordinary).await;
    assert_eq!(recovered.source_identity(), "disconnect-1");
    assert!(recovered.redelivered());
    recovered
        .settlement()
        .accept()
        .await
        .expect("the stable redelivery settles after reconnect");

    let above_broker_limit = vec![b'z'; BROKER_MAXIMUM_MESSAGE_BYTES + 1];
    let publish_result = publish(
        &broker,
        &names.queue,
        Some("broker-bound-1"),
        &above_broker_limit,
    )
    .await;
    assert!(
        publish_result.is_err(),
        "the synthetic broker must enforce max_message_size before the source can allocate it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_ca_amqps_succeeds_and_wrong_trust_refuses_before_credentials() {
    let (broker, ca_pem) = shared_broker::BrokerFixture::start_amqps();
    let names = shared_broker::TopologyNames::new();
    let source = shared_broker::source_with_tls(
        &broker,
        &names,
        RabbitMqTls::PrivateCa { pem: ca_pem },
        Duration::from_secs(5),
    )
    .expect("the bounded private CA source is accepted");
    let request =
        RabbitMqReadRequest::new(4_096, Duration::from_secs(5)).expect("the AMQPS read is bounded");
    let mut ready = false;
    for _ in 0..20 {
        match source.read(&request).await {
            Ok(None) => {
                ready = true;
                break;
            }
            Ok(Some(message)) => panic!("the fresh AMQPS queue yielded {message:?}"),
            Err(RabbitMqReadFault::Unavailable | RabbitMqReadFault::Timeout) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(fault) => panic!("the AMQPS fixture failed under {fault}"),
        }
    }
    assert!(ready, "the private CA establishes verified AMQPS");
    source
        .disconnect_for_test()
        .await
        .expect("the verified AMQPS fixture connection closes cleanly");

    let wrong = rcgen::generate_simple_self_signed(vec!["wrong.invalid".to_owned()])
        .expect("the unrelated synthetic root is generated")
        .cert;
    let wrong = shared_broker::pem_certificate(wrong.der().as_ref());
    let canary_user = "credential-canary-must-not-reach-broker";
    std::env::set_var(
        shared_broker::FIXTURE_PASSWORD_ENV,
        shared_broker::FIXTURE_PASSWORD,
    );
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment-only resolver starts");
    let password = resolver
        .resolve(&format!(
            "secret:env/{}",
            shared_broker::FIXTURE_PASSWORD_ENV
        ))
        .expect("the synthetic password resolves");
    std::env::remove_var(shared_broker::FIXTURE_PASSWORD_ENV);
    let wrong_trust = LapinRabbitMqSource::new(
        RabbitMqSourceConfig {
            host: "127.0.0.1".to_owned(),
            port: broker.port,
            vhost: "/".to_owned(),
            username: canary_user.to_owned(),
            queue: names.queue.clone(),
            dead_letter_exchange: names.dead_letter_exchange.clone(),
            dead_letter_queue: names.dead_letter_queue.clone(),
            dead_letter_routing_key: names.dead_letter_routing_key.clone(),
            maximum_outstanding_deliveries: 1,
            connection_timeout: Duration::from_secs(3),
            heartbeat: Duration::from_secs(5),
            tls: RabbitMqTls::PrivateCa { pem: wrong },
        },
        password,
    )
    .expect("the bounded wrong-root candidate is structurally valid");
    let fault = wrong_trust
        .read(&request)
        .await
        .expect_err("an unrelated root refuses the broker certificate");
    assert!(matches!(
        fault,
        RabbitMqReadFault::Unavailable | RabbitMqReadFault::Timeout
    ));
    let rendered = fault.to_string();
    for private in [canary_user, shared_broker::FIXTURE_PASSWORD, "127.0.0.1"] {
        assert!(!rendered.contains(private));
    }
    let logs = broker.logs();
    assert!(!logs.contains(canary_user));
    assert!(!logs.contains(shared_broker::FIXTURE_PASSWORD));
}

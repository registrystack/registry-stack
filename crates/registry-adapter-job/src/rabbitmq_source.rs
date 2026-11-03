// SPDX-License-Identifier: Apache-2.0

//! The RabbitMQ source host for governed ingestion.
//!
//! This module owns lapin, the resolved broker credential, TLS, durable
//! source and dead-letter topology, one-message manual acknowledgement, and
//! the channel lifecycle that requeues an unsettled delivery. The shared
//! engine sees only its transport-neutral RabbitMQ seam.
//!
//! This host uses `basic.get`, so broker QoS does not bound its outstanding
//! deliveries. A local semaphore is the effective delivery and concurrency
//! bound. Lapin yields a fully accumulated body, therefore the request byte
//! ceiling is a post-allocation retained-body check. Operators must also set
//! RabbitMQ's hard `max_message_size` no higher than the deployment ceiling.
//!
//! The lifecycle comparison is pinned to Camel 4.23.0 commit
//! `b2329103df8f5d1edfca2ad262be09e3be95ee68`. In maintained
//! `components/camel-spring-parent/camel-spring-rabbitmq`, files
//! `SpringRabbitMQEndpoint.java` and `SpringRabbitPollingConsumer.java`,
//! `SpringRabbitMQEndpoint#createPollingConsumer` constructs the polling
//! consumer, whose `receive(long)` delegates to Spring's
//! `RabbitTemplate.receive`. The same directory's
//! `SpringRabbitMQConsumer.java` and `EndpointMessageListener.java` own the
//! listener path described below. Spring Rabbit 4.1.1 commit
//! `cc1c35f30c3e2f06af1c9f258d71b0255e9e5ddc`, file
//! `spring-rabbit/src/main/java/org/springframework/amqp/rabbit/core/RabbitTemplate.java`,
//! method `doReceiveNoWait`, calls `basicGet` and uses broker auto-ack outside
//! a transaction. Camel's listener path is separately owned by
//! `SpringRabbitMQConsumer` methods
//! `prepareAndStartListenerContainer` and `stopAndDestroyListenerContainer`,
//! with `EndpointMessageListener#onMessage`; Spring's
//! `spring-rabbit/src/main/java/org/springframework/amqp/rabbit/listener/BlockingQueueConsumer.java`
//! methods `commitIfNecessary`,
//! `rollbackOnExceptionIfNecessary`, and `stop` own listener ack, reject or
//! requeue, and shutdown recovery.
//!
//! This host deliberately differs: `basic.get` is bounded locally rather than
//! by listener QoS, and settlement remains source-owned until the Adapter pass
//! has a durable destination outcome. The real-broker cases
//! `real_broker_manual_settlement_and_failure_contract` and
//! `real_broker_and_postgres_pass_acknowledge_only_after_durable_acceptance`
//! map that difference, including channel-close redelivery, reject without
//! requeue, connection recovery, and uncertain settlement.

use std::fmt;
use std::future::Future;
#[cfg(feature = "rabbitmq-test-plaintext")]
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use lapin::options::{
    BasicAckOptions, BasicGetOptions, BasicRejectOptions, ExchangeDeclareOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::tcp::OwnedTLSConfig;
use lapin::types::{AMQPValue, FieldTable, LongString, ShortString};
use lapin::uri::{AMQPAuthority, AMQPQueryString, AMQPScheme, AMQPUri, AMQPUserInfo};
use lapin::{Acker, Channel, Connection, ConnectionProperties, ExchangeKind};
use registry_adapter_engine::component::rabbitmq::{
    RabbitMqMessage, RabbitMqReadFault, RabbitMqReadRequest, RabbitMqSettlement,
    RabbitMqSettlementFault, RabbitMqSource,
};
use registry_adapter_engine::job::JobProgram;
use registry_adapter_engine::job_sources::{RabbitMqSourceBinding, RabbitMqSourceTls};
use registry_platform_config::{ProtectedSecret, SecretResolver};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

const MAXIMUM_AMQP_NAME_BYTES: usize = 255;
const CONNECTION_NAME: &str = "registry-adapter-job";
/// Maximum private CA bytes retained by one RabbitMQ host.
pub const MAXIMUM_RABBITMQ_PRIVATE_CA_BYTES: usize = 1024 * 1024;

/// Resolve and register every compiled RabbitMQ source before the first pass.
/// No socket is opened here. The broker credential and optional private CA are
/// captured once, then retained only inside the value-redacted host client.
pub fn activate_rabbitmq_sources(
    program: &mut JobProgram,
    resolver: &SecretResolver,
) -> Result<(), String> {
    let bindings = program
        .rabbitmq_source_bindings()
        .cloned()
        .collect::<Vec<_>>();
    for binding in bindings {
        let endpoint = binding.endpoint.clone();
        let source = Arc::new(build_source(binding, resolver)?);
        program
            .register_rabbitmq_source(&endpoint, source)
            .map_err(|_| "the RabbitMQ source client could not be registered".to_owned())?;
    }
    Ok(())
}

fn build_source(
    binding: RabbitMqSourceBinding,
    resolver: &SecretResolver,
) -> Result<LapinRabbitMqSource, String> {
    let refused = || "the RabbitMQ source connection was refused".to_owned();
    let password = resolver
        .resolve(binding.password_ref.as_str())
        .map_err(|_| refused())?;
    let tls = match binding.tls {
        RabbitMqSourceTls::SystemRoots => RabbitMqTls::SystemRoots,
        RabbitMqSourceTls::CaBundle { ca_bundle_file } => RabbitMqTls::PrivateCa {
            pem: capture_private_ca(&ca_bundle_file)?,
        },
        #[cfg(feature = "rabbitmq-test-plaintext")]
        RabbitMqSourceTls::PlaintextTest => RabbitMqTls::PlaintextTest,
    };
    LapinRabbitMqSource::new(
        RabbitMqSourceConfig {
            host: binding.host,
            port: binding.port,
            vhost: binding.vhost,
            username: binding.user,
            queue: binding.queue,
            dead_letter_exchange: binding.dead_letter_exchange,
            dead_letter_queue: binding.dead_letter_queue,
            dead_letter_routing_key: binding.dead_letter_routing_key,
            maximum_outstanding_deliveries: binding.maximum_outstanding_deliveries,
            connection_timeout: Duration::from_millis(binding.connection_timeout_milliseconds),
            heartbeat: Duration::from_secs(u64::from(binding.heartbeat_seconds)),
            tls,
        },
        password,
    )
    .map_err(|_| refused())
}

fn capture_private_ca(path: &str) -> Result<String, String> {
    let refused = || "the RabbitMQ private CA bundle was refused".to_owned();
    let metadata = std::fs::metadata(path).map_err(|_| refused())?;
    if !metadata.is_file()
        || metadata.len()
            > u64::try_from(MAXIMUM_RABBITMQ_PRIVATE_CA_BYTES)
                .expect("the private CA byte bound fits in u64")
    {
        return Err(refused());
    }
    let bytes = std::fs::read(path).map_err(|_| refused())?;
    if bytes.len() > MAXIMUM_RABBITMQ_PRIVATE_CA_BYTES {
        return Err(refused());
    }
    String::from_utf8(bytes).map_err(|_| refused())
}

/// TLS policy for the broker connection. Plain AMQP does not exist in a
/// production build.
pub enum RabbitMqTls {
    /// Use the platform's native trust roots.
    SystemRoots,
    /// Add one bounded private CA bundle to the platform roots.
    PrivateCa {
        /// The already captured PEM bundle. Its content is never reported.
        pem: String,
    },
    /// Plain AMQP to a numeric-loopback synthetic broker only.
    #[cfg(feature = "rabbitmq-test-plaintext")]
    PlaintextTest,
}

impl fmt::Debug for RabbitMqTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SystemRoots => formatter.write_str("SystemRoots"),
            Self::PrivateCa { .. } => formatter.write_str("PrivateCa([REDACTED])"),
            #[cfg(feature = "rabbitmq-test-plaintext")]
            Self::PlaintextTest => formatter.write_str("PlaintextTest"),
        }
    }
}

/// Fixed operator state for one RabbitMQ source. It contains no password or
/// URL; the password arrives separately as a resolved [`ProtectedSecret`].
pub struct RabbitMqSourceConfig {
    /// The fixed broker host.
    pub host: String,
    /// The fixed broker port.
    pub port: u16,
    /// The fixed virtual host.
    pub vhost: String,
    /// The broker principal.
    pub username: String,
    /// The durable source queue.
    pub queue: String,
    /// The durable direct exchange for item refusals.
    pub dead_letter_exchange: String,
    /// The durable dead-letter queue the host binds and verifies.
    pub dead_letter_queue: String,
    /// The fixed routing key from the dead-letter exchange to its queue.
    pub dead_letter_routing_key: String,
    /// The maximum number of broker deliveries this source may hold unsettled.
    pub maximum_outstanding_deliveries: u16,
    /// The finite connection portion of a read deadline.
    pub connection_timeout: Duration,
    /// The finite broker heartbeat.
    pub heartbeat: Duration,
    /// The broker transport policy.
    pub tls: RabbitMqTls,
}

impl fmt::Debug for RabbitMqSourceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RabbitMqSourceConfig")
            .field("port", &self.port)
            .field(
                "maximum_outstanding_deliveries",
                &self.maximum_outstanding_deliveries,
            )
            .field("connection_timeout", &self.connection_timeout)
            .field("heartbeat", &self.heartbeat)
            .field("tls", &self.tls)
            .finish_non_exhaustive()
    }
}

/// The lapin-backed source. The password and broker names are private and its
/// `Debug` output is value-free.
pub struct LapinRabbitMqSource {
    config: RabbitMqSourceConfig,
    password: ProtectedSecret,
    connection: Mutex<Option<Arc<Connection>>>,
    outstanding: Arc<Semaphore>,
}

impl fmt::Debug for LapinRabbitMqSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LapinRabbitMqSource")
            .field(
                "maximum_outstanding_deliveries",
                &self.config.maximum_outstanding_deliveries,
            )
            .finish_non_exhaustive()
    }
}

impl LapinRabbitMqSource {
    /// Validate fixed operator state and retain one resolved credential.
    ///
    /// # Errors
    ///
    /// Invalid or unbounded connection state is refused without repeating any
    /// configured value.
    pub fn new(
        config: RabbitMqSourceConfig,
        password: ProtectedSecret,
    ) -> Result<Self, RabbitMqReadFault> {
        let names = [
            config.host.as_str(),
            config.vhost.as_str(),
            config.username.as_str(),
            config.queue.as_str(),
            config.dead_letter_exchange.as_str(),
            config.dead_letter_queue.as_str(),
            config.dead_letter_routing_key.as_str(),
        ];
        if names
            .iter()
            .any(|name| name.is_empty() || name.len() > MAXIMUM_AMQP_NAME_BYTES)
            || config.port == 0
            || config.maximum_outstanding_deliveries == 0
            || config.connection_timeout.is_zero()
            || config.heartbeat.as_secs() == 0
            || config.heartbeat.as_secs() > u64::from(u16::MAX)
            || std::str::from_utf8(password.expose_secret()).is_err()
        {
            return Err(RabbitMqReadFault::InvalidBounds);
        }
        if matches!(
            &config.tls,
            RabbitMqTls::PrivateCa { pem }
                if pem.is_empty() || pem.len() > MAXIMUM_RABBITMQ_PRIVATE_CA_BYTES
        ) {
            return Err(RabbitMqReadFault::InvalidBounds);
        }
        #[cfg(feature = "rabbitmq-test-plaintext")]
        if matches!(config.tls, RabbitMqTls::PlaintextTest)
            && !config
                .host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
        {
            return Err(RabbitMqReadFault::InvalidBounds);
        }
        let maximum_outstanding_deliveries = usize::from(config.maximum_outstanding_deliveries);
        Ok(Self {
            config,
            password,
            connection: Mutex::new(None),
            outstanding: Arc::new(Semaphore::new(maximum_outstanding_deliveries)),
        })
    }

    /// Close the current synthetic-broker connection with an unsettled
    /// delivery so the real broker requeues it. This hook exists only in the
    /// explicitly named plaintext test lane.
    #[cfg(feature = "rabbitmq-test-plaintext")]
    pub async fn disconnect_for_test(&self) -> Result<(), RabbitMqReadFault> {
        let Some(connection) = self.connection.lock().await.take() else {
            return Ok(());
        };
        if !connection.status().connected() {
            return Ok(());
        }
        match connection.close(200, "synthetic disconnect".into()).await {
            Ok(()) => Ok(()),
            Err(_) if !connection.status().connected() => Ok(()),
            Err(_) => Err(RabbitMqReadFault::Unavailable),
        }
    }

    async fn read_inner(
        &self,
        request: &RabbitMqReadRequest,
    ) -> Result<Option<RabbitMqMessage>, RabbitMqReadFault> {
        let permit = Arc::clone(&self.outstanding)
            .acquire_owned()
            .await
            .map_err(|_| RabbitMqReadFault::Unavailable)?;
        let connection = self.connection().await?;
        let channel = connection
            .create_channel()
            .await
            .map_err(|_| RabbitMqReadFault::Unavailable)?;
        self.verify_topology(&channel).await?;
        // Camel's Spring polling consumer acknowledges inside
        // RabbitTemplate.receive before returning. This source must instead
        // keep the delivery unsettled through the later destination outcome.
        let Some(message) = channel
            .basic_get(
                short_string(&self.config.queue)?,
                BasicGetOptions { no_ack: false },
            )
            .await
            .map_err(|_| RabbitMqReadFault::Unavailable)?
        else {
            return Ok(None);
        };
        let delivery = message.delivery;
        if delivery.data.len() > request.maximum_message_bytes() {
            reject_poison(&delivery.acker).await?;
            return Err(RabbitMqReadFault::Oversized);
        }
        let source_identity = delivery
            .properties
            .message_id()
            .as_ref()
            .map(ShortString::as_str);
        if source_identity.is_none_or(str::is_empty) {
            reject_poison(&delivery.acker).await?;
            return Err(RabbitMqReadFault::MissingIdentity);
        }
        if delivery.properties.delivery_mode().as_ref().copied() != Some(2) {
            reject_poison(&delivery.acker).await?;
            return Err(RabbitMqReadFault::NonPersistent);
        }
        let settlement: Arc<dyn RabbitMqSettlement> = Arc::new(LapinSettlement {
            acker: delivery.acker,
            settlement_deadline: request.deadline(),
            _channel: channel,
            _connection: connection,
            _permit: permit,
        });
        RabbitMqMessage::new(
            source_identity,
            delivery.redelivered,
            delivery.data,
            settlement,
        )
        .map(Some)
    }

    async fn connection(&self) -> Result<Arc<Connection>, RabbitMqReadFault> {
        let mut slot = self.connection.lock().await;
        if let Some(connection) = slot
            .as_ref()
            .filter(|connection| connection.status().connected())
        {
            return Ok(Arc::clone(connection));
        }
        let uri = self.uri()?;
        let tls = match &self.config.tls {
            RabbitMqTls::SystemRoots => {
                crate::tls_provider::initialize().map_err(|_| RabbitMqReadFault::Unavailable)?;
                OwnedTLSConfig::default()
            }
            RabbitMqTls::PrivateCa { pem } => {
                crate::tls_provider::initialize().map_err(|_| RabbitMqReadFault::Unavailable)?;
                OwnedTLSConfig {
                    identity: None,
                    cert_chain: Some(pem.clone()),
                }
            }
            #[cfg(feature = "rabbitmq-test-plaintext")]
            RabbitMqTls::PlaintextTest => OwnedTLSConfig::default(),
        };
        // This host reconnects on the next bounded read after a connection
        // ends. Lapin's detached auto-recovery loop outlives a refused TLS
        // handshake, so it cannot be given an unbounded lifecycle here.
        let properties =
            ConnectionProperties::default().with_connection_name(CONNECTION_NAME.into());
        let connection = tokio::time::timeout(
            self.config.connection_timeout,
            Connection::connect_uri_with_config(
                uri,
                properties,
                tls,
                lapin::runtime::default_runtime().map_err(|_| RabbitMqReadFault::Unavailable)?,
            ),
        )
        .await
        .map_err(|_| RabbitMqReadFault::Timeout)?
        .map_err(|_| RabbitMqReadFault::Unavailable)?;
        let connection = Arc::new(connection);
        *slot = Some(Arc::clone(&connection));
        Ok(connection)
    }

    fn uri(&self) -> Result<AMQPUri, RabbitMqReadFault> {
        let password = std::str::from_utf8(self.password.expose_secret())
            .map_err(|_| RabbitMqReadFault::Unavailable)?
            .to_owned();
        let scheme = match &self.config.tls {
            RabbitMqTls::SystemRoots | RabbitMqTls::PrivateCa { .. } => AMQPScheme::AMQPS,
            #[cfg(feature = "rabbitmq-test-plaintext")]
            RabbitMqTls::PlaintextTest => AMQPScheme::AMQP,
        };
        Ok(AMQPUri {
            scheme,
            authority: AMQPAuthority {
                userinfo: AMQPUserInfo {
                    username: self.config.username.clone(),
                    password,
                },
                host: self.config.host.clone(),
                port: self.config.port,
            },
            vhost: self.config.vhost.clone(),
            query: AMQPQueryString {
                heartbeat: Some(self.config.heartbeat.as_secs() as u16),
                connection_timeout: Some(self.config.connection_timeout.as_millis() as u64),
                ..Default::default()
            },
        })
    }

    async fn verify_topology(&self, channel: &Channel) -> Result<(), RabbitMqReadFault> {
        channel
            .exchange_declare(
                short_string(&self.config.dead_letter_exchange)?,
                ExchangeKind::Direct,
                ExchangeDeclareOptions {
                    durable: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(|_| RabbitMqReadFault::Topology)?;
        channel
            .queue_declare(
                short_string(&self.config.dead_letter_queue)?,
                QueueDeclareOptions::durable(),
                FieldTable::default(),
            )
            .await
            .map_err(|_| RabbitMqReadFault::Topology)?;
        channel
            .queue_bind(
                short_string(&self.config.dead_letter_queue)?,
                short_string(&self.config.dead_letter_exchange)?,
                short_string(&self.config.dead_letter_routing_key)?,
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|_| RabbitMqReadFault::Topology)?;
        let mut arguments = FieldTable::default();
        arguments.insert(
            "x-dead-letter-exchange".into(),
            AMQPValue::LongString(LongString::from(self.config.dead_letter_exchange.clone())),
        );
        arguments.insert(
            "x-dead-letter-routing-key".into(),
            AMQPValue::LongString(LongString::from(
                self.config.dead_letter_routing_key.clone(),
            )),
        );
        channel
            .queue_declare(
                short_string(&self.config.queue)?,
                QueueDeclareOptions::durable(),
                arguments,
            )
            .await
            .map_err(|_| RabbitMqReadFault::Topology)?;
        Ok(())
    }
}

impl RabbitMqSource for LapinRabbitMqSource {
    fn read<'a>(
        &'a self,
        request: &'a RabbitMqReadRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RabbitMqMessage>, RabbitMqReadFault>> + Send + 'a>>
    {
        Box::pin(async move {
            tokio::time::timeout(request.deadline(), self.read_inner(request))
                .await
                .map_err(|_| RabbitMqReadFault::Timeout)?
        })
    }
}

struct LapinSettlement {
    acker: Acker,
    settlement_deadline: Duration,
    // Dropping the last channel handle without settlement closes it. RabbitMQ
    // then requeues the outstanding delivery; keeping the connection beside it
    // makes that lifecycle explicit even when the source replaces its slot.
    _channel: Channel,
    _connection: Arc<Connection>,
    _permit: OwnedSemaphorePermit,
}

impl RabbitMqSettlement for LapinSettlement {
    fn accept(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RabbitMqSettlementFault>> + Send + '_>> {
        Box::pin(async move {
            match tokio::time::timeout(
                self.settlement_deadline,
                self.acker.ack(BasicAckOptions::default()),
            )
            .await
            {
                Err(_) => Err(RabbitMqSettlementFault::Uncertain),
                Ok(Ok(true)) => Ok(()),
                Ok(Ok(false) | Err(_)) => Err(RabbitMqSettlementFault::Uncertain),
            }
        })
    }

    fn refuse(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RabbitMqSettlementFault>> + Send + '_>> {
        Box::pin(async move {
            match tokio::time::timeout(
                self.settlement_deadline,
                self.acker.reject(BasicRejectOptions { requeue: false }),
            )
            .await
            {
                Err(_) => Err(RabbitMqSettlementFault::Uncertain),
                Ok(Ok(true)) => Ok(()),
                Ok(Ok(false) | Err(_)) => Err(RabbitMqSettlementFault::Uncertain),
            }
        })
    }
}

fn short_string(value: &str) -> Result<ShortString, RabbitMqReadFault> {
    ShortString::try_new(value).map_err(|_| RabbitMqReadFault::InvalidBounds)
}

async fn reject_poison(acker: &Acker) -> Result<(), RabbitMqReadFault> {
    match acker.reject(BasicRejectOptions { requeue: false }).await {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(RabbitMqReadFault::Unavailable),
    }
}

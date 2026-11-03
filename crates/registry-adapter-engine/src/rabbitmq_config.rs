// SPDX-License-Identifier: Apache-2.0

//! Pure operator configuration for a RabbitMQ job source.
//!
//! This module owns only the closed, bounded runtime-file shape and the
//! immutable binding a job host activates. It has no AMQP client dependency,
//! opens no socket, and resolves no credential. The broker's hard
//! `max_message_size` remains an operator-owned broker setting, not a boolean
//! this client can attest. The engine separately applies its retained-message
//! ceiling after Lapin has assembled one delivery.

use registry_platform_config::SecretReference;
use registry_platform_yaml::BoundedU64;
use serde::Deserialize;

const MAXIMUM_RABBITMQ_NAME_BYTES: usize = 255;
const MAXIMUM_RABBITMQ_HOST_BYTES: usize = 253;
const MAXIMUM_RABBITMQ_NAMESPACE_BYTES: usize = 128;
const MAXIMUM_CA_BUNDLE_PATH_BYTES: usize = 4_096;

/// The immutable host binding for one selected RabbitMQ endpoint.
#[derive(Clone, Debug)]
pub struct RabbitMqSourceBinding {
    /// The pack endpoint this binding activates.
    pub endpoint: String,
    /// The broker host, never a URL.
    pub host: String,
    /// The TLS broker port.
    pub port: u16,
    /// The fixed AMQP virtual host.
    pub vhost: String,
    /// The fixed broker principal.
    pub user: String,
    /// The source password reference. The host resolves it without logging it.
    pub password_ref: SecretReference,
    /// The durable source queue.
    pub queue: String,
    /// The durable direct exchange for refused messages.
    pub dead_letter_exchange: String,
    /// The durable queue that receives refused messages.
    pub dead_letter_queue: String,
    /// The fixed routing key from the dead-letter exchange to its queue.
    pub dead_letter_routing_key: String,
    /// The namespace prepended to the encoded stable message identity.
    pub namespace: String,
    /// The local outstanding-delivery concurrency bound. `basic.get` is not
    /// governed by AMQP QoS, so the host enforces this with a semaphore.
    pub maximum_outstanding_deliveries: u16,
    /// The finite connection portion of the read deadline, in milliseconds.
    pub connection_timeout_milliseconds: u64,
    /// The finite AMQP heartbeat, in seconds.
    pub heartbeat_seconds: u16,
    /// The broker transport trust policy.
    pub tls: RabbitMqSourceTls,
}

/// The TLS posture of one RabbitMQ source.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RabbitMqSourceTls {
    /// Platform-native roots, with AMQPS required.
    #[default]
    SystemRoots,
    /// Platform-native roots plus one captured private CA bundle.
    CaBundle {
        /// Absolute path of the PEM CA bundle the host captures at activation.
        #[serde(deserialize_with = "absolute_ca_bundle_path")]
        ca_bundle_file: String,
    },
    /// Plain AMQP to numeric loopback, available only in the named broker
    /// fixture feature and absent from production builds and schemas.
    #[cfg(feature = "rabbitmq-test-plaintext")]
    PlaintextTest,
}

impl RabbitMqSourceTls {
    /// The private CA bundle path, when this posture declares one.
    #[must_use]
    pub fn ca_bundle_file(&self) -> Option<&str> {
        match self {
            Self::CaBundle { ca_bundle_file } => Some(ca_bundle_file),
            Self::SystemRoots => None,
            #[cfg(feature = "rabbitmq-test-plaintext")]
            Self::PlaintextTest => None,
        }
    }
}

/// The strict runtime-file shape for one RabbitMQ source.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(not(feature = "job-rabbitmq"), allow(dead_code))]
pub(crate) struct RabbitMqSourceConfig {
    #[serde(deserialize_with = "rabbitmq_host")]
    host: String,
    #[serde(default = "default_rabbitmq_port")]
    port: BoundedU64<1, 65_535>,
    #[serde(default = "default_vhost", deserialize_with = "rabbitmq_name")]
    vhost: String,
    #[serde(deserialize_with = "rabbitmq_name")]
    user: String,
    password_ref: SecretReference,
    #[serde(deserialize_with = "rabbitmq_name")]
    queue: String,
    #[serde(deserialize_with = "rabbitmq_name")]
    dead_letter_exchange: String,
    #[serde(deserialize_with = "rabbitmq_name")]
    dead_letter_queue: String,
    #[serde(deserialize_with = "rabbitmq_name")]
    dead_letter_routing_key: String,
    #[serde(deserialize_with = "rabbitmq_namespace")]
    namespace: String,
    #[serde(default = "default_maximum_outstanding_deliveries")]
    maximum_outstanding_deliveries: BoundedU64<1, 64>,
    #[serde(default = "default_connection_timeout_milliseconds")]
    connection_timeout_milliseconds: BoundedU64<1, 10_000>,
    #[serde(default = "default_heartbeat_seconds")]
    heartbeat_seconds: BoundedU64<1, 65_535>,
    #[serde(default)]
    tls: RabbitMqSourceTls,
}

#[cfg_attr(not(feature = "job-rabbitmq"), allow(dead_code))]
impl RabbitMqSourceConfig {
    pub(crate) fn host_binding(&self, endpoint: &str) -> RabbitMqSourceBinding {
        RabbitMqSourceBinding {
            endpoint: endpoint.to_owned(),
            host: self.host.clone(),
            port: u16::try_from(self.port.get()).expect("the reader bounds a RabbitMQ port"),
            vhost: self.vhost.clone(),
            user: self.user.clone(),
            password_ref: self.password_ref.clone(),
            queue: self.queue.clone(),
            dead_letter_exchange: self.dead_letter_exchange.clone(),
            dead_letter_queue: self.dead_letter_queue.clone(),
            dead_letter_routing_key: self.dead_letter_routing_key.clone(),
            namespace: self.namespace.clone(),
            maximum_outstanding_deliveries: u16::try_from(
                self.maximum_outstanding_deliveries.get(),
            )
            .expect("the reader bounds outstanding RabbitMQ deliveries"),
            connection_timeout_milliseconds: self.connection_timeout_milliseconds.get(),
            heartbeat_seconds: u16::try_from(self.heartbeat_seconds.get())
                .expect("the reader bounds a RabbitMQ heartbeat"),
            tls: self.tls.clone(),
        }
    }
}

fn default_rabbitmq_port() -> BoundedU64<1, 65_535> {
    BoundedU64::new(5_671).expect("5671 is a valid AMQPS port")
}

fn default_vhost() -> String {
    "/".to_owned()
}

fn default_maximum_outstanding_deliveries() -> BoundedU64<1, 64> {
    BoundedU64::new(1).expect("one outstanding delivery is within the bound")
}

fn default_connection_timeout_milliseconds() -> BoundedU64<1, 10_000> {
    BoundedU64::new(5_000).expect("five seconds is within the bound")
}

fn default_heartbeat_seconds() -> BoundedU64<1, 65_535> {
    BoundedU64::new(30).expect("thirty seconds is within the bound")
}

fn rabbitmq_host<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_text(deserializer, MAXIMUM_RABBITMQ_HOST_BYTES, "host")
}

fn rabbitmq_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_text(deserializer, MAXIMUM_RABBITMQ_NAME_BYTES, "RabbitMQ name")
}

fn rabbitmq_namespace<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded_text(deserializer, MAXIMUM_RABBITMQ_NAMESPACE_BYTES, "namespace")
}

fn bounded_text<'de, D>(
    deserializer: D,
    maximum: usize,
    member: &'static str,
) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    if text.is_empty() || text.len() > maximum || text.chars().any(char::is_control) {
        return Err(serde::de::Error::custom(format!(
            "{member} must carry 1 to {maximum} bytes without control characters"
        )));
    }
    Ok(text)
}

fn absolute_ca_bundle_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let path = String::deserialize(deserializer)?;
    if path.is_empty()
        || path.len() > MAXIMUM_CA_BUNDLE_PATH_BYTES
        || path.chars().any(char::is_control)
        || !std::path::Path::new(&path).is_absolute()
    {
        return Err(serde::de::Error::custom(
            "caBundleFile must be one bounded absolute path",
        ));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::RabbitMqSourceTls;

    #[test]
    fn private_ca_reader_uses_the_runtime_camel_case_contract() {
        let tls: RabbitMqSourceTls = serde_json::from_value(serde_json::json!({
            "type": "ca-bundle",
            "caBundleFile": "/run/secrets/broker-ca.pem"
        }))
        .expect("the documented private CA posture must deserialize");
        assert_eq!(tls.ca_bundle_file(), Some("/run/secrets/broker-ca.pem"));
    }

    #[test]
    fn private_ca_reader_refuses_unreviewed_or_invalid_members() {
        for input in [
            serde_json::json!({"type": "ca-bundle", "ca_bundle_file": "/run/secrets/broker-ca.pem"}),
            serde_json::json!({"type": "ca-bundle", "caBundleFile": "relative.pem"}),
            serde_json::json!({"type": "ca-bundle", "caBundleFile": "/run/secrets/broker-ca.pem", "extra": true}),
        ] {
            assert!(serde_json::from_value::<RabbitMqSourceTls>(input).is_err());
        }
    }
}

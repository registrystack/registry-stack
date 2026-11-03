// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lapin::options::{BasicGetOptions, BasicPublishOptions, ConfirmSelectOptions};
use lapin::uri::{AMQPAuthority, AMQPQueryString, AMQPScheme, AMQPUri, AMQPUserInfo};
use lapin::{BasicProperties, Confirmation, Connection, ConnectionProperties};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use registry_adapter_engine::component::rabbitmq::{
    RabbitMqMessage, RabbitMqReadFault, RabbitMqReadRequest, RabbitMqSource,
};
use registry_adapter_job::rabbitmq_source::{
    LapinRabbitMqSource, RabbitMqSourceConfig, RabbitMqTls,
};
use registry_platform_config::{SecretProvider, SecretResolver};

pub const FIXTURE_USER: &str = "adapter_fixture";
pub const FIXTURE_PASSWORD: &str = "fixture-password-not-production";
pub const FIXTURE_PASSWORD_ENV: &str = "ADAPTER_RABBITMQ_FIXTURE_PASSWORD";
pub const BROKER_MAXIMUM_MESSAGE_BYTES: usize = 131_072;
const RABBITMQ_IMAGE: &str =
    "rabbitmq:4.1.8-alpine@sha256:153322e3974e6365c50e523e5eadd5a7fae231f0e8c58f67c03bb3e02056e34e";
const LEAST_PRIVILEGED_USER: &str = "adapter_source_least_privileged";
const LEAST_PRIVILEGED_PASSWORD: &str = "fixture-least-privileged-password";

pub struct BrokerFixture {
    pub port: u16,
    container: Option<String>,
    _tls_directory: Option<tempfile::TempDir>,
}

impl BrokerFixture {
    pub fn start() -> Self {
        if let Ok(port) = std::env::var("ADAPTER_TEST_RABBITMQ_PORT") {
            return Self {
                port: port.parse().expect("the fixture port is numeric"),
                container: None,
                _tls_directory: None,
            };
        }
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the system clock follows the epoch")
            .as_nanos();
        let container = format!("adapter-rabbitmq-{}-{suffix}", std::process::id());
        let run = Command::new("docker")
            .args([
                "run",
                "--detach",
                "--rm",
                "--name",
                &container,
                "--publish",
                "127.0.0.1::5672",
                "--env",
                &format!("RABBITMQ_DEFAULT_USER={FIXTURE_USER}"),
                "--env",
                &format!("RABBITMQ_DEFAULT_PASS={FIXTURE_PASSWORD}"),
                "--env",
                &format!(
                    "RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS=-rabbit max_message_size {BROKER_MAXIMUM_MESSAGE_BYTES}"
                ),
                RABBITMQ_IMAGE,
            ])
            .output()
            .expect("docker must be available for the native RabbitMQ suite");
        assert!(
            run.status.success(),
            "the synthetic RabbitMQ container starts"
        );
        let port = Command::new("docker")
            .args(["port", &container, "5672/tcp"])
            .output()
            .expect("the fixture port can be inspected");
        assert!(port.status.success(), "the fixture port is published");
        let port = String::from_utf8(port.stdout)
            .expect("docker reports a UTF-8 port")
            .trim()
            .rsplit_once(':')
            .expect("docker reports host:port")
            .1
            .parse()
            .expect("the published port is numeric");
        Self {
            port,
            container: Some(container),
            _tls_directory: None,
        }
    }

    pub fn start_amqps() -> (Self, String) {
        let tls_directory = tempfile::tempdir().expect("the broker TLS directory is created");
        let mut ca_params = CertificateParams::new(Vec::<String>::new())
            .expect("the synthetic CA parameters are valid");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().expect("the synthetic CA key is generated");
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key)
            .expect("the synthetic CA certificate is signed");
        let server_key = KeyPair::generate().expect("the synthetic server key is generated");
        let server_params = CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .expect("the loopback server parameters are valid");
        let server = server_params
            .signed_by(&server_key, &ca)
            .expect("the loopback server certificate is signed");
        let ca_pem = pem("CERTIFICATE", ca.der().as_ref());
        std::fs::write(tls_directory.path().join("ca.pem"), &ca_pem)
            .expect("the synthetic CA is written");
        std::fs::write(
            tls_directory.path().join("server.pem"),
            pem("CERTIFICATE", server.der().as_ref()),
        )
        .expect("the synthetic server certificate is written");
        std::fs::write(
            tls_directory.path().join("server.key"),
            pem("PRIVATE KEY", &server_key.serialize_der()),
        )
        .expect("the synthetic server key is written");
        std::fs::write(
            tls_directory.path().join("rabbitmq.conf"),
            "listeners.tcp = none\nlisteners.ssl.default = 5671\nssl_options.cacertfile = /fixture-tls/ca.pem\nssl_options.certfile = /fixture-tls/server.pem\nssl_options.keyfile = /fixture-tls/server.key\nssl_options.verify = verify_none\nssl_options.fail_if_no_peer_cert = false\n",
        )
        .expect("the synthetic broker TLS config is written");

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the system clock follows the epoch")
            .as_nanos();
        let container = format!("adapter-rabbitmq-tls-{}-{suffix}", std::process::id());
        let mount = format!("{}:/fixture-tls:ro", tls_directory.path().display());
        let run = Command::new("docker")
            .args([
                "run",
                "--detach",
                "--rm",
                "--name",
                &container,
                "--publish",
                "127.0.0.1::5671",
                "--volume",
                &mount,
                "--env",
                &format!("RABBITMQ_DEFAULT_USER={FIXTURE_USER}"),
                "--env",
                &format!("RABBITMQ_DEFAULT_PASS={FIXTURE_PASSWORD}"),
                "--env",
                "RABBITMQ_CONFIG_FILE=/fixture-tls/rabbitmq",
                RABBITMQ_IMAGE,
            ])
            .output()
            .expect("docker must be available for the native AMQPS suite");
        assert!(run.status.success(), "the synthetic AMQPS container starts");
        let port = Command::new("docker")
            .args(["port", &container, "5671/tcp"])
            .output()
            .expect("the AMQPS fixture port can be inspected");
        assert!(port.status.success(), "the AMQPS fixture port is published");
        let port = String::from_utf8(port.stdout)
            .expect("docker reports a UTF-8 port")
            .trim()
            .rsplit_once(':')
            .expect("docker reports host:port")
            .1
            .parse()
            .expect("the published AMQPS port is numeric");
        (
            Self {
                port,
                container: Some(container),
                _tls_directory: Some(tls_directory),
            },
            ca_pem,
        )
    }

    pub fn logs(&self) -> String {
        let Some(container) = &self.container else {
            return String::new();
        };
        let output = Command::new("docker")
            .args(["logs", container])
            .output()
            .expect("the broker logs can be inspected");
        let mut logs = String::from_utf8_lossy(&output.stdout).into_owned();
        logs.push_str(&String::from_utf8_lossy(&output.stderr));
        logs
    }

    pub fn messages_unacknowledged(&self, queue: &str) -> u64 {
        let Some(container) = &self.container else {
            return 0;
        };
        let output = Command::new("docker")
            .args([
                "exec",
                container,
                "rabbitmqctl",
                "list_queues",
                "--quiet",
                "name",
                "messages_unacknowledged",
            ])
            .output()
            .expect("the broker queue state can be inspected");
        assert!(
            output.status.success(),
            "rabbitmqctl reads the owned fixture"
        );
        String::from_utf8(output.stdout)
            .expect("rabbitmqctl output is UTF-8")
            .lines()
            .find_map(|line| {
                let (name, count) = line.split_once('\t')?;
                (name == queue).then(|| count.parse().expect("the unacknowledged count is numeric"))
            })
            .expect("the source queue is listed")
    }

    pub fn provision_least_privileged(&self, names: &TopologyNames) -> FixturePrincipal {
        let container = self
            .container
            .as_ref()
            .expect("least-privileged acceptance requires the owned Docker fixture");
        let configure = resource_regex([
            names.queue.as_str(),
            names.dead_letter_exchange.as_str(),
            names.dead_letter_queue.as_str(),
        ]);
        let write = resource_regex([
            names.dead_letter_exchange.as_str(),
            names.dead_letter_queue.as_str(),
        ]);
        let read = resource_regex([names.queue.as_str(), names.dead_letter_exchange.as_str()]);
        let add = Command::new("docker")
            .args([
                "exec",
                container,
                "rabbitmqctl",
                "add_user",
                LEAST_PRIVILEGED_USER,
                LEAST_PRIVILEGED_PASSWORD,
            ])
            .output()
            .expect("the owned broker can add its least-privileged fixture user");
        assert!(add.status.success(), "the least-privileged user is added");
        let permissions = Command::new("docker")
            .args([
                "exec",
                container,
                "rabbitmqctl",
                "set_permissions",
                "--vhost",
                "/",
                LEAST_PRIVILEGED_USER,
                &configure,
                &write,
                &read,
            ])
            .output()
            .expect("the owned broker can scope its fixture permissions");
        assert!(
            permissions.status.success(),
            "the least-privileged permissions are installed"
        );
        FixturePrincipal {
            username: LEAST_PRIVILEGED_USER,
            password: LEAST_PRIVILEGED_PASSWORD,
            configure,
            write,
            read,
        }
    }
}

pub fn pem_certificate(der: &[u8]) -> String {
    pem("CERTIFICATE", der)
}

fn pem(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(der.len().div_ceil(3) * 4);
    for chunk in der.chunks(3) {
        let value = chunk
            .iter()
            .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte))
            << (8 * (3 - chunk.len()));
        encoded.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
        encoded.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
        encoded.push(if chunk.len() >= 2 {
            ALPHABET[((value >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() == 3 {
            ALPHABET[(value & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    let mut output = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(chunk).expect("base64 output is UTF-8"));
        output.push('\n');
    }
    output.push_str(&format!("-----END {label}-----\n"));
    output
}

impl Drop for BrokerFixture {
    fn drop(&mut self) {
        if let Some(container) = &self.container {
            let _ = Command::new("docker").args(["stop", container]).output();
        }
    }
}

pub struct TopologyNames {
    pub queue: String,
    pub dead_letter_exchange: String,
    pub dead_letter_queue: String,
    pub dead_letter_routing_key: String,
}

pub struct FixturePrincipal {
    pub username: &'static str,
    pub password: &'static str,
    pub configure: String,
    pub write: String,
    pub read: String,
}

impl TopologyNames {
    pub fn new() -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the system clock follows the epoch")
            .as_nanos();
        Self {
            queue: format!("adapter.source.{suffix}"),
            dead_letter_exchange: format!("adapter.dlx.{suffix}"),
            dead_letter_queue: format!("adapter.dlq.{suffix}"),
            dead_letter_routing_key: format!("adapter.refused.{suffix}"),
        }
    }
}

pub fn build_source(broker: &BrokerFixture, names: &TopologyNames) -> LapinRabbitMqSource {
    source_with_tls(
        broker,
        names,
        RabbitMqTls::PlaintextTest,
        Duration::from_secs(5),
    )
    .expect("the numeric-loopback plaintext fixture is accepted")
}

pub fn source_with_tls(
    broker: &BrokerFixture,
    names: &TopologyNames,
    tls: RabbitMqTls,
    heartbeat: Duration,
) -> Result<LapinRabbitMqSource, RabbitMqReadFault> {
    source_with_principal(
        broker,
        names,
        tls,
        heartbeat,
        FIXTURE_USER,
        FIXTURE_PASSWORD,
    )
}

pub fn source_with_principal(
    broker: &BrokerFixture,
    names: &TopologyNames,
    tls: RabbitMqTls,
    heartbeat: Duration,
    username: &str,
    fixture_password: &str,
) -> Result<LapinRabbitMqSource, RabbitMqReadFault> {
    std::env::set_var(FIXTURE_PASSWORD_ENV, fixture_password);
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the environment-only resolver starts");
    let password = resolver
        .resolve(&format!("secret:env/{FIXTURE_PASSWORD_ENV}"))
        .expect("the synthetic password resolves");
    std::env::remove_var(FIXTURE_PASSWORD_ENV);
    LapinRabbitMqSource::new(
        RabbitMqSourceConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            vhost: "/".to_string(),
            username: username.to_string(),
            queue: names.queue.clone(),
            dead_letter_exchange: names.dead_letter_exchange.clone(),
            dead_letter_queue: names.dead_letter_queue.clone(),
            dead_letter_routing_key: names.dead_letter_routing_key.clone(),
            maximum_outstanding_deliveries: 1,
            connection_timeout: Duration::from_secs(5),
            heartbeat,
            tls,
        },
        password,
    )
}

fn resource_regex<'a>(names: impl IntoIterator<Item = &'a str>) -> String {
    let names = names
        .into_iter()
        .map(regex_literal)
        .collect::<Vec<_>>()
        .join("|");
    format!("^({names})$")
}

fn regex_literal(name: &str) -> String {
    let mut escaped = String::with_capacity(name.len());
    for character in name.chars() {
        if matches!(
            character,
            '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
        ) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

pub async fn next_message(
    source: &LapinRabbitMqSource,
    request: &RabbitMqReadRequest,
) -> RabbitMqMessage {
    for _ in 0..50 {
        match source.read(request).await {
            Ok(Some(message)) => return message,
            Ok(None) | Err(RabbitMqReadFault::Unavailable) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(fault) => panic!("the fixture read failed under {fault}"),
        }
    }
    panic!("the broker did not deliver within the finite fixture wait")
}

pub async fn next_dead_letter(broker: &BrokerFixture, queue: &str) -> lapin::message::Delivery {
    let connection = fixture_connection(broker)
        .await
        .expect("the fixture connects");
    let channel = connection
        .create_channel()
        .await
        .expect("the fixture channel opens");
    for _ in 0..50 {
        if let Some(message) = channel
            .basic_get(queue.into(), BasicGetOptions { no_ack: true })
            .await
            .expect("the dead-letter poll runs")
        {
            return message.delivery;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the refused message did not reach the configured dead-letter queue")
}

pub async fn publish(
    broker: &BrokerFixture,
    queue: &str,
    message_id: Option<&str>,
    body: &[u8],
) -> Result<(), ()> {
    let properties = message_id.map_or_else(BasicProperties::default, |message_id| {
        BasicProperties::default()
            .with_message_id(message_id.into())
            .with_delivery_mode(2)
    });
    publish_with_properties(broker, queue, body, properties).await
}

pub async fn publish_nonpersistent(
    broker: &BrokerFixture,
    queue: &str,
    message_id: &str,
    body: &[u8],
) -> Result<(), ()> {
    publish_with_properties(
        broker,
        queue,
        body,
        BasicProperties::default().with_message_id(message_id.into()),
    )
    .await
}

async fn publish_with_properties(
    broker: &BrokerFixture,
    queue: &str,
    body: &[u8],
    properties: BasicProperties,
) -> Result<(), ()> {
    let connection = fixture_connection(broker).await.map_err(|_| ())?;
    let channel = connection.create_channel().await.map_err(|_| ())?;
    channel
        .confirm_select(ConfirmSelectOptions::default())
        .await
        .map_err(|_| ())?;
    let confirmation = channel
        .basic_publish(
            "".into(),
            queue.into(),
            BasicPublishOptions {
                mandatory: true,
                immediate: false,
            },
            body,
            properties,
        )
        .await
        .map_err(|_| ())?
        .await
        .map_err(|_| ())?;
    match confirmation {
        Confirmation::Ack(None) => Ok(()),
        Confirmation::Ack(Some(_)) | Confirmation::Nack(_) | Confirmation::NotRequested => Err(()),
    }
}

pub async fn fixture_connection(broker: &BrokerFixture) -> Result<Connection, lapin::Error> {
    let uri = |query| AMQPUri {
        scheme: AMQPScheme::AMQP,
        authority: AMQPAuthority {
            userinfo: AMQPUserInfo {
                username: FIXTURE_USER.to_string(),
                password: FIXTURE_PASSWORD.to_string(),
            },
            host: "127.0.0.1".to_string(),
            port: broker.port,
        },
        vhost: "/".to_string(),
        query,
    };
    for _ in 0..100 {
        if let Ok(connection) = Connection::connect_uri(
            uri(AMQPQueryString {
                heartbeat: Some(5),
                connection_timeout: Some(1_000),
                ..Default::default()
            }),
            ConnectionProperties::default(),
        )
        .await
        {
            return Ok(connection);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Connection::connect_uri(
        uri(AMQPQueryString::default()),
        ConnectionProperties::default(),
    )
    .await
}

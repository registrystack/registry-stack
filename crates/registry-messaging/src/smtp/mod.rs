// SPDX-License-Identifier: Apache-2.0

//! The SMTP provider kind: one send attempt to a configured relay.
//!
//! The relay's host is resolved once per attempt and every answer is checked
//! before any connection opens: in a TLS mode with the same production
//! classification the HTTP destination applies, and in development only
//! loopback. The connection goes to a checked address, while TLS verifies the
//! relay's certificate against the configured host name. The attempt then
//! classifies what happened into the dispatch core's neutral outcome:
//!
//! - anything before `MAIL FROM` concerns the relay, not the message, and is
//!   transient, whatever the reply;
//! - a `4xx` reply to `MAIL FROM`, `RCPT TO`, `DATA`, or the end of data is
//!   transient, and a `5xx` reply is permanent with the bounded code
//!   `smtp-<reply>`;
//! - a failure before the end-of-data marker was answered is transient;
//! - a drop, timeout, or unreadable reply once the message content started is
//!   maybe-sent, because the relay may have accepted it;
//! - a `2xx` reply to the end of data is accepted, carrying the relay's queue
//!   id when it names one.
//!
//! Nothing here logs an address, a subject, a body, a credential, or a relay
//! reply's text. The attempt detail is value-free: a stage, a reply code, and
//! a failure class.

mod settings;
#[cfg(test)]
pub(crate) mod stub;
#[cfg(test)]
mod tests;

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr as _;
use std::time::Duration;

use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{AsyncSmtpConnection, TlsParameters};
use lettre::transport::smtp::commands::{Data, Mail, Rcpt};
use lettre::transport::smtp::extension::{ClientId, Extension, MailBodyParameter, MailParameter};
use lettre::transport::smtp::response::Response;
use lettre::{Address, Message};
use registry_messaging_core::RenderedParts;
use registry_platform_dispatch::{FailureCode, ProviderReference, SendOutcome, Sent};
use registry_platform_httputil::destination::ProductionAddressPolicy;
use tokio::time::{timeout_at, Instant};

pub use settings::{
    SmtpAuthentication, SmtpProviderSettings, SmtpSettingsError, SmtpTlsMode,
    DEFAULT_SMTP_ATTEMPT_TIMEOUT_SECONDS, MAXIMUM_SMTP_ATTEMPT_TIMEOUT_SECONDS,
    SMTP_IMPLICIT_TLS_PORT, SMTP_SUBMISSION_PORT,
};

/// The most resolved addresses one attempt tries to connect to.
const MAXIMUM_CONNECT_ADDRESSES: usize = 4;

/// The most resolver answers one attempt accepts before refusing the host.
const MAXIMUM_RESOLVER_ANSWERS: usize = 32;

/// The longest message id the `Message-ID` header is derived from.
pub const MAXIMUM_SMTP_MESSAGE_ID_BYTES: usize = 128;

/// How long an accepted attempt waits to close the session politely.
const QUIT_BOUND: Duration = Duration::from_secs(2);

/// One message to hand to the relay.
#[derive(Clone, Copy)]
pub struct SmtpMessage<'a> {
    /// The Messaging message id: 1 to 128 ASCII letters, digits, `-`, or
    /// `_`. The `Message-ID` header is `<{message_id}@{sender domain}>`, so
    /// a duplicate send after an unknown outcome can be spotted downstream.
    pub message_id: &'a str,
    /// The sender profile's address.
    pub from: &'a str,
    /// The recipient's address.
    pub to: &'a str,
    /// The persisted rendered parts: a subject, the text, and optional HTML.
    pub parts: &'a RenderedParts,
}

impl fmt::Debug for SmtpMessage<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmtpMessage")
            .field("message_id", &self.message_id)
            .finish_non_exhaustive()
    }
}

/// Where an attempt ended.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SmtpStage {
    /// Checking the message before any network activity.
    Prepare,
    /// Resolving and checking the relay's addresses.
    Resolve,
    /// Connecting, implicit TLS, the greeting, and `EHLO`.
    Connect,
    /// `STARTTLS` and the second `EHLO`.
    StartTls,
    Authenticate,
    MailFrom,
    RcptTo,
    Data,
    /// The content and the end-of-data marker, and the reply to them.
    EndOfData,
}

impl SmtpStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Resolve => "resolve",
            Self::Connect => "connect",
            Self::StartTls => "starttls",
            Self::Authenticate => "authenticate",
            Self::MailFrom => "mail-from",
            Self::RcptTo => "rcpt-to",
            Self::Data => "data",
            Self::EndOfData => "end-of-data",
        }
    }
}

/// Why an attempt did not end accepted, without any value from the message
/// or the relay's reply text.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SmtpFailure {
    /// The relay replied with a failure code, in [`SmtpAttemptDetail::reply_code`].
    Reply,
    /// The attempt timeout ran out.
    TimedOut,
    /// The host did not resolve, or resolved to too many answers.
    Resolution,
    /// A resolved address is outside what the settings allow.
    DestinationRefused,
    /// The connection, TLS, or the reply stream failed.
    Connection,
    /// The relay does not offer `STARTTLS`.
    StartTlsUnavailable,
    /// The relay lacks an extension the message needs (`SMTPUTF8` or
    /// `8BITMIME`), or a credential mechanism this runtime speaks.
    Unsupported,
    /// The message id, an address, or the content cannot form a message.
    InvalidMessage,
}

impl SmtpFailure {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reply => "reply",
            Self::TimedOut => "timed-out",
            Self::Resolution => "resolution",
            Self::DestinationRefused => "destination-refused",
            Self::Connection => "connection",
            Self::StartTlsUnavailable => "starttls-unavailable",
            Self::Unsupported => "unsupported",
            Self::InvalidMessage => "invalid-message",
        }
    }
}

/// The value-free account of one attempt, for the product's audit and
/// attempt record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmtpAttemptDetail {
    pub stage: SmtpStage,
    /// The relay's last reply code, when a reply decided the outcome.
    pub reply_code: Option<u16>,
    pub failure: Option<SmtpFailure>,
}

/// An activated SMTP provider, built by [`SmtpProviderSettings::activate`].
pub struct SmtpProvider {
    host: String,
    port: u16,
    transport: Transport,
    credentials: Option<Credentials>,
    attempt_timeout: Duration,
    policy: ProductionAddressPolicy,
    network: Network,
}

impl fmt::Debug for SmtpProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmtpProvider")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("transport", &self.transport.as_str())
            .field("authenticates", &self.credentials.is_some())
            .field("attempt_timeout", &self.attempt_timeout)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

pub(crate) enum Transport {
    Starttls(TlsParameters),
    Implicit(TlsParameters),
    DevelopmentLoopback,
}

impl Transport {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Starttls(_) => "starttls",
            Self::Implicit(_) => "implicit",
            Self::DevelopmentLoopback => "development-loopback",
        }
    }
}

/// Where resolution answers come from and where a checked address connects.
pub(crate) enum Network {
    /// The system resolver, and the checked address itself.
    System,
    /// Fixed answers, and every checked address redirected to a local stub,
    /// so a test can drive the address checks and TLS name verification of a
    /// public host against a loopback server.
    #[cfg(test)]
    Scripted {
        answers: Vec<IpAddr>,
        connect_to: SocketAddr,
    },
}

struct Prepared {
    from: Address,
    to: Address,
    content: Vec<u8>,
}

enum StepFailure {
    TimedOut,
    Smtp(lettre::transport::smtp::Error),
}

impl SmtpProvider {
    /// The configured attempt timeout.
    #[must_use]
    pub fn attempt_timeout(&self) -> Duration {
        self.attempt_timeout
    }

    /// Make one send attempt and classify it.
    pub async fn send(&self, message: &SmtpMessage<'_>) -> Sent<SmtpAttemptDetail> {
        let deadline = Instant::now() + self.attempt_timeout;
        let sent = self.attempt(message, deadline).await;
        tracing::debug!(
            stage = sent.detail.stage.as_str(),
            reply_code = sent.detail.reply_code,
            failure = sent.detail.failure.map(SmtpFailure::as_str),
            outcome = outcome_class(&sent.outcome),
            "smtp attempt finished"
        );
        sent
    }

    async fn attempt(
        &self,
        message: &SmtpMessage<'_>,
        deadline: Instant,
    ) -> Sent<SmtpAttemptDetail> {
        let prepared = match prepare(message) {
            Ok(prepared) => prepared,
            Err(code) => {
                return permanent(SmtpStage::Prepare, None, SmtpFailure::InvalidMessage, code)
            }
        };
        let addresses = match timeout_at(deadline, self.resolve()).await {
            Err(_) => return transient(SmtpStage::Resolve, None, SmtpFailure::TimedOut),
            Ok(Err(failure)) => return transient(SmtpStage::Resolve, None, failure),
            Ok(Ok(addresses)) => addresses,
        };

        let hello = ClientId::default();
        let implicit = match &self.transport {
            Transport::Implicit(parameters) => Some(parameters),
            Transport::Starttls(_) | Transport::DevelopmentLoopback => None,
        };
        let mut connection = None;
        let mut last_failure = StepFailure::TimedOut;
        for address in addresses.iter().take(MAXIMUM_CONNECT_ADDRESSES) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                last_failure = StepFailure::TimedOut;
                break;
            }
            let target = self.connect_target(SocketAddr::new(*address, self.port));
            let connect = AsyncSmtpConnection::connect_tokio1(
                target,
                Some(remaining),
                &hello,
                implicit.cloned(),
                None,
            );
            match timeout_at(deadline, connect).await {
                Ok(Ok(opened)) => {
                    connection = Some(opened);
                    break;
                }
                Ok(Err(error)) => last_failure = StepFailure::Smtp(error),
                Err(_) => {
                    last_failure = StepFailure::TimedOut;
                    break;
                }
            }
        }
        let Some(mut connection) = connection else {
            return session_failure(SmtpStage::Connect, &last_failure);
        };

        if let Transport::Starttls(parameters) = &self.transport {
            if !connection.can_starttls() {
                return transient(SmtpStage::StartTls, None, SmtpFailure::StartTlsUnavailable);
            }
            let upgrade = connection.starttls(parameters.clone(), &hello);
            if let Err(failure) = step(deadline, upgrade).await {
                return session_failure(SmtpStage::StartTls, &failure);
            }
        }

        if let Some(credentials) = &self.credentials {
            let supported = connection
                .server_info()
                .get_auth_mechanism(&[Mechanism::Plain, Mechanism::Login])
                .is_some();
            if !supported {
                return transient(SmtpStage::Authenticate, None, SmtpFailure::Unsupported);
            }
            let authenticate = connection.auth(&[Mechanism::Plain, Mechanism::Login], credentials);
            if let Err(failure) = step(deadline, authenticate).await {
                return session_failure(SmtpStage::Authenticate, &failure);
            }
        }

        let mut mail_parameters = Vec::new();
        if !is_ascii(&prepared.from) || !is_ascii(&prepared.to) {
            if !connection
                .server_info()
                .supports_feature(Extension::SmtpUtfEight)
            {
                return permanent(
                    SmtpStage::MailFrom,
                    None,
                    SmtpFailure::Unsupported,
                    "smtp-smtputf8-unsupported",
                );
            }
            mail_parameters.push(MailParameter::SmtpUtfEight);
        }
        if !prepared.content.is_ascii() {
            if !connection
                .server_info()
                .supports_feature(Extension::EightBitMime)
            {
                return permanent(
                    SmtpStage::MailFrom,
                    None,
                    SmtpFailure::Unsupported,
                    "smtp-8bitmime-unsupported",
                );
            }
            mail_parameters.push(MailParameter::Body(MailBodyParameter::EightBitMime));
        }

        let mail = connection.command(Mail::new(Some(prepared.from), mail_parameters));
        if let Err(failure) = step(deadline, mail).await {
            return transaction_failure(SmtpStage::MailFrom, &failure);
        }
        let rcpt = connection.command(Rcpt::new(prepared.to, Vec::new()));
        if let Err(failure) = step(deadline, rcpt).await {
            return transaction_failure(SmtpStage::RcptTo, &failure);
        }
        if let Err(failure) = step(deadline, connection.command(Data)).await {
            return transaction_failure(SmtpStage::Data, &failure);
        }
        let response = match step(deadline, connection.message(&prepared.content)).await {
            Ok(response) => response,
            Err(failure) => return end_of_data_failure(&failure),
        };

        let quit_deadline = deadline.min(Instant::now() + QUIT_BOUND);
        if !matches!(
            timeout_at(quit_deadline, connection.quit()).await,
            Ok(Ok(_))
        ) {
            // The relay already accepted the message, so a failed goodbye
            // changes nothing about the outcome.
            tracing::debug!("smtp session did not close cleanly after acceptance");
        }
        Sent {
            outcome: SendOutcome::Accepted {
                provider_reference: queue_reference(&response),
            },
            detail: SmtpAttemptDetail {
                stage: SmtpStage::EndOfData,
                reply_code: Some(u16::from(response.code())),
                failure: None,
            },
        }
    }

    /// Resolve the host once and refuse the whole answer set when any answer
    /// is outside what the settings allow.
    async fn resolve(&self) -> Result<Vec<IpAddr>, SmtpFailure> {
        let answers = match (self.host.parse::<IpAddr>(), &self.network) {
            (Ok(literal), _) => vec![literal],
            (Err(_), Network::System) => {
                let resolved = tokio::net::lookup_host((self.host.as_str(), self.port))
                    .await
                    .map_err(|_| SmtpFailure::Resolution)?;
                let mut answers = Vec::new();
                for address in resolved {
                    if answers.len() == MAXIMUM_RESOLVER_ANSWERS {
                        return Err(SmtpFailure::Resolution);
                    }
                    if !answers.contains(&address.ip()) {
                        answers.push(address.ip());
                    }
                }
                answers
            }
            #[cfg(test)]
            (Err(_), Network::Scripted { answers, .. }) => answers.clone(),
        };
        if answers.is_empty() {
            return Err(SmtpFailure::Resolution);
        }
        for address in &answers {
            let allowed = match self.transport {
                Transport::DevelopmentLoopback => address.to_canonical().is_loopback(),
                Transport::Starttls(_) | Transport::Implicit(_) => {
                    self.policy.classify(*address).is_ok()
                }
            };
            if !allowed {
                return Err(SmtpFailure::DestinationRefused);
            }
        }
        Ok(answers)
    }

    fn connect_target(&self, checked: SocketAddr) -> SocketAddr {
        match &self.network {
            Network::System => checked,
            #[cfg(test)]
            Network::Scripted { connect_to, .. } => *connect_to,
        }
    }
}

async fn step<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = Result<T, lettre::transport::smtp::Error>>,
) -> Result<T, StepFailure> {
    match timeout_at(deadline, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(StepFailure::Smtp(error)),
        Err(_) => Err(StepFailure::TimedOut),
    }
}

/// Check the message and build its content before any network activity.
fn prepare(message: &SmtpMessage<'_>) -> Result<Prepared, &'static str> {
    if !valid_message_id(message.message_id) {
        return Err("smtp-message-id-invalid");
    }
    let from = Address::from_str(message.from).map_err(|_| "smtp-sender-invalid")?;
    let to = Address::from_str(message.to).map_err(|_| "smtp-recipient-invalid")?;
    if !from.domain().is_ascii() {
        return Err("smtp-sender-invalid");
    }
    let mut builder = Message::builder()
        .message_id(Some(format!("<{}@{}>", message.message_id, from.domain())))
        .from(Mailbox::new(None, from.clone()))
        .to(Mailbox::new(None, to.clone()));
    if let Some(subject) = &message.parts.subject {
        builder = builder.subject(subject.as_str());
    }
    let built = match &message.parts.html {
        Some(html) => builder.multipart(MultiPart::alternative_plain_html(
            message.parts.text.clone(),
            html.clone(),
        )),
        None => builder.singlepart(SinglePart::plain(message.parts.text.clone())),
    }
    .map_err(|_| "smtp-message-invalid")?;
    Ok(Prepared {
        from,
        to,
        content: built.formatted(),
    })
}

fn is_ascii(address: &Address) -> bool {
    address.user().is_ascii() && address.domain().is_ascii()
}

fn valid_message_id(value: &str) -> bool {
    (1..=MAXIMUM_SMTP_MESSAGE_ID_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// The queue id a relay names in its acceptance, such as Postfix's
/// `250 2.0.0 Ok: queued as 4BCD12345`, when it fits a provider reference.
fn queue_reference(response: &Response) -> Option<ProviderReference> {
    const MARKER: &str = "queued as ";
    response.message().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        let start = lower.find(MARKER)? + MARKER.len();
        let token = line.get(start..)?.split_whitespace().next()?;
        ProviderReference::new(token).ok()
    })
}

fn reply_code(failure: &StepFailure) -> Option<u16> {
    match failure {
        StepFailure::Smtp(error) => error.status().map(u16::from),
        StepFailure::TimedOut => None,
    }
}

fn failure_class(failure: &StepFailure) -> SmtpFailure {
    match failure {
        StepFailure::TimedOut => SmtpFailure::TimedOut,
        StepFailure::Smtp(error) if error.status().is_some() => SmtpFailure::Reply,
        StepFailure::Smtp(_) => SmtpFailure::Connection,
    }
}

/// Before `MAIL FROM` the failure concerns the relay, so a later attempt may
/// succeed whatever the reply was.
fn session_failure(stage: SmtpStage, failure: &StepFailure) -> Sent<SmtpAttemptDetail> {
    transient(stage, reply_code(failure), failure_class(failure))
}

/// Between `MAIL FROM` and `DATA` the relay has not seen the content: a `5xx`
/// is permanent, and anything else is transient.
fn transaction_failure(stage: SmtpStage, failure: &StepFailure) -> Sent<SmtpAttemptDetail> {
    classify_reply(stage, failure).unwrap_or_else(|| transient(stage, None, failure_class(failure)))
}

/// Once the content started, only a reply decides the outcome. A drop, a
/// timeout, or an unreadable reply may follow an acceptance the relay never
/// reported.
fn end_of_data_failure(failure: &StepFailure) -> Sent<SmtpAttemptDetail> {
    classify_reply(SmtpStage::EndOfData, failure).unwrap_or(Sent {
        outcome: SendOutcome::MaybeSent,
        detail: SmtpAttemptDetail {
            stage: SmtpStage::EndOfData,
            reply_code: None,
            failure: Some(failure_class(failure)),
        },
    })
}

fn classify_reply(stage: SmtpStage, failure: &StepFailure) -> Option<Sent<SmtpAttemptDetail>> {
    let code = reply_code(failure)?;
    Some(if (500..600).contains(&code) {
        permanent(
            stage,
            Some(code),
            SmtpFailure::Reply,
            &format!("smtp-{code}"),
        )
    } else {
        transient(stage, Some(code), SmtpFailure::Reply)
    })
}

fn transient(
    stage: SmtpStage,
    reply_code: Option<u16>,
    failure: SmtpFailure,
) -> Sent<SmtpAttemptDetail> {
    Sent {
        outcome: SendOutcome::Transient { retry_after: None },
        detail: SmtpAttemptDetail {
            stage,
            reply_code,
            failure: Some(failure),
        },
    }
}

fn permanent(
    stage: SmtpStage,
    reply_code: Option<u16>,
    failure: SmtpFailure,
    code: &str,
) -> Sent<SmtpAttemptDetail> {
    let code = FailureCode::new(code).expect("SMTP failure codes are bounded lowercase literals");
    Sent {
        outcome: SendOutcome::Permanent { code },
        detail: SmtpAttemptDetail {
            stage,
            reply_code,
            failure: Some(failure),
        },
    }
}

const fn outcome_class(outcome: &SendOutcome) -> &'static str {
    match outcome {
        SendOutcome::Accepted { .. } => "accepted",
        SendOutcome::Transient { .. } => "transient",
        SendOutcome::Permanent { .. } => "permanent",
        SendOutcome::MaybeSent => "maybe-sent",
    }
}

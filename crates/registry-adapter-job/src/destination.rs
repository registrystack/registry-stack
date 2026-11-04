// SPDX-License-Identifier: Apache-2.0

//! The destination seam (`products/adapter/CONCEPT.md` section 17.3):
//! the one hand-off point
//! every destination plugs into. A destination receives only the job
//! identity and the item's deliverable, which carries the declared
//! projection, never the raw source item and never a credential. The
//! seam's contract:
//!
//! - [`JobDestination::deliver`] is called once per new or changed item,
//!   and once more per unchanged `pending` item the pass re-delivers.
//!   An item-scoped refusal returns [`HandOffOutcome::Refused`] and the
//!   pass continues with the next item. An item that cannot safely be
//!   delivered again returns [`HandOffOutcome::Held`] and waits for an operator
//!   without another automatic attempt. A queue-shaped source keeps its
//!   delivery unsettled because it is the only payload buffer. A deployment-level failure
//!   (authentication, a held deployment, an unavailable service)
//!   returns [`HandOffOutcome::StopPass`] and the pass stops with the
//!   source position unchanged. An accepted item returns
//!   [`HandOffOutcome::Acknowledged`] with the reference the destination
//!   returned.
//! - Retry identity belongs to the caller of the seam: the deliverable
//!   carries `(job id, item key, sequence, digest)`, and the pass
//!   re-delivers a crashed hand-off with those four values unchanged.
//!   A destination derives its own retry key from them, so a replayed
//!   delivery recovers the earlier effect instead of duplicating it.
//!   This is the plug-in point the direct destination builds on; the
//!   signed-event destination derives its event id the same way.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use registry_adapter_core::JobIdentity;
use serde_json::Value;

/// The pass-stop code a destination's own answer cannot name: the seam
/// could not complete the exchange at all (no connection, a timeout, a
/// body outside the seam's answer shape). A destination that received
/// the delivery answers with its own code instead.
pub const DESTINATION_UNREACHABLE: &str = "adapter.job.destination-unreachable";

/// The stop code of a destination answer the item table cannot hold: a
/// refusal or stop code, or an acknowledgement's reference, that is
/// empty or longer than [`MAXIMUM_ANSWER_BYTES`].
pub const DESTINATION_ANSWER_INVALID: &str = "adapter.job.destination-answer-invalid";

/// The longest code or reference a destination may answer with, in
/// bytes: the item table's own column bound.
pub const MAXIMUM_ANSWER_BYTES: usize = 256;

/// How one hand-off ended. Every code is the destination's own and
/// value-free: the pass records it and never derives a message from the
/// item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandOffOutcome {
    /// The destination accepted the item. `run_id` is the reference the
    /// destination returned, such as a proposal id or a run id, stored
    /// beside the item row.
    Acknowledged {
        /// The destination's reference for the accepted item.
        run_id: Option<String>,
    },
    /// The destination refused this item, item-scoped. The pass records
    /// the code and continues with the next item.
    Refused {
        /// The destination's own item-scoped refusal code.
        code: String,
    },
    /// The item cannot safely be handed off again without an operator's
    /// decision. The pass records the code and optional destination
    /// reference and skips this digest on ordinary and rescan passes. A
    /// queue delivery remains unsettled; a later digest is still surfaced as
    /// a revision.
    Held {
        /// The destination's value-free reason for the hold.
        code: String,
        /// The destination reference an operator follows, when known.
        run_id: Option<String>,
    },
    /// The destination refused the deployment, not the item. The pass
    /// stops with the source position unchanged.
    StopPass {
        /// The destination's own deployment-level code.
        code: String,
    },
}

/// The one item the seam delivers: the source key, the change sequence,
/// the plain digest, what a previous hand-off of this key returned, and
/// the declared projection. The raw source item is not carried and no
/// credential rides beside it.
#[derive(Clone, Debug)]
pub struct DeliverableItem {
    /// The source item's stable key, under the job's namespace.
    pub key: String,
    /// How many changes this key has seen, from 1. Two deliveries that
    /// agree on key, sequence, and digest are the same logical hand-off.
    pub sequence: i64,
    /// The plain `sha256:` digest of the bytes the job's digestOf
    /// declaration covers.
    pub digest: String,
    /// The run reference a previous, different-digest hand-off of this
    /// key returned, when one did.
    pub prior_run_id: Option<String>,
    /// Whether this key was handed off before under a digest whose
    /// receipt may have been lost: a destination treats a changed
    /// digest beside `admitted_before` as a question for an operator,
    /// never as a license to write again.
    pub admitted_before: bool,
    /// The persisted time this item key first entered the item table.
    pub first_seen: SystemTime,
    /// The event time frozen for this sequence. A retry never replaces it
    /// with the current clock; a changed digest receives a new event time.
    pub event_time: SystemTime,
    /// The positive, persisted delivery attempt for this sequence.
    pub delivery_attempt: i64,
    /// The job's declared projection of the item value: one member per
    /// declared field, missing fields as `null`. A destination never
    /// sees more of the item than this.
    pub projected: Value,
}

/// Which destination a [`DeliveryIdentity`] fences, so a stopped pass names
/// the receiver the operator configured, never another destination's.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryFamily {
    /// The signed Coordinator event destination.
    Coordinator,
    /// The direct BReg destination.
    Breg,
}

/// What a fenced destination commits to before an item leaves the process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryIdentity {
    /// The destination whose stop codes a refused fence reports.
    pub family: DeliveryFamily,
    /// The digest of the selected public governed receiver authority and
    /// configuration.
    pub receiver: [u8; 32],
    /// The SHA-256 digest of the exact canonical bytes (an event envelope, or
    /// the mapped BReg operation) the destination would send. `Err(())` means
    /// the current item cannot form canonical bytes and therefore must never
    /// recover an uncertain pending attempt by changing or discarding its
    /// frozen body.
    pub canonical_body: Result<[u8; 32], ()>,
}

/// The destination seam. Implementations are shared across passes, so
/// they are `Send + Sync`; the futures they return are `Send` so a pass
/// runs under the operator's own runtime. The boxed futures keep the
/// trait an object, which the pass takes as `&dyn JobDestination`, so a
/// destination is a configuration choice and not a compile-time one.
pub trait JobDestination: Send + Sync {
    /// The identities a fenced destination freezes before it sends, or `None`
    /// when this destination does not use the delivery-identity fence. The pass
    /// freezes both before calling [`Self::deliver`], so a pending retry
    /// cannot silently move the same event identity to another target or
    /// change the event bytes. The two identities travel together because a
    /// receiver identity without a body identity could never be checked.
    fn delivery_identity(
        &self,
        _job: &JobIdentity,
        _item: &DeliverableItem,
    ) -> Option<DeliveryIdentity> {
        None
    }

    /// Deliver one item. Called after the item row is already written as
    /// `pending`, so a crash after this call leaves a pending row whose
    /// next pass re-delivers identical bytes: the at-least-once hand-off
    /// whose dedup duty the retry identity above puts on the
    /// destination.
    fn deliver<'a>(
        &'a self,
        job: &'a JobIdentity,
        item: &'a DeliverableItem,
    ) -> Pin<Box<dyn Future<Output = HandOffOutcome> + Send + 'a>>;
}

/// The operator-preview destination of `pass --dry-run`: it acknowledges
/// nothing and records what a real destination would have received, so
/// the preview reads what would leave the process. The pass runs it
/// without writing any state.
#[derive(Default)]
pub struct NullDestination {
    recorded: Mutex<Vec<(String, DeliverableItem)>>,
}

impl NullDestination {
    /// An empty preview destination.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// What the pass would have delivered, in delivery order, as
    /// `(job id, deliverable)` pairs.
    #[must_use]
    pub fn recorded(&self) -> Vec<(String, DeliverableItem)> {
        self.recorded
            .lock()
            .expect("the preview record lock is never poisoned while held")
            .clone()
    }
}

impl JobDestination for NullDestination {
    fn deliver<'a>(
        &'a self,
        job: &'a JobIdentity,
        item: &'a DeliverableItem,
    ) -> Pin<Box<dyn Future<Output = HandOffOutcome> + Send + 'a>> {
        Box::pin(async move {
            self.recorded
                .lock()
                .expect("the preview record lock is never poisoned while held")
                .push((job.id.as_str().to_string(), item.clone()));
            HandOffOutcome::Acknowledged { run_id: None }
        })
    }
}

/// The built-in fixture destination of `pass --fixture`:
/// it posts one deliverable to a fixture receiver over plain HTTP and
/// maps the receiver's scripted answer back onto the seam's outcomes.
/// It speaks loopback HTTP only, because the exchange is unauthenticated
/// and unencrypted by construction; a real destination is the brief's
/// own build on this seam, not this client.
#[derive(Clone, Debug)]
pub struct FixtureDestination {
    /// The receiver's base URL; the host must be a loopback address.
    url: String,
    /// How long one delivery may take before the seam reports the
    /// receiver unreachable.
    timeout: Duration,
}

impl FixtureDestination {
    /// A fixture destination for a loopback receiver, such as the test
    /// suite's scripted receiver. A URL whose host is outside the
    /// loopback refuses: the fixture exchange carries no transport
    /// security.
    ///
    /// # Errors
    ///
    /// A URL that is not loopback HTTP refuses, so a projection never
    /// travels an unencrypted hop off the machine.
    pub fn new(url: &str) -> Result<Self, String> {
        let rest = url.strip_prefix("http://").ok_or_else(|| {
            "the fixture url must be plain http to a loopback receiver".to_string()
        })?;
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host = authority
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(authority);
        let loopback = matches!(host, "127.0.0.1" | "::1" | "[::1]" | "localhost");
        if !loopback {
            return Err(format!(
                "the fixture url host {host} is not a loopback address; the fixture receiver runs on this machine"
            ));
        }
        Ok(Self {
            url: url.trim_end_matches('/').to_string(),
            timeout: Duration::from_secs(5),
        })
    }

    /// Shorten the delivery timeout, for the test that proves a stalled
    /// receiver stops the pass.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// The answer body the fixture receiver sends: one outcome member, plus
/// the reference or code the scripted outcome names.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixtureAnswer {
    outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

impl JobDestination for FixtureDestination {
    fn deliver<'a>(
        &'a self,
        job: &'a JobIdentity,
        item: &'a DeliverableItem,
    ) -> Pin<Box<dyn Future<Output = HandOffOutcome> + Send + 'a>> {
        Box::pin(async move {
            // The request body is exactly the deliverable, canonically
            // serialized: the same bytes a retry of this hand-off sends.
            let body = serde_json::json!({
                "jobId": job.id.as_str(),
                "jobVersion": job.version,
                "key": item.key,
                "sequence": item.sequence,
                "digest": item.digest,
                "priorRunId": item.prior_run_id,
                "admittedBefore": item.admitted_before,
                "projected": item.projected,
            });
            let body = crate::projection::canonical_bytes(&body);
            match post_json(&self.url, &body, self.timeout).await {
                Ok(answer) => match answer.outcome.as_str() {
                    "acknowledged" => HandOffOutcome::Acknowledged {
                        run_id: answer.run_id,
                    },
                    "refused" => match answer.code {
                        Some(code) => HandOffOutcome::Refused { code },
                        None => HandOffOutcome::StopPass {
                            code: DESTINATION_UNREACHABLE.to_string(),
                        },
                    },
                    "held" => match answer.code {
                        Some(code) => HandOffOutcome::Held {
                            code,
                            run_id: answer.run_id,
                        },
                        None => HandOffOutcome::StopPass {
                            code: DESTINATION_UNREACHABLE.to_string(),
                        },
                    },
                    "stop" => match answer.code {
                        Some(code) => HandOffOutcome::StopPass { code },
                        None => HandOffOutcome::StopPass {
                            code: DESTINATION_UNREACHABLE.to_string(),
                        },
                    },
                    _ => HandOffOutcome::StopPass {
                        code: DESTINATION_UNREACHABLE.to_string(),
                    },
                },
                Err(()) => HandOffOutcome::StopPass {
                    code: DESTINATION_UNREACHABLE.to_string(),
                },
            }
        })
    }
}

/// One minimal HTTP/1.1 POST to the loopback receiver, the response
/// parsed as the seam's answer. Any transport fault, status outside 200,
/// or unparseable body is a transport failure: `Err`, which the caller
/// maps to the pass-stop for an unreachable destination.
async fn post_json(url: &str, body: &[u8], timeout: Duration) -> Result<FixtureAnswer, ()> {
    let rest = url.strip_prefix("http://").ok_or(())?;
    let authority_and_path = rest.split(['?', '#']).next().ok_or(())?;
    let (authority, path) = match authority_and_path.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (authority_and_path, "/".to_string()),
    };
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let send = async {
        let stream = tokio::net::TcpStream::connect(authority)
            .await
            .map_err(|_| ())?;
        let (mut read, mut write) = tokio::io::split(stream);
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        write.write_all(request.as_bytes()).await.map_err(|_| ())?;
        write.write_all(body).await.map_err(|_| ())?;
        // Content-Length delimits the request; keep the write side open while
        // the receiver prepares its response, including its in-flight work.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        // Read the header block to its blank line.
        loop {
            if read.read_exact(&mut byte).await.is_err() {
                return Err(());
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
            if head.len() > 16_384 {
                return Err(());
            }
        }
        let head = String::from_utf8(head).map_err(|_| ())?;
        let status_line = head.lines().next().ok_or(())?;
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or(())?;
        if status != 200 {
            return Err(());
        }
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .ok_or(())?;
        if length > 1_048_576 {
            return Err(());
        }
        let mut answer = vec![0u8; length];
        read.read_exact(&mut answer).await.map_err(|_| ())?;
        serde_json::from_slice::<FixtureAnswer>(&answer).map_err(|_| ())
    };
    tokio::time::timeout(timeout, send).await.map_err(|_| ())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fixture_destination_refuses_any_non_loopback_receiver() {
        assert!(FixtureDestination::new("http://127.0.0.1:9000/deliver").is_ok());
        assert!(FixtureDestination::new("http://localhost:9000/deliver").is_ok());
        assert!(FixtureDestination::new("http://[::1]:9000/deliver").is_ok());
        let refused = FixtureDestination::new("http://kobo.example.invalid/deliver");
        assert!(refused.is_err(), "a non-loopback fixture url refuses");
        assert!(FixtureDestination::new("https://127.0.0.1:9000/deliver").is_err());
    }

    #[tokio::test]
    async fn fixture_waits_for_response_without_half_closing() {
        use std::io::{Read as _, Write as _};
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind the owned fixture receiver");
        let address = listener.local_addr().expect("read the fixture address");
        let receiver = tokio::task::spawn_blocking(move || {
            let (mut socket, _) = listener.accept().expect("accept the fixture request");
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("bound the fixture request read");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).expect("read the request head");
                head.push(byte[0]);
                assert!(head.len() <= 16_384);
            }
            let mut body = [0u8; 2];
            socket
                .read_exact(&mut body)
                .expect("read the complete request body");
            assert_eq!(&body, b"{}");
            // A receiver need not support client half-closure while its
            // response is pending. Content-Length already delimits the request.
            match socket.read(&mut byte) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Ok(0) => panic!("the fixture client closed its write side before the response"),
                Ok(_) => panic!("the fixture client sent undeclared request bytes"),
                Err(error) => panic!("the bounded fixture read failed: {error}"),
            }
            let answer = br#"{"outcome":"acknowledged"}"#;
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                answer.len()
            )
            .expect("write the fixture response head");
            socket
                .write_all(answer)
                .expect("write the fixture response body");
        });
        let answer = post_json(
            &format!("http://{address}/deliver"),
            b"{}",
            Duration::from_secs(5),
        )
        .await
        .expect("the fixture client waits for the receiver's response");
        assert_eq!(answer.outcome, "acknowledged");
        receiver
            .await
            .expect("the owned fixture receiver completes");
    }
}

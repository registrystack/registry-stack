// SPDX-License-Identifier: Apache-2.0

//! The `pollEnrich` processor, the bounded job-only read step
//! (`products/adapter/CONCEPT.md` sections 8.10 and 17.2).
//!
//! One step executes one bounded read: the static `file:<endpointId>`
//! uri resolves against the compiled file source, the read runs inside
//! the step's mandatory `timeoutMilliseconds` (1 to 10000) as its read
//! deadline, and the page lands on the exchange through the step's
//! aggregation strategy, which by default replaces the body, the same
//! default an `enrich` with no strategy carries. The strategy machinery
//! is the enrich processor's own fold.
//!
//! Timeout semantics: camel-4.23.0's PollEnricher receives with the
//! timeout and, when no resource arrives, aggregates nothing
//! (camel-4.23.0:core/camel-core-processor/src/main/java/org/apache/camel/processor/PollEnricher.java,
//! the null-resource path whose default strategy leaves the original
//! exchange standing). WE DIVERGE: our read is local and immediate, so
//! the timeout is the read deadline, and a read that cannot finish
//! inside it raises `upstream.timeout` instead of silently aggregating
//! nothing, because nothing is silently skipped here.

use std::time::Duration;

#[cfg(feature = "job-file")]
use registry_adapter_core::PollDecoder;
#[cfg(any(feature = "job-file", feature = "job-sftp"))]
use registry_adapter_core::RecordLocator;
use registry_adapter_core::{
    AggregationStrategy, ErrorClass, PollEnrichStep, SendComponent, SendUri,
};
#[cfg(feature = "job-rabbitmq")]
use registry_platform_config::sha256_uri;
use serde_json::json;

#[cfg(feature = "job-file")]
use crate::component::file::{read_page, FileReadFault};
#[cfg(feature = "job-rabbitmq")]
use crate::component::rabbitmq::{
    rabbitmq_item_key, RabbitMqPageReceipt, RabbitMqReadFault, RabbitMqReadRequest,
    RabbitMqSettlementFault,
};
#[cfg(feature = "job-sftp")]
use crate::component::sftp::SftpReadFault;
#[cfg(feature = "job-file")]
use crate::decoder::Decoder;
#[cfg(feature = "job-file")]
use crate::job::ADAPTER_JOB_CURSOR_PROPERTY;
use crate::job::JOB_PAGE_DECODE_FAULTS_EVENT;
use crate::job_sources::SourceReadPage;
use crate::processor::aggregation;
use crate::route::{Flow, RouteFailure, Run};

/// The closed code a read refusal carries, value-free.
const READ_BOUND_CODE: &str = "adapter.job.read-bound";
const READ_TIMEOUT_CODE: &str = "adapter.job.read-timeout";
const DECODER_ROW_CODE: &str = "adapter.job.decoder-row";
#[cfg(any(feature = "job-file", feature = "job-sftp"))]
const DECODER_KEY_MISSING_CODE: &str = "adapter.job.decoder-key-missing";
#[cfg(any(feature = "job-file", feature = "job-sftp"))]
const DECODER_KEY_INVALID_CODE: &str = "adapter.job.decoder-key-invalid";
#[cfg(any(feature = "job-file", feature = "job-sftp"))]
const DECODER_KEY_DUPLICATE_CODE: &str = "adapter.job.decoder-key-duplicate";
#[cfg(feature = "job-rabbitmq")]
const RABBITMQ_DELIVERY_MODE_CODE: &str = "adapter.job.rabbitmq-delivery-mode";
#[cfg(feature = "job-rabbitmq")]
const RABBITMQ_TOPOLOGY_CODE: &str = "adapter.job.rabbitmq-topology";
#[cfg(feature = "job-rabbitmq")]
const RABBITMQ_UNAVAILABLE_CODE: &str = "adapter.job.rabbitmq-unavailable";
#[cfg(feature = "job-sftp")]
const SFTP_CONNECTION_CODE: &str = "adapter.job.sftp-connection";
#[cfg(feature = "job-sftp")]
const SFTP_HOST_KEY_CODE: &str = "adapter.job.sftp-host-key";
#[cfg(feature = "job-sftp")]
const SFTP_CREDENTIAL_CODE: &str = "adapter.job.sftp-credential";
#[cfg(feature = "job-sftp")]
const SFTP_AUTHENTICATION_CODE: &str = "adapter.job.sftp-authentication";
#[cfg(feature = "job-sftp")]
const SFTP_MALFORMED_CODE: &str = "adapter.job.sftp-malformed";
#[cfg(feature = "job-sftp")]
const SFTP_PATH_CODE: &str = "adapter.job.sftp-path";

pub(crate) async fn run(
    run: &mut Run<'_, '_>,
    poll: &PollEnrichStep,
) -> Result<Flow, RouteFailure> {
    // The served shape is refused at load; the runtime holds the same
    // line so a hand-built context cannot slip past it.
    let Some(uri) = SendUri::parse(&poll.uri) else {
        return Err(read_refused(
            ErrorClass::EgressRefused,
            READ_BOUND_CODE,
            "the pollEnrich step names no file endpoint the engine can read".to_owned(),
        ));
    };
    if !matches!(
        uri.component,
        SendComponent::File | SendComponent::RabbitMq | SendComponent::Sftp
    ) {
        return Err(read_refused(
            ErrorClass::EgressRefused,
            READ_BOUND_CODE,
            "a pollEnrich step is served over a file, RabbitMQ, or SFTP endpoint only".to_owned(),
        ));
    }
    let Some(timeout) = poll.timeout_milliseconds else {
        return Err(read_refused(
            ErrorClass::EgressRefused,
            READ_BOUND_CODE,
            "the pollEnrich step declares no timeoutMilliseconds".to_owned(),
        ));
    };
    let rabbitmq_json = poll
        .decoder
        .as_ref()
        .map(registry_adapter_core::PollDecoder::name)
        == Some("rabbitmq-json");
    if matches!(uri.component, SendComponent::RabbitMq) != rabbitmq_json {
        return Err(read_refused(
            ErrorClass::EgressRefused,
            READ_BOUND_CODE,
            "the RabbitMQ source and rabbitmq-json decoder profile do not match".to_owned(),
        ));
    }
    #[cfg(feature = "job-file")]
    let decoder = match poll.decoder.as_ref() {
        None => Decoder::Raw,
        Some(PollDecoder::Csv(options)) => Decoder::Csv {
            options: options.clone(),
            key_pointer: row_key_pointer(poll)?,
        },
        Some(PollDecoder::Named(name)) if name == "raw" => Decoder::Raw,
        Some(PollDecoder::Named(name)) if name == "csv" => Decoder::Csv {
            options: Default::default(),
            key_pointer: row_key_pointer(poll)?,
        },
        Some(PollDecoder::Named(name)) if name == "jsonl" => Decoder::Jsonl {
            key_pointer: row_key_pointer(poll)?,
        },
        Some(_) => {
            return Err(read_refused(
                ErrorClass::EgressRefused,
                READ_BOUND_CODE,
                "the pollEnrich names no decoder the engine carries".to_owned(),
            ))
        }
    };
    let bounds = run
        .context
        .job
        .profile
        .as_ref()
        .map(|profile| profile.read.clone())
        .unwrap_or_else(crate::job_sources::unused_read_bounds);
    #[cfg(feature = "job-file")]
    let cursor = run.exchange.property(ADAPTER_JOB_CURSOR_PROPERTY).cloned();
    run.ensure_deadline()?;
    let remaining = run
        .deadline
        .saturating_duration_since(tokio::time::Instant::now());
    let read_deadline = Duration::from_millis(timeout.get()).min(remaining);
    let operation_deadline = tokio::time::Instant::now() + read_deadline;
    let page = match uri.component {
        SendComponent::File => {
            #[cfg(feature = "job-file")]
            {
                let source = run.context.job.files.get(uri.id.as_str()).ok_or_else(|| {
                    read_refused(
                        ErrorClass::EgressRefused,
                        READ_BOUND_CODE,
                        "the pollEnrich names an endpoint this build carries no file source for"
                            .to_owned(),
                    )
                })?;
                match tokio::time::timeout_at(
                    operation_deadline,
                    read_page(
                        source,
                        &bounds,
                        cursor.as_ref(),
                        &decoder,
                        run.context.job.ongoing_scan,
                    ),
                )
                .await
                {
                    Err(_) => return Err(read_timeout()),
                    Ok(Err(fault)) => return Err(read_fault(fault)),
                    Ok(Ok(page)) => page,
                }
            }
            #[cfg(not(feature = "job-file"))]
            {
                return Err(read_refused(
                    ErrorClass::EgressRefused,
                    READ_BOUND_CODE,
                    "this build carries no file source host".to_owned(),
                ));
            }
        }
        SendComponent::Sftp => {
            #[cfg(feature = "job-sftp")]
            {
                let plan = run.context.job.sftp.get(uri.id.as_str()).ok_or_else(|| {
                    read_refused(
                        ErrorClass::EgressRefused,
                        READ_BOUND_CODE,
                        "the pollEnrich names an endpoint this job carries no SFTP plan for"
                            .to_owned(),
                    )
                })?;
                let source = run
                    .context
                    .job
                    .sftp_clients
                    .get(uri.id.as_str())
                    .ok_or_else(|| {
                        read_refused(
                            ErrorClass::EgressRefused,
                            READ_BOUND_CODE,
                            "the job host did not register the declared SFTP source".to_owned(),
                        )
                    })?;
                match tokio::time::timeout_at(
                    operation_deadline,
                    crate::component::sftp::read_page(
                        plan,
                        source.as_ref(),
                        &bounds,
                        cursor.as_ref(),
                        &decoder,
                        operation_deadline,
                        run.context.job.ongoing_scan,
                    ),
                )
                .await
                {
                    Err(_) => return Err(read_timeout()),
                    Ok(Err(fault)) => return Err(sftp_read_fault(fault)),
                    Ok(Ok(page)) => page,
                }
            }
            #[cfg(not(feature = "job-sftp"))]
            {
                return Err(read_refused(
                    ErrorClass::EgressRefused,
                    READ_BOUND_CODE,
                    "this build carries no SFTP source host".to_owned(),
                ));
            }
        }
        SendComponent::RabbitMq => {
            #[cfg(feature = "job-rabbitmq")]
            {
                let plan = run
                    .context
                    .job
                    .rabbitmq
                    .get(uri.id.as_str())
                    .ok_or_else(|| {
                        read_refused(
                        ErrorClass::EgressRefused,
                        READ_BOUND_CODE,
                        "the pollEnrich names an endpoint this job carries no RabbitMQ plan for"
                            .to_owned(),
                    )
                    })?;
                let source = run
                    .context
                    .job
                    .rabbitmq_clients
                    .get(uri.id.as_str())
                    .ok_or_else(|| {
                        read_refused(
                            ErrorClass::EgressRefused,
                            READ_BOUND_CODE,
                            "the job host did not register the declared RabbitMQ source".to_owned(),
                        )
                    })?;
                let maximum_message_bytes =
                    usize::try_from(bounds.maximum_row_bytes.get()).map_err(|_| read_bound())?;
                let request = RabbitMqReadRequest::new(maximum_message_bytes, read_deadline)
                    .map_err(rabbitmq_read_fault)?;
                let message = match tokio::time::timeout_at(
                    operation_deadline,
                    source.read(&request),
                )
                .await
                {
                    Err(_) => return Err(read_timeout()),
                    Ok(Err(fault)) => return Err(rabbitmq_read_fault(fault)),
                    Ok(Ok(message)) => message,
                };
                let Some(message) = message else {
                    return aggregate_page(
                        run,
                        poll,
                        SourceReadPage {
                            body: json!({ "items": [] }),
                            malformed_lines: 0,
                        },
                    );
                };
                let (source_identity, redelivered, body, settlement) = message.into_parts();
                let value: serde_json::Value = match serde_json::from_slice(&body) {
                    Ok(value) => value,
                    Err(_) => {
                        tokio::time::timeout(read_deadline, settlement.refuse())
                            .await
                            .map_err(|_| {
                                rabbitmq_settlement_fault(RabbitMqSettlementFault::Uncertain)
                            })?
                            .map_err(rabbitmq_settlement_fault)?;
                        return Err(read_refused(
                            ErrorClass::UpstreamMalformed,
                            DECODER_ROW_CODE,
                            "the rabbitmq-json decoder refused the message body".to_owned(),
                        ));
                    }
                };
                if !crate::json_bounds::json_within_field_bound(
                    &value,
                    bounds.maximum_field_bytes.get() as usize,
                ) {
                    tokio::time::timeout(read_deadline, settlement.refuse())
                        .await
                        .map_err(|_| rabbitmq_settlement_fault(RabbitMqSettlementFault::Uncertain))?
                        .map_err(rabbitmq_settlement_fault)?;
                    return Err(read_refused(
                        ErrorClass::UpstreamTooLarge,
                        READ_BOUND_CODE,
                        "the rabbitmq-json decoder refused an over-bound field".to_owned(),
                    ));
                }
                let key = rabbitmq_item_key(&plan.namespace, &source_identity);
                let revision = sha256_uri(&body);
                let receipt = RabbitMqPageReceipt::new(
                    key.clone(),
                    revision.clone(),
                    redelivered,
                    read_deadline,
                    settlement,
                );
                let mut slot = run
                    .context
                    .job
                    .rabbitmq_receipt
                    .lock()
                    .map_err(|_| rabbitmq_page_shape())?;
                if slot.is_some() {
                    return Err(rabbitmq_page_shape());
                }
                *slot = Some(receipt);
                SourceReadPage {
                    body: json!({
                        "items": [{
                            "key": key,
                            "revision": revision,
                            "value": value
                        }]
                    }),
                    malformed_lines: 0,
                }
            }
            #[cfg(not(feature = "job-rabbitmq"))]
            {
                return Err(read_refused(
                    ErrorClass::EgressRefused,
                    READ_BOUND_CODE,
                    "this build carries no RabbitMQ source host".to_owned(),
                ));
            }
        }
        _ => unreachable!("the served component check is exhaustive"),
    };
    aggregate_page(run, poll, page)
}

#[cfg(feature = "job-file")]
fn row_key_pointer(poll: &PollEnrichStep) -> Result<String, RouteFailure> {
    poll.key_pointer.clone().ok_or_else(|| {
        read_refused(
            ErrorClass::EgressRefused,
            READ_BOUND_CODE,
            "the row decoder declares no business-key pointer".to_owned(),
        )
    })
}

fn aggregate_page(
    run: &mut Run<'_, '_>,
    poll: &PollEnrichStep,
    page: SourceReadPage,
) -> Result<Flow, RouteFailure> {
    if page.malformed_lines > 0 {
        run.record(
            JOB_PAGE_DECODE_FAULTS_EVENT,
            json!({ "malformedLines": page.malformed_lines }),
        );
    }
    // The page aggregates like an enrich reply: the strategy folds the
    // resource body into the route body, replacing it by default.
    let strategy = poll
        .aggregation_strategy
        .clone()
        .unwrap_or(AggregationStrategy::UseLatest {});
    let mut resource = run.exchange.clone();
    resource.message.body = page.body;
    let old_body = run.exchange.message.body.clone();
    run.ensure_deadline()?;
    let merged = aggregation::fold_enrich(
        run.context.scripts,
        &run.context.code_maps,
        &strategy,
        &old_body,
        &resource,
        run.deadline,
        run.maximum_exchange_bytes,
    )?;
    run.exchange.message.body = merged.body;
    for (name, value) in merged.properties {
        match value {
            Some(value) => run.exchange.set_property(&name, value),
            None => run.exchange.remove_property(&name),
        }
    }
    Ok(Flow::Continue)
}

#[cfg(feature = "job-rabbitmq")]
fn read_bound() -> RouteFailure {
    read_refused(
        ErrorClass::UpstreamTooLarge,
        READ_BOUND_CODE,
        "the RabbitMQ retained-message bound cannot be represented by this host".to_owned(),
    )
}

#[cfg(feature = "job-rabbitmq")]
fn rabbitmq_page_shape() -> RouteFailure {
    read_refused(
        ErrorClass::EgressRefused,
        "adapter.job.rabbitmq-page-shape",
        "one RabbitMQ page attempted to carry contradictory source receipts".to_owned(),
    )
}

#[cfg(feature = "job-rabbitmq")]
fn rabbitmq_read_fault(fault: RabbitMqReadFault) -> RouteFailure {
    let (class, code, message) = match fault {
        RabbitMqReadFault::Timeout => (
            ErrorClass::UpstreamTimeout,
            READ_TIMEOUT_CODE,
            "the RabbitMQ read deadline passed; check the broker's load or raise the step's timeoutMilliseconds",
        ),
        RabbitMqReadFault::Oversized => (
            ErrorClass::UpstreamTooLarge,
            READ_BOUND_CODE,
            "the RabbitMQ delivery exceeded the retained-message bound",
        ),
        RabbitMqReadFault::MissingIdentity | RabbitMqReadFault::IdentityBound => (
            ErrorClass::UpstreamMalformed,
            DECODER_ROW_CODE,
            "the RabbitMQ delivery carried no usable stable message identity",
        ),
        RabbitMqReadFault::NonPersistent => (
            ErrorClass::UpstreamMalformed,
            RABBITMQ_DELIVERY_MODE_CODE,
            "the RabbitMQ publisher did not mark the delivery persistent",
        ),
        RabbitMqReadFault::InvalidBounds => (
            ErrorClass::EgressRefused,
            READ_BOUND_CODE,
            "the RabbitMQ read bounds were refused",
        ),
        RabbitMqReadFault::Topology => (
            ErrorClass::EgressRefused,
            RABBITMQ_TOPOLOGY_CODE,
            "the RabbitMQ broker refused the source and dead-letter topology; check the user's permissions, and with declareTopology: true make existing queue arguments match the durable x-dead-letter-exchange and x-dead-letter-routing-key the runtime names",
        ),
        RabbitMqReadFault::MissingQueue => (
            ErrorClass::EgressRefused,
            RABBITMQ_TOPOLOGY_CODE,
            "the RabbitMQ source queue named by `queue` does not exist; create it durable with its dead-letter exchange, or set declareTopology: true so the runtime declares it",
        ),
        RabbitMqReadFault::MissingDeadLetterExchange => (
            ErrorClass::EgressRefused,
            RABBITMQ_TOPOLOGY_CODE,
            "the RabbitMQ dead-letter exchange named by `deadLetterExchange` does not exist; create it (direct, durable) with its queue and routing key, or set declareTopology: true so the runtime declares it",
        ),
        RabbitMqReadFault::Unavailable => (
            ErrorClass::UpstreamConnection,
            RABBITMQ_UNAVAILABLE_CODE,
            "the RabbitMQ source was unavailable; check host, port, vhost, user and passwordRef, and that the broker is running",
        ),
    };
    read_refused(class, code, message.to_owned())
}

#[cfg(feature = "job-rabbitmq")]
fn rabbitmq_settlement_fault(_fault: RabbitMqSettlementFault) -> RouteFailure {
    read_refused(
        ErrorClass::UpstreamConnection,
        RABBITMQ_UNAVAILABLE_CODE,
        "the RabbitMQ poison delivery settlement was uncertain; rerun the job once the broker is reachable, a redelivery is safe".to_owned(),
    )
}

fn read_timeout() -> RouteFailure {
    read_refused(
        ErrorClass::UpstreamTimeout,
        READ_TIMEOUT_CODE,
        "the pollEnrich read did not finish inside its timeoutMilliseconds; check the source's latency or raise timeoutMilliseconds".to_owned(),
    )
}

/// One read refusal as a route failure: the class the hierarchy carries
/// and the closed engine-read code the job entry reports beside it.
fn read_refused(class: ErrorClass, code: &'static str, message: String) -> RouteFailure {
    RouteFailure {
        class,
        message: Some(message),
        data: None,
        auth: None,
        code: Some(code),
        record: None,
        evidence_diagnostic: None,
    }
}

#[cfg(any(feature = "job-file", feature = "job-sftp"))]
fn record_refused(
    class: ErrorClass,
    code: &'static str,
    message: String,
    ordinal: u64,
) -> RouteFailure {
    let mut failure = read_refused(class, code, message);
    failure.record = Some(Box::new(RecordLocator {
        ordinal,
        column: None,
    }));
    failure
}

/// One file read fault as a route failure.
#[cfg(feature = "job-file")]
fn read_fault(fault: FileReadFault) -> RouteFailure {
    match fault {
        FileReadFault::Row(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_ROW_CODE,
                format!("the decoder refused record {ordinal} of the file (counted from 0, header included): a field is not valid UTF-8 (UTF-8 is required, so re-export the file as UTF-8), the record has more fields than the header, or the header repeats a column name; correct or replace the file, since the read stays blocked on it until then"),
                ordinal,
            )
        }
        FileReadFault::KeyMissing(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_KEY_MISSING_CODE,
                format!("the decoder found no declared business key on record {ordinal} of the file; check keyPointer against the file's columns"),
                ordinal,
            )
        }
        FileReadFault::KeyInvalid(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_KEY_INVALID_CODE,
                format!("the decoder refused the declared business key on record {ordinal} of the file; the key must be a non-empty string within the key bound"),
                ordinal,
            )
        }
        FileReadFault::KeyDuplicate(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_KEY_DUPLICATE_CODE,
                format!("the decoder found record {ordinal} of the file repeats an earlier business key; keys must be unique within one file"),
                ordinal,
            )
        }
        _ => {}
    }
    let (class, message): (ErrorClass, String) = match fault {
        FileReadFault::Traversal => (
            ErrorClass::EgressRefused,
            "the read refused a file name that contains a path separator (a backslash); rename the file, or narrow `include` so the name is not selected".to_owned(),
        ),
        FileReadFault::NameUnreadable => (
            ErrorClass::EgressRefused,
            "the read refused a file name that is not valid UTF-8; rename the file, or narrow `include` so the name is not selected".to_owned(),
        ),
        FileReadFault::Escape => (
            ErrorClass::EgressRefused,
            "the read refused a candidate whose path leaves the source directory".to_owned(),
        ),
        FileReadFault::Oversize => (
            ErrorClass::UpstreamTooLarge,
            "the read refused a file over the profile's file bound".to_owned(),
        ),
        FileReadFault::DirectoryUnreadable => (
            ErrorClass::UpstreamConnection,
            "the source directory could not be read".to_owned(),
        ),
        FileReadFault::Row(_)
        | FileReadFault::KeyMissing(_)
        | FileReadFault::KeyInvalid(_)
        | FileReadFault::KeyDuplicate(_) => unreachable!("record faults returned above"),
        FileReadFault::RowBound => (
            ErrorClass::UpstreamTooLarge,
            "the decoder refused a record or field over the profile's read bounds".to_owned(),
        ),
        FileReadFault::DecoderSyntax => (
            ErrorClass::EgressRefused,
            "the CSV decoder declares a syntax character outside ASCII".to_owned(),
        ),
        FileReadFault::LockTimeout => (
            ErrorClass::UpstreamTimeout,
            "the changed read lock did not settle inside its timeout; check that the producer has finished writing the file, or raise readLockTimeoutMilliseconds".to_owned(),
        ),
        FileReadFault::DecodeTimeout => (
            ErrorClass::UpstreamTimeout,
            "the file decode did not finish inside the pollEnrich timeoutMilliseconds; raise timeoutMilliseconds or split the file".to_owned(),
        ),
    };
    let code = match class {
        ErrorClass::UpstreamMalformed => DECODER_ROW_CODE,
        ErrorClass::UpstreamTimeout => READ_TIMEOUT_CODE,
        _ => READ_BOUND_CODE,
    };
    read_refused(class, code, message)
}

#[cfg(feature = "job-sftp")]
fn sftp_read_fault(fault: SftpReadFault) -> RouteFailure {
    match fault {
        SftpReadFault::Row(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_ROW_CODE,
                format!("the decoder refused record {ordinal} of the SFTP file (counted from 0, header included): a field is not valid UTF-8 (UTF-8 is required, so re-export the file as UTF-8), the record has more fields than the header, or the header repeats a column name; correct or replace the file, since the read stays blocked on it until then"),
                ordinal,
            )
        }
        SftpReadFault::KeyMissing(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_KEY_MISSING_CODE,
                format!("the decoder found no declared business key on record {ordinal} of the SFTP file; check keyPointer against the file's columns"),
                ordinal,
            )
        }
        SftpReadFault::KeyInvalid(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_KEY_INVALID_CODE,
                format!("the decoder refused the declared business key on record {ordinal} of the SFTP file; the key must be a non-empty string within the key bound"),
                ordinal,
            )
        }
        SftpReadFault::KeyDuplicate(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_KEY_DUPLICATE_CODE,
                format!("the decoder found record {ordinal} of the SFTP file repeats an earlier business key; keys must be unique within one file"),
                ordinal,
            )
        }
        _ => {}
    }
    let (class, code, message) = match fault {
        SftpReadFault::Timeout => (
            ErrorClass::UpstreamTimeout,
            READ_TIMEOUT_CODE,
            "the SFTP operation deadline passed; check the server's latency or raise the step's timeoutMilliseconds",
        ),
        SftpReadFault::Connection | SftpReadFault::Close => (
            ErrorClass::UpstreamConnection,
            SFTP_CONNECTION_CODE,
            "the SFTP connection failed; check host and port, and that the server accepts connections from this host",
        ),
        SftpReadFault::Negotiation => (
            ErrorClass::UpstreamConnection,
            SFTP_CONNECTION_CODE,
            "the SFTP server offers no key exchange, cipher or host-key algorithm this host accepts; the host accepts curve25519-sha256, ecdh-sha2-nistp256 and ecdh-sha2-nistp384 key exchange, AES-GCM and AES-CTR ciphers with hmac-sha2-256-etm or hmac-sha2-512-etm, and an Ed25519 or ECDSA P-256 host key matching pinnedHostKey; enable one of them on the server",
        ),
        SftpReadFault::HostKey => (
            ErrorClass::EgressRefused,
            SFTP_HOST_KEY_CODE,
            "the SFTP server's key does not match pinnedHostKey; verify the server's key out of band before updating the pin, since a changed key can mean an interception",
        ),
        SftpReadFault::Credential => (
            ErrorClass::EgressRefused,
            SFTP_CREDENTIAL_CODE,
            "the configured SFTP credential could not be loaded; check that its secret reference resolves to a valid password or OpenSSH private key",
        ),
        SftpReadFault::Authentication => (
            ErrorClass::EgressRefused,
            SFTP_AUTHENTICATION_CODE,
            "the SFTP server refused the user and credential; check user, rotate the password or key, and confirm the account is enabled",
        ),
        SftpReadFault::Listing | SftpReadFault::Incomplete | SftpReadFault::Malformed => (
            ErrorClass::UpstreamMalformed,
            SFTP_MALFORMED_CODE,
            "the SFTP source returned an incomplete or malformed read; check that the producer finished the file under its completion protocol, then rerun",
        ),
        SftpReadFault::Traversal | SftpReadFault::Escape | SftpReadFault::NotRegular => (
            ErrorClass::EgressRefused,
            SFTP_PATH_CODE,
            "the SFTP read refused a path outside its fixed regular-file boundary; place regular files, not links or directories, directly under baseDirectory",
        ),
        SftpReadFault::TooLarge => (
            ErrorClass::UpstreamTooLarge,
            READ_BOUND_CODE,
            "the SFTP file exceeded the profile's read.maximumFileBytes; raise it within the platform ceiling or split the file",
        ),
        SftpReadFault::ListingTooLarge => (
            ErrorClass::UpstreamTooLarge,
            READ_BOUND_CODE,
            "the SFTP listing exceeded the runtime's maximumListingEntries; raise it (at most 10000) or move processed files out of baseDirectory",
        ),
        SftpReadFault::RowBound => (
            ErrorClass::UpstreamTooLarge,
            READ_BOUND_CODE,
            "the SFTP decoder refused a record or field over the profile's read bounds",
        ),
        SftpReadFault::Row(_)
        | SftpReadFault::KeyMissing(_)
        | SftpReadFault::KeyInvalid(_)
        | SftpReadFault::KeyDuplicate(_) => unreachable!("record faults returned above"),
        SftpReadFault::DecoderSyntax => (
            ErrorClass::EgressRefused,
            READ_BOUND_CODE,
            "the decoder configuration was refused",
        ),
    };
    read_refused(class, code, message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::JOB_ENGINE_CODES;

    fn code_of(failure: &RouteFailure) -> &'static str {
        failure
            .code
            .expect("a read refusal carries its closed code")
    }

    /// Each operator-actionable read fault names its own closed code, so
    /// a pinned-key mismatch, a refused password and a differing queue
    /// declaration are told apart without reading a message.
    #[cfg(feature = "job-sftp")]
    #[test]
    fn sftp_faults_name_the_condition_the_operator_fixes() {
        let cases = [
            (SftpReadFault::Timeout, "adapter.job.read-timeout"),
            (SftpReadFault::Connection, "adapter.job.sftp-connection"),
            (SftpReadFault::Close, "adapter.job.sftp-connection"),
            (SftpReadFault::Negotiation, "adapter.job.sftp-connection"),
            (SftpReadFault::HostKey, "adapter.job.sftp-host-key"),
            (SftpReadFault::Credential, "adapter.job.sftp-credential"),
            (
                SftpReadFault::Authentication,
                "adapter.job.sftp-authentication",
            ),
            (SftpReadFault::Listing, "adapter.job.sftp-malformed"),
            (SftpReadFault::Incomplete, "adapter.job.sftp-malformed"),
            (SftpReadFault::Malformed, "adapter.job.sftp-malformed"),
            (SftpReadFault::Traversal, "adapter.job.sftp-path"),
            (SftpReadFault::Escape, "adapter.job.sftp-path"),
            (SftpReadFault::NotRegular, "adapter.job.sftp-path"),
            (SftpReadFault::TooLarge, "adapter.job.read-bound"),
            (SftpReadFault::RowBound, "adapter.job.read-bound"),
            (SftpReadFault::Row(0), "adapter.job.decoder-row"),
        ];
        for (fault, code) in cases {
            let failure = sftp_read_fault(fault);
            assert_eq!(code_of(&failure), code, "{fault:?}");
            assert!(JOB_ENGINE_CODES.contains(&code), "{code} is registered");
        }
    }

    #[cfg(feature = "job-rabbitmq")]
    #[test]
    fn rabbitmq_faults_name_the_condition_the_operator_fixes() {
        let cases = [
            (RabbitMqReadFault::Timeout, "adapter.job.read-timeout"),
            (RabbitMqReadFault::Oversized, "adapter.job.read-bound"),
            (RabbitMqReadFault::InvalidBounds, "adapter.job.read-bound"),
            (RabbitMqReadFault::Topology, "adapter.job.rabbitmq-topology"),
            (
                RabbitMqReadFault::MissingQueue,
                "adapter.job.rabbitmq-topology",
            ),
            (
                RabbitMqReadFault::MissingDeadLetterExchange,
                "adapter.job.rabbitmq-topology",
            ),
            (
                RabbitMqReadFault::Unavailable,
                "adapter.job.rabbitmq-unavailable",
            ),
            (
                RabbitMqReadFault::NonPersistent,
                RABBITMQ_DELIVERY_MODE_CODE,
            ),
        ];
        for (fault, code) in cases {
            let failure = rabbitmq_read_fault(fault);
            assert_eq!(code_of(&failure), code, "{fault:?}");
            assert!(JOB_ENGINE_CODES.contains(&code), "{code} is registered");
        }
    }

    #[cfg(feature = "job-file")]
    #[test]
    fn a_file_read_lock_timeout_is_a_timeout_not_a_bound() {
        let failure = read_fault(FileReadFault::LockTimeout);
        assert_eq!(code_of(&failure), "adapter.job.read-timeout");
        assert_eq!(failure.class, ErrorClass::UpstreamTimeout);
    }

    /// A refused record names its number, the UTF-8 requirement and the
    /// fix, so an operator can find the row and know the file blocks the
    /// folder until it is replaced.
    #[cfg(feature = "job-file")]
    #[test]
    fn a_malformed_file_record_names_its_number_and_the_utf8_requirement() {
        let failure = read_fault(FileReadFault::Row(7));
        let message = failure.message.expect("a message");
        assert!(message.contains("record 7"), "{message}");
        assert!(message.contains("UTF-8 is required"), "{message}");
        assert!(message.contains("replace the file"), "{message}");
        assert_eq!(failure.record.expect("the locator").ordinal, 7);
    }

    #[cfg(feature = "job-file")]
    #[test]
    fn a_refused_file_name_names_the_include_fix() {
        for fault in [FileReadFault::Traversal, FileReadFault::NameUnreadable] {
            let message = read_fault(fault).message.expect("a message");
            assert!(message.contains("`include`"), "{message}");
            assert!(message.contains("rename"), "{message}");
        }
    }

    #[cfg(feature = "job-file")]
    #[test]
    fn an_abandoned_file_decode_is_a_timeout_that_names_the_poll_deadline() {
        let failure = read_fault(FileReadFault::DecodeTimeout);
        assert_eq!(code_of(&failure), "adapter.job.read-timeout");
        assert_eq!(failure.class, ErrorClass::UpstreamTimeout);
        let message = failure.message.expect("a message");
        assert!(message.contains("timeoutMilliseconds"), "{message}");
        assert!(!message.contains("lock"), "{message}");
    }

    #[cfg(feature = "job-sftp")]
    #[test]
    fn an_sftp_bound_fault_names_the_field_that_was_hit() {
        let file = sftp_read_fault(SftpReadFault::TooLarge)
            .message
            .expect("a message");
        assert!(file.contains("read.maximumFileBytes"), "{file}");
        let listing = sftp_read_fault(SftpReadFault::ListingTooLarge)
            .message
            .expect("a message");
        assert!(listing.contains("maximumListingEntries"), "{listing}");
        assert_eq!(
            code_of(&sftp_read_fault(SftpReadFault::ListingTooLarge)),
            "adapter.job.read-bound"
        );
    }

    #[test]
    fn a_read_deadline_is_a_timeout_not_a_bound() {
        assert_eq!(code_of(&read_timeout()), "adapter.job.read-timeout");
        assert!(JOB_ENGINE_CODES.contains(&"adapter.job.read-timeout"));
    }

    #[cfg(feature = "job-postgres")]
    #[test]
    fn postgres_row_codes_are_registered() {
        for code in [
            crate::component::postgres::POSTGRES_COLUMN_TYPE_CODE,
            crate::component::postgres::POSTGRES_KEY_NULL_CODE,
        ] {
            assert!(JOB_ENGINE_CODES.contains(&code), "{code} is registered");
        }
    }
}

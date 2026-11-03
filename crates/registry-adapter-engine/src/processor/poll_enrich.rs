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
use registry_adapter_core::{
    AggregationStrategy, ErrorClass, PollEnrichStep, RecordLocator, SendComponent, SendUri,
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
const DECODER_ROW_CODE: &str = "adapter.job.decoder-row";
const DECODER_KEY_MISSING_CODE: &str = "adapter.job.decoder-key-missing";
const DECODER_KEY_INVALID_CODE: &str = "adapter.job.decoder-key-invalid";
const DECODER_KEY_DUPLICATE_CODE: &str = "adapter.job.decoder-key-duplicate";
#[cfg(feature = "job-rabbitmq")]
const RABBITMQ_DELIVERY_MODE_CODE: &str = "adapter.job.rabbitmq-delivery-mode";

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
                    read_page(source, &bounds, cursor.as_ref(), &decoder),
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
                    usize::try_from(bounds.maximum_row_bytes).map_err(|_| read_bound())?;
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
                    bounds.maximum_field_bytes as usize,
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
            READ_BOUND_CODE,
            "the RabbitMQ read deadline passed",
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
            READ_BOUND_CODE,
            "the RabbitMQ source and dead-letter topology was refused",
        ),
        RabbitMqReadFault::Unavailable => (
            ErrorClass::UpstreamConnection,
            READ_BOUND_CODE,
            "the RabbitMQ source was unavailable",
        ),
    };
    read_refused(class, code, message.to_owned())
}

#[cfg(feature = "job-rabbitmq")]
fn rabbitmq_settlement_fault(_fault: RabbitMqSettlementFault) -> RouteFailure {
    read_refused(
        ErrorClass::UpstreamConnection,
        READ_BOUND_CODE,
        "the RabbitMQ poison delivery settlement was uncertain".to_owned(),
    )
}

fn read_timeout() -> RouteFailure {
    read_refused(
        ErrorClass::UpstreamTimeout,
        READ_BOUND_CODE,
        "the pollEnrich read did not finish inside its timeoutMilliseconds".to_owned(),
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

fn record_refused(
    class: ErrorClass,
    code: &'static str,
    message: &'static str,
    ordinal: u64,
) -> RouteFailure {
    let mut failure = read_refused(class, code, message.to_owned());
    failure.record = Some(Box::new(RecordLocator { ordinal }));
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
                "the decoder refused a malformed file record",
                ordinal,
            )
        }
        FileReadFault::KeyMissing(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_KEY_MISSING_CODE,
                "the decoder found no declared business key on a file record",
                ordinal,
            )
        }
        FileReadFault::KeyInvalid(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_KEY_INVALID_CODE,
                "the decoder refused a file record's declared business key",
                ordinal,
            )
        }
        FileReadFault::KeyDuplicate(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_KEY_DUPLICATE_CODE,
                "the decoder found a duplicate business key in one file",
                ordinal,
            )
        }
        _ => {}
    }
    let (class, message): (ErrorClass, String) = match fault {
        FileReadFault::Traversal => (
            ErrorClass::EgressRefused,
            "the read refused a candidate name that leaves the source directory".to_owned(),
        ),
        FileReadFault::NameUnreadable => (
            ErrorClass::EgressRefused,
            "the read refused a candidate name the engine cannot carry".to_owned(),
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
            "the changed read lock did not settle inside its timeout".to_owned(),
        ),
    };
    let code = match class {
        ErrorClass::UpstreamMalformed => DECODER_ROW_CODE,
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
                "the decoder refused a malformed SFTP record",
                ordinal,
            )
        }
        SftpReadFault::KeyMissing(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_KEY_MISSING_CODE,
                "the decoder found no declared business key on an SFTP record",
                ordinal,
            )
        }
        SftpReadFault::KeyInvalid(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_KEY_INVALID_CODE,
                "the decoder refused an SFTP record's declared business key",
                ordinal,
            )
        }
        SftpReadFault::KeyDuplicate(ordinal) => {
            return record_refused(
                ErrorClass::UpstreamMalformed,
                DECODER_KEY_DUPLICATE_CODE,
                "the decoder found a duplicate business key in one SFTP file",
                ordinal,
            )
        }
        _ => {}
    }
    let (class, message) = match fault {
        SftpReadFault::Timeout => (
            ErrorClass::UpstreamTimeout,
            "the SFTP operation deadline passed",
        ),
        SftpReadFault::Connection | SftpReadFault::Close => {
            (ErrorClass::UpstreamConnection, "the SFTP connection failed")
        }
        SftpReadFault::HostKey | SftpReadFault::Credential | SftpReadFault::Authentication => (
            ErrorClass::EgressRefused,
            "the SFTP trust or credential boundary refused the connection",
        ),
        SftpReadFault::Listing | SftpReadFault::Incomplete | SftpReadFault::Malformed => (
            ErrorClass::UpstreamMalformed,
            "the SFTP source returned an incomplete or malformed read",
        ),
        SftpReadFault::Traversal | SftpReadFault::Escape | SftpReadFault::NotRegular => (
            ErrorClass::EgressRefused,
            "the SFTP read refused a path outside its fixed regular-file boundary",
        ),
        SftpReadFault::TooLarge | SftpReadFault::RowBound => (
            ErrorClass::UpstreamTooLarge,
            "the SFTP read exceeded a configured bound",
        ),
        SftpReadFault::Row(_)
        | SftpReadFault::KeyMissing(_)
        | SftpReadFault::KeyInvalid(_)
        | SftpReadFault::KeyDuplicate(_) => unreachable!("record faults returned above"),
        SftpReadFault::DecoderSyntax => (
            ErrorClass::EgressRefused,
            "the decoder configuration was refused",
        ),
    };
    read_refused(class, READ_BOUND_CODE, message.to_owned())
}

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

use registry_adapter_core::{
    AggregationStrategy, ErrorClass, PollDecoder, PollEnrichStep, SendComponent, SendUri,
};
use serde_json::json;

use crate::engine::component::file::{read_page, FileReadFault};
use crate::engine::decoder::Decoder;
use crate::engine::job::{ADAPTER_JOB_CURSOR_PROPERTY, JOB_PAGE_DECODE_FAULTS_EVENT};
use crate::engine::processor::aggregation;
use crate::engine::route::{Flow, RouteFailure, Run};

/// The closed code a read refusal carries, value-free.
const READ_BOUND_CODE: &str = "adapter.job.read-bound";
const DECODER_ROW_CODE: &str = "adapter.job.decoder-row";

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
    if uri.component != SendComponent::File {
        return Err(read_refused(
            ErrorClass::EgressRefused,
            READ_BOUND_CODE,
            "a pollEnrich step is served over a file endpoint only".to_owned(),
        ));
    }
    let Some(timeout) = poll.timeout_milliseconds else {
        return Err(read_refused(
            ErrorClass::EgressRefused,
            READ_BOUND_CODE,
            "the pollEnrich step declares no timeoutMilliseconds".to_owned(),
        ));
    };
    let decoder = match poll.decoder.as_ref() {
        None => Decoder::Raw,
        Some(PollDecoder::Csv(options)) => Decoder::Csv(options.clone()),
        Some(PollDecoder::Named(name)) if name == "raw" => Decoder::Raw,
        Some(PollDecoder::Named(name)) if name == "csv" => Decoder::Csv(Default::default()),
        Some(PollDecoder::Named(name)) if name == "jsonl" => Decoder::Jsonl,
        Some(_) => {
            return Err(read_refused(
                ErrorClass::EgressRefused,
                READ_BOUND_CODE,
                "the pollEnrich names no decoder the engine carries".to_owned(),
            ))
        }
    };
    let source = run.context.job.files.get(uri.id.as_str()).ok_or_else(|| {
        read_refused(
            ErrorClass::EgressRefused,
            READ_BOUND_CODE,
            "the pollEnrich names an endpoint this build carries no file source for".to_owned(),
        )
    })?;
    let bounds = run
        .context
        .job
        .profile
        .as_ref()
        .map(|profile| profile.read.clone())
        .unwrap_or_else(crate::engine::job_sources::unused_read_bounds);
    let cursor = run.exchange.property(ADAPTER_JOB_CURSOR_PROPERTY).cloned();
    run.ensure_deadline()?;
    let remaining = run
        .deadline
        .saturating_duration_since(tokio::time::Instant::now());
    let read_deadline = Duration::from_millis(timeout.get()).min(remaining);
    let read = tokio::time::timeout(
        read_deadline,
        read_page(source, &bounds, cursor.as_ref(), &decoder),
    )
    .await;
    let page = match read {
        Err(_elapsed) => {
            return Err(read_refused(
                ErrorClass::UpstreamTimeout,
                READ_BOUND_CODE,
                "the pollEnrich read did not finish inside its timeoutMilliseconds".to_owned(),
            ))
        }
        Ok(Err(fault)) => return Err(read_fault(fault)),
        Ok(Ok(page)) => page,
    };
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

/// One read refusal as a route failure: the class the hierarchy carries
/// and the closed engine-read code the job entry reports beside it.
fn read_refused(class: ErrorClass, code: &'static str, message: String) -> RouteFailure {
    RouteFailure {
        class,
        message: Some(message),
        data: None,
        auth: None,
        code: Some(code),
    }
}

/// One file read fault as a route failure.
fn read_fault(fault: FileReadFault) -> RouteFailure {
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
        FileReadFault::Row(index) => (
            ErrorClass::UpstreamMalformed,
            // The record's index is the one value a decoder refusal
            // names; never the record's content.
            format!("the decoder refused record {index} of the file"),
        ),
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

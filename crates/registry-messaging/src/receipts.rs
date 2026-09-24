// SPDX-License-Identifier: Apache-2.0

//! Delivery receipts: a verified provider callback's receipt applied to the
//! stored message it names (spec 6.2 and 7.4).
//!
//! A receipt names its message by the reference the provider answered when
//! it accepted an attempt, scoped to that provider: the same reference from
//! another provider names nothing. Everything a receipt changes is decided
//! in one transaction, under the message row's lock:
//!
//! - the report moves only as [`advance_report`] allows, so a duplicate or
//!   out-of-order receipt never regresses it, and a final report is never
//!   replaced;
//! - the receipt joins the message's bounded history unless the same report
//!   and code are already there or the history is full, so a provider
//!   repeating itself cannot grow the store;
//! - a receipt that changed either is audited through the outbox in the same
//!   transaction, by identifiers, the report, and the provider's code only.
//!   The reference, the recipient, the parts, and the callback's body never
//!   reach the record.
//!
//! A reference that names no message, or more than one, changes nothing and
//! journals nothing; the route counts it and answers the provider as
//! received, since refusing it would only make the provider retry.

use registry_messaging_core::{advance_report, DeliveryReport, Receipt, ReportAdvance};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::messages::MessageStoreError;
use crate::outbox;
use crate::store::PostgresStore;

/// The audited event for a receipt that changed a message's report or
/// history.
pub const RECEIPT_RECORDED_EVENT: &str = "messaging.receipt.recorded";

/// How many distinct receipts one message keeps at most.
pub const MAXIMUM_STORED_RECEIPTS: i64 = 16;

/// The longest provider reference an attempt stores, so the longest a
/// receipt can match.
const MAXIMUM_STORED_REFERENCE_BYTES: usize = 128;

/// What applying one receipt did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptOutcome {
    /// The receipt advanced the message's report to `report`.
    Applied {
        message_id: Uuid,
        report: DeliveryReport,
    },
    /// The receipt matched a message and left its report as it was.
    Unchanged { message_id: Uuid },
    /// No message of this provider carries the reference.
    Unmatched,
    /// More than one message of this provider carries the reference.
    Ambiguous,
}

/// Apply `receipt` from `provider` to the message it names.
///
/// # Errors
///
/// The store's error when it cannot answer, and
/// [`MessageStoreError::Refused`] when the audit record cannot be written.
pub async fn record_receipt(
    store: &PostgresStore,
    provider: &str,
    receipt: &Receipt,
) -> Result<ReceiptOutcome, MessageStoreError> {
    if receipt.provider_reference.is_empty()
        || receipt.provider_reference.len() > MAXIMUM_STORED_REFERENCE_BYTES
    {
        return Ok(ReceiptOutcome::Unmatched);
    }
    let mut client = store.client().await?;
    let transaction = client.transaction().await?;
    let matches = transaction
        .query(
            "SELECT DISTINCT attempt.message_id \
               FROM messaging_attempts AS attempt \
               JOIN messaging_messages AS message ON message.message_id = attempt.message_id \
              WHERE message.provider = $1 AND attempt.provider_reference = $2 \
              LIMIT 2",
            &[&provider, &receipt.provider_reference],
        )
        .await?;
    let message_id: Uuid = match matches.as_slice() {
        [] => {
            transaction.commit().await?;
            return Ok(ReceiptOutcome::Unmatched);
        }
        [row] => row.try_get(0)?,
        _ => {
            transaction.commit().await?;
            return Ok(ReceiptOutcome::Ambiguous);
        }
    };
    let current: Option<String> = transaction
        .query_one(
            "SELECT report FROM messaging_messages WHERE message_id = $1 FOR UPDATE",
            &[&message_id],
        )
        .await?
        .try_get(0)?;
    let current = match current.as_deref() {
        None => None,
        Some(stored) => Some(DeliveryReport::parse(stored).ok_or(MessageStoreError::Refused)?),
    };
    let advanced = match advance_report(current, receipt.report) {
        ReportAdvance::Advance(report) => Some(report),
        ReportAdvance::NoChange => None,
    };
    let stored = transaction
        .execute(
            "INSERT INTO messaging_receipts \
                    (message_id, sequence, received_at, report, code, applied) \
             SELECT $1, (count(*) + 1)::smallint, transaction_timestamp(), $2, $3, $4 \
               FROM messaging_receipts WHERE message_id = $1 \
             HAVING count(*) < $5 \
             ON CONFLICT DO NOTHING",
            &[
                &message_id,
                &receipt.report.as_str(),
                &receipt.code,
                &advanced.is_some(),
                &MAXIMUM_STORED_RECEIPTS,
            ],
        )
        .await?
        == 1;
    if let Some(report) = advanced {
        let changed = transaction
            .execute(
                "UPDATE messaging_messages \
                    SET report = $2, report_at = transaction_timestamp() \
                  WHERE message_id = $1",
                &[&message_id, &report.as_str()],
            )
            .await?;
        if changed != 1 {
            return Err(MessageStoreError::Refused);
        }
    }
    if stored || advanced.is_some() {
        outbox::write(
            &transaction,
            json!({
                "event": RECEIPT_RECORDED_EVENT,
                "messageId": message_id.to_string(),
                "provider": provider,
                "report": receipt.report.as_str(),
                "code": receipt.code,
                "applied": advanced.is_some(),
                "from": current.map_or(Value::Null, |report| Value::from(report.as_str())),
                "disposition": advanced.or(current).map(DeliveryReport::as_str),
            }),
        )
        .await?;
    }
    transaction.commit().await?;
    Ok(match advanced {
        Some(report) => ReceiptOutcome::Applied { message_id, report },
        None => ReceiptOutcome::Unchanged { message_id },
    })
}

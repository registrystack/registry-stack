// SPDX-License-Identifier: Apache-2.0

//! HTTP wire documents the runtime and every client share.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::content::DirectContent;
use crate::naming::{MAXIMUM_CORRELATION_ID_BYTES, MESSAGES_PATH};
use crate::package::{valid_e164, valid_email_sender, Channel, TemplateReference};
use crate::problem::{type_uri, ProblemCode};
use crate::receipt::DeliveryReport;

/// Where one message goes: exactly one email address or one E.164 phone
/// number, written `{"email": ...}` or `{"phone": ...}`.
///
/// Its `Debug` never prints the contact, so a recipient that reaches a log
/// through a derived `Debug` names only its kind.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum Recipient {
    Email(String),
    Phone(String),
}

impl Recipient {
    /// The channel that can carry this recipient.
    #[must_use]
    pub const fn channel(&self) -> Channel {
        match self {
            Self::Email(_) => Channel::Email,
            Self::Phone(_) => Channel::Sms,
        }
    }

    /// The contact itself. Callers hand it only to a transport and to the
    /// payload store, never to a log, an audit record, or a response.
    #[must_use]
    pub fn contact(&self) -> &str {
        match self {
            Self::Email(value) | Self::Phone(value) => value,
        }
    }

    /// Whether the contact is well formed for its kind: one address for
    /// email, E.164 for a phone. No carrier or region lookup is made.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        match self {
            Self::Email(address) => valid_email_sender(address),
            Self::Phone(number) => valid_e164(number),
        }
    }

    /// The stored kind: `email` or `phone`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Email(_) => "email",
            Self::Phone(_) => "phone",
        }
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Recipient")
            .field(&self.kind())
            .finish()
    }
}

/// The body of `POST /v1/messages`. Exactly one of `template` or `content`
/// is present; `locale` and `data` accompany a template and nothing else.
/// Instants are RFC 3339 strings the runtime parses.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubmitMessageRequest {
    pub sender_profile: String,
    pub to: Recipient,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<TemplateReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<DirectContent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

impl fmt::Debug for SubmitMessageRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubmitMessageRequest")
            .field("sender_profile", &self.sender_profile)
            .field("to", &self.to)
            .field("template", &self.template)
            .finish_non_exhaustive()
    }
}

/// How a submission selects its content, once its shape was checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionContent<'a> {
    Template {
        template: &'a TemplateReference,
        locale: &'a str,
        data: &'a Value,
    },
    Direct(&'a DirectContent),
}

impl SubmitMessageRequest {
    /// Check the shape the schema cannot: exactly one content source, the
    /// template's locale and data only beside a template, a well-formed
    /// recipient, and a bounded correlation identifier. Every refusal is
    /// `request.unprocessable`, so no member's value is echoed.
    pub fn content(&self) -> Result<SubmissionContent<'_>, ProblemCode> {
        if !self.to.is_well_formed()
            || self.correlation_id.as_ref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > MAXIMUM_CORRELATION_ID_BYTES
                    || value.chars().any(char::is_control)
            })
        {
            return Err(ProblemCode::RequestUnprocessable);
        }
        match (&self.template, &self.content) {
            (Some(template), None) => match (&self.locale, &self.data) {
                (Some(locale), Some(data)) => Ok(SubmissionContent::Template {
                    template,
                    locale,
                    data,
                }),
                _ => Err(ProblemCode::RequestUnprocessable),
            },
            (None, Some(content)) if self.locale.is_none() && self.data.is_none() => {
                Ok(SubmissionContent::Direct(content))
            }
            _ => Err(ProblemCode::RequestUnprocessable),
        }
    }
}

/// The public status of one message, derived from its dispatch state and
/// its delivery report by [`derive_status`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MessageStatus {
    Queued,
    Sending,
    Submitted,
    Delivered,
    Failed,
    Expired,
    Cancelled,
    Unknown,
}

impl MessageStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sending => "sending",
            Self::Submitted => "submitted",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }
}

/// What the dispatch worker did with one message (spec 6.2). `submitted`
/// means the provider accepted the message, never that it was delivered.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MessageDispatch {
    Queued,
    Sending,
    Submitted,
    Failed,
    Unknown,
    Cancelled,
    Expired,
}

impl MessageDispatch {
    /// Every dispatch state.
    pub const ALL: [Self; 7] = [
        Self::Queued,
        Self::Sending,
        Self::Submitted,
        Self::Failed,
        Self::Unknown,
        Self::Cancelled,
        Self::Expired,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sending => "sending",
            Self::Submitted => "submitted",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    /// The public status of a message in this dispatch state that no
    /// final delivery report has settled.
    #[must_use]
    pub const fn status(self) -> MessageStatus {
        match self {
            Self::Queued => MessageStatus::Queued,
            Self::Sending => MessageStatus::Sending,
            Self::Submitted => MessageStatus::Submitted,
            Self::Failed => MessageStatus::Failed,
            Self::Unknown => MessageStatus::Unknown,
            Self::Cancelled => MessageStatus::Cancelled,
            Self::Expired => MessageStatus::Expired,
        }
    }
}

/// What delivery receipts said about a message (spec 6.2). The report moves
/// only forward, `none` then `sent` then `delivered` or `undelivered`, and a
/// final report is never replaced.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MessageReport {
    /// The message's provider records delivery receipts and none has
    /// reported on this message yet.
    None,
    /// The provider reports the message handed on towards the recipient.
    Sent,
    /// The provider reports the message delivered. Final.
    Delivered,
    /// The provider reports the message could not be delivered. Final.
    Undelivered,
    /// The runtime records no delivery receipts for this message's
    /// provider, so `submitted` is the last status it will report.
    Unavailable,
}

impl From<DeliveryReport> for MessageReport {
    fn from(report: DeliveryReport) -> Self {
        match report {
            DeliveryReport::Sent => Self::Sent,
            DeliveryReport::Delivered => Self::Delivered,
            DeliveryReport::Undelivered => Self::Undelivered,
        }
    }
}

/// The public status of a message (spec 6.2): its dispatch state, except
/// that a submitted message a final report settled is `delivered` or, when
/// the report is `undelivered`, `failed`. A report reaches only a message
/// its provider accepted, so no other dispatch state is ever settled by one.
#[must_use]
pub const fn derive_status(dispatch: MessageDispatch, report: MessageReport) -> MessageStatus {
    match (dispatch, report) {
        (MessageDispatch::Submitted, MessageReport::Delivered) => MessageStatus::Delivered,
        (MessageDispatch::Submitted, MessageReport::Undelivered) => MessageStatus::Failed,
        _ => dispatch.status(),
    }
}

/// The links a message answer carries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageLinks {
    #[serde(rename = "self")]
    pub self_link: String,
    pub cancel: String,
}

impl MessageLinks {
    #[must_use]
    pub fn for_message(id: &str) -> Self {
        Self {
            self_link: format!("{MESSAGES_PATH}/{id}"),
            cancel: format!("{MESSAGES_PATH}/{id}/cancel"),
        }
    }
}

/// The `202` answer to an accepted submission, and what a replayed key
/// answers again.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MessageReceipt {
    pub id: String,
    pub status: MessageStatus,
    pub links: MessageLinks,
}

/// How one attempt ended, without any provider text.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptOutcome {
    /// The attempt is still running.
    InProgress,
    Accepted,
    Transient,
    Permanent,
    MaybeSent,
    /// The worker stopped before it recorded an outcome.
    Interrupted,
}

/// One attempt, as the status answer summarizes it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptSummary {
    pub generation: i64,
    pub attempt: i16,
    pub outcome: AttemptOutcome,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    /// Whether the provider returned a reference. The reference itself is
    /// provider data and is not returned.
    pub provider_reference: bool,
}

/// The answer to `GET /v1/messages/{id}`: the derived status, the dispatch
/// state and delivery report it is derived from, metadata, a masked
/// recipient, and attempt summaries. The body and the template data are
/// never returned.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MessageView {
    pub id: String,
    /// [`derive_status`] of `dispatch` and `report`.
    pub status: MessageStatus,
    pub dispatch: MessageDispatch,
    pub report: MessageReport,
    /// When the stored report last moved. Absent while the report is `none`
    /// or `unavailable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_at: Option<String>,
    pub channel: Channel,
    pub sender_profile: String,
    /// The recipient's kind with its contact masked.
    pub to: Recipient,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<TemplateReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub accepted_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    pub expires_at: String,
    pub updated_at: String,
    pub attempts: Vec<AttemptSummary>,
    pub links: MessageLinks,
}

/// The problem document every refusal answers with, as a client reads it.
/// Field names match the Registry Stack problem envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProblemDocument {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub code: String,
    pub trace_id: String,
}

impl ProblemDocument {
    /// The closed-vocabulary code this document carries, when the document
    /// is exactly the one the runtime renders for that code: the type URI,
    /// title, detail, and status all match what the vocabulary pins.
    #[must_use]
    pub fn problem(&self) -> Option<ProblemCode> {
        let code = ProblemCode::from_code(&self.code)?;
        (self.type_uri == type_uri(code.code())
            && self.status == code.http_status()
            && self.title == code.title()
            && self.detail == code.detail())
        .then_some(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rendered(code: ProblemCode) -> serde_json::Value {
        json!({
            "type": type_uri(code.code()),
            "title": code.title(),
            "status": code.http_status(),
            "detail": code.detail(),
            "code": code.code(),
            "traceId": "0af7651916cd43dd8448eb211c80319c",
        })
    }

    #[test]
    fn a_pinned_problem_document_reads_back_as_its_code() {
        for code in ProblemCode::ALL {
            let document: ProblemDocument = serde_json::from_value(rendered(*code)).unwrap();
            assert_eq!(document.problem(), Some(*code));
        }
    }

    fn submission(value: serde_json::Value) -> Result<SubmitMessageRequest, serde_json::Error> {
        serde_json::from_value(value)
    }

    fn templated() -> serde_json::Value {
        json!({
            "senderProfile": "transactional",
            "to": {"email": "person@example.org"},
            "template": {"id": "appointment-reminder", "version": "1"},
            "locale": "en",
            "data": {"name": "Ada"},
            "correlationId": "case-847"
        })
    }

    #[test]
    fn a_submission_is_closed_and_selects_exactly_one_content_source() {
        let request = submission(templated()).unwrap();
        assert!(matches!(
            request.content(),
            Ok(SubmissionContent::Template { locale: "en", .. })
        ));
        for (member, value) in [
            ("channel", json!("email")),
            ("priority", json!("high")),
            ("sender", json!("other@example.org")),
        ] {
            let mut body = templated();
            body[member] = value;
            assert!(submission(body).is_err(), "{member}");
        }
        let mut body = templated();
        body["to"] = json!({"email": "a@example.org", "phone": "+15551234567"});
        assert!(submission(body).is_err());
        let mut body = templated();
        body["template"]["latest"] = json!(true);
        assert!(submission(body).is_err());

        let direct = submission(json!({
            "senderProfile": "transactional",
            "to": {"phone": "+15551234567"},
            "content": {"text": "Hello"}
        }))
        .unwrap();
        assert!(matches!(direct.content(), Ok(SubmissionContent::Direct(_))));

        for mutate in [
            |body: &mut serde_json::Value| body["content"] = json!({"text": "Hello"}),
            |body: &mut serde_json::Value| {
                body.as_object_mut().unwrap().remove("locale");
            },
            |body: &mut serde_json::Value| {
                body.as_object_mut().unwrap().remove("data");
            },
            |body: &mut serde_json::Value| {
                body.as_object_mut().unwrap().remove("template");
            },
            |body: &mut serde_json::Value| body["to"] = json!({"email": "not-an-address"}),
            |body: &mut serde_json::Value| body["to"] = json!({"phone": "5551234567"}),
            |body: &mut serde_json::Value| body["correlationId"] = json!("c".repeat(129)),
            |body: &mut serde_json::Value| body["correlationId"] = json!(""),
        ] {
            let mut body = templated();
            mutate(&mut body);
            assert_eq!(
                submission(body.clone()).unwrap().content().unwrap_err(),
                ProblemCode::RequestUnprocessable,
                "{body}"
            );
        }
    }

    #[test]
    fn a_recipient_never_prints_its_contact() {
        let request = submission(templated()).unwrap();
        let printed = format!("{request:?} {:?}", request.to);
        assert!(!printed.contains("person@example.org"), "{printed}");
        assert!(!printed.contains("Ada"), "{printed}");
        assert!(printed.contains("email"), "{printed}");
        assert_eq!(request.to.channel(), Channel::Email);
        assert_eq!(request.to.contact(), "person@example.org");
    }

    #[test]
    fn a_receipt_names_its_status_and_links() {
        let receipt = MessageReceipt {
            id: "0b5c".to_owned(),
            status: MessageStatus::Queued,
            links: MessageLinks::for_message("0b5c"),
        };
        assert_eq!(
            serde_json::to_value(&receipt).unwrap(),
            json!({
                "id": "0b5c",
                "status": "queued",
                "links": {"self": "/v1/messages/0b5c", "cancel": "/v1/messages/0b5c/cancel"}
            })
        );
        for (status, spelled) in [
            (MessageStatus::Queued, "queued"),
            (MessageStatus::Sending, "sending"),
            (MessageStatus::Submitted, "submitted"),
            (MessageStatus::Delivered, "delivered"),
            (MessageStatus::Failed, "failed"),
            (MessageStatus::Expired, "expired"),
            (MessageStatus::Cancelled, "cancelled"),
            (MessageStatus::Unknown, "unknown"),
        ] {
            assert_eq!(serde_json::to_value(status).unwrap(), json!(spelled));
            assert_eq!(status.as_str(), spelled);
        }
        assert_eq!(
            serde_json::to_value(AttemptOutcome::MaybeSent).unwrap(),
            json!("maybe-sent")
        );
    }

    #[test]
    fn the_dispatch_state_and_the_report_are_spelled_as_the_specification_names_them() {
        for (dispatch, spelled) in [
            (MessageDispatch::Queued, "queued"),
            (MessageDispatch::Sending, "sending"),
            (MessageDispatch::Submitted, "submitted"),
            (MessageDispatch::Failed, "failed"),
            (MessageDispatch::Unknown, "unknown"),
            (MessageDispatch::Cancelled, "cancelled"),
            (MessageDispatch::Expired, "expired"),
        ] {
            assert_eq!(serde_json::to_value(dispatch).unwrap(), json!(spelled));
            assert_eq!(dispatch.as_str(), spelled);
        }
        assert_eq!(MessageDispatch::ALL.len(), 7);
        for (report, spelled) in [
            (MessageReport::None, "none"),
            (MessageReport::Sent, "sent"),
            (MessageReport::Delivered, "delivered"),
            (MessageReport::Undelivered, "undelivered"),
            (MessageReport::Unavailable, "unavailable"),
        ] {
            assert_eq!(serde_json::to_value(report).unwrap(), json!(spelled));
        }
        for (stored, served) in [
            (DeliveryReport::Sent, MessageReport::Sent),
            (DeliveryReport::Delivered, MessageReport::Delivered),
            (DeliveryReport::Undelivered, MessageReport::Undelivered),
        ] {
            assert_eq!(MessageReport::from(stored), served);
        }
    }

    #[test]
    fn the_status_is_the_dispatch_state_until_a_final_report_settles_a_submitted_message() {
        for dispatch in MessageDispatch::ALL {
            for report in [
                MessageReport::None,
                MessageReport::Sent,
                MessageReport::Unavailable,
            ] {
                assert_eq!(
                    derive_status(dispatch, report),
                    dispatch.status(),
                    "{dispatch:?} {report:?}"
                );
            }
        }
        assert_eq!(
            MessageDispatch::Submitted.status(),
            MessageStatus::Submitted
        );
        assert_eq!(
            derive_status(MessageDispatch::Submitted, MessageReport::Delivered),
            MessageStatus::Delivered
        );
        assert_eq!(
            derive_status(MessageDispatch::Submitted, MessageReport::Undelivered),
            MessageStatus::Failed
        );
        // A report reaches only a submitted message; anywhere else the
        // dispatch state stands.
        for dispatch in MessageDispatch::ALL
            .into_iter()
            .filter(|dispatch| *dispatch != MessageDispatch::Submitted)
        {
            for report in [MessageReport::Delivered, MessageReport::Undelivered] {
                assert_eq!(derive_status(dispatch, report), dispatch.status());
            }
        }
    }

    #[test]
    fn a_message_view_serves_the_derived_status_the_dispatch_state_and_the_report() {
        let view = MessageView {
            id: "0b5c".to_owned(),
            status: MessageStatus::Delivered,
            dispatch: MessageDispatch::Submitted,
            report: MessageReport::Delivered,
            reported_at: Some("2026-09-25T10:00:05Z".to_owned()),
            channel: Channel::Sms,
            sender_profile: "sms-default".to_owned(),
            to: Recipient::Phone("***".to_owned()),
            template: None,
            correlation_id: None,
            accepted_at: "2026-09-25T10:00:00Z".to_owned(),
            not_before: None,
            expires_at: "2026-09-26T10:00:00Z".to_owned(),
            updated_at: "2026-09-25T10:00:01Z".to_owned(),
            attempts: Vec::new(),
            links: MessageLinks::for_message("0b5c"),
        };
        let value = serde_json::to_value(&view).unwrap();
        assert_eq!(value["status"], json!("delivered"));
        assert_eq!(value["dispatch"], json!("submitted"));
        assert_eq!(value["report"], json!("delivered"));
        assert_eq!(value["reportedAt"], json!("2026-09-25T10:00:05Z"));
        assert_eq!(serde_json::from_value::<MessageView>(value).unwrap(), view);

        let unreported = MessageView {
            reported_at: None,
            report: MessageReport::Unavailable,
            ..view
        };
        let value = serde_json::to_value(&unreported).unwrap();
        assert!(value.get("reportedAt").is_none(), "{value}");
    }

    #[test]
    fn a_document_that_disagrees_with_the_vocabulary_is_not_trusted() {
        let mut value = rendered(ProblemCode::MessageNotVisible);
        value["status"] = json!(403);
        let document: ProblemDocument = serde_json::from_value(value).unwrap();
        assert_eq!(document.problem(), None);

        let mut value = rendered(ProblemCode::MessageNotVisible);
        value["code"] = json!("message.unknown");
        let document: ProblemDocument = serde_json::from_value(value).unwrap();
        assert_eq!(document.problem(), None);
    }
}

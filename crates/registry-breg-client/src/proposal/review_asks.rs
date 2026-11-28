// SPDX-License-Identifier: Apache-2.0
//! Live answers are intrinsic review context, outside the authored field schema.
use super::*;

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalReviewAsk {
    pub id: String,
    pub text: String,
    pub wants: Vec<BRegProposalAskWant>,
    pub asked_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_at: Option<String>,
    pub state: BRegProposalAskState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<BRegProposalReviewAnswer>,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalReviewAnswer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub documents: Vec<BRegProposalReviewAnswerDocument>,
    pub answered_at: String,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalReviewAnswerDocument {
    pub id: String,
    pub sha256: String,
    pub content_type: String,
    pub byte_size: u64,
    pub verification_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<BRegProposalReviewAnswerDownload>,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalReviewAnswerDownload {
    pub method: String,
    pub operation: String,
    pub access_profile: String,
    pub path: String,
}
impl fmt::Debug for BRegProposalReviewAsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BRegProposalReviewAsk(<redacted>)")
    }
}
impl fmt::Debug for BRegProposalReviewAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BRegProposalReviewAnswer(<redacted>)")
    }
}

pub(super) fn valid(document: &BRegProposalReviewDocument) -> bool {
    let mut ids = std::collections::BTreeSet::new();
    for ask in &document.context.asks {
        let Some(asked) = proposal_instant(&ask.asked_at) else {
            return false;
        };
        if !canonical_proposal_id(&ask.id)
            || !ids.insert(&ask.id)
            || registry_review_protocol::check_public_reason(&ask.text).is_err()
            || ask.wants.len() > 8
            || ask
                .wants
                .iter()
                .enumerate()
                .any(|(i, w)| ask.wants[..i].contains(w))
            || ask
                .due_at
                .as_deref()
                .is_some_and(|due| proposal_instant(due).is_none_or(|due| due <= asked))
        {
            return false;
        }
        if let Some(answer) = &ask.answer {
            let Some(at) = proposal_instant(&answer.answered_at) else {
                return false;
            };
            if ask.state != BRegProposalAskState::Answered
                || at < asked
                || !at.nanosecond().is_multiple_of(1000)
                || answer.text.as_deref().is_some_and(|text| {
                    text.trim().is_empty() || text.len() > 2000 || text.contains('\0')
                })
                || (answer.text.is_none() && ask.wants.contains(&BRegProposalAskWant::Answer {}))
                || answer.documents.len() > 32
                || (answer.documents.is_empty()
                    && ask.wants.contains(&BRegProposalAskWant::Document {}))
            {
                return false;
            }
            let mut files = std::collections::BTreeSet::new();
            for file in &answer.documents {
                if !canonical_proposal_id(&file.id)
                    || !files.insert(&file.id)
                    || !digest(&format!("sha256:{}", file.sha256))
                    || !crate::attachment::valid_attachment_content_type(&file.content_type)
                    || !(1..=MAX_BREG_ATTACHMENT_BYTES).contains(&file.byte_size)
                    || !matches!(
                        file.verification_status.as_str(),
                        "notRequired" | "approved" | "pending" | "rejected"
                    )
                {
                    return false;
                }
                if let Some(link) = &file.download {
                    let Some(contract) = &document.context.contract else {
                        return false;
                    };
                    let path=format!("/v1/proposals/{}/additions/{}?submissionVersion={}&reviewAskId={}&effectDigest={}&contextSchemaDigest={}",document.id,file.id,document.submission_version,ask.id,document.effect_digest.replace(':',"%3A"),contract.schema_digest.replace(':',"%3A"));
                    if link.method != "GET"
                        || link.operation != "get-review-context"
                        || !identifier(&link.access_profile)
                        || link.path != path
                        || !matches!(
                            file.verification_status.as_str(),
                            "notRequired" | "approved"
                        )
                    {
                        return false;
                    }
                }
            }
        }
    }
    document.context.asks.is_empty() || document.authority.is_some()
}
pub(super) fn profiles(document: &BRegProposalReviewDocument, profile: &str) -> bool {
    document
        .context
        .asks
        .iter()
        .filter_map(|ask| ask.answer.as_ref())
        .flat_map(|answer| &answer.documents)
        .filter_map(|file| file.download.as_ref())
        .all(|link| link.access_profile == profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cited_documents_require_the_verification_status_that_the_server_schema_promises() {
        let file = serde_json::json!({"id":"00000000-0000-4000-8000-000000000001","sha256":"a".repeat(64),"contentType":"text/plain","byteSize":1});
        assert!(serde_json::from_value::<BRegProposalReviewAnswerDocument>(file).is_err());
    }
}

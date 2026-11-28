// SPDX-License-Identifier: Apache-2.0
//! Applicant-visible asks and explicitly selected answer commands.
use super::*;
pub use registry_review_protocol::{
    ReviewAskState as BRegProposalAskState, ReviewAskWant as BRegProposalAskWant,
};

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalAsk {
    pub id: String,
    pub text: String,
    pub wants: Vec<BRegProposalAskWant>,
    pub asked_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_at: Option<String>,
    pub state: BRegProposalAskState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<BRegProposalAskAnswer>,
    pub links: BTreeMap<String, BRegProposalLink>,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalAskAnswer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub additions: Vec<String>,
    pub answered_at: String,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalAnswerRequest {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_text"
    )]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additions: Vec<String>,
}
impl fmt::Debug for BRegProposalAsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BRegProposalAsk(<redacted>)")
    }
}
impl fmt::Debug for BRegProposalAskAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BRegProposalAskAnswer(<redacted>)")
    }
}
impl fmt::Debug for BRegProposalAnswerRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BRegProposalAnswerRequest(<redacted>)")
    }
}

fn valid_answer(text: Option<&str>, additions: &[String], wants: &[BRegProposalAskWant]) -> bool {
    (text.is_some() || !additions.is_empty())
        && text.is_none_or(|text| {
            !text.trim().is_empty() && text.len() <= 2000 && !text.contains('\0')
        })
        && (text.is_some() || !wants.contains(&BRegProposalAskWant::Answer {}))
        && additions.len() <= 32
        && additions.iter().all(|id| canonical_proposal_id(id))
        && additions
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == additions.len()
        && (!additions.is_empty() || !wants.contains(&BRegProposalAskWant::Document {}))
}

impl BRegProposal {
    pub(super) fn validate_asks(&self) -> Result<(), BaseRegistryClientError> {
        if self.asks.len() > 50 {
            return Err(refusal());
        }
        let mut ids = std::collections::BTreeSet::new();
        for ask in &self.asks {
            let asked = proposal_instant(&ask.asked_at).ok_or_else(refusal)?;
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
                    .as_ref()
                    .is_some_and(|due| proposal_instant(due).is_none_or(|due| due <= asked))
            {
                return Err(refusal());
            }
            if let Some(answer) = &ask.answer {
                let at = proposal_instant(&answer.answered_at).ok_or_else(refusal)?;
                if ask.state != BRegProposalAskState::Answered
                    || at < asked
                    || !at.nanosecond().is_multiple_of(1000)
                    || !valid_answer(answer.text.as_deref(), &answer.additions, &ask.wants)
                {
                    return Err(refusal());
                }
            }
            for (name, link) in &ask.links {
                validate_link(link)?;
                if name != "answer"
                    || link.method != "POST"
                    || link.operation != "answer"
                    || link.path != format!("/v1/proposals/{}/asks/{}/answer", self.id, ask.id)
                    || link
                        .availability
                        .as_ref()
                        .is_none_or(|a| !valid_availability(a, self.revision, self.state))
                {
                    return Err(refusal());
                }
            }
        }
        Ok(())
    }
}

fn present_text<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

impl BaseRegistryClient {
    /// Answer the explicitly selected ask using its promoted, origin-bound link.
    /// The caller retains the same Proposal and key when resending an unknown outcome.
    pub async fn answer_proposal_ask(
        &self,
        proposal: &BRegProposal,
        ask_id: &str,
        body: &BRegProposalAnswerRequest,
        key: &BRegIdempotencyKey,
    ) -> Result<BRegComplete<BRegProposal>, BaseRegistryClientError> {
        if proposal.source.as_deref() != Some(self.source_binding().as_str())
            || proposal.state != BRegProposalState::Submitted
        {
            return Err(refusal());
        }
        let ask = proposal
            .asks
            .iter()
            .find(|ask| ask.id == ask_id)
            .ok_or_else(refusal)?;
        let link = ask.links.get("answer").ok_or_else(refusal)?;
        if let Some(availability) = link
            .availability
            .as_ref()
            .filter(|availability| !availability.available)
        {
            return Err(unavailable(availability));
        }
        if ask.state != BRegProposalAskState::Open
            || ask.answer.is_some()
            || !valid_answer(body.text.as_deref(), &body.additions, &ask.wants)
        {
            return Err(refusal());
        }
        let response = self
            .proposal_exchange(
                link,
                Some(serde_json::to_vec(body).map_err(|_| refusal())?),
                Some(key),
            )
            .await?;
        let invalid = || {
            BaseRegistryClientError::protocol(
                200,
                BRegProtocolFailure::Body,
                Some(response.metadata.trace_id().clone()),
            )
        };
        let current = BRegProposal::from_slice(response.value.as_bytes()).map_err(|_| invalid())?;
        let matches_answer = current.asks.is_empty()
            || current
                .asks
                .iter()
                .find(|candidate| candidate.id == ask.id)
                .is_some_and(|candidate| {
                    candidate.text == ask.text
                        && candidate.wants == ask.wants
                        && candidate.asked_at == ask.asked_at
                        && candidate.due_at == ask.due_at
                        && candidate.answer.as_ref().is_some_and(|answer| {
                            answer.text == body.text
                                && answer
                                    .additions
                                    .iter()
                                    .collect::<std::collections::BTreeSet<_>>()
                                    == body
                                        .additions
                                        .iter()
                                        .collect::<std::collections::BTreeSet<_>>()
                        })
                });
        if current.discloses_application_actor()
            || current.id != proposal.id
            || current.action_id != proposal.action_id
            || current.action_revision != proposal.action_revision
            || current.state != BRegProposalState::Submitted
            || current.submission_version != proposal.submission_version
            || current.effect_digest != proposal.effect_digest
            || Some(current.revision) != proposal.revision.checked_add(1)
            || !matches_answer
        {
            return Err(invalid());
        }
        Ok(BRegComplete {
            value: current
                .bind_profile(self.source_binding(), &link.access_profile)
                .map_err(|_| invalid())?,
            metadata: response.metadata,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_answer_without_wants_still_needs_content_before_io() {
        assert!(!valid_answer(None, &[], &[]));
        assert!(valid_answer(Some("explanation"), &[], &[]));
    }
}

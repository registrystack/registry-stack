// SPDX-License-Identifier: Apache-2.0
use super::*;

impl BaseRegistryClient {
    /// Add supporting bytes to the exact submission named by a promoted slot.
    pub async fn add_proposal_addition(
        &self,
        proposal: &BRegProposal,
        slot: &str,
        content_type: &str,
        bytes: &[u8],
        key: &BRegIdempotencyKey,
    ) -> Result<BRegComplete<BRegProposal>, BaseRegistryClientError> {
        if proposal.source.as_deref() != Some(self.source_binding().as_str()) {
            return Err(refusal());
        }
        let slot = proposal.additions.get(slot).ok_or_else(refusal)?;
        let link = slot
            .links
            .get("add")
            .filter(|link| link.availability.as_ref().is_none_or(|a| a.available))
            .ok_or_else(refusal)?;
        if proposal.state != BRegProposalState::Submitted
            || bytes.is_empty()
            || bytes.len() as u64 > slot.maximum_bytes
            || slot.items.len() >= slot.maximum_count as usize
            || !slot.content_types.iter().any(|media| media == content_type)
        {
            return Err(refusal());
        }
        let response = self
            .proposal_attachment_exchange(
                link,
                Some(bytes.to_vec()),
                Some(content_type),
                Some(key),
                slot.maximum_bytes,
                None,
            )
            .await?;
        let invalid_receipt = || {
            BaseRegistryClientError::protocol(
                200,
                BRegProtocolFailure::Body,
                Some(response.metadata.trace_id().clone()),
            )
        };
        let current =
            BRegProposal::from_slice(response.value.as_bytes()).map_err(|_| invalid_receipt())?;
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let current_slot = current
            .additions
            .get(&slot.id)
            .ok_or_else(invalid_receipt)?;
        let valid_items = current_slot.items.is_empty() && slot.items.is_empty()
            || current_slot.items.len() == slot.items.len() + 1
                && slot.items.iter().all(|prior| {
                    current_slot.items.iter().any(|item| {
                        item.id == prior.id
                            && item.sha256 == prior.sha256
                            && item.byte_size == prior.byte_size
                            && item.content_type == prior.content_type
                    })
                })
                && current_slot.items.iter().any(|item| {
                    !slot.items.iter().any(|prior| prior.id == item.id)
                        && item.sha256 == hash
                        && item.byte_size == bytes.len() as u64
                        && item.content_type == content_type
                });
        if current.discloses_application_actor()
            || current.id != proposal.id
            || current.action_id != proposal.action_id
            || current.action_revision != proposal.action_revision
            || current.state != BRegProposalState::Submitted
            || current.submission_version != proposal.submission_version
            || current.effect_digest != proposal.effect_digest
            || current.revision <= proposal.revision
            || !valid_items
        {
            return Err(invalid_receipt());
        }
        Ok(BRegComplete {
            value: current
                .bind_profile(self.source_binding(), &link.access_profile)
                .map_err(|_| invalid_receipt())?,
            metadata: response.metadata,
        })
    }

    pub async fn download_proposal_addition(
        &self,
        proposal: &BRegProposal,
        addition: &str,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        if proposal.source.as_deref() != Some(self.source_binding().as_str()) {
            return Err(refusal());
        }
        let item = proposal
            .additions
            .values()
            .flat_map(|slot| &slot.items)
            .find(|item| item.id == addition)
            .ok_or_else(refusal)?;
        let link = item
            .links
            .get("download")
            .filter(|link| link.availability.as_ref().is_none_or(|a| a.available))
            .ok_or_else(refusal)?;
        let response = self
            .proposal_attachment_exchange(link, None, None, None, item.byte_size, None)
            .await?;
        crate::attachment::verify_download(
            response,
            &item.content_type,
            item.byte_size,
            &item.sha256,
        )
    }
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalAdditionSlot {
    id: String,
    maximum_bytes: u64,
    maximum_count: u32,
    content_types: Vec<String>,
    classification: String,
    items: Vec<BRegProposalAddition>,
    links: BTreeMap<String, BRegProposalLink>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalAddition {
    id: String,
    submission_version: u32,
    sha256: String,
    byte_size: u64,
    content_type: String,
    added_at: String,
    verification_status: String,
    links: BTreeMap<String, BRegProposalLink>,
}

impl BRegProposalAdditionSlot {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }
    pub fn maximum_count(&self) -> u32 {
        self.maximum_count
    }
    pub fn content_types(&self) -> &[String] {
        &self.content_types
    }
    pub fn items(&self) -> &[BRegProposalAddition] {
        &self.items
    }
    pub fn link(&self, operation: &str) -> Option<&BRegProposalLink> {
        self.links.get(operation)
    }
}
impl BRegProposalAddition {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn submission_version(&self) -> u32 {
        self.submission_version
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn byte_size(&self) -> u64 {
        self.byte_size
    }
    pub fn content_type(&self) -> &str {
        &self.content_type
    }
    pub fn added_at(&self) -> &str {
        &self.added_at
    }
    pub fn link(&self, operation: &str) -> Option<&BRegProposalLink> {
        self.links.get(operation)
    }
}

impl BRegProposal {
    pub fn addition_slot(&self, slot: &str) -> Option<&BRegProposalAdditionSlot> {
        self.additions.get(slot)
    }
    pub(super) fn addition_links(&self) -> impl Iterator<Item = &BRegProposalLink> {
        self.additions.values().flat_map(|slot| {
            slot.links
                .values()
                .chain(slot.items.iter().flat_map(|item| item.links.values()))
        })
    }
    pub(super) fn validate_additions(&self) -> Result<(), BaseRegistryClientError> {
        if self.additions.len() > 1 {
            return Err(refusal());
        }
        for (id, slot) in &self.additions {
            if id != &slot.id
                || !identifier(id)
                || !(1..=MAX_BREG_ATTACHMENT_BYTES).contains(&slot.maximum_bytes)
                || !(1..=32).contains(&slot.maximum_count)
                || slot.items.len() > slot.maximum_count as usize
                || slot.content_types.is_empty()
                || slot.content_types.len() > MAX_BREG_ATTACHMENT_CONTENT_TYPES
                || slot
                    .content_types
                    .iter()
                    .any(|media| !crate::attachment::valid_attachment_content_type(media))
                || slot
                    .content_types
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != slot.content_types.len()
                || !matches!(
                    slot.classification.as_str(),
                    "public" | "internal" | "restricted"
                )
            {
                return Err(refusal());
            }
            for (name, link) in &slot.links {
                if name != "add"
                    || link.operation != "add"
                    || link.method != "POST"
                    || link.path != format!("/v1/proposals/{}/additions/{id}", self.id)
                    || !identifier(&link.access_profile)
                    || !valid_condition(link.if_match.as_deref())
                    || link
                        .availability
                        .as_ref()
                        .is_some_and(|a| !valid_availability(a, self.revision, self.state))
                {
                    return Err(refusal());
                }
            }
            let mut ids = std::collections::BTreeSet::new();
            for item in &slot.items {
                if !canonical_proposal_id(&item.id)
                    || !ids.insert(&item.id)
                    || item.submission_version != self.submission_version
                    || !digest(&format!("sha256:{}", item.sha256))
                    || !(1..=MAX_BREG_ATTACHMENT_BYTES).contains(&item.byte_size)
                    || !crate::attachment::valid_attachment_content_type(&item.content_type)
                    || proposal_instant(&item.added_at).is_none()
                    || !matches!(
                        item.verification_status.as_str(),
                        "notRequired" | "pending" | "approved" | "rejected"
                    )
                {
                    return Err(refusal());
                }
                for (name, link) in &item.links {
                    if name != "download"
                        || link.operation != "download"
                        || link.method != "GET"
                        || link.path
                            != format!(
                                "/v1/proposals/{}/additions/{}?submissionVersion={}",
                                self.id, item.id, self.submission_version
                            )
                        || !identifier(&link.access_profile)
                        || link.if_match.is_some()
                        || !matches!(
                            item.verification_status.as_str(),
                            "notRequired" | "approved"
                        )
                        || link
                            .availability
                            .as_ref()
                            .is_some_and(|a| !valid_availability(a, self.revision, self.state))
                    {
                        return Err(refusal());
                    }
                }
            }
        }
        Ok(())
    }
}

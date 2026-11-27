// SPDX-License-Identifier: Apache-2.0
use super::*;

impl MutationTransaction {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn append_additions(
        &self,
        tx: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        document: &ProposalDocument,
        current: &ProposalAuthority,
        claims: &crate::api::VerifiedRequestClaims,
        permission: &crate::model::CompiledProposalPermission,
        read: Option<&ProposalAuthority>,
        value: &mut Value,
    ) -> Result<(), MutationError> {
        let CompiledActionExecution::Proposal { proposal } = &action.execution else {
            return Ok(());
        };
        let Some(slot) = &proposal.additions else {
            return Ok(());
        };
        let readable = read.is_some() && permission.readable_attachments.contains(&slot.id);
        let write = crate::api::proposals::authorize(
            registry,
            action,
            claims,
            Some(current.common.access_profile()),
            ProposalAuthorityOperation::Lifecycle(ProposalOperation::Add),
            Some(document.proposal_id),
        )
        .filter(|_| permission.writable_attachments.contains(&slot.id));
        let write = match write {
            Some(authority) => link_readable(
                self.authorize_proposal_document(tx, registry, document, &authority)
                    .await,
            )?
            .then_some(authority),
            None => None,
        };
        if !readable && write.is_none() {
            return Ok(());
        }
        let metadata = crate::attachment_store::additions::metadata(
            tx,
            &action.id,
            document.proposal_id,
            document.header.submission_version,
            &slot.id,
        )
        .await?;
        let mut descriptor = json!({"id":slot.id,"maximumBytes":slot.maximum_bytes,"maximumCount":slot.maximum_count,
            "contentTypes":slot.content_types,"classification":slot.classification,"items":[],"links":{}});
        if readable {
            let mut items = Vec::new();
            for addition in &metadata {
                let file = &addition.file;
                let mut item = json!({"id":addition.id,"submissionVersion":addition.submission_version,
                    "sha256":file.sha256,"byteSize":file.byte_size,"contentType":file.content_type,
                    "addedAt":file.uploaded_at,"verificationStatus":file.verification_status,"links":{}});
                if file.verification_status.permits_content() {
                    item["links"]["download"] = json!({"method":"GET",
                        "path":format!("/v1/proposals/{}/additions/{}?submissionVersion={}", document.proposal_id, addition.id, addition.submission_version),
                        "accessProfile":current.common.access_profile(),"operation":"download",
                        "availability":{"available":true,"observedRevision":document.header.workflow_revision}});
                }
                items.push(item);
            }
            descriptor["items"] = json!(items);
        }
        if let Some(write) = write {
            let workflow = if document.header.state == "submitted"
                && !document.header.current_proposal_erased
            {
                Some(proposal_store::load(tx, &action.id, document.proposal_id, false).await?)
            } else {
                None
            };
            let progress = match workflow
                .as_ref()
                .and_then(|workflow| workflow.current_proposal())
            {
                Some(frozen) => review_progress(tx, document, frozen).await?,
                None => ProposalReviewProgress::NotRequired,
            };
            let refusal = if document.header.state == "applied" {
                Some((LinkReason::AlreadyApplied, LinkRecovery::ReceiptOnly))
            } else if document.header.state == "rejected" {
                Some((LinkReason::ReviewRejected, LinkRecovery::ReceiptOnly))
            } else if document.header.state != "submitted"
                || document.header.current_proposal_erased
            {
                Some((LinkReason::StaleRevision, LinkRecovery::ReceiptOnly))
            } else if metadata.len() > slot.maximum_count as usize {
                // Retained files remain visible after a lower current limit.
                Some((LinkReason::LimitReached, LinkRecovery::ReceiptOnly))
            } else if document.blocked_reason.as_deref() == Some("application-refused") {
                Some((LinkReason::InvalidInput, LinkRecovery::CorrectInput))
            } else if document.blocked_reason.is_some()
                || document.action_revision != action.definition_revision
            {
                Some((LinkReason::PackageChanged, LinkRecovery::Rebase))
            } else if !matches!(
                progress,
                ProposalReviewProgress::Pending | ProposalReviewProgress::Retrying
            ) {
                Some(match progress {
                    ProposalReviewProgress::Rejected => {
                        (LinkReason::ReviewRejected, LinkRecovery::Revise)
                    }
                    ProposalReviewProgress::ChangesRequested => {
                        (LinkReason::ReviewChangesRequested, LinkRecovery::Revise)
                    }
                    _ => (LinkReason::ReviewEnded, LinkRecovery::Revise),
                })
            } else if metadata.len() >= slot.maximum_count as usize {
                Some((LinkReason::LimitReached, LinkRecovery::ReceiptOnly))
            } else {
                None
            };
            let mut link = json!({"method":"POST","path":format!("/v1/proposals/{}/additions/{}",document.proposal_id,slot.id),
                "accessProfile":write.common.access_profile(),"operation":"add","ifMatch":self.proposal_etag(document,&write)?,
                "availability":{"available":refusal.is_none(),"observedRevision":document.header.workflow_revision}});
            if let Some((reason, recovery)) = refusal {
                link["availability"]["reason"] = json!(reason);
                link["availability"]["recovery"] = json!(recovery);
            }
            descriptor["links"]["add"] = link;
        }
        value["additions"] = json!({slot.id.clone():descriptor});
        Ok(())
    }
}

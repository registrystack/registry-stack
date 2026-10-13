// SPDX-License-Identifier: Apache-2.0
//! Distinct Proposal resources and exact, caller-controlled transition attempts.

use std::collections::BTreeMap;
use std::fmt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;
use crate::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegRecoveryHint { Refresh, Retry, CorrectInput, Terminal, ReceiptOnly }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegAvailabilityReason { PendingReview, StaleRevision, ContractChanged, DependencyOutage, InvalidInput, AlreadyApplied }
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegAvailability {
    pub available: bool,
    pub observed_revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<BRegAvailabilityReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<BRegRecoveryHint>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegProposalState { Draft, Submitted, Applied, Cancelled }

/// Inert server-issued link. Only a client-bound Proposal promotes its use.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalLink {
    method: String,
    path: String,
    access_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    if_match: Option<String>,
    operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    availability: Option<BRegAvailability>,
}
impl BRegProposalLink {
    pub fn method(&self) -> &str { &self.method }
    pub fn operation(&self) -> &str { &self.operation }
    pub fn availability(&self) -> Option<&BRegAvailability> { self.availability.as_ref() }
    pub(crate) fn path(&self) -> &str { &self.path }
    pub(crate) fn access_profile(&self) -> &str { &self.access_profile }
    pub(crate) fn if_match(&self) -> Option<&str> { self.if_match.as_deref() }
}
impl fmt::Debug for BRegProposalLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { formatter.write_str("BRegProposalLink(<inert>)") }
}

/// A Proposal is independently versioned and never decoded as a Record subtype.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposal {
    id: String,
    action_id: String,
    action_revision: String,
    version: u32,
    revision: u64,
    state: BRegProposalState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blocked_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect_digest: Option<String>,
    links: BTreeMap<String, BRegProposalLink>,
    #[serde(skip)]
    source: Option<String>,
}
impl BRegProposal {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, BaseRegistryClientError> {
        if bytes.len() > DEFAULT_MAX_RESPONSE_BYTES as usize { return Err(refusal()); }
        let value = crate::strict_json::from_slice(bytes).map_err(|_| refusal())?;
        let proposal: Self = serde_json::from_value(value).map_err(|_| refusal())?;
        proposal.validate()?;
        Ok(proposal)
    }
    fn validate(&self) -> Result<(), BaseRegistryClientError> {
        if Uuid::parse_str(&self.id).is_err() || self.revision == 0
            || !identifier(&self.action_id) || !digest(&self.action_revision)
            || self.effect_digest.as_ref().is_some_and(|value| !digest(value))
            || self.blocked_reason.as_deref().is_some_and(|reason| reason != "package-changed") { return Err(refusal()); }
        for (operation, link) in &self.links {
            validate_link(link)?;
            if !matches!(operation.as_str(), "self" | "submit" | "revise" | "cancel" | "apply" | "reviewContext" | "replay")
                || link.availability.as_ref().is_some_and(|availability| availability.observed_revision != self.revision
                    || !availability.available && (availability.reason.is_none() || availability.recovery.is_none())) {
                return Err(refusal());
            }
        }
        Ok(())
    }
    pub fn id(&self) -> &str { &self.id }
    pub fn action_id(&self) -> &str { &self.action_id }
    pub fn action_revision(&self) -> &str { &self.action_revision }
    pub const fn revision(&self) -> u64 { self.revision }
    pub const fn version(&self) -> u32 { self.version }
    pub const fn state(&self) -> BRegProposalState { self.state }
    pub fn blocked_reason(&self) -> Option<&str> { self.blocked_reason.as_deref() }
    pub fn link(&self, operation: &str) -> Option<&BRegProposalLink> { self.links.get(operation) }
    pub(crate) fn bind(mut self, source: String) -> Self { self.source = Some(source); self }
}
impl fmt::Debug for BRegProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { formatter.write_str("BRegProposal(<redacted>)") }
}

/// One explicitly bounded collection response. The caller chooses each continuation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalPage {
    pub items: Vec<BRegProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone)]
pub struct BRegProposalCollection {
    source: String,
    registry_revision: String,
    path: String,
    profile: String,
}
impl fmt::Debug for BRegProposalCollection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { formatter.write_str("BRegProposalCollection(<bound>)") }
}
impl BRegProposalCollection {
    pub(crate) fn from_metadata(value: &Value, source: &str, revision: &str, profile: &str) -> Result<Self, BaseRegistryClientError> {
        let path = value.get("path").and_then(Value::as_str).ok_or_else(refusal)?;
        let profiles = value.get("accessProfiles").and_then(Value::as_array).ok_or_else(refusal)?;
        if value.get("method").and_then(Value::as_str) != Some("GET")
            || !profiles.iter().any(|candidate| candidate.as_str() == Some(profile))
            || !path.starts_with("/v1/") || path.contains(['?','#','%','\\'])
            || path.split('/').skip(1).any(|segment| !identifier(segment)) { return Err(refusal()); }
        Ok(Self { source: source.to_owned(), registry_revision: revision.to_owned(), path: path.to_owned(), profile: profile.to_owned() })
    }
    pub fn registry_revision(&self) -> &str { &self.registry_revision }
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct BRegProposalQuery {
    pub action: Option<String>,
    pub owner_is_caller: bool,
    pub target: Option<Uuid>,
    pub state: Option<BRegProposalState>,
    pub cursor: Option<String>,
    pub top: Option<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedEvidence {
    version: u8,
    source: String,
    proposal_id: String,
    action_id: String,
    action_revision: String,
    proposal_version: u32,
    link: BRegProposalLink,
    body: String,
    key: String,
}
/// Original exact transition evidence, containing inputs and key material.
/// Persist it in application-protected state before sending. Parsing grants no authority.
#[derive(Clone)]
pub struct BRegPreparedProposal {
    bytes: Zeroizing<Vec<u8>>,
    executable: bool,
}
impl BRegPreparedProposal {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, BaseRegistryClientError> {
        if bytes.len() > DEFAULT_MAX_RESPONSE_BYTES as usize { return Err(refusal()); }
        let value = crate::strict_json::from_slice(bytes).map_err(|_| refusal())?;
        let data: PreparedEvidence = serde_json::from_value(value).map_err(|_| refusal())?;
        if data.version != 1 || Uuid::parse_str(&data.proposal_id).is_err() || !digest(&data.action_revision) { return Err(refusal()); }
        validate_link(&data.link)?;
        BRegIdempotencyKey::parse(&data.key).map_err(|_| refusal())?;
        crate::strict_json::from_slice(data.body.as_bytes()).map_err(|_| refusal())?;
        Ok(Self { bytes: Zeroizing::new(bytes.to_vec()), executable: false })
    }
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }
    fn decode(&self) -> Result<PreparedEvidence, BaseRegistryClientError> {
        serde_json::from_slice(&self.bytes).map_err(|_| refusal())
    }
}
impl fmt::Debug for BRegPreparedProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { formatter.write_str("BRegPreparedProposal(<redacted>)") }
}
impl BaseRegistryClient {
    /// List one bounded, explicitly authorized page. No automatic continuation.
    pub async fn list_proposals(&self, collection: &BRegProposalCollection, query: &BRegProposalQuery) -> Result<BRegComplete<BRegProposalPage>, BaseRegistryClientError> {
        if collection.source != self.source_binding() || query.top.is_some_and(|top| !(1..=100).contains(&top))
            || query.action.as_ref().is_some_and(|action| !identifier(action))
            || query.cursor.as_ref().is_some_and(|cursor| cursor.len() > 512 || cursor.is_empty() || cursor.bytes().any(|byte| byte <= 32 || byte >= 127)) { return Err(refusal()); }
        let mut pairs = vec![("accessProfile".to_owned(), collection.profile.clone())];
        if let Some(action) = &query.action { pairs.push(("action".to_owned(), action.clone())); }
        if query.owner_is_caller { pairs.push(("owner".to_owned(), "caller".to_owned())); }
        if let Some(target) = query.target { pairs.push(("target".to_owned(), target.to_string())); }
        if let Some(state) = query.state { pairs.push(("state".to_owned(), serde_json::to_value(state).map_err(|_| refusal())?.as_str().ok_or_else(refusal)?.to_owned())); }
        if let Some(cursor) = &query.cursor { pairs.push(("cursor".to_owned(), cursor.clone())); }
        if let Some(top) = query.top { pairs.push(("top".to_owned(), top.to_string())); }
        let response = self.proposal_list_exchange(&collection.path, &pairs).await?;
        let value = crate::strict_json::from_slice(response.value.as_bytes()).map_err(|_| refusal())?;
        let mut page: BRegProposalPage = serde_json::from_value(value).map_err(|_| refusal())?;
        if page.items.len() > query.top.unwrap_or(50) as usize || page.next_cursor.as_ref().is_some_and(|cursor| cursor.len()>512) { return Err(refusal()); }
        for item in &mut page.items {
            item.validate()?;
            if query.action.as_ref().is_some_and(|action| action != &item.action_id) { return Err(refusal()); }
            item.source = Some(self.source_binding());
        }
        Ok(BRegComplete { value: page, metadata: response.metadata })
    }
    /// Validate and bind a promoted transition without I/O or Evidence acquisition.
    pub fn prepare_proposal(
        &self, proposal: &BRegProposal, operation: &str, body: Value, key: &BRegIdempotencyKey,
    ) -> Result<BRegPreparedProposal, BaseRegistryClientError> {
        if proposal.source.as_deref() != Some(self.source_binding().as_str()) { return Err(refusal()); }
        let link = proposal.links.get(operation).filter(|link| link.method == "POST"
            && link.availability.as_ref().is_none_or(|availability| availability.available)).ok_or_else(refusal)?;
        if !body.is_object() || !matches!(operation, "submit" | "revise" | "cancel" | "apply") { return Err(refusal()); }
        let evidence = PreparedEvidence { version: 1, source: self.source_binding(), proposal_id: proposal.id.clone(),
            action_id: proposal.action_id.clone(), action_revision: proposal.action_revision.clone(),
            proposal_version: proposal.version, link: link.clone(),
            body: serde_json::to_string(&body).map_err(|_| refusal())?, key: key.as_str().to_owned() };
        let mut attempt = BRegPreparedProposal::from_slice(&serde_json::to_vec(&evidence).map_err(|_| refusal())?)?;
        attempt.executable = true;
        Ok(attempt)
    }
    /// Execute the exact prepared transition; its response is another bound Proposal.
    pub async fn execute_proposal(&self, attempt: &BRegPreparedProposal) -> Result<BRegComplete<BRegProposal>, BaseRegistryClientError> {
        let evidence = attempt.decode()?;
        if !attempt.executable || evidence.source != self.source_binding() { return Err(refusal()); }
        let key = BRegIdempotencyKey::parse(&evidence.key).map_err(|_| refusal())?;
        let response = self.proposal_exchange(&evidence.link, Some(evidence.body.into_bytes()), Some(&key)).await?;
        let proposal = BRegProposal::from_slice(response.value.as_bytes())?;
        if proposal.id != evidence.proposal_id || proposal.action_id != evidence.action_id { return Err(refusal()); }
        Ok(BRegComplete { value: proposal.bind(self.source_binding()), metadata: response.metadata })
    }
    /// Explicitly read one server-promoted resource link. No linked resource is followed automatically.
    pub async fn read_proposal(&self, proposal: &BRegProposal) -> Result<BRegComplete<BRegProposal>, BaseRegistryClientError> {
        if proposal.source.as_deref() != Some(self.source_binding().as_str()) { return Err(refusal()); }
        let link = proposal.links.get("self").ok_or_else(refusal)?;
        let response = self.proposal_exchange(link, None, None).await?;
        let current = BRegProposal::from_slice(response.value.as_bytes())?;
        if current.id != proposal.id || current.action_id != proposal.action_id { return Err(refusal()); }
        Ok(BRegComplete { value: current.bind(self.source_binding()), metadata: response.metadata })
    }
    /// Revalidate saved evidence against a current authorized resource, retaining the original bytes.
    pub fn recover_proposal(&self, current: &BRegProposal, attempt: &BRegPreparedProposal) -> Result<BRegPreparedProposal, BaseRegistryClientError> {
        let evidence = attempt.decode()?;
        if current.source.as_deref() != Some(self.source_binding().as_str()) || evidence.source != self.source_binding()
            || evidence.proposal_id != current.id || evidence.action_id != current.action_id
            || evidence.action_revision != current.action_revision
            || !current.links.values().any(|link| link.path == evidence.link.path
                && link.method == evidence.link.method && link.access_profile == evidence.link.access_profile
                && link.operation == evidence.link.operation
                && (link == &evidence.link || link.availability.as_ref().is_some_and(|availability|
                    availability.recovery == Some(BRegRecoveryHint::ReceiptOnly)))) { return Err(refusal()); }
        let mut recovered = BRegPreparedProposal::from_slice(attempt.as_bytes())?;
        recovered.executable = true;
        Ok(recovered)
    }
}
fn identifier(value: &str) -> bool { !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte,b'-'|b'_'|b'.')) }
fn digest(value: &str) -> bool { value.strip_prefix("sha256:").is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))) }
fn validate_link(link: &BRegProposalLink) -> Result<(), BaseRegistryClientError> {
    if !matches!(link.method.as_str(), "GET"|"POST") || !link.path.starts_with("/v1/") || link.path.len() > 2048
        || link.path.contains(['?','#','%','\\']) || link.path.split('/').skip(1).any(|segment| !identifier(segment))
        || !identifier(&link.access_profile) || !identifier(&link.operation)
        || link.method == "POST" && link.if_match.as_ref().is_none_or(|etag| etag.len() < 3 || etag.len()>256 || !etag.starts_with('"') || !etag.ends_with('"') || etag.bytes().any(|byte|byte<=32 || byte>=127)) { return Err(refusal()); }
    Ok(())
}
fn refusal() -> BaseRegistryClientError { BaseRegistryClientError::invalid_request("the Base Registry Engine Proposal contract or attempt is invalid") }

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const REVISION: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ID: &str = "00000000-0000-4000-8000-000000000001";
    fn client(origin: &str) -> BaseRegistryClient {
        BaseRegistryClient::new(BaseRegistryClientConfig::new(origin.parse().unwrap())).unwrap()
    }
    fn document() -> Value {
        json!({"id":ID,"actionId":"correct-address","actionRevision":REVISION,
            "version":1,"revision":2,"state":"submitted","links":{
                "self":{"method":"GET","path":format!("/v1/proposals/{ID}"),"accessProfile":"author","operation":"get"},
                "apply":{"method":"POST","path":format!("/v1/proposals/{ID}/apply"),"accessProfile":"author","operation":"apply","ifMatch":"\"original-condition\"",
                    "availability":{"available":true,"observedRevision":2}}
            }})
    }
    fn proposal(client: &BaseRegistryClient, value: Value) -> BRegProposal {
        BRegProposal::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap().bind(client.source_binding())
    }
    #[test]
    fn inspection_is_inert_and_transitions_are_bound_to_the_client_origin() {
        let client = client("https://registry.example/base/");
        let bytes = serde_json::to_vec(&document()).unwrap();
        let inert = BRegProposal::from_slice(&bytes).unwrap();
        let key = BRegIdempotencyKey::parse("original-key").unwrap();
        assert!(client.prepare_proposal(&inert,"apply",json!({}),&key).is_err());
        let bound = proposal(&client, document());
        let attempt = client.prepare_proposal(&bound,"apply",json!({}),&key).unwrap();
        assert!(!format!("{attempt:?}").contains("original-key"));
        let other = super::tests::client("https://other.example/");
        assert!(other.prepare_proposal(&bound,"apply",json!({}),&key).is_err());
        let restored = BRegPreparedProposal::from_slice(attempt.as_bytes()).unwrap();
        assert!(!restored.executable);
        assert!(client.recover_proposal(&bound,&restored).unwrap().executable);
        assert_eq!(restored.as_bytes(),attempt.as_bytes());
    }
    #[test]
    fn committed_recovery_retains_original_condition_body_key_and_contract() {
        let client = client("https://registry.example/");
        let original = proposal(&client,document());
        let attempt = client.prepare_proposal(&original,"apply",json!({"effectDigest":REVISION}),&BRegIdempotencyKey::parse("original-key").unwrap()).unwrap();
        let mut terminal = document();
        terminal["state"] = json!("applied"); terminal["revision"] = json!(3);
        terminal["links"]["apply"]["ifMatch"] = json!("\"current-condition\"");
        terminal["links"]["apply"]["availability"] = json!({"available":false,"observedRevision":3,"reason":"already-applied","recovery":"receipt-only"});
        let terminal = proposal(&client,terminal);
        assert!(client.prepare_proposal(&terminal,"apply",json!({}),&BRegIdempotencyKey::parse("new-key").unwrap()).is_err());
        let recovered = client.recover_proposal(&terminal,&attempt).unwrap();
        assert_eq!(recovered.as_bytes(),attempt.as_bytes());
        let mut changed = document(); changed["actionRevision"] = json!("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert!(client.recover_proposal(&proposal(&client,changed),&attempt).is_err());
        let mut revoked = document(); revoked["links"].as_object_mut().unwrap().remove("apply");
        assert!(client.recover_proposal(&proposal(&client,revoked),&attempt).is_err());
    }
    #[test]
    fn link_confinement_duplicate_members_and_revision_bound_availability_are_checked() {
        for path in ["https://other.example/", "/v1/proposals/../secret", "/v1/proposals/%2e%2e", "/v1/proposals/a?accessProfile=admin"] {
            let mut invalid=document();invalid["links"]["apply"]["path"]=json!(path);
            assert!(BRegProposal::from_slice(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let mut invalid=document();invalid["links"]["apply"]["availability"]["observedRevision"]=json!(1);
        assert!(BRegProposal::from_slice(&serde_json::to_vec(&invalid).unwrap()).is_err());
        assert!(BRegProposal::from_slice(br#"{"id":"a","id":"b"}"#).is_err());
        let mut start_only=document();start_only["links"]=json!({});
        assert!(BRegProposal::from_slice(&serde_json::to_vec(&start_only).unwrap()).is_ok());
    }
    #[test]
    fn a_get_grant_does_not_promote_collection_authority() {
        assert!(BRegProposalCollection::from_metadata(&json!({"method":"GET","path":"/v1/proposals","accessProfiles":["list-author"]}),"https://registry.example/",REVISION,"get-author").is_err());
        assert!(BRegProposalCollection::from_metadata(&json!({"method":"GET","path":"/v1/proposals","accessProfiles":["list-author"]}),"https://registry.example/",REVISION,"list-author").is_ok());
    }
}

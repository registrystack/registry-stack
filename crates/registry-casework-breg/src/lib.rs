// SPDX-License-Identifier: Apache-2.0
//! Read-only native Proposal context provider. No discovery, events or source writes.
mod config;
mod served;
use async_trait::async_trait;
pub use config::*;
use registry_breg_client::{
    BRegProposalReviewBinding, BRegProposalReviewContextContract, BRegProposalReviewDocument,
    BRegProposalReviewSubject, BRegProposalTaskContextIdentity, BRegProposalTaskContextRequest,
    BaseRegistryClient, BaseRegistryClientError, BearerToken,
};
use registry_casework_core::*;
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::{
    ExchangeAuthorization, ExchangeContext, PrivateKeyJwt, PrivateKeyJwtConfig, SubjectTokenType,
    TokenProvider, UpstreamSubjectToken,
};
pub use served::{unserved_capabilities, SERVED_CAPABILITIES};
use std::{sync::Arc, time::Duration};
use url::Url;

struct DelegatedDisplayExchange {
    token_endpoint: Url,
    client_id: String,
    key: PrivateJwk,
    assertion_audience: Option<String>,
    resource: String,
    scopes: Vec<String>,
    generation: String,
    actor: Arc<PrivateKeyJwt>,
}

impl DelegatedDisplayExchange {
    #[allow(clippy::too_many_arguments)]
    fn new(
        token_endpoint: Url,
        client_id: String,
        key: PrivateJwk,
        assertion_audience: Option<String>,
        resource: String,
        scopes: Vec<String>,
        generation: String,
    ) -> Result<Self, ReviewContextError> {
        let valid_token = |value: &str, maximum| {
            !value.is_empty()
                && value.len() <= maximum
                && !value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        };
        if !valid_token(&resource, 2048)
            || scopes.is_empty()
            || scopes.len() > 128
            || scopes.iter().any(|scope| !valid_token(scope, 512))
            || scopes
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != scopes.len()
            || !valid_token(&generation, 512)
        {
            return Err(ReviewContextError::Invalid);
        }
        let actor = Arc::new(
            PrivateKeyJwt::new(Self::client_config(
                &token_endpoint,
                &client_id,
                &key,
                assertion_audience.as_deref(),
            ))
            .map_err(|_| ReviewContextError::Invalid)?,
        );
        PrivateKeyJwt::new(
            Self::client_config(
                &token_endpoint,
                &client_id,
                &key,
                assertion_audience.as_deref(),
            )
            .with_resource(resource.clone())
            .with_scopes(scopes.iter().cloned()),
        )
        .map_err(|_| ReviewContextError::Invalid)?;
        Ok(Self {
            token_endpoint,
            client_id,
            key,
            assertion_audience,
            resource,
            scopes,
            generation,
            actor,
        })
    }

    fn client_config(
        token_endpoint: &Url,
        client_id: &str,
        key: &PrivateJwk,
        assertion_audience: Option<&str>,
    ) -> PrivateKeyJwtConfig {
        let config = PrivateKeyJwtConfig::new(token_endpoint.clone(), client_id, key.clone())
            .with_attempt_timeout(Duration::from_secs(30))
            .with_connect_timeout(Duration::from_secs(10));
        match assertion_audience {
            Some(audience) => config.with_audience(audience),
            None => config,
        }
    }

    async fn bearer(
        &self,
        credential: EphemeralCredential<'_>,
        context: &DelegatedCredentialContext,
    ) -> Result<BearerToken, ReviewContextError> {
        let exchange = PrivateKeyJwt::new(
            Self::client_config(
                &self.token_endpoint,
                &self.client_id,
                &self.key,
                self.assertion_audience.as_deref(),
            )
            .with_resource(self.resource.clone())
            .with_scopes(self.scopes.iter().cloned()),
        )
        .map_err(|_| ReviewContextError::Unavailable)?;
        let exchange_context = ExchangeContext::first_party(
            context.issuer(),
            context.subject(),
            context.audience(),
            self.generation.clone(),
            context.expires_at(),
        )
        .map_err(|_| ReviewContextError::Denied)?;
        let subject = UpstreamSubjectToken::new(
            credential.expose(),
            SubjectTokenType::AccessToken,
            context.expires_at(),
        )
        .map_err(|_| ReviewContextError::Denied)?;
        ExchangeAuthorization::upstream(
            exchange,
            exchange_context,
            subject,
            Some(Arc::clone(&self.actor)),
        )
        .map_err(|_| ReviewContextError::Unavailable)?
        .bearer_token()
        .await
        .map_err(|_| ReviewContextError::Unavailable)
    }
}

impl std::fmt::Debug for DelegatedDisplayExchange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedDisplayExchange")
            .field("resource", &"<configured>")
            .field("scopes", &self.scopes.len())
            .field("generation", &"<configured>")
            .finish_non_exhaustive()
    }
}

pub struct BregContextProvider {
    id: String,
    export: BregContextExport,
    client: BaseRegistryClient,
    status_profile: String,
    task_grant_profile: Option<String>,
    delegated_display_exchange: Option<DelegatedDisplayExchange>,
}
impl BregContextProvider {
    pub fn new(
        id: String,
        export: BregContextExport,
        client: BaseRegistryClient,
        status_profile: String,
    ) -> Result<Self, ReviewContextError> {
        export.check()?;
        if id.is_empty() || status_profile.is_empty() {
            return Err(ReviewContextError::Invalid);
        }
        Ok(Self {
            id,
            export,
            client,
            status_profile,
            task_grant_profile: None,
            delegated_display_exchange: None,
        })
    }
    fn with_delegated_display_exchange(mut self, exchange: DelegatedDisplayExchange) -> Self {
        self.delegated_display_exchange = Some(exchange);
        self
    }
    pub fn with_task_grant_profile(mut self, profile: String) -> Result<Self, ReviewContextError> {
        if !registry_casework_core::valid_profile_identifier(&profile)
            || profile == self.status_profile
        {
            return Err(ReviewContextError::Invalid);
        }
        self.task_grant_profile = Some(profile);
        Ok(self)
    }
    async fn read(
        &self,
        client: &BaseRegistryClient,
        identity: &ReviewContextIdentity,
        profile: &str,
        display: bool,
    ) -> Result<BRegProposalReviewDocument, ReviewContextError> {
        self.validate_identity(identity)?;
        let binding = self.read_binding(client, profile, display).await?;
        self.read_bound(client, identity, &binding, display).await
    }

    fn validate_identity(
        &self,
        identity: &ReviewContextIdentity,
    ) -> Result<(), ReviewContextError> {
        if identity.contract != self.export.contract
            || identity.subject.source != self.export.source_namespace
            || identity.subject.subject_type != "proposal"
        {
            return Err(ReviewContextError::ContractChanged);
        }
        Ok(())
    }

    async fn read_binding(
        &self,
        client: &BaseRegistryClient,
        profile: &str,
        display: bool,
    ) -> Result<BRegProposalReviewBinding, ReviewContextError> {
        let (version, metadata) = client
            .registry_contract_and_engine_version(Some(profile))
            .await;
        // A successful but incompatible peer may not decode at all. Name the
        // lockstep mismatch before interpreting its document, without releasing
        // a subject or echoing an untrusted header into diagnostics.
        if version.is_some() || metadata.is_ok() {
            check_peer_version(
                version.as_deref(),
                registry_platform_buildinfo::DISPLAY_VERSION,
            )?;
        } else if matches!(
            metadata,
            Err(BaseRegistryClientError::Protocol { status: 200, .. })
        ) {
            return Err(ReviewContextError::VersionUnavailable);
        }
        let metadata = metadata.map_err(map_error)?.value;
        // Current caller-visible metadata selects only the exact purpose and action.
        // The reply binds the exported context contract, independently of unrelated
        // changes to the registry package.
        if display {
            metadata.select_proposal_review_context(profile, &self.export.action_id)
        } else {
            metadata.select_proposal_review_status(profile, &self.export.action_id)
        }
        .map_err(|_| ReviewContextError::Concealed)
    }

    async fn read_bound(
        &self,
        client: &BaseRegistryClient,
        identity: &ReviewContextIdentity,
        binding: &BRegProposalReviewBinding,
        display: bool,
    ) -> Result<BRegProposalReviewDocument, ReviewContextError> {
        if identity.contract != self.export.contract
            || identity.subject.source != self.export.source_namespace
            || identity.subject.subject_type != "proposal"
        {
            return Err(ReviewContextError::ContractChanged);
        }
        let document = client
            .read_proposal_review_by_id(binding, &identity.subject.id)
            .await
            .map_err(|error| match error {
                // A context reply without the owning closed contract is not
                // the interface this paired provider was authorized to use.
                BaseRegistryClientError::InvalidRequest { .. } if display => {
                    ReviewContextError::ContractChanged
                }
                error => map_error(error),
            })?
            .value;
        self.validate_bound(identity, document)
    }

    fn validate_bound(
        &self,
        identity: &ReviewContextIdentity,
        document: BRegProposalReviewDocument,
    ) -> Result<BRegProposalReviewDocument, ReviewContextError> {
        if document.subject.source != identity.subject.source
            || document.subject.subject_type != identity.subject.subject_type
            || document.subject.id != identity.subject.id
            || document.subject.version != identity.subject.version
            || document.subject.digest != identity.subject.digest.as_str()
        {
            return Err(ReviewContextError::BindingMoved);
        }
        if !document.context.contract.as_ref().is_some_and(|contract| {
            contract.id == self.export.contract.id
                && contract.revision == self.export.contract.revision.as_str()
                && contract.schema_digest == self.export.contract.schema_digest.as_str()
        }) {
            return Err(ReviewContextError::ContractChanged);
        }
        Ok(document)
    }

    async fn display_batch_with_client(
        &self,
        identities: &[ReviewContextIdentity],
        source_profile_id: &str,
        client: &BaseRegistryClient,
    ) -> Vec<Result<HumanDisplayObservation, ReviewContextError>> {
        let valid = |identity: &ReviewContextIdentity| self.validate_identity(identity).is_ok();
        let ids = identities
            .iter()
            .filter(|identity| valid(identity))
            .map(|identity| identity.subject.id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let documents = match self.read_binding(client, source_profile_id, true).await {
            Ok(binding) => client
                .read_proposal_review_context_batch(&binding, &ids)
                .await
                .map(|reply| {
                    ids.iter()
                        .copied()
                        .zip(reply.value)
                        .collect::<std::collections::BTreeMap<_, _>>()
                })
                .map_err(|error| match error {
                    BaseRegistryClientError::InvalidRequest { .. } => {
                        ReviewContextError::ContractChanged
                    }
                    error => map_error(error),
                }),
            Err(error) => Err(error),
        };
        identities
            .iter()
            .map(|identity| {
                if !valid(identity) {
                    return Err(ReviewContextError::ContractChanged);
                }
                match &documents {
                    Ok(documents) => documents
                        .get(identity.subject.id.as_str())
                        .and_then(|document| document.clone())
                        .ok_or(ReviewContextError::Concealed)
                        .and_then(|document| self.validate_bound(identity, document))
                        .and_then(|document| self.display_observation(identity, document)),
                    Err(error) => Err(*error),
                }
            })
            .collect()
    }

    fn task_projection_schema(
        &self,
        fields: &[String],
    ) -> Result<serde_json::Value, ReviewContextError> {
        let source = self
            .export
            .schema
            .as_object()
            .ok_or(ReviewContextError::Invalid)?;
        let properties = source
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .ok_or(ReviewContextError::Invalid)?;
        let selected = fields
            .iter()
            .map(|field| {
                properties
                    .get(field)
                    .cloned()
                    .map(|definition| (field.clone(), definition))
                    .ok_or(ReviewContextError::ContractChanged)
            })
            .collect::<Result<serde_json::Map<_, _>, _>>()?;
        if selected.len() != fields.len() {
            return Err(ReviewContextError::ContractChanged);
        }
        let mut pending = std::collections::BTreeSet::new();
        collect_definition_references(&serde_json::Value::Object(selected.clone()), &mut pending)?;
        let mut processed = std::collections::BTreeSet::new();
        let mut retained: std::collections::BTreeMap<
            &str,
            serde_json::Map<String, serde_json::Value>,
        > = std::collections::BTreeMap::new();
        while let Some((container, name)) = pending.iter().next().cloned() {
            pending.remove(&(container, name.clone()));
            if !processed.insert((container, name.clone())) {
                continue;
            }
            let definition = source
                .get(container)
                .and_then(serde_json::Value::as_object)
                .and_then(|definitions| definitions.get(&name))
                .cloned()
                .ok_or(ReviewContextError::ContractChanged)?;
            let mut nested = std::collections::BTreeSet::new();
            collect_definition_references(&definition, &mut nested)?;
            pending.extend(
                nested
                    .into_iter()
                    .filter(|reference| !processed.contains(reference)),
            );
            retained
                .entry(container)
                .or_default()
                .insert(name, definition);
        }
        let mut reduced = serde_json::Map::new();
        for keyword in ["$schema", "$id"] {
            if let Some(value) = source.get(keyword) {
                reduced.insert(keyword.to_owned(), value.clone());
            }
        }
        reduced.insert("type".into(), serde_json::json!("object"));
        reduced.insert(
            "additionalProperties".into(),
            serde_json::Value::Bool(false),
        );
        reduced.insert("required".into(), serde_json::json!(fields));
        reduced.insert("properties".into(), serde_json::Value::Object(selected));
        for (container, definitions) in retained {
            reduced.insert(container.to_owned(), serde_json::Value::Object(definitions));
        }
        Ok(serde_json::Value::Object(reduced))
    }
}
impl BregContextProvider {
    fn display_observation(
        &self,
        identity: &ReviewContextIdentity,
        document: BRegProposalReviewDocument,
    ) -> Result<HumanDisplayObservation, ReviewContextError> {
        let fields = document.context.fields.ok_or(ReviewContextError::Invalid)?;
        let schema = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&self.export.schema)
            .map_err(|_| ReviewContextError::Invalid)?;
        if !schema
            .is_valid(&serde_json::to_value(&fields).map_err(|_| ReviewContextError::Invalid)?)
        {
            return Err(ReviewContextError::Invalid);
        }
        let display_reference = Some(document.context.reference);
        Ok(HumanDisplayObservation {
            identity: identity.clone(),
            reviewable: document.reviewable,
            display_reference,
            fields,
        })
    }
}

#[async_trait]
impl ReviewContextProvider for BregContextProvider {
    fn provider_id(&self) -> &str {
        &self.id
    }
    fn capabilities(&self) -> &[ReviewContextCapability] {
        SERVED_CAPABILITIES
    }
    async fn human_display(
        &self,
        request: HumanDisplayRequest<'_>,
    ) -> Result<HumanDisplayObservation, ReviewContextError> {
        // Override every configured service token for this one exact human read.
        let token = BearerToken::new(request.credential.expose().to_owned())
            .map_err(|_| ReviewContextError::Denied)?;
        let client = self.client.with_bearer_token(token);
        let document = self
            .read(&client, request.identity, request.source_profile_id, true)
            .await?;
        self.display_observation(request.identity, document)
    }
    async fn human_display_batch(
        &self,
        identities: &[ReviewContextIdentity],
        source_profile_id: &str,
        credential: EphemeralCredential<'_>,
    ) -> Vec<Result<HumanDisplayObservation, ReviewContextError>> {
        if identities.len() > 100 {
            return vec![Err(ReviewContextError::Invalid); identities.len()];
        }
        let token = match BearerToken::new(credential.expose().to_owned()) {
            Ok(token) => token,
            Err(_) => return vec![Err(ReviewContextError::Denied); identities.len()],
        };
        if !identities
            .iter()
            .any(|identity| self.validate_identity(identity).is_ok())
        {
            return vec![Err(ReviewContextError::ContractChanged); identities.len()];
        }
        let client = self.client.with_bearer_token(token);
        // Metadata is current and caller-visible for this invocation only.
        // Every subject still passes its own current disclosure read.
        self.display_batch_with_client(identities, source_profile_id, &client)
            .await
    }
    async fn delegated_display(
        &self,
        request: DelegatedDisplayRequest<'_>,
    ) -> Result<HumanDisplayObservation, ReviewContextError> {
        self.validate_identity(request.identity)?;
        let exchange = self
            .delegated_display_exchange
            .as_ref()
            .ok_or(ReviewContextError::Denied)?;
        let token = exchange
            .bearer(request.credential, request.credential_context)
            .await?;
        let client = self.client.with_bearer_token(token);
        let document = self
            .read(&client, request.identity, request.source_profile_id, true)
            .await?;
        self.display_observation(request.identity, document)
    }
    async fn delegated_display_batch(
        &self,
        identities: &[ReviewContextIdentity],
        source_profile_id: &str,
        credential: EphemeralCredential<'_>,
        credential_context: &DelegatedCredentialContext,
    ) -> Vec<Result<HumanDisplayObservation, ReviewContextError>> {
        if identities.len() > 100 {
            return vec![Err(ReviewContextError::Invalid); identities.len()];
        }
        if !identities
            .iter()
            .any(|identity| self.validate_identity(identity).is_ok())
        {
            return vec![Err(ReviewContextError::ContractChanged); identities.len()];
        }
        let Some(exchange) = self.delegated_display_exchange.as_ref() else {
            return vec![Err(ReviewContextError::Denied); identities.len()];
        };
        let token = match exchange.bearer(credential, credential_context).await {
            Ok(token) => token,
            Err(error) => return vec![Err(error); identities.len()],
        };
        let client = self.client.with_bearer_token(token);
        self.display_batch_with_client(identities, source_profile_id, &client)
            .await
    }
    async fn service_status(
        &self,
        identity: &ReviewContextIdentity,
    ) -> Result<ServiceStatusObservation, ReviewContextError> {
        let document = self
            .read(&self.client, identity, &self.status_profile, false)
            .await?;
        // A status credential is never used for a display or field projection.
        if document.context.fields.is_some() {
            return Err(ReviewContextError::Invalid);
        }
        Ok(ServiceStatusObservation {
            identity: identity.clone(),
            reviewable: document.reviewable,
        })
    }

    async fn task_grant_context(
        &self,
        request: &ServiceContextRequest,
    ) -> Result<ServiceContextObservation, ReviewContextError> {
        let profile = self
            .task_grant_profile
            .as_deref()
            .ok_or(ReviewContextError::Unsupported)?;
        if request.identity.subject.check().is_err()
            || request.request_id.is_nil()
            || request.task_id.is_nil()
            || request.task_revision < 1
            || request.policy.check().is_err()
            || request.purpose.is_empty()
            || request.purpose.len() > 128
            || request.purpose.chars().any(char::is_control)
            || request.fields.is_empty()
            || request.fields.len() > 128
            || request
                .fields
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != request.fields.len()
        {
            return Err(ReviewContextError::Invalid);
        }
        if request.identity.contract != self.export.contract
            || request.identity.subject.source != self.export.source_namespace
            || request.identity.subject.subject_type != "proposal"
        {
            return Err(ReviewContextError::ContractChanged);
        }
        let schema = self.task_projection_schema(&request.fields)?;
        let (version, metadata) = self
            .client
            .registry_contract_and_engine_version(Some(profile))
            .await;
        if version.is_some() || metadata.is_ok() {
            check_peer_version(
                version.as_deref(),
                registry_platform_buildinfo::DISPLAY_VERSION,
            )?;
        } else if matches!(
            metadata,
            Err(BaseRegistryClientError::Protocol { status: 200, .. })
        ) {
            return Err(ReviewContextError::VersionUnavailable);
        }
        let metadata = metadata.map_err(map_error)?.value;
        let binding = metadata
            .select_proposal_task_grant_context(profile, &self.export.action_id)
            .map_err(|_| ReviewContextError::Concealed)?;
        if !request
            .fields
            .iter()
            .all(|field| binding.readable_context_fields().contains(field))
        {
            return Err(ReviewContextError::Denied);
        }
        let wire_request = BRegProposalTaskContextRequest {
            expected: BRegProposalTaskContextIdentity {
                action_id: self.export.action_id.clone(),
                subject: BRegProposalReviewSubject {
                    source: request.identity.subject.source.clone(),
                    subject_type: request.identity.subject.subject_type.clone(),
                    id: request.identity.subject.id.clone(),
                    version: request.identity.subject.version.clone(),
                    digest: request.identity.subject.digest.as_str().to_owned(),
                },
                contract: BRegProposalReviewContextContract {
                    id: request.identity.contract.id.clone(),
                    revision: request.identity.contract.revision.as_str().to_owned(),
                    schema_digest: request.identity.contract.schema_digest.as_str().to_owned(),
                },
            },
            request_id: request.request_id,
            task_id: request.task_id,
            task_revision: request.task_revision,
            policy: request.policy.clone(),
            purpose: request.purpose.clone(),
            fields: request.fields.clone(),
        };
        let document = self
            .client
            .read_proposal_task_grant_context(&binding, &wire_request)
            .await
            .map_err(map_error)?
            .value
            .proposal;
        let document = self.validate_bound(&request.identity, document)?;
        let fields = document.context.fields.ok_or(ReviewContextError::Invalid)?;
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .map_err(|_| ReviewContextError::Invalid)?;
        if !validator
            .is_valid(&serde_json::to_value(&fields).map_err(|_| ReviewContextError::Invalid)?)
        {
            return Err(ReviewContextError::Invalid);
        }
        let observed = ServiceContextObservation {
            request: request.clone(),
            reviewable: document.reviewable,
            fields,
        };
        observed.check(request)?;
        Ok(observed)
    }
}

fn collect_definition_references(
    value: &serde_json::Value,
    references: &mut std::collections::BTreeSet<(&'static str, String)>,
) -> Result<(), ReviewContextError> {
    match value {
        serde_json::Value::Object(object) => {
            for member in ["$ref", "$dynamicRef", "$recursiveRef"] {
                if let Some(reference) = object.get(member) {
                    let reference = reference
                        .as_str()
                        .ok_or(ReviewContextError::ContractChanged)?;
                    let (container, tail) = ["$defs", "definitions"]
                        .into_iter()
                        .find_map(|container| {
                            reference
                                .strip_prefix(&format!("#/{container}/"))
                                .map(|tail| (container, tail))
                        })
                        .ok_or(ReviewContextError::ContractChanged)?;
                    let name = tail
                        .split('/')
                        .next()
                        .filter(|name| !name.is_empty())
                        .ok_or(ReviewContextError::ContractChanged)?;
                    let name = decode_json_pointer_segment(name)?;
                    references.insert((container, name));
                }
            }
            for nested in object.values() {
                collect_definition_references(nested, references)?;
            }
        }
        serde_json::Value::Array(values) => {
            for nested in values {
                collect_definition_references(nested, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn decode_json_pointer_segment(value: &str) -> Result<String, ReviewContextError> {
    let mut decoded = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        decoded.push(match characters.next() {
            Some('0') => '~',
            Some('1') => '/',
            _ => return Err(ReviewContextError::ContractChanged),
        });
    }
    Ok(decoded)
}
fn map_error(error: BaseRegistryClientError) -> ReviewContextError {
    match error {
        BaseRegistryClientError::Problem {
            status: 401 | 403 | 404,
            ..
        }
        | BaseRegistryClientError::UnrecognizedProblem {
            status: 401 | 403 | 404,
            ..
        } => ReviewContextError::Concealed,
        BaseRegistryClientError::Transport { .. } | BaseRegistryClientError::Token(_) => {
            ReviewContextError::Unavailable
        }
        BaseRegistryClientError::Problem {
            status: 409 | 412, ..
        } => ReviewContextError::BindingMoved,
        BaseRegistryClientError::Problem {
            status: 500..=599, ..
        }
        | BaseRegistryClientError::UnrecognizedProblem {
            status: 500..=599, ..
        } => ReviewContextError::Unavailable,
        _ => ReviewContextError::Invalid,
    }
}

fn check_peer_version(actual: Option<&str>, expected: &str) -> Result<(), ReviewContextError> {
    match actual {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => Err(ReviewContextError::VersionMismatch),
        None => Err(ReviewContextError::VersionUnavailable),
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn projection_provider(schema: serde_json::Value) -> BregContextProvider {
        BregContextProvider {
            id: "provider".into(),
            export: BregContextExport {
                api_version: DESCRIPTION_API_VERSION.into(),
                kind: DESCRIPTION_KIND.into(),
                source_namespace: "source".into(),
                action_id: "action".into(),
                context_id: "context".into(),
                contract: ReviewContextContract {
                    id: "urn:registry:breg:review-context:source:action:context".into(),
                    revision: ContentDigest::parse(DIGEST).unwrap(),
                    schema_digest: ContentDigest::parse(DIGEST).unwrap(),
                },
                schema,
                schema_bytes: "{}".into(),
            },
            client: BaseRegistryClient::new(registry_breg_client::BaseRegistryClientConfig::new(
                "http://127.0.0.1/".parse().unwrap(),
            ))
            .unwrap(),
            status_profile: "status".into(),
            task_grant_profile: None,
            delegated_display_exchange: None,
        }
    }

    #[test]
    fn lockstep_accepts_exact_release_and_dev_identity_without_normalization() {
        for version in ["1.2.3", "1.2.3-dev"] {
            assert_eq!(check_peer_version(Some(version), version), Ok(()));
        }
        for actual in ["1.2.2", "1.2.3-dev", "1.2.3+other"] {
            assert_eq!(
                check_peer_version(Some(actual), "1.2.3"),
                Err(ReviewContextError::VersionMismatch)
            );
        }
        assert_eq!(
            check_peer_version(None, "1.2.3"),
            Err(ReviewContextError::VersionUnavailable)
        );
    }

    #[tokio::test]
    async fn delegated_exchange_uses_exact_source_authority() {
        use registry_platform_testing::{
            fixtures, ExchangeProfile, TestActorKind, TestAuthorizationServer, TestClient,
        };
        use serde_json::json;
        use std::{collections::BTreeMap, time::SystemTime};

        const CASEWORK_RESOURCE: &str = "urn:casework:test";
        const BREG_RESOURCE: &str = "urn:breg:test";
        const SOURCE_CLIENT: &str = "casework-source-reader";
        const SOURCE_ACTOR: &str = "00000000-0000-4000-8000-0000000000c7";
        let (source_key, source_public) = fixtures::ed25519_pair();
        let server = TestAuthorizationServer::builder()
            .exchange_profile(ExchangeProfile::IssuerQualifiedActor)
            .client(
                TestClient::new("casework-gateway")
                    .with_resource(CASEWORK_RESOURCE)
                    .with_actor_kind(TestActorKind::Human),
            )
            .client(
                TestClient::new(SOURCE_CLIENT)
                    .with_public_jwk(source_public)
                    .with_resource(BREG_RESOURCE)
                    .with_service_subject(SOURCE_ACTOR)
                    .with_exchange_subject_claim("registry_principal")
                    .with_exchange_subject_claim("registry_purpose")
                    .with_exchange_subject_claim("jurisdiction")
                    .with_exchange_subject_resource(CASEWORK_RESOURCE)
                    .with_exchange_scope_grant(
                        "casework:staff:delegated-read",
                        "registry:proposal:review",
                    ),
            )
            .start()
            .await;
        let expires_at = i64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
            + 60;
        let subject = server.issue_access_token_with_claims(
            "casework-gateway",
            "staff-subject",
            CASEWORK_RESOURCE,
            "casework:staff:delegated-read",
            expires_at,
            BTreeMap::from([
                ("registry_principal".into(), json!("staff-subject")),
                ("registry_purpose".into(), json!("facility-review")),
                ("jurisdiction".into(), json!("zone-a")),
                ("not_allowlisted".into(), json!("must-not-propagate")),
            ]),
        );
        let exchange = DelegatedDisplayExchange::new(
            server.token_endpoint().parse().unwrap(),
            SOURCE_CLIENT.into(),
            source_key,
            None,
            BREG_RESOURCE.into(),
            vec!["registry:proposal:review".into()],
            "test-generation".into(),
        )
        .unwrap();
        exchange
            .bearer(
                EphemeralCredential::new(&subject),
                &DelegatedCredentialContext::verified(
                    server.issuer(),
                    "staff-subject".into(),
                    CASEWORK_RESOURCE.into(),
                    expires_at,
                ),
            )
            .await
            .expect("the independently authorized source exchange succeeds");

        let observations = server.exchange_observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].client_id, SOURCE_CLIENT);
        assert_eq!(observations[0].resource, BREG_RESOURCE);
        assert_eq!(observations[0].scopes, ["registry:proposal:review"]);
        assert_eq!(observations[0].subject_issuer, server.issuer());
        assert_eq!(
            observations[0].subject_resource.as_deref(),
            Some(CASEWORK_RESOURCE)
        );
        assert_eq!(observations[0].subject, "staff-subject");
        assert_eq!(observations[0].actor_subject.as_deref(), Some(SOURCE_ACTOR));
        assert_eq!(
            observations[0].actor_issuer.as_deref(),
            Some(server.issuer().as_str())
        );
        assert_eq!(
            observations[0].propagated_claims,
            BTreeMap::from([
                ("jurisdiction".into(), json!("zone-a")),
                ("registry_principal".into(), json!("staff-subject")),
                ("registry_purpose".into(), json!("facility-review")),
            ])
        );
    }

    #[test]
    fn delegated_exchange_refuses_ambiguous_authority_configuration() {
        use registry_platform_testing::fixtures;

        let invalid = [
            ("", vec!["registry:proposal:review"], "generation"),
            (
                "urn:breg:test",
                vec!["registry:proposal:review", "registry:proposal:review"],
                "generation",
            ),
            (
                "urn:breg:test",
                vec!["registry proposal review"],
                "generation",
            ),
            ("urn:breg:test", vec!["registry:proposal:review"], ""),
        ];
        for (resource, scopes, generation) in invalid {
            let result = DelegatedDisplayExchange::new(
                "https://idp.example.test/token".parse().unwrap(),
                "casework-source-reader".into(),
                fixtures::ed25519_pair().0,
                None,
                resource.into(),
                scopes.into_iter().map(str::to_owned).collect(),
                generation.into(),
            );
            assert!(matches!(result, Err(ReviewContextError::Invalid)));
        }
    }

    #[test]
    fn task_projection_keeps_only_definitions_reachable_from_selected_properties() {
        let provider = projection_provider(serde_json::json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "$id":"urn:source-context",
            "type":"object",
            "required":["selected","ignored"],
            "properties":{
                "selected":{"$ref":"#/$defs/Zed"},
                "ignored":{"$ref":"https://untrusted.invalid/schema"}
            },
            "$defs":{
                "Zed":{"type":"object","required":["value"],"properties":{"value":{"$ref":"#/$defs/Alpha"}}},
                "Alpha":{"type":"string","maxLength":8},
                "Ignored":{"$ref":"https://untrusted.invalid/schema"}
            }
        }));
        let projected = provider
            .task_projection_schema(&["selected".into()])
            .unwrap();
        assert!(projected["$defs"].get("Zed").is_some());
        assert!(projected["$defs"].get("Alpha").is_some());
        assert!(projected["$defs"].get("Ignored").is_none());
        assert_eq!(projected["required"], serde_json::json!(["selected"]));
        assert!(provider
            .task_projection_schema(&["ignored".into()])
            .is_err());
    }
}

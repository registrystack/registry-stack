use crate::{PostgresStore, StoreError};
use registry_casework_core::{CaseworkProject, InboxPolicy, ReviewContextProvider};
use std::collections::BTreeMap;
use std::sync::Arc;
#[derive(Clone)]
pub struct CaseworkService {
    pub(crate) store: PostgresStore,
    pub(crate) providers: Arc<BTreeMap<String, Arc<dyn ReviewContextProvider>>>,
    pub(crate) project: Arc<CaseworkProject>,
    pub(crate) task_authority: Option<Arc<crate::task_grants::TaskAuthority>>,
}
impl std::fmt::Debug for CaseworkService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaseworkService")
            .field("providers", &self.providers.keys())
            .field("project", &self.project.project.id)
            .finish()
    }
}
impl CaseworkService {
    pub fn new(
        store: PostgresStore,
        project: CaseworkProject,
        providers: impl IntoIterator<Item = Arc<dyn ReviewContextProvider>>,
    ) -> Result<Self, ServiceError> {
        let mut registered = BTreeMap::new();
        for provider in providers {
            if registered
                .insert(provider.provider_id().to_owned(), provider)
                .is_some()
            {
                return Err(ServiceError::Configuration);
            }
        }
        for policy in &project.review_policies {
            if let registry_casework_core::ReviewContextPolicy::CurrentSource { provider, .. } =
                &policy.context
            {
                if !project.context_providers.iter().any(|p| p.id == *provider) {
                    return Err(ServiceError::Configuration);
                }
                if let Some(loaded) = registered.get(provider) {
                    if project
                        .required_context_capabilities(policy)
                        .iter()
                        .any(|c| !loaded.capabilities().contains(c))
                    {
                        return Err(ServiceError::Configuration);
                    }
                }
            }
        }
        Ok(Self {
            store: store.with_context_providers(Arc::new(registered.clone())),
            providers: Arc::new(registered),
            project: Arc::new(project),
            task_authority: None,
        })
    }
    pub fn store(&self) -> &PostgresStore {
        &self.store
    }
    pub fn inbox_policy(&self) -> &InboxPolicy {
        &self.project.inbox
    }
    pub async fn ready(&self) -> Result<(), ServiceError> {
        self.store.ready().await?;
        if !self.store.audit_ready().await {
            return Err(StoreError::AuditUnavailable.into());
        }
        Ok(())
    }
}
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("the Casework service configuration is invalid")]
    Configuration,
    #[error("the requested review task was not found")]
    NotFound,
    #[error("the caller is not authorized")]
    Forbidden,
    #[error(transparent)]
    ReviewValidation(#[from] registry_casework_core::ReviewValidationError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Context(#[from] registry_casework_core::ReviewContextError),
}

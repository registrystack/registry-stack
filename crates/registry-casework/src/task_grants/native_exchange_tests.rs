//! Actual Casework approval -> native RFC 8693 exchange -> BREG PostgreSQL mutation.
//! Credentials and protected response bodies stay in memory and never enter logs or argv.
use super::*;
use async_trait::async_trait;
use axum::{body::{to_bytes, Body}, http::{Request, StatusCode}, Router};
use registry_casework_core::*;
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use registry_platform_httputil::{PrivateKeyJwt, PrivateKeyJwtConfig, TokenProvider};
use registry_thunderid_tooling::{description::*, local, render, container::Session};
use std::{collections::BTreeMap, sync::{Arc, atomic::{AtomicUsize,Ordering}}, time::Duration, path::Path, os::unix::fs::PermissionsExt};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD,Engine};
#[path = "native_resource.rs"]
mod resource;
const CASEWORK_RESOURCE: &str = "urn:casework:native-task";
const BREG_RESOURCE: &str = "urn:breg:task-test";
const AUTHORITY: &str = "https://casework.example";
const IMAGE: &str = "sha256:9f16ec5995a5d23220055fba152f7d8d32fdde5083f87866fbe345b53810ce79";
fn binding() -> SourceBinding {
    SourceBinding {
        source_revision: "1".into(),
        version: "proposal-1".into(),
        integrity: None,
        generation: "generation-1".into(),
    }
}
struct Source {
    mode: Arc<AtomicUsize>,
}
#[async_trait]
impl SourceAdapter for Source {
    fn source_id(&self) -> &str {
        "source"
    }
    fn binding_generation(&self) -> &str {
        "generation-1"
    }
    async fn verify_transition(
        &self,
        _: EventRequest,
    ) -> Result<TransitionHint, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }
    async fn read_authoritative(
        &self,
        _: &SubjectRef,
    ) -> Result<AuthoritativeObservation, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }
    async fn discover_active(
        &self,
        _: Option<&DiscoveryCursor>,
        _: usize,
    ) -> Result<ActiveSubjectsPage, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }
    async fn read_for_caller(
        &self,
        subject: &SubjectRef,
        _: &str,
        _: EphemeralCredential<'_>,
    ) -> Result<CallerSubjectView, SourceAdapterError> {
        Ok(CallerSubjectView {
            display_reference: None,
            subject: subject.clone(),
            binding: binding(),
            disclosed: Default::default(),
            permitted_operations: Vec::new(),
        })
    }
    async fn read_task_context(
        &self,
        _: &SubjectRef,
        fields: &[String],
        caller: Option<(&str, EphemeralCredential<'_>)>,
    ) -> Result<TaskSubjectContext, SourceAdapterError> {
        assert_eq!(fields, &["tenant"]);
        match self.mode.load(Ordering::SeqCst) {
            1 => return Err(SourceAdapterError::Unavailable),
            3 if caller.is_some() => return Err(SourceAdapterError::Denied),
            4 if caller.is_none() => {
                tokio::time::sleep(std::time::Duration::from_millis(1250)).await
            }
            _ => (),
        }
        let person = if self.mode.load(Ordering::SeqCst) == 2 {
            "different-person"
        } else {
            "tenant-a"
        };
        Ok(TaskSubjectContext {
            binding: binding(),
            values: std::collections::BTreeMap::from([("tenant".into(), json!(person))]),
        })
    }
    async fn prepare_action(
        &self,
        _: PrepareActionRequest<'_>,
    ) -> Result<PreparedSourceAttempt, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }
    async fn execute_prepared(
        &self,
        _: ExecutePreparedRequest<'_>,
    ) -> Result<SourceReceipt, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }
}


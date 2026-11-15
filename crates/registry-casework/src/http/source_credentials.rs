//! Closed, invocation-local admission for a separately issued human source bearer.
use super::*;
use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::{request::Parts, Method};
use zeroize::Zeroizing;

#[derive(Clone)]
struct ScopedState(HttpState);

/// State is overridden only inside one admitted request, never in the router.
pub(super) struct RequestState(pub HttpState);
impl FromRequestParts<HttpState> for RequestState {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &HttpState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ScopedState>()
                .map_or_else(|| state.clone(), |scope| scope.0.clone()),
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Collection,
    Task(Uuid),
    Request(Uuid),
}

fn target(method: &Method, path: &str) -> Option<Target> {
    if method == Method::GET
        && [
            "/v1/review-tasks",
            "/v1/review-tasks/next",
            "/v1/review-tasks/holdings",
            "/v1/review-tasks/own-decisions",
            "/v1/review-tasks/supervision",
        ]
        .contains(&path)
    {
        return Some(Target::Collection);
    }
    if method == Method::POST
        && [
            "/v1/directory/clocks/recompute/preview",
            "/v1/directory/clocks/recompute/apply",
            "/v1/directory/caseload/preview",
            "/v1/directory/caseload/apply",
        ]
        .contains(&path)
    {
        return Some(Target::Collection);
    }
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() < 4 || !parts[0].is_empty() || parts[1] != "v1" {
        return None;
    }
    let id = Uuid::parse_str(parts[3]).ok()?;
    let suffix = parts.get(4).copied().unwrap_or("");
    if parts[2] == "review-tasks" && parts.len() <= 5 {
        let admitted = (method == Method::GET
            && ["", "context", "draft", "task-templates", "task-grants"].contains(&suffix))
            || (method == Method::POST
                && ["claim", "assign", "delegate", "decisions", "task-grants"].contains(&suffix))
            || ((method == Method::PUT || method == Method::DELETE) && suffix == "draft");
        return admitted.then_some(Target::Task(id));
    }
    if parts[2] == "review-requests"
        && parts.len() == 5
        && ((method == Method::GET && ["history", "clocks"].contains(&suffix))
            || (method == Method::POST && suffix == "notes"))
    {
        return Some(Target::Request(id));
    }
    None
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, HttpError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(HttpError::Invalid)?;
    if values.next().is_some() {
        return Err(HttpError::Invalid);
    }
    value.to_str().map_err(|_| HttpError::Invalid)
}

pub(super) async fn boundary(
    State(state): State<HttpState>,
    mut request: Request,
    next: Next,
) -> Response {
    if !request.headers().contains_key(SOURCE_AUTHORIZATION_HEADER) {
        return next.run(request).await;
    }
    let admitted = admit(
        &state,
        request.method(),
        request.uri().path(),
        request.headers(),
    )
    .await;
    match admitted {
        Ok(state) => {
            request.extensions_mut().insert(ScopedState(state));
            next.run(request).await
        }
        Err(error) => error.into_response(),
    }
}

/// Target-dependent admission must preserve the ordinary concealed-row shape.
/// A bad source credential cannot reveal a stored policy or target's existence.
fn conceal_target_error(target: Target, error: HttpError) -> HttpError {
    match (target, error) {
        (
            Target::Task(_) | Target::Request(_),
            HttpError::AuthenticationRefused
            | HttpError::NotFound
            | HttpError::SourceProfileNotApplicable,
        ) => HttpError::NotFound,
        (_, error) => error,
    }
}

async fn admit(
    state: &HttpState,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
) -> Result<HttpState, HttpError> {
    let target = target(method, path).ok_or(HttpError::Invalid)?;
    let source = parse_bearer_token(single_header(headers, SOURCE_AUTHORIZATION_HEADER)?)
        .map_err(|_| HttpError::AuthenticationRefused)?;
    registry_platform_authcommon::validate_compact_access_token(source)
        .map_err(|_| HttpError::AuthenticationRefused)?;
    single_header(headers, AUTHORIZATION.as_str())?;
    single_header(headers, CASEWORK_PROFILE_HEADER)?;
    if !headers.contains_key(SOURCE_PROFILE_HEADER) {
        return Err(HttpError::SourceProfileRequired);
    }
    let profile = single_header(headers, SOURCE_PROFILE_HEADER)?;
    if !registry_casework_core::valid_profile_identifier(profile) {
        return Err(HttpError::Invalid);
    }
    let (actor, primary) = authenticate(state, headers).await?;
    if actor.role == CaseworkActsAs::Requester {
        return Err(HttpError::ProfileNotAuthorized);
    }
    let provider = state
        .service
        .human_source_provider(
            match target {
                Target::Task(id) => Some(id),
                _ => None,
            },
            match target {
                Target::Request(id) => Some(id),
                _ => None,
            },
        )
        .await
        .map_err(|error| conceal_target_error(target, error.into()))?;
    // This fatal verification precedes any inbox observation, even empty pages.
    state
        .authenticator
        .verify_human_source_pair(primary, source, &provider)
        .await
        .map_err(|_| conceal_target_error(target, HttpError::AuthenticationRefused))?;
    let original = state
        .service
        .providers
        .get(&provider)
        .ok_or_else(|| conceal_target_error(target, HttpError::AuthenticationRefused))?;
    let scoped = VerifiedSourceProvider {
        inner: Arc::clone(original),
        token: Zeroizing::new(source.to_owned()),
        profile: profile.to_owned(),
    };
    let mut providers = (*state.service.providers).clone();
    providers.insert(provider, Arc::new(scoped));
    let mut state = state.clone();
    state.service.providers = Arc::new(providers);
    Ok(state)
}

/// Only constructed after cryptographic same-human and exact provider admission.
/// The request owns this handle; no store or process-wide cache receives it.
struct VerifiedSourceProvider {
    inner: Arc<dyn ReviewContextProvider>,
    token: Zeroizing<String>,
    profile: String,
}
impl std::fmt::Debug for VerifiedSourceProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedSourceProvider(<redacted>)")
    }
}
#[async_trait]
impl ReviewContextProvider for VerifiedSourceProvider {
    fn provider_id(&self) -> &str {
        self.inner.provider_id()
    }
    fn capabilities(&self) -> &[ReviewContextCapability] {
        self.inner.capabilities()
    }
    async fn human_display(
        &self,
        request: HumanDisplayRequest<'_>,
    ) -> Result<HumanDisplayObservation, ReviewContextError> {
        if request.source_profile_id != self.profile {
            return Err(ReviewContextError::Denied);
        }
        self.inner
            .human_display(HumanDisplayRequest {
                identity: request.identity,
                source_profile_id: &self.profile,
                credential: EphemeralCredential::new(&self.token),
            })
            .await
    }
    async fn human_display_batch(
        &self,
        identities: &[ReviewContextIdentity],
        profile: &str,
        _credential: EphemeralCredential<'_>,
    ) -> Vec<Result<HumanDisplayObservation, ReviewContextError>> {
        if profile != self.profile {
            return vec![Err(ReviewContextError::Denied); identities.len()];
        }
        self.inner
            .human_display_batch(
                identities,
                &self.profile,
                EphemeralCredential::new(&self.token),
            )
            .await
    }
    async fn service_status(
        &self,
        identity: &ReviewContextIdentity,
    ) -> Result<ServiceStatusObservation, ReviewContextError> {
        self.inner.service_status(identity).await
    }
    async fn task_grant_context(
        &self,
        request: &ServiceContextRequest,
    ) -> Result<ServiceContextObservation, ReviewContextError> {
        self.inner.task_grant_context(request).await
    }
    async fn routing_context(
        &self,
        request: &ServiceContextRequest,
    ) -> Result<ServiceContextObservation, ReviewContextError> {
        self.inner.routing_context(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn source_header_is_admitted_only_on_exact_ordinary_source_operations() {
        let id = "00000000-0000-4000-8000-000000000001";
        for (method, path) in [
            (Method::GET, "/v1/review-tasks".to_owned()),
            (Method::GET, "/v1/review-tasks/next".to_owned()),
            (Method::GET, "/v1/review-tasks/holdings".to_owned()),
            (Method::GET, "/v1/review-tasks/own-decisions".to_owned()),
            (Method::GET, "/v1/review-tasks/supervision".to_owned()),
            (
                Method::POST,
                "/v1/directory/clocks/recompute/preview".to_owned(),
            ),
            (
                Method::POST,
                "/v1/directory/clocks/recompute/apply".to_owned(),
            ),
            (Method::POST, "/v1/directory/caseload/preview".to_owned()),
            (Method::POST, "/v1/directory/caseload/apply".to_owned()),
        ] {
            assert!(target(&method, &path).is_some(), "{method} {path}");
        }
        for suffix in ["", "/context", "/draft", "/task-templates", "/task-grants"] {
            assert_eq!(
                target(&Method::GET, &format!("/v1/review-tasks/{id}{suffix}")),
                Some(Target::Task(Uuid::parse_str(id).unwrap()))
            );
        }
        for suffix in ["claim", "assign", "delegate", "decisions", "task-grants"] {
            assert!(target(&Method::POST, &format!("/v1/review-tasks/{id}/{suffix}")).is_some());
        }
        for method in [Method::PUT, Method::DELETE] {
            assert!(target(&method, &format!("/v1/review-tasks/{id}/draft")).is_some());
        }
        for suffix in ["history", "clocks"] {
            assert!(target(&Method::GET, &format!("/v1/review-requests/{id}/{suffix}")).is_some());
        }
        assert!(target(&Method::POST, &format!("/v1/review-requests/{id}/notes")).is_some());
        for path in [
            "/health",
            "/ready",
            "/v1/casework",
            "/v1/directory",
            "/v1/directory/targets",
            "/v1/directory/bootstrap",
            "/v1/directory/absences",
            "/v1/review-policies",
            "/v1/review-requests",
            "/v1/review-results",
            "/v1/delegated-staff/review-tasks",
        ] {
            for method in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
                assert!(target(&method, path).is_none());
            }
        }
        for path in [
            format!("/v1/review-tasks/{id}/release"),
            format!("/v1/review-tasks/{id}/task-grants/{id}/revoke"),
            format!("/v1/review-accountability/{id}"),
            format!("/v1/delegated-staff/review-tasks/{id}/context"),
            format!("/v1/task-grants/{id}/assertion"),
            format!("/v1/task-grants/{id}/status"),
            format!("/v1/review-requests/{id}/cancel"),
        ] {
            for method in [Method::GET, Method::POST] {
                assert!(target(&method, &path).is_none());
            }
        }
    }

    #[test]
    fn duplicate_and_non_text_source_selectors_are_not_chosen() {
        for name in [
            SOURCE_AUTHORIZATION_HEADER,
            SOURCE_PROFILE_HEADER,
            CASEWORK_PROFILE_HEADER,
            "authorization",
        ] {
            let mut headers = HeaderMap::new();
            assert!(single_header(&headers, name).is_err());
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                "first".parse().unwrap(),
            );
            assert_eq!(single_header(&headers, name).unwrap(), "first");
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                "second".parse().unwrap(),
            );
            assert!(single_header(&headers, name).is_err());
        }
    }

    struct Capture(Arc<Mutex<Vec<String>>>);
    #[async_trait]
    impl ReviewContextProvider for Capture {
        fn provider_id(&self) -> &str {
            "source"
        }
        fn capabilities(&self) -> &[ReviewContextCapability] {
            &[
                ReviewContextCapability::HumanDisplay,
                ReviewContextCapability::ServiceStatus,
            ]
        }
        async fn human_display(
            &self,
            request: HumanDisplayRequest<'_>,
        ) -> Result<HumanDisplayObservation, ReviewContextError> {
            self.0
                .lock()
                .unwrap()
                .push(request.credential.expose().to_owned());
            Ok(HumanDisplayObservation {
                identity: request.identity.clone(),
                reviewable: true,
                display_reference: None,
                fields: Default::default(),
            })
        }
        async fn service_status(
            &self,
            identity: &ReviewContextIdentity,
        ) -> Result<ServiceStatusObservation, ReviewContextError> {
            Ok(ServiceStatusObservation {
                identity: identity.clone(),
                reviewable: true,
            })
        }
    }

    #[tokio::test]
    async fn verified_provider_handles_do_not_forward_casework_or_mix_invocations() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let inner: Arc<dyn ReviewContextProvider> = Arc::new(Capture(captured.clone()));
        let first = VerifiedSourceProvider {
            inner: inner.clone(),
            token: Zeroizing::new("source-first-canary".into()),
            profile: "source-profile".into(),
        };
        let second = VerifiedSourceProvider {
            inner,
            token: Zeroizing::new("source-second-canary".into()),
            profile: "source-profile".into(),
        };
        assert!(!format!("{first:?}").contains("canary"));
        let digest = ContentDigest::parse(&format!("sha256:{}", "a".repeat(64))).unwrap();
        let identity = ReviewContextIdentity {
            subject: registry_casework_core::SubjectBinding {
                source: "source".into(),
                subject_type: "proposal".into(),
                id: "one".into(),
                version: "1".into(),
                digest: digest.clone(),
            },
            contract: ReviewContextContract {
                id: "context".into(),
                revision: digest.clone(),
                schema_digest: digest,
            },
        };
        let request = || HumanDisplayRequest {
            identity: &identity,
            source_profile_id: "source-profile",
            credential: EphemeralCredential::new("casework-canary"),
        };
        let (a, b) = tokio::join!(
            first.human_display(request()),
            second.human_display(request())
        );
        a.unwrap();
        b.unwrap();
        let mut tokens = captured.lock().unwrap().clone();
        tokens.sort();
        assert_eq!(tokens, ["source-first-canary", "source-second-canary"]);
        assert!(first
            .human_display(HumanDisplayRequest {
                identity: &identity,
                source_profile_id: "wrong",
                credential: EphemeralCredential::new("casework-canary")
            })
            .await
            .is_err());
        assert_eq!(captured.lock().unwrap().len(), 2);
    }
}

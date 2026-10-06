// SPDX-License-Identifier: Apache-2.0

//! The review page, its submit, and sign-out.
//!
//! Every request resolves in the same order: the request identifier's shape,
//! the session, the limit of the person it names, the form and its CSRF
//! token, and only then the registry. A submit re-reads the
//! draft and its target before it calls the registry, so a crafted form
//! cannot skip the check the page made before it offered the form.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use registry_breg_client::{BRegIdempotencyKey, BRegProblemCode};

use crate::journal::{Action, Operation, Outcome};
use crate::registry::{self, Profile, Refusal, Review};
use crate::session::{random_token, tokens_match, Current, View};
use crate::signin::single_valued;
use crate::templates::ReviewPage;
use crate::{canonical_uuid, cookie, App, Problem, MAXIMUM_FORM_BYTES};

/// A signed-in person and the session cookie that names them.
struct Caller<'a> {
    cookie: &'a str,
    session: Current,
}

/// Send a person with no live session to sign in again. A navigation is
/// redirected. A form post answers a page linking to sign-in instead, because
/// the content security policy's `form-action 'self'` covers the redirects a
/// form submission follows, and sign-in continues on the provider's origin.
fn sign_in_again(app: &App, request_id: &str, action: Action) -> Response {
    match action {
        Action::Submit => app.rendered(StatusCode::OK, app.templates.sign_in_again(request_id)),
        Action::SignIn | Action::Read | Action::SignOut => sign_in_redirect(request_id),
    }
}

fn sign_in_redirect(request_id: &str) -> Response {
    let location = format!("/signin?return=%2Frequests%2F{request_id}");
    (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            HeaderValue::from_str(&location).expect("a canonical UUID is header-safe"),
        )],
    )
        .into_response()
}

/// Admit a request for `/requests/{id}` made for `action`: the identifier's
/// shape, the session, and the limit of the person it names, in that order.
async fn admit<'a>(
    app: &App,
    action: Action,
    path: Result<Path<String>, PathRejection>,
    headers: &'a HeaderMap,
) -> Result<(String, Caller<'a>), Response> {
    let Ok(Path(request_id)) = path else {
        return Err(app.problem(Problem::NotFound));
    };
    if !canonical_uuid(&request_id) {
        return Err(app.problem(Problem::NotFound));
    }
    let Some((cookie, session)) = cookie(headers, app.cookies.session)
        .and_then(|value| app.sessions.current(value).map(|session| (value, session)))
    else {
        return Err(sign_in_again(app, &request_id, action));
    };
    app.admit_citizen(&session.citizen).await?;
    Ok((request_id, Caller { cookie, session }))
}

fn profile(app: &App) -> Profile<'_> {
    Profile {
        entity: &app.entity,
        target_field: &app.target_field,
        access_profile: &app.access_profile,
    }
}

/// Record the request before protected registry I/O starts.
async fn begin_audit(
    app: &App,
    caller: &Caller<'_>,
    action: Action,
    request_id: &str,
) -> Result<Operation, Response> {
    app.journal
        .begin(action, Some(&caller.session.citizen), Some(request_id))
        .await
        .map_err(|error| {
            tracing::error!(%error, "an action request could not be audited");
            app.problem(Problem::AuditUnavailable)
        })
}

/// Record a known terminal outcome before releasing its answer.
async fn finish_audit(app: &App, operation: Operation, outcome: Outcome) -> Result<(), Response> {
    operation.finish(outcome, None).await.map_err(|error| {
        tracing::error!(%error, "an action response could not be audited");
        app.problem(Problem::AuditUnavailable)
    })
}

/// Answer a review that could not be loaded.
async fn refused(
    app: &App,
    caller: &Caller<'_>,
    action: Action,
    request_id: &str,
    operation: Operation,
    refusal: Refusal,
) -> Response {
    // A read, or a submit the registry answered definitely, changed nothing.
    if let Err(response) = finish_audit(app, operation, Outcome::Refused).await {
        return response;
    }
    match refusal {
        Refusal::NotFound => app.problem(Problem::NotFound),
        Refusal::SignedOut => {
            end_session(app, caller.cookie, sign_in_again(app, request_id, action))
        }
        Refusal::Refused(reason) => {
            tracing::warn!(%reason, "the registry declined a review request");
            app.problem(Problem::RegistryRefused)
        }
        Refusal::Unavailable(reason) => {
            tracing::warn!(%reason, "the registry could not answer a review");
            app.problem(Problem::RegistryUnavailable)
        }
    }
}

fn end_session(app: &App, cookie: &str, mut response: Response) -> Response {
    app.sessions.remove(cookie);
    response.headers_mut().append(
        header::SET_COOKIE,
        app.cookies.clear(app.cookies.session, "Strict"),
    );
    response
}

/// Render `review` in answer to `answering`, remembering a fresh view when
/// it offers a submit. An `Err` carries the answer that replaces the page.
fn render(
    app: &App,
    answering: Action,
    caller: &Caller<'_>,
    request_id: &str,
    review: Review,
    status: StatusCode,
) -> Result<Response, Response> {
    let view = match review.submit {
        Some(action) => {
            let (Ok(id), Ok(key)) = (random_token(), random_token()) else {
                tracing::error!("the operating system random source failed");
                return Err(app.problem(Problem::Internal));
            };
            let view = View {
                id: id.clone(),
                request_id: request_id.to_owned(),
                action,
                target: review.target.clone(),
                idempotency_key: format!("breg-review-{key}"),
            };
            if !app.sessions.remember_view(caller.cookie, view) {
                return Err(sign_in_again(app, request_id, answering));
            }
            Some(id)
        }
        None => None,
    };
    let page = ReviewPage {
        request_id,
        entity_label: &review.entity_label,
        target_label: &review.target_label,
        current: &review.current,
        proposed: &review.proposed,
        csrf: &caller.session.csrf,
        view: view.as_deref(),
        notice: status == StatusCode::CONFLICT,
    };
    app.try_rendered(status, app.templates.review(&page))
}

/// `GET /requests/{id}`: read the draft and the record it changes under the
/// person's own token and render both.
pub(crate) async fn review(
    State(app): State<Arc<App>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Response {
    let (request_id, caller) = match admit(&app, Action::Read, path, &headers).await {
        Ok(admitted) => admitted,
        Err(response) => return response,
    };
    let operation = match begin_audit(&app, &caller, Action::Read, &request_id).await {
        Ok(operation) => operation,
        Err(response) => return response,
    };
    let review = match registry::load(&caller.session.registry, &profile(&app), &request_id).await {
        Ok(review) => review,
        Err(refusal) => {
            return refused(&app, &caller, Action::Read, &request_id, operation, refusal).await
        }
    };
    // The page is rendered before the read is audited, so a page that could
    // not be offered is never recorded as one that was.
    let (outcome, response) = match render(
        &app,
        Action::Read,
        &caller,
        &request_id,
        review,
        StatusCode::OK,
    ) {
        Ok(page) => (Outcome::Ok, page),
        Err(refusal) => (Outcome::Refused, refusal),
    };
    if let Err(response) = finish_audit(&app, operation, outcome).await {
        return response;
    }
    response
}

/// The two fields a form posted to this page may carry.
#[derive(Default)]
struct Form {
    csrf: Option<String>,
    view: Option<String>,
}

async fn read_form(app: &App, body: Body) -> Result<Form, Response> {
    let bytes = axum::body::to_bytes(body, MAXIMUM_FORM_BYTES)
        .await
        .map_err(|_| app.problem(Problem::RequestTooLarge))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| app.problem(Problem::FormRefused))?;
    let pairs = single_valued(text).ok_or_else(|| app.problem(Problem::FormRefused))?;
    let mut form = Form::default();
    for (name, value) in pairs {
        match name.as_str() {
            "csrf" => form.csrf = Some(value),
            "view" => form.view = Some(value),
            _ => return Err(app.problem(Problem::FormRefused)),
        }
    }
    Ok(form)
}

fn check_csrf(app: &App, form: &Form, session: &Current) -> Result<(), Response> {
    match &form.csrf {
        Some(presented) if tokens_match(presented, &session.csrf) => Ok(()),
        _ => Err(app.problem(Problem::CsrfRefused)),
    }
}

/// `POST /requests/{id}/submit`: submit exactly the action the person saw,
/// under the idempotency key bound to that view.
pub(crate) async fn submit(
    State(app): State<Arc<App>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (request_id, caller) = match admit(&app, Action::Submit, path, &headers).await {
        Ok(admitted) => admitted,
        Err(response) => return response,
    };
    let form = match read_form(&app, body).await {
        Ok(form) => form,
        Err(response) => return response,
    };
    if let Err(response) = check_csrf(&app, &form, &caller.session) {
        return response;
    }
    let operation = match begin_audit(&app, &caller, Action::Submit, &request_id).await {
        Ok(operation) => operation,
        Err(response) => return response,
    };
    // The same reads as the page: the draft, then its target. A draft naming
    // a record this person may not read ends here, before any submit.
    let review = match registry::load(&caller.session.registry, &profile(&app), &request_id).await {
        Ok(review) => review,
        Err(refusal) => {
            return refused(
                &app,
                &caller,
                Action::Submit,
                &request_id,
                operation,
                refusal,
            )
            .await
        }
    };
    // The action's precondition binds only the draft, so the page itself
    // holds the submit to the target revision the person saw beside it.
    let Some(view) = form
        .view
        .as_deref()
        .and_then(|view| app.sessions.view(caller.cookie, &request_id, view))
        .filter(|view| view.target == review.target)
    else {
        // Not a view this session rendered for this request, or one whose
        // target has changed since: show the current state and ask again.
        if let Err(response) = finish_audit(&app, operation, Outcome::Refused).await {
            return response;
        }
        return render(
            &app,
            Action::Submit,
            &caller,
            &request_id,
            review,
            StatusCode::CONFLICT,
        )
        .unwrap_or_else(|response| response);
    };
    let Ok(key) = BRegIdempotencyKey::parse(view.idempotency_key.clone()) else {
        tracing::error!("a stored idempotency key is not valid");
        if let Err(response) = finish_audit(&app, operation, Outcome::Refused).await {
            return response;
        }
        return app.problem(Problem::Internal);
    };
    let outcome = caller
        .session
        .registry
        .execute_lifecycle_action(&view.action, &key)
        .await;
    match outcome {
        Ok(_) => {
            if let Err(error) = operation.finish(Outcome::Ok, None).await {
                // The registry committed, so the page must not say nothing
                // happened. The unanswered request records `unfinished`, and
                // the retained view lets the person retry the same action and
                // idempotency key to see the stored result.
                tracing::error!(%error, "an action response could not be audited");
                return app.problem(Problem::RegistryUnavailable);
            }
            app.rendered(
                StatusCode::OK,
                app.templates.submitted(&caller.session.csrf),
            )
        }
        Err(error) => match error.problem_code() {
            Some(BRegProblemCode::PreconditionFailed | BRegProblemCode::MutationConflict) => {
                // The draft changed between the read at the top of this POST
                // and the registry's refusal, so the review loaded then is
                // stale. Reloading now renders the confirmation the person
                // would actually be agreeing to, instead of one that has
                // already changed and would only conflict again.
                let fresh =
                    match registry::load(&caller.session.registry, &profile(&app), &request_id)
                        .await
                    {
                        Ok(fresh) => fresh,
                        Err(refusal) => {
                            return refused(
                                &app,
                                &caller,
                                Action::Submit,
                                &request_id,
                                operation,
                                refusal,
                            )
                            .await
                        }
                    };
                if let Err(response) = finish_audit(&app, operation, Outcome::Refused).await {
                    return response;
                }
                render(
                    &app,
                    Action::Submit,
                    &caller,
                    &request_id,
                    fresh,
                    StatusCode::CONFLICT,
                )
                .unwrap_or_else(|response| response)
            }
            // A key past the receipt horizon stays spent: an earlier submit
            // under it committed, and this one runs nothing. It is neither a
            // refusal that changed nothing nor an outcome worth retrying.
            Some(BRegProblemCode::IdempotencyConflict | BRegProblemCode::IdempotencyExpired) => {
                if let Err(response) = finish_audit(&app, operation, Outcome::Refused).await {
                    return response;
                }
                app.problem(Problem::RequestConflict)
            }
            _ => {
                let refusal = Refusal::from_client(&error);
                if error
                    .status()
                    .is_some_and(|status| (400..500).contains(&status))
                {
                    refused(
                        &app,
                        &caller,
                        Action::Submit,
                        &request_id,
                        operation,
                        refusal,
                    )
                    .await
                } else {
                    // A transport failure or server-side failure may have
                    // happened after the registry committed. Dropping the
                    // operation records `unfinished`; the retained view lets
                    // the person retry the same action and idempotency key.
                    let Refusal::Unavailable(reason) = refusal else {
                        unreachable!("non-4xx submit failures are unavailable")
                    };
                    tracing::warn!(%reason, "the registry submit outcome is uncertain");
                    drop(operation);
                    app.problem(Problem::RegistryUnavailable)
                }
            }
        },
    }
}

/// `POST /signout`: end the session. A person with no session is already
/// signed out.
pub(crate) async fn sign_out(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let signed_out = |app: &App| {
        let mut response = app.rendered(StatusCode::OK, app.templates.signed_out());
        response.headers_mut().append(
            header::SET_COOKIE,
            app.cookies.clear(app.cookies.session, "Strict"),
        );
        response
    };
    let Some((cookie, session)) = cookie(&headers, app.cookies.session)
        .and_then(|value| app.sessions.current(value).map(|session| (value, session)))
    else {
        return signed_out(&app);
    };
    if let Err(response) = app.admit_citizen(&session.citizen).await {
        return response;
    }
    let form = match read_form(&app, body).await {
        Ok(form) => form,
        Err(response) => return response,
    };
    if form.view.is_some() {
        return app.problem(Problem::FormRefused);
    }
    if let Err(response) = check_csrf(&app, &form, &session) {
        return response;
    }
    let operation = match app
        .journal
        .begin(Action::SignOut, Some(&session.citizen), None)
        .await
    {
        Ok(operation) => operation,
        Err(error) => {
            tracing::error!(%error, "a sign-out request could not be audited");
            return app.problem(Problem::AuditUnavailable);
        }
    };
    app.sessions.remove(cookie);
    if let Err(error) = operation.finish(Outcome::Ok, None).await {
        // The session is already gone and is never restored, so the answer
        // still says so. The unanswered request records `unfinished`.
        tracing::error!(%error, "a sign-out could not be audited");
    }
    signed_out(&app)
}

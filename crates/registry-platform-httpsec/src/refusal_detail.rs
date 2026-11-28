// SPDX-License-Identifier: Apache-2.0
//! The development-only `failedCheck` member of a refusal body.
//!
//! A refusal carries a [`RefusalNote`] in its response extensions, naming the
//! check that failed. The note is operator-side: the recording layer counts and
//! logs it, and a production body never carries it. [`name_failed_check`] adds
//! the check's label to a JSON refusal body when the process declared
//! development, so a developer sees which check refused without reading the
//! log. In production the layer returns the response as it received it and
//! does not read the body.
//!
//! The note's remedy names a setting and stays on the log line. It never enters
//! a body.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{to_bytes, Body, HttpBody};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderValue, Request, Response};
use registry_platform_authcommon::RefusalNote;
use registry_platform_posture::Posture;
use serde_json::Value;
use tower::{Layer, Service};

/// The largest refusal body the layer reads to add the member. A larger or
/// unsized body is returned as it is.
pub const MAX_DETAIL_BODY_BYTES: usize = 16 * 1024;

/// The member the layer adds.
pub const FAILED_CHECK_MEMBER: &str = "failedCheck";

/// Add `failedCheck` to a JSON refusal body under the development posture.
///
/// Place it once per router, outside the layer that records refusals. A
/// response is changed only when `posture` is [`Posture::Development`], it
/// carries a [`RefusalNote`], and its body is a JSON object of at most
/// [`MAX_DETAIL_BODY_BYTES`] under `application/problem+json` or
/// `application/json`. Status, headers other than `content-length`, and every
/// other member are unchanged.
#[must_use]
pub fn name_failed_check(posture: Posture) -> NameFailedCheckLayer {
    NameFailedCheckLayer { posture }
}

#[derive(Clone, Copy, Debug)]
pub struct NameFailedCheckLayer {
    posture: Posture,
}

impl<S> Layer<S> for NameFailedCheckLayer {
    type Service = NameFailedCheckService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        NameFailedCheckService {
            inner,
            posture: self.posture,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NameFailedCheckService<S> {
    inner: S,
    posture: Posture,
}

impl<S, ReqBody> Service<Request<ReqBody>> for NameFailedCheckService<S>
where
    S: Service<Request<ReqBody>, Response = Response<Body>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let future = self.inner.call(request);
        let development = self.posture == Posture::Development;
        Box::pin(async move {
            let response = future.await?;
            if development {
                Ok(add_failed_check(response).await)
            } else {
                Ok(response)
            }
        })
    }
}

async fn add_failed_check(response: Response<Body>) -> Response<Body> {
    let Some(note) = response.extensions().get::<RefusalNote>().copied() else {
        return response;
    };
    if !is_json(&response) || !is_bounded(response.body()) {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    // The size was checked above, so the read cannot exceed the bound and a
    // failure is a body that errored. That body is gone, so the response
    // carries an empty one rather than a partial document, and no longer
    // states the length of the body it lost.
    let bytes = match to_bytes(body, MAX_DETAIL_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::debug!(%error, "refusal body could not be read; sending it empty");
            parts.headers.remove(CONTENT_LENGTH);
            return Response::from_parts(parts, Body::empty());
        }
    };
    let Ok(Value::Object(mut members)) = serde_json::from_slice::<Value>(&bytes) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    members.insert(
        FAILED_CHECK_MEMBER.to_owned(),
        Value::from(note.check.as_str()),
    );
    let Ok(rewritten) = serde_json::to_vec(&Value::Object(members)) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    if parts.headers.contains_key(CONTENT_LENGTH) {
        parts
            .headers
            .insert(CONTENT_LENGTH, HeaderValue::from(rewritten.len()));
    }
    Response::from_parts(parts, Body::from(rewritten))
}

fn is_json(response: &Response<Body>) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let media = value.split(';').next().unwrap_or("").trim();
            media.eq_ignore_ascii_case("application/problem+json")
                || media.eq_ignore_ascii_case("application/json")
        })
}

/// True when the body states an upper size within the bound.
fn is_bounded(body: &Body) -> bool {
    body.size_hint()
        .upper()
        .is_some_and(|upper| upper <= MAX_DETAIL_BODY_BYTES as u64)
}

#[cfg(test)]
#[path = "refusal_detail_tests.rs"]
mod tests;

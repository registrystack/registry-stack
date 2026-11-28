use super::*;
use axum::body::{to_bytes, Body};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use registry_platform_authcommon::{FailedCheck, RefusalNote};
use serde_json::{json, Value};
use tower::ServiceExt;

const PROBLEM: &str = "application/problem+json";

fn refusal(content_type: &'static str, body: Body, note: Option<RefusalNote>) -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        [
            (CONTENT_TYPE, content_type),
            (axum::http::header::WWW_AUTHENTICATE, "Bearer"),
        ],
        body,
    )
        .into_response();
    if let Some(note) = note {
        response.extensions_mut().insert(note);
    }
    response
}

fn note() -> RefusalNote {
    RefusalNote::new(FailedCheck::TokenType).with_remedy("the issuer entry admits at+jwt")
}

async fn call(
    posture: Posture,
    make: impl Fn() -> Response + Clone + Send + Sync + 'static,
) -> Response {
    let app = Router::new()
        .route(
            "/",
            get(move || {
                let make = make.clone();
                async move { make() }
            }),
        )
        .layer(name_failed_check(posture));
    app.oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn problem_text() -> String {
    json!({"type": "https://id.registrystack.org/problems/x", "title": "Unauthorized", "status": 401, "code": "authentication.failed"})
        .to_string()
}

fn problem_body() -> Body {
    Body::from(problem_text())
}

/// A body of a stated size whose read fails.
struct FailingBody;

impl http_body::Body for FailingBody {
    type Data = axum::body::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Ready(Some(Err(std::io::Error::other("the body failed"))))
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(40)
    }
}

async fn json_of(response: Response) -> (StatusCode, axum::http::HeaderMap, Value) {
    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, usize::MAX).await.unwrap();
    (
        parts.status,
        parts.headers,
        serde_json::from_slice(&bytes).unwrap(),
    )
}

#[tokio::test]
async fn development_adds_the_failed_check_to_a_problem_body_that_carries_a_note() {
    let response = call(Posture::Development, || {
        refusal(PROBLEM, problem_body(), Some(note()))
    })
    .await;
    let (status, headers, body) = json_of(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["failedCheck"], "token-type");
    assert_eq!(body["code"], "authentication.failed");
    assert_eq!(body["status"], 401);
    assert_eq!(headers[CONTENT_TYPE], PROBLEM);
    assert_eq!(headers["www-authenticate"], "Bearer");
}

#[tokio::test]
async fn the_content_length_follows_the_rewritten_body() {
    let response = call(Posture::Development, || {
        let text = problem_text();
        let mut response = refusal(PROBLEM, Body::from(text.clone()), Some(note()));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from(text.len()));
        response
    })
    .await;
    let declared: usize = response.headers()[CONTENT_LENGTH]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["failedCheck"], "token-type");
    assert_eq!(declared, bytes.len());
}

#[tokio::test]
async fn a_body_that_fails_to_read_leaves_no_stated_length() {
    let response = call(Posture::Development, || {
        let mut response = refusal(PROBLEM, Body::new(FailingBody), Some(note()));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from(40_usize));
        response
    })
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // The router states the length of the empty body itself, or nothing.
    let declared = response
        .headers()
        .get(CONTENT_LENGTH)
        .map(|value| value.to_str().unwrap().parse::<usize>().unwrap());
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(bytes.is_empty());
    assert_eq!(declared.unwrap_or(0), 0, "the failed body's length stays");
}

#[tokio::test]
async fn development_also_names_the_check_in_a_plain_json_body() {
    let response = call(Posture::Development, || {
        refusal(
            "application/json",
            Body::from(r#"{"error":"denied"}"#),
            Some(note()),
        )
    })
    .await;
    let (_, _, body) = json_of(response).await;
    assert_eq!(
        body,
        json!({"error": "denied", "failedCheck": "token-type"})
    );
}

#[tokio::test]
async fn the_remedy_and_every_setting_name_stay_out_of_the_body() {
    let response = call(Posture::Development, || {
        refusal(PROBLEM, problem_body(), Some(note()))
    })
    .await;
    let text = serde_json::to_string(&json_of(response).await.2).unwrap();
    assert!(
        !text.contains("accessTokenType") && !text.contains("at+jwt"),
        "{text}"
    );
}

#[tokio::test]
async fn a_response_with_no_note_is_returned_untouched_in_development() {
    let response = call(Posture::Development, || {
        refusal(PROBLEM, problem_body(), None)
    })
    .await;
    let (_, _, body) = json_of(response).await;
    assert!(body.get("failedCheck").is_none());
}

#[tokio::test]
async fn a_body_that_is_not_json_is_returned_untouched() {
    let response = call(Posture::Development, || {
        refusal("text/plain", Body::from("denied"), Some(note()))
    })
    .await;
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&bytes[..], b"denied");
}

#[tokio::test]
async fn json_that_is_not_an_object_is_returned_untouched() {
    let response = call(Posture::Development, || {
        refusal("application/json", Body::from("[1,2]"), Some(note()))
    })
    .await;
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&bytes[..], b"[1,2]");
}

#[tokio::test]
async fn a_body_over_the_bound_is_returned_whole_and_untouched() {
    let padding = "x".repeat(MAX_DETAIL_BODY_BYTES + 1);
    let large = json!({"detail": padding}).to_string();
    let expected = large.clone();
    let response = call(Posture::Development, move || {
        refusal(PROBLEM, Body::from(large.clone()), Some(note()))
    })
    .await;
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(bytes, expected.as_bytes());
}

#[tokio::test]
async fn production_returns_the_response_untouched_with_its_note_intact() {
    let response = call(Posture::Production, || {
        refusal(PROBLEM, problem_body(), Some(note()))
    })
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.extensions().get::<RefusalNote>().copied(),
        Some(note())
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(body.get("failedCheck").is_none(), "{body}");
    assert_eq!(body["code"], "authentication.failed");
}

#[tokio::test]
async fn production_leaves_a_body_over_the_detail_bound_whole() {
    let large = json!({"detail": "x".repeat(MAX_DETAIL_BODY_BYTES + 1)}).to_string();
    let expected = large.clone();
    let response = call(Posture::Production, move || {
        refusal(PROBLEM, Body::from(large.clone()), Some(note()))
    })
    .await;
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(bytes, expected.as_bytes());
}

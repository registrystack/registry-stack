// SPDX-License-Identifier: Apache-2.0
//! In-memory capture and malformed credentials for authentication diagnostics tests.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::PrivateJwk;
use serde_json::{json, Value};
use std::{
    future::Future,
    io::Write,
    sync::{Arc, Mutex},
};

use crate::sign_compact_jwt_with_key;

/// Shared in-memory writer for scoped, value-free diagnostic assertions.
#[derive(Clone, Debug, Default)]
pub struct CapturedDiagnosticLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedDiagnosticLogs {
    /// Return a UTF-8 snapshot after the observed operation completes.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("diagnostic capture lock").clone())
            .expect("diagnostics are UTF-8")
    }

    /// A JSON subscriber that writes into this capture. Attach it to one
    /// future with `tracing::instrument::WithSubscriber`.
    #[must_use]
    pub fn subscriber(&self) -> tracing::Dispatch {
        let writer = self.clone();
        tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish(),
        )
    }

    /// Assert that the capture holds exactly one header-stage diagnostic and
    /// that it renders none of the supplied credentials.
    ///
    /// # Panics
    ///
    /// Panics when the capture is not one value-free header diagnostic.
    pub fn assert_one_value_free_header_diagnostic(&self, tokens: &[String]) {
        let rendered = self.text();
        assert_eq!(
            rendered.lines().count(),
            1,
            "one bounded diagnostic per header stage"
        );
        assert!(rendered.contains(r#""stage":"header""#));
        assert!(!rendered.contains("canary"));
        for token in tokens.iter().filter(|token| !token.is_empty()) {
            assert!(
                !rendered.contains(token),
                "diagnostics must not contain credentials"
            );
        }
    }
}

impl Write for CapturedDiagnosticLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("diagnostic capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Empty, oversized, malformed-base64 and duplicate-member credentials.
#[must_use]
pub fn malformed_access_token_fixtures() -> Vec<String> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
    let duplicate_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","alg":"ES256"}"#);
    let duplicate_claims = URL_SAFE_NO_PAD.encode(br#"{"sub":"canary-one","sub":"canary-two"}"#);
    vec![
        String::new(),
        "canary-sensitive-token".repeat(8192),
        "!canary-invalid-base64.e30.c2ln".to_owned(),
        format!("{duplicate_header}.e30.c2ln"),
        format!("{header}.{duplicate_claims}.c2ln"),
    ]
}

/// Resource audiences that are never the audience under test.
const OTHER_RESOURCE_AUDIENCES: [&str; 4] = [
    "urn:canary:breg",
    "urn:canary:casework",
    "urn:canary:scheduling",
    "urn:canary:messaging",
];

/// Drive the audience and token-type rules every resource server shares:
/// the token is admitted, a multi-audience token naming the resource is still
/// admitted, a token for any other resource is refused, and so is `typ: JWT`.
/// `claims` must be valid for `authenticate` and carry the resource's own `aud`.
///
/// # Panics
///
/// Panics when any case is not admitted or refused as described.
pub async fn assert_resource_audience_and_token_type_rules<T, E, F, Fut>(
    key: &PrivateJwk,
    claims: Value,
    authenticate: F,
    is_refused: impl Fn(&E) -> bool,
) where
    E: std::fmt::Debug,
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let sign = |claims: Value, typ: &str| {
        sign_compact_jwt_with_key(key, typ, "canary-resource-key", claims)
    };
    assert!(authenticate(sign(claims.clone(), "at+jwt")).await.is_ok());
    let mut multiple = claims.clone();
    multiple["aud"] = json!([claims["aud"], "urn:canary:additional-resource"]);
    assert!(
        authenticate(sign(multiple, "at+jwt")).await.is_ok(),
        "audience membership remains sufficient on this ordinary resource profile"
    );
    for resource in OTHER_RESOURCE_AUDIENCES {
        let mut other = claims.clone();
        other["aud"] = json!(resource);
        let refusal = authenticate(sign(other, "at+jwt")).await.err();
        assert!(
            refusal.as_ref().is_some_and(&is_refused),
            "a token for {resource} must be refused, got {refusal:?}"
        );
    }
    let refusal = authenticate(sign(claims, "JWT")).await.err();
    assert!(
        refusal.as_ref().is_some_and(&is_refused),
        "a non-access-token type must be refused, got {refusal:?}"
    );
}

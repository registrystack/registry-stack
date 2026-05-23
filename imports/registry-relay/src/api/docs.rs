// SPDX-License-Identifier: Apache-2.0
//! `/docs` Scalar API reference viewer.
//!
//! Two routes:
//!
//! - `GET /docs` returns a tiny HTML shell whose job is to collect a
//!   bearer token, fetch `/openapi.json`, and load Scalar.
//! - `GET /docs/scalar.js` serves the vendored Scalar IIFE bundle
//!   (`@scalar/api-reference@1.57.1`) verbatim from the embedded
//!   `SCALAR_BUNDLE` byte slice.
//!
//! Both routes sit on the public unauthenticated sub-router so a browser
//! can open `/docs` directly. The shell and JS bundle contain no catalog
//! content. The OpenAPI document at `/openapi.json` stays inside the
//! auth-gated data-plane router; the shell attaches the operator's bearer
//! token to that fetch and passes the same token to Scalar for "Try it"
//! calls. A route-local CSP keeps the docs page on same-origin network
//! access and allows only the static bootstrap script hashes plus the
//! same-origin Scalar bundle. `style-src 'unsafe-inline'` remains because
//! the vendored Scalar runtime injects styles dynamically.
//!
//! The bundle is hash-pinned in `resources/MANIFEST.toml`; the
//! `tests/resources_manifest.rs` invariant re-hashes both the on-disk
//! file and `SCALAR_BUNDLE` to assert sha256 equality with the manifest.

use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

/// Vendored Scalar API Reference standalone bundle.
/// Pinned to `@scalar/api-reference@1.57.1`. See
/// `resources/MANIFEST.toml` for the sha256.
pub const SCALAR_BUNDLE: &[u8] = include_bytes!("../../resources/scalar/api-reference.js");

const TEXT_HTML: HeaderValue = HeaderValue::from_static("text/html; charset=utf-8");
const APPLICATION_JAVASCRIPT: HeaderValue =
    HeaderValue::from_static("application/javascript; charset=utf-8");
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
const CACHE_CONTROL_7D_IMMUTABLE: HeaderValue =
    HeaderValue::from_static("public, max-age=604800, immutable");
const CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");
const DOCS_HTML_CSP: HeaderValue = HeaderValue::from_static(
    "default-src 'none'; script-src 'self' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' 'sha256-O+yKSHtPIjBdJ+bty0Fj1HzND1gVaz+ApkQRleQYXIc='; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; frame-src 'none'; worker-src 'none'; manifest-src 'none'",
);
const SCALAR_BUNDLE_CSP: HeaderValue = HeaderValue::from_static(
    "default-src 'none'; script-src 'none'; style-src 'none'; img-src 'none'; font-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; frame-src 'none'",
);

/// HTML shell that mounts Scalar with a pre-fetched OpenAPI document.
///
/// `/openapi.json` is auth-gated. Scalar's `authentication` config
/// only governs "Try it" calls, not the initial spec fetch, so the
/// inline bootstrap fetches `/openapi.json` itself with the bearer
/// header attached, parses it, and hands the content to Scalar via
/// `data-configuration.content`. The bundle is loaded dynamically
/// after the spec is in hand so Scalar never issues an unauthenticated
/// fetch. The same bearer is also injected into `authentication` so
/// "Try it" calls inherit it.
///
/// Storing the token in `localStorage` accepts the standard XSS-exfil
/// risk: any script that lands on this origin can read it. The viewer
/// is an operator-facing tool, not a production app. The route-local
/// CSP narrows the script surface to this same-origin shell and its
/// static bootstrap hashes.
const DOCS_HTML: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Registry Relay API</title>
    <style>
      body { margin: 0; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
      #auth-bar {
        display: flex; align-items: center; gap: 8px;
        padding: 8px 12px;
        background: #f6f7f9;
        border-bottom: 1px solid #dde0e3;
        font-size: 13px;
      }
      #auth-bar label { color: #555; white-space: nowrap; }
      #auth-bar input {
        flex: 1; min-width: 0;
        padding: 6px 8px;
        border: 1px solid #ccc;
        border-radius: 4px;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size: 12px;
      }
      #auth-bar button {
        padding: 6px 12px;
        border: 1px solid #c1c5cb;
        background: white;
        border-radius: 4px;
        cursor: pointer;
        font-size: 13px;
      }
      #auth-bar button:hover { background: #eef0f3; }
      #auth-bar .status { color: #888; font-size: 12px; white-space: nowrap; }
    </style>
  </head>
  <body>
    <form id="auth-bar" autocomplete="off">
      <label for="token">API key:</label>
      <input id="token" name="token" type="password" placeholder="Paste bearer token; persisted in localStorage" />
      <button type="submit">Apply</button>
      <button type="button" id="clear">Clear</button>
      <span id="status" class="status"></span>
    </form>

    <script id="api-reference"></script>
    <script>
      // Bootstrap: Scalar's bundle does not attach our bearer to its
      // own spec fetch, so we fetch /openapi.json ourselves with the
      // Authorization header, then hand the parsed content to Scalar
      // via data-configuration.content and load the bundle dynamically.
      (function () {
        var STORAGE_KEY = 'registry-relay.api_key';
        var SPEC_URL = '/openapi.json';
        var BUNDLE_URL = '/docs/scalar.js';
        var input = document.getElementById('token');
        var status = document.getElementById('status');
        var form = document.getElementById('auth-bar');
        var clearBtn = document.getElementById('clear');
        var refEl = document.getElementById('api-reference');

        var stored = '';
        try { stored = localStorage.getItem(STORAGE_KEY) || ''; } catch (e) {}
        if (stored) { input.value = stored; }

        form.addEventListener('submit', function (e) {
          e.preventDefault();
          var v = input.value.trim();
          try {
            if (v) { localStorage.setItem(STORAGE_KEY, v); }
            else   { localStorage.removeItem(STORAGE_KEY); }
          } catch (e) {}
          location.reload();
        });
        clearBtn.addEventListener('click', function () {
          try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
          input.value = '';
          location.reload();
        });

        function mountScalar(spec, token) {
          refEl.dataset.configuration = JSON.stringify({
            content: spec,
            authentication: {
              preferredSecurityScheme: 'bearerAuth',
              http: { bearer: { token: token } },
            },
          });
          var s = document.createElement('script');
          s.src = BUNDLE_URL;
          document.body.appendChild(s);
        }

        if (!stored) {
          status.textContent = 'no key set; paste a bearer token above to load the spec';
          return;
        }

        status.textContent = 'fetching spec with stored key...';
        fetch(SPEC_URL, {
          headers: { 'Authorization': 'Bearer ' + stored, 'Accept': 'application/json' },
          credentials: 'omit',
          cache: 'no-store',
        })
          .then(function (r) {
            if (!r.ok) {
              return r.text().then(function (text) {
                throw new Error(r.status + ' ' + r.statusText + (text ? ' - ' + text.slice(0, 200) : ''));
              });
            }
            return r.json();
          })
          .then(function (spec) {
            var ver = spec && spec.info && spec.info.version ? 'v' + spec.info.version : 'ok';
            status.textContent = 'spec loaded (' + ver + ')';
            mountScalar(spec, stored);
          })
          .catch(function (err) {
            status.textContent = 'spec fetch failed: ' + (err && err.message ? err.message : err);
          });
      })();
    </script>
  </body>
</html>
"#;

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/docs", get(serve_html))
        .route("/docs/scalar.js", get(serve_bundle))
}

async fn serve_html() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, TEXT_HTML),
            (header::CACHE_CONTROL, NO_STORE),
            (CONTENT_SECURITY_POLICY, DOCS_HTML_CSP),
        ],
        DOCS_HTML,
    )
        .into_response()
}

async fn serve_bundle() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, APPLICATION_JAVASCRIPT),
            (header::CACHE_CONTROL, CACHE_CONTROL_7D_IMMUTABLE),
            (CONTENT_SECURITY_POLICY, SCALAR_BUNDLE_CSP),
        ],
        SCALAR_BUNDLE,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_bundle_is_non_empty() {
        assert!(!SCALAR_BUNDLE.is_empty());
    }

    #[test]
    fn docs_html_references_openapi_and_bundle() {
        assert!(DOCS_HTML.contains("/openapi.json"));
        assert!(DOCS_HTML.contains("/docs/scalar.js"));
    }

    #[test]
    fn docs_html_wires_bearer_token_from_local_storage_into_scalar_config() {
        // The page must (a) read a token from localStorage,
        // (b) fetch /openapi.json itself with the bearer attached so
        // the spec is in hand before Scalar mounts, and (c) hand the
        // parsed content to Scalar via the configuration and load the
        // bundle dynamically. The order check is structural: the
        // configuration write must appear before the bundle script is
        // appended to the DOM.
        assert!(DOCS_HTML.contains("registry-relay.api_key"));
        assert!(DOCS_HTML.contains("localStorage"));
        assert!(DOCS_HTML.contains("preferredSecurityScheme"));
        assert!(DOCS_HTML.contains("bearerAuth"));
        assert!(
            DOCS_HTML.contains("'Authorization': 'Bearer '"),
            "spec fetch must attach the bearer header"
        );
        assert!(
            DOCS_HTML.contains("dataset.configuration"),
            "Scalar configuration must be set"
        );
        let config_pos = DOCS_HTML
            .find("dataset.configuration")
            .expect("configuration write present");
        let bundle_pos = DOCS_HTML
            .find("s.src = BUNDLE_URL")
            .expect("dynamic bundle load present");
        assert!(
            config_pos < bundle_pos,
            "Scalar configuration must be set before the bundle is loaded"
        );
    }

    #[test]
    fn docs_html_csp_hashes_cover_inline_scripts() {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let script_hashes: Vec<String> = DOCS_HTML
            .split("<script")
            .skip(1)
            .filter_map(|part| part.split_once('>').map(|(_, rest)| rest))
            .filter_map(|part| part.split_once("</script>").map(|(script, _)| script))
            .map(|script| {
                let digest = Sha256::digest(script.as_bytes());
                format!(
                    "'sha256-{}'",
                    base64::engine::general_purpose::STANDARD.encode(digest)
                )
            })
            .collect();
        let csp_header = DOCS_HTML_CSP;
        let csp = csp_header.to_str().expect("CSP is ASCII");

        assert!(!script_hashes.is_empty());
        for hash in script_hashes {
            assert!(
                csp.contains(&hash),
                "docs CSP must allow inline script hash {hash}"
            );
        }
    }

    #[tokio::test]
    async fn docs_html_response_includes_route_local_csp() {
        use tower::ServiceExt;

        let response = router::<()>()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/docs")
                    .body(axum::body::Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("service responds");

        assert_eq!(response.status(), StatusCode::OK);
        let csp = response
            .headers()
            .get(CONTENT_SECURITY_POLICY)
            .expect("content-security-policy header");
        let csp = csp.to_str().expect("CSP is ASCII");
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("connect-src 'self'"));
        assert!(csp.contains("style-src 'self' 'unsafe-inline'"));
        assert!(csp.contains("frame-ancestors 'none'"));

        // `'unsafe-inline'` must never appear in `script-src`: inline
        // scripts are pinned to their sha256 hashes, and a regression
        // here would re-open the XSS surface the docs CSP exists to
        // close (the bearer token in localStorage stays exfiltratable).
        let script_src = csp
            .split(';')
            .map(str::trim)
            .find(|directive| directive.starts_with("script-src"))
            .expect("script-src directive present");
        assert!(
            !script_src.contains("'unsafe-inline'"),
            "script-src must not allow 'unsafe-inline': {script_src}"
        );
    }

    #[tokio::test]
    async fn scalar_bundle_response_includes_deny_all_csp() {
        use tower::ServiceExt;

        let response = router::<()>()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/docs/scalar.js")
                    .body(axum::body::Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("service responds");

        assert_eq!(response.status(), StatusCode::OK);
        let csp = response
            .headers()
            .get(CONTENT_SECURITY_POLICY)
            .expect("content-security-policy header");
        let csp = csp.to_str().expect("CSP is ASCII");
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("script-src 'none'"));
        assert!(csp.contains("style-src 'none'"));
        assert!(csp.contains("connect-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }
}

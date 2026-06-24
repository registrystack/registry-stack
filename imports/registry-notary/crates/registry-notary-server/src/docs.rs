// SPDX-License-Identifier: Apache-2.0
//! `/docs` Scalar API reference viewer.
//!
//! The docs shell and vendored Scalar bundle are public static routes. The
//! OpenAPI document at `/openapi.json` remains auth-gated by default, but the
//! shell can fetch it anonymously when demo deployments set
//! `server.openapi_requires_auth: false`. For protected deployments, operators
//! can paste an API key and the shell uses it for both the spec fetch and
//! Scalar's "Try it" calls.

use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

/// Vendored Scalar API Reference standalone bundle.
/// Pinned to `@scalar/api-reference@1.57.1`.
pub const SCALAR_BUNDLE: &[u8] = include_bytes!("../resources/scalar/api-reference.js");

const TEXT_HTML: HeaderValue = HeaderValue::from_static("text/html; charset=utf-8");
const APPLICATION_JAVASCRIPT: HeaderValue =
    HeaderValue::from_static("application/javascript; charset=utf-8");
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
const CACHE_CONTROL_7D_IMMUTABLE: HeaderValue =
    HeaderValue::from_static("public, max-age=604800, immutable");
const CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");
const DOCS_HTML_CSP: HeaderValue = HeaderValue::from_static(
    "default-src 'none'; script-src 'self' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' 'sha256-W+ePrtSBohwU9Ex8EJT1P2P93ZDXNOUJGYyWFN0+WB8='; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; frame-src 'none'; worker-src 'none'; manifest-src 'none'",
);
const SCALAR_BUNDLE_CSP: HeaderValue = HeaderValue::from_static(
    "default-src 'none'; script-src 'none'; style-src 'none'; img-src 'none'; font-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; frame-src 'none'",
);

/// HTML shell that mounts Scalar with a pre-fetched OpenAPI document.
const DOCS_HTML: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Registry Notary API</title>
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
      <input id="token" name="token" type="password" placeholder="Paste X-Api-Key; persisted in localStorage" />
      <button type="submit">Apply</button>
      <button type="button" id="clear">Clear</button>
      <span id="status" class="status"></span>
    </form>

    <script id="api-reference"></script>
    <script>
      (function () {
        var STORAGE_KEY = 'registry-notary.api_key';
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
              preferredSecurityScheme: 'apiKeyAuth',
              securitySchemes: {
                apiKeyAuth: {
                  name: 'X-Api-Key',
                  in: 'header',
                  value: token,
                },
              },
            },
          });
          var s = document.createElement('script');
          s.src = BUNDLE_URL;
          document.body.appendChild(s);
        }

        function specHeaders(token) {
          var headers = { 'Accept': 'application/json' };
          if (token) { headers['X-Api-Key'] = token; }
          return headers;
        }

        status.textContent = stored ? 'fetching spec with stored key...' : 'fetching public spec...';
        fetch(SPEC_URL, {
          headers: specHeaders(stored),
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
            var message = err && err.message ? err.message : err;
            status.textContent = stored
              ? 'spec fetch failed: ' + message
              : 'spec fetch failed; paste an API key above if this deployment protects OpenAPI: ' + message;
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
    fn docs_html_wires_optional_api_key_into_scalar_config() {
        assert!(DOCS_HTML.contains("registry-notary.api_key"));
        assert!(DOCS_HTML.contains("localStorage"));
        assert!(DOCS_HTML.contains("preferredSecurityScheme: 'apiKeyAuth'"));
        assert!(DOCS_HTML.contains("securitySchemes"));
        assert!(DOCS_HTML.contains("headers['X-Api-Key'] = token"));
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
}

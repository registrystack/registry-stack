// SPDX-License-Identifier: Apache-2.0
//! Explicit source-owned download of one frozen Review display document.

use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReviewDocument {
    #[serde(rename = "type")]
    kind: String,
    slot_id: String,
    sha256: String,
    content_type: String,
    byte_size: u64,
    download: ReviewDocumentLink,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReviewDocumentLink {
    method: String,
    operation: String,
    access_profile: String,
    path: String,
}

impl BaseRegistryClient {
    /// Download an explicitly selected document from an exact Review context.
    /// The link supplies no authority. The source rechecks current disclosure,
    /// while this client validates its binding before acquiring credentials.
    pub async fn download_proposal_review_document(
        &self,
        binding: &BRegProposalReviewBinding,
        context: &BRegProposalReviewDocument,
        field: &str,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        if binding.source != self.source_binding()
            || binding.operation != "get-review-context"
            || binding.action != context.action_id
            || !valid_review_document(context, true)
            || field.is_empty()
            || field.len() > 64
            || !field.as_bytes()[0].is_ascii_lowercase()
            || !field.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(refusal());
        }
        let value = context
            .context
            .fields
            .as_ref()
            .and_then(|fields| fields.get(field))
            .ok_or_else(refusal)?;
        let document: ReviewDocument =
            serde_json::from_value(value.clone()).map_err(|_| refusal())?;
        if document.kind != "document"
            || !identifier(&document.slot_id)
            || matches!(document.slot_id.as_str(), "." | "..")
            || !digest(&format!("sha256:{}", document.sha256))
            || !crate::attachment::valid_attachment_content_type(&document.content_type)
            || !(1..=MAX_BREG_ATTACHMENT_BYTES).contains(&document.byte_size)
            || document.download.method != "GET"
            || document.download.operation != binding.operation
            || document.download.access_profile != binding.profile
        {
            return Err(refusal());
        }
        let contract = context.context.contract.as_ref().ok_or_else(refusal)?;
        let query = vec![
            (
                "submissionVersion".to_owned(),
                context.submission_version.to_string(),
            ),
            ("reviewContextField".to_owned(), field.to_owned()),
            ("effectDigest".to_owned(), context.effect_digest.clone()),
            (
                "contextSchemaDigest".to_owned(),
                contract.schema_digest.clone(),
            ),
        ];
        let path = format!(
            "/v1/proposals/{}/attachments/{}",
            context.id, document.slot_id
        );
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&query)
            .finish();
        if document.download.path != format!("{path}?{encoded}") {
            return Err(refusal());
        }
        let link = BRegProposalLink {
            method: "GET".to_owned(),
            path,
            access_profile: binding.profile.clone(),
            operation: binding.operation.to_owned(),
            if_match: None,
            availability: None,
        };
        let response = self
            .proposal_attachment_exchange(&link, None, None, None, document.byte_size, Some(&query))
            .await?;
        crate::attachment::verify_download(
            response,
            &document.content_type,
            document.byte_size,
            &document.sha256,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::{
        body::Body,
        extract::State,
        http::{Request, Response},
        routing::any,
        Router,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    const ID: &str = "00000000-0000-4000-8000-000000000001";
    const REVISION: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PDF: &[u8] = b"%PDF-1.7 synthetic review evidence";

    #[derive(Debug, Default)]
    struct CountingToken(AtomicUsize);
    #[async_trait]
    impl TokenProvider for CountingToken {
        async fn bearer_token(&self) -> Result<BearerToken, TokenError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            BearerToken::new("synthetic-reviewer-token")
        }
    }

    #[derive(Clone)]
    struct StateData {
        requests: Arc<Mutex<Vec<String>>>,
        response: Arc<Mutex<(String, Vec<u8>)>>,
    }
    struct Fixture {
        client: BaseRegistryClient,
        token: Arc<CountingToken>,
        state: StateData,
        server: tokio::task::JoinHandle<()>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }
    impl Fixture {
        async fn new() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let state = StateData {
                requests: Arc::default(),
                response: Arc::new(Mutex::new(("application/pdf".to_owned(), PDF.to_vec()))),
            };
            let app = Router::new()
                .fallback(any(
                    |State(state): State<StateData>, request: Request<Body>| async move {
                        assert_eq!(request.method(), "GET");
                        assert_eq!(
                            request.headers()["authorization"],
                            "Bearer synthetic-reviewer-token"
                        );
                        state
                            .requests
                            .lock()
                            .unwrap()
                            .push(request.uri().to_string());
                        let (media, bytes) = state.response.lock().unwrap().clone();
                        Response::builder()
                            .status(200)
                            .header("content-type", media)
                            .header("content-disposition", "attachment")
                            .header("x-content-type-options", "nosniff")
                            .header("cache-control", "no-store")
                            .header("vary", "authorization")
                            .header(
                                "traceparent",
                                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                            )
                            .body(Body::from(bytes))
                            .unwrap()
                    },
                ))
                .with_state(state.clone());
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let token = Arc::new(CountingToken::default());
            let client = BaseRegistryClient::new(
                BaseRegistryClientConfig::new(
                    url::Url::parse(&format!("http://{address}/tenant/base")).unwrap(),
                )
                .with_token_provider(token.clone()),
            )
            .unwrap();
            Self {
                client,
                token,
                state,
                server,
            }
        }
        fn binding(&self, status: bool) -> BRegProposalReviewBinding {
            let operation = if status {
                "get-review-status"
            } else {
                "get-review-context"
            };
            BRegProposalReviewBinding::from_metadata(
                &json!([{"actionId":"correct","accessProfile":"reviewer","operations":[operation]}]),
                &self.client.source_binding(), "reviewer", "correct", status,
            ).unwrap()
        }
    }

    fn context() -> Value {
        let hash: String = Sha256::digest(PDF)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let path = format!("/v1/proposals/{ID}/attachments/support?submissionVersion=1&reviewContextField=supportingDocument&effectDigest={}&contextSchemaDigest={}",
            REVISION.replace(':', "%3A"), REVISION.replace(':', "%3A"));
        json!({"id":ID,"actionId":"correct","actionRevision":REVISION,"submissionVersion":1,"revision":2,"effectDigest":REVISION,
            "subject":{"source":"registry","subjectType":"proposal","id":ID,"version":"1","digest":REVISION},
            "reviewable":true,"context":{"reference":"opaque",
                "contract":{"id":"urn:registry:breg:review-context:registry:correct:review","revision":REVISION,"schemaDigest":REVISION},
                "fields":{"optionalDocument":null,"supportingDocument":{"type":"document","slotId":"support","sha256":hash,"contentType":"application/pdf","byteSize":PDF.len(),
                    "download":{"method":"GET","operation":"get-review-context","accessProfile":"reviewer","path":path}}}}})
    }

    #[tokio::test]
    async fn review_only_download_binds_exact_context_and_preserves_deployment_prefix() {
        let fixture = Fixture::new().await;
        let context: BRegProposalReviewDocument = serde_json::from_value(context()).unwrap();
        let response = fixture
            .client
            .download_proposal_review_document(
                &fixture.binding(false),
                &context,
                "supportingDocument",
            )
            .await
            .unwrap();
        assert_eq!(response.value.as_bytes(), PDF);
        assert_eq!(response.value.media_type(), "application/pdf");
        let requests = fixture.state.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let url = url::Url::parse(&format!("http://local{}", requests[0])).unwrap();
        assert_eq!(
            url.path(),
            format!("/tenant/base/v1/proposals/{ID}/attachments/support")
        );
        let pairs = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
        assert_eq!(
            pairs,
            BTreeMap::from([
                ("accessProfile".into(), "reviewer".into()),
                ("submissionVersion".into(), "1".into()),
                ("reviewContextField".into(), "supportingDocument".into()),
                ("effectDigest".into(), REVISION.into()),
                ("contextSchemaDigest".into(), REVISION.into()),
            ])
        );
        assert_eq!(fixture.token.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn malformed_context_document_never_acquires_credentials_or_sends_http() {
        let fixture = Fixture::new().await;
        let prefix = "/context/fields/supportingDocument";
        for (pointer, replacement) in [
            ("/actionId".to_owned(), json!("other")),
            (
                "/subject/id".to_owned(),
                json!("00000000-0000-4000-8000-000000000002"),
            ),
            ("/submissionVersion".to_owned(), json!(2)),
            (format!("{prefix}/type"), json!("link")),
            (format!("{prefix}/slotId"), json!("../private")),
            (format!("{prefix}/slotId"), json!("other")),
            (format!("{prefix}/sha256"), json!("A".repeat(64))),
            (format!("{prefix}/contentType"), json!("application/*")),
            (format!("{prefix}/byteSize"), json!(0)),
            (
                format!("{prefix}/byteSize"),
                json!(MAX_BREG_ATTACHMENT_BYTES + 1),
            ),
            (format!("{prefix}/download/method"), json!("POST")),
            (format!("{prefix}/download/operation"), json!("get")),
            (format!("{prefix}/download/accessProfile"), json!("author")),
            (
                format!("{prefix}/download/path"),
                json!("https://untrusted.invalid/file"),
            ),
        ] {
            let mut value = context();
            *value.pointer_mut(&pointer).unwrap() = replacement;
            let value = serde_json::from_value(value).unwrap();
            assert!(
                fixture
                    .client
                    .download_proposal_review_document(
                        &fixture.binding(false),
                        &value,
                        "supportingDocument",
                    )
                    .await
                    .is_err(),
                "accepted {pointer}"
            );
        }
        let value = serde_json::from_value(context()).unwrap();
        for field in ["optionalDocument", "missing", "../supportingDocument"] {
            assert!(fixture
                .client
                .download_proposal_review_document(&fixture.binding(false), &value, field,)
                .await
                .is_err());
        }
        assert!(
            fixture
                .client
                .download_proposal_review_document(
                    &fixture.binding(true),
                    &value,
                    "supportingDocument",
                )
                .await
                .is_err()
        );
        let foreign = Fixture::new().await;
        assert!(fixture
            .client
            .download_proposal_review_document(
                &foreign.binding(false),
                &value,
                "supportingDocument",
            )
            .await
            .is_err());
        assert_eq!(fixture.token.0.load(Ordering::SeqCst), 0);
        assert!(fixture.state.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn review_document_rejects_changed_bytes_size_and_media_type() {
        let fixture = Fixture::new().await;
        let value = serde_json::from_value(context()).unwrap();
        for (media, bytes) in [
            ("application/pdf", vec![b'x'; PDF.len()]),
            ("application/pdf", PDF[..PDF.len() - 1].to_vec()),
            ("text/plain", PDF.to_vec()),
        ] {
            *fixture.state.response.lock().unwrap() = (media.to_owned(), bytes);
            assert!(matches!(
                fixture
                    .client
                    .download_proposal_review_document(
                        &fixture.binding(false),
                        &value,
                        "supportingDocument",
                    )
                    .await,
                Err(BaseRegistryClientError::Protocol {
                    failure: BRegProtocolFailure::Body,
                    ..
                })
            ));
        }
        assert_eq!(fixture.state.requests.lock().unwrap().len(), 3);
    }
}

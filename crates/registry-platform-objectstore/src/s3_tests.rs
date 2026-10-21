use super::*;
use registry_platform_config::SecretProvider;
use serde_json::json;
use std::sync::Arc;

const TIMESTAMP: &str = "20260909T120000Z";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const NAMESPACE: ObjectNamespace = ObjectNamespace {
    key_prefix: "breg",
    binding_domain: "breg-attachment-s3-v1",
    max_object_bytes: 1024 * 1024,
};

/// Synthetic credentials in a private directory the resolver reads.
struct SecretFiles(tempfile::TempDir);

impl SecretFiles {
    fn new() -> Self {
        Self::with(&[
            ("access", "breg960test"),
            ("secret", "breg960-test-only-secret"),
            ("token", "breg960-session-token"),
        ])
    }

    fn with(entries: &[(&str, &str)]) -> Self {
        let root = tempfile::tempdir().unwrap();
        for (name, value) in entries {
            let path = root.path().join(name);
            std::fs::write(&path, value).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        Self(root)
    }

    fn resolver(&self) -> SecretResolver {
        SecretResolver::new([SecretProvider::File], self.0.path()).unwrap()
    }
}

fn raw(url: &str) -> serde_json::Value {
    json!({"url":url, "bucket":"breg-960-test", "region":"us-east-1", "accessKeyIdRef":"secret:file/access", "secretAccessKeyRef":"secret:file/secret"})
}

fn settings(input: serde_json::Value) -> Result<S3Settings> {
    S3Settings::from_config(&serde_json::from_value::<ObjectStorageConfig>(input).unwrap())
}

/// A store over `url` built without the versioning probe, so a test can
/// sign or send whatever it needs.
fn store_from(input: serde_json::Value, scope: &str, files: &SecretFiles) -> S3ObjectStore {
    let settings = settings(input).unwrap();
    let resolver = files.resolver();
    let scope = hex::encode(Sha256::digest(scope));
    S3ObjectStore {
        client: OutboundClientBuilder::new()
            .timeout(settings.timeout)
            .connect_timeout(connect_timeout(settings.timeout))
            .try_build()
            .unwrap(),
        namespace: NAMESPACE,
        binding_digest: binding_digest(NAMESPACE, &settings.bucket_url, &settings.region, &scope)
            .unwrap(),
        bucket_url: settings.bucket_url,
        region: settings.region,
        scope,
        access_key_id: resolver
            .resolve_reference(&settings.access_key_id_ref)
            .unwrap(),
        secret_access_key: resolver
            .resolve_reference(&settings.secret_access_key_ref)
            .unwrap(),
        session_token: settings
            .session_token_ref
            .as_ref()
            .map(|reference| resolver.resolve_reference(reference).unwrap()),
    }
}

fn store(url: &str, scope: &str) -> S3ObjectStore {
    store_from(raw(url), scope, &SecretFiles::new())
}

#[test]
fn aws_published_sigv4_examples_pin_the_canonical_request_and_signature() {
    // The two GET bucket examples of the AWS Signature Version 4 S3 header
    // authentication documentation, with their published credentials.
    let files = SecretFiles::with(&[
        ("access", "AKIAIOSFODNN7EXAMPLE"),
        ("secret", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ]);
    let mut input = raw("https://s3.amazonaws.com");
    input["bucket"] = json!("examplebucket");
    input["pathStyle"] = json!(false);
    let store = store_from(input, "registry", &files);
    assert_eq!(
        store.bucket_url.as_str(),
        "https://examplebucket.s3.amazonaws.com/"
    );
    for (query, canonical_hash, signature) in [
        (
            "lifecycle=",
            "9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca",
            "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
        ),
        (
            "max-keys=2&prefix=J",
            "df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7",
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
        ),
    ] {
        let mut url = store.bucket_url.clone();
        url.set_query(Some(query));
        let headers = store
            .signed_headers(&Method::GET, &url, &[], "20130524T000000Z")
            .unwrap();
        let mut unsigned = headers.clone();
        unsigned.remove("authorization");
        let (canonical, signed_names) =
            canonical_request(&Method::GET, &url, &unsigned, EMPTY_SHA256).unwrap();
        assert_eq!(
            canonical.as_str(),
            format!(
                "GET\n/\n{query}\nhost:examplebucket.s3.amazonaws.com\n\
                 x-amz-content-sha256:{EMPTY_SHA256}\nx-amz-date:20130524T000000Z\n\n\
                 host;x-amz-content-sha256;x-amz-date\n{EMPTY_SHA256}"
            )
        );
        assert_eq!(signed_names, "host;x-amz-content-sha256;x-amz-date");
        assert_eq!(
            hex::encode(Sha256::digest(canonical.as_bytes())),
            canonical_hash
        );
        assert_eq!(
            headers["authorization"],
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}"
            )
            .as_str()
        );
    }
}

#[test]
fn a_put_signs_exactly_host_payload_date_and_session_token_and_marks_secrets_sensitive() {
    // Generated independently with Python hashlib/hmac for this exact PUT.
    let mut input = raw("http://127.0.0.1:1234");
    input["sessionTokenRef"] = json!("secret:file/token");
    let store = store_from(input, "registry", &SecretFiles::new());
    let digest = hex::encode(Sha256::digest(b"content"));
    let url = store.object_url(&digest).unwrap();
    assert_eq!(
        url.path(),
        format!(
            "/breg-960-test/breg/872491a30d60d598962de6e7b834ab76b2aa65fbab102c6ebaaae6acdc238822/{digest}"
        )
    );
    let headers = store
        .signed_headers(&Method::PUT, &url, b"content", TIMESTAMP)
        .unwrap();
    let mut names = headers.keys().map(|name| name.as_str()).collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "authorization",
            "host",
            "x-amz-content-sha256",
            "x-amz-date",
            "x-amz-security-token"
        ]
    );
    assert_eq!(headers["host"], "127.0.0.1:1234");
    assert_eq!(headers["x-amz-content-sha256"], digest.as_str());
    assert_eq!(headers["x-amz-date"], TIMESTAMP);
    assert!(headers["authorization"].is_sensitive());
    assert!(headers["x-amz-security-token"].is_sensitive());
    assert_eq!(
        headers["authorization"],
        "AWS4-HMAC-SHA256 Credential=breg960test/20260909/us-east-1/s3/aws4_request, \
         SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, \
         Signature=a172ac9c46f97ea3d3056ab340df0427e5dc8a671eec662bb83299f40c6f4908"
    );
}

#[test]
fn ipv6_signed_host_preserves_brackets_and_normalizes_default_ports() {
    // Generated independently with Python hashlib/hmac using the explicitly
    // bracketed canonical Host, empty payload, and fixed timestamp below.
    for (url, expected_host, signature) in [
        (
            "http://[::1]",
            "[::1]",
            "0ee10b0dc41c4bff26a5dd9eaad63941772aae90d96c7019fce39cd81cd52150",
        ),
        (
            "http://[::1]:80",
            "[::1]",
            "0ee10b0dc41c4bff26a5dd9eaad63941772aae90d96c7019fce39cd81cd52150",
        ),
        (
            "http://[::1]:9000",
            "[::1]:9000",
            "36ddf894e9015041c902f6634914112167bb44b846e701ae807a5d165eebb194",
        ),
        (
            "https://[2001:db8::1]",
            "[2001:db8::1]",
            "950e3a5899c2224bca023a1c0718c2d55c967c90da7bdd03a8b3ac32e97d369e",
        ),
        (
            "https://[2001:db8::1]:443",
            "[2001:db8::1]",
            "950e3a5899c2224bca023a1c0718c2d55c967c90da7bdd03a8b3ac32e97d369e",
        ),
        (
            "https://[2001:db8::1]:9443",
            "[2001:db8::1]:9443",
            "7457aafa835bafa86bae6674c427198ac240c89b22488b2907c3ce60f7c885c1",
        ),
    ] {
        let store = store(url, "registry");
        let mut url = store.bucket_url.clone();
        url.set_query(Some("versioning="));
        let parsed_host = url.host_str().unwrap();
        assert!(parsed_host.starts_with('[') && parsed_host.ends_with(']'));
        let headers = store
            .signed_headers(&Method::GET, &url, &[], TIMESTAMP)
            .unwrap();
        assert_eq!(headers["host"], expected_host);
        let expected_authorization = format!("AWS4-HMAC-SHA256 Credential=breg960test/20260909/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}");
        assert_eq!(headers["authorization"], expected_authorization);
        let request = store.client.get(url).headers(headers).build().unwrap();
        assert_eq!(request.headers()["host"], expected_host);
    }
}

#[tokio::test]
async fn ipv6_signed_request_preserves_bracketed_host_on_wire() {
    use axum::{extract::Request, routing::get, Router};
    use std::sync::atomic::{AtomicBool, Ordering};

    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let expected_host = address.to_string();
    let received = Arc::new(AtomicBool::new(false));
    let observed = received.clone();
    let app = Router::new().route(
        "/breg-960-test",
        get(move |request: Request| {
            let expected_host = expected_host.clone();
            let observed = observed.clone();
            async move {
                let host_matches = request
                    .headers()
                    .get("host")
                    .is_some_and(|value| value == expected_host.as_str());
                let host_is_signed = request
                    .headers()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| {
                        value.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date,")
                    });
                let exact_request =
                    host_matches && host_is_signed && request.uri().query() == Some("versioning=");
                observed.store(exact_request, Ordering::SeqCst);
                if exact_request {
                    (StatusCode::OK, "<VersioningConfiguration/>")
                } else {
                    (StatusCode::BAD_REQUEST, "")
                }
            }
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let result = store(&format!("http://{address}"), "registry")
        .ensure_unversioned()
        .await;
    server.abort();
    result.unwrap();
    assert!(received.load(Ordering::SeqCst));
}

#[test]
fn strict_storage_configuration_and_debug_are_value_free() {
    for url in [
        "http://storage.example",
        "https://storage.example/path",
        "https://storage.example?canary",
        "https://storage.example#canary",
    ] {
        assert_eq!(
            settings(raw(url)).unwrap_err(),
            ObjectStoreError::InvalidConfiguration,
            "{url}"
        );
    }
    // The shared block's `Url` already refuses credentials and other schemes.
    for url in ["https://user:canary@storage.example", "file:///canary"] {
        assert!(serde_json::from_value::<ObjectStorageConfig>(raw(url)).is_err());
    }
    for (key, value) in [
        ("bucket", json!("../canary")),
        ("bucket", json!("127.0.0.1")),
        ("bucket", json!("-bucket")),
        ("bucket", json!("bucket-")),
        ("bucket", json!("bu..cket")),
        ("bucket", json!("Bucket")),
        ("bucket", json!("bu")),
        ("region", json!("us/east")),
        ("region", json!("")),
        ("region", json!("US-EAST-1")),
    ] {
        let mut input = raw("https://storage.example");
        input[key] = value.clone();
        assert_eq!(
            settings(input).unwrap_err(),
            ObjectStoreError::InvalidConfiguration,
            "{key} {value}"
        );
    }
    let mut input = raw("http://127.0.0.1:1234");
    input["pathStyle"] = json!(false);
    assert_eq!(
        settings(input).unwrap_err(),
        ObjectStoreError::InvalidConfiguration
    );
    let accepted = settings(raw("https://storage.example")).unwrap();
    assert_eq!(
        accepted.bucket_url.as_str(),
        "https://storage.example/breg-960-test"
    );
    assert_eq!(format!("{accepted:?}"), "S3Settings(<redacted>)");
    assert_eq!(
        format!("{:?}", store("http://127.0.0.1:1234", "registry")),
        "S3ObjectStore(<redacted>)"
    );
}

#[test]
fn attempt_and_connect_timeouts_follow_the_configured_attempt() {
    let defaults = settings(raw("https://storage.example")).unwrap();
    assert_eq!(defaults.timeout, Duration::from_millis(10_000));
    assert_eq!(connect_timeout(defaults.timeout), Duration::from_secs(5));
    let mut input = raw("https://storage.example");
    input["attemptTimeoutMilliseconds"] = json!(100);
    let short = settings(input).unwrap();
    assert_eq!(short.timeout, Duration::from_millis(100));
    assert_eq!(connect_timeout(short.timeout), Duration::from_millis(100));
    for refused in [0, 99, 60_001] {
        let mut input = raw("https://storage.example");
        input["attemptTimeoutMilliseconds"] = json!(refused);
        assert!(serde_json::from_value::<ObjectStorageConfig>(input).is_err());
    }
}

#[tokio::test]
async fn a_response_slower_than_the_attempt_timeout_is_unavailable() {
    use axum::{routing::any, Router};
    let app = Router::new().fallback(any(|| async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        (StatusCode::OK, "<VersioningConfiguration/>")
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut input = raw(&url);
    input["attemptTimeoutMilliseconds"] = json!(100);
    let store = store_from(input, "registry", &SecretFiles::new());
    assert_eq!(
        store.ensure_unversioned().await,
        Err(ObjectStoreError::Unavailable)
    );
    server.abort();
}

#[test]
fn the_namespace_is_checked_before_anything_is_resolved() {
    for namespace in [
        ObjectNamespace {
            key_prefix: "",
            ..NAMESPACE
        },
        ObjectNamespace {
            key_prefix: "Breg",
            ..NAMESPACE
        },
        ObjectNamespace {
            key_prefix: "breg/other",
            ..NAMESPACE
        },
        ObjectNamespace {
            binding_domain: "",
            ..NAMESPACE
        },
        ObjectNamespace {
            binding_domain: "with space",
            ..NAMESPACE
        },
        ObjectNamespace {
            max_object_bytes: 0,
            ..NAMESPACE
        },
    ] {
        assert_eq!(
            namespace.check(),
            Err(ObjectStoreError::InvalidConfiguration)
        );
    }
    NAMESPACE.check().unwrap();
}

#[tokio::test]
async fn activation_refuses_scope_and_secret_shapes_before_any_request() {
    // Nothing listens on this loopback port: a refusal that reached the
    // network would be `Unavailable`, not the refusal asserted.
    let settings = settings(raw("http://127.0.0.1:9")).unwrap();
    let files = SecretFiles::new();
    for scope in ["", &"s".repeat(MAXIMUM_SCOPE_INPUT_BYTES + 1)] {
        assert_eq!(
            settings
                .activate(NAMESPACE, scope, &files.resolver())
                .await
                .unwrap_err(),
            ObjectStoreError::InvalidConfiguration
        );
    }
    for (access, secret) in [
        ("", "breg960-test-only-secret"),
        ("breg960test", ""),
        ("breg960test", "with space"),
        ("breg/960", "breg960-test-only-secret"),
    ] {
        let files = SecretFiles::with(&[("access", access), ("secret", secret)]);
        assert_eq!(
            settings
                .activate(NAMESPACE, "registry", &files.resolver())
                .await
                .unwrap_err(),
            ObjectStoreError::Secret
        );
    }
    let missing = SecretFiles::with(&[("access", "breg960test")]);
    assert_eq!(
        settings
            .activate(NAMESPACE, "registry", &missing.resolver())
            .await
            .unwrap_err(),
        ObjectStoreError::Secret
    );
}

#[test]
fn bucket_versioning_parser_fails_closed() {
    for value in ["<VersioningConfiguration/>", "<?xml version=\"1.0\"?><VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></VersioningConfiguration>"] {
        validate_unversioned_xml(value.as_bytes()).unwrap();
    }
    for state in ["Enabled", "Suspended", "", "unknown"] {
        let document =
            format!("<VersioningConfiguration><Status>{state}</Status></VersioningConfiguration>");
        assert_eq!(
            validate_unversioned_xml(document.as_bytes()),
            Err(ObjectStoreError::VersionedBucket)
        );
    }
    for value in [
        "",
        "<Other/>",
        "<VersioningConfiguration>",
        "<VersioningConfiguration/><VersioningConfiguration/>",
        "<!DOCTYPE canary><VersioningConfiguration/>",
        "<VersioningConfiguration>canary</VersioningConfiguration>",
    ] {
        assert!(validate_unversioned_xml(value.as_bytes()).is_err());
    }
}

#[test]
fn object_keys_are_prefix_and_scope_bound_and_digest_only() {
    let one = store("http://127.0.0.1:1234", "registry-one");
    let two = store("http://127.0.0.1:1234", "registry-two");
    let digest = hex::encode(Sha256::digest(b"content"));
    assert_ne!(
        one.object_url(&digest).unwrap(),
        two.object_url(&digest).unwrap()
    );
    let mut other = store("http://127.0.0.1:1234", "registry-one");
    other.namespace = ObjectNamespace {
        key_prefix: "documents",
        ..NAMESPACE
    };
    assert_eq!(
        other.object_url(&digest).unwrap().path(),
        one.object_url(&digest)
            .unwrap()
            .path()
            .replacen("/breg/", "/documents/", 1)
    );
    for bad in ["../secret", "", "https://storage.example", &"A".repeat(64)] {
        assert_eq!(one.object_url(bad), Err(ObjectStoreError::Integrity));
    }
    assert!(one.verify_content(&digest, 7, b"corrupt").is_err());
    assert!(one.verify_content(&digest, 6, b"content").is_err());
    let mut small = store("http://127.0.0.1:1234", "registry-one");
    small.namespace.max_object_bytes = 6;
    assert_eq!(
        small.verify_content(&digest, 7, b"content"),
        Err(ObjectStoreError::Integrity)
    );
}

#[test]
fn the_binding_digest_commits_to_domain_bucket_region_and_scope_only() {
    // The hex SHA-256 of
    // ["breg-attachment-s3-v1","http://127.0.0.1:1234/breg-960-test","us-east-1",sha256("registry")],
    // generated independently with Python.
    let pinned = "817a89128612f5d9af80c138ebccc301f1a89c01624ae00d02d90107b4d62f65";
    assert_eq!(
        store("http://127.0.0.1:1234", "registry").binding_digest(),
        pinned
    );
    let mut tuned = raw("http://127.0.0.1:1234");
    tuned["attemptTimeoutMilliseconds"] = json!(5000);
    tuned["sessionTokenRef"] = json!("secret:file/token");
    let rotated = SecretFiles::with(&[
        ("access", "rotated"),
        ("secret", "rotated-secret"),
        ("token", "rotated-token"),
    ]);
    assert_eq!(
        store_from(tuned, "registry", &rotated).binding_digest(),
        pinned
    );
    assert_ne!(
        store("http://127.0.0.1:1234", "other").binding_digest(),
        pinned
    );
    let mut moved = raw("http://127.0.0.1:1234");
    moved["bucket"] = json!("different-bucket");
    assert_ne!(
        store_from(moved, "registry", &SecretFiles::new()).binding_digest(),
        pinned
    );
    let mut region = raw("http://127.0.0.1:1234");
    region["region"] = json!("eu-west-1");
    assert_ne!(
        store_from(region, "registry", &SecretFiles::new()).binding_digest(),
        pinned
    );
    let settings = settings(raw("http://127.0.0.1:1234")).unwrap();
    let scope = hex::encode(Sha256::digest("registry"));
    assert_ne!(
        binding_digest(
            ObjectNamespace {
                binding_domain: "documents-s3-v1",
                ..NAMESPACE
            },
            &settings.bucket_url,
            &settings.region,
            &scope
        )
        .unwrap(),
        pinned
    );
}

async fn mock(
    body: &'static str,
    status: StatusCode,
    headers: &'static [(&'static str, &'static str)],
) -> (String, tokio::task::JoinHandle<()>) {
    use axum::{
        http::{HeaderName, HeaderValue},
        response::IntoResponse,
        routing::any,
        Router,
    };
    let app = Router::new().fallback(any(move || async move {
        let mut response = (status, body).into_response();
        for (name, value) in headers {
            response.headers_mut().insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        response
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, handle)
}

#[tokio::test]
async fn activation_probes_versioning_and_binds_the_scope() {
    let (url, server) = mock("<VersioningConfiguration/>", StatusCode::OK, &[]).await;
    let files = SecretFiles::new();
    let settings = settings(raw(&url)).unwrap();
    let first = settings
        .activate(NAMESPACE, "database-one/registry", &files.resolver())
        .await
        .unwrap();
    let second = settings
        .activate(NAMESPACE, "database-two/registry", &files.resolver())
        .await
        .unwrap();
    assert_ne!(first.binding_digest(), second.binding_digest());
    server.abort();
    let (url, server) = mock(
        "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>",
        StatusCode::OK,
        &[],
    )
    .await;
    assert_eq!(
        self::settings(raw(&url))
            .unwrap()
            .activate(NAMESPACE, "registry", &files.resolver())
            .await
            .unwrap_err(),
        ObjectStoreError::VersionedBucket
    );
    server.abort();
}

#[tokio::test]
async fn downloads_refuse_missing_corrupt_oversized_versioned_and_redirect_responses() {
    let digest = hex::encode(Sha256::digest(b"content"));
    for (body, status, headers, error) in [
        (
            "content",
            StatusCode::NOT_FOUND,
            &[][..],
            ObjectStoreError::Missing,
        ),
        (
            "content",
            StatusCode::FOUND,
            &[("location", "http://127.0.0.1:9/elsewhere")][..],
            ObjectStoreError::Unavailable,
        ),
        (
            "content",
            StatusCode::SERVICE_UNAVAILABLE,
            &[][..],
            ObjectStoreError::Unavailable,
        ),
        (
            "corrupt",
            StatusCode::OK,
            &[][..],
            ObjectStoreError::Integrity,
        ),
        (
            "content-too-long",
            StatusCode::OK,
            &[][..],
            ObjectStoreError::Integrity,
        ),
        (
            "content",
            StatusCode::OK,
            &[("x-amz-version-id", "3HL4kqtJlcpXroDTDmJ")][..],
            ObjectStoreError::VersionedBucket,
        ),
        (
            "content",
            StatusCode::OK,
            &[("x-amz-delete-marker", "true")][..],
            ObjectStoreError::VersionedBucket,
        ),
    ] {
        let (url, server) = mock(body, status, headers).await;
        assert_eq!(store(&url, "registry").get(&digest, 7).await, Err(error));
        server.abort();
    }
    let (url, server) = mock("content", StatusCode::OK, &[("x-amz-version-id", "null")]).await;
    let store = store(&url, "registry");
    assert_eq!(store.get(&digest, 7).await.unwrap(), b"content");
    assert_eq!(
        store.get(&digest, NAMESPACE.max_object_bytes + 1).await,
        Err(ObjectStoreError::Integrity)
    );
    server.abort();
}

#[tokio::test]
async fn writes_verify_remote_bytes_and_deletion_can_be_retried() {
    use axum::{extract::Request, routing::any, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let deletes = Arc::new(AtomicUsize::new(0));
    let count = deletes.clone();
    let app = Router::new().fallback(any(move |request: Request| {
        let count = count.clone();
        async move {
            if request.uri().query() == Some("versioning=") {
                (StatusCode::OK, "<VersioningConfiguration/>")
            } else if request.method() == Method::DELETE {
                if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    (StatusCode::SERVICE_UNAVAILABLE, "backend-secret-canary")
                } else {
                    (StatusCode::NO_CONTENT, "")
                }
            } else if request.method() == Method::PUT {
                (StatusCode::OK, "")
            } else if count.load(Ordering::SeqCst) > 0 {
                (StatusCode::NOT_FOUND, "")
            } else {
                (StatusCode::OK, "corrupt")
            }
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let store = store(&url, "registry");
    let digest = hex::encode(Sha256::digest(b"content"));
    assert_eq!(
        store.put(&digest, b"content".to_vec()).await,
        Err(ObjectStoreError::Integrity)
    );
    assert_eq!(
        store.put(&digest, b"other".to_vec()).await,
        Err(ObjectStoreError::Integrity)
    );
    let error = store.delete(&digest).await.unwrap_err();
    assert_eq!(error, ObjectStoreError::Unavailable);
    assert!(!format!("{error:?} {error}").contains("canary"));
    store.delete(&digest).await.unwrap();
    assert_eq!(deletes.load(Ordering::SeqCst), 2);
    server.abort();
}

#[tokio::test]
async fn download_refuses_interrupted_response() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npart")
            .await
            .unwrap();
    });
    let digest = hex::encode(Sha256::digest(b"content"));
    assert_eq!(
        store(&url, "registry").get(&digest, 7).await,
        Err(ObjectStoreError::Integrity)
    );
    server.await.unwrap();
}

/// Run against a disposable S3-compatible service with the synthetic
/// credentials above, as `products/breg/scripts/test-attachment-s3.sh` does.
/// This test creates a private bucket and enables then suspends versioning.
#[tokio::test]
#[ignore = "requires OBJECTSTORE_TEST_S3_URL pointing to a disposable S3-compatible service"]
async fn real_s3_put_get_deduplicate_delete_and_version_refusal() {
    let url = std::env::var("OBJECTSTORE_TEST_S3_URL").expect("disposable S3 URL required");
    let scope = format!("scope-{}", std::process::id());
    let mut store = store(&url, &scope);
    let bucket = format!(
        "objectstore-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    store.bucket_url.set_path(&format!("/{bucket}"));
    require_success(
        &store
            .send(Method::PUT, store.bucket_url.clone(), Vec::new())
            .await
            .unwrap(),
    )
    .unwrap();
    store.ensure_unversioned().await.unwrap();
    let bytes = b"synthetic request attachment".to_vec();
    let digest = hex::encode(Sha256::digest(&bytes));
    store.put(&digest, bytes.clone()).await.unwrap();
    store.put(&digest, bytes.clone()).await.unwrap();
    assert_eq!(store.get(&digest, bytes.len() as u64).await.unwrap(), bytes);
    assert_eq!(
        store.get(&digest, 1).await,
        Err(ObjectStoreError::Integrity)
    );
    require_success(
        &store
            .send(
                Method::PUT,
                store.object_url(&digest).unwrap(),
                b"corrupt content".to_vec(),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.get(&digest, bytes.len() as u64).await,
        Err(ObjectStoreError::Integrity)
    );
    store.put(&digest, bytes.clone()).await.unwrap();
    let response = store
        .send(Method::GET, store.bucket_url.clone(), Vec::new())
        .await
        .unwrap();
    let listing =
        String::from_utf8(read_bounded(response, MAXIMUM_CONTROL_BYTES).await.unwrap()).unwrap();
    assert_eq!(
        listing.matches("<Contents>").count(),
        1,
        "identical content has one physical object"
    );
    // A rejected authenticated attempt must leave the retained object intact;
    // retrying with the valid deployment credential can finish deletion.
    let wrong = SecretFiles::with(&[("access", "breg960test"), ("secret", "wrong-test-secret")]);
    let mut rejected = store_from(raw(&url), "retry", &wrong);
    rejected.bucket_url = store.bucket_url.clone();
    rejected.scope = store.scope.clone();
    assert_eq!(
        rejected.delete(&digest).await,
        Err(ObjectStoreError::Unavailable)
    );
    assert_eq!(store.get(&digest, bytes.len() as u64).await.unwrap(), bytes);
    store.delete(&digest).await.unwrap();
    store.delete(&digest).await.unwrap();
    assert_eq!(
        store.get(&digest, bytes.len() as u64).await,
        Err(ObjectStoreError::Missing)
    );
    // Simulate a PUT whose backend completion arrived after the first
    // deletion confirmation. A durable tombstone can reconcile it again.
    require_success(
        &store
            .send(
                Method::PUT,
                store.object_url(&digest).unwrap(),
                bytes.clone(),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(store.get(&digest, bytes.len() as u64).await.unwrap(), bytes);
    store.delete(&digest).await.unwrap();
    assert_eq!(
        store.get(&digest, bytes.len() as u64).await,
        Err(ObjectStoreError::Missing)
    );
    let mut versioning_url = store.bucket_url.clone();
    versioning_url.set_query(Some("versioning="));
    let enabled = br#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    require_success(
        &store
            .send(Method::PUT, versioning_url.clone(), enabled)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.ensure_unversioned().await,
        Err(ObjectStoreError::VersionedBucket)
    );
    assert_eq!(
        store.put(&digest, bytes.clone()).await,
        Err(ObjectStoreError::VersionedBucket)
    );
    assert_eq!(
        store.delete(&digest).await,
        Err(ObjectStoreError::VersionedBucket)
    );
    let suspended = br#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Suspended</Status></VersioningConfiguration>"#.to_vec();
    require_success(
        &store
            .send(Method::PUT, versioning_url, suspended)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.ensure_unversioned().await,
        Err(ObjectStoreError::VersionedBucket)
    );
    require_success(
        &store
            .send(Method::DELETE, store.bucket_url.clone(), Vec::new())
            .await
            .unwrap(),
    )
    .unwrap();
}

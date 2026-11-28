// SPDX-License-Identifier: Apache-2.0
//! Every refusal of a payment caller, through the real routes over a real
//! journal: the answer is frozen against a checked-in golden file (status,
//! the fixed headers and the body), and the refusal counter rises by one under
//! the check that refused.
//!
//! `ADAPTER_WRITE_GOLDEN=1` rewrites the golden file. Without it the answers
//! are compared to the file. Needs `ADAPTER_TEST_DATABASE_URL`; without it the
//! test fails on the spot.
use super::*;
use registry_platform_config::SecretProvider;
use registry_platform_testing::{
    access_token_test_key, jwks_from_private_jwk, sign_compact_jwt_with_key,
};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const ISSUER: &str = "https://issuer.example.test";
const AUDIENCE: &str = "registry-adapter-test";
const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/payment_refusals.json"
);

fn runtime() -> AdapterRuntimeConfig {
    serde_json::from_value(json!({
        "id": "payment-refusals",
        "endpoints": [{"endpoint": "tracker", "baseUrl": "https://tracker.example.invalid"}],
        "listener": {"bind": "127.0.0.1:8080"},
        "database": {
            "runtimeUrlRef": "secret:file/database-runtime",
            "migrationUrlRef": "secret:file/database-migration"
        },
        "oidc": {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "jwksSource": {"type": "static", "documentRef": "secret:file/issuer-keys.json"}
        },
        "allowedClients": ["coordinator", "other"],
        "allowedPrivateCidrs": ["10.0.0.0/8"],
        "audit": {"retentionDays": 90}
    }))
    .expect("the runtime configuration parses")
}

fn payments() -> PaymentsConfig {
    serde_json::from_value(json!({"connections":[{
        "id":"fees","institutionId":"ministry","serviceId":"permit","allowedClients":["coordinator"],"requiredScope":"payments:collections",
        "binding":{"simulation":true,"currency":"USD","currencyScale":2,"providerCredentialRef":"secret:env/SIMULATOR_TOKEN","providerCredentialIdentity":"producer","replayWindowSeconds":3600,
          "provider":{"type":"simulator","connection":{"baseUrl":"http://127.0.0.1:8099/","tenant":"pilot","biller":"ministry","billerName":"Ministry","callbackUrl":"https://programme.example.test/callback","payerFiBic":"SIMBANK"}},
          "registry":{"baseUrl":"http://127.0.0.1:8080/","recordType":"service-fee-bill","recordRoute":"service-fee-bills","readProfile":"reporter","bindProfile":"binder","receiptProfile":"reporter","bindAction":"bind-payment-attempt","receiptAction":"record-payment-receipt","credentialRef":"secret:env/REPORTER_TOKEN","credentialIdentity":"payment-adapter"}
        }}]}))
    .expect("the payment configuration parses")
}

fn token(
    key: &registry_platform_crypto::PrivateJwk,
    client: &str,
    scope: &str,
    exp: u64,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("epoch")
        .as_secs();
    sign_compact_jwt_with_key(
        key,
        "at+jwt",
        "canary-resource-key",
        json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": "workflow-service", "client_id": client,
            "scope": scope, "iat": now, "nbf": now, "exp": exp,
            "jti": Uuid::new_v4().to_string(),
        }),
    )
}

/// One request over a fresh connection: status, head, JSON body.
async fn send(
    port: u16,
    method: &str,
    path: &str,
    authorization: &[&str],
    body: Option<&Value>,
) -> (u16, String, Value) {
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for value in authorization {
        request.push_str(&format!("Authorization: {value}\r\n"));
    }
    let payload = body.map(Value::to_string).unwrap_or_default();
    if body.is_some() {
        request.push_str(&format!(
            "Content-Type: application/json\r\nIdempotency-Key: key-1\r\nContent-Length: {}\r\n",
            payload.len()
        ));
    }
    request.push_str("\r\n");
    request.push_str(&payload);
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect the payment router");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write the request");
    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .await
        .expect("read the answer");
    let (head, body) = raw.split_once("\r\n\r\n").expect("a header block");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("a status line");
    (
        status,
        head.to_owned(),
        serde_json::from_str(body).unwrap_or(Value::Null),
    )
}

/// A case: name, check, method, path, authorization headers, body.
type Case<'a> = (
    &'a str,
    &'a str,
    &'a str,
    String,
    Vec<String>,
    Option<&'a Value>,
);

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn frozen(status: u16, head: &str, body: &Value) -> Value {
    let mut body = body.clone();
    if let Some(object) = body.as_object_mut() {
        for member in ["traceId", "requestId"] {
            if object.contains_key(member) {
                object.insert(member.to_owned(), json!("<per-request>"));
            }
        }
    }
    json!({
        "status": status,
        "content-type": header(head, "content-type"),
        "www-authenticate": header(head, "www-authenticate"),
        "retry-after": header(head, "retry-after"),
        "cache-control": header(head, "cache-control"),
        "x-content-type-options": header(head, "x-content-type-options"),
        "traceparent-present": header(head, "traceparent").is_some(),
        "body": body,
    })
}

#[tokio::test]
async fn every_payment_refusal_keeps_its_answer_and_is_counted_under_its_check() {
    let signing_key = access_token_test_key(jsonwebtoken::Algorithm::ES256);
    let directory = tempfile::tempdir().expect("a scratch directory");
    let root = directory.path().canonicalize().expect("physical directory");
    let key_file = root.join("issuer-keys.json");
    std::fs::write(&key_file, jwks_from_private_jwk(&signing_key).to_string())
        .expect("write the key set");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only key file");
    }
    let resolver = Arc::new(SecretResolver::new([SecretProvider::File], root).expect("resolver"));
    let authenticator = crate::serve::authenticator(&runtime(), &resolver)
        .await
        .expect("the authenticator builds over the static key set");

    let url = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("postgres-test requires ADAPTER_TEST_DATABASE_URL");
    let manager = deadpool_postgres::Manager::new(
        url.parse().expect("a database url"),
        tokio_postgres::NoTls,
    );
    let pool = deadpool_postgres::Pool::builder(manager)
        .max_size(8)
        .build()
        .expect("a pool");
    {
        let mut client = pool.get().await.expect("a connection");
        migrate(&mut client).await.expect("the payment tables");
    }
    let deployment = format!("payment-refusals-{}", Uuid::new_v4());
    let service = PaymentService::new(
        payments(),
        PaymentStore::new(pool.clone(), deployment.clone()),
        Arc::new(BregBridge::new(resolver.clone())),
        Arc::new(SyntheticProvider::new(resolver.clone(), None)),
    )
    .expect("the payment service");
    let g2p = G2pService::new(
        G2pStore::new(pool, deployment),
        Arc::new(BregG2pBridge::new(resolver.clone())),
        Arc::new(HttpG2pProvider::new(resolver)),
    );
    let state = Arc::new(HttpState {
        authenticator,
        service,
        g2p,
        disbursements: Vec::new(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a probe port");
    let port = listener.local_addr().expect("the probe port").port();
    tokio::spawn(async move {
        axum::serve(listener, payment_router(state))
            .await
            .expect("the payment router serves");
    });

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("epoch")
        .as_secs();
    let good = |client: &str, scope: &str| {
        format!("Bearer {}", token(&signing_key, client, scope, now + 300))
    };
    let expired = format!(
        "Bearer {}",
        token(
            &signing_key,
            "coordinator",
            "payments:collections",
            now - 3_600
        )
    );
    let stranger = good("stranger", "payments:collections");
    let forged = {
        let other = access_token_test_key(jsonwebtoken::Algorithm::ES256);
        format!(
            "Bearer {}",
            token(&other, "coordinator", "payments:collections", now + 300)
        )
    };
    let member = good("coordinator", "payments:collections");
    let other_client = good("other", "payments:collections");
    let no_scope = good("coordinator", "other.scope");
    let collection = json!({"billId": Uuid::new_v4(), "billVersion": 1});
    let disbursement = json!({"instructionRecordId": Uuid::new_v4(), "instructionVersion": 1});
    let known = "/v1/payments/fees/collections";
    let missing_attempt = format!("{known}/{}", Uuid::new_v4());

    let counter = |check: &str| {
        crate::metrics::refusal_recorder()
            .counter()
            .get(&[check])
            .expect("every check is declared")
    };
    let mut answers = serde_json::Map::new();
    // Each case: name, check, method, path, authorization headers, body.
    let cases: Vec<Case> = vec![
        (
            "no-authorization",
            "credential-missing",
            "POST",
            known.into(),
            vec![],
            Some(&collection),
        ),
        (
            "basic-scheme",
            "credential-missing",
            "POST",
            known.into(),
            vec!["Basic YWJjOmRlZg==".into()],
            Some(&collection),
        ),
        (
            "two-authorization-headers",
            "credential-malformed",
            "POST",
            known.into(),
            vec![member.clone(), member.clone()],
            Some(&collection),
        ),
        (
            "not-a-compact-token",
            "credential-malformed",
            "POST",
            known.into(),
            vec!["Bearer not-a-token".into()],
            Some(&collection),
        ),
        (
            "unknown-signer",
            "token-signature",
            "POST",
            known.into(),
            vec![forged],
            Some(&collection),
        ),
        (
            "expired",
            "token-time",
            "POST",
            known.into(),
            vec![expired],
            Some(&collection),
        ),
        (
            "unlisted-client",
            "token-client",
            "POST",
            known.into(),
            vec![stranger],
            Some(&collection),
        ),
        (
            "unknown-connection",
            "visibility",
            "POST",
            "/v1/payments/nowhere/collections".into(),
            vec![member.clone()],
            Some(&collection),
        ),
        (
            "client-not-allowed",
            "requester-client",
            "POST",
            known.into(),
            vec![other_client],
            Some(&collection),
        ),
        (
            "scope-not-held",
            "scope",
            "POST",
            known.into(),
            vec![no_scope],
            Some(&collection),
        ),
        (
            "unknown-attempt",
            "visibility",
            "GET",
            missing_attempt,
            vec![member.clone()],
            None,
        ),
        (
            "unknown-disbursement-connection",
            "visibility",
            "POST",
            "/v1/payments/nowhere/disbursements".into(),
            vec![member.clone()],
            Some(&disbursement),
        ),
    ];
    let mut deltas: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    for (name, check, method, path, authorization, body) in &cases {
        let before = counter(check);
        let headers: Vec<&str> = authorization.iter().map(String::as_str).collect();
        let (status, head, answer) = send(port, method, path, &headers, *body).await;
        answers.insert((*name).to_owned(), frozen(status, &head, &answer));
        *deltas.entry(check).or_default() += counter(check) - before;
    }
    let answers = Value::Object(answers);
    if std::env::var_os("ADAPTER_WRITE_GOLDEN").is_some() {
        std::fs::write(
            GOLDEN,
            serde_json::to_string_pretty(&answers).expect("serialize the golden") + "\n",
        )
        .expect("write the golden file");
    }
    let golden: Value = serde_json::from_str(
        &std::fs::read_to_string(GOLDEN).expect("the golden file is checked in"),
    )
    .expect("the golden file is JSON");
    assert_eq!(answers, golden, "a payment refusal answer changed");
    let mut wanted: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    for (_, check, ..) in &cases {
        *wanted.entry(check).or_default() += 1;
    }
    assert_eq!(
        deltas, wanted,
        "each refusal is counted once under its check"
    );
}

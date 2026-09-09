// SPDX-License-Identifier: Apache-2.0
//! Supervised loopback webhook inbox. Receipt is distinct from runtime delivery state.

use super::private;
use anyhow::{bail, Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use registry_breg::contract::EventTrigger;
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    net::{Ipv4Addr, TcpListener},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

const MAX_BODY: usize = 1024 * 1024;
const MAX_STORAGE: u64 = 16 * 1024 * 1024;
const SIGNED_HEADERS: [&str; 9] = [
    "ce-specversion",
    "ce-id",
    "ce-source",
    "ce-type",
    "ce-time",
    "ce-dataschema",
    "x-registry-event-generation",
    "x-registry-delivery-attempt",
    "x-registry-delivery-time",
];

pub(super) struct Receiver {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

struct Inbox {
    root: PathBuf,
    key: Zeroizing<Vec<u8>>,
    deliveries: BTreeMap<(String, String), Delivery>,
}

struct Delivery {
    id: String,
    destination_id: String,
    trigger: EventTrigger,
    data_schema: String,
    projection_fields: Vec<String>,
}

impl Receiver {
    pub(super) fn start(root: &Path, port: u16) -> Result<Self> {
        let compiled = crate::compile(&root.join("project"), crate::ProfileArg::Production, "dev")
            .map_err(|_| anyhow::anyhow!("captured event project no longer compiles"))?;
        if compiled
            .package()
            .is_none_or(|identity| identity.environment != "local")
        {
            bail!("local webhook receiver requires package.environment: local");
        }
        let deliveries = compiled
            .event_deliveries()
            .deliveries
            .iter()
            .map(|delivery| {
                (
                    (delivery.event_id.clone(), delivery.entity_id.clone()),
                    Delivery {
                        id: delivery.id.clone(),
                        destination_id: delivery.destination_id.clone(),
                        trigger: delivery.trigger,
                        data_schema: delivery.data_schema.clone(),
                        projection_fields: delivery.projection_fields.clone(),
                    },
                )
            })
            .collect();
        Self::start_with_deliveries(root, port, deliveries)
    }

    fn start_with_deliveries(
        root: &Path,
        port: u16,
        deliveries: BTreeMap<(String, String), Delivery>,
    ) -> Result<Self> {
        private::check(root, true)?;
        // Runtime secret:file resolution uses the exact file bytes as the HMAC
        // key. Generated base64url text is key material, not a transport encoding
        // for the receiver to decode independently.
        let key = Zeroizing::new(private::read(&root.join("secrets/webhook-key"), 64 * 1024)?);
        if key.len() < 32 {
            bail!("local webhook key must contain at least 32 bytes");
        }
        {
            let _lock = storage_lock(root)?;
            let path = root.join("events.jsonl");
            if path.try_exists()? {
                private::read(&path, MAX_STORAGE)?;
            } else {
                private::create(&path, b"")?;
            }
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .context("cannot bind retained local webhook receiver port")?;
        listener.set_nonblocking(true)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let listener = {
            let _guard = runtime.enter();
            tokio::net::TcpListener::from_std(listener)?
        };
        let inbox = Arc::new(Inbox {
            root: root.to_path_buf(),
            key,
            deliveries,
        });
        let (stop, stopped) = oneshot::channel();
        let thread = thread::Builder::new()
            .name("breg-dev-events".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let app = Router::new()
                        .route("/events", post(receive))
                        .with_state(inbox);
                    // Dropping the server future also closes accepted connections, so a slow
                    // local sender cannot keep the supervisor alive after shutdown.
                    tokio::select! {
                        _ = stopped => (),
                        _ = async { let _ = axum::serve(listener, app).await; } => (),
                    }
                });
            })?;
        Ok(Self {
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    pub(super) fn exited(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn receive(
    State(inbox): State<Arc<Inbox>>,
    request: Request<Body>,
) -> (StatusCode, &'static str) {
    if request.uri().path_and_query().map(|value| value.as_str()) != Some("/events") {
        return (StatusCode::BAD_REQUEST, "invalid local webhook request");
    }
    let (parts, body) = request.into_parts();
    let Ok(Ok(body)) = tokio::time::timeout(Duration::from_secs(5), to_bytes(body, MAX_BODY)).await
    else {
        return (StatusCode::BAD_REQUEST, "invalid local webhook request");
    };
    let Ok(mut record) = verify(&inbox.key, &parts.headers, &body) else {
        return (
            StatusCode::UNAUTHORIZED,
            "local webhook verification refused",
        );
    };
    let Some(delivery) = inbox.deliveries.get(&(
        record["eventType"].as_str().unwrap_or_default().to_owned(),
        record["entity"].as_str().unwrap_or_default().to_owned(),
    )) else {
        return (
            StatusCode::UNAUTHORIZED,
            "local webhook verification refused",
        );
    };
    // The runtime emits every compiled projection key, including fields whose
    // captured value is null. Signed but differently shaped packets must not
    // become teaching receipts for the captured event contract.
    let values = record["payload"]
        .as_object()
        .expect("verified projection object");
    if serde_json::from_value::<EventTrigger>(record["trigger"].clone()).ok()
        != Some(delivery.trigger)
        || header(&parts.headers, "ce-dataschema").ok() != Some(delivery.data_schema.as_str())
        || values.len() != delivery.projection_fields.len()
        || !delivery
            .projection_fields
            .iter()
            .all(|field| values.contains_key(field))
    {
        return (
            StatusCode::UNAUTHORIZED,
            "local webhook verification refused",
        );
    }
    record["deliveryId"] = Value::String(delivery.id.clone());
    record["destinationId"] = Value::String(delivery.destination_id.clone());
    match append(&inbox.root, &record) {
        Ok(()) => (StatusCode::NO_CONTENT, ""),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE,
            "local event storage unavailable: verify owner-only permissions and the 16 MiB inbox bound"),
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .context("webhook metadata is missing")?
        .to_str()
        .map_err(|_| anyhow::anyhow!("webhook metadata must be ASCII"))?;
    if values.next().is_some()
        || value.is_empty()
        || value.len() > 1024
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        bail!("webhook metadata is ambiguous or exceeds its bound");
    }
    Ok(value)
}

fn positive(value: &str) -> Result<u64> {
    if value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("webhook counter is invalid");
    }
    value.parse().context("webhook counter exceeds its bound")
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn verify(key: &[u8], headers: &HeaderMap, body: &[u8]) -> Result<Value> {
    let signed = SIGNED_HEADERS
        .iter()
        .map(|name| header(headers, name))
        .collect::<Result<Vec<_>>>()?;
    if signed[0] != "1.0"
        || header(headers, "content-type")? != "application/json"
        || header(headers, "accept")? != "application/json"
        || body.is_empty()
        || body.len() > MAX_BODY
    {
        bail!("webhook profile is invalid");
    }
    let event_id = uuid::Uuid::parse_str(signed[1]).context("webhook event identity is invalid")?;
    if event_id.to_string() != signed[1] {
        bail!("webhook event identity must be canonical");
    }
    OffsetDateTime::parse(signed[4], &Rfc3339).context("webhook event time is invalid")?;
    let delivery_time =
        OffsetDateTime::parse(signed[8], &Rfc3339).context("webhook delivery time is invalid")?;
    if (OffsetDateTime::now_utc() - delivery_time).abs() > time::Duration::seconds(30) {
        bail!("webhook delivery time is stale");
    }
    let generation = positive(signed[6])?;
    let attempt = positive(signed[7])?;
    let idempotency_key = header(headers, "idempotency-key")?;
    if !digest(idempotency_key) {
        bail!("webhook idempotency key is invalid");
    }
    let signature = header(headers, "x-registry-signature")?
        .strip_prefix("v1=")
        .context("webhook signature version is invalid")?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| anyhow::anyhow!("webhook signature encoding is invalid"))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).context("webhook key is invalid")?;
    mac.update(b"breg-webhook-signature-v1");
    for value in signed.iter().map(|value| value.as_bytes()).chain([
        b"POST".as_slice(),
        b"/events".as_slice(),
        b"application/json".as_slice(),
        idempotency_key.as_bytes(),
        body,
    ]) {
        mac.update(&(value.len() as u64).to_be_bytes());
        mac.update(value);
    }
    mac.verify_slice(&signature)
        .map_err(|_| anyhow::anyhow!("webhook signature is invalid"))?;
    let document = parse_json_strict(body).context("webhook body is invalid")?;
    if canonicalize_json(&document)? != body {
        bail!("webhook body is not canonical");
    }
    let object = document
        .as_object()
        .context("webhook body must be an object")?;
    let lifecycle = document["trigger"] == "request_lifecycle";
    if object.len() != if lifecycle { 7 } else { 6 }
        || ![
            "entity",
            "recordId",
            "revision",
            "trigger",
            "packageRevision",
            "values",
        ]
        .iter()
        .all(|field| object.contains_key(*field))
        || (lifecycle && !document["request"].is_object())
        || !document["values"].is_object()
        || document["revision"].as_u64().is_none_or(|n| n == 0)
        || !document["packageRevision"].as_str().is_some_and(digest)
        || !document["entity"]
            .as_str()
            .is_some_and(|entity| !entity.is_empty() && entity.len() <= 64)
        || !matches!(
            document["trigger"].as_str(),
            Some("created" | "patched" | "tombstoned" | "request_lifecycle")
        )
        || !document["recordId"].as_str().is_some_and(|id| {
            uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id)
        })
    {
        bail!("webhook body shape is invalid");
    }
    let registry = signed[2]
        .strip_prefix("urn:registrystack:registry:")
        .and_then(|source| source.split_once(":instance:"))
        .filter(|(registry, instance)| !registry.is_empty() && !instance.is_empty())
        .context("webhook source is invalid")?
        .0;
    let prefix = format!(
        "urn:breg:event-schema:{registry}:{}:{}:",
        document["entity"]
            .as_str()
            .context("webhook entity is invalid")?,
        signed[3]
    );
    if !signed[5].strip_prefix(&prefix).is_some_and(digest) {
        bail!("webhook schema does not match event metadata");
    }
    Ok(json!({
        "eventId":signed[1],"eventType":signed[3],"entity":document["entity"],
        "trigger":document["trigger"],"deliveryId":null,"idempotencyKey":idempotency_key,
        "generation":generation,"attempt":attempt,"status":"received",
        "receivedAt":OffsetDateTime::now_utc().format(&Rfc3339)?,"payload":document["values"]
    }))
}

fn storage_lock(root: &Path) -> Result<File> {
    private::check(root, true)?;
    let path = root.join("events.lock");
    if !path.try_exists()? {
        match private::create(&path, b"") {
            Ok(()) => (),
            Err(_) if path.try_exists()? => (),
            Err(error) => return Err(error),
        }
    }
    private::check(&path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)?;
    let opened = file.metadata()?;
    private::check_metadata(&opened, false)?;
    let named = fs::symlink_metadata(&path)?;
    if named.ino() != opened.ino() || named.dev() != opened.dev() {
        bail!("local event storage changed while opening it");
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => break,
            Err(error) if error == rustix::io::Errno::WOULDBLOCK && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => bail!("local event storage is busy or unavailable; retry the command"),
        }
    }
    Ok(file)
}

fn append(root: &Path, record: &Value) -> Result<()> {
    let _lock = storage_lock(root)?;
    let path = root.join("events.jsonl");
    let mut bytes = private::read(&path, MAX_STORAGE)?;
    let line = serde_json::to_vec(record)?;
    if bytes.len() as u64 + line.len() as u64 + 1 > MAX_STORAGE {
        bail!("local event inbox reached its 16 MiB bound; stop the session and move the journal to an owner-only location before restarting");
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        bail!("local event inbox has an incomplete record");
    }
    bytes.extend_from_slice(&line);
    bytes.push(b'\n');
    // Atomic replacement under the stable lock prevents partial reports and
    // acknowledges only a durable complete record, including repeated attempts.
    private::replace(&path, &bytes)
}

pub(super) fn report(root: &Path, include_payload: bool) -> Result<Value> {
    let _lock = storage_lock(root)?;
    let path = root.join("events.jsonl");
    // Reject dangling links as well as links to existing files before deciding
    // that an event-free development instance has no retained receipts.
    match fs::symlink_metadata(&path) {
        Ok(metadata) => private::check_metadata(&metadata, false)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let mut deliveries = Vec::new();
    if path.try_exists()? {
        let bytes = private::read(&path, MAX_STORAGE)?;
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            bail!("local event inbox has an incomplete record");
        }
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let mut record =
                parse_json_strict(line).context("local event inbox record is invalid")?;
            if !include_payload {
                let metadata = record
                    .as_object_mut()
                    .context("local event inbox record is invalid")?;
                metadata.retain(|key, _| {
                    matches!(
                        key.as_str(),
                        "eventId"
                            | "eventType"
                            | "entity"
                            | "trigger"
                            | "deliveryId"
                            | "destinationId"
                            | "idempotencyKey"
                            | "generation"
                            | "attempt"
                            | "status"
                            | "receivedAt"
                    )
                });
            }
            deliveries.push(record);
        }
    }
    Ok(json!({"ok":true,"command":"dev events","deliveries":deliveries}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::{io::Write, net::TcpStream, os::unix::fs::PermissionsExt, time::Instant};

    fn fixture() -> (tempfile::TempDir, u16, Receiver) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        private::directory(&root.path().join("secrets")).unwrap();
        private::create(
            &root.path().join("secrets/webhook-key"),
            URL_SAFE_NO_PAD.encode([7; 32]).as_bytes(),
        )
        .unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let receiver = Receiver::start_with_deliveries(
            root.path(),
            port,
            BTreeMap::from([(
                ("record-created-v1".into(), "record".into()),
                Delivery {
                    id: "events.record.record-created-v1.webhook".into(),
                    destination_id: "local-hook".into(),
                    trigger: EventTrigger::Created,
                    data_schema: format!(
                        "urn:breg:event-schema:example:record:record-created-v1:sha256:{}",
                        "0".repeat(64)
                    ),
                    projection_fields: vec!["label".into()],
                },
            )]),
        )
        .unwrap();
        (root, port, receiver)
    }

    fn signed(attempt: u64, generation: u64) -> (HeaderMap, Vec<u8>) {
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("accept", "application/json".into()),
            ("content-type", "application/json".into()),
            ("ce-specversion", "1.0".into()),
            ("ce-id", "00000000-0000-4000-8000-000000000001".into()),
            (
                "ce-source",
                "urn:registrystack:registry:example:instance:local".into(),
            ),
            ("ce-type", "record-created-v1".into()),
            ("ce-time", now.clone()),
            (
                "ce-dataschema",
                format!(
                    "urn:breg:event-schema:example:record:record-created-v1:sha256:{}",
                    "0".repeat(64)
                ),
            ),
            ("x-registry-event-generation", generation.to_string()),
            ("x-registry-delivery-attempt", attempt.to_string()),
            ("x-registry-delivery-time", now),
            ("idempotency-key", format!("sha256:{}", "1".repeat(64))),
        ] {
            headers.insert(name, HeaderValue::from_str(&value).unwrap());
        }
        let body = canonicalize_json(&json!({
            "entity":"record", "recordId":"00000000-0000-4000-8000-000000000002",
            "revision":1,"trigger":"created","packageRevision":format!("sha256:{}", "0".repeat(64)),
            "values":{"label":"projected-value-canary"}
        }))
        .unwrap();
        sign(&mut headers, &body);
        (headers, body)
    }

    fn sign(headers: &mut HeaderMap, body: &[u8]) {
        sign_with_key(headers, body, URL_SAFE_NO_PAD.encode([7; 32]).as_bytes());
    }

    fn sign_with_key(headers: &mut HeaderMap, body: &[u8], key: &[u8]) {
        // Independently construct the documented wire message, like the demo
        // verifier, rather than calling the receiver's verification routine.
        let mut input = b"breg-webhook-signature-v1".to_vec();
        for value in SIGNED_HEADERS
            .iter()
            .map(|name| headers[*name].as_bytes())
            .chain([
                b"POST".as_slice(),
                b"/events".as_slice(),
                b"application/json".as_slice(),
                headers["idempotency-key"].as_bytes(),
                body,
            ])
        {
            input.extend_from_slice(&(value.len() as u64).to_be_bytes());
            input.extend_from_slice(value);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(&input);
        headers.insert(
            "x-registry-signature",
            HeaderValue::from_str(&format!(
                "v1={}",
                URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
            ))
            .unwrap(),
        );
    }

    fn request(port: u16, headers: HeaderMap, body: Vec<u8>) -> u16 {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                reqwest::Client::builder()
                    .no_proxy()
                    .timeout(Duration::from_secs(3))
                    .build()
                    .unwrap()
                    .post(format!("http://127.0.0.1:{port}/events"))
                    .headers(headers)
                    .body(body)
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .as_u16()
            })
    }

    #[test]
    fn signed_receipts_preserve_attempts_and_generation_and_redact_values() {
        let (root, port, receiver) = fixture();
        for (attempt, generation) in [(1, 1), (2, 1), (1, 2)] {
            let (headers, body) = signed(attempt, generation);
            assert_eq!(request(port, headers, body), 204);
        }
        assert!(!receiver.exited());
        let metadata = report(root.path(), false).unwrap();
        assert!(!metadata.to_string().contains("projected-value-canary"));
        assert!(!metadata
            .to_string()
            .contains("00000000-0000-4000-8000-000000000002"));
        let records = metadata["deliveries"].as_array().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[1]["attempt"], 2);
        assert_eq!(records[2]["generation"], 2);
        assert_eq!(records[0]["status"], "received");
        assert_eq!(
            records[0]["deliveryId"],
            "events.record.record-created-v1.webhook"
        );
        assert_eq!(records[0]["destinationId"], "local-hook");
        assert_eq!(
            report(root.path(), true).unwrap()["deliveries"][0]["payload"]["label"],
            "projected-value-canary"
        );
        assert_eq!(
            fs::metadata(root.path().join("events.jsonl"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(receiver);
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
        assert_eq!(
            report(root.path(), false).unwrap()["deliveries"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn configured_raw_key_bytes_match_runtime_and_decoded_key_is_refused() {
        let (root, port, _receiver) = fixture();
        let key = private::read(&root.path().join("secrets/webhook-key"), 128).unwrap();
        let (mut headers, body) = signed(1, 1);
        sign_with_key(&mut headers, &body, &key);
        assert_eq!(request(port, headers, body), 204);
        let (mut headers, body) = signed(2, 1);
        let decoded = URL_SAFE_NO_PAD.decode(&key).unwrap();
        sign_with_key(&mut headers, &body, &decoded);
        assert_eq!(request(port, headers, body), 401);
        assert_eq!(
            report(root.path(), false).unwrap()["deliveries"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn tampered_stale_duplicate_and_noncanonical_packets_are_refused() {
        let (root, port, _receiver) = fixture();
        let (headers, mut body) = signed(1, 1);
        body.push(b' ');
        assert_eq!(request(port, headers, body), 401);
        let (mut headers, body) = signed(1, 1);
        headers.insert("x-registry-delivery-attempt", HeaderValue::from_static("2"));
        assert_eq!(request(port, headers, body), 401);
        let (mut headers, body) = signed(1, 1);
        headers.append("ce-type", HeaderValue::from_static("record-created-v1"));
        assert_eq!(request(port, headers, body), 401);
        let (mut headers, body) = signed(1, 1);
        headers.insert(
            "x-registry-delivery-time",
            HeaderValue::from_static("2020-01-01T00:00:00Z"),
        );
        sign(&mut headers, &body);
        assert_eq!(request(port, headers, body), 401);
        let (mut headers, mut body) = signed(1, 1);
        body.push(b' ');
        sign(&mut headers, &body);
        assert_eq!(request(port, headers, body), 401);
        assert!(report(root.path(), false).unwrap()["deliveries"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn signed_packets_must_match_compiled_trigger_schema_and_projection() {
        let (root, port, _receiver) = fixture();
        for change in [
            "trigger",
            "schema",
            "extra projection",
            "missing projection",
        ] {
            let (mut headers, body) = signed(1, 1);
            let mut document = parse_json_strict(&body).unwrap();
            match change {
                "trigger" => document["trigger"] = json!("patched"),
                "schema" => {
                    headers.insert(
                        "ce-dataschema",
                        HeaderValue::from_str(&format!(
                            "urn:breg:event-schema:example:record:record-created-v1:sha256:{}",
                            "f".repeat(64)
                        ))
                        .unwrap(),
                    );
                }
                "extra projection" => {
                    document["values"]["undeclared"] = json!("extra-value-canary")
                }
                "missing projection" => {
                    document["values"].as_object_mut().unwrap().remove("label");
                }
                _ => unreachable!(),
            }
            let body = canonicalize_json(&document).unwrap();
            sign(&mut headers, &body);
            assert_eq!(request(port, headers, body), 401, "{change}");
            assert_eq!(
                report(root.path(), true).unwrap()["deliveries"],
                json!([]),
                "{change}"
            );
        }
        let (headers, body) = signed(1, 1);
        assert_eq!(request(port, headers, body), 204);
        assert_eq!(
            report(root.path(), false).unwrap()["deliveries"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn projected_null_values_remain_present_in_the_exact_key_set() {
        let (root, port, _receiver) = fixture();
        let (mut headers, body) = signed(1, 1);
        let mut document = parse_json_strict(&body).unwrap();
        document["values"]["label"] = Value::Null;
        let body = canonicalize_json(&document).unwrap();
        sign(&mut headers, &body);
        assert_eq!(request(port, headers, body), 204);
        assert_eq!(
            report(root.path(), true).unwrap()["deliveries"][0]["payload"],
            json!({"label":null})
        );
    }

    #[test]
    fn unsafe_or_full_storage_refuses_acknowledgement_and_recovers() {
        let (root, port, _receiver) = fixture();
        let path = root.path().join("events.jsonl");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let (headers, body) = signed(1, 1);
        assert_eq!(request(port, headers, body), 503);
        assert!(report(root.path(), false).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (headers, body) = signed(2, 1);
        assert_eq!(request(port, headers, body), 204);
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_STORAGE)
            .unwrap();
        let (headers, body) = signed(1, 2);
        assert_eq!(request(port, headers, body), 503);
        assert_eq!(fs::metadata(&path).unwrap().len(), MAX_STORAGE);
    }

    #[test]
    fn receiver_shutdown_does_not_wait_for_an_incomplete_request() {
        let (_root, port, receiver) = fixture();
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        stream
            .write_all(b"POST /events HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n{")
            .unwrap();
        let started = Instant::now();
        drop(receiver);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
    }

    #[test]
    fn empty_inbox_and_concurrent_reports_use_complete_snapshots() {
        let empty = tempfile::tempdir().unwrap();
        fs::set_permissions(empty.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            report(empty.path(), false).unwrap()["deliveries"],
            json!([])
        );
        let (root, port, _receiver) = fixture();
        let path = root.path().to_owned();
        let reader = thread::spawn(move || {
            for _ in 0..20 {
                let snapshot = report(&path, false).unwrap();
                assert!(snapshot["deliveries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|record| {
                        record["status"] == "received" && record.get("payload").is_none()
                    }));
            }
        });
        for attempt in 1..=5 {
            let (headers, body) = signed(attempt, 1);
            assert_eq!(request(port, headers, body), 204);
        }
        reader.join().unwrap();
        assert_eq!(
            report(root.path(), false).unwrap()["deliveries"]
                .as_array()
                .unwrap()
                .len(),
            5
        );
    }

    #[test]
    fn symbolic_link_and_hard_link_storage_are_refused() {
        let (root, _port, receiver) = fixture();
        drop(receiver);
        let path = root.path().join("events.jsonl");
        let target = root.path().join("target.jsonl");
        fs::rename(&path, &target).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(report(root.path(), false).is_err());
        fs::remove_file(&path).unwrap();
        fs::hard_link(&target, &path).unwrap();
        assert!(report(root.path(), false).is_err());
    }
}

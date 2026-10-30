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
use registry_breg::model::{CompiledEventDelivery, CompiledRegistry};
use registry_platform_canonical_json::parse_json_strict;
use registry_platform_hooks::{
    receiver::{verify_delivery, DeliveryFreshness, SignedDelivery},
    EnvelopeLimits, EventSubject, HookEnvelope,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    net::{Ipv4Addr, TcpListener},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

const MAX_BODY: usize = 1024 * 1024;
const MAX_STORAGE: u64 = 16 * 1024 * 1024;

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
    matching: Vec<(String, String)>,
    data_schema: String,
    source: String,
    schema: jsonschema::JSONSchema,
}

impl Delivery {
    fn compile(
        registry: &CompiledRegistry,
        delivery: &CompiledEventDelivery,
        instance_id: &str,
    ) -> Result<Self> {
        let artifact = registry
            .artifacts()
            .get(&delivery.data_schema_artifact_path)
            .context("compiled local event schema is missing")?;
        let schema =
            parse_json_strict(&artifact.bytes).context("compiled local event schema is invalid")?;
        let schema = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .should_validate_formats(true)
            .compile(&schema)
            .map_err(|_| anyhow::anyhow!("compiled local event schema cannot be validated"))?;
        Ok(Self {
            id: delivery.id.clone(),
            matching: Vec::new(),
            destination_id: delivery
                .destination_id
                .clone()
                .context("local event receiver serves url deliveries only")?,
            data_schema: delivery.data_schema.clone(),
            // The engine names its source from the runtime
            // `identity.instanceId`, which a package does not carry.
            source: format!(
                "urn:registrystack:registry:{}:instance:{instance_id}",
                registry.registry_id(),
            ),
            schema,
        })
    }
}

impl Receiver {
    pub(super) fn start(root: &Path, port: u16, instance_id: &str) -> Result<Self> {
        let compiled = crate::compile(&root.join("project"), crate::ProfileArg::Production, "dev")
            .map_err(|_| anyhow::anyhow!("captured event project no longer compiles"))?;
        // The local receiver stands in for a remote destination, so it holds
        // the url deliveries only; a local handler runs inside the engine and
        // never reaches an HTTP receiver.
        let mut deliveries: BTreeMap<(String, String), Delivery> = BTreeMap::new();
        for delivery in compiled
            .event_deliveries()
            .deliveries
            .iter()
            .filter(|delivery| delivery.destination_id.is_some())
        {
            let keys = match &delivery.owner {
                registry_breg::model::CompiledEventOwner::RecordType { record_type, .. } => {
                    vec![(delivery.event_id.clone(), record_type.clone())]
                }
                registry_breg::model::CompiledEventOwner::ProposalAction { action } => {
                    let owner = compiled
                        .actions()
                        .actions
                        .iter()
                        .find(|entry| &entry.id == action)
                        .context("Proposal observer Action is missing")?;
                    let registry_breg::model::CompiledActionExecution::Proposal { proposal } =
                        &owner.execution
                    else {
                        bail!("Proposal observer Action mode is invalid")
                    };
                    let hook = proposal
                        .hooks
                        .iter()
                        .find(|hook| hook.id == delivery.event_id)
                        .context("Proposal observer declaration is missing")?;
                    registry_breg::proposal_hooks::matching_transitions(&hook.transitions)
                        .map(|transition| {
                            (format!("proposal.{}", transition.as_str()), action.clone())
                        })
                        .collect()
                }
            };
            for key in keys {
                if let Some(existing) = deliveries.get_mut(&key) {
                    existing.matching.push((
                        delivery.id.clone(),
                        delivery.destination_id.clone().expect("URL delivery"),
                    ));
                } else {
                    deliveries.insert(key, Delivery::compile(&compiled, delivery, instance_id)?);
                }
            }
        }
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
    let Ok((mut record, document)) = verify(&inbox.key, &parts.headers, &body) else {
        return (
            StatusCode::UNAUTHORIZED,
            "local webhook verification refused",
        );
    };
    let Some(delivery) = inbox.deliveries.get(&(
        record["eventType"].as_str().unwrap_or_default().to_owned(),
        record["recordType"]
            .as_str()
            .or_else(|| record["actionId"].as_str())
            .unwrap_or_default()
            .to_owned(),
    )) else {
        return (
            StatusCode::UNAUTHORIZED,
            "local webhook verification refused",
        );
    };
    // Validate the complete body against the same generated contract that
    // supplies its signed schema identity, including nullable projected fields
    // and the closed request metadata on lifecycle events.
    if header(&parts.headers, "ce-dataschema").ok() != Some(delivery.data_schema.as_str())
        || header(&parts.headers, "ce-source").ok() != Some(delivery.source.as_str())
        || !delivery.schema.is_valid(&document)
    {
        return (
            StatusCode::UNAUTHORIZED,
            "local webhook verification refused",
        );
    }
    if delivery.matching.is_empty() {
        record["deliveryId"] = Value::String(delivery.id.clone());
        record["destinationId"] = Value::String(delivery.destination_id.clone());
    } else {
        // The signed transport identifies the event, not its subscription.
        // Keep the candidate subscriptions instead of guessing which sent it.
        let matching = std::iter::once((&delivery.id, &delivery.destination_id))
            .chain(
                delivery
                    .matching
                    .iter()
                    .map(|(id, destination)| (id, destination)),
            )
            .map(|(id, destination)| json!({"deliveryId":id,"destinationId":destination}))
            .collect::<Vec<_>>();
        record["matchingDeliveries"] = json!(matching);
    }
    match append(&inbox.root, &record) {
        Ok(()) => (StatusCode::NO_CONTENT, ""),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "local event storage unavailable: verify owner-only permissions and the 16 MiB inbox bound",
        ),
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

fn verify(key: &[u8], headers: &HeaderMap, body: &[u8]) -> Result<(Value, Value)> {
    // Authenticity is the shared Version 1 receiver's reading; what follows is
    // this inbox's local policy over the verified attributes.
    let verified = verify_delivery(
        SignedDelivery {
            method: "POST",
            request_target: "/events",
            headers: headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes())),
            body,
            key,
        },
        DeliveryFreshness::Within {
            now: SystemTime::now(),
            skew: Duration::from_secs(30),
        },
    )
    .map_err(|error| anyhow::anyhow!("webhook verification refused: {error}"))?;
    if verified.content_type != "application/json"
        || header(headers, "accept")? != "application/json"
        || body.is_empty()
    {
        bail!("webhook profile is invalid");
    }
    let event_id =
        uuid::Uuid::parse_str(verified.id).context("webhook event identity is invalid")?;
    if event_id.to_string() != verified.id {
        bail!("webhook event identity must be canonical");
    }
    let event_time =
        OffsetDateTime::parse(verified.time, &Rfc3339).context("webhook event time is invalid")?;
    let generation = positive(verified.generation)?;
    let attempt = positive(verified.attempt)?;
    let idempotency_key = verified.idempotency_key;
    if !digest(idempotency_key) {
        bail!("webhook idempotency key is invalid");
    }
    let envelope = HookEnvelope::from_canonical_bytes(body, &EnvelopeLimits::default())
        .map_err(|_| anyhow::anyhow!("webhook envelope is invalid"))?;
    if envelope.id != verified.id
        || envelope.event_type != verified.event_type
        || envelope.source != verified.source
        || envelope.dataschema != verified.data_schema
        || envelope.time != event_time
    {
        bail!("webhook envelope does not match its signed delivery attributes");
    }
    let data = envelope.data;
    let object = data
        .as_object()
        .context("webhook envelope data must be an object")?;
    let registry = verified
        .source
        .strip_prefix("urn:registrystack:registry:")
        .and_then(|source| source.split_once(":instance:"))
        .filter(|(registry, instance)| !registry.is_empty() && !instance.is_empty())
        .context("webhook source is invalid")?
        .0;
    if envelope.dataschema == registry_breg::proposal_hooks::PROPOSAL_EVENT_SCHEMA {
        static SCHEMA: std::sync::LazyLock<jsonschema::JSONSchema> =
            std::sync::LazyLock::new(|| {
                jsonschema::JSONSchema::options()
                    .with_draft(jsonschema::Draft::Draft202012)
                    .should_validate_formats(true)
                    .compile(&registry_breg::proposal_hooks::proposal_event_schema())
                    .expect("fixed native Proposal event schema")
            });
        let EventSubject::Proposal {
            proposal_reference,
            proposal_revision,
        } = &envelope.subject
        else {
            bail!("webhook Proposal event subject shape is invalid");
        };
        if !SCHEMA.is_valid(&data)
            || verified.event_type
                != format!(
                    "proposal.{}",
                    data["transition"].as_str().unwrap_or_default()
                )
            || data["revision"].as_i64() != Some(*proposal_revision)
            || data["proposalId"].as_str().is_none_or(|proposal_id| {
                proposal_reference != &format!("/v1/proposals/{proposal_id}")
            })
        {
            bail!("webhook Proposal event data shape is invalid");
        }
        let record = json!({"eventId":verified.id,"eventType":verified.event_type,"actionId":data["actionId"],
            "trigger":"proposal-lifecycle","transition":data["transition"],"deliveryId":null,
            "idempotencyKey":idempotency_key,"generation":generation,"attempt":attempt,"status":"received",
            "receivedAt":OffsetDateTime::now_utc().format(&Rfc3339)?,"payload":data});
        return Ok((record, data));
    }
    if object.len() != 6
        || ![
            "recordType",
            "recordId",
            "revision",
            "trigger",
            "packageRevision",
            "values",
        ]
        .iter()
        .all(|field| object.contains_key(*field))
        || !data["values"].is_object()
        || data["revision"].as_u64().is_none_or(|n| n == 0)
        || !data["packageRevision"].as_str().is_some_and(digest)
        || !data["recordType"]
            .as_str()
            .is_some_and(|entity| !entity.is_empty() && entity.len() <= 64)
        || !matches!(
            data["trigger"].as_str(),
            Some("created" | "patched" | "tombstoned")
        )
        || !data["recordId"].as_str().is_some_and(|id| {
            uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id)
        })
    {
        bail!("webhook envelope data shape is invalid");
    }
    let EventSubject::Record {
        record_revision, ..
    } = &envelope.subject
    else {
        bail!("webhook Record event subject shape is invalid");
    };
    if data["revision"].as_i64() != Some(*record_revision) {
        bail!("webhook Record event revision does not match its subject");
    }
    let prefix = format!(
        "urn:breg:event-schema:{registry}:{}:{}:",
        data["recordType"]
            .as_str()
            .context("webhook entity is invalid")?,
        verified.event_type
    );
    if !verified
        .data_schema
        .strip_prefix(&prefix)
        .is_some_and(digest)
    {
        bail!("webhook schema does not match event metadata");
    }
    let record = json!({
        "eventId":verified.id,"eventType":verified.event_type,"recordType":data["recordType"],
        "trigger":data["trigger"],"deliveryId":null,"idempotencyKey":idempotency_key,
        "generation":generation,"attempt":attempt,"status":"received",
        "receivedAt":OffsetDateTime::now_utc().format(&Rfc3339)?,"payload":data["values"]
    });
    Ok((record, data))
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
        bail!(
            "local event inbox reached its 16 MiB bound; stop the session and move the journal to an owner-only location before restarting"
        );
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

/// Reclaim received payloads with the disposable database, retaining secrets
/// and the stable storage lock for a subsequent local start.
pub(super) fn clear(root: &Path) -> Result<()> {
    let _lock = storage_lock(root)?;
    let path = root.join("events.jsonl");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => private::check_metadata(&metadata, false)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    fs::remove_file(&path).context("cannot reclaim the local event inbox")?;
    File::open(root)?.sync_all()?;
    Ok(())
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
                            | "recordType"
                            | "actionId"
                            | "transition"
                            | "matchingDeliveries"
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
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

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
    use registry_breg::{
        compiler::{compile_project, CompileProfile},
        contract::{parse_project_json, EventTrigger},
    };
    use registry_platform_canonical_json::canonicalize_json;
    use std::{io::Write, net::TcpStream, os::unix::fs::PermissionsExt, time::Instant};

    fn fixture() -> (tempfile::TempDir, u16, Receiver) {
        fixture_with_contract(EventTrigger::Created, false)
    }

    fn fixture_with_contract(
        trigger: EventTrigger,
        vocabulary: bool,
    ) -> (tempfile::TempDir, u16, Receiver) {
        let mut field =
            json!({"id":"label", "type":"string", "maximumLength":64, "classification":"internal"});
        if vocabulary {
            field = json!({"id":"label", "type":"vocabulary-code", "vocabulary":"labels", "values":["projected-value-canary", "ready"], "classification":"internal"});
        }
        let project = json!({
            "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
            "project":{"id":"example", "version":"1", "defaultLanguage":"en", "canonicalBaseIri":"https://example.test"},
            "package":{"sourceRevision":"test"},
            "datasets":[{"id":"test-dataset","display":{"label":"Test dataset"}}],
            "recordTypes":[{
                "id":"record", "primaryDataset":"test-dataset", "route":"records", "mutationMode":"mutable",
                "fields":[field],
                "hooks":[{"phase":"after","id":"record-created-v1", "trigger":trigger, "projection":["label"], "handler":{"type":"url","destinationId":"local-hook"}}]
            }]
        });
        let project = parse_project_json(&serde_json::to_vec(&project).unwrap()).unwrap();
        let compiled = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
        let mut delivery = Delivery::compile(
            &compiled,
            &compiled.event_deliveries().deliveries[0],
            "local",
        )
        .unwrap();
        // Wire helpers use a fixed synthetic identity; the validator itself is
        // always built from the compiler's actual generated event artifact.
        delivery.data_schema = format!(
            "urn:breg:event-schema:example:record:record-created-v1:sha256:{}",
            "0".repeat(64)
        );
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
            BTreeMap::from([(("record-created-v1".into(), "record".into()), delivery)]),
        )
        .unwrap();
        (root, port, receiver)
    }

    /// The capture instant the delivery headers and the envelope share. Whole
    /// milliseconds, the precision the envelope's wire form spells.
    const EVENT_TIME: &str = "2026-01-01T00:00:00.123Z";

    fn event_headers(attempt: u64, generation: u64) -> HeaderMap {
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
            ("ce-time", EVENT_TIME.to_owned()),
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
        headers
    }

    /// The product projection a delivered envelope carries as `data`.
    fn event_data() -> Value {
        json!({
            "recordType":"record", "recordId":"00000000-0000-4000-8000-000000000002",
            "revision":1,"trigger":"created","packageRevision":format!("sha256:{}", "0".repeat(64)),
            "values":{"label":"projected-value-canary"}
        })
    }

    /// The canonical envelope bytes a delivery with `headers` would carry.
    fn envelope_bytes(headers: &HeaderMap, data: Value) -> Vec<u8> {
        envelope_bytes_with_subject(headers, data, EventSubject::record("0".repeat(63) + "2", 1))
    }

    fn envelope_bytes_with_subject(
        headers: &HeaderMap,
        data: Value,
        subject: EventSubject,
    ) -> Vec<u8> {
        HookEnvelope {
            id: headers["ce-id"].to_str().unwrap().to_owned(),
            event_type: headers["ce-type"].to_str().unwrap().to_owned(),
            source: headers["ce-source"].to_str().unwrap().to_owned(),
            time: OffsetDateTime::parse(headers["ce-time"].to_str().unwrap(), &Rfc3339).unwrap(),
            subject,
            dataschema: headers["ce-dataschema"].to_str().unwrap().to_owned(),
            data,
            causation: registry_platform_hooks::Causation::root(headers["ce-id"].to_str().unwrap()),
        }
        .to_canonical_bytes(&EnvelopeLimits::default())
        .unwrap()
    }

    fn signed(attempt: u64, generation: u64) -> (HeaderMap, Vec<u8>) {
        signed_data(attempt, generation, event_data())
    }

    fn signed_data(attempt: u64, generation: u64, data: Value) -> (HeaderMap, Vec<u8>) {
        let mut headers = event_headers(attempt, generation);
        let body = envelope_bytes(&headers, data);
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
            let mut headers = event_headers(1, 1);
            let mut data = event_data();
            match change {
                "trigger" => data["trigger"] = json!("patched"),
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
                "extra projection" => data["values"]["undeclared"] = json!("extra-value-canary"),
                "missing projection" => {
                    data["values"].as_object_mut().unwrap().remove("label");
                }
                _ => unreachable!(),
            }
            let body = envelope_bytes(&headers, data);
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
    fn a_pre_envelope_body_is_refused_and_never_recorded() {
        let (root, port, _receiver) = fixture();
        let mut headers = event_headers(1, 1);
        let body = canonicalize_json(&event_data()).unwrap();
        sign(&mut headers, &body);
        assert_eq!(
            request(port, headers, body),
            401,
            "the projection alone is no longer a delivery body"
        );
        assert_eq!(report(root.path(), true).unwrap()["deliveries"], json!([]));
    }

    #[test]
    fn an_envelope_that_disagrees_with_its_signed_attributes_is_refused() {
        let (root, port, _receiver) = fixture();
        let mut headers = event_headers(1, 1);
        let mut other = event_headers(1, 1);
        other.insert(
            "ce-source",
            HeaderValue::from_static("urn:registrystack:registry:example:instance:other"),
        );
        let body = envelope_bytes(&other, event_data());
        sign(&mut headers, &body);
        assert_eq!(
            request(port, headers, body),
            401,
            "an envelope source that differs from the signed header is refused"
        );
        assert_eq!(report(root.path(), true).unwrap()["deliveries"], json!([]));
    }

    #[test]
    fn signed_source_must_match_the_configured_registry_instance() {
        let (root, port, _receiver) = fixture();
        let (mut headers, body) = signed(1, 1);
        headers.insert(
            "ce-source",
            HeaderValue::from_static("urn:registrystack:registry:example:instance:other"),
        );
        sign(&mut headers, &body);
        assert_eq!(request(port, headers, body), 401);
        assert_eq!(report(root.path(), true).unwrap()["deliveries"], json!([]));
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
        let mut data = event_data();
        data["values"]["label"] = Value::Null;
        let (headers, body) = signed_data(1, 1, data);
        assert_eq!(request(port, headers, body), 204);
        assert_eq!(
            report(root.path(), true).unwrap()["deliveries"][0]["payload"],
            json!({"label":null})
        );
    }

    #[test]
    fn signed_projected_values_must_match_generated_types_and_vocabulary() {
        for vocabulary in [false, true] {
            let (root, port, _receiver) = fixture_with_contract(EventTrigger::Created, vocabulary);
            let mut invalid = vec![json!(7), json!({"label":"wrong-shape"})];
            if vocabulary {
                invalid.push(json!("undeclared-code"));
            }
            for value in invalid {
                let mut data = event_data();
                data["values"]["label"] = value;
                let (headers, body) = signed_data(1, 1, data);
                assert_eq!(request(port, headers, body), 401);
                assert_eq!(report(root.path(), true).unwrap()["deliveries"], json!([]));
            }
            let (headers, body) = signed(1, 1);
            assert_eq!(request(port, headers, body), 204);
        }
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
    fn clearing_received_payloads_is_idempotent_and_preserves_local_keys() {
        let (root, port, receiver) = fixture();
        let key_path = root.path().join("secrets/webhook-key");
        let key = private::read(&key_path, 128).unwrap();
        let (headers, body) = signed(1, 1);
        assert_eq!(request(port, headers, body), 204);
        drop(receiver);
        assert_eq!(
            report(root.path(), true).unwrap()["deliveries"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        clear(root.path()).unwrap();
        clear(root.path()).unwrap();
        assert!(!root.path().join("events.jsonl").exists());
        assert_eq!(report(root.path(), true).unwrap()["deliveries"], json!([]));
        assert_eq!(private::read(&key_path, 128).unwrap(), key);
        private::check(&root.path().join("events.lock"), false).unwrap();
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
        assert!(clear(root.path()).is_err());
        assert!(target.exists());
        fs::remove_file(&path).unwrap();
        fs::hard_link(&target, &path).unwrap();
        assert!(report(root.path(), false).is_err());
        assert!(clear(root.path()).is_err());
        assert!(target.exists());
    }

    #[test]
    fn native_proposal_receipts_verify_the_fixed_contract_and_exact_transition() {
        let mut headers = event_headers(1, 1);
        headers.insert("ce-type", HeaderValue::from_static("proposal.submitted"));
        headers.insert(
            "ce-dataschema",
            HeaderValue::from_static(registry_breg::proposal_hooks::PROPOSAL_EVENT_SCHEMA),
        );
        let data = json!({"actionId":"correct-name","actionRevision":format!("sha256:{}","a".repeat(64)),
            "proposalId":"00000000-0000-4000-8000-000000000002","submissionVersion":1,"revision":1,
            "fromState":"draft","state":"submitted","transition":"submitted","effectDigest":null,
            "authorityKind":"caller","systemApplyGrantRevision":null,"turn":"official"});
        let key = URL_SAFE_NO_PAD.encode([7; 32]);
        let proposal_subject =
            EventSubject::proposal("/v1/proposals/00000000-0000-4000-8000-000000000002", 1);
        let body = envelope_bytes_with_subject(&headers, data.clone(), proposal_subject.clone());
        sign(&mut headers, &body);
        let (record, projection) = verify(key.as_bytes(), &headers, &body).unwrap();
        assert_eq!(record["actionId"], "correct-name");
        assert!(record.get("recordType").is_none());
        assert_eq!(projection, data);
        for member in ["input", "context", "attachments", "actor"] {
            let mut widened = data.clone();
            widened[member] = json!("private-canary");
            let body = envelope_bytes_with_subject(&headers, widened, proposal_subject.clone());
            sign(&mut headers, &body);
            assert!(verify(key.as_bytes(), &headers, &body).is_err());
        }
        let retired = envelope_bytes(&headers, data.clone());
        sign(&mut headers, &retired);
        assert!(
            verify(key.as_bytes(), &headers, &retired).is_err(),
            "a Proposal event cannot retain the Record subject family"
        );
        let mismatched = envelope_bytes_with_subject(
            &headers,
            data.clone(),
            EventSubject::proposal("/v1/proposals/00000000-0000-4000-8000-000000000003", 1),
        );
        sign(&mut headers, &mismatched);
        assert!(
            verify(key.as_bytes(), &headers, &mismatched).is_err(),
            "a Proposal subject must name the event data's Proposal"
        );
        headers.insert("ce-type", HeaderValue::from_static("proposal.applied"));
        let body = envelope_bytes_with_subject(&headers, data, proposal_subject);
        sign(&mut headers, &body);
        assert!(verify(key.as_bytes(), &headers, &body).is_err());
    }
}

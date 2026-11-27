// SPDX-License-Identifier: Apache-2.0
//! Supervised loopback webhook inbox. Receipt is distinct from runtime delivery state.

use super::private;
use anyhow::{bail, Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::StatusCode,
    routing::post,
    Router,
};
use registry_breg::model::{CompiledEventDelivery, CompiledRegistry};
use registry_platform_canonical_json::parse_json_strict;
use registry_platform_hooks::{
    receiver::{verify_hook_delivery, DeliveryFreshness, HookDelivery},
    DeliveryKey, DeliveryKeys, EventSubject, HookEnvelope,
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

type DeliveryMap = BTreeMap<(String, String), Delivery>;

pub(super) struct Receiver {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

struct Inbox {
    root: PathBuf,
    keys: BTreeMap<String, DeliveryKeys>,
    deliveries: DeliveryMap,
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

pub(super) fn check_destination_keys(root: &Path) -> Result<()> {
    let compiled = crate::compile(&root.join("project"), crate::ProfileArg::Production, "dev")
        .map_err(|_| anyhow::anyhow!("captured event project no longer compiles"))?;
    for destination in compiled
        .event_deliveries()
        .deliveries
        .iter()
        .filter_map(|delivery| delivery.destination_id.as_deref())
    {
        check_destination_key(&super::config::inbox_key_path(root, destination))?;
    }
    Ok(())
}

fn check_destination_key(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!("This development session predates per-destination keys. Run bregctl dev stop --remove and start again.");
        }
        Err(error) => Err(error.into()),
        Ok(metadata) => {
            private::check_metadata(&metadata, false)?;
            if metadata.len() != super::config::INBOX_KEY_BYTES {
                bail!("The local inbox key is incomplete. Run bregctl dev stop --remove and start again.");
            }
            Ok(())
        }
    }
}

impl Receiver {
    pub(super) fn start(root: &Path, port: u16, instance_id: &str) -> Result<Self> {
        let compiled = crate::compile(&root.join("project"), crate::ProfileArg::Production, "dev")
            .map_err(|_| anyhow::anyhow!("captured event project no longer compiles"))?;
        // The local receiver stands in for a remote destination, so it holds
        // the url deliveries only; a local handler runs inside the engine and
        // never reaches an HTTP receiver.
        let mut deliveries: DeliveryMap = BTreeMap::new();
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

    fn start_with_deliveries(root: &Path, port: u16, deliveries: DeliveryMap) -> Result<Self> {
        private::check(root, true)?;
        let mut keys = BTreeMap::new();
        for delivery in deliveries.values() {
            for destination in std::iter::once(&delivery.destination_id)
                .chain(delivery.matching.iter().map(|(_, destination)| destination))
            {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    keys.entry(destination.clone())
                {
                    let path = super::config::inbox_key_path(root, destination);
                    check_destination_key(&path)?;
                    // Use the 43-character base64url text as the key bytes as written.
                    let bytes = Zeroizing::new(private::read(&path, 64 * 1024)?);
                    let key = DeliveryKey::new(&bytes)
                        .with_context(|| format!("invalid local inbox key for {destination}"))?;
                    entry.insert(DeliveryKeys::new(key, None).expect("one validated key"));
                }
            }
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
            keys,
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
    let refused = (
        StatusCode::UNAUTHORIZED,
        "local webhook verification refused",
    );
    let freshness = DeliveryFreshness::default_at(SystemTime::now());
    let Some((destination, verified)) = inbox.keys.iter().find_map(|(destination, keys)| {
        let request = HookDelivery {
            headers: parts
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes())),
            body: &body,
            keys,
        };
        verify_hook_delivery(request, freshness)
            .ok()
            .map(|verified| (destination, verified))
    }) else {
        return refused;
    };
    let source = verified.envelope.source.clone();
    let data_schema = verified.envelope.dataschema.clone();
    let Ok((mut record, document)) = receipt(verified.envelope) else {
        return refused;
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
    if data_schema != delivery.data_schema
        || source != delivery.source
        || !delivery.schema.is_valid(&document)
    {
        return refused;
    }
    let matching = std::iter::once((&delivery.id, &delivery.destination_id))
        .chain(
            delivery
                .matching
                .iter()
                .map(|(id, destination)| (id, destination)),
        )
        .filter(|(_, candidate)| *candidate == destination)
        .collect::<Vec<_>>();
    record["destinationId"] = json!(destination);
    match matching.as_slice() {
        [] => return refused,
        [(id, _)] => record["deliveryId"] = json!(id),
        _ => {
            record["matchingDeliveries"] = json!(matching
                .into_iter()
                .map(|(id, destination)| json!({"deliveryId":id,"destinationId":destination}))
                .collect::<Vec<_>>());
        }
    }
    match append(&inbox.root, &record) {
        Ok(()) => (StatusCode::NO_CONTENT, ""),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "local event storage unavailable: verify owner-only permissions and the 16 MiB inbox bound",
        ),
    }
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn receipt(envelope: HookEnvelope) -> Result<(Value, Value)> {
    let event_id =
        uuid::Uuid::parse_str(&envelope.id).context("webhook event identity is invalid")?;
    if event_id.to_string() != envelope.id {
        bail!("webhook event identity must be canonical");
    }
    let data = envelope.data;
    let object = data
        .as_object()
        .context("webhook envelope data must be an object")?;
    let registry = envelope
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
            || envelope.event_type
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
        let record = json!({"eventId":envelope.id,"eventType":envelope.event_type,"actionId":data["actionId"],
            "trigger":"proposal-lifecycle","transition":data["transition"],"deliveryId":null,
            "webhookId":envelope.id,"status":"received",
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
        envelope.event_type
    );
    if !envelope
        .dataschema
        .strip_prefix(&prefix)
        .is_some_and(digest)
    {
        bail!("webhook schema does not match event metadata");
    }
    let record = json!({
        "eventId":envelope.id,"eventType":envelope.event_type,"recordType":data["recordType"],
        "trigger":data["trigger"],"deliveryId":null,"webhookId":envelope.id,"status":"received",
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
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        bail!("local event inbox has an incomplete record");
    }
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let received = parse_json_strict(line).context("local event inbox record is invalid")?;
        if received["destinationId"] == record["destinationId"]
            && received["webhookId"] == record["webhookId"]
        {
            return Ok(());
        }
    }
    let line = serde_json::to_vec(record)?;
    if bytes.len() as u64 + line.len() as u64 + 1 > MAX_STORAGE {
        bail!(
            "local event inbox reached its 16 MiB bound; stop the session and move the journal to an owner-only location before restarting"
        );
    }
    bytes.extend_from_slice(&line);
    bytes.push(b'\n');
    // Atomic replacement under the stable lock prevents partial reports and
    // acknowledges only a durable complete record.
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
                            | "webhookId"
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
    use axum::http::HeaderMap;
    use axum::http::HeaderValue;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use registry_platform_crypto::delivery_signature;
    use registry_platform_hooks::EnvelopeLimits;

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
        let (root, port, deliveries) = captured_inbox(trigger, vocabulary);
        let receiver = Receiver::start_with_deliveries(root.path(), port, deliveries).unwrap();
        (root, port, receiver)
    }

    fn captured_inbox(
        trigger: EventTrigger,
        vocabulary: bool,
    ) -> (tempfile::TempDir, u16, DeliveryMap) {
        let mut field =
            json!({"id":"label", "type":"string", "maximumLength":64, "classification":"internal"});
        if vocabulary {
            field = json!({"id":"label", "type":"vocabulary-code", "vocabulary":"labels", "values":["projected-value-canary", "ready"], "classification":"internal"});
        }
        let project = json!({
            "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
            "project":{"id":"example", "version":"1", "defaultLanguage":"en", "canonicalBaseIri":"https://example.test"},
            "package":{"sourceRevision":"test"},
            "datasets":{"test-dataset": {"display":{"label":"Test dataset"}}},
            "recordTypes":{"record": { "primaryDataset":"test-dataset", "route":"records", "mutationMode":"mutable",
                "fields":[field],
                "hooks":[{"phase":"after","id":"record-created-v1", "trigger":trigger, "projection":["label"], "handler":{"type":"url","destinationId":"local-hook"}}]
            }}
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
            &root.path().join("secrets/inbox-key-local-hook"),
            URL_SAFE_NO_PAD.encode([7; 32]).as_bytes(),
        )
        .unwrap();
        private::create(
            &root.path().join("secrets/inbox-key-second-hook"),
            URL_SAFE_NO_PAD.encode([8; 32]).as_bytes(),
        )
        .unwrap();
        delivery
            .matching
            .push(("test-second-delivery".to_owned(), "second-hook".to_owned()));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let deliveries =
            BTreeMap::from([(("record-created-v1".into(), "record".into()), delivery)]);
        (root, port, deliveries)
    }

    const EVENT_TIME: &str = "2026-01-01T00:00:00.123Z";
    const EVENT_ID: &str = "00000000-0000-4000-8000-000000000001";
    const EVENT_SOURCE: &str = "urn:registrystack:registry:example:instance:local";
    const EVENT_SCHEMA_PREFIX: &str =
        "urn:breg:event-schema:example:record:record-created-v1:sha256:";

    fn event_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("application/json"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("webhook-id", HeaderValue::from_static(EVENT_ID));
        headers.insert(
            "webhook-timestamp",
            HeaderValue::from_str(&OffsetDateTime::now_utc().unix_timestamp().to_string()).unwrap(),
        );
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

    fn envelope(data: Value) -> HookEnvelope {
        HookEnvelope {
            id: EVENT_ID.to_owned(),
            event_type: "record-created-v1".to_owned(),
            source: EVENT_SOURCE.to_owned(),
            time: OffsetDateTime::parse(EVENT_TIME, &Rfc3339).unwrap(),
            subject: EventSubject::record("0".repeat(63) + "2", 1),
            dataschema: format!("{EVENT_SCHEMA_PREFIX}{}", "0".repeat(64)),
            data,
            causation: registry_platform_hooks::Causation::root(EVENT_ID),
        }
    }

    fn signed() -> (HeaderMap, Vec<u8>) {
        signed_envelope(envelope(event_data()))
    }

    fn signed_envelope(envelope: HookEnvelope) -> (HeaderMap, Vec<u8>) {
        let mut headers = event_headers();
        headers.insert("webhook-id", HeaderValue::from_str(&envelope.id).unwrap());
        let body = envelope
            .to_canonical_bytes(&EnvelopeLimits::default())
            .unwrap();
        sign(&mut headers, &body);
        (headers, body)
    }

    fn sign(headers: &mut HeaderMap, body: &[u8]) {
        sign_with_key(headers, body, URL_SAFE_NO_PAD.encode([7; 32]).as_bytes());
    }

    fn sign_with_key(headers: &mut HeaderMap, body: &[u8], key: &[u8]) {
        let keys = DeliveryKeys::new(DeliveryKey::new(key).unwrap(), None).unwrap();
        let signature = delivery_signature::sign(
            &keys,
            headers["webhook-id"].to_str().unwrap(),
            headers["webhook-timestamp"]
                .to_str()
                .unwrap()
                .parse()
                .unwrap(),
            body,
        )
        .unwrap();
        headers.insert(
            "webhook-signature",
            HeaderValue::from_str(&signature).unwrap(),
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
    fn a_session_missing_a_destination_key_explains_how_to_restart() {
        let (root, port, deliveries) = captured_inbox(EventTrigger::Created, false);
        fs::remove_file(root.path().join("secrets/inbox-key-second-hook")).unwrap();
        let error = Receiver::start_with_deliveries(root.path(), port, deliveries)
            .err()
            .expect("missing key prevents receiver startup");
        assert_eq!(error.to_string(), "This development session predates per-destination keys. Run bregctl dev stop --remove and start again.");
    }

    #[test]
    fn signed_receipts_record_the_webhook_id_and_destination_and_redact_values() {
        let (root, port, receiver) = fixture();
        for _ in 0..3 {
            let (headers, body) = signed();
            assert_eq!(request(port, headers, body), 204);
        }
        let (mut headers, body) = signed();
        headers.insert(
            "webhook-timestamp",
            HeaderValue::from_str(&(OffsetDateTime::now_utc().unix_timestamp() + 10).to_string())
                .unwrap(),
        );
        sign(&mut headers, &body);
        assert_eq!(request(port, headers, body), 204);
        assert!(!receiver.exited());
        let metadata = report(root.path(), false).unwrap();
        assert!(!metadata.to_string().contains("projected-value-canary"));
        assert!(!metadata
            .to_string()
            .contains("00000000-0000-4000-8000-000000000002"));
        let records = metadata["deliveries"].as_array().unwrap();
        assert_eq!(records.len(), 1);
        assert!(records.iter().all(|record| record["webhookId"] == EVENT_ID));
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
            1
        );
    }

    #[test]
    fn a_delivery_is_attributed_to_the_destination_whose_key_verifies() {
        let (root, port, _receiver) = fixture();
        let (headers, body) = signed();
        assert_eq!(request(port, headers, body), 204);
        let (mut headers, body) = signed();
        sign_with_key(
            &mut headers,
            &body,
            URL_SAFE_NO_PAD.encode([8; 32]).as_bytes(),
        );
        assert_eq!(request(port, headers, body), 204);
        let metadata = report(root.path(), false).unwrap();
        let records = metadata["deliveries"].as_array().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["destinationId"], "local-hook");
        assert_eq!(records[1]["destinationId"], "second-hook");
        assert_eq!(records[1]["deliveryId"], "test-second-delivery");
    }

    #[test]
    fn a_delivery_no_destination_key_verifies_is_refused_and_not_recorded() {
        let (root, port, _receiver) = fixture();
        let (mut headers, body) = signed();
        sign_with_key(&mut headers, &body, &[9; 32]);
        assert_eq!(request(port, headers, body), 401);
        assert_eq!(report(root.path(), false).unwrap()["deliveries"], json!([]));
    }

    #[test]
    fn configured_raw_key_bytes_match_runtime_and_decoded_key_is_refused() {
        let (root, port, _receiver) = fixture();
        let key = private::read(&root.path().join("secrets/inbox-key-local-hook"), 128).unwrap();
        let (mut headers, body) = signed();
        sign_with_key(&mut headers, &body, &key);
        assert_eq!(request(port, headers, body), 204);
        let (mut headers, body) = signed();
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
        let (headers, mut body) = signed();
        body.push(b' ');
        assert_eq!(request(port, headers, body), 401);
        let (mut headers, body) = signed();
        headers.insert("webhook-timestamp", HeaderValue::from_static("1"));
        assert_eq!(request(port, headers, body), 401);
        let (mut headers, body) = signed();
        headers.append("webhook-id", HeaderValue::from_static(EVENT_ID));
        assert_eq!(request(port, headers, body), 401);
        let (mut headers, body) = signed();
        headers.insert(
            "webhook-timestamp",
            HeaderValue::from_str(&(OffsetDateTime::now_utc().unix_timestamp() - 301).to_string())
                .unwrap(),
        );
        sign(&mut headers, &body);
        assert_eq!(request(port, headers, body), 401);
        let (mut headers, mut body) = signed();
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
            let mut delivery = envelope(event_data());
            match change {
                "trigger" => delivery.data["trigger"] = json!("patched"),
                "schema" => {
                    delivery.dataschema = format!("{EVENT_SCHEMA_PREFIX}{}", "f".repeat(64))
                }
                "extra projection" => {
                    delivery.data["values"]["undeclared"] = json!("extra-value-canary")
                }
                "missing projection" => {
                    delivery.data["values"]
                        .as_object_mut()
                        .unwrap()
                        .remove("label");
                }
                _ => unreachable!(),
            }
            let (headers, body) = signed_envelope(delivery);
            assert_eq!(request(port, headers, body), 401, "{change}");
            assert_eq!(
                report(root.path(), true).unwrap()["deliveries"],
                json!([]),
                "{change}"
            );
        }
        let (headers, body) = signed();
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
        let mut headers = event_headers();
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
    fn an_envelope_that_disagrees_with_its_webhook_id_is_refused() {
        let (root, port, _receiver) = fixture();
        let (mut headers, body) = signed();
        headers.insert(
            "webhook-id",
            HeaderValue::from_static("00000000-0000-4000-8000-000000000003"),
        );
        sign(&mut headers, &body);
        assert_eq!(request(port, headers, body), 401);
        assert_eq!(report(root.path(), true).unwrap()["deliveries"], json!([]));
    }

    #[test]
    fn signed_source_must_match_the_configured_registry_instance() {
        let (root, port, _receiver) = fixture();
        let mut delivery = envelope(event_data());
        delivery.source = "urn:registrystack:registry:example:instance:other".to_owned();
        let (headers, body) = signed_envelope(delivery);
        assert_eq!(request(port, headers, body), 401);
        assert_eq!(report(root.path(), true).unwrap()["deliveries"], json!([]));
        let (headers, body) = signed();
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
        let (headers, body) = signed_envelope(envelope(data));
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
                let (headers, body) = signed_envelope(envelope(data));
                assert_eq!(request(port, headers, body), 401);
                assert_eq!(report(root.path(), true).unwrap()["deliveries"], json!([]));
            }
            let (headers, body) = signed();
            assert_eq!(request(port, headers, body), 204);
        }
    }

    #[test]
    fn unsafe_or_full_storage_refuses_acknowledgement_and_recovers() {
        let (root, port, _receiver) = fixture();
        let path = root.path().join("events.jsonl");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let (headers, body) = signed();
        assert_eq!(request(port, headers, body), 503);
        assert!(report(root.path(), false).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (headers, body) = signed();
        assert_eq!(request(port, headers, body), 204);
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_STORAGE)
            .unwrap();
        let (headers, body) = signed();
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
        for _ in 0..5 {
            let mut event = envelope(event_data());
            event.id = uuid::Uuid::new_v4().to_string();
            event.causation = registry_platform_hooks::Causation::root(&event.id);
            let (headers, body) = signed_envelope(event);
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
        let key_path = root.path().join("secrets/inbox-key-local-hook");
        let key = private::read(&key_path, 128).unwrap();
        let (headers, body) = signed();
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
        let data = json!({"actionId":"correct-name","actionRevision":format!("sha256:{}","a".repeat(64)),
            "proposalId":"00000000-0000-4000-8000-000000000002","submissionVersion":1,"revision":1,
            "fromState":"draft","state":"submitted","transition":"submitted","effectDigest":null,
            "authorityKind":"caller","systemApplyGrantRevision":null,"turn":"official"});
        let proposal = |data, subject| HookEnvelope {
            event_type: "proposal.submitted".to_owned(),
            dataschema: registry_breg::proposal_hooks::PROPOSAL_EVENT_SCHEMA.to_owned(),
            subject,
            ..envelope(data)
        };
        let subject =
            EventSubject::proposal("/v1/proposals/00000000-0000-4000-8000-000000000002", 1);
        let (record, projection) = receipt(proposal(data.clone(), subject.clone())).unwrap();
        assert_eq!(record["actionId"], "correct-name");
        assert!(record.get("recordType").is_none());
        assert_eq!(projection, data);
        for member in ["input", "context", "attachments", "actor"] {
            let mut widened = data.clone();
            widened[member] = json!("private-canary");
            assert!(receipt(proposal(widened, subject.clone())).is_err());
        }
        assert!(receipt(proposal(
            data.clone(),
            EventSubject::record("0".repeat(63) + "2", 1)
        ))
        .is_err());
        let mismatched =
            EventSubject::proposal("/v1/proposals/00000000-0000-4000-8000-000000000003", 1);
        assert!(receipt(proposal(data.clone(), mismatched)).is_err());
        let mut applied = proposal(data, subject);
        applied.event_type = "proposal.applied".to_owned();
        assert!(receipt(applied).is_err());
    }
}

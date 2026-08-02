//! Opt-in, ignored, read-only compatibility checks for approved public demos.
//!
//! Credentials and selectors are loaded only from exact owner-only files outside
//! the repository. Errors and status output are deliberately value-free.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use registry_platform_crypto::parse_json_strict;
use reqwest::{header::CONTENT_TYPE, redirect::Policy, Client, Response, StatusCode, Url};
use serde_json::{json, Value};
use zeroize::Zeroizing;

const MAX_CREDENTIAL_FILE_BYTES: u64 = 16 * 1024;
const MAX_TOKEN_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_SOURCE_RESPONSE_BYTES: usize = 256 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveError {
    Skipped,
    CredentialFile,
    Configuration,
    Authentication,
    Unavailable,
    SchemaDrift,
    ExcessDisclosure,
}

#[tokio::test]
#[ignore = "opt-in read-only public-demo check; requires EVIDENCE_DHIS2_LIVE_ENV_FILE"]
async fn dhis2() {
    run_live("dhis2", run_dhis2).await;
}

#[tokio::test]
#[ignore = "opt-in read-only public-demo check; requires EVIDENCE_OPENCRVS_LIVE_ENV_FILE"]
async fn opencrvs() {
    run_live("opencrvs", run_opencrvs).await;
}

async fn run_live<F, Fut>(profile: &'static str, operation: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), LiveError>>,
{
    let started = Instant::now();
    let result = operation().await;
    let (phase, outcome) = match result {
        Ok(()) => ("complete", "pass"),
        Err(LiveError::Skipped) => ("configuration", "skip"),
        Err(LiveError::CredentialFile | LiveError::Configuration) => {
            ("configuration", "inconclusive")
        }
        Err(LiveError::Authentication) => ("authentication", "inconclusive"),
        Err(LiveError::Unavailable) => ("lookup", "inconclusive"),
        Err(LiveError::SchemaDrift) => ("lookup-schema", "fail"),
        Err(LiveError::ExcessDisclosure) => ("lookup-minimization", "fail"),
    };
    eprintln!(
        "live-source profile={profile} phase={phase} outcome={outcome} duration_ms={}",
        started.elapsed().as_millis()
    );
    match result {
        Ok(()) | Err(LiveError::Skipped) => {}
        Err(LiveError::SchemaDrift | LiveError::ExcessDisclosure) => {
            panic!("authenticated live source contract requires investigation")
        }
        Err(_) => {}
    }
}

async fn run_dhis2() -> Result<(), LiveError> {
    let path = credential_path("EVIDENCE_DHIS2_LIVE_ENV_FILE", None)?;
    let config = read_exact_credentials(
        &path,
        &[
            "DHIS2_BASE_URL",
            "DHIS2_USERNAME",
            "DHIS2_PASSWORD",
            "DHIS2_TEST_PROGRAM_ID",
            "DHIS2_TEST_ORG_UNIT_ID",
            "DHIS2_TEST_TRACKED_ENTITY_ID",
        ],
    )?;
    let base = safe_https_base(required(&config, "DHIS2_BASE_URL")?)?;
    let client = live_client()?;

    let metadata = base
        .join("api/system/info?fields=version")
        .map_err(|_| LiveError::Configuration)?;
    let response = client
        .get(metadata)
        .basic_auth(
            required(&config, "DHIS2_USERNAME")?,
            Some(required(&config, "DHIS2_PASSWORD")?),
        )
        .send()
        .await
        .map_err(|_| LiveError::Unavailable)?;
    require_success(response.status(), true)?;
    require_json_media(&response, LiveError::SchemaDrift)?;
    let metadata = bounded_body(response, MAX_SOURCE_RESPONSE_BYTES).await?;
    let metadata = parse_json_strict(&metadata).map_err(|_| LiveError::SchemaDrift)?;
    if metadata.get("version").and_then(Value::as_str).is_none() {
        return Err(LiveError::SchemaDrift);
    }

    let lookup = base
        .join("api/tracker/trackedEntities")
        .map_err(|_| LiveError::Configuration)?;
    let lookup_query = dhis2_lookup_query(&config)?;
    let response = client
        .get(lookup)
        .basic_auth(
            required(&config, "DHIS2_USERNAME")?,
            Some(required(&config, "DHIS2_PASSWORD")?),
        )
        .query(&lookup_query)
        .send()
        .await
        .map_err(|_| LiveError::Unavailable)?;
    require_success(response.status(), false)?;
    require_json_media(&response, LiveError::SchemaDrift)?;
    let body = bounded_body(response, MAX_SOURCE_RESPONSE_BYTES).await?;
    let body = parse_json_strict(&body).map_err(|_| LiveError::SchemaDrift)?;
    validate_dhis2_lookup(&body, required(&config, "DHIS2_TEST_TRACKED_ENTITY_ID")?)
}

async fn run_opencrvs() -> Result<(), LiveError> {
    let path = credential_path("EVIDENCE_OPENCRVS_LIVE_ENV_FILE", None)?;
    let config = read_exact_credentials(
        &path,
        &[
            "OPENCRVS_CLIENT_ID",
            "OPENCRVS_SECRET",
            "OPENCRVS_URL",
            "OPENCRVS_TEST_TRACKING_ID",
        ],
    )?;
    let (token_url, search_url) = opencrvs_urls(required(&config, "OPENCRVS_URL")?)?;
    let client = live_client()?;

    // Form-body placement mirrors the reviewed reference bundle and keeps the
    // client credentials out of the token URL, where a proxy or ingress log
    // would capture them.
    let response = client
        .post(token_url)
        .form(&[
            ("client_id", required(&config, "OPENCRVS_CLIENT_ID")?),
            ("client_secret", required(&config, "OPENCRVS_SECRET")?),
            ("grant_type", "client_credentials"),
        ])
        .send()
        .await
        .map_err(|_| LiveError::Unavailable)?;
    require_success(response.status(), true)?;
    require_json_media(&response, LiveError::Authentication)?;
    let token_body = bounded_body(response, MAX_TOKEN_RESPONSE_BYTES).await?;
    let token_body = parse_json_strict(&token_body).map_err(|_| LiveError::Authentication)?;
    let mut token_object = token_body
        .as_object()
        .cloned()
        .ok_or(LiveError::Authentication)?;
    // This check must stay as strict as the product's own token parser in
    // `source::parse_token_response`. A live check that accepts a response the
    // product rejects reports a passing profile for a source Evidence cannot
    // actually reach.
    if !token_object.keys().all(|key| {
        matches!(
            key.as_str(),
            "access_token" | "token_type" | "expires_in" | "scope"
        )
    }) {
        return Err(LiveError::Authentication);
    }
    let token = token_object
        .remove("access_token")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .filter(|value| !value.is_empty() && value.len() <= MAX_TOKEN_RESPONSE_BYTES)
        .map(Zeroizing::new)
        .ok_or(LiveError::Authentication)?;
    // `token_type` is required by RFC 6749 section 5.1 and by the product.
    if !token_object
        .remove("token_type")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .is_some_and(|token_type| token_type.eq_ignore_ascii_case("bearer"))
    {
        return Err(LiveError::Authentication);
    }
    // `expires_in` is only recommended, so an absent lifetime is accepted here
    // exactly as the product accepts it under a configured assumed lifetime.
    // A present lifetime must still be a positive integer.
    if token_object
        .remove("expires_in")
        .is_some_and(|value| value.as_u64().is_none_or(|seconds| seconds == 0))
    {
        return Err(LiveError::Authentication);
    }
    if token_object
        .remove("scope")
        .is_some_and(|value| value.as_str().is_none_or(str::is_empty))
    {
        return Err(LiveError::Authentication);
    }

    let tracking_id = required(&config, "OPENCRVS_TEST_TRACKING_ID")?;
    let search_body = opencrvs_tracking_id_search(tracking_id);
    let response = client
        .post(search_url)
        .bearer_auth(token.as_str())
        .json(&search_body)
        .send()
        .await
        .map_err(|_| LiveError::Unavailable)?;
    require_success(response.status(), false)?;
    require_json_media(&response, LiveError::SchemaDrift)?;
    let body = bounded_body(response, MAX_SOURCE_RESPONSE_BYTES).await?;
    let body = parse_json_strict(&body).map_err(|_| LiveError::SchemaDrift)?;
    validate_opencrvs_search(&body, tracking_id)
}

fn dhis2_lookup_query(
    config: &BTreeMap<String, Zeroizing<String>>,
) -> Result<Vec<(&'static str, String)>, LiveError> {
    Ok(vec![
        (
            "program",
            required(config, "DHIS2_TEST_PROGRAM_ID")?.to_owned(),
        ),
        (
            "orgUnits",
            required(config, "DHIS2_TEST_ORG_UNIT_ID")?.to_owned(),
        ),
        (
            "trackedEntities",
            required(config, "DHIS2_TEST_TRACKED_ENTITY_ID")?.to_owned(),
        ),
        (
            "fields",
            "trackedEntity,attributes[attribute,value]".to_owned(),
        ),
        ("pageSize", "2".to_owned()),
        ("page", "1".to_owned()),
        ("totalPages", "true".to_owned()),
    ])
}

fn validate_dhis2_lookup(body: &Value, expected_tracked_entity: &str) -> Result<(), LiveError> {
    let object = body.as_object().ok_or(LiveError::SchemaDrift)?;
    if !object
        .keys()
        .all(|key| matches!(key.as_str(), "pager" | "trackedEntities"))
    {
        return Err(LiveError::ExcessDisclosure);
    }
    let pager = object
        .get("pager")
        .and_then(Value::as_object)
        .ok_or(LiveError::SchemaDrift)?;
    if pager.get("page").and_then(Value::as_u64) != Some(1)
        || pager.get("pageSize").and_then(Value::as_u64) != Some(2)
        || !pager
            .keys()
            .all(|key| matches!(key.as_str(), "page" | "pageSize" | "total" | "pageCount"))
    {
        return Err(LiveError::SchemaDrift);
    }
    let records = object
        .get("trackedEntities")
        .and_then(Value::as_array)
        .ok_or(LiveError::SchemaDrift)?;
    if records.len() > 2 {
        return Err(LiveError::ExcessDisclosure);
    }
    if records.len() != 1 {
        return Err(LiveError::Unavailable);
    }
    let record = records[0].as_object().ok_or(LiveError::SchemaDrift)?;
    if !record.contains_key("trackedEntity") || !record.contains_key("attributes") {
        return Err(LiveError::SchemaDrift);
    }
    if !record
        .keys()
        .all(|key| matches!(key.as_str(), "trackedEntity" | "attributes"))
    {
        return Err(LiveError::ExcessDisclosure);
    }
    if record.get("trackedEntity").and_then(Value::as_str) != Some(expected_tracked_entity) {
        return Err(LiveError::SchemaDrift);
    }
    let attributes = record
        .get("attributes")
        .and_then(Value::as_array)
        .ok_or(LiveError::SchemaDrift)?;
    if attributes.is_empty() {
        return Err(LiveError::SchemaDrift);
    }
    for attribute in attributes {
        let attribute = attribute.as_object().ok_or(LiveError::SchemaDrift)?;
        if attribute.get("attribute").and_then(Value::as_str).is_none()
            || attribute.get("value").and_then(Value::as_str).is_none()
        {
            return Err(LiveError::SchemaDrift);
        }
        if !attribute
            .keys()
            .all(|key| matches!(key.as_str(), "attribute" | "value"))
        {
            return Err(LiveError::ExcessDisclosure);
        }
    }
    Ok(())
}

fn opencrvs_tracking_id_search(tracking_id: &str) -> Value {
    json!({
        "query": {
            "type": "and",
            "clauses": [{
                "eventType": "birth",
                "status": {"type": "exact", "term": "REGISTERED"},
                "trackingId": {
                    "type": "exact",
                    "term": tracking_id
                }
            }]
        },
        "limit": 2,
        "offset": 0
    })
}

fn validate_opencrvs_search(body: &Value, expected_tracking_id: &str) -> Result<(), LiveError> {
    let object = body.as_object().ok_or(LiveError::SchemaDrift)?;
    let results = object
        .get("results")
        .and_then(Value::as_array)
        .ok_or(LiveError::SchemaDrift)?;
    let total = object
        .get("total")
        .and_then(Value::as_u64)
        .ok_or(LiveError::SchemaDrift)?;
    if results.len() > 2 {
        return Err(LiveError::ExcessDisclosure);
    }
    if results.len() as u64 > total {
        return Err(LiveError::SchemaDrift);
    }
    if total != 1 || results.len() != 1 {
        return Err(LiveError::Unavailable);
    }
    let returned_tracking_id = results[0]
        .get("trackingId")
        .and_then(Value::as_str)
        .ok_or(LiveError::SchemaDrift)?;
    if returned_tracking_id != expected_tracking_id {
        return Err(LiveError::SchemaDrift);
    }
    Ok(())
}

fn credential_path(variable: &str, default: Option<&str>) -> Result<PathBuf, LiveError> {
    let value = env::var_os(variable)
        .or_else(|| default.map(Into::into))
        .ok_or(LiveError::Skipped)?;
    let path = PathBuf::from(value);
    if !path.exists() && default.is_some() && env::var_os(variable).is_none() {
        return Err(LiveError::Skipped);
    }
    if !path.is_absolute() {
        return Err(LiveError::CredentialFile);
    }
    Ok(path)
}

fn read_exact_credentials(
    path: &Path,
    required_keys: &[&str],
) -> Result<BTreeMap<String, Zeroizing<String>>, LiveError> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|_| LiveError::CredentialFile)?;
    let canonical = path.canonicalize().map_err(|_| LiveError::CredentialFile)?;
    if canonical.starts_with(&repository) {
        return Err(LiveError::CredentialFile);
    }
    let file = open_owner_only(path)?;
    let metadata = file.metadata().map_err(|_| LiveError::CredentialFile)?;
    if metadata.len() == 0 || metadata.len() > MAX_CREDENTIAL_FILE_BYTES {
        return Err(LiveError::CredentialFile);
    }
    let mut text = Zeroizing::new(String::new());
    file.take(MAX_CREDENTIAL_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| LiveError::CredentialFile)?;
    if text.len() as u64 != metadata.len() || text.contains('\0') {
        return Err(LiveError::CredentialFile);
    }

    let allow = required_keys.iter().copied().collect::<BTreeSet<_>>();
    let mut values = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() || line.trim() != line {
            return Err(LiveError::CredentialFile);
        }
        let (key, value) = line.split_once('=').ok_or(LiveError::CredentialFile)?;
        if !allow.contains(key)
            || value.is_empty()
            || value.len() > 16 * 1024
            || values
                .insert(key.to_owned(), Zeroizing::new(value.to_owned()))
                .is_some()
        {
            return Err(LiveError::CredentialFile);
        }
    }
    if values.len() != required_keys.len()
        || required_keys.iter().any(|key| !values.contains_key(*key))
    {
        return Err(LiveError::CredentialFile);
    }
    Ok(values)
}

#[cfg(unix)]
fn open_owner_only(path: &Path) -> Result<File, LiveError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(path).map_err(|_| LiveError::CredentialFile)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.mode() & 0o777 != 0o600
    {
        return Err(LiveError::CredentialFile);
    }
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| LiveError::CredentialFile)?;
    let file = File::from(fd);
    let opened = file.metadata().map_err(|_| LiveError::CredentialFile)?;
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.uid() != rustix::process::getuid().as_raw()
        || opened.uid() != metadata.uid()
        || opened.mode() & 0o777 != 0o600
        || opened.nlink() != 1
    {
        return Err(LiveError::CredentialFile);
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_owner_only(_path: &Path) -> Result<File, LiveError> {
    Err(LiveError::CredentialFile)
}

fn required<'a>(
    config: &'a BTreeMap<String, Zeroizing<String>>,
    key: &str,
) -> Result<&'a str, LiveError> {
    config
        .get(key)
        .map(|value| value.as_str())
        .ok_or(LiveError::Configuration)
}

fn live_client() -> Result<Client, LiveError> {
    Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(REQUEST_TIMEOUT)
        .user_agent("registry-evidence-live-source-check/1")
        .build()
        .map_err(|_| LiveError::Configuration)
}

fn require_json_media(response: &Response, failure: LiveError) -> Result<(), LiveError> {
    let mut values = response.headers().get_all(CONTENT_TYPE).iter();
    let value = values.next().ok_or(failure)?;
    if values.next().is_some() {
        return Err(failure);
    }
    let value = value.to_str().map_err(|_| failure)?;
    let media_type = value.split(';').next().unwrap_or_default().trim();
    if media_type.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(failure)
    }
}

fn safe_https_base(value: &str) -> Result<Url, LiveError> {
    let mut url = Url::parse(value).map_err(|_| LiveError::Configuration)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(LiveError::Configuration);
    }
    url.set_query(None);
    url.set_fragment(None);
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

fn opencrvs_urls(value: &str) -> Result<(Url, Url), LiveError> {
    let normalized = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let base = safe_https_base(&normalized)?;
    if base.path() != "/" || base.port().is_some() {
        return Err(LiveError::Configuration);
    }
    let host = base.host_str().ok_or(LiveError::Configuration)?;
    let mut labels = host.split('.').collect::<Vec<_>>();
    if labels.len() < 2 {
        return Err(LiveError::Configuration);
    }
    if matches!(labels[0], "gateway" | "register" | "auth" | "events") {
        labels.remove(0);
    }
    if labels.len() < 2 {
        return Err(LiveError::Configuration);
    }
    let domain = labels.join(".");
    let token = Url::parse(&format!("https://auth.{domain}/token"))
        .map_err(|_| LiveError::Configuration)?;
    let search = Url::parse(&format!("https://events.{domain}/events/search"))
        .map_err(|_| LiveError::Configuration)?;
    Ok((token, search))
}

fn require_success(status: StatusCode, authentication: bool) -> Result<(), LiveError> {
    if status.is_success() {
        Ok(())
    } else if authentication && matches!(status.as_u16(), 400 | 401 | 403) {
        Err(LiveError::Authentication)
    } else {
        Err(LiveError::Unavailable)
    }
}

async fn bounded_body(mut response: Response, maximum: usize) -> Result<Vec<u8>, LiveError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(LiveError::ExcessDisclosure);
    }
    let mut output = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| LiveError::Unavailable)? {
        if output.len().saturating_add(chunk.len()) > maximum {
            return Err(LiveError::ExcessDisclosure);
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    #[cfg(unix)]
    #[test]
    fn exact_file_parser_accepts_only_owner_only_external_files() {
        let temporary = tempfile::tempdir().expect("external temporary directory");
        let path = temporary.path().join("profile.env");
        fs::write(&path, "A=one\nB=two\n").expect("fixture file writes");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode sets");
        let parsed = read_exact_credentials(&path, &["A", "B"]).expect("exact file parses");
        assert_eq!(parsed.len(), 2);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("mode sets");
        assert_eq!(
            read_exact_credentials(&path, &["A", "B"]),
            Err(LiveError::CredentialFile)
        );
    }

    #[cfg(unix)]
    #[test]
    fn parser_rejects_unknown_duplicate_empty_and_symlinked_inputs() {
        let temporary = tempfile::tempdir().expect("external temporary directory");
        for (name, contents) in [
            ("unknown", "A=one\nC=two\n"),
            ("duplicate", "A=one\nA=two\nB=three\n"),
            ("empty", "A=\nB=two\n"),
            ("shell", "A=$(command)\nB=two\nEXTRA=value\n"),
        ] {
            let path = temporary.path().join(name);
            fs::write(&path, contents).expect("fixture file writes");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode sets");
            assert_eq!(
                read_exact_credentials(&path, &["A", "B"]),
                Err(LiveError::CredentialFile)
            );
        }
        let target = temporary.path().join("target");
        let link = temporary.path().join("link");
        fs::write(&target, "A=one\nB=two\n").expect("target writes");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("mode sets");
        std::os::unix::fs::symlink(&target, &link).expect("symlink creates");
        assert_eq!(
            read_exact_credentials(&link, &["A", "B"]),
            Err(LiveError::CredentialFile)
        );
    }

    #[test]
    fn service_urls_are_fixed_and_never_carry_credentials() {
        let (token, search) = opencrvs_urls("https://register.example.test").expect("URL derives");
        assert_eq!(token.as_str(), "https://auth.example.test/token");
        assert_eq!(search.as_str(), "https://events.example.test/events/search");
        let (token, search) = opencrvs_urls("example.test").expect("bare domain derives");
        assert_eq!(token.as_str(), "https://auth.example.test/token");
        assert_eq!(search.as_str(), "https://events.example.test/events/search");
        assert!(opencrvs_urls("http://example.test").is_err());
        assert!(safe_https_base("https://user:secret@example.test").is_err());
    }

    #[test]
    fn dhis2_tracker_query_is_deployment_scoped_and_bounded() {
        let config = BTreeMap::from([
            (
                "DHIS2_TEST_PROGRAM_ID".to_owned(),
                Zeroizing::new("PROGRAM-CANARY".to_owned()),
            ),
            (
                "DHIS2_TEST_ORG_UNIT_ID".to_owned(),
                Zeroizing::new("ORG-UNIT-CANARY".to_owned()),
            ),
            (
                "DHIS2_TEST_TRACKED_ENTITY_ID".to_owned(),
                Zeroizing::new("TRACKED-ENTITY-CANARY".to_owned()),
            ),
        ]);
        assert!(
            dhis2_lookup_query(&config)
                == Ok(vec![
                    ("program", "PROGRAM-CANARY".to_owned()),
                    ("orgUnits", "ORG-UNIT-CANARY".to_owned()),
                    ("trackedEntities", "TRACKED-ENTITY-CANARY".to_owned()),
                    (
                        "fields",
                        "trackedEntity,attributes[attribute,value]".to_owned(),
                    ),
                    ("pageSize", "2".to_owned()),
                    ("page", "1".to_owned()),
                    ("totalPages", "true".to_owned()),
                ]),
            "DHIS2 lookup query did not match the fixed bounded shape"
        );
        assert_eq!(
            validate_dhis2_lookup(
                &json!({
                    "pager": {"page": 1, "pageSize": 2},
                    "trackedEntities": [{
                        "trackedEntity": "TRACKED-ENTITY-CANARY",
                        "attributes": [{"attribute": "ATTRIBUTE-CANARY", "value": "VALUE-CANARY"}]
                    }]
                }),
                "TRACKED-ENTITY-CANARY"
            ),
            Ok(())
        );
        assert_eq!(
            validate_dhis2_lookup(
                &json!({"pager": {"page": 1, "pageSize": 2}, "trackedEntities": []}),
                "TRACKED-ENTITY-CANARY"
            ),
            Err(LiveError::Unavailable)
        );
        assert_eq!(
            validate_dhis2_lookup(
                &json!({"pager": {"page": 1, "pageSize": 2}, "trackedEntities": [{}, {}, {}]}),
                "TRACKED-ENTITY-CANARY"
            ),
            Err(LiveError::ExcessDisclosure)
        );
        assert_eq!(
            validate_dhis2_lookup(
                &json!({
                    "pager": {"page": 1, "pageSize": 2},
                    "trackedEntities": [{
                        "trackedEntity": "WRONG-ENTITY",
                        "attributes": [{"attribute": "ATTRIBUTE-CANARY", "value": "VALUE-CANARY"}]
                    }]
                }),
                "TRACKED-ENTITY-CANARY"
            ),
            Err(LiveError::SchemaDrift)
        );
    }

    #[test]
    fn opencrvs_tracking_id_search_is_exact_and_bounded() {
        let selector = "TRACKING-CANARY";
        assert!(
            opencrvs_tracking_id_search(selector)
                == json!({
                    "query": {
                        "type": "and",
                        "clauses": [{
                            "eventType": "birth",
                            "status": {"type": "exact", "term": "REGISTERED"},
                            "trackingId": {
                                "type": "exact",
                                "term": selector
                            }
                        }]
                    },
                    "limit": 2,
                    "offset": 0
                }),
            "OpenCRVS search body did not match the fixed bounded shape"
        );
        let exact = json!({
            "results": [{
                "trackingId": selector
            }],
            "total": 1
        });
        assert_eq!(validate_opencrvs_search(&exact, selector), Ok(()));
        assert_eq!(
            validate_opencrvs_search(
                &json!({"results": [{"trackingId": "WRONG-TRACKING-CANARY"}], "total": 1}),
                selector
            ),
            Err(LiveError::SchemaDrift)
        );
        assert_eq!(
            validate_opencrvs_search(&json!({"results": [], "total": 0}), selector),
            Err(LiveError::Unavailable)
        );
        assert_eq!(
            validate_opencrvs_search(&json!({"results": [{}, {}, {}], "total": 3}), selector),
            Err(LiveError::ExcessDisclosure)
        );
    }
}

// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};
use url::Url;

pub(crate) const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: "ProjectDevPlan",
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(
            "id.registrystack.org/formats/project-dev/v1alpha1",
        )],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

#[cfg(feature = "schema")]
pub(crate) fn schema() -> schemars::Schema {
    schemars::schema_for!(Plan)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub(super) enum Product {
    Breg,
    Casework,
}

impl Product {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Breg => "breg",
            Self::Casework => "casework",
        }
    }
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Plan {
    pub issuer: String,
    pub products: Vec<ProductPlan>,
    pub people: BTreeMap<String, Person>,
    pub journey: Journey,
    #[serde(default)]
    pub bindings: super::bindings::Bindings,
    #[serde(default)]
    pub schema_test_people: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct ProductPlan {
    pub product: Product,
    pub project: PathBuf,
    pub audience: String,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Person {
    pub subject: String,
    pub client: String,
    pub grants: BTreeMap<Product, Grant>,
    /// Forward the same authority to both products. Both grants must declare the same scopes and additional claims.
    #[serde(default, rename = "caseworkContext")]
    pub casework_context: bool,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Grant {
    pub profile: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub claims: Map<String, Value>,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Journey {
    pub id: String,
    pub steps: Vec<Step>,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Step {
    pub id: String,
    pub product: Product,
    #[serde(rename = "as")]
    pub person: String,
    pub method: Method,
    pub path: String,
    pub body: Option<Value>,
    pub raw: Option<RawBody>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub expect: Expected,
    #[serde(default)]
    pub capture: BTreeMap<String, Capture>,
    pub poll: Option<Poll>,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "UPPERCASE")]
pub(super) enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl From<&Method> for reqwest::Method {
    fn from(method: &Method) -> Self {
        match method {
            Method::Get => Self::GET,
            Method::Post => Self::POST,
            Method::Put => Self::PUT,
            Method::Patch => Self::PATCH,
            Method::Delete => Self::DELETE,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Expected {
    pub status: ExpectedStatus,
    #[serde(default)]
    pub json: BTreeMap<String, Value>,
    #[serde(default)]
    pub checks: Vec<Check>,
    pub code: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub(super) enum ExpectedStatus {
    One(u16),
    Many(Vec<u16>),
}

impl ExpectedStatus {
    pub(super) fn first(&self) -> u16 {
        match self {
            Self::One(status) => *status,
            Self::Many(statuses) => statuses[0],
        }
    }

    pub(super) fn contains(&self, status: u16) -> bool {
        match self {
            Self::One(expected) => *expected == status,
            Self::Many(expected) => expected.contains(&status),
        }
    }

    fn values(&self) -> Vec<u16> {
        match self {
            Self::One(status) => vec![*status],
            Self::Many(statuses) => statuses.clone(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Check {
    pub pointer: String,
    pub equals: Option<Value>,
    pub length: Option<usize>,
    pub contains: Option<Value>,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub(super) enum Capture {
    Pointer(String),
    Header(HeaderCapture),
    Find(FindCapture),
    Value(ValueCapture),
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct HeaderCapture {
    pub header: CapturedHeader,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub(super) enum CapturedHeader {
    Etag,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct ValueCapture {
    pub pointer: String,
    pub query: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct FindCapture {
    pub find: String,
    pub r#where: FindWhere,
    pub pointer: String,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct FindWhere {
    pub pointer: String,
    pub equals: Value,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Poll {
    pub timeout_ms: u64,
    pub interval_ms: u64,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RawBody {
    pub content_type: String,
    pub base64: String,
}

pub(super) fn identifier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn bounded_atom(value: &str) -> bool {
    (1..=256).contains(&value.len()) && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}

pub(super) fn reserved_claim(claim: &str) -> bool {
    matches!(
        claim,
        "iss"
            | "aud"
            | "sub"
            | "client_id"
            | "azp"
            | "exp"
            | "iat"
            | "nbf"
            | "jti"
            | "scope"
            | "registry_principal"
            | "registry_assertion_issuer"
    ) || claim.starts_with("registry_grant_")
}

fn require(condition: bool, field: &str, message: &str) -> Result<()> {
    if !condition {
        bail!("dev.yaml {field} {message}");
    }
    Ok(())
}

pub(super) fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() as u64 <= limit, "file exceeds the size limit");
    Ok(bytes)
}

pub(super) fn load(root: &Path) -> Result<Plan> {
    let file = root.join("dev.yaml");
    let bytes = read(&file, 256 * 1024).context("cannot read dev.yaml")?;
    let plan = Reader::new("dev.yaml")
        .decode::<Plan>(&bytes, &Expect::one(&FORMAT))?
        .value;
    plan.validate(root)?;
    Ok(plan)
}

impl Plan {
    pub(super) fn product(&self, product: Product) -> &ProductPlan {
        self.products
            .iter()
            .find(|entry| entry.product == product)
            .expect("validated product")
    }

    fn validate(&self, root: &Path) -> Result<()> {
        require(
            Url::parse(&self.issuer).is_ok_and(|url| {
                url.scheme() == "https"
                    && url.host().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && self.issuer.len() <= 512
            }),
            "/issuer",
            "must be the project's HTTPS issuer URL",
        )?;
        require(
            !self.products.is_empty(),
            "/products",
            "must name at least one product",
        )?;
        let mut products = BTreeSet::new();
        let mut audiences = BTreeSet::new();
        for (index, entry) in self.products.iter().enumerate() {
            let field = format!("/products/{index}");
            require(
                products.insert(entry.product),
                &format!("{field}/product"),
                "is repeated",
            )?;
            require(
                bounded_atom(&entry.audience) && audiences.insert(&entry.audience),
                &format!("{field}/audience"),
                "must be a distinct, bounded audience",
            )?;
            require(
                entry.project == Path::new(".")
                    || (!entry.project.as_os_str().is_empty()
                        && entry
                            .project
                            .components()
                            .all(|part| matches!(part, Component::Normal(_)))),
                &format!("{field}/project"),
                "must be a path inside the project directory",
            )?;
            let manifest = match entry.product {
                Product::Breg => "registry.yaml",
                Product::Casework => "casework.yaml",
            };
            require(
                root.join(&entry.project)
                    .join(manifest)
                    .canonicalize()
                    .is_ok_and(|path| path.starts_with(root) && path.is_file()),
                &format!("{field}/project"),
                &format!("must contain {manifest} inside the project directory"),
            )?;
        }
        require(
            (1..=32).contains(&self.people.len()),
            "/people",
            "must define 1 to 32 people",
        )?;
        for (name, person) in &self.people {
            require(
                identifier(name),
                "/people",
                "contains an invalid person name",
            )?;
            let field = format!("/people/{name}");
            require(
                bounded_atom(&person.subject),
                &format!("{field}/subject"),
                "must be a bounded subject",
            )?;
            require(
                bounded_atom(&person.client),
                &format!("{field}/client"),
                "must be a bounded client ID",
            )?;
            require(
                !person.grants.is_empty(),
                &format!("{field}/grants"),
                "must name a product grant",
            )?;
            for (product, grant) in &person.grants {
                let field = format!("{field}/grants/{}", product.name());
                require(
                    products.contains(product),
                    &field,
                    "must name a started product",
                )?;
                require(
                    identifier(&grant.profile),
                    &format!("{field}/profile"),
                    "must name a profile",
                )?;
                let scopes = grant.scopes.iter().collect::<BTreeSet<_>>();
                require(
                    scopes.len() == grant.scopes.len()
                        && scopes.len() <= 32
                        && scopes.iter().all(|scope| bounded_atom(scope)),
                    &format!("{field}/scopes"),
                    "must contain up to 32 distinct scopes",
                )?;
                for claim in grant.claims.keys() {
                    require(
                        bounded_atom(claim) && !reserved_claim(claim),
                        &format!("{field}/claims"),
                        "contains a reserved or invalid claim",
                    )?;
                }
            }
            if person.casework_context {
                require(
                    self.bindings.casework_context_provider.is_some(),
                    &format!("{field}/caseworkContext"),
                    "requires /bindings/caseworkContextProvider",
                )?;
                let breg = person.grants.get(&Product::Breg);
                let casework = person.grants.get(&Product::Casework);
                require(
                    breg.is_some() && casework.is_some(),
                    &format!("{field}/caseworkContext"),
                    "requires both BReg and Casework grants",
                )?;
                let (breg, casework) = (
                    breg.expect("checked grant"),
                    casework.expect("checked grant"),
                );
                require(
                    breg.claims == casework.claims
                        && breg.scopes.iter().collect::<BTreeSet<_>>()
                            == casework.scopes.iter().collect(),
                    &format!("{field}/caseworkContext"),
                    "requires the same scopes and additional claims in both grants",
                )?;
            }
        }
        for (journey, steps) in &self.schema_test_people {
            for (step, person) in steps {
                require(
                    self.people
                        .get(person)
                        .is_some_and(|person| person.grants.contains_key(&Product::Breg)),
                    &format!("/schemaTestPeople/{journey}/{step}"),
                    "must name a person with a BReg grant",
                )?;
            }
        }
        for product in products {
            require(
                self.people
                    .values()
                    .any(|person| person.grants.contains_key(&product)),
                "/people",
                &format!("must define at least one grant for {}", product.name()),
            )?;
        }
        self.bindings.validate(self)?;
        self.journey.validate(self)
    }
}

impl Journey {
    fn validate(&self, plan: &Plan) -> Result<()> {
        require(
            identifier(&self.id),
            "/journey/id",
            "must be a local identifier",
        )?;
        require(
            (1..=32).contains(&self.steps.len()),
            "/journey/steps",
            "must contain 1 to 32 steps",
        )?;
        let mut ids = BTreeSet::new();
        let mut captures = BTreeSet::new();
        for (index, step) in self.steps.iter().enumerate() {
            let field = format!("/journey/steps/{index}");
            require(
                step_identifier(&step.id) && ids.insert(&step.id),
                &format!("{field}/id"),
                "must be a unique local identifier",
            )?;
            require(
                plan.people
                    .get(&step.person)
                    .is_some_and(|person| person.grants.contains_key(&step.product)),
                &format!("{field}/as"),
                "must name a person with a grant for the step's product",
            )?;
            require(
                valid_path(&step.path),
                &format!("{field}/path"),
                "must be a relative product API path starting with /v1/",
            )?;
            let statuses = step.expect.status.values();
            require(
                (1..=16).contains(&statuses.len())
                    && statuses.iter().all(|status| (200..=599).contains(status))
                    && statuses.iter().collect::<BTreeSet<_>>().len() == statuses.len(),
                &format!("{field}/expect/status"),
                "must contain 1 to 16 distinct HTTP statuses from 200 to 599",
            )?;
            require(
                step.body.is_none() || step.raw.is_none(),
                &field,
                "must not contain both body and raw",
            )?;
            require(
                step.raw.is_none() || !matches!(step.method, Method::Get),
                &format!("{field}/raw"),
                "is supported only for non-GET requests",
            )?;
            if let Some(body) = &step.body {
                require(
                    serde_json::to_vec(body).is_ok_and(|bytes| bytes.len() <= 1024 * 1024),
                    &format!("{field}/body"),
                    "must encode to at most 1 MiB",
                )?;
            }
            if let Some(raw) = &step.raw {
                require(
                    (1..=256).contains(&raw.content_type.len())
                        && raw.content_type.contains('/')
                        && raw
                            .content_type
                            .bytes()
                            .all(|byte| byte.is_ascii() && byte != b'\r' && byte != b'\n'),
                    &format!("{field}/raw/contentType"),
                    "must be a bounded HTTP media type",
                )?;
                require(
                    raw.base64.len() <= 1_398_104
                        && BASE64
                            .decode(&raw.base64)
                            .is_ok_and(|bytes| bytes.len() <= 1024 * 1024),
                    &format!("{field}/raw/base64"),
                    "must be valid base64 encoding at most 1 MiB",
                )?;
            }
            if let Some(poll) = &step.poll {
                require(
                    matches!(step.method, Method::Get),
                    &format!("{field}/poll"),
                    "is supported only for GET requests",
                )?;
                require(
                    (1..=60_000).contains(&poll.timeout_ms)
                        && (50..=5_000).contains(&poll.interval_ms)
                        && poll.interval_ms <= poll.timeout_ms
                        && poll.timeout_ms.div_ceil(poll.interval_ms) < 250,
                    &format!("{field}/poll"),
                    "must use a 1 to 60000 ms timeout, a 50 to 5000 ms interval, and at most 250 attempts",
                )?;
            }
            for header in step.headers.keys() {
                require(
                    matches!(
                        header.as_str(),
                        "If-Match" | "Idempotency-Key" | "Registry-Source-Profile"
                    ),
                    &format!("{field}/headers"),
                    "contains a header outside the supported list",
                )?;
            }
            let verify_reference = |value: &str| {
                captures
                    .contains(value)
                    .then(|| value.to_owned())
                    .context("must refer to an earlier capture")
            };
            expand(&step.path, verify_reference)
                .with_context(|| format!("dev.yaml {field}/path"))?;
            for value in step.headers.values() {
                expand(value, verify_reference)
                    .with_context(|| format!("dev.yaml {field}/headers"))?;
            }
            if let Some(body) = &step.body {
                expand_json(body, verify_reference)
                    .with_context(|| format!("dev.yaml {field}/body"))?;
            }
            require(
                step.expect.json.keys().all(|value| pointer(value)),
                &format!("{field}/expect/json"),
                "must use JSON pointers",
            )?;
            for value in step.expect.json.values() {
                expand_json(value, verify_reference)
                    .with_context(|| format!("dev.yaml {field}/expect/json"))?;
            }
            require(
                step.expect.checks.len() <= 32,
                &format!("{field}/expect/checks"),
                "must contain at most 32 checks",
            )?;
            for check in &step.expect.checks {
                require(
                    pointer(&check.pointer),
                    &format!("{field}/expect/checks"),
                    "must use JSON pointers",
                )?;
                require(
                    usize::from(check.equals.is_some())
                        + usize::from(check.length.is_some())
                        + usize::from(check.contains.is_some())
                        == 1,
                    &format!("{field}/expect/checks"),
                    "must contain exactly one of equals, length, or contains",
                )?;
                require(
                    check.length.is_none_or(|length| length <= 1024 * 1024),
                    &format!("{field}/expect/checks"),
                    "contains an excessive length",
                )?;
                for value in check.equals.iter().chain(&check.contains) {
                    expand_json(value, verify_reference)
                        .with_context(|| format!("dev.yaml {field}/expect/checks"))?;
                }
            }
            if let Some(code) = &step.expect.code {
                require(
                    bounded_atom(code),
                    &format!("{field}/expect/code"),
                    "must be a bounded problem code",
                )?;
                expand(code, verify_reference)
                    .with_context(|| format!("dev.yaml {field}/expect/code"))?;
            }
            for (name, capture) in &step.capture {
                require(
                    capture_identifier(name) && !captures.contains(name.as_str()),
                    &format!("{field}/capture"),
                    "must use unique bounded capture names",
                )?;
                match capture {
                    Capture::Pointer(pointer_value) => require(
                        pointer(pointer_value),
                        &format!("{field}/capture/{name}"),
                        "must use a JSON pointer",
                    )?,
                    Capture::Header(_) => {}
                    Capture::Value(capture) => {
                        require(
                            pointer(&capture.pointer),
                            &format!("{field}/capture/{name}/pointer"),
                            "must be a JSON pointer",
                        )?;
                        if let Some(query) = &capture.query {
                            require(
                                bounded_atom(query),
                                &format!("{field}/capture/{name}/query"),
                                "must name a bounded query parameter",
                            )?;
                        }
                    }
                    Capture::Find(capture) => {
                        require(
                            pointer(&capture.find)
                                && pointer(&capture.r#where.pointer)
                                && pointer(&capture.pointer),
                            &format!("{field}/capture/{name}"),
                            "must use JSON pointers",
                        )?;
                        expand_json(&capture.r#where.equals, |value| {
                            captures
                                .contains(value)
                                .then(|| value.to_owned())
                                .context("must refer to an earlier capture")
                        })
                        .with_context(|| format!("dev.yaml {field}/capture/{name}/find"))?;
                    }
                }
                captures.insert(name.clone());
            }
        }
        Ok(())
    }
}

fn step_identifier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-.".contains(&byte))
        && !matches!(value.as_bytes().first(), Some(b'-' | b'.'))
        && !value.ends_with('.')
        && !value.contains("..")
}

fn capture_identifier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn pointer(value: &str) -> bool {
    value.is_empty() || value.starts_with('/')
}

pub(super) fn valid_path(value: &str) -> bool {
    value.len() <= 2048
        && value.starts_with("/v1/")
        && !value.contains(['\\', '#'])
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}

pub(super) fn expand(value: &str, lookup: impl Fn(&str) -> Result<String>) -> Result<String> {
    let mut result = String::new();
    let mut remainder = value;
    while let Some((prefix, after)) = remainder.split_once("{{") {
        result.push_str(prefix);
        let (name, tail) = after
            .split_once("}}")
            .context("has an unclosed capture reference")?;
        result.push_str(&lookup(name)?);
        remainder = tail;
    }
    result.push_str(remainder);
    Ok(result)
}

pub(super) fn expand_json(
    value: &Value,
    lookup: impl Fn(&str) -> Result<String> + Copy,
) -> Result<Value> {
    match value {
        Value::String(value) => Ok(Value::String(expand(value, lookup)?)),
        Value::Array(values) => values
            .iter()
            .map(|item| expand_json(item, lookup))
            .collect(),
        Value::Object(values) => values
            .iter()
            .map(|(key, item)| Ok((key.clone(), expand_json(item, lookup)?)))
            .collect(),
        value => Ok(value.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn plan(step: Value) -> (tempfile::TempDir, Plan) {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("registry.yaml"), "fixture").unwrap();
        let plan = serde_json::from_value(json!({
            "issuer": "https://issuer.example.invalid",
            "products": [{
                "product": "breg", "project": ".", "audience": "registry"
            }],
            "people": {"operator": {
                "subject": "operator", "client": "operator-client",
                "grants": {"breg": {"profile": "operator", "scopes": []}}
            }},
            "journey": {"id": "smoke", "steps": [step]}
        }))
        .unwrap();
        (root, plan)
    }

    fn canonical(root: &tempfile::TempDir) -> PathBuf {
        root.path().canonicalize().unwrap()
    }

    #[test]
    fn studio_journey_wire_variants_deserialize() {
        let (_, plan) = plan(json!({
            "id": "create.v1", "product": "breg", "as": "operator",
            "method": "POST", "path": "/v1/records",
            "raw": {"contentType": "application/octet-stream", "base64": "YQ=="},
            "expect": {
                "status": [200, 201], "code": "request.accepted",
                "checks": [
                    {"pointer": "/items", "length": 1},
                    {"pointer": "/state", "equals": "ready"},
                    {"pointer": "/tags", "contains": "open"}
                ]
            },
            "capture": {
                "requestId": {"pointer": "/requestId", "query": "id"},
                "etag": {"header": "etag"},
                "selected-item": {
                    "find": "/items", "where": {"pointer": "/id", "equals": "one"},
                    "pointer": "/value"
                }
            }
        }));
        assert_eq!(plan.journey.steps[0].expect.status.first(), 200);
        assert!(plan.journey.steps[0].expect.status.contains(201));
        assert!(matches!(
            plan.journey.steps[0].capture["etag"],
            Capture::Header(_)
        ));
        assert!(!plan.people["operator"].casework_context);
    }

    #[test]
    fn validation_accepts_dotted_steps_and_camel_case_captures() {
        let (root, plan) = plan(json!({
            "id": "read.v1", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records",
            "expect": {"status": [200, 202]},
            "capture": {"recordId": "/recordIdentifier"},
            "poll": {"timeoutMs": 500, "intervalMs": 50}
        }));
        plan.validate(&canonical(&root)).unwrap();
    }

    #[test]
    fn validation_refuses_polling_a_mutation() {
        let (root, plan) = plan(json!({
            "id": "create", "product": "breg", "as": "operator",
            "method": "POST", "path": "/v1/records", "body": {},
            "expect": {"status": 201},
            "poll": {"timeoutMs": 500, "intervalMs": 50}
        }));
        let error = plan.validate(&canonical(&root)).unwrap_err().to_string();
        assert!(error.contains("supported only for GET"), "{error}");
    }

    #[test]
    fn validation_refuses_forward_capture_references() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records/{{later}}",
            "expect": {"status": 200},
            "capture": {"later": "/recordIdentifier"}
        }));
        let error = format!("{:#}", plan.validate(&canonical(&root)).unwrap_err());
        assert!(error.contains("earlier capture"), "{error}");
    }

    #[test]
    fn validation_refuses_unbounded_poll_attempts() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records",
            "expect": {"status": 200},
            "poll": {"timeoutMs": 30000, "intervalMs": 50}
        }));
        let error = plan.validate(&canonical(&root)).unwrap_err().to_string();
        assert!(error.contains("at most 250 attempts"), "{error}");
    }

    #[test]
    fn validation_accepts_the_studio_review_poll() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200},
            "poll": {"timeoutMs": 60000, "intervalMs": 250}
        }));
        plan.validate(&canonical(&root)).unwrap();
    }

    #[test]
    fn casework_context_requires_the_binding_and_both_grants() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        let mut value = serde_json::to_value(plan).unwrap();
        value["people"]["operator"]["caseworkContext"] = json!(true);
        let plan: Plan = serde_json::from_value(value).unwrap();
        let error = plan.validate(&canonical(&root)).unwrap_err().to_string();
        assert!(
            error.contains("requires /bindings/caseworkContextProvider"),
            "{error}"
        );
    }

    #[test]
    fn casework_context_requires_both_grants_to_declare_all_forwarded_authority() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("registry.yaml"), "fixture").unwrap();
        fs::write(root.path().join("casework.yaml"), "fixture").unwrap();
        let value = |casework_jurisdiction: &str, casework_scopes: &[&str]| {
            json!({
                "issuer": "https://issuer.example.invalid",
                "products": [
                    {"product": "breg", "project": ".", "audience": "registry"},
                    {"product": "casework", "project": ".", "audience": "review"}
                ],
                "people": {
                    "context-reader": {
                        "subject": "context-reader", "client": "context-client",
                        "grants": {"breg": {
                            "profile": "context-reader", "scopes": ["registry:read"]
                        }}
                    },
                    "reviewer": {
                        "subject": "reviewer", "client": "reviewer-client",
                        "caseworkContext": true,
                        "grants": {
                            "breg": {
                                "profile": "reviewer", "scopes": ["registry:read", "casework:review"],
                                "claims": {"jurisdiction": "north"}
                            },
                            "casework": {
                                "profile": "reviewer", "scopes": casework_scopes,
                                "claims": {"jurisdiction": casework_jurisdiction}
                            }
                        }
                    }
                },
                "bindings": {"caseworkContextProvider": {
                    "id": "registry", "person": "context-reader", "action": "review-record"
                }},
                "journey": {"id": "review", "steps": [{
                    "id": "read", "product": "breg", "as": "reviewer",
                    "method": "GET", "path": "/v1/records", "expect": {"status": 200}
                }]}
            })
        };
        let shared_scopes = ["casework:review", "registry:read"];
        let valid: Plan = serde_json::from_value(value("north", &shared_scopes)).unwrap();
        valid.validate(&canonical(&root)).unwrap();

        let mut one_sided_claim = value("north", &shared_scopes);
        one_sided_claim["people"]["reviewer"]["grants"]["breg"]["claims"]["extra"] = json!(true);
        for invalid in [
            value("south", &shared_scopes),
            value("north", &["casework:review"]),
            one_sided_claim,
        ] {
            let invalid: Plan = serde_json::from_value(invalid).unwrap();
            let error = invalid.validate(&canonical(&root)).unwrap_err().to_string();
            assert!(
                error.contains("same scopes and additional claims"),
                "{error}"
            );
        }
    }
}

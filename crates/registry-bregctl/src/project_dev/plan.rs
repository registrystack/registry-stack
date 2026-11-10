// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use registry_breg::literal_text::{LiteralText, WRITE_THE_VALUE};
use registry_platform_yaml::{
    ApiVersion, BoundedU32, Decoded, EnvelopeRule, Expect, FormatSpec, Identified, LocalId, Reader,
    Report, Severity, UniqueIdList, UniqueList,
};
#[cfg(feature = "schema")]
use registry_platform_yaml::{ExternalId, Url as PlatformUrl};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};
use url::Url as ParsedUrl;

pub(crate) const API_VERSION: &str = "id.registrystack.org/formats/breg/project-dev/v1alpha1";
pub(crate) const KIND: &str = "BRegProjectDev";

pub(crate) const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

#[cfg(feature = "schema")]
pub(crate) fn schema() -> schemars::Schema {
    schemars::schema_for!(Plan)
}

#[cfg(feature = "schema")]
fn keyed_schema<K: schemars::JsonSchema, V: schemars::JsonSchema>(
    generator: &mut schemars::SchemaGenerator,
) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "propertyNames": generator.subschema_for::<K>(),
        "additionalProperties": generator.subschema_for::<V>(),
    })
}

#[cfg(feature = "schema")]
struct DerivedId;

#[cfg(feature = "schema")]
impl schemars::JsonSchema for DerivedId {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "DerivedId".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "maxLength": 64,
            "pattern": "^[a-z][a-z0-9_-]{0,63}(\\.[a-z][a-z0-9_-]{0,63})+$",
            "description": "A dotted development journey step identifier whose segments are local identifiers.",
        })
    }
}

#[cfg(feature = "schema")]
fn step_id_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "anyOf": [
            generator.subschema_for::<LocalId>(),
            generator.subschema_for::<DerivedId>(),
        ],
    })
}

#[cfg(feature = "schema")]
fn capture_map_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let names = schemars::json_schema!({
        "allOf": [
            generator.subschema_for::<ExternalId>(),
            {
                "type": "string",
                "maxLength": 64,
                "pattern": "^[A-Za-z][A-Za-z0-9-]{0,63}$",
            },
        ],
    });
    schemars::json_schema!({
        "type": "object",
        "propertyNames": names,
        "additionalProperties": generator.subschema_for::<Capture>(),
    })
}

#[cfg(feature = "schema")]
fn schema_test_people_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let steps = schemars::json_schema!({
        "type": "object",
        "propertyNames": step_id_schema(generator),
        "additionalProperties": generator.subschema_for::<LocalId>(),
    });
    schemars::json_schema!({
        "type": "object",
        "propertyNames": generator.subschema_for::<LocalId>(),
        "additionalProperties": steps,
    })
}

#[cfg(feature = "schema")]
fn claims_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "propertyNames": generator.subschema_for::<ExternalId>(),
        "additionalProperties": true,
        "x-registry-passthrough": "Claim values are written into the development token as given.",
    })
}

#[cfg(feature = "schema")]
fn scopes_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "array",
        "items": generator.subschema_for::<ExternalId>(),
        "maxItems": 32,
        "uniqueItems": true,
    })
}

#[cfg(feature = "schema")]
fn expected_json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "propertyNames": generator.subschema_for::<ExternalId>(),
        "additionalProperties": true,
        "x-registry-passthrough": "Expected values are compared with the product response at the named JSON pointers.",
    })
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
    #[cfg_attr(feature = "schema", schemars(with = "PlatformUrl"))]
    pub issuer: String,
    pub products: Vec<ProductPlan>,
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<LocalId, TestPerson>")
    )]
    pub people: BTreeMap<String, TestPerson>,
    pub journey: Journey,
    #[serde(default)]
    pub bindings: super::bindings::Bindings,
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "schema_test_people_schema")
    )]
    pub schema_test_people: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct ProductPlan {
    pub product: Product,
    pub project: PathBuf,
    #[cfg_attr(feature = "schema", schemars(with = "ExternalId"))]
    pub audience: String,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct TestPerson {
    #[cfg_attr(feature = "schema", schemars(with = "ExternalId"))]
    pub subject: String,
    #[cfg_attr(feature = "schema", schemars(with = "ExternalId"))]
    pub client: String,
    #[serde(deserialize_with = "deserialize_grants")]
    pub grants: BTreeMap<Product, Grant>,
    /// Forward the same authority to both products. Both grants must declare the same scopes and additional claims.
    #[serde(default, rename = "caseworkContext")]
    pub casework_context: bool,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Grant {
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    pub profile: String,
    #[serde(deserialize_with = "deserialize_scopes")]
    #[cfg_attr(feature = "schema", schemars(schema_with = "scopes_schema"))]
    pub scopes: Vec<String>,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(schema_with = "claims_schema"))]
    pub claims: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantsDocument {
    breg: Option<Grant>,
    casework: Option<Grant>,
}

fn deserialize_grants<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<Product, Grant>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let grants = GrantsDocument::deserialize(deserializer)?;
    Ok([
        grants.breg.map(|grant| (Product::Breg, grant)),
        grants.casework.map(|grant| (Product::Casework, grant)),
    ]
    .into_iter()
    .flatten()
    .collect())
}

fn deserialize_scopes<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    UniqueList::<String>::deserialize(deserializer).map(UniqueList::into_vec)
}

fn deserialize_steps<'de, D>(deserializer: D) -> std::result::Result<Vec<Step>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    UniqueIdList::<Step>::deserialize(deserializer).map(UniqueIdList::into_vec)
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Journey {
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    pub id: String,
    #[serde(deserialize_with = "deserialize_steps")]
    pub steps: Vec<Step>,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Step {
    #[cfg_attr(feature = "schema", schemars(schema_with = "step_id_schema"))]
    pub id: String,
    pub product: Product,
    #[serde(rename = "as")]
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    pub person: String,
    pub method: Method,
    pub path: String,
    pub body: Option<Value>,
    pub raw: Option<RawBody>,
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<ExternalId, String>")
    )]
    pub headers: BTreeMap<String, String>,
    pub expect: Expected,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(schema_with = "capture_map_schema"))]
    pub capture: BTreeMap<String, Capture>,
    pub poll: Option<Poll>,
}

impl Identified for Step {
    fn id(&self) -> &str {
        &self.id
    }
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
    #[cfg_attr(feature = "schema", schemars(schema_with = "expected_json_schema"))]
    pub json: BTreeMap<String, Value>,
    #[serde(default)]
    pub checks: Vec<Check>,
    pub code: Option<String>,
}

#[derive(Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
#[cfg_attr(feature = "schema", schemars(untagged))]
pub(super) enum ExpectedStatus {
    One(BoundedU32<200, 599>),
    Many(Vec<BoundedU32<200, 599>>),
}

registry_platform_yaml::shape_union!(ExpectedStatus {
    scalar => One,
    list => Many,
});

impl ExpectedStatus {
    pub(super) fn first(&self) -> u16 {
        match self {
            Self::One(status) => status.get() as u16,
            Self::Many(statuses) => statuses[0].get() as u16,
        }
    }

    pub(super) fn contains(&self, status: u16) -> bool {
        match self {
            Self::One(expected) => expected.get() == u32::from(status),
            Self::Many(expected) => expected
                .iter()
                .any(|expected| expected.get() == u32::from(status)),
        }
    }

    fn values(&self) -> Vec<u16> {
        match self {
            Self::One(status) => vec![status.get() as u16],
            Self::Many(statuses) => statuses.iter().map(|status| status.get() as u16).collect(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Check {
    pub pointer: String,
    pub equals: Option<Value>,
    #[cfg_attr(feature = "schema", schemars(range(min = 0, max = 1_048_576)))]
    pub length: Option<usize>,
    pub contains: Option<Value>,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Capture {
    Pointer {
        pointer: String,
    },
    Header {
        header: CapturedHeader,
    },
    Find {
        find: String,
        r#where: FindWhere,
        pointer: String,
    },
    Value {
        pointer: String,
        query: Option<String>,
    },
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
pub(super) struct FindWhere {
    pub pointer: String,
    pub equals: Value,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Poll {
    #[serde(rename = "maximumWaitMilliseconds")]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 60_000)))]
    pub timeout_ms: u64,
    #[serde(rename = "pollIntervalMilliseconds")]
    #[cfg_attr(feature = "schema", schemars(range(min = 50, max = 5_000)))]
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
    LocalId::new(value).is_ok()
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

fn read_plan(root: &Path) -> Result<Decoded<Plan>> {
    let file = root.join("dev.yaml");
    let bytes = read(
        &file,
        registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES as u64 + 1,
    )
    .context("cannot read dev.yaml")?;
    Ok(Reader::new(file.display().to_string())
        .with_hook(&mut LiteralText {
            remedy: WRITE_THE_VALUE,
        })
        .decode::<Plan>(&bytes, &Expect::one(&FORMAT))?)
}

fn validate_plan(root: &Path, decoded: &Decoded<Plan>) -> Result<()> {
    if let Err(error) = decoded.value.validate(root) {
        let rendered = error.to_string();
        let path = rendered
            .strip_prefix("dev.yaml ")
            .and_then(|detail| detail.split_once(' '))
            .map_or("", |(path, _)| path);
        let diagnostic = decoded.document.diagnostic_at_value(
            Severity::Error,
            "rstack.dev.invalid-plan",
            path,
            "The development plan is inconsistent.",
            "Correct the named development plan field, then run the check again.",
        );
        return Err(decoded.document.report_with([diagnostic]).into());
    }
    Ok(())
}

pub(crate) fn check(root: &Path) -> Result<Report> {
    let decoded = read_plan(root)?;
    validate_plan(root, &decoded)?;
    Ok(decoded.document.report_with(Vec::new()))
}

pub(super) fn load(root: &Path) -> Result<Plan> {
    let decoded = read_plan(root)?;
    validate_plan(root, &decoded)?;
    Ok(decoded.value)
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
            ParsedUrl::parse(&self.issuer).is_ok_and(|url| {
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
                    Capture::Pointer {
                        pointer: pointer_value,
                    } => require(
                        pointer(pointer_value),
                        &format!("{field}/capture/{name}"),
                        "must use a JSON pointer",
                    )?,
                    Capture::Header { .. } => {}
                    Capture::Value { pointer, query } => {
                        require(
                            self::pointer(pointer),
                            &format!("{field}/capture/{name}/pointer"),
                            "must be a JSON pointer",
                        )?;
                        if let Some(query) = query {
                            require(
                                bounded_atom(query),
                                &format!("{field}/capture/{name}/query"),
                                "must name a bounded query parameter",
                            )?;
                        }
                    }
                    Capture::Find {
                        find,
                        r#where,
                        pointer: selected,
                    } => {
                        require(
                            pointer(find) && pointer(&r#where.pointer) && pointer(selected),
                            &format!("{field}/capture/{name}"),
                            "must use JSON pointers",
                        )?;
                        expand_json(&r#where.equals, |value| {
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
        && (identifier(value) || (value.contains('.') && value.split('.').all(identifier)))
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
                "requestId": {"type": "value", "pointer": "/requestId", "query": "id"},
                "etag": {"type": "header", "header": "etag"},
                "selected-item": {
                    "type": "find",
                    "find": "/items", "where": {"pointer": "/id", "equals": "one"},
                    "pointer": "/value"
                }
            }
        }));
        assert_eq!(plan.journey.steps[0].expect.status.first(), 200);
        assert!(plan.journey.steps[0].expect.status.contains(201));
        assert!(matches!(
            plan.journey.steps[0].capture["etag"],
            Capture::Header { .. }
        ));
        assert!(!plan.people["operator"].casework_context);
    }

    #[test]
    fn validation_accepts_dotted_steps_and_camel_case_captures() {
        let (root, plan) = plan(json!({
            "id": "read.v1", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records",
            "expect": {"status": [200, 202]},
            "capture": {"draftEtag": {"type": "pointer", "pointer": "/recordIdentifier"}},
            "poll": {"maximumWaitMilliseconds": 500, "pollIntervalMilliseconds": 50}
        }));
        let mut value = serde_json::to_value(plan).unwrap();
        let person = value["people"]
            .as_object_mut()
            .unwrap()
            .remove("operator")
            .unwrap();
        value["people"]["date_of_birth"] = person;
        value["people"]["date_of_birth"]["grants"]["breg"]["profile"] = json!("date_of_birth");
        value["journey"]["id"] = json!("review_flow");
        value["journey"]["steps"][0]["as"] = json!("date_of_birth");
        value["journey"]["steps"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": "use.v1", "product": "breg", "as": "date_of_birth",
                "method": "GET", "path": "/v1/records/{{draftEtag}}",
                "expect": {"status": 200}
            }));
        value["schemaTestPeople"] = json!({
            "review_flow": {"read.v1": "date_of_birth"}
        });
        let plan: Plan = serde_json::from_value(value).unwrap();

        plan.validate(&canonical(&root)).unwrap();
    }

    #[test]
    fn identifier_grammars_refuse_values_the_schema_refuses() {
        for accepted in ["date-of-birth", "date_of_birth"] {
            assert!(identifier(accepted), "local identifier: {accepted}");
        }
        for refused in ["-person", "1person", "Person", "person.name"] {
            assert!(!identifier(refused), "local identifier: {refused}");
        }

        for accepted in ["read", "read_v1", "read.v1", "read_record.v1_beta"] {
            assert!(step_identifier(accepted), "step identifier: {accepted}");
        }
        for refused in [
            "-read", "1read", ".read", "read.", "read..v1", "read.-v1", "Read.v1",
        ] {
            assert!(!step_identifier(refused), "step identifier: {refused}");
        }

        for accepted in ["draftEtag", "DraftEtag", "draft-etag"] {
            assert!(
                capture_identifier(accepted),
                "capture identifier: {accepted}"
            );
        }
        for refused in ["1draft", "draft_etag", "draft.etag"] {
            assert!(
                !capture_identifier(refused),
                "capture identifier: {refused}"
            );
        }
    }

    #[test]
    fn validation_refuses_a_product_project_outside_the_development_project() {
        let (root, mut plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        plan.products[0].project = PathBuf::from("../outside");

        let error = plan.validate(&canonical(&root)).unwrap_err().to_string();

        assert!(error.contains("/products/0/project"), "{error}");
    }

    #[test]
    fn validation_refuses_a_product_project_link_outside_the_development_project() {
        let (root, mut plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("registry.yaml"), "fixture").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("registry")).unwrap();
        plan.products[0].project = PathBuf::from("registry");

        let error = plan.validate(&canonical(&root)).unwrap_err().to_string();

        assert!(error.contains("/products/0/project"), "{error}");
    }

    #[test]
    fn validation_refuses_polling_a_mutation() {
        let (root, plan) = plan(json!({
            "id": "create", "product": "breg", "as": "operator",
            "method": "POST", "path": "/v1/records", "body": {},
            "expect": {"status": 201},
            "poll": {"maximumWaitMilliseconds": 500, "pollIntervalMilliseconds": 50}
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
            "capture": {"later": {"type": "pointer", "pointer": "/recordIdentifier"}}
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
            "poll": {"maximumWaitMilliseconds": 30000, "pollIntervalMilliseconds": 50}
        }));
        let error = plan.validate(&canonical(&root)).unwrap_err().to_string();
        assert!(error.contains("at most 250 attempts"), "{error}");
    }

    #[test]
    fn validation_accepts_the_studio_review_poll() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200},
            "poll": {"maximumWaitMilliseconds": 60000, "pollIntervalMilliseconds": 250}
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
                    "id": "registry", "identity": "context-reader", "action": "review-record"
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

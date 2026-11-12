// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use registry_breg::literal_text::{LiteralText, WRITE_THE_VALUE};
use registry_platform_yaml::{
    escape_pointer_segment, ApiVersion, BoundedU32, Decoded, EnvelopeRule, Expect, FormatSpec,
    Identified, LocalId, Reader, Report, Severity, UniqueIdList, UniqueList,
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

/// A product the development run can start.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub(super) enum Product {
    Breg,
    Casework,
    Messaging,
}

impl Product {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Breg => "breg",
            Self::Casework => "casework",
            Self::Messaging => "messaging",
        }
    }
}

/// The development plan: the products to start, the test people who call them, and the journey to run.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Plan {
    /// HTTPS URL, at most 512 characters and without credentials, query or fragment, that the run's tokens name as their issuer.
    #[cfg_attr(feature = "schema", schemars(with = "PlatformUrl"))]
    pub issuer: String,
    /// The products to start, each with its project directory and token audience. List each product at most once.
    pub products: Vec<ProductPlan>,
    /// The test people, keyed by a lowercase local identifier. Define 1 to 32, and give at least one grant to every started product.
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<LocalId, TestPerson>")
    )]
    pub people: BTreeMap<String, TestPerson>,
    /// Service workload bindings whose short-lived credentials the live run owns and rotates.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<LocalId, Workload>")
    )]
    pub workloads: BTreeMap<String, Workload>,
    /// Explicit local person-picker services. Omit this map for normal production-style connections.
    #[serde(default)]
    pub development_pickers: DevelopmentPickers,
    /// The ordered sequence of HTTP requests the run sends to the started products.
    pub journey: Journey,
    /// Run-local connections between BReg and Casework. Leave empty when the products do not call each other.
    #[serde(default)]
    pub bindings: super::bindings::Bindings,
    /// Chooses the test person for a BReg fixture step in tests/journeys.yaml, keyed by journey identifier and then step identifier. Needed only when several people could run the step; every named person needs a BReg grant.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "schema_test_people_schema")
    )]
    pub schema_test_people: BTreeMap<String, BTreeMap<String, String>>,
}

/// One product to start and where its project lives.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct ProductPlan {
    /// Which product to start.
    pub product: Product,
    /// Relative path from the plan's directory to the product project, or `.` for the plan's own directory. It must contain registry.yaml for BReg, casework.yaml for Casework, or messaging.yaml for Messaging.
    pub project: PathBuf,
    /// Token audience this product accepts: 1 to 256 characters without whitespace or control characters, distinct from the other products' audiences.
    #[cfg_attr(feature = "schema", schemars(with = "ExternalId"))]
    pub audience: String,
}

/// A named test identity that signs in to the started products.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct TestPerson {
    /// Subject claim of this person's tokens: 1 to 256 characters without whitespace or control characters.
    #[cfg_attr(feature = "schema", schemars(with = "ExternalId"))]
    pub subject: String,
    /// Client identifier of this person's tokens: 1 to 256 characters without whitespace or control characters.
    #[cfg_attr(feature = "schema", schemars(with = "ExternalId"))]
    pub client: String,
    /// The authority this person holds in each product, keyed by `breg`, `casework`, or `messaging`. Give at least one grant, only for products listed in `products`.
    #[serde(deserialize_with = "deserialize_grants")]
    pub grants: BTreeMap<Product, Grant>,
    /// Forward the same authority to both products. Both grants must declare the same scopes and additional claims.
    #[serde(default, rename = "caseworkContext")]
    pub casework_context: bool,
}

/// The authority a test person or service workload holds in one product.
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Grant {
    /// Local identifier of the product profile this grant uses.
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    pub profile: String,
    /// Distinct scopes written into the token, at most 32, each 1 to 256 characters without whitespace or control characters.
    #[serde(deserialize_with = "deserialize_scopes")]
    #[cfg_attr(feature = "schema", schemars(schema_with = "scopes_schema"))]
    pub scopes: Vec<String>,
    /// Additional token claims, keyed by claim name. Names must not be reserved token claims such as `iss`, `aud`, `sub`, `scope` or any `registry_grant_` claim.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(schema_with = "claims_schema"))]
    pub claims: Map<String, Value>,
}

/// One runner-owned service identity and its fixed product authority.
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Workload {
    /// Product this binding calls. Generated workload connections support BReg and Messaging.
    pub product: Product,
    /// Whether this is the generated connection's default binding for its product.
    pub default: bool,
    /// Stable subject claim preserved across token generations.
    #[cfg_attr(feature = "schema", schemars(with = "ExternalId"))]
    pub subject: String,
    /// Stable client identifier preserved across token generations.
    #[cfg_attr(feature = "schema", schemars(with = "ExternalId"))]
    pub client: String,
    /// Fixed profile, scopes and additional claims for this binding.
    pub grant: Grant,
}

/// The two deliberately separate local browser personas a development run may expose.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum PickerPersona {
    Holder,
    Staff,
}

impl PickerPersona {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Holder => "holder",
            Self::Staff => "staff",
        }
    }
}

/// Optional local picker services. Holder and staff keep distinct origins and cookies.
#[derive(Default, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct DevelopmentPickers {
    /// A holder-only local admission simulation.
    pub holder: Option<DevelopmentPicker>,
    /// A staff-only local admission simulation.
    pub staff: Option<DevelopmentPicker>,
}

impl DevelopmentPickers {
    pub(super) fn iter(&self) -> impl Iterator<Item = (PickerPersona, &DevelopmentPicker)> {
        [
            (PickerPersona::Holder, self.holder.as_ref()),
            (PickerPersona::Staff, self.staff.as_ref()),
        ]
        .into_iter()
        .filter_map(|(persona, picker)| picker.map(|picker| (persona, picker)))
    }

    pub(super) fn is_empty(&self) -> bool {
        self.holder.is_none() && self.staff.is_none()
    }
}

/// One runner-generated loopback picker and exactly the authority it may expose.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DevelopmentPicker {
    /// Test-person aliases eligible for this persona. The browser receives opaque selectors instead.
    pub people: Vec<String>,
    /// Complete person credential set required before a picker session opens.
    pub person_products: Vec<Product>,
    /// Service workload bindings available to this picker-backed application.
    #[serde(default)]
    pub workloads: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantsDocument {
    breg: Option<Grant>,
    casework: Option<Grant>,
    messaging: Option<Grant>,
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
        grants.messaging.map(|grant| (Product::Messaging, grant)),
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

/// An ordered list of requests the run sends and checks.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Journey {
    /// Local identifier naming this journey.
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    pub id: String,
    /// The steps, run in order. Include 1 to 32 with distinct identifiers. A step may refer to captures from earlier steps only.
    #[serde(deserialize_with = "deserialize_steps")]
    pub steps: Vec<Step>,
}

/// One HTTP request, what to expect back, and what to remember from the response.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Step {
    /// Unique step identifier: a local identifier, or a dotted sequence of local identifiers, at most 64 characters.
    #[cfg_attr(feature = "schema", schemars(schema_with = "step_id_schema"))]
    pub id: String,
    /// The product that receives the request.
    pub product: Product,
    /// The test person who sends the request. The person needs a grant for this step's product.
    #[serde(rename = "as")]
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    pub person: String,
    /// The HTTP method.
    pub method: Method,
    /// Request path, starting with `/v1/`, at most 2048 characters, without whitespace, control characters, backslashes or fragments. It may contain `{{name}}` references to earlier captures.
    pub path: String,
    /// JSON request body, at most 1 MiB once encoded. String values may contain `{{name}}` references to earlier captures. Do not combine with `raw`.
    pub body: Option<Value>,
    /// Non-JSON request body. Allowed only for methods other than GET. Do not combine with `body`.
    pub raw: Option<RawBody>,
    /// Extra request headers, keyed by header name. Only `If-Match`, `Idempotency-Key` and `Registry-Source-Profile` are supported. Values may contain `{{name}}` references to earlier captures.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<ExternalId, String>")
    )]
    pub headers: BTreeMap<String, String>,
    /// What the response must look like for the step to pass.
    pub expect: Expected,
    /// Values to remember from the response, keyed by a capture name. Later steps refer to a capture as `{{name}}` in paths, headers, bodies and expectations. Names are unique across the journey.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(schema_with = "capture_map_schema"))]
    pub capture: BTreeMap<String, Capture>,
    /// Repeat a GET request until it passes or the wait runs out. Allowed only for GET.
    pub poll: Option<Poll>,
}

impl Identified for Step {
    fn id(&self) -> &str {
        &self.id
    }
}

/// An HTTP request method.
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

/// The conditions a response must meet.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Expected {
    /// Accepted HTTP status: one status, or a list of 1 to 16 distinct statuses, each from 200 to 599.
    pub status: ExpectedStatus,
    /// Exact values the response body must hold, keyed by JSON pointer (empty for the whole body, otherwise starting with `/`). String values may contain `{{name}}` references to earlier captures.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(schema_with = "expected_json_schema"))]
    pub json: BTreeMap<String, Value>,
    /// Further assertions about the response body, at most 32. Each one tests a single JSON pointer.
    #[serde(default)]
    pub checks: Vec<Check>,
    /// Problem code the error response must carry, 1 to 256 characters without whitespace or control characters. It may contain `{{name}}` references to earlier captures.
    pub code: Option<String>,
}

/// One accepted HTTP status or a list of them.
#[derive(Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
#[cfg_attr(feature = "schema", schemars(untagged))]
pub(super) enum ExpectedStatus {
    /// A single accepted status from 200 to 599.
    One(BoundedU32<200, 599>),
    /// Several accepted statuses, each from 200 to 599; the response may carry any one of them.
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

/// An assertion about one value in the response body. Set exactly one of `equals`, `length` or `contains`.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Check {
    /// JSON pointer to the value to test: empty for the whole body, otherwise starting with `/`.
    pub pointer: String,
    /// The value at the pointer must equal this. String values may contain `{{name}}` references to earlier captures.
    pub equals: Option<Value>,
    /// The array, object or string at the pointer must have this many items, entries or characters, at most 1048576.
    #[cfg_attr(feature = "schema", schemars(range(min = 0, max = 1_048_576)))]
    pub length: Option<usize>,
    /// The array at the pointer must hold this item, the string must contain this text, or the object must have this key. String values may contain `{{name}}` references to earlier captures.
    pub contains: Option<Value>,
}

/// A value remembered from a response, selected by `type`.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Capture {
    /// Remember the value at a JSON pointer in the response body.
    Pointer {
        /// JSON pointer into the response body: empty for the whole body, otherwise starting with `/`.
        pointer: String,
    },
    /// Remember a response header.
    Header {
        /// The response header to remember.
        header: CapturedHeader,
    },
    /// Remember a value from the one array item that matches a condition. The step fails if no item or more than one item matches.
    Find {
        /// JSON pointer to the array in the response body to search.
        find: String,
        /// The condition an item must meet.
        r#where: FindWhere,
        /// JSON pointer, relative to the matching item, of the value to remember.
        pointer: String,
    },
    /// Remember the value at a JSON pointer, optionally reading one query parameter from a URL found there.
    Value {
        /// JSON pointer into the response body: empty for the whole body, otherwise starting with `/`.
        pointer: String,
        /// Name of a query parameter. When set, the value at the pointer must be a URL or relative reference, and the parameter's value is remembered instead. At most 256 characters without whitespace or control characters.
        query: Option<String>,
    },
}

/// A response header a capture can remember.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub(super) enum CapturedHeader {
    /// The entity tag, usable as an `If-Match` value in a later step.
    Etag,
}

/// The condition a `find` capture uses to pick an array item.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct FindWhere {
    /// JSON pointer, relative to each array item, of the value to compare.
    pub pointer: String,
    /// The value an item must hold at the pointer to match. String values may contain `{{name}}` references to earlier captures.
    pub equals: Value,
}

/// How long and how often to repeat a GET request. The wait divided by the interval, rounded up, must be below 250 attempts.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Poll {
    /// Longest total wait in milliseconds, from 1 to 60000.
    #[serde(rename = "maximumWaitMilliseconds")]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 60_000)))]
    pub timeout_ms: u64,
    /// Pause between attempts in milliseconds, from 50 to 5000 and not above the maximum wait.
    #[serde(rename = "pollIntervalMilliseconds")]
    #[cfg_attr(feature = "schema", schemars(range(min = 50, max = 5_000)))]
    pub interval_ms: u64,
}

/// A request body sent as given, without JSON encoding.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RawBody {
    /// HTTP media type for the Content-Type header, containing a slash, 1 to 256 ASCII characters.
    pub content_type: String,
    /// The body as standard base64, at most 1 MiB once decoded.
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

#[derive(Debug, thiserror::Error)]
#[error("dev.yaml {field}: {reason} Next: {remedy}")]
pub(super) struct SemanticRefusal {
    field: String,
    reason: String,
    remedy: String,
}

impl SemanticRefusal {
    pub(super) fn new(
        field: impl Into<String>,
        reason: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
            remedy: remedy.into(),
        }
    }
}

pub(super) type SemanticResult<T> = std::result::Result<T, SemanticRefusal>;

pub(super) fn require(
    condition: bool,
    field: &str,
    reason: impl Into<String>,
    remedy: impl Into<String>,
) -> SemanticResult<()> {
    if !condition {
        return Err(SemanticRefusal::new(field, reason, remedy));
    }
    Ok(())
}

pub(super) fn refuse<T>(field: &str, reason: &str, remedy: &str) -> SemanticResult<T> {
    Err(SemanticRefusal::new(field, reason, remedy))
}

#[derive(Debug, thiserror::Error)]
#[error("capture reference must name an earlier capture")]
struct EarlierCapture;

fn validate_expansion<T>(result: Result<T>, field: &str) -> SemanticResult<T> {
    match result {
        Ok(value) => Ok(value),
        Err(error) if error.downcast_ref::<EarlierCapture>().is_some() => refuse(
            field,
            "The capture reference must name an earlier capture.",
            "Move the referenced capture to an earlier step or correct the capture name.",
        ),
        Err(_) => refuse(
            field,
            "The field has an unclosed capture reference.",
            "Close the capture reference with `}}`.",
        ),
    }
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

fn refusal_report(decoded: &Decoded<Plan>, refusal: &SemanticRefusal) -> Report {
    let diagnostic = decoded.document.diagnostic_at_value(
        Severity::Error,
        "breg.project-dev.invalid-plan",
        &refusal.field,
        &refusal.reason,
        &refusal.remedy,
    );
    decoded.document.report_with([diagnostic])
}

fn validate_plan(root: &Path, decoded: &Decoded<Plan>) -> Result<()> {
    decoded
        .value
        .validate(root)
        .map_err(|refusal| refusal_report(decoded, &refusal).into())
}

pub(crate) fn check(root: &Path) -> Result<Report> {
    let decoded = read_plan(root)?;
    validate_plan(root, &decoded)?;
    if let Err(refusal) = super::products::schema_people(root, &decoded.value, false) {
        return Err(refusal_report(&decoded, &refusal).into());
    }
    let terminate = super::signals()?;
    if let Err(error) = super::products::inspect(root, &decoded.value, &terminate) {
        return match error.downcast::<SemanticRefusal>() {
            Ok(refusal) => Err(refusal_report(&decoded, &refusal).into()),
            Err(error) => Err(error),
        };
    }
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

    fn validate(&self, root: &Path) -> SemanticResult<()> {
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
            "The issuer must be the project's bounded HTTPS URL without credentials, query, or fragment.",
            "Set issuer to an HTTPS URL with a host and no credentials, query, or fragment.",
        )?;
        require(
            !self.products.is_empty(),
            "/products",
            "The plan must name at least one product.",
            "Add a BReg, Casework, or Messaging product to products.",
        )?;
        let mut products = BTreeSet::new();
        let mut audiences = BTreeSet::new();
        for (index, entry) in self.products.iter().enumerate() {
            let field = format!("/products/{index}");
            require(
                products.insert(entry.product),
                &format!("{field}/product"),
                "The product is repeated.",
                "Remove the duplicate product entry.",
            )?;
            require(
                bounded_atom(&entry.audience) && audiences.insert(&entry.audience),
                &format!("{field}/audience"),
                "The audience must be distinct, bounded text without whitespace or control characters.",
                "Set audience to a distinct identifier of at most 256 characters without whitespace or control characters.",
            )?;
            require(
                entry.project == Path::new(".")
                    || (!entry.project.as_os_str().is_empty()
                        && entry
                            .project
                            .components()
                            .all(|part| matches!(part, Component::Normal(_)))),
                &format!("{field}/project"),
                "The product project must be a relative path inside the development project directory.",
                "Set project to `.` or a relative path made only of normal path components.",
            )?;
            let manifest = match entry.product {
                Product::Breg => "registry.yaml",
                Product::Casework => "casework.yaml",
                Product::Messaging => "messaging.yaml",
            };
            require(
                root.join(&entry.project)
                    .join(manifest)
                    .canonicalize()
                    .is_ok_and(|path| path.starts_with(root) && path.is_file()),
                &format!("{field}/project"),
                format!("The product project must contain {manifest} inside the development project directory."),
                format!("Create {manifest} at this project path inside the development project directory."),
            )?;
        }
        require(
            (1..=32).contains(&self.people.len()),
            "/people",
            "The plan must define 1 to 32 test people.",
            "Add or remove test people until people contains between 1 and 32 entries.",
        )?;
        for (name, person) in &self.people {
            require(
                identifier(name),
                "/people",
                "A test person name is not a local identifier.",
                "Rename the test person with a lowercase local identifier of at most 64 characters.",
            )?;
            let field = format!("/people/{name}");
            require(
                bounded_atom(&person.subject),
                &format!("{field}/subject"),
                "The test person's subject must be bounded text without whitespace or control characters.",
                "Set subject to at most 256 characters without whitespace or control characters.",
            )?;
            require(
                bounded_atom(&person.client),
                &format!("{field}/client"),
                "The test person's client must be a bounded client identifier.",
                "Set client to at most 256 characters without whitespace or control characters.",
            )?;
            require(
                !person.grants.is_empty(),
                &format!("{field}/grants"),
                "The test person must have at least one product grant.",
                "Add a BReg, Casework, or Messaging grant for this test person.",
            )?;
            for (product, grant) in &person.grants {
                let field = format!("{field}/grants/{}", product.name());
                require(
                    products.contains(product),
                    &field,
                    "The grant names a product that is not started.",
                    "Add the grant's product to products, or remove this grant.",
                )?;
                validate_grant(grant, &field)?;
            }
            if person.casework_context {
                require(
                    self.bindings.casework_context_provider.is_some(),
                    &format!("{field}/caseworkContext"),
                    "Casework context forwarding requires /bindings/caseworkContextProvider.",
                    "Configure bindings.caseworkContextProvider or remove caseworkContext from this person.",
                )?;
                let breg = person.grants.get(&Product::Breg);
                let casework = person.grants.get(&Product::Casework);
                require(
                    breg.is_some() && casework.is_some(),
                    &format!("{field}/caseworkContext"),
                    "Casework context forwarding requires both BReg and Casework grants.",
                    "Add both product grants to this person or remove caseworkContext.",
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
                    "Casework context forwarding requires the same scopes and additional claims in both grants.",
                    "Make the BReg and Casework grant scopes and additional claims identical.",
                )?;
            }
        }
        let mut workload_products = BTreeSet::new();
        let mut workload_defaults = BTreeMap::<Product, usize>::new();
        for (name, workload) in &self.workloads {
            let escaped = escape_pointer_segment(name);
            let field = format!("/workloads/{escaped}");
            require(
                identifier(name),
                "/workloads",
                "A workload binding name is not a local identifier.",
                "Rename the workload binding with a lowercase local identifier of at most 64 characters.",
            )?;
            require(
                matches!(workload.product, Product::Breg | Product::Messaging)
                    && products.contains(&workload.product),
                &format!("{field}/product"),
                "The workload binding must name a started product supported by the generated Python connection.",
                "Use a started BReg or Messaging product, or remove this workload binding.",
            )?;
            require(
                bounded_atom(&workload.subject),
                &format!("{field}/subject"),
                "The workload subject must be bounded text without whitespace or control characters.",
                "Set subject to at most 256 characters without whitespace or control characters.",
            )?;
            require(
                bounded_atom(&workload.client),
                &format!("{field}/client"),
                "The workload client must be a bounded client identifier.",
                "Set client to at most 256 characters without whitespace or control characters.",
            )?;
            let grant_field = format!("{field}/grant");
            validate_grant(&workload.grant, &grant_field)?;
            require(
                !workload.grant.scopes.is_empty()
                    && workload.grant.scopes.iter().all(|scope| scope.len() <= 128),
                &format!("{grant_field}/scopes"),
                "A generated Python workload needs one to 32 scopes of at most 128 characters.",
                "Add the exact workload scopes and keep each scope within 128 characters.",
            )?;
            workload_products.insert(workload.product);
            if workload.default {
                *workload_defaults.entry(workload.product).or_default() += 1;
            }
        }
        for product in workload_products {
            require(
                workload_defaults.get(&product) == Some(&1),
                "/workloads",
                format!(
                    "The generated connection needs exactly one default workload binding for {}.",
                    product.name()
                ),
                format!(
                    "Mark exactly one {} workload binding as default.",
                    product.name()
                ),
            )?;
        }
        let mut picker_people = BTreeSet::new();
        for (persona, picker) in self.development_pickers.iter() {
            let field = format!("/developmentPickers/{}", persona.name());
            let people = picker.people.iter().collect::<BTreeSet<_>>();
            require(
                (1..=32).contains(&picker.people.len()) && people.len() == picker.people.len(),
                &format!("{field}/people"),
                "A development picker needs 1 to 32 distinct test people.",
                "Name each eligible test person exactly once.",
            )?;
            for person in &picker.people {
                require(
                    self.people.contains_key(person),
                    &format!("{field}/people"),
                    "A development picker names an unknown test person.",
                    "Name a test person declared in people.",
                )?;
                require(
                    picker_people.insert(person),
                    &format!("{field}/people"),
                    "One test person cannot be eligible for both local picker personas.",
                    "Use separate synthetic test people for holder and staff services.",
                )?;
            }
            let person_products = picker.person_products.iter().collect::<BTreeSet<_>>();
            require(
                !picker.person_products.is_empty()
                    && person_products.len() == picker.person_products.len(),
                &format!("{field}/personProducts"),
                "A development picker needs a distinct nonempty person product set.",
                "List every product grant required before the local session opens.",
            )?;
            for product in &picker.person_products {
                require(
                    matches!(product, Product::Breg | Product::Casework)
                        && products.contains(product),
                    &format!("{field}/personProducts"),
                    "A development picker person product must be a started BReg or Casework product.",
                    "Use BReg and Casework person grants; keep Messaging authority in a declared service workload.",
                )?;
                for person in &picker.people {
                    require(
                        self.people[person].grants.contains_key(product),
                        &format!("{field}/people"),
                        format!(
                            "Test person {person} lacks the complete {} grant required by this picker.",
                            product.name()
                        ),
                        "Add the declared product grant or remove this person from the picker.",
                    )?;
                }
            }
            let picker_workloads = picker.workloads.iter().collect::<BTreeSet<_>>();
            require(
                picker.workloads.len() <= 32 && picker_workloads.len() == picker.workloads.len(),
                &format!("{field}/workloads"),
                "A development picker may name at most 32 distinct workload bindings.",
                "Remove duplicate or excess workload binding names.",
            )?;
            require(
                picker_workloads
                    == self.workloads.keys().collect::<BTreeSet<_>>(),
                &format!("{field}/workloads"),
                "A development picker must explicitly bind the complete runner workload set.",
                "List every runner-owned workload binding, or remove workloads not intended for this local service.",
            )?;
            for workload in &picker.workloads {
                require(
                    self.workloads.contains_key(workload),
                    &format!("{field}/workloads"),
                    "A development picker names an unknown workload binding.",
                    "Name a runner-owned binding declared in workloads.",
                )?;
            }
        }
        for (journey, steps) in &self.schema_test_people {
            for (step, person) in steps {
                let field = format!(
                    "/schemaTestPeople/{}/{}",
                    escape_pointer_segment(journey),
                    escape_pointer_segment(step)
                );
                require(
                    self.people
                        .get(person)
                        .is_some_and(|person| person.grants.contains_key(&Product::Breg)),
                    &field,
                    "The schema test assignment must name a person with a BReg grant.",
                    "Set this assignment to a test person that has a BReg grant.",
                )?;
            }
        }
        for product in products {
            require(
                self.people
                    .values()
                    .any(|person| person.grants.contains_key(&product)),
                "/people",
                format!(
                    "The plan must define at least one grant for {}.",
                    product.name()
                ),
                format!(
                    "Add a {} grant to at least one test person.",
                    product.name()
                ),
            )?;
        }
        self.bindings.validate(self)?;
        self.journey.validate(self)
    }
}

fn validate_grant(grant: &Grant, field: &str) -> SemanticResult<()> {
    require(
        identifier(&grant.profile),
        &format!("{field}/profile"),
        "The grant profile must be a local identifier.",
        "Set profile to a lowercase local identifier of at most 64 characters.",
    )?;
    let scopes = grant.scopes.iter().collect::<BTreeSet<_>>();
    require(
        scopes.len() == grant.scopes.len()
            && scopes.len() <= 32
            && scopes.iter().all(|scope| bounded_atom(scope)),
        &format!("{field}/scopes"),
        "The grant must contain at most 32 distinct bounded scopes.",
        "Remove duplicate or excess scopes, and keep each scope within 256 characters without whitespace or control characters.",
    )?;
    for claim in grant.claims.keys() {
        require(
            bounded_atom(claim) && !reserved_claim(claim),
            &format!("{field}/claims"),
            "The grant contains a reserved or invalid additional claim name.",
            "Remove the claim or rename it to bounded text that is not reserved by the token contract.",
        )?;
    }
    Ok(())
}

impl Journey {
    fn validate(&self, plan: &Plan) -> SemanticResult<()> {
        require(
            identifier(&self.id),
            "/journey/id",
            "The journey ID must be a local identifier.",
            "Set id to a lowercase local identifier of at most 64 characters.",
        )?;
        require(
            (1..=32).contains(&self.steps.len()),
            "/journey/steps",
            "The journey must contain 1 to 32 steps.",
            "Add or remove steps until the journey contains between 1 and 32 steps.",
        )?;
        let mut ids = BTreeSet::new();
        let mut captures = BTreeSet::new();
        for (index, step) in self.steps.iter().enumerate() {
            let field = format!("/journey/steps/{index}");
            require(
                step_identifier(&step.id) && ids.insert(&step.id),
                &format!("{field}/id"),
                "The step ID must be a unique local or dotted derived identifier.",
                "Set id to a unique lowercase local identifier or dotted sequence of local identifiers.",
            )?;
            require(
                plan.people
                    .get(&step.person)
                    .is_some_and(|person| person.grants.contains_key(&step.product)),
                &format!("{field}/as"),
                "The step must name a test person with a grant for its product.",
                "Set as to a test person that has a grant for this step's product.",
            )?;
            require(
                valid_path(&step.path),
                &format!("{field}/path"),
                "The request path must be a relative product API path starting with /v1/.",
                "Set path to a bounded /v1/ path without whitespace, control characters, backslashes, or fragments.",
            )?;
            let statuses = step.expect.status.values();
            require(
                (1..=16).contains(&statuses.len())
                    && statuses.iter().all(|status| (200..=599).contains(status))
                    && statuses.iter().collect::<BTreeSet<_>>().len() == statuses.len(),
                &format!("{field}/expect/status"),
                "Expected status must contain 1 to 16 distinct HTTP statuses from 200 to 599.",
                "List between 1 and 16 distinct HTTP status numbers from 200 to 599.",
            )?;
            require(
                step.body.is_none() || step.raw.is_none(),
                &field,
                "A journey step must not contain both body and raw.",
                "Remove body or raw so the step declares only one request body form.",
            )?;
            require(
                step.raw.is_none() || !matches!(step.method, Method::Get),
                &format!("{field}/raw"),
                "A raw request body is supported only for non-GET requests.",
                "Remove raw or change method to a non-GET request method.",
            )?;
            if let Some(body) = &step.body {
                require(
                    serde_json::to_vec(body).is_ok_and(|bytes| bytes.len() <= 1024 * 1024),
                    &format!("{field}/body"),
                    "The JSON request body must encode to at most 1 MiB.",
                    "Reduce body until its encoded JSON is at most 1 MiB.",
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
                    "The raw content type must be a bounded ASCII HTTP media type.",
                    "Set contentType to an ASCII media type with a slash and at most 256 characters.",
                )?;
                require(
                    raw.base64.len() <= 1_398_104
                        && BASE64
                            .decode(&raw.base64)
                            .is_ok_and(|bytes| bytes.len() <= 1024 * 1024),
                    &format!("{field}/raw/base64"),
                    "The raw body must be valid base64 encoding of at most 1 MiB.",
                    "Encode at most 1 MiB of raw request data as base64.",
                )?;
            }
            if let Some(poll) = &step.poll {
                require(
                    matches!(step.method, Method::Get),
                    &format!("{field}/poll"),
                    "Polling is supported only for GET requests.",
                    "Remove poll or change method to GET.",
                )?;
                require(
                    (1..=60_000).contains(&poll.timeout_ms)
                        && (50..=5_000).contains(&poll.interval_ms)
                        && poll.timeout_ms.div_ceil(poll.interval_ms) < 250,
                    &format!("{field}/poll"),
                    "Polling must use a 1 to 60000 ms maximum wait, a 50 to 5000 ms interval, and at most 250 attempts.",
                    "Set maximumWaitMilliseconds and pollIntervalMilliseconds within those bounds and limit the resulting attempts to at most 250.",
                )?;
                require(
                    poll.interval_ms <= poll.timeout_ms,
                    &format!("{field}/poll/pollIntervalMilliseconds"),
                    "The poll interval must not exceed the maximum wait.",
                    "Set pollIntervalMilliseconds to no more than maximumWaitMilliseconds.",
                )?;
            }
            for header in step.headers.keys() {
                require(
                    matches!(
                        header.as_str(),
                        "If-Match" | "Idempotency-Key" | "Registry-Source-Profile"
                    ),
                    &format!("{field}/headers"),
                    "The request contains a header outside the supported list.",
                    "Remove the header or use only If-Match, Idempotency-Key, or Registry-Source-Profile.",
                )?;
            }
            let verify_reference = |value: &str| {
                captures
                    .contains(value)
                    .then(|| value.to_owned())
                    .ok_or_else(|| EarlierCapture.into())
            };
            validate_expansion(
                expand(&step.path, verify_reference),
                &format!("{field}/path"),
            )?;
            for value in step.headers.values() {
                validate_expansion(expand(value, verify_reference), &format!("{field}/headers"))?;
            }
            if let Some(body) = &step.body {
                validate_expansion(
                    expand_json(body, verify_reference),
                    &format!("{field}/body"),
                )?;
            }
            require(
                step.expect.json.keys().all(|value| pointer(value)),
                &format!("{field}/expect/json"),
                "Expected JSON keys must be JSON pointers.",
                "Replace each expected JSON key with an empty pointer or one starting with `/`.",
            )?;
            for value in step.expect.json.values() {
                validate_expansion(
                    expand_json(value, verify_reference),
                    &format!("{field}/expect/json"),
                )?;
            }
            require(
                step.expect.checks.len() <= 32,
                &format!("{field}/expect/checks"),
                "Expected checks must contain at most 32 entries.",
                "Remove checks until at most 32 remain.",
            )?;
            for check in &step.expect.checks {
                require(
                    pointer(&check.pointer),
                    &format!("{field}/expect/checks"),
                    "Each expected check must use a JSON pointer.",
                    "Set each check pointer to an empty pointer or one starting with `/`.",
                )?;
                require(
                    usize::from(check.equals.is_some())
                        + usize::from(check.length.is_some())
                        + usize::from(check.contains.is_some())
                        == 1,
                    &format!("{field}/expect/checks"),
                    "Each expected check must contain exactly one of equals, length, or contains.",
                    "Keep exactly one assertion member in each expected check.",
                )?;
                require(
                    check.length.is_none_or(|length| length <= 1024 * 1024),
                    &format!("{field}/expect/checks"),
                    "An expected length exceeds 1 MiB.",
                    "Set length to at most 1048576.",
                )?;
                for value in check.equals.iter().chain(&check.contains) {
                    validate_expansion(
                        expand_json(value, verify_reference),
                        &format!("{field}/expect/checks"),
                    )?;
                }
            }
            if let Some(code) = &step.expect.code {
                require(
                    bounded_atom(code),
                    &format!("{field}/expect/code"),
                    "The expected problem code must be bounded text without whitespace or control characters.",
                    "Set code to at most 256 characters without whitespace or control characters.",
                )?;
                validate_expansion(
                    expand(code, verify_reference),
                    &format!("{field}/expect/code"),
                )?;
            }
            for (name, capture) in &step.capture {
                require(
                    capture_identifier(name) && !captures.contains(name.as_str()),
                    &format!("{field}/capture"),
                    "Capture names must be unique bounded ASCII identifiers.",
                    "Rename the capture with a unique identifier of at most 64 ASCII letters, digits, or hyphens, starting with a letter.",
                )?;
                match capture {
                    Capture::Pointer {
                        pointer: pointer_value,
                    } => require(
                        pointer(pointer_value),
                        &format!("{field}/capture/{name}"),
                        "The capture must use a JSON pointer.",
                        "Set pointer to an empty pointer or one starting with `/`.",
                    )?,
                    Capture::Header { .. } => {}
                    Capture::Value { pointer, query } => {
                        require(
                            self::pointer(pointer),
                            &format!("{field}/capture/{name}/pointer"),
                            "The value capture pointer must be a JSON pointer.",
                            "Set pointer to an empty pointer or one starting with `/`.",
                        )?;
                        if let Some(query) = query {
                            require(
                                bounded_atom(query),
                                &format!("{field}/capture/{name}/query"),
                                "The value capture query must name a bounded query parameter.",
                                "Set query to at most 256 characters without whitespace or control characters.",
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
                            "The find capture must use JSON pointers.",
                            "Set find, where.pointer, and pointer to empty pointers or pointers starting with `/`.",
                        )?;
                        validate_expansion(
                            expand_json(&r#where.equals, |value| {
                                captures
                                    .contains(value)
                                    .then(|| value.to_owned())
                                    .ok_or_else(|| EarlierCapture.into())
                            }),
                            &format!("{field}/capture/{name}/find"),
                        )?;
                    }
                }
            }
            // A step's captures are all read from its own response, so they
            // become available only to later steps.
            captures.extend(step.capture.keys().cloned());
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
    fn workload_bindings_declare_service_authority_without_a_key_or_token() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        let mut value = serde_json::to_value(plan).unwrap();
        value["workloads"] = json!({
            "registry": {
                "product": "breg", "default": true,
                "subject": "licensing-service", "client": "licensing-service",
                "grant": {
                    "profile": "operator", "scopes": ["registry:read"],
                    "claims": {"registry_actor_kind": "service"}
                }
            }
        });
        let plan: Plan = serde_json::from_value(value).unwrap();

        plan.validate(&canonical(&root)).unwrap();
        let binding = &plan.workloads["registry"];
        assert_eq!(binding.product, Product::Breg);
        assert!(binding.default);
        assert_eq!(binding.grant.profile, "operator");
    }

    #[test]
    fn workload_bindings_require_one_default_and_started_products() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        let base = serde_json::to_value(plan).unwrap();
        for workloads in [
            json!({
                "one": {"product": "breg", "default": false, "subject": "service",
                    "client": "service", "grant": {
                        "profile": "operator", "scopes": ["registry:read"]}}
            }),
            json!({
                "one": {"product": "breg", "default": true, "subject": "service",
                    "client": "service", "grant": {
                        "profile": "operator", "scopes": ["registry:read"]}},
                "two": {"product": "breg", "default": true, "subject": "service-two",
                    "client": "service-two", "grant": {
                        "profile": "operator", "scopes": ["registry:read"]}}
            }),
        ] {
            let mut value = base.clone();
            value["workloads"] = workloads;
            let plan: Plan = serde_json::from_value(value).unwrap();
            let error = plan.validate(&canonical(&root)).unwrap_err().to_string();
            assert!(error.contains("default workload binding"), "{error}");
        }
    }

    #[test]
    fn messaging_people_and_workloads_use_their_own_product_authority() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        fs::create_dir(root.path().join("messaging")).unwrap();
        fs::write(root.path().join("messaging/messaging.yaml"), "fixture").unwrap();
        let mut value = serde_json::to_value(plan).unwrap();
        value["products"].as_array_mut().unwrap().push(json!({
            "product": "messaging",
            "project": "messaging",
            "audience": "urn:test:messaging"
        }));
        value["people"]["operator"]["grants"]["messaging"] = json!({
            "profile": "service-sender",
            "scopes": ["messaging:send"],
            "claims": {"registry_actor_kind": "service"}
        });
        value["workloads"] = json!({
            "registry": {
                "product": "breg", "default": true,
                "subject": "registry-service", "client": "registry-service",
                "grant": {"profile": "operator", "scopes": ["registry:read"]}
            },
            "notices": {
                "product": "messaging", "default": true,
                "subject": "notice-service", "client": "notice-service",
                "grant": {
                    "profile": "service-sender", "scopes": ["messaging:send"],
                    "claims": {"registry_actor_kind": "service"}
                }
            }
        });
        let plan: Plan = serde_json::from_value(value).unwrap();

        plan.validate(&canonical(&root)).unwrap();
        assert_eq!(plan.workloads["notices"].product, Product::Messaging);
        assert_ne!(
            plan.product(Product::Breg).audience,
            plan.product(Product::Messaging).audience
        );
    }

    #[test]
    fn development_pickers_explicitly_bind_persona_people_products_and_workloads() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        let mut value = serde_json::to_value(plan).unwrap();
        value["workloads"] = json!({
            "registry": {
                "product": "breg", "default": true,
                "subject": "portal-service", "client": "portal-service",
                "grant": {"profile": "operator", "scopes": ["registry:read"]}
            }
        });
        value["developmentPickers"] = json!({
            "holder": {
                "people": ["operator"],
                "personProducts": ["breg"],
                "workloads": ["registry"]
            }
        });
        let plan: Plan = serde_json::from_value(value).unwrap();

        plan.validate(&canonical(&root)).unwrap();
        let picker = plan.development_pickers.holder.as_ref().unwrap();
        assert_eq!(picker.people, ["operator"]);
        assert_eq!(picker.person_products, [Product::Breg]);
        assert_eq!(picker.workloads, ["registry"]);
    }

    #[test]
    fn development_pickers_refuse_implicit_people_incomplete_grants_and_external_workloads() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        let base = serde_json::to_value(plan).unwrap();
        for picker in [
            json!({"holder": {
                "people": ["unknown"], "personProducts": ["breg"], "workloads": []
            }}),
            json!({"holder": {
                "people": ["operator"], "personProducts": ["casework"], "workloads": []
            }}),
            json!({"holder": {
                "people": ["operator"], "personProducts": ["breg"],
                "workloads": ["production"]
            }}),
        ] {
            let mut value = base.clone();
            value["developmentPickers"] = picker;
            let plan: Plan = serde_json::from_value(value).unwrap();
            assert!(plan.validate(&canonical(&root)).is_err());
        }
        let mut value = base;
        value["developmentPickers"] = json!({
            "holder": {"people": ["operator"], "personProducts": ["breg"]},
            "staff": {"people": ["operator"], "personProducts": ["breg"]}
        });
        let plan: Plan = serde_json::from_value(value).unwrap();
        assert!(plan
            .validate(&canonical(&root))
            .unwrap_err()
            .to_string()
            .contains("both local picker personas"));
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
    fn validation_refuses_a_find_capture_that_refers_to_its_own_step() {
        let (root, plan) = plan(json!({
            "id": "list", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records",
            "expect": {"status": 200},
            "capture": {
                "first": {"type": "pointer", "pointer": "/items/0/recordIdentifier"},
                "second": {
                    "type": "find", "find": "/items",
                    "where": {"pointer": "/recordIdentifier", "equals": "{{first}}"},
                    "pointer": "/status"
                }
            }
        }));
        let error = format!("{:#}", plan.validate(&canonical(&root)).unwrap_err());
        assert!(error.contains("earlier capture"), "{error}");
        assert!(error.contains("/capture/second/find"), "{error}");
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
                    {"product": "breg", "project": ".", "audience": "urn:example:registry"},
                    {"product": "casework", "project": ".", "audience": "urn:example:review"}
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

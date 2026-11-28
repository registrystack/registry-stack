// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use registry_platform_config::contains_environment_expression;
use registry_platform_httputil::valid_scope_token;
use registry_platform_yaml::{
    escape_pointer_segment, ApiVersion, BoundedU32, Decoded, EnvelopeRule, Expect, FormatSpec,
    Identified, LocalId, Reader, Refusal, RemovedKey, Report, ScalarHook, ScalarSite, Severity,
    UniqueIdList, UniqueList,
};
#[cfg(feature = "schema")]
use registry_platform_yaml::{ExternalId, Url as PlatformUrl};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

/// Refuses every `${...}` substitution expression in a development file: the
/// plan and the scenarios are read as written (CFG-SEC-2). Text that is not an
/// expression, such as a lone `${`, is accepted.
struct LiteralText {
    /// What to write instead, the refusal's suggested action.
    remedy: &'static str,
}

/// The remedy for a file whose values are written as they are meant.
const WRITE_THE_VALUE: &str = "Write the value in the file directly.";

impl LiteralText {
    fn check(&self, text: &str) -> std::result::Result<(), Refusal> {
        if contains_environment_expression(text) {
            return Err(Refusal {
                code: "config.substitution-not-allowed".to_owned(),
                message: "a `${...}` expression is written in a file BReg reads as written; \
                          substitution applies to runtime.yaml only"
                    .to_owned(),
                suggested_action: self.remedy.to_owned(),
            });
        }
        Ok(())
    }
}

impl ScalarHook for LiteralText {
    fn key(&mut self, site: &ScalarSite<'_>) -> std::result::Result<(), Refusal> {
        self.check(site.text)
    }

    fn value(&mut self, site: &ScalarSite<'_>) -> std::result::Result<Option<String>, Refusal> {
        self.check(site.text).map(|()| None)
    }
}
use url::Url as ParsedUrl;

pub(crate) const API_VERSION: &str = "id.registrystack.org/formats/rstack/dev/v1alpha1";
pub(crate) const KIND: &str = "RStackDev";
pub(crate) const SCENARIOS_API_VERSION: &str =
    "id.registrystack.org/formats/rstack/scenarios/v1alpha1";
pub(crate) const SCENARIOS_KIND: &str = "RStackScenarios";

pub(crate) const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[RemovedKey {
        pointer: "/journey",
        replacement: "Move the inline journey steps into a scenarios file (for example tests/scenarios.yaml, under `scenarios`) and set `scenarioFile` to its project-relative path.",
    }],
};

pub(crate) const SCENARIOS_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: SCENARIOS_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(SCENARIOS_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

#[cfg(feature = "schema")]
pub(crate) fn schema() -> schemars::Schema {
    schemars::schema_for!(Plan)
}

#[cfg(feature = "schema")]
pub(crate) fn scenarios_schema() -> schemars::Schema {
    schemars::schema_for!(ScenarioFile)
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
fn display_name_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "allOf": [generator.subschema_for::<registry_platform_yaml::DisplayText>()],
        "type": "string",
        "minLength": 1,
        "maxLength": 128,
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

#[cfg(feature = "schema")]
fn issuer_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "anyOf": [generator.subschema_for::<PlatformUrl>(), {"const": "run"}],
    })
}

/// A product the development run can start.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub(super) enum Product {
    Breg,
    Casework,
    Evidence,
    Messaging,
    Scheduling,
    Documents,
    Coordinator,
    Adapter,
    Render,
    Discovery,
}

impl Product {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Breg => "breg",
            Self::Casework => "casework",
            Self::Evidence => "evidence",
            Self::Messaging => "messaging",
            Self::Scheduling => "scheduling",
            Self::Documents => "documents",
            Self::Coordinator => "coordinator",
            Self::Adapter => "adapter",
            Self::Render => "render",
            Self::Discovery => "discovery",
        }
    }
    pub(super) fn manifest(self) -> &'static str {
        match self {
            Self::Breg => "registry.yaml",
            Self::Casework => "casework.yaml",
            Self::Evidence => "evidence.yaml",
            Self::Messaging => "messaging.yaml",
            Self::Scheduling => "scheduling.yaml",
            Self::Documents => "documents.yaml",
            Self::Coordinator => "workflow.yaml",
            Self::Adapter => "project.yaml",
            Self::Render => "manifest.yaml",
            Self::Discovery => "origins.yaml",
        }
    }

    pub(super) fn needs_database(self) -> bool {
        !matches!(self, Self::Evidence | Self::Render | Self::Discovery)
    }

    pub(super) fn verifies_tokens(self) -> bool {
        self != Self::Discovery
    }
}

/// The most test people one plan defines: enough for a load test to give each
/// synthetic caller its own principal and per-principal rate limit.
const MAXIMUM_PEOPLE: usize = 256;

/// The development plan: the products to start, the test people who call them, and the scenarios to run.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Plan {
    /// The issuer name written into every test token. Use an HTTPS URL that the products' trusted issuers and producers name. Set `run` instead only when the plan declares an `application` or a paired BReg and Casework `runIssuerBinding`: each of those requires `run`, and `run` requires one of them.
    #[cfg_attr(feature = "schema", schemars(schema_with = "issuer_schema"))]
    pub issuer: String,
    /// The products to start, each with its project directory and token audience. List each product at most once.
    pub products: Vec<ProductPlan>,
    /// The test people, keyed by a lowercase local identifier. Define up to 256, and give at least one grant to every started product that verifies tokens.
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<LocalId, TestPerson>")
    )]
    pub people: BTreeMap<String, TestPerson>,
    /// Project-relative path to the authored Stack scenarios file. Required: a development run exists to run scenarios.
    pub scenario_file: PathBuf,
    /// Run-local connections between BReg and Casework. Leave empty when the products do not call each other. A `runIssuerBinding` replaces the producer's fixed issuer with the run's own, so it requires `issuer: run`.
    #[serde(default)]
    pub bindings: super::bindings::Bindings,
    /// Chooses the test person for a BReg fixture step in tests/journeys.yaml, keyed by journey identifier and then step identifier. Needed only when several people could run the step; every named person needs a BReg grant.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "schema_test_people_schema")
    )]
    pub schema_test_people: BTreeMap<String, BTreeMap<String, String>>,
    /// A built local application this run prepares, starts, checks and stops. Its artifact root is supplied to `rstack dev start`.
    #[serde(default)]
    pub application: Option<ApplicationPlan>,
}

/// A generic Node application and its configuration command. All artifact paths are relative to the supplied built root.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ApplicationPlan {
    /// Explicit existing served roles opting into separate same-human source credentials.
    /// The application's checked configuration command validates their BReg mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "application_source_roles_schema")
    )]
    pub casework_source_credential_roles: Option<Vec<String>>,
    /// Confidential browser client identifier admitted by the selected product profiles.
    pub client: String,
    /// Exact loopback callback path registered with the run issuer.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 256)))]
    pub callback_path: String,
    /// Local readiness path served by the application.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 256)))]
    pub health_path: String,
    /// Built application entry, relative to the supplied artifact root.
    pub entry: PathBuf,
    /// Built configuration command, invoked with --deployment, --run and --out.
    pub prepare: PathBuf,
    /// Built configuration checker, invoked with the generated config path.
    pub checker: PathBuf,
    /// Configuration source file, relative to the development project.
    pub deployment: PathBuf,
    /// Closed run-input schema name understood by the declared configuration command.
    pub config_schema: String,
    /// Environment variable naming the generated host configuration for the child.
    pub config_environment: String,
    /// Exact one-line response of the configuration command's --version flag.
    pub prepare_version: String,
}

/// One product to start and where its project lives.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct ProductPlan {
    /// Which product to start.
    pub product: Product,
    /// Relative path from the plan's directory to the product project, or `.` for the plan's own directory. It must contain the product’s project manifest.
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
    /// Name shown in the synthetic browser sign-in picker; it grants no authority.
    #[serde(
        default,
        rename = "displayName",
        deserialize_with = "registry_platform_yaml::optional_display_text"
    )]
    #[cfg_attr(feature = "schema", schemars(schema_with = "display_name_schema"))]
    pub display_name: Option<String>,
    /// Client identifier of this person's tokens: 1 to 256 characters without whitespace or control characters.
    #[cfg_attr(feature = "schema", schemars(with = "ExternalId"))]
    pub client: String,
    /// The authority this person holds in each product, keyed by its product identifier. An Evidence grant's profile is the requester tag the token carries. Give at least one grant, only for products listed in `products`.
    #[serde(deserialize_with = "deserialize_grants")]
    #[cfg_attr(feature = "schema", schemars(with = "GrantsDocument"))]
    pub grants: BTreeMap<Product, Grant>,
    /// Forward the same authority to both products. Both grants must declare the same scopes and additional claims.
    #[serde(default, rename = "caseworkContext")]
    pub casework_context: bool,
}

/// The authority a test person holds in one product.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(super) struct Grant {
    /// Local identifier of the product profile, the Coordinator caller policy, or a local label for a product without profiles.
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    pub profile: String,
    /// Distinct scopes written into the token, at most 32, each an OAuth scope-token of 1 to 256 bytes: printable ASCII without spaces, double quotes or backslashes.
    #[serde(deserialize_with = "deserialize_scopes")]
    #[cfg_attr(feature = "schema", schemars(schema_with = "scopes_schema"))]
    pub scopes: Vec<String>,
    /// Additional token claims, keyed by claim name. Names must not be reserved token claims such as `iss`, `aud`, `sub`, `scope` or any `registry_grant_` claim.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(schema_with = "claims_schema"))]
    pub claims: Map<String, Value>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
struct GrantsDocument {
    breg: Option<Grant>,
    casework: Option<Grant>,
    evidence: Option<Grant>,
    messaging: Option<Grant>,
    scheduling: Option<Grant>,
    documents: Option<Grant>,
    coordinator: Option<Grant>,
    adapter: Option<Grant>,
    render: Option<Grant>,
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
        grants.evidence.map(|grant| (Product::Evidence, grant)),
        grants.messaging.map(|grant| (Product::Messaging, grant)),
        grants.scheduling.map(|grant| (Product::Scheduling, grant)),
        grants.documents.map(|grant| (Product::Documents, grant)),
        grants
            .coordinator
            .map(|grant| (Product::Coordinator, grant)),
        grants.adapter.map(|grant| (Product::Adapter, grant)),
        grants.render.map(|grant| (Product::Render, grant)),
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

impl Identified for Journey {
    fn id(&self) -> &str {
        &self.id
    }
}

fn deserialize_scenarios<'de, D>(deserializer: D) -> std::result::Result<Vec<Journey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    UniqueIdList::<Journey>::deserialize(deserializer).map(UniqueIdList::into_vec)
}

/// Authored HTTP scenarios shared by standalone rstack dev and Studio.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
struct ScenarioFile {
    /// Ordered scenarios. Each uses the development runner's Journey, Step, Expected and Capture contract.
    #[serde(deserialize_with = "deserialize_scenarios")]
    scenarios: Vec<Journey>,
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
    /// The test person who sends the request. Omit for a public Discovery request.
    #[serde(rename = "as")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<LocalId>"))]
    pub person: Option<String>,
    /// The HTTP method.
    pub method: Method,
    /// Request path, starting with `/v1/` or using the Adapter effective-contract path, at most 2048 characters, without whitespace, control characters, backslashes or fragments. It may contain `{{name}}` references to earlier captures.
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
    #[serde(default, deserialize_with = "expected_json_values")]
    #[cfg_attr(feature = "schema", schemars(schema_with = "expected_json_schema"))]
    pub json: BTreeMap<String, Value>,
    /// Further assertions about the response body, at most 32. Each one tests a single JSON pointer.
    #[serde(default)]
    pub checks: Vec<Check>,
    /// Problem code the error response must carry, 1 to 256 characters without whitespace or control characters. It may contain `{{name}}` references to earlier captures.
    pub code: Option<String>,
}

// Only each asserted JSON value is foreign data; the pointer map and the
// surrounding scenario remain ordinary, strictly decoded configuration.
fn expected_json_values<'de, D>(deserializer: D) -> Result<BTreeMap<String, Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    BTreeMap::<String, registry_platform_yaml::ForeignValue>::deserialize(deserializer).map(
        |values| {
            values
                .into_iter()
                .map(|(pointer, value)| (pointer, value.into_value()))
                .collect()
        },
    )
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
#[serde(remote = "Self", rename_all = "kebab-case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
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

registry_platform_yaml::tagged_union!(Capture);

impl Serialize for Capture {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let external =
            Capture::serialize(self, serde_json::value::Serializer).map_err(S::Error::custom)?;
        let Value::Object(external) = external else {
            return Err(S::Error::custom("a capture must serialize as a mapping"));
        };
        let mut variants = external.into_iter();
        let (Some((name, Value::Object(members))), None) = (variants.next(), variants.next())
        else {
            return Err(S::Error::custom("a capture must contain one variant"));
        };
        let mut tagged = Map::new();
        tagged.insert("type".to_owned(), Value::String(name));
        tagged.extend(members);
        Value::Object(tagged).serialize(serializer)
    }
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

#[cfg(feature = "schema")]
fn application_source_roles_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let item = generator.subschema_for::<LocalId>();
    schemars::json_schema!({"anyOf": [{"type":"null"}, {"type":"array","items":item,"minItems":1,"maxItems":32,"uniqueItems":true}]})
}

fn valid_application_source_roles(roles: &[String]) -> bool {
    !roles.is_empty()
        && roles.len() <= 32
        && roles.iter().all(|role| identifier(role))
        && roles.iter().collect::<BTreeSet<_>>().len() == roles.len()
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

fn browser_host_claim(claim: &str) -> bool {
    matches!(claim, "name" | "registry_scopes")
}

pub(super) fn validate_application_authority(
    plan: &Plan,
    inspection: &super::products::ProductInspection,
) -> SemanticResult<()> {
    if plan.application.is_none() {
        return Ok(());
    }
    if let Some(authority) = &inspection.breg_authority {
        if browser_host_claim(&authority.principal) {
            let index = plan
                .products
                .iter()
                .position(|entry| entry.product == Product::Breg)
                .expect("an application plan has a BReg product");
            return refuse(
                &format!("/products/{index}/project"),
                "The BReg project selects a principal claim reserved by the browser host.",
                "Choose `sub`, `registry_principal`, or another principal claim that is neither `name` nor `registry_scopes`.",
            );
        }
    }
    for (name, person) in &plan.people {
        let Some(grant) = person.grants.get(&Product::Casework) else {
            continue;
        };
        if inspection
            .casework_principals
            .get(&grant.profile)
            .is_some_and(|principal| browser_host_claim(principal))
        {
            return refuse(
                &format!(
                    "/people/{}/grants/casework/profile",
                    registry_platform_yaml::escape_pointer_segment(name)
                ),
                "The Casework profile selects a principal claim reserved by the browser host.",
                "Choose a profile whose principal claim is `sub`, `registry_principal`, or another claim that is neither `name` nor `registry_scopes`.",
            );
        }
    }
    Ok(())
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
        "rstack.dev.invalid-plan",
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

fn read_scenarios(root: &Path, plan: &Plan) -> Result<(Vec<Journey>, String)> {
    let file = root.join(&plan.scenario_file);
    let bytes = read(
        &file,
        registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES as u64 + 1,
    )
    .context("cannot read the authored scenario file")?;
    let mut decoded = Reader::new(file.display().to_string())
        .with_hook(&mut LiteralText {
            remedy: WRITE_THE_VALUE,
        })
        .decode::<ScenarioFile>(&bytes, &Expect::one(&SCENARIOS_FORMAT))?;
    if let Err(refusal) = decoded.value.validate(plan) {
        let diagnostic = decoded.document.diagnostic_at_value(
            Severity::Error,
            "rstack.dev.invalid-scenarios",
            &refusal.field,
            &refusal.reason,
            &refusal.remedy,
        );
        return Err(decoded.document.report_with([diagnostic]).into());
    }
    let revision = format!(
        "sha256:{}",
        Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    Ok((std::mem::take(&mut decoded.value.scenarios), revision))
}

pub(super) struct LoadedPlan {
    pub plan: Plan,
    pub scenarios: Vec<Journey>,
    pub scenario_digest: String,
}

pub(crate) fn check(root: &Path) -> Result<Report> {
    let decoded = read_plan(root)?;
    validate_plan(root, &decoded)?;
    read_scenarios(root, &decoded.value)?;
    if let Err(refusal) = super::products::schema_people(root, &decoded.value, false) {
        return Err(refusal_report(&decoded, &refusal).into());
    }
    let terminate = super::signals()?;
    let inspection = match super::products::inspect(root, &decoded.value, &terminate) {
        Ok(inspection) => inspection,
        Err(error) => {
            return match error.downcast::<SemanticRefusal>() {
                Ok(refusal) => Err(refusal_report(&decoded, &refusal).into()),
                Err(error) => Err(error),
            }
        }
    };
    validate_application_authority(&decoded.value, &inspection)
        .map_err(|refusal| refusal_report(&decoded, &refusal))?;
    Ok(decoded.document.report_with(Vec::new()))
}

pub(super) fn load(root: &Path) -> Result<LoadedPlan> {
    let decoded = read_plan(root)?;
    validate_plan(root, &decoded)?;
    let (scenarios, scenario_digest) = read_scenarios(root, &decoded.value)?;
    Ok(LoadedPlan {
        plan: decoded.value,
        scenarios,
        scenario_digest,
    })
}

impl Plan {
    pub(super) fn paired_run_binding(&self) -> bool {
        self.bindings.binds_run_issuer()
            && self.products.iter().any(|p| p.product == Product::Breg)
            && self.products.iter().any(|p| p.product == Product::Casework)
    }

    pub(super) fn runs_evidence(&self) -> bool {
        self.products
            .iter()
            .any(|entry| entry.product == Product::Evidence)
    }

    /// Puts the products in the order a run starts them: BReg before Casework,
    /// which pairs with the BReg package. The author may list them either way.
    pub(super) fn order_products_for_start(&mut self) {
        self.products.sort_by_key(|entry| entry.product);
    }

    pub(super) fn product(&self, product: Product) -> &ProductPlan {
        self.products
            .iter()
            .find(|entry| entry.product == product)
            .expect("validated product")
    }

    fn validate(&self, root: &Path) -> SemanticResult<()> {
        let path = &self.scenario_file;
        require(
            !path.as_os_str().is_empty()
                && !path.to_string_lossy().contains('\\')
                && path
                    .components()
                    .all(|part| matches!(part, Component::Normal(_))),
            "/scenarioFile",
            "The scenario file path must be relative to the project without `.`, `..`, or backslashes.",
            "Use normal relative path components inside the development project.",
        )?;
        require_file_inside(root, path, "/scenarioFile", "authored scenario file")?;
        require(
            self.issuer == "run" || ParsedUrl::parse(&self.issuer).is_ok_and(|url| {
                url.scheme() == "https"
                    && url.host().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && self.issuer.len() <= 512
            }),
            "/issuer",
            "The issuer must be `run` or a bounded HTTPS URL without credentials, query, or fragment.",
            "Set issuer to `run` for an application or exact paired run issuer binding, or to an HTTPS URL with a host and no credentials, query, or fragment.",
        )?;
        require(
            (self.issuer != "run"
                || self.application.is_some()
                || self.paired_run_binding()
                || self.runs_evidence())
                && ((self.application.is_none() && !self.bindings.binds_run_issuer()) || self.issuer == "run"),
            "/issuer",
            "The run issuer requires an application, an explicitly bound BReg and Casework pair, or Evidence; applications and run issuer bindings require issuer run.",
            "Use issuer `run` with application, the exact paired runIssuerBinding, or Evidence; otherwise remove them and set an HTTPS issuer.",
        )?;
        require(
            !self.runs_evidence() || (self.issuer == "run" && self.application.is_none()),
            "/issuer",
            "An Evidence target accepts only the run's own loopback issuer, and a browser application already owns that issuer.",
            "Set issuer to `run` and remove the application when the plan starts Evidence.",
        )?;
        if let Some(application) = &self.application {
            if let Some(roles) = &application.casework_source_credential_roles {
                require(
                    valid_application_source_roles(roles)
                        && self.products.iter().any(|product| product.product == Product::Breg)
                        && self.products.iter().any(|product| product.product == Product::Casework)
                        && self.bindings.casework_context_provider.is_some(),
                    "/application/caseworkSourceCredentialRoles",
                    "Separate source credentials require 1 through 32 distinct existing role identifiers and a paired BReg/Casework context binding.",
                    "Declare the exact served roles and both product bindings, or omit caseworkSourceCredentialRoles.",
                )?;
            }
            require(
                bounded_atom(&application.client),
                "/application/client",
                "The browser client must be bounded text without whitespace or control characters.",
                "Set client to the application's declared OIDC client identifier.",
            )?;
            for (field, path) in [
                ("callbackPath", &application.callback_path),
                ("healthPath", &application.health_path),
            ] {
                require(
                    path.len() <= 256 && super::products::valid_health_path(path),
                    &format!("/application/{field}"),
                    "The path must be a bounded local absolute path without a query or fragment.",
                    "Use a single-slash path of at most 256 bytes on the application origin.",
                )?;
            }
            for (field, path) in [
                ("entry", &application.entry),
                ("prepare", &application.prepare),
                ("checker", &application.checker),
                ("deployment", &application.deployment),
            ] {
                require(
                    !path.as_os_str().is_empty()
                        && path
                            .components()
                            .all(|part| matches!(part, Component::Normal(_))),
                    &format!("/application/{field}"),
                    "The path must be relative and stay inside its declared root.",
                    "Use normal relative path components without `.` or `..`.",
                )?;
            }
            require_file_inside(
                root,
                &application.deployment,
                "/application/deployment",
                "deployment file",
            )?;
            require(
                bounded_atom(&application.config_schema),
                "/application/configSchema",
                "The configuration input schema name must be bounded text.",
                "Set configSchema to the configuration command's schema name.",
            )?;
            require(
                !application.config_environment.is_empty()
                    && application.config_environment.len() <= 128
                    && application.config_environment.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    })
                    && !application.config_environment.starts_with("RSTACK_")
                    && !application.config_environment.as_bytes()[0].is_ascii_digit(),
                "/application/configEnvironment",
                "The configuration environment name must be uppercase and cannot use the runner namespace.",
                "Set configEnvironment to the application's uppercase configuration-file variable.",
            )?;
            require(
                (1..=128).contains(&application.prepare_version.len())
                    && !application.prepare_version.chars().any(char::is_control),
                "/application/prepareVersion",
                "The configuration command version line must be bounded visible text.",
                "Set prepareVersion to the exact one-line --version output.",
            )?;
        }
        require(
            !self.products.is_empty(),
            "/products",
            "The plan must name at least one product.",
            "Add a supported product to products.",
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
            let manifest = entry.product.manifest();
            require_file_inside(
                root,
                &entry.project.join(manifest),
                &format!("{field}/project"),
                &format!("{manifest} of the product project"),
            )?;
        }
        if self.application.is_some() {
            require(
                products.contains(&Product::Breg),
                "/application",
                "The declared application needs a BReg product.",
                "Add the BReg product or remove application.",
            )?;
        }
        require(
            self.people.len() <= MAXIMUM_PEOPLE,
            "/people",
            "The plan may define at most 256 test people.",
            "Remove test people until people contains at most 256 entries.",
        )?;
        require(
            !self.people.is_empty() || products.iter().all(|product| !product.verifies_tokens()),
            "/people",
            "The plan must define test people for products that verify tokens.",
            "Add a test person with a grant for each product that verifies tokens.",
        )?;
        let mut coordinator_scopes = BTreeMap::new();
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
            if let Some(name) = &person.display_name {
                require(
                    !name.is_empty()
                        && name.chars().count() <= 128
                        && !name.chars().any(char::is_control),
                    &format!("{field}/displayName"),
                    "The test person's display name must be 1 to 128 visible characters.",
                    "Set displayName to short text without control characters.",
                )?;
            }
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
                "Add a grant for a started product that verifies tokens.",
            )?;
            for (product, grant) in &person.grants {
                let field = format!("{field}/grants/{}", product.name());
                require(
                    products.contains(product),
                    &field,
                    "The grant names a product that is not started.",
                    "Add the grant's product to products, or remove this grant.",
                )?;
                require(
                    identifier(&grant.profile),
                    &format!("{field}/profile"),
                    "The grant profile must be a local identifier.",
                    "Set profile to a lowercase local identifier of at most 64 characters.",
                )?;
                require(
                    grant.scopes.len() <= 32
                        && grant
                            .scopes
                            .iter()
                            .all(|scope| scope.len() <= 256 && valid_scope_token(scope)),
                    &format!("{field}/scopes"),
                    "The grant must contain at most 32 scopes, each an OAuth scope-token.",
                    "Remove excess scopes, and keep each scope within 256 bytes of printable ASCII without spaces, double quotes or backslashes.",
                )?;
                if *product == Product::Coordinator {
                    require(
                        grant.profile == person.client,
                        &format!("{field}/profile"),
                        "The Coordinator grant's profile must match its client policy ID.",
                        "Set profile to the person's client.",
                    )?;
                    let scopes = grant.scopes.iter().collect::<BTreeSet<_>>();
                    let expected = coordinator_scopes
                        .entry(&person.client)
                        .or_insert_with(|| scopes.clone());
                    require(
                        *expected == scopes,
                        &format!("{field}/scopes"),
                        "Coordinator grants for the same client must have the same scopes.",
                        "Align the scopes for every Coordinator grant using this client.",
                    )?;
                }
                for claim in grant.claims.keys() {
                    if self.application.is_some() && browser_host_claim(claim) {
                        return refuse(
                            &format!("{field}/claims"),
                            "The grant authors a claim reserved by the browser host.",
                            "Remove `name` and `registry_scopes`; the browser issuer supplies them from the selected identity and narrowed scopes.",
                        );
                    }
                    require(
                        bounded_atom(claim) && !reserved_claim(claim),
                        &format!("{field}/claims"),
                        "The grant contains a reserved or invalid additional claim name.",
                        "Remove the claim or rename it to bounded text that is not reserved by the token contract.",
                    )?;
                }
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
        for product in products
            .into_iter()
            .filter(|product| product.verifies_tokens())
        {
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
        Ok(())
    }
}

impl Journey {
    fn validate(&self, plan: &Plan, base: &str) -> SemanticResult<()> {
        require(
            identifier(&self.id),
            &format!("{base}/id"),
            "The journey ID must be a local identifier.",
            "Set id to a lowercase local identifier of at most 64 characters.",
        )?;
        require(
            (1..=32).contains(&self.steps.len()),
            &format!("{base}/steps"),
            "The journey must contain 1 to 32 steps.",
            "Add or remove steps until the journey contains between 1 and 32 steps.",
        )?;
        let mut captures = BTreeSet::new();
        for (index, step) in self.steps.iter().enumerate() {
            let field = format!("{base}/steps/{index}");
            require(
                step_identifier(&step.id),
                &format!("{field}/id"),
                "The step ID must be a local or dotted derived identifier.",
                "Set id to a lowercase local identifier or dotted sequence of local identifiers.",
            )?;
            require(
                if step.product.verifies_tokens() {
                    step.person
                        .as_ref()
                        .and_then(|name| plan.people.get(name))
                        .is_some_and(|person| person.grants.contains_key(&step.product))
                } else {
                    step.person.is_none() && plan.products.iter().any(|p| p.product == step.product)
                },
                &format!("{field}/as"),
                "The step must name a test person with a grant for its product.",
                "Set as to a test person that has a grant for this step's product.",
            )?;
            require(
                valid_path(&step.path) && (step.path != ADAPTER_CONTRACT_PATH || step.product == Product::Adapter),
                &format!("{field}/path"),
                "The request path must be a relative product API path starting with /v1/.",
                "Set path to a bounded /v1/ path without whitespace, control characters, backslashes, or fragments.",
            )?;
            if step.product == Product::Breg {
                let person = step.person.as_ref().expect("validated BReg step");
                let grant_profile = &plan.people[person].grants[&Product::Breg].profile;
                if let Some(named) = path_access_profile(&step.path) {
                    require(
                        named == *grant_profile || named.contains("{{"),
                        &format!("{field}/path"),
                        format!(
                            "Step `{}` names the BReg access profile `{named}`, but its test person `{}` has a grant for `{grant_profile}`.",
                            step.id, person
                        ),
                        format!(
                            "Remove `accessProfile={named}` from the path (the scenario takes the profile from the test person's grant), or run the step as a test person whose BReg grant selects `{named}`."
                        ),
                    )?;
                }
            }
            let statuses = step.expect.status.values();
            require(
                (1..=16).contains(&statuses.len())
                    && statuses.iter().collect::<BTreeSet<_>>().len() == statuses.len(),
                &format!("{field}/expect/status"),
                "Expected status must contain 1 to 16 distinct HTTP statuses.",
                "List between 1 and 16 distinct HTTP status numbers.",
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
                (value == "run.issuer" || captures.contains(value))
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
                                (value == "run.issuer" || captures.contains(value))
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

impl ScenarioFile {
    fn validate(&self, plan: &Plan) -> SemanticResult<()> {
        require(
            (1..=16).contains(&self.scenarios.len()),
            "/scenarios",
            "The authored file must contain 1 to 16 scenarios.",
            "Add a scenario or reduce the pack to at most 16 scenarios.",
        )?;
        require(
            self.scenarios
                .iter()
                .map(|scenario| scenario.steps.len())
                .sum::<usize>()
                <= 64,
            "/scenarios",
            "The authored scenarios contain more than 64 steps in total.",
            "Reduce the total to at most 64 steps.",
        )?;
        for (index, scenario) in self.scenarios.iter().enumerate() {
            scenario.validate(plan, &format!("/scenarios/{index}"))?;
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

/// The `accessProfile` query value a step path names itself, if any.
pub(super) fn path_access_profile(path: &str) -> Option<String> {
    let (_, query) = path.split_once('?')?;
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == "accessProfile")
        .map(|(_, value)| value.into_owned())
}

/// Refuses unless `relative` under `root` resolves, symlinks included, to a
/// regular file still inside the resolved `root`. Both sides are resolved so a
/// project reached through a symlinked parent is accepted while a link leading
/// outside it is refused. A path that does not exist or is not a regular file is
/// refused as not found, apart from one that resolves outside the project.
fn require_file_inside(
    root: &Path,
    relative: &Path,
    field: &str,
    subject: &str,
) -> SemanticResult<()> {
    let resolved = root
        .canonicalize()
        .ok()
        .and_then(|root| Some((root.join(relative).canonicalize().ok()?, root)));
    match resolved {
        Some((file, root)) if !file.starts_with(&root) => refuse(
            field,
            &format!("The {subject} resolves outside the development project."),
            "Point the path at a file inside the development project, and remove any symlink that leads outside it.",
        ),
        Some((file, _)) if file.is_file() => Ok(()),
        _ => refuse(
            field,
            &format!("The {subject} was not found or is not a regular file."),
            "Create the file at the declared path inside the development project.",
        ),
    }
}

pub(super) const ADAPTER_CONTRACT_PATH: &str = "/.well-known/registry-adapter/effective-contract";

pub(super) fn valid_path(value: &str) -> bool {
    value.len() <= 2048
        && (value.starts_with("/v1/") || value == ADAPTER_CONTRACT_PATH)
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
            "scenarioFile": "tests/scenarios.yaml"
        }))
        .unwrap();
        write_scenarios(root.path(), json!({"id": "smoke", "steps": [step]}));
        (root, plan)
    }

    #[test]
    fn a_plan_takes_up_to_256_test_people() {
        let step = json!({"id": "list", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}});
        let (root, mut plan) = plan(step);
        let person = serde_json::to_value(&plan.people["operator"]).unwrap();
        let copy = || serde_json::from_value::<TestPerson>(person.clone()).unwrap();
        for index in 1..256 {
            plan.people.insert(format!("person-{index}"), copy());
        }
        assert_eq!(plan.people.len(), 256);
        plan.validate(root.path()).unwrap();

        plan.people.insert("person-256".to_owned(), copy());
        let refusal = plan.validate(root.path()).unwrap_err().to_string();
        assert!(refusal.contains("/people"), "{refusal}");
        assert!(refusal.contains("at most 256 test people"), "{refusal}");
    }

    /// Writes `tests/scenarios.yaml` holding one scenario.
    fn write_scenarios(root: &Path, journey: Value) {
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::write(
            root.join("tests/scenarios.yaml"),
            format!(
                "apiVersion: {SCENARIOS_API_VERSION}\nkind: {SCENARIOS_KIND}\nscenarios:\n  - {journey}\n"
            ),
        )
        .unwrap();
    }

    fn scenario_file(root: &Path, plan: &Plan) -> ScenarioFile {
        let bytes = fs::read(root.join(&plan.scenario_file)).unwrap();
        Reader::new("scenarios")
            .with_hook(&mut LiteralText {
                remedy: WRITE_THE_VALUE,
            })
            .decode::<ScenarioFile>(&bytes, &Expect::one(&SCENARIOS_FORMAT))
            .unwrap()
            .value
    }

    /// Validates the plan and then its scenarios file, as `check` does.
    fn validate_all(root: &Path, plan: &Plan) -> SemanticResult<()> {
        plan.validate(root)?;
        scenario_file(root, plan).validate(plan)
    }

    // Exercise the production file readers, not serde_json's independent decoder.
    fn read_expected_json(expected: &str) -> Result<Expected> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("registry.yaml"), "fixture")?;
        let base = format!(
            "apiVersion: {API_VERSION}\nkind: {KIND}\nissuer: https://issuer.example.invalid\nproducts:\n  - {{product: breg, project: ., audience: registry}}\npeople:\n  operator:\n    subject: operator\n    client: operator-client\n    grants:\n      breg: {{profile: operator, scopes: []}}\n"
        );
        let journey = format!(
            r#"{{"id":"smoke","steps":[{{"id":"read","product":"breg","as":"operator","method":"GET","path":"/v1/records/widgets/00000000-0000-4000-8000-000000000001","expect":{expected}}}]}}"#
        );
        fs::create_dir(root.path().join("tests"))?;
        fs::write(
            root.path().join("tests/scenarios.yaml"),
            format!(
                "apiVersion: {SCENARIOS_API_VERSION}\nkind: {SCENARIOS_KIND}\nscenarios:\n  - {journey}\n"
            ),
        )?;
        fs::write(
            root.path().join("dev.yaml"),
            format!("{base}scenarioFile: tests/scenarios.yaml\n"),
        )?;
        let decoded = read_plan(root.path())?;
        validate_plan(root.path(), &decoded)?;
        let mut journeys = read_scenarios(root.path(), &decoded.value)?.0;
        Ok(journeys.remove(0).steps.remove(0).expect)
    }

    #[test]
    fn expected_json_reader_accepts_direct_null_values() {
        let expected =
            read_expected_json(r#"{"status":200,"json":{"/data/domainData":null}}"#).unwrap();
        assert_eq!(expected.json["/data/domainData"], Value::Null);
    }

    #[test]
    fn expected_json_reader_accepts_inline_null_values() {
        let expected = read_expected_json(
            r#"{"status":200,"json":{"/data/domainData":{"optionalText":null}}}"#,
        )
        .unwrap();
        assert_eq!(
            expected.json["/data/domainData"],
            json!({"optionalText": null})
        );
    }

    #[test]
    fn expected_json_reader_preserves_null_as_distinct_from_missing_and_text() {
        let expected =
            read_expected_json(r#"{"status":200,"json":{"/data":{"optionalText":null}}}"#).unwrap();
        let asserted = &expected.json["/data"];
        assert_eq!(asserted.pointer("/optionalText"), Some(&Value::Null));
        assert_eq!(asserted.pointer("/absent"), None);
        assert_ne!(asserted, &json!({}));
        assert_ne!(asserted, &json!({"optionalText": "null"}));
        assert_ne!(asserted, &json!({"optionalText": null, "extra": true}));
    }

    #[test]
    fn expected_json_reader_accepts_nested_null_and_preserves_exact_typed_values() {
        let value = json!({"optionalText": null, "nested": [null, {"text": "null", "flag": false, "integer": 7, "fraction": 1.5}], "empty": {}});
        let source = format!(r#"{{"status":200,"json":{{"/data/domainData":{value}}}}}"#);
        let expected = read_expected_json(&source).unwrap();
        assert_eq!(expected.json["/data/domainData"], value);
        assert_eq!(
            serde_json::to_value(&expected).unwrap()["json"]["/data/domainData"],
            value
        );
        let expanded = expand_json(&expected.json["/data/domainData"], |_| unreachable!()).unwrap();
        assert_eq!(expanded, value);
        assert_ne!(expanded, json!({"optionalText": null}));
        assert_ne!(
            expanded,
            json!({"optionalText": "null", "nested": value["nested"], "empty": {}})
        );
    }

    #[test]
    fn expected_json_reader_keeps_null_scoped_to_each_expected_value() {
        for expected in [
            r#"{"status":200,"json":null}"#,
            r#"{"json":{"/data":null},"status":null}"#,
            r#"{"status":200,"json":{"/data":null},"code":null}"#,
        ] {
            let error = read_expected_json(expected).err().unwrap();
            assert!(error.to_string().contains("config.null-value"), "{error}");
        }
        assert!(read_expected_json(r#"{"status":200,"json":[]}"#).is_err());
        for expected in [r#"{"status":200}"#, r#"{"status":200,"json":{}}"#] {
            assert!(read_expected_json(expected).unwrap().json.is_empty());
        }
    }

    #[test]
    fn expected_json_reader_retains_unknown_key_and_yaml_syntax_guards() {
        for (expected, code) in [
            (
                r#"{"status":200,"json":{"/data":null},"unexpected":true}"#,
                "config.unknown-key",
            ),
            (
                r#"{"status":200,"json":{"/data":null,"/data":{}}}"#,
                "yaml.duplicate-key",
            ),
            (
                r#"{"status":200,"json":{"/data":{"optionalText":null,"optionalText":"text"}}}"#,
                "yaml.duplicate-key",
            ),
            (
                r#"{"status":200,"json":{"/data":{optionalText: &item null}}}"#,
                "yaml.anchor",
            ),
            (
                r#"{"status":200,"json":{"/data":{optionalText: *item}}}"#,
                "yaml.alias",
            ),
            (
                r#"{"status":200,"json":{"/data":{optionalText: !!str null}}}"#,
                "yaml.tag",
            ),
        ] {
            let error = read_expected_json(expected).err().unwrap();
            assert!(error.to_string().contains(code), "{code}: {error}");
        }
    }

    #[test]
    fn expected_json_reader_retains_document_size_and_depth_bounds() {
        let deep = format!("{}null{}", "[".repeat(129), "]".repeat(129));
        let large = format!(
            "\"{}\"",
            "x".repeat(registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES)
        );
        let expected = format!(r#"{{"status":200,"json":{{"/data":{deep}}}}}"#);
        let error = read_expected_json(&expected).err().unwrap();
        assert!(error.to_string().contains("yaml.too-deep"), "{error}");
        let expected = format!(r#"{{"status":200,"json":{{"/data":{large}}}}}"#);
        let error = read_expected_json(&expected).err().unwrap();
        let detail = format!("{error:#}");
        assert!(
            detail.contains("size limit") || detail.contains("yaml.too-large"),
            "{detail}"
        );
    }

    #[cfg(feature = "schema")]
    #[test]
    fn expected_json_reader_matches_the_existing_exact_json_schema() {
        let document = serde_json::to_value(schemars::schema_for!(Expected)).unwrap();
        let schema = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&document)
            .unwrap();
        for value in [
            Value::Null,
            json!({"optionalText": null}),
            json!([null, true, 1, "null"]),
        ] {
            let expected = json!({"status": 200, "json": {"/data/domainData": value}});
            assert!(schema.is_valid(&expected), "{expected}");
        }
        assert!(!schema.is_valid(&json!({"status": 200, "json": null})));
        assert!(!schema.is_valid(&json!({"status": null, "json": {}})));
    }

    fn canonical(root: &tempfile::TempDir) -> PathBuf {
        root.path().canonicalize().unwrap()
    }

    #[test]
    fn application_source_role_list_is_explicit_bounded_and_unique() {
        assert!(valid_application_source_roles(&[
            "reviewer".into(),
            "supervisor".into()
        ]));
        for roles in [
            vec![],
            vec!["reviewer".into(), "reviewer".into()],
            vec!["invalid role".into()],
            (0..33).map(|n| format!("role-{n}")).collect(),
        ] {
            assert!(!valid_application_source_roles(&roles));
        }
        let (root, plan) = application_plan();
        let mut value = serde_json::to_value(plan).unwrap();
        value["application"]["caseworkSourceCredentialRoles"] = json!(["reviewer"]);
        let plan: Plan = serde_json::from_value(value).unwrap();
        let refusal = validate_all(&canonical(&root), &plan).unwrap_err();
        assert_eq!(refusal.field, "/application/caseworkSourceCredentialRoles");
    }

    fn application_plan() -> (tempfile::TempDir, Plan) {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        fs::write(root.path().join("deployment.json"), "{}").unwrap();
        let mut value = serde_json::to_value(plan).unwrap();
        value["issuer"] = json!("run");
        value["application"] = json!({
            "client": "browser-client", "callbackPath": "/callback", "healthPath": "/health",
            "entry": "dist/main.js", "prepare": "dist/prepare.js",
            "checker": "dist/check.js", "deployment": "deployment.json",
            "configSchema": "example/host-run/v1", "configEnvironment": "HOST_CONFIG",
            "prepareVersion": "example-prepare 1.0"
        });
        (root, serde_json::from_value(value).unwrap())
    }

    #[test]
    fn display_name_is_presentation_only_and_bounded() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        let mut value = serde_json::to_value(plan).unwrap();
        value["people"]["operator"]["displayName"] = json!("A person");
        let valid: Plan = serde_json::from_value(value.clone()).unwrap();
        assert!(validate_all(&canonical(&root), &valid).is_ok());
        value["people"]["operator"]["displayName"] = json!("control\ncharacter");
        let invalid: Plan = serde_json::from_value(value).unwrap();
        assert!(validate_all(&canonical(&root), &invalid)
            .unwrap_err()
            .to_string()
            .contains("displayName"));
    }

    #[test]
    fn display_name_refuses_bidi_override_and_isolate_controls() {
        let (_, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        let valid = serde_json::to_value(plan).unwrap();
        for display_name in ["unsafe\u{202e}name", "unsafe\u{2066}name"] {
            let mut value = valid.clone();
            value["people"]["operator"]["displayName"] = json!(display_name);
            assert!(
                serde_json::from_value::<Plan>(value).is_err(),
                "display name {display_name:?}"
            );
        }
    }

    #[cfg(feature = "schema")]
    #[test]
    fn display_name_schema_matches_display_text_and_length_bounds() {
        let document = serde_json::to_value(schema()).unwrap();
        let schema = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&document)
            .unwrap();
        let valid = json!({
            "issuer": "https://issuer.example.invalid",
            "products": [{"product": "breg", "project": ".", "audience": "registry"}],
            "people": {"operator": {
                "subject": "operator", "client": "operator-client",
                "grants": {"breg": {"profile": "operator", "scopes": []}}
            }},
            "scenarioFile": "tests/scenarios.yaml"
        });
        for display_name in [
            "unsafe\u{202e}name".to_owned(),
            "unsafe\u{2066}name".to_owned(),
            String::new(),
            "x".repeat(129),
        ] {
            let mut value = valid.clone();
            value["people"]["operator"]["displayName"] = json!(display_name);
            assert!(!schema.is_valid(&value), "display name {display_name:?}");
        }
        for display_name in ["Visible name".to_owned(), "é".repeat(128)] {
            let mut value = valid.clone();
            value["people"]["operator"]["displayName"] = json!(display_name);
            assert!(schema.is_valid(&value), "display name {display_name:?}");
        }
    }

    #[test]
    fn product_only_run_issuer_requires_the_exact_explicit_paired_binding() {
        let (root, plan) = plan(
            json!({"id":"read","product":"breg","as":"operator","method":"GET","path":"/v1/records","expect":{"status":200}}),
        );
        fs::create_dir(root.path().join("casework")).unwrap();
        fs::write(root.path().join("casework/casework.yaml"), "fixture").unwrap();
        let mut value = serde_json::to_value(plan).unwrap();
        value["issuer"] = json!("run");
        value["products"]
            .as_array_mut()
            .unwrap()
            .push(json!({"product":"casework","project":"casework","audience":"urn:test:review"}));
        value["people"]["operator"]["grants"]["casework"] =
            json!({"profile":"requester","scopes":["casework:request"]});
        value["bindings"] = json!({"bregReviewAuthority":{"id":"casework","producer":"registry","identity":"operator","runIssuerBinding":{"producer":{"expectedIssuer":"https://issuer.example.test","expectedProfile":"requester","expectedSubject":"operator"}}}});
        let valid: Plan = serde_json::from_value(value.clone()).unwrap();
        validate_all(&canonical(&root), &valid).unwrap();
        assert!(valid.application.is_none());
        for mode in [
            "no-binding",
            "breg-only",
            "fixed-https",
            "fixed-http",
            "missing-grant",
        ] {
            let mut refused = value.clone();
            match mode {
                "no-binding" => {
                    refused["bindings"] = json!({});
                }
                "breg-only" => {
                    refused["products"].as_array_mut().unwrap().pop();
                }
                "fixed-https" => {
                    refused["issuer"] = json!("https://issuer.example.test");
                }
                "fixed-http" => {
                    refused["issuer"] = json!("http://127.0.0.1:8191");
                }
                _ => {
                    refused["people"]["operator"]["grants"]["casework"] = Value::Null;
                }
            }
            let result = serde_json::from_value::<Plan>(refused);
            assert!(
                result.map_or(true, |plan| validate_all(&canonical(&root), &plan).is_err()),
                "{mode}"
            );
        }
    }

    #[test]
    fn run_issuer_requires_a_bounded_declared_application() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        fs::write(root.path().join("deployment.json"), "{}").unwrap();
        let mut value = serde_json::to_value(plan).unwrap();
        value["issuer"] = json!("run");
        let without_application: Plan = serde_json::from_value(value.clone()).unwrap();
        assert!(validate_all(&canonical(&root), &without_application).is_err());
        value["application"] = json!({
            "client": "browser-client", "callbackPath": "/callback", "healthPath": "/health",
            "entry": "dist/main.js", "prepare": "dist/prepare.js",
            "checker": "dist/check.js", "deployment": "deployment.json",
            "configSchema": "example/host-run/v1", "configEnvironment": "HOST_CONFIG",
            "prepareVersion": "example-prepare 1.0"
        });
        let valid: Plan = serde_json::from_value(value.clone()).unwrap();
        assert!(validate_all(&canonical(&root), &valid).is_ok());
        let mut conflicting = value.clone();
        conflicting["people"]["operator"]["grants"]["breg"]["claims"]["registry_scopes"] =
            json!("unreviewed:scope");
        let conflicting: Plan = serde_json::from_value(conflicting).unwrap();
        assert!(validate_all(&canonical(&root), &conflicting)
            .unwrap_err()
            .to_string()
            .contains("reserved"));
        value["application"]["callbackPath"] = json!("//other-host/callback");
        let invalid: Plan = serde_json::from_value(value).unwrap();
        assert!(validate_all(&canonical(&root), &invalid)
            .unwrap_err()
            .to_string()
            .contains("callbackPath"));
    }

    #[test]
    fn application_grants_cannot_author_browser_host_claims() {
        for claim in ["name", "registry_scopes"] {
            let (root, plan) = application_plan();
            let mut value = serde_json::to_value(plan).unwrap();
            value["people"]["operator"]["grants"]["breg"]["claims"][claim] =
                json!("authority-value");
            let plan: Plan = serde_json::from_value(value).unwrap();

            let refusal = validate_all(&canonical(&root), &plan).unwrap_err();
            assert_eq!(refusal.field, "/people/operator/grants/breg/claims");
            assert!(refusal.reason.contains("browser host"));
        }
    }

    #[test]
    fn application_products_cannot_select_browser_host_principal_claims() {
        for principal in ["name", "registry_scopes"] {
            let (_, plan) = application_plan();
            let inspection = super::super::products::ProductInspection {
                breg_authority: Some(super::super::BregAuthority {
                    principal: principal.to_owned(),
                    purpose: false,
                    requires_postgis: false,
                    encrypts_fields: false,
                    named_clients: BTreeSet::new(),
                }),
                casework_principals: BTreeMap::new(),
            };

            let refusal = validate_application_authority(&plan, &inspection).unwrap_err();
            assert_eq!(refusal.field, "/products/0/project");
            assert!(refusal.reason.contains("BReg"));
        }

        for principal in ["name", "registry_scopes"] {
            let (_, plan) = application_plan();
            let mut value = serde_json::to_value(plan).unwrap();
            value["products"].as_array_mut().unwrap().push(json!({
                "product": "casework", "project": "casework", "audience": "casework-service"
            }));
            value["people"]["operator"]["grants"]["casework"] = json!({
                "profile": "reviewer", "scopes": ["casework.read"]
            });
            let plan: Plan = serde_json::from_value(value).unwrap();
            let inspection = super::super::products::ProductInspection {
                breg_authority: Some(super::super::BregAuthority {
                    principal: "registry_principal".to_owned(),
                    purpose: false,
                    requires_postgis: false,
                    encrypts_fields: false,
                    named_clients: BTreeSet::new(),
                }),
                casework_principals: BTreeMap::from([(
                    "reviewer".to_owned(),
                    principal.to_owned(),
                )]),
            };

            let refusal = validate_application_authority(&plan, &inspection).unwrap_err();
            assert_eq!(refusal.field, "/people/operator/grants/casework/profile");
            assert!(refusal.reason.contains("Casework"));
        }
    }

    #[test]
    fn studio_journey_wire_variants_deserialize() {
        let (root, plan) = plan(json!({
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
        let scenarios = scenario_file(root.path(), &plan).scenarios;
        let step = &scenarios[0].steps[0];
        assert_eq!(step.expect.status.first(), 200);
        assert!(step.expect.status.contains(201));
        assert!(matches!(step.capture["etag"], Capture::Header { .. }));
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
        let mut value = serde_json::to_value(&plan).unwrap();
        let person = value["people"]
            .as_object_mut()
            .unwrap()
            .remove("operator")
            .unwrap();
        value["people"]["date_of_birth"] = person;
        value["people"]["date_of_birth"]["grants"]["breg"]["profile"] = json!("date_of_birth");
        let journey = json!({"id": "review_flow", "steps": [
            {
                "id": "read.v1", "product": "breg", "as": "date_of_birth",
                "method": "GET", "path": "/v1/records",
                "expect": {"status": [200, 202]},
                "capture": {"draftEtag": {"type": "pointer", "pointer": "/recordIdentifier"}},
                "poll": {"maximumWaitMilliseconds": 500, "pollIntervalMilliseconds": 50}
            },
            {
                "id": "use.v1", "product": "breg", "as": "date_of_birth",
                "method": "GET", "path": "/v1/records/{{draftEtag}}",
                "expect": {"status": 200}
            }
        ]});
        write_scenarios(root.path(), journey);
        value["schemaTestPeople"] = json!({
            "review_flow": {"read.v1": "date_of_birth"}
        });
        let plan: Plan = serde_json::from_value(value).unwrap();

        validate_all(&canonical(&root), &plan).unwrap();
    }

    #[test]
    fn a_project_reached_through_a_symlinked_parent_is_accepted() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        let links = tempfile::tempdir().unwrap();
        let link = links.path().join("parent-link");
        std::os::unix::fs::symlink(root.path(), &link).unwrap();

        plan.validate(&link).unwrap();
    }

    #[test]
    fn a_scenario_file_symlinked_outside_the_project_is_refused() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        let outside = tempfile::tempdir().unwrap();
        fs::copy(
            root.path().join("tests/scenarios.yaml"),
            outside.path().join("scenarios.yaml"),
        )
        .unwrap();
        fs::remove_file(root.path().join("tests/scenarios.yaml")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("scenarios.yaml"),
            root.path().join("tests/scenarios.yaml"),
        )
        .unwrap();

        let refusal = plan.validate(root.path()).unwrap_err().to_string();

        assert!(refusal.contains("/scenarioFile"), "{refusal}");
        assert!(
            refusal.contains("resolves outside the development project"),
            "{refusal}"
        );
        assert!(!refusal.contains("not found"), "{refusal}");
    }

    #[test]
    fn products_start_in_the_order_breg_then_casework_whatever_the_author_wrote() {
        let (_root, mut plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        plan.products.insert(
            0,
            serde_json::from_value(
                json!({"product": "casework", "project": "casework", "audience": "review"}),
            )
            .unwrap(),
        );
        plan.order_products_for_start();
        let order: Vec<_> = plan.products.iter().map(|entry| entry.product).collect();
        assert_eq!(order, [Product::Breg, Product::Casework]);
    }

    #[test]
    fn a_missing_scenario_file_is_reported_as_not_found() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200}
        }));
        fs::remove_file(root.path().join("tests/scenarios.yaml")).unwrap();

        let refusal = plan.validate(root.path()).unwrap_err().to_string();

        assert!(refusal.contains("/scenarioFile"), "{refusal}");
        assert!(
            refusal.contains("not found or is not a regular file"),
            "{refusal}"
        );
        assert!(!refusal.contains("resolves outside"), "{refusal}");
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

        let error = validate_all(&canonical(&root), &plan)
            .unwrap_err()
            .to_string();

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

        let error = validate_all(&canonical(&root), &plan)
            .unwrap_err()
            .to_string();

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
        let error = validate_all(&canonical(&root), &plan)
            .unwrap_err()
            .to_string();
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
        let error = format!("{:#}", validate_all(&canonical(&root), &plan).unwrap_err());
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
        let error = format!("{:#}", validate_all(&canonical(&root), &plan).unwrap_err());
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
        let error = validate_all(&canonical(&root), &plan)
            .unwrap_err()
            .to_string();
        assert!(error.contains("at most 250 attempts"), "{error}");
    }

    #[test]
    fn validation_accepts_the_studio_review_poll() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records", "expect": {"status": 200},
            "poll": {"maximumWaitMilliseconds": 60000, "pollIntervalMilliseconds": 250}
        }));
        validate_all(&canonical(&root), &plan).unwrap();
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
        let error = validate_all(&canonical(&root), &plan)
            .unwrap_err()
            .to_string();
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
                "scenarioFile": "tests/scenarios.yaml"
            })
        };
        write_scenarios(
            root.path(),
            json!({"id": "review", "steps": [{
                "id": "read", "product": "breg", "as": "reviewer",
                "method": "GET", "path": "/v1/records", "expect": {"status": 200}
            }]}),
        );
        let shared_scopes = ["casework:review", "registry:read"];
        let valid: Plan = serde_json::from_value(value("north", &shared_scopes)).unwrap();
        validate_all(&canonical(&root), &valid).unwrap();

        let mut one_sided_claim = value("north", &shared_scopes);
        one_sided_claim["people"]["reviewer"]["grants"]["breg"]["claims"]["extra"] = json!(true);
        for invalid in [
            value("south", &shared_scopes),
            value("north", &["casework:review"]),
            one_sided_claim,
        ] {
            let invalid: Plan = serde_json::from_value(invalid).unwrap();
            let error = validate_all(&canonical(&root), &invalid)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("same scopes and additional claims"),
                "{error}"
            );
        }
    }

    #[test]
    fn validation_accepts_a_step_naming_its_grant_profile() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records?accessProfile=operator",
            "expect": {"status": 200}
        }));
        validate_all(&canonical(&root), &plan).unwrap();
    }

    #[test]
    fn validation_refuses_a_step_naming_another_access_profile() {
        let (root, plan) = plan(json!({
            "id": "read", "product": "breg", "as": "operator",
            "method": "GET", "path": "/v1/records?accessProfile=applicant",
            "expect": {"status": 200}
        }));
        let error = validate_all(&canonical(&root), &plan)
            .unwrap_err()
            .to_string();
        for part in ["`read`", "`applicant`", "`operator`", "grant"] {
            assert!(error.contains(part), "{part}: {error}");
        }
    }

    #[test]
    fn a_plan_with_an_inline_journey_is_told_to_use_a_scenarios_file() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("registry.yaml"), "fixture").unwrap();
        fs::write(
            root.path().join("dev.yaml"),
            format!(
                "apiVersion: {API_VERSION}\nkind: {KIND}\nissuer: https://issuer.example.invalid\nproducts:\n  - {{product: breg, project: ., audience: registry}}\npeople:\n  operator:\n    subject: operator\n    client: operator-client\n    grants:\n      breg: {{profile: operator, scopes: []}}\njourney: {{id: smoke, steps: []}}\n"
            ),
        )
        .unwrap();
        let error = read_plan(root.path()).err().unwrap().to_string();
        assert!(error.contains("journey"), "{error}");
        assert!(error.contains("scenarioFile"), "{error}");
    }

    #[test]
    fn evidence_grant_requires_profile() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("evidence.yaml"), "fixture").unwrap();
        write_scenarios(
            root.path(),
            json!({"id": "ask", "steps": [{
                "id": "assert", "product": "evidence", "as": "caller",
                "method": "POST", "path": "/v1/evidence", "body": {},
                "expect": {"status": 200}
            }]}),
        );
        let plan = |grant: &str| {
            format!(
                "apiVersion: {API_VERSION}\nkind: {KIND}\nissuer: run\nproducts:\n  - {{product: evidence, project: ., audience: evidence}}\npeople:\n  caller:\n    subject: caller\n    client: caller-client\n    grants:\n      evidence: {grant}\nscenarioFile: tests/scenarios.yaml\n"
            )
        };

        fs::write(
            root.path().join("dev.yaml"),
            plan("{profile: local-service, scopes: [\"evidence:request\"]}"),
        )
        .unwrap();
        let decoded = read_plan(root.path()).unwrap();
        validate_plan(root.path(), &decoded).unwrap();
        assert_eq!(decoded.value.products[0].product, Product::Evidence);
        assert!(decoded.value.people["caller"]
            .grants
            .contains_key(&Product::Evidence));

        fs::write(
            root.path().join("dev.yaml"),
            plan("{scopes: [\"evidence:request\"]}"),
        )
        .unwrap();
        let error = read_plan(root.path()).err().unwrap().to_string();
        assert!(error.contains("profile"), "{error}");
    }

    /// A Messaging-only plan: the project holds `messaging.yaml`, the run issuer
    /// is an HTTPS name (Messaging verifies tokens against the run's static key
    /// set), and the grant is the Messaging access profile with its scopes.
    #[test]
    fn messaging_plan_and_grant_decode_and_validate() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("messaging.yaml"), "fixture").unwrap();
        write_scenarios(
            root.path(),
            json!({"id": "send", "steps": [{
                "id": "list", "product": "messaging", "as": "operator",
                "method": "GET", "path": "/v1/messages",
                "expect": {"status": 200}
            }]}),
        );
        let plan = |issuer: &str, grant: &str| {
            format!(
                "apiVersion: {API_VERSION}\nkind: {KIND}\nissuer: {issuer}\nproducts:\n  - {{product: messaging, project: ., audience: urn:example:messaging}}\npeople:\n  operator:\n    subject: operator\n    client: operations-console\n    grants:\n      messaging: {grant}\nscenarioFile: tests/scenarios.yaml\n"
            )
        };

        fs::write(
            root.path().join("dev.yaml"),
            plan(
                "https://issuer.example.invalid",
                "{profile: operations, scopes: [\"messaging:operate\"]}",
            ),
        )
        .unwrap();
        let decoded = read_plan(root.path()).unwrap();
        validate_plan(root.path(), &decoded).unwrap();
        assert_eq!(decoded.value.products[0].product, Product::Messaging);
        assert_eq!(Product::Messaging.name(), "messaging");
        assert_eq!(
            decoded.value.people["operator"].grants[&Product::Messaging].profile,
            "operations"
        );

        // Messaging verifies a static key set, so it does not own the run issuer.
        fs::write(
            root.path().join("dev.yaml"),
            plan("run", "{profile: operations, scopes: []}"),
        )
        .unwrap();
        let decoded = read_plan(root.path()).unwrap();
        let refusal = validate_plan(root.path(), &decoded).err().unwrap();
        assert!(format!("{refusal:#}").contains("/issuer"), "{refusal:#}");

        fs::write(
            root.path().join("dev.yaml"),
            plan("https://issuer.example.invalid", "{scopes: []}"),
        )
        .unwrap();
        let error = read_plan(root.path()).err().unwrap().to_string();
        assert!(error.contains("profile"), "{error}");
    }
    #[test]
    fn new_products_have_closed_grants_and_discovery_needs_none() {
        for (name, manifest) in [
            ("scheduling", "scheduling.yaml"),
            ("documents", "documents.yaml"),
            ("coordinator", "workflow.yaml"),
            ("adapter", "project.yaml"),
            ("render", "manifest.yaml"),
            ("discovery", "origins.yaml"),
        ] {
            let root = tempfile::tempdir().unwrap();
            fs::write(root.path().join(manifest), "fixture").unwrap();
            fs::create_dir(root.path().join("tests")).unwrap();
            fs::write(root.path().join("tests/scenarios.yaml"), "fixture").unwrap();
            let plan = |people: Value| {
                json!({
                    "apiVersion": API_VERSION,
                    "kind": KIND,
                    "issuer": "https://issuer.example.invalid",
                    "products": [{"product": name, "project": ".", "audience": name}],
                    "people": people,
                    "scenarioFile": "tests/scenarios.yaml",
                })
            };
            let people = if name == "discovery" {
                json!({})
            } else {
                json!({"operator": {"subject": "operator", "client": "console",
                    "grants": {name: {"profile": "console", "scopes": []}}}})
            };
            let file = root.path().join("dev.yaml");
            fs::write(&file, plan(people).to_string()).unwrap();
            let decoded =
                read_plan(root.path()).unwrap_or_else(|error| panic!("{name}: {error:#}"));
            validate_plan(root.path(), &decoded)
                .unwrap_or_else(|error| panic!("{name}: {error:#}"));
            assert_eq!(decoded.value.products[0].product.name(), name);

            if name != "discovery" {
                fs::write(root.path().join("messaging.yaml"), "fixture").unwrap();
                let mut missing_grant = plan(json!({
                    "operator": {"subject": "operator", "client": "console",
                        "grants": {"messaging": {"profile": "operator", "scopes": []}}}
                }));
                missing_grant["products"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({
                        "product": "messaging", "project": ".", "audience": "messaging"
                    }));
                fs::write(&file, missing_grant.to_string()).unwrap();
                let decoded = read_plan(root.path()).unwrap();
                let error = validate_plan(root.path(), &decoded).unwrap_err();
                assert!(format!("{error:#}").contains(&format!(
                    "The plan must define at least one grant for {name}."
                )));
            }
        }
    }
    #[test]
    fn coordinator_grant_conflicts_are_reported_at_the_grant() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("workflow.yaml"), "fixture").unwrap();
        fs::write(root.path().join("scenarios.yaml"), "fixture").unwrap();
        let mut plan = json!({
            "apiVersion": API_VERSION, "kind": KIND,
            "issuer": "https://issuer.example.invalid",
            "products": [{"product": "coordinator", "project": ".", "audience": "coordinator"}],
            "people": {
                "first": {"subject": "first", "client": "console",
                    "grants": {"coordinator": {"profile": "console", "scopes": ["status"]}}},
                "second": {"subject": "second", "client": "console",
                    "grants": {"coordinator": {"profile": "reader", "scopes": ["start"]}}},
            },
            "scenarioFile": "scenarios.yaml",
        });
        for (field, fix) in [("profile", json!("console")), ("scopes", json!(["status"]))] {
            let pointer = format!("/people/second/grants/coordinator/{field}");
            fs::write(root.path().join("dev.yaml"), plan.to_string()).unwrap();
            let decoded = read_plan(root.path()).unwrap();
            let error = validate_plan(root.path(), &decoded).unwrap_err();
            assert!(format!("{error:#}").contains(&pointer), "{error:#}");
            *plan.pointer_mut(&pointer).unwrap() = fix;
        }
        fs::write(root.path().join("dev.yaml"), plan.to_string()).unwrap();
        validate_plan(root.path(), &read_plan(root.path()).unwrap()).unwrap();
    }

    #[test]
    fn plan_does_not_accept_authentication_overrides_or_unknown_grants() {
        let root = tempfile::tempdir().unwrap();
        let valid = json!({
            "apiVersion": API_VERSION,
            "kind": KIND,
            "issuer": "https://issuer.example.invalid",
            "products": [{"product": "scheduling", "project": ".", "audience": "urn:scheduling"}],
            "people": {"reader": {"subject": "reader", "client": "console",
                "grants": {"scheduling": {"profile": "reader", "scopes": []}}}},
            "scenarioFile": "scenarios.yaml",
        });
        for (pointer, field) in [
            ("", "issuerUrl"),
            ("/products/0", "jwksUri"),
            ("/people/reader/grants", "unknown"),
            ("/people/reader/grants/scheduling", "role"),
        ] {
            let mut invalid = valid.clone();
            invalid.pointer_mut(pointer).unwrap()[field] = json!("unexpected");
            fs::write(root.path().join("dev.yaml"), invalid.to_string()).unwrap();
            let error = read_plan(root.path())
                .err()
                .expect("unknown member refused");
            assert!(
                error.to_string().contains(&format!("{pointer}/{field}")),
                "{error:#}"
            );
        }
    }
}

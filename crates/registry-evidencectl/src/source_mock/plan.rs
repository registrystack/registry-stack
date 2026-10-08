//! Strict materialized source-mock plan.
//!
//! This module owns only the authored storage contract. OpenAPI discovery,
//! generation, and response-schema validation remain with their respective
//! source-mock stages.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display, Formatter},
    path::{Component, Path},
    str::FromStr,
};

use anyhow::{bail, Context as _, Result};
use chrono::{Datelike as _, NaiveDate};
use registry_evidence_authoring::{
    formats::{decode_authored, envelope_lines, MOCK_PLAN, MOCK_PLAN_API_VERSION, MOCK_PLAN_KIND},
    valid_local_identifier,
};
use registry_platform_yaml::Report;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// The generator contract written by initial V1 materialization.
pub(super) const GENERATOR_CONTRACT: &str = "evidencectl-source-mock-v1";
/// A plan is authoring metadata, not a bulk-data container: it is held to
/// the document size the shared reader accepts, which reads it.
pub(super) const MAX_PLAN_BYTES: usize = registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES;
/// The largest seed a plan stores: the greatest integer every JSON consumer
/// reads exactly.
pub(super) const MAX_SEED: u64 = 9_007_199_254_740_991;
pub(super) const MAX_OPERATIONS: usize = 256;
pub(super) const MAX_CASES_PER_OPERATION: usize = 256;
pub(super) const MAX_TOTAL_CASES: usize = 1024;
pub(super) const MAX_DATASETS: usize = 128;
pub(super) const MAX_PATH_BYTES: usize = 512;
pub(super) const MAX_PATH_PARAMETERS: usize = 16;
pub(super) const MAX_PATH_PARAMETER_BYTES: usize = 4096;

/// One strict `mocks/source.yaml` document. Its format version is the
/// document's `apiVersion`, which the shared reader checks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct MockPlan {
    pub openapi: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::Digest>")
    )]
    pub openapi_digest: Option<Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<GenerationSettings>,
    pub operations: Vec<PlanOperation>,
}

/// Settings retained solely so `generate --config` can create missing bodies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct GenerationSettings {
    pub contract: String,
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 0, max = 9_007_199_254_740_991_u64))
    )]
    pub seed: u64,
    pub as_of: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "BTreeMap<registry_platform_yaml::LocalId, registry_platform_yaml::Digest>"
        )
    )]
    pub datasets: BTreeMap<String, Digest>,
}

impl GenerationSettings {
    pub fn as_of_date(&self) -> Result<NaiveDate> {
        let date = NaiveDate::parse_from_str(&self.as_of, "%Y-%m-%d")
            .context("generation.asOf must be an ISO calendar date")?;
        if !(1900..=9999).contains(&date.year()) {
            bail!("generation.asOf year is outside 1900..=9999");
        }
        Ok(date)
    }
}

/// One configured GET operation. Method plus templated path is its identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PlanOperation {
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub response: PlanResponse,
    pub cases: Vec<PlanCase>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PlanResponse {
    #[cfg_attr(feature = "schema", schemars(range(min = 200, max = 200)))]
    pub status: u16,
    pub media_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PlanCase {
    pub name: String,
    pub request: PlanRequest,
    pub body: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PlanRequest {
    #[cfg_attr(feature = "schema", schemars(schema_with = "path_parameters_schema"))]
    pub path_parameters: BTreeMap<String, Value>,
}

/// The closed shape of a case's path parameter bindings: each template
/// parameter name maps to one safe scalar.
#[cfg(feature = "schema")]
fn path_parameters_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let names = generator.subschema_for::<registry_platform_yaml::ExternalId>();
    schemars::json_schema!({
        "type": "object",
        "propertyNames": names,
        "maxProperties": MAX_PATH_PARAMETERS,
        "additionalProperties": {
            "anyOf": [
                {"type": "string", "maxLength": MAX_PATH_PARAMETER_BYTES},
                {"type": "boolean"},
                {"type": "number"}
            ]
        }
    })
}

/// A syntactically valid lowercase SHA-256 label.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct Digest([u8; 32]);

impl Digest {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Display for Digest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "sha256:{}", hex::encode(self.0))
    }
}

impl FromStr for Digest {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let Some(encoded) = value.strip_prefix("sha256:") else {
            bail!("digest must use sha256 lowercase-hex syntax");
        };
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            bail!("digest must use sha256 lowercase-hex syntax");
        }
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(encoded, &mut bytes)
            .context("digest must use sha256 lowercase-hex syntax")?;
        Ok(Self(bytes))
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// Read one complete plan through the shared reader, then validate its
/// structure.
#[cfg(test)]
pub(super) fn parse_plan(file: &str, bytes: &[u8]) -> Result<MockPlan> {
    Ok(parse_plan_reporting(file, bytes)?.0)
}

/// Parse a plan and keep the warnings the reader reported on it.
pub(super) fn parse_plan_reporting(file: &str, bytes: &[u8]) -> Result<(MockPlan, Report)> {
    let decoded = decode_authored::<MockPlan>(file, bytes, &MOCK_PLAN)?;
    validate_plan(&decoded.value)?;
    Ok((decoded.value, decoded.document.warnings()))
}

/// Render the stable authored YAML spelling, envelope first, with one
/// trailing newline.
pub(super) fn render_plan(plan: &MockPlan) -> Result<Vec<u8>> {
    validate_plan(plan)?;
    let mut rendered = envelope_lines(MOCK_PLAN_API_VERSION, MOCK_PLAN_KIND);
    rendered
        .push_str(&crate::authored::to_indented_yaml(plan).context("failed to render mock plan")?);
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    if rendered.len() > MAX_PLAN_BYTES {
        bail!("rendered mock plan exceeds its byte limit");
    }
    Ok(rendered.into_bytes())
}

/// Validate the closed V1 structure without reading any referenced artifact.
pub(super) fn validate_plan(plan: &MockPlan) -> Result<()> {
    validate_config_reference(&plan.openapi, "openapi")?;
    if let Some(generation) = &plan.generation {
        if generation.contract != GENERATOR_CONTRACT {
            bail!("generation.contract is not the V1 generator contract");
        }
        if generation.seed > MAX_SEED {
            bail!("generation.seed exceeds the largest exactly representable integer");
        }
        generation.as_of_date()?;
        if generation.datasets.len() > MAX_DATASETS {
            bail!("generation.datasets exceeds its entry limit");
        }
        if generation
            .datasets
            .keys()
            .any(|identifier| !valid_local_identifier(identifier))
        {
            bail!("generation.datasets contains an invalid local identifier");
        }
    }
    if plan.operations.is_empty() || plan.operations.len() > MAX_OPERATIONS {
        bail!("operations must contain a bounded non-empty set");
    }

    let mut operation_identities = BTreeSet::new();
    let mut body_paths = BTreeSet::new();
    let mut expanded_routes = BTreeSet::new();
    let mut total_cases = 0usize;
    for (operation_index, operation) in plan.operations.iter().enumerate() {
        validate_operation(operation, operation_index)?;
        if !operation_identities.insert((&operation.method, &operation.path)) {
            bail!("operations contains a repeated method and path identity");
        }
        total_cases = total_cases
            .checked_add(operation.cases.len())
            .context("case count exceeds its limit")?;
        let parameter_names = path_parameter_names(&operation.path)?;
        let mut case_names = BTreeSet::new();
        for (case_index, case) in operation.cases.iter().enumerate() {
            if !valid_local_identifier(&case.name) {
                bail!("operation {operation_index} case {case_index} has an invalid local name");
            }
            if !case_names.insert(&case.name) {
                bail!("operation {operation_index} repeats a case name");
            }
            validate_relative_path(&case.body, "case body")?;
            if !body_paths.insert(&case.body) {
                bail!("mock plan assigns one body path to more than one case");
            }
            if case.request.path_parameters.len() > MAX_PATH_PARAMETERS {
                bail!("operation {operation_index} case {case_index} has too many path parameters");
            }
            let actual = case
                .request
                .path_parameters
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if actual != parameter_names {
                bail!("operation {operation_index} case {case_index} does not exactly bind its path parameters");
            }
            let expanded = expand_path(&operation.path, &case.request.path_parameters)?;
            if !expanded_routes.insert((operation.method.as_str(), expanded)) {
                bail!("mock plan contains structurally duplicate concrete routes");
            }
        }
    }
    if total_cases > MAX_TOTAL_CASES {
        bail!("mock plan exceeds its total case limit");
    }
    Ok(())
}

fn validate_operation(operation: &PlanOperation, index: usize) -> Result<()> {
    if operation.method != "GET" {
        bail!("operation {index} method must be GET");
    }
    validate_route_template(&operation.path)?;
    if operation.response.status != 200 || operation.response.media_type != "application/json" {
        bail!("operation {index} response must be 200 application/json");
    }
    if operation.cases.is_empty() || operation.cases.len() > MAX_CASES_PER_OPERATION {
        bail!("operation {index} cases must contain a bounded non-empty set");
    }
    if operation.operation_id.as_ref().is_some_and(|identifier| {
        identifier.is_empty() || identifier.len() > 256 || identifier.chars().any(char::is_control)
    }) {
        bail!("operation {index} operationId is invalid");
    }
    Ok(())
}

fn validate_route_template(path: &str) -> Result<()> {
    if path.len() > MAX_PATH_BYTES
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['?', '#', '\\'])
        || path.chars().any(char::is_control)
    {
        bail!("operation path is outside the closed route-template grammar");
    }
    if path == "/" {
        return Ok(());
    }
    for segment in path.split('/').skip(1) {
        if segment.is_empty() || matches!(segment, "." | "..") {
            bail!("operation path is outside the closed route-template grammar");
        }
        if segment.contains(['{', '}'])
            && !(segment.starts_with('{')
                && segment.ends_with('}')
                && segment[1..segment.len() - 1]
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
                && segment.len() > 2)
        {
            bail!("operation path contains a partial or invalid template segment");
        }
    }
    Ok(())
}

fn path_parameter_names(path: &str) -> Result<BTreeSet<&str>> {
    let mut names = BTreeSet::new();
    for segment in path.split('/').skip(1) {
        if let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            if !names.insert(name) {
                bail!("operation path repeats a template parameter");
            }
        }
    }
    Ok(names)
}

pub(super) fn expand_path(path: &str, parameters: &BTreeMap<String, Value>) -> Result<String> {
    if path == "/" {
        return Ok(path.to_owned());
    }
    let mut expanded = String::new();
    for segment in path.split('/').skip(1) {
        expanded.push('/');
        if let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            let value = parameters
                .get(name)
                .context("path parameter binding is incomplete")?;
            let text = path_scalar(value)?;
            if text.is_empty() || text.len() > MAX_PATH_PARAMETER_BYTES {
                bail!("path parameter value is outside its storage bound");
            }
            expanded.push_str(&percent_encode_segment(&text));
        } else {
            expanded.push_str(segment);
        }
    }
    Ok(expanded)
}

fn path_scalar(value: &Value) -> Result<String> {
    match value {
        Value::String(text)
            if !text.chars().any(char::is_control) && !text.contains(['/', '\\']) =>
        {
            Ok(text.clone())
        }
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        _ => bail!("path parameter value must be a safe scalar"),
    }
}

fn percent_encode_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("writing to a string cannot fail");
        }
    }
    encoded
}

/// Validate a body or dataset path. These paths never admit parent traversal.
pub(super) fn validate_relative_path(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        bail!("{label} must be a bounded normalized relative path");
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || value.split('/').any(str::is_empty)
    {
        bail!("{label} must be a bounded normalized relative path");
    }
    Ok(())
}

/// Validate the config-relative OpenAPI spelling. Parent components are
/// admitted here only because resolution later confines the normalized result
/// beneath an explicitly held project root.
fn validate_config_reference(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || Path::new(value).is_absolute()
        || value
            .split('/')
            .any(|segment| segment.is_empty() || segment == ".")
    {
        bail!("{label} must be a bounded config-relative path");
    }
    Ok(())
}

/// The derived JSON Schema of one mock plan document.
#[cfg(feature = "schema")]
pub(crate) fn plan_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(MockPlan)).expect("a derived schema is JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn plan() -> MockPlan {
        MockPlan {
            openapi: "../source.openapi.yaml".to_owned(),
            openapi_digest: Some(
                format!("sha256:{}", "a".repeat(64))
                    .parse()
                    .expect("digest"),
            ),
            generation: Some(GenerationSettings {
                contract: GENERATOR_CONTRACT.to_owned(),
                seed: 0,
                as_of: "2025-01-01".to_owned(),
                datasets: BTreeMap::new(),
            }),
            operations: vec![PlanOperation {
                method: "GET".to_owned(),
                path: "/people/{person_id}".to_owned(),
                operation_id: None,
                response: PlanResponse {
                    status: 200,
                    media_type: "application/json".to_owned(),
                },
                cases: vec![PlanCase {
                    name: "sample".to_owned(),
                    request: PlanRequest {
                        path_parameters: BTreeMap::from([(
                            "person_id".to_owned(),
                            json!("person-123"),
                        )]),
                    },
                    body: "cases/get-people/sample.json".to_owned(),
                }],
            }],
        }
    }

    #[test]
    fn plan_round_trips_in_a_stable_strict_spelling() {
        let first = render_plan(&plan()).expect("render");
        let parsed = parse_plan("source.yaml", &first).expect("parse");
        let second = render_plan(&parsed).expect("render again");

        assert_eq!(first, second);
        assert!(first.ends_with(b"\n"));
        assert!(String::from_utf8_lossy(&first).contains("operations:\n  - method:"));
        assert!(String::from_utf8(first)
            .expect("UTF-8")
            .contains("openapiDigest: sha256:aaaaaaaa"));
    }

    #[test]
    fn unknown_retired_and_duplicate_keys_are_refused_by_the_reader() {
        let codes = |text: &str| {
            let error = parse_plan("source.yaml", text.as_bytes()).expect_err("refused");
            crate::authored::report_in(&error)
                .expect("the reader's report")
                .diagnostics()
                .iter()
                .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
                .collect::<Vec<_>>()
        };
        let rendered = String::from_utf8(render_plan(&plan()).expect("render")).unwrap();
        assert!(rendered.starts_with(
            "apiVersion: id.registrystack.org/formats/evidence/mock-plan/v1alpha1\nkind: EvidenceMockPlan\n"
        ));
        assert_eq!(
            codes(&format!("{rendered}unknown: true\n")),
            [("config.unknown-key".to_owned(), "/unknown".to_owned())]
        );
        assert_eq!(
            codes(&format!("{rendered}version: 1\n")),
            [("config.removed-key".to_owned(), "/version".to_owned())]
        );
        assert_eq!(
            codes("version: 1\nopenapi: ../source.openapi.yaml\noperations: []\n"),
            [
                ("config.missing-envelope".to_owned(), String::new()),
                ("config.removed-key".to_owned(), "/version".to_owned())
            ]
        );
        let duplicate = rendered.replace(
            "openapi: ../source.openapi.yaml\n",
            "openapi: ../source.openapi.yaml\nopenapi: ../source.openapi.yaml\n",
        );
        assert_eq!(codes(&duplicate)[0].0, "yaml.duplicate-key");
    }

    #[test]
    fn digest_syntax_is_exact_lowercase_sha256() {
        let valid = format!("sha256:{}", "f".repeat(64));
        assert_eq!(valid.parse::<Digest>().unwrap().to_string(), valid);
        for invalid in [
            format!("sha256:{}", "F".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha512:{}", "a".repeat(64)),
        ] {
            assert!(invalid.parse::<Digest>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn a_seed_beyond_the_exact_integer_range_is_refused() {
        let mut at_the_bound = plan();
        at_the_bound.generation.as_mut().expect("generation").seed = MAX_SEED;
        assert!(validate_plan(&at_the_bound).is_ok());
        let mut past_the_bound = plan();
        past_the_bound.generation.as_mut().expect("generation").seed = MAX_SEED + 1;
        assert!(validate_plan(&past_the_bound).is_err());
    }

    #[test]
    fn duplicate_operation_case_body_and_concrete_route_shapes_are_refused() {
        let mut duplicate_operation = plan();
        duplicate_operation
            .operations
            .push(duplicate_operation.operations[0].clone());
        assert!(validate_plan(&duplicate_operation).is_err());

        let mut duplicate_case = plan();
        let repeated_case = duplicate_case.operations[0].cases[0].clone();
        duplicate_case.operations[0].cases.push(repeated_case);
        assert!(validate_plan(&duplicate_case).is_err());

        let mut duplicate_route = plan();
        let mut second = duplicate_route.operations[0].cases[0].clone();
        second.name = "second".to_owned();
        second.body = "cases/get-people/second.json".to_owned();
        duplicate_route.operations[0].cases.push(second);
        assert!(validate_plan(&duplicate_route).is_err());
    }

    #[test]
    fn body_paths_are_traversal_free_but_openapi_may_name_its_project_parent() {
        assert!(validate_config_reference("../source.openapi.yaml", "openapi").is_ok());
        assert!(validate_relative_path("cases/a.json", "body").is_ok());
        for invalid in ["../a.json", "/a.json", "cases/../a.json", "cases//a.json"] {
            assert!(validate_relative_path(invalid, "body").is_err());
        }
    }

    #[test]
    fn path_bindings_are_exact_safe_scalars() {
        let mut missing = plan();
        missing.operations[0].cases[0]
            .request
            .path_parameters
            .clear();
        assert!(validate_plan(&missing).is_err());

        let mut slash = plan();
        slash.operations[0].cases[0]
            .request
            .path_parameters
            .insert("person_id".to_owned(), json!("one/two"));
        assert!(validate_plan(&slash).is_err());
    }

    #[test]
    fn root_operation_paths_validate_and_expand_to_slash() {
        let mut root = plan();
        root.operations[0].path = "/".to_owned();
        root.operations[0].cases[0].request.path_parameters.clear();

        assert!(validate_plan(&root).is_ok());
        assert_eq!(expand_path("/", &BTreeMap::new()).unwrap(), "/");
    }

    #[test]
    fn invalid_generation_metadata_is_refused_without_needing_generation() {
        let mut hand_authored = plan();
        hand_authored.generation = None;
        hand_authored.openapi_digest = None;
        assert!(validate_plan(&hand_authored).is_ok());

        let mut invalid = plan();
        invalid.generation.as_mut().unwrap().as_of = "1899-12-31".to_owned();
        assert!(validate_plan(&invalid).is_err());
    }
}

// SPDX-License-Identifier: Apache-2.0

//! The pure authoring checks over parsed artifacts (`products/adapter/CONCEPT.md`
//! sections 5.5, 7, 8.7, 8.10, and 10.2). No I/O: every check takes parsed
//! values and returns [`registry_platform_yaml::Diagnostic`]s carrying
//! closed `adapter.*` codes. Accept and reject behavior is pinned by the
//! tests of this module.

use crate::auth::{is_reserved_header_name, EndpointAuthentication, RuntimeCredential};
use crate::diagnostics::{finding, CheckCode};
use crate::fixture::{AdapterFixture, Intercept};
use crate::model::{Expression, SendComponent};
use crate::pack::AdapterPack;
use crate::profile::{
    AdapterProfile, EnvelopeTemplate, ProfileOperation, SLOT_PROBLEM_CODE, SLOT_RECORD,
    SLOT_RECORDS,
};
use crate::project::AdapterProject;
use crate::route::{Step, TemplateParameterType};
use crate::runtime::AdapterRuntimeConfig;
use registry_platform_yaml::{Diagnostic, Digest, ExternalId};
use std::collections::{HashMap, HashSet};

/// The deepest `direct:` call chain the graph may form
/// (`products/adapter/CONCEPT.md` section 8.3).
pub const MAX_DIRECT_DEPTH: usize = 16;

/// The headers the rest consumer places on the exchange before a route
/// runs; a route reads them, never writes them
/// (`products/adapter/CONCEPT.md` section 8.11.1). Lowercase; names
/// compare without case.
const FACADE_INPUT_HEADERS: &[&str] = &["idempotency-key", "pagesize", "recordid", "recordtype"];

/// The headers the engine itself places on the exchange; a route reads
/// them, never writes them (`products/adapter/CONCEPT.md` lines covering
/// the engine-set Camel headers). Lowercase; names compare without case.
const ENGINE_HEADERS: &[&str] = &[
    "camelduplicatemessage",
    "camelexceptioncaught",
    "camelfiltermatched",
    "camelhttpresponsecode",
    "camelloopindex",
    "camelsplitcomplete",
    "camelsplitindex",
    "camelsplitsize",
];

/// The credential, cookie, and hop-by-hop header names a route never
/// writes or removes (`products/adapter/CONCEPT.md` section 8.11.4,
/// never-allowlistable list). Lowercase, sorted; names compare without
/// case, and the `proxy-` prefix joins them.
const RESERVED_ROUTE_HEADER_WRITES: &[&str] = &[
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "host",
    "keep-alive",
    "set-cookie",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Whether a route may write (set or remove) the named header. Reserved
/// names, the `proxy-` prefix, engine-placed Camel headers, and the
/// facade inputs all refuse.
fn is_reserved_header_write(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    RESERVED_ROUTE_HEADER_WRITES.contains(&lower.as_str())
        || FACADE_INPUT_HEADERS.contains(&lower.as_str())
        || ENGINE_HEADERS.contains(&lower.as_str())
        || lower.starts_with("proxy-")
}

/// Whether a route may read the named header: a facade input, an
/// engine-placed header, a response header some endpoint allowlist
/// declares, or a header an earlier step of the same body set.
fn is_header_read_known(name: &str, placed: &HashSet<String>, allowlist: &HashSet<String>) -> bool {
    let lower = name.to_ascii_lowercase();
    FACADE_INPUT_HEADERS.contains(&lower.as_str())
        || ENGINE_HEADERS.contains(&lower.as_str())
        || placed.contains(lower.as_str())
        || allowlist.contains(lower.as_str())
}

/// The valid placeholder references of an envelope or template text:
/// `(name, optional)` pairs for every `{{name}}` and `{{?name}}`. Any other
/// text passes through; `has_malformed_placeholder` refuses a `{{` that
/// opens neither form.
#[must_use]
pub fn placeholders(text: &str) -> Vec<(String, bool)> {
    let mut found = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'{' && bytes[index + 1] == b'{' {
            if let Some(close) = text[index..].find("}}") {
                let inner = &text[index + 2..index + close];
                let (name, optional) = match inner.strip_prefix('?') {
                    Some(stripped) => (stripped, true),
                    None => (inner, false),
                };
                if is_placeholder_name(name) {
                    found.push((name.to_string(), optional));
                    index += close + 2;
                    continue;
                }
            }
        }
        index += 1;
    }
    found
}

/// Whether an envelope or template text carries a `{{` that opens neither a
/// valid required nor a valid optional placeholder.
#[must_use]
pub fn has_malformed_placeholder(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'{' && bytes[index + 1] == b'{' {
            if let Some(close) = text[index..].find("}}") {
                let inner = &text[index + 2..index + close];
                let name = inner.strip_prefix('?').unwrap_or(inner);
                if is_placeholder_name(name) {
                    index += close + 2;
                    continue;
                }
            }
            return true;
        }
        index += 1;
    }
    false
}

/// The character set a placeholder name may carry.
/// Whether a placeholder text is a valid `{{name}}` name: an ASCII
/// alphabetic lead and alphanumeric, `_`, or `-` thereafter. Public so the
/// envelope-template parse shares one name rule with the scanner.
pub fn is_placeholder_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|rest| rest.is_ascii_alphanumeric() || rest == '_' || rest == '-')
}

/// The artifacts one deployment composes, passed together to the
/// cross-artifact checks.
pub struct Workspace<'a> {
    pub profile: &'a AdapterProfile,
    pub pack: &'a AdapterPack,
    pub project: &'a AdapterProject,
    pub runtime: Option<&'a AdapterRuntimeConfig>,
    pub fixtures: &'a [AdapterFixture],
}

/// The route bodies a `direct:` name resolves to, keyed by the route's
/// `from` URI as Camel connects routes: a pack route by its from name, a
/// template by its id, and an instantiation by its route id (its from
/// becomes `direct:<routeId>`).
fn route_bodies<'a>(
    pack: &'a AdapterPack,
    project: &'a AdapterProject,
) -> HashMap<&'a str, &'a [Step]> {
    let mut bodies: HashMap<&str, &[Step]> = HashMap::new();
    for route in &pack.routes {
        bodies.insert(route.from.uri.id.as_str(), route.steps.as_slice());
    }
    for template in &pack.route_templates {
        bodies.insert(template.id.as_str(), template.steps.as_slice());
    }
    for instantiated in &project.templated_routes {
        if let Some(template) = pack
            .route_templates
            .get(instantiated.route_template.as_str())
        {
            bodies.insert(instantiated.route_id.as_str(), template.steps.as_slice());
        }
    }
    bodies
}

/// The route bodies a binding's route reference resolves to, keyed by the
/// declared id: a pack route by its id, a template by its id, and an
/// instantiation by its route id.
fn route_bodies_by_id<'a>(
    pack: &'a AdapterPack,
    project: &'a AdapterProject,
) -> HashMap<&'a str, &'a [Step]> {
    let mut bodies: HashMap<&str, &[Step]> = HashMap::new();
    for route in &pack.routes {
        bodies.insert(route.id.as_str(), route.steps.as_slice());
    }
    for template in &pack.route_templates {
        bodies.insert(template.id.as_str(), template.steps.as_slice());
    }
    for instantiated in &project.templated_routes {
        if let Some(template) = pack
            .route_templates
            .get(instantiated.route_template.as_str())
        {
            bodies.insert(instantiated.route_id.as_str(), template.steps.as_slice());
        }
    }
    bodies
}

/// Run every check over one composed workspace.
#[must_use]
pub fn check_workspace(workspace: &Workspace<'_>) -> Vec<Diagnostic> {
    let mut findings = check_profile(workspace.profile);
    findings.extend(check_pack(workspace.pack));
    findings.extend(check_routes(workspace.pack, workspace.project));
    findings.extend(check_project(workspace));
    findings.extend(crate::result_schema::check_envelope_derivation(
        workspace.profile,
        workspace.project,
    ));
    if let Some(runtime) = workspace.runtime {
        findings.extend(check_runtime(workspace, runtime));
    }
    findings.extend(check_fixtures(workspace));
    findings
}

/// Profile checks (`products/adapter/CONCEPT.md` section 7): envelope
/// grammar, the closed slot vocabulary, and the result, record, and code
/// slots.
#[must_use]
pub fn check_profile(profile: &AdapterProfile) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for (index, operation) in profile.operations.iter().enumerate() {
        let prefix = format!("/operations/{index}");
        if let Some(fault) = origin_relative_path_fault(&operation.path) {
            findings.push(finding(
                CheckCode::ProfileInvalidPath,
                &format!("{prefix}/path"),
                fault,
                "Author the path origin-relative: a leading slash, no scheme or authority, and no `..` segment.",
            ));
        }
        findings.extend(envelope_checks(&prefix, &operation.response_envelope));
        if !(operation.response_envelope.mentions(SLOT_RECORD)
            || operation.response_envelope.mentions(SLOT_RECORDS))
        {
            findings.push(finding(
                CheckCode::ProfileResponseEnvelopeMissingResultSlot,
                &prefix,
                "the response envelope names no result slot",
                "Place the record or records slot where the route result lands.",
            ));
        }
        if !operation.method.is_safe() {
            findings.extend(request_envelope_checks(&prefix, operation));
        }
    }
    findings.extend(envelope_checks(
        "/problemEnvelope",
        &profile.problem_envelope,
    ));
    if !profile.problem_envelope.mentions(SLOT_PROBLEM_CODE) {
        findings.push(finding(
            CheckCode::ProfileProblemEnvelopeMissingCodeSlot,
            "/problemEnvelope",
            "the problem envelope carries no {{problemCode}} slot",
            "Place the problemCode slot in the problem envelope.",
        ));
    }
    findings
}

/// The origin-relative fault of an authored static path, if any: no
/// scheme or authority, no `..` segment, and a leading slash. The fault
/// text never quotes the path.
fn origin_relative_path_fault(path: &str) -> Option<&'static str> {
    if path.contains("://") {
        return Some("the path carries a scheme");
    }
    if path.starts_with("//") {
        return Some("the path carries an authority");
    }
    if !path.starts_with('/') {
        return Some("the path lacks a leading slash");
    }
    if path.split(['/', '?', '#']).any(|segment| segment == "..") {
        return Some("the path escapes the origin with a `..` segment");
    }
    None
}

fn request_envelope_checks(prefix: &str, operation: &ProfileOperation) -> Vec<Diagnostic> {
    let Some(request_envelope) = &operation.request_envelope else {
        return vec![finding(
            CheckCode::ProfileRequestEnvelopeMissingRecordSlot,
            &format!("{prefix}/requestEnvelope"),
            "a write operation declares no request envelope",
            "Declare where the writable record sits in an incoming body.",
        )];
    };
    let mut findings = envelope_checks(&format!("{prefix}/requestEnvelope"), request_envelope);
    if !request_envelope.mentions(SLOT_RECORD) {
        findings.push(finding(
            CheckCode::ProfileRequestEnvelopeMissingRecordSlot,
            &format!("{prefix}/requestEnvelope"),
            "the request envelope of a write operation names no {{record}} slot",
            "Place the record slot where the writable record sits in the body.",
        ));
    }
    findings
}

fn envelope_checks(path: &str, envelope: &EnvelopeTemplate) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    if has_malformed_placeholder(envelope.text()) {
        findings.push(finding(
            CheckCode::EnvelopeInvalidPlaceholder,
            path,
            "the envelope carries a malformed placeholder",
            "Write placeholders as {{name}} or {{?name}}.",
        ));
    }
    for (name, _) in placeholders(envelope.text()) {
        if !crate::profile::ENVELOPE_SLOTS.contains(&name.as_str()) {
            findings.push(finding(
                CheckCode::ProfileUnknownSlot,
                path,
                "the envelope names a slot outside the closed vocabulary",
                "Use a slot of the closed vocabulary in CONCEPT.md section 7.",
            ));
        }
    }
    findings
}

/// Pack checks (`products/adapter/CONCEPT.md` sections 8.8 and 10.2):
/// endpoint components, GraphQL query files, the script inventory, and
/// reserved header names.
#[must_use]
pub fn check_pack(pack: &AdapterPack) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for (index, endpoint) in pack.endpoints.iter().enumerate() {
        let prefix = format!("/endpoints/{index}");
        if !endpoint.component.is_producer() {
            findings.push(finding(
                CheckCode::PackEndpointComponentInvalid,
                &format!("{prefix}/component"),
                "an endpoint declares a non-producer component",
                "Declare http or graphql on an endpoint; direct names routes and rest is the facade consumer.",
            ));
        }
        if endpoint.component == crate::model::ComponentKind::GraphQl
            && endpoint.query_file.is_none()
        {
            findings.push(finding(
                CheckCode::PackGraphQlQueryRequired,
                &format!("{prefix}/queryFile"),
                "a graphql endpoint names no query file",
                "Reference a digest-pinned query file from the pack inventory.",
            ));
        }
        if let EndpointAuthentication::StaticApiKey { header_name } = &endpoint.authentication {
            if is_reserved_header_name(header_name) {
                findings.push(finding(
                    CheckCode::PackReservedHeaderName,
                    &format!("{prefix}/authentication/headerName"),
                    "the api-key header name is reserved by the engine",
                    "Declare a header the engine does not own.",
                ));
            }
        }
        if let Some(query_file) = &endpoint.query_file {
            if pack.pinned_file(query_file).is_none() {
                findings.push(finding(
                    CheckCode::PackUnknownScript,
                    &format!("{prefix}/queryFile"),
                    "the query file is not in the pack's digest-pinned inventory",
                    "List the query file in queryFiles with its sha256 digest.",
                ));
            }
        }
        if let Some(crate::model::Expression::Rhai(rhai)) = &endpoint.variables {
            if pack.pinned_file(&rhai.file).is_none() {
                findings.push(finding(
                    CheckCode::PackUnknownScript,
                    &format!("{prefix}/variables"),
                    "the variables script is not in the pack's digest-pinned inventory",
                    "List the script in scripts with its sha256 digest.",
                ));
            }
        }
    }
    findings.extend(script_reference_checks(pack));
    findings.extend(template_parameter_checks(pack));
    findings
}

/// Every placeholder a template body uses must name a declared template
/// parameter (CFG-VAL-9): a body reference with no declaration can never
/// resolve at instantiation.
fn template_parameter_checks(pack: &AdapterPack) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for (index, template) in pack.route_templates.iter().enumerate() {
        let mut refused: HashSet<(String, String)> = HashSet::new();
        walk_steps(&template.steps, &mut |step, path| {
            // A send's path carries placeholders like any expression slot.
            let path_text = match step {
                Step::To(to) => to.parameters.as_ref().and_then(|p| p.path.clone()),
                Step::Enrich(enrich) => enrich.parameters.as_ref().and_then(|p| p.path.clone()),
                _ => None,
            };
            if let Some(text) = path_text {
                for (name, _) in placeholders(&text) {
                    let declared = template
                        .parameters
                        .iter()
                        .any(|parameter| parameter.name.as_str() == name);
                    if !declared && refused.insert((name.clone(), path.to_string())) {
                        findings.push(finding(
                            CheckCode::PackUnknownTemplateParameter,
                            &format!("/routeTemplates/{index}/steps{path}"),
                            &format!(
                                "the template body references {{{{{name}}}}}, which no declared parameter provides"
                            ),
                            "Declare the parameter in the template's parameters or remove the placeholder.",
                        ));
                    }
                }
            }
            for expression in step_expressions(step) {
                if let Expression::Constant(value) = expression {
                    let Some(text) = value.as_str() else {
                        continue;
                    };
                    for (name, _) in placeholders(text) {
                        let declared = template
                            .parameters
                            .iter()
                            .any(|parameter| parameter.name.as_str() == name);
                        if !declared && refused.insert((name.clone(), path.to_string())) {
                            findings.push(finding(
                                CheckCode::PackUnknownTemplateParameter,
                                &format!("/routeTemplates/{index}/steps{path}"),
                                &format!(
                                    "the template body references {{{{{name}}}}}, which no declared parameter provides"
                                ),
                                "Declare the parameter in the template's parameters or remove the placeholder.",
                            ));
                        }
                    }
                }
            }
        });
    }
    findings
}

/// Whether a supplied parameter value matches the declared parameter type
/// (CFG-VAL-9): `string` accepts JSON strings, `integer` accepts integral
/// JSON numbers, `number` accepts any JSON number, and `boolean` accepts
/// JSON booleans.
fn value_matches_type(value: &serde_json::Value, expected: TemplateParameterType) -> bool {
    match expected {
        TemplateParameterType::String => value.is_string(),
        TemplateParameterType::Integer => value.is_i64() || value.is_u64(),
        TemplateParameterType::Number => value.is_number(),
        TemplateParameterType::Boolean => value.is_boolean(),
    }
}

/// Every Rhai reference in every route body must resolve to a digest-pinned
/// inventory entry (CFG-EMBED-1: `rhai` always names a digest-pinned file).
fn script_reference_checks(pack: &AdapterPack) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    let mut bodies: Vec<&[Step]> = pack
        .routes
        .iter()
        .map(|route| route.steps.as_slice())
        .collect();
    bodies.extend(pack.route_templates.iter().map(|t| t.steps.as_slice()));
    for steps in bodies {
        for script in script_references(steps) {
            if pack.pinned_file(&script.file).is_none() {
                findings.push(finding(
                    CheckCode::PackUnknownScript,
                    &format!("/steps{}/rhai", script.path),
                    "the script file is not in the pack's digest-pinned inventory",
                    "List the script in scripts with its sha256 digest.",
                ));
            }
        }
    }
    findings
}

/// Route checks over one pack and the project that instantiates it
/// (`products/adapter/CONCEPT.md` sections 5.5, 8.3, and 8.7): the direct
/// graph shape, the two mandatory bounds, endpoint and route references,
/// uncatchable clauses, redelivery over non-safe sends, and the split
/// confinement of non-safe sends.
#[must_use]
pub fn check_routes(pack: &AdapterPack, project: &AdapterProject) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    let bodies = route_bodies(pack, project);
    let known_ids: HashSet<&str> = bodies.keys().copied().collect();
    let endpoint_ids: HashSet<&str> = pack
        .endpoints
        .iter()
        .map(|endpoint| endpoint.id.as_str())
        .collect();

    // Findings iterate route ids in sorted order so snapshots and CI
    // diffs stay stable however the body map hashes.
    let mut ordered_bodies: Vec<(&str, &[Step])> =
        bodies.iter().map(|(id, steps)| (*id, *steps)).collect();
    ordered_bodies.sort_by_key(|(id, _)| *id);

    // The response-header allowlists every endpoint declares, lowercased;
    // header names compare without case
    // (`products/adapter/CONCEPT.md` section 8.11.4).
    let allowlist: HashSet<String> = pack
        .endpoints
        .iter()
        .flat_map(|endpoint| {
            endpoint
                .response_headers
                .iter()
                .map(|header| header.as_str().to_ascii_lowercase())
        })
        .collect();

    // Graph shape over direct: edges.
    let mut edges: HashMap<&str, Vec<&str>> = HashMap::new();
    for (id, steps) in &ordered_bodies {
        let mut targets = Vec::new();
        collect_direct_targets(steps, &mut targets);
        edges.insert(id, targets);
    }
    if let Some(cycle_node) = find_cycle(&edges) {
        findings.push(finding(
            CheckCode::RouteDirectCycle,
            &format!("/routes/{cycle_node}"),
            "the direct call graph carries a cycle",
            "Break the cycle; the direct call graph is acyclic.",
        ));
    } else {
        let deepest = longest_chain(&edges);
        if deepest > MAX_DIRECT_DEPTH {
            findings.push(finding(
                CheckCode::RouteDirectDepthExceeded,
                "/routes",
                "the direct call graph is deeper than the bounded depth",
                "Flatten the direct chain to the bounded depth.",
            ));
        }
    }

    for (id, steps) in &ordered_bodies {
        let steps: &[Step] = steps;
        let mut route_findings = Vec::new();
        let sends = collect_non_safe_sends(steps, &bodies);
        walk_steps(steps, &mut |step, path| match step {
            Step::To(to) => {
                let target = &to.uri;
                if let Some(fault) = to
                    .parameters
                    .as_ref()
                    .and_then(|parameters| parameters.path.as_deref())
                    .and_then(origin_relative_path_fault)
                {
                    route_findings.push(finding(
                        CheckCode::RouteInvalidPath,
                        &format!("/routes/{id}/steps{path}/parameters/path"),
                        fault,
                        "Author the path origin-relative: a leading slash, no scheme or authority, and no `..` segment.",
                    ));
                }
                match target.component {
                    SendComponent::Http | SendComponent::GraphQl => {
                        if !endpoint_ids.contains(target.id.as_str()) {
                            route_findings.push(finding(
                                CheckCode::RouteUnknownEndpoint,
                                &format!("/routes/{id}/steps{path}"),
                                "the send names no declared endpoint",
                                "Name an endpoint the pack declares.",
                            ));
                        }
                    }
                    SendComponent::Direct => {
                        if !known_ids.contains(target.id.as_str()) {
                            route_findings.push(finding(
                                    CheckCode::RouteUnknownDirectTarget,
                                    &format!("/routes/{id}/steps{path}"),
                                    "the direct send names no route or template",
                                    "Name a route or template the pack declares or the project instantiates.",
                                ));
                        }
                    }
                }
            }
            Step::Enrich(enrich) => {
                if let Some(fault) = enrich
                    .parameters
                    .as_ref()
                    .and_then(|parameters| parameters.path.as_deref())
                    .and_then(origin_relative_path_fault)
                {
                    route_findings.push(finding(
                        CheckCode::RouteInvalidPath,
                        &format!("/routes/{id}/steps{path}/parameters/path"),
                        fault,
                        "Author the path origin-relative: a leading slash, no scheme or authority, and no `..` segment.",
                    ));
                }
                match enrich.uri.component {
                    SendComponent::Http | SendComponent::GraphQl => {
                        if !endpoint_ids.contains(enrich.uri.id.as_str()) {
                            route_findings.push(finding(
                                CheckCode::RouteUnknownEndpoint,
                                &format!("/routes/{id}/steps{path}"),
                                "the enrichment names no declared endpoint",
                                "Name an endpoint the pack declares.",
                            ));
                        }
                    }
                    SendComponent::Direct => {
                        if !known_ids.contains(enrich.uri.id.as_str()) {
                            route_findings.push(finding(
                                CheckCode::RouteUnknownDirectTarget,
                                &format!("/routes/{id}/steps{path}"),
                                "the direct enrichment names no route or template",
                                "Name a route or template the pack declares or the project instantiates.",
                            ));
                        }
                    }
                }
            }
            Step::Split(split) => {
                if split.maximum_items.is_none() {
                    route_findings.push(finding(
                        CheckCode::RouteMaximumItemsRequired,
                        &format!("/routes/{id}/steps{path}"),
                        "the split declares no maximumItems bound",
                        "Declare maximumItems on every split.",
                    ));
                }
                if !split.stop_on_exception {
                    walk_steps(&split.steps, &mut |inner, inner_path| {
                        if let Step::To(to) = inner {
                            if is_non_safe_to(to) {
                                route_findings.push(finding(
                                    CheckCode::RouteNonSafeSendInSplit,
                                    &format!("/routes/{id}/steps{path}/steps{inner_path}"),
                                    "a non-safe send sits inside a split without stopOnException",
                                    "Set stopOnException on the split, or move the send out.",
                                ));
                            }
                        }
                    });
                }
                // Camel makes stopOnException exclusive with the failure
                // accounting: stopping at the first failure leaves no
                // threshold to reach.
                if split.stop_on_exception
                    && (split.error_threshold.is_some() || split.maximum_failed_records.is_some())
                {
                    route_findings.push(finding(
                        CheckCode::RouteStopOnExceptionExclusive,
                        &format!("/routes/{id}/steps{path}"),
                        "the split sets stopOnException beside its failure accounting",
                        "Keep stopOnException or the failure accounting, not both.",
                    ));
                }
            }
            Step::Choice(choice) => {
                for (when_index, when) in choice.when.iter().enumerate() {
                    let pointer = &format!("/routes/{id}/steps{path}/when/{when_index}");
                    match when.language_members() {
                        0 => route_findings.push(finding(
                            CheckCode::RoutePredicateLanguageRequired,
                            pointer,
                            "the when clause carries no predicate language key",
                            "Add exactly one language key (constant, header, exchangeProperty, jsonpath, or rhai).",
                        )),
                        1 => {}
                        _ => route_findings.push(finding(
                            CheckCode::RoutePredicateAmbiguous,
                            pointer,
                            "the when clause carries more than one predicate language key",
                            "Keep exactly one language key beside steps.",
                        )),
                    }
                }
            }
            Step::Filter(filter) => {
                let pointer = &format!("/routes/{id}/steps{path}");
                match filter.language_members() {
                    0 => route_findings.push(finding(
                        CheckCode::RoutePredicateLanguageRequired,
                        pointer,
                        "the filter carries no predicate language key",
                        "Add exactly one language key (constant, header, exchangeProperty, jsonpath, or rhai).",
                    )),
                    1 => {}
                    _ => route_findings.push(finding(
                        CheckCode::RoutePredicateAmbiguous,
                        pointer,
                        "the filter carries more than one predicate language key",
                        "Keep exactly one language key beside steps.",
                    )),
                }
            }
            Step::Loop(loop_step) => {
                let pointer = &format!("/routes/{id}/steps{path}");
                match loop_step.language_members() {
                    0 => route_findings.push(finding(
                        CheckCode::RoutePredicateLanguageRequired,
                        pointer,
                        "the loop carries no count or predicate language key",
                        "Add exactly one language key (constant, header, exchangeProperty, jsonpath, or rhai).",
                    )),
                    1 => {}
                    _ => route_findings.push(finding(
                        CheckCode::RoutePredicateAmbiguous,
                        pointer,
                        "the loop carries more than one count or predicate language key",
                        "Keep exactly one language key beside maximumIterations and steps.",
                    )),
                }
                if loop_step.maximum_iterations.is_none() {
                    route_findings.push(finding(
                        CheckCode::RouteMaximumIterationsRequired,
                        pointer,
                        "the loop declares no maximumIterations bound",
                        "Declare maximumIterations on every loop.",
                    ));
                }
                // A counted loop above its own bound can never finish by
                // counting; refuse it here instead of failing at runtime.
                if !loop_step.do_while {
                    if let (Some(count), Some(bound)) =
                        (loop_step.constant.as_ref(), loop_step.maximum_iterations)
                    {
                        if count.as_u64().is_some_and(|count| count > bound.get()) {
                            route_findings.push(finding(
                                CheckCode::RouteLoopCountAboveBound,
                                pointer,
                                "the loop's constant count exceeds maximumIterations",
                                "Raise maximumIterations above the count, or lower the count.",
                            ));
                        }
                    }
                }
            }
            Step::ErrorHandler(handler) => {
                let members = handler.default_error_handler.is_some() as usize
                    + handler.no_error_handler.is_some() as usize;
                if members != 1 {
                    route_findings.push(finding(
                        CheckCode::RouteErrorHandlerShape,
                        &format!("/routes/{id}/steps{path}"),
                        "the errorHandler carries none or both handlers",
                        "Carry exactly one of defaultErrorHandler or noErrorHandler.",
                    ));
                }
                if let Some(policy) = handler
                    .default_error_handler
                    .as_ref()
                    .and_then(|handler| handler.redelivery_policy.as_ref())
                {
                    // A retryWhile only stops redelivery earlier; with no
                    // redeliveries behind it, it could never fire.
                    if policy.retry_while.is_some() && policy.maximum_redeliveries == 0 {
                        route_findings.push(finding(
                            CheckCode::RouteRetryWhileWithoutRedeliveries,
                            &format!("/routes/{id}/steps{path}"),
                            "a retryWhile predicate sits on a redelivery policy with maximumRedeliveries 0",
                            "Set maximumRedeliveries above zero, or drop the retryWhile.",
                        ));
                    }
                }
            }
            Step::OnException(clause)
                if clause.exception.iter().any(|class| class.is_uncatchable()) =>
            {
                route_findings.push(finding(
                    CheckCode::RouteUncatchableClause,
                    &format!("/routes/{id}/steps{path}"),
                    "an onException clause names an uncatchable class",
                    "Remove the clause; the boundary classes cannot be handled.",
                ));
            }
            Step::DoTry(do_try)
                if do_try
                    .do_catch
                    .iter()
                    .any(|catch| catch.exception.iter().any(|class| class.is_uncatchable())) =>
            {
                route_findings.push(finding(
                    CheckCode::RouteUncatchableClause,
                    &format!("/routes/{id}/steps{path}"),
                    "a doCatch clause names an uncatchable class",
                    "Remove the clause; the boundary classes cannot be handled.",
                ));
            }
            // A retryWhile only stops redelivery earlier; with no
            // redeliveries behind it, it could never fire.
            Step::OnException(clause)
                if clause.redelivery_policy.as_ref().is_some_and(|policy| {
                    policy.retry_while.is_some() && policy.maximum_redeliveries == 0
                }) =>
            {
                route_findings.push(finding(
                    CheckCode::RouteRetryWhileWithoutRedeliveries,
                    &format!("/routes/{id}/steps{path}"),
                    "a retryWhile predicate sits on a redelivery policy with maximumRedeliveries 0",
                    "Set maximumRedeliveries above zero, or drop the retryWhile.",
                ));
            }
            Step::OnException(clause) => {
                if clause.exception.is_empty() {
                    route_findings.push(finding(
                        CheckCode::RouteEmptyExceptionList,
                        &format!("/routes/{id}/steps{path}"),
                        "the onException clause names no error class",
                        "Name at least one error class the clause matches.",
                    ));
                }
                if clause.handled == Some(true) && clause.continued == Some(true) {
                    route_findings.push(finding(
                        CheckCode::RouteHandledAndContinued,
                        &format!("/routes/{id}/steps{path}"),
                        "the onException clause sets handled and continued together",
                        "Keep handled or continued, not both.",
                    ));
                }
            }
            Step::DoTry(do_try) => {
                for (catch_index, catch) in do_try.do_catch.iter().enumerate() {
                    if catch.exception.is_empty() {
                        route_findings.push(finding(
                            CheckCode::RouteEmptyExceptionList,
                            &format!("/routes/{id}/steps{path}/doCatch/{catch_index}"),
                            "the doCatch clause names no error class",
                            "Name at least one error class the clause matches.",
                        ));
                    }
                }
            }
            _ => {}
        });

        // Header writes and reads stay bounded
        // (`products/adapter/CONCEPT.md` section 8.11.4).
        check_route_headers(id, steps, &allowlist, &mut route_findings);

        // A non-safe send naming an operation the endpoint does not
        // declare is a reference defect on its own (CFG-ID-4).
        for send in &sends {
            let declared = send.operation.as_ref().is_none_or(|operation| {
                pack.endpoints
                    .get(send.endpoint.as_str())
                    .is_some_and(|endpoint| {
                        endpoint
                            .operations
                            .iter()
                            .any(|op| op.id.as_str() == operation.as_str())
                    })
            });
            if !declared {
                findings.push(finding(
                    CheckCode::RouteUnknownOperation,
                    &format!("/routes/{id}"),
                    "the send names no operation its endpoint declares",
                    "Name an operation the send's endpoint declares.",
                ));
            }
        }
        // Redelivery over a non-safe send needs every non-safe send the
        // route makes to carry an idempotentUpstream claim
        // (`products/adapter/CONCEPT.md` section 8.7).
        if declares_redelivery(steps)
            && !sends
                .iter()
                .all(|send| send_claims_idempotent(pack, &send.endpoint, send.operation.as_ref()))
        {
            findings.push(finding(
                CheckCode::RouteRedeliveryOverNonSafeSend,
                &format!("/routes/{id}"),
                "redelivery is declared over a non-safe send without an idempotentUpstream claim",
                "Declare idempotentUpstream on the endpoint operation, or drop the redelivery.",
            ));
        }
        // Redelivery applies only to upstream component sends; a
        // declaration whose reachable sends are all `direct:` could never
        // take effect, and no send is multiplied twice.
        if declares_redelivery(steps) && !reaches_component_send(steps, &bodies, 0) {
            findings.push(finding(
                CheckCode::RouteRedeliveryWithoutUpstreamSend,
                &format!("/routes/{id}"),
                "redelivery is declared but the route reaches no http: or graphql: send",
                "Send to an http: or graphql: endpoint, or drop the redelivery.",
            ));
        }
        findings.extend(route_findings);
    }

    for (index, route) in pack.routes.iter().enumerate() {
        if route.from.uri.component != SendComponent::Direct {
            findings.push(finding(
                CheckCode::RouteFromNotDirect,
                &format!("/routes/{index}/from/uri"),
                "a route consumes outside the direct: scheme",
                "Declare a direct: from; the rest consumer dispatches to direct routes.",
            ));
        }
    }
    findings
}

/// A route's header writes and reads stay bounded
/// (`products/adapter/CONCEPT.md` section 8.11.4): no `setHeader` or
/// `removeHeader` names a credential, cookie, host, hop-by-hop, engine, or
/// facade-input header, and every `header` expression reads a facade
/// input, an engine-placed header, a response header some endpoint
/// allowlist declares, or a header an earlier step of the same body set.
/// Findings sit at the step.
fn check_route_headers(
    id: &str,
    steps: &[Step],
    allowlist: &HashSet<String>,
    findings: &mut Vec<Diagnostic>,
) {
    let mut placed: HashSet<String> = HashSet::new();
    walk_steps(steps, &mut |step, path| {
        let pointer = format!("/routes/{id}/steps{path}");
        // Reads answer before the step runs, so a step's own setHeader
        // does not authorize its own value.
        for expression in step_expressions(step) {
            if let Expression::Header(name) = expression {
                if !is_header_read_known(&name, &placed, allowlist) {
                    findings.push(finding(
                        CheckCode::RouteUnknownHeader,
                        &pointer,
                        "the route reads a header nothing places",
                        "Read only a facade input, an engine-placed header, a header an endpoint response allowlist declares, or a header an earlier step of this route sets.",
                    ));
                }
            }
        }
        match step {
            Step::SetHeader(header) if is_reserved_header_write(&header.name) => {
                findings.push(finding(
                    CheckCode::RouteReservedHeaderName,
                    &pointer,
                    "the route sets a header reserved to the consumer, the engine, or the HTTP hop",
                    "Set only headers the route owns; credential, cookie, host, hop-by-hop, engine, and facade-input headers are never written by a route.",
                ));
            }
            // A setHeader the route owns places its name for the reads
            // after it.
            Step::SetHeader(header) => {
                placed.insert(header.name.to_ascii_lowercase());
            }
            Step::RemoveHeader(name) if is_reserved_header_write(name) => {
                findings.push(finding(
                    CheckCode::RouteReservedHeaderName,
                    &pointer,
                    "the route removes a header reserved to the consumer, the engine, or the HTTP hop",
                    "Remove only headers the route owns; credential, cookie, host, hop-by-hop, engine, and facade-input headers are never written by a route.",
                ));
            }
            _ => {}
        }
    });
}

/// Whether a `to` send is a non-safe upstream send.
fn is_non_safe_to(to: &crate::route::ToStep) -> bool {
    is_non_safe_upstream(to.uri.component, to.parameters.as_ref())
}

/// Whether a send or enrichment to the component is a non-safe upstream
/// send: an `http:` or `graphql:` destination carrying an unsafe method.
fn is_non_safe_upstream(
    component: SendComponent,
    parameters: Option<&crate::route::ToParameters>,
) -> bool {
    matches!(component, SendComponent::Http | SendComponent::GraphQl)
        && parameters.is_some_and(|parameters| !parameters.http_method.is_safe())
}

/// Whether any step in the body declares redelivery beyond the first
/// attempt, or a `retryWhile`.
fn declares_redelivery(steps: &[Step]) -> bool {
    let mut declared = false;
    walk_steps(steps, &mut |step, _| match step {
        Step::ErrorHandler(handler) => {
            if let Some(policy) = handler
                .default_error_handler
                .as_ref()
                .and_then(|handler| handler.redelivery_policy.as_ref())
            {
                if policy.maximum_redeliveries > 0 || policy.retry_while.is_some() {
                    declared = true;
                }
            }
        }
        Step::OnException(clause)
            if clause.redelivery_policy.as_ref().is_some_and(|policy| {
                policy.maximum_redeliveries > 0 || policy.retry_while.is_some()
            }) =>
        {
            declared = true;
        }
        _ => {}
    });
    declared
}

/// Whether the send's endpoint operation declares `idempotentUpstream`. A
/// send naming no operation is never idempotent, and an operation id the
/// endpoint does not declare is refused on its own under
/// `adapter.route.unknown-operation`, never silently false.
fn send_claims_idempotent(
    pack: &AdapterPack,
    endpoint_id: &str,
    operation: Option<&ExternalId>,
) -> bool {
    let Some(endpoint) = pack.endpoints.get(endpoint_id) else {
        return false;
    };
    let Some(operation_id) = operation else {
        return false;
    };
    endpoint
        .operations
        .iter()
        .any(|op| op.id.as_str() == operation_id.as_str() && op.idempotent_upstream)
}

/// Whether any upstream component send (`http:` or `graphql:`) is
/// reachable from the body, through composite steps and `direct:`
/// expansion. Redelivery applies only to component sends, so a
/// declaration whose reachable sends are all `direct:` has no effect.
/// The depth bound counts `direct:` hops only: composite nesting is
/// unbounded here and the cycle check guards the graph.
fn reaches_component_send(steps: &[Step], bodies: &HashMap<&str, &[Step]>, depth: usize) -> bool {
    if depth > MAX_DIRECT_DEPTH {
        return false;
    }
    steps.iter().any(|step| match step {
        Step::To(to) => match to.uri.component {
            SendComponent::Http | SendComponent::GraphQl => true,
            SendComponent::Direct => bodies
                .get(to.uri.id.as_str())
                .is_some_and(|target| reaches_component_send(target, bodies, depth + 1)),
        },
        Step::Enrich(enrich) => match enrich.uri.component {
            SendComponent::Http | SendComponent::GraphQl => true,
            SendComponent::Direct => bodies
                .get(enrich.uri.id.as_str())
                .is_some_and(|target| reaches_component_send(target, bodies, depth + 1)),
        },
        Step::Filter(filter) => reaches_component_send(&filter.steps, bodies, depth),
        Step::Split(split) => reaches_component_send(&split.steps, bodies, depth),
        Step::Loop(loop_step) => reaches_component_send(&loop_step.steps, bodies, depth),
        Step::Choice(choice) => {
            choice
                .when
                .iter()
                .any(|when| reaches_component_send(&when.steps, bodies, depth))
                || choice.otherwise.as_ref().is_some_and(|otherwise| {
                    reaches_component_send(&otherwise.steps, bodies, depth)
                })
        }
        Step::CircuitBreaker(breaker) => {
            reaches_component_send(&breaker.steps, bodies, depth)
                || breaker
                    .on_fallback
                    .as_ref()
                    .is_some_and(|fallback| reaches_component_send(&fallback.steps, bodies, depth))
        }
        Step::Throttle(throttle) => reaches_component_send(&throttle.steps, bodies, depth),
        Step::IdempotentConsumer(idempotent) => {
            reaches_component_send(&idempotent.steps, bodies, depth)
        }
        Step::OnException(clause) => reaches_component_send(&clause.steps, bodies, depth),
        Step::DoTry(do_try) => {
            reaches_component_send(&do_try.steps, bodies, depth)
                || do_try
                    .do_catch
                    .iter()
                    .any(|catch| reaches_component_send(&catch.steps, bodies, depth))
                || do_try.do_finally.as_ref().is_some_and(|do_finally| {
                    reaches_component_send(&do_finally.steps, bodies, depth)
                })
        }
        _ => false,
    })
}

/// One non-safe upstream send a route body can make.
struct NonSafeSend {
    /// The endpoint id the send names.
    endpoint: String,
    /// The endpoint operation the send names, when declared.
    operation: Option<ExternalId>,
    /// Whether the send sits inside an `idempotentConsumer`.
    inside_idempotency: bool,
    /// Whether the send runs per item or iteration (inside a `split` or
    /// `loop`).
    repeated: bool,
}

/// Every non-safe upstream send a body can reach, with its enclosing
/// `idempotentConsumer` context.
fn collect_non_safe_sends(steps: &[Step], bodies: &HashMap<&str, &[Step]>) -> Vec<NonSafeSend> {
    #[allow(clippy::too_many_arguments)]
    fn walk<'a>(
        steps: &'a [Step],
        inside_idempotency: bool,
        repeated: bool,
        bodies: &HashMap<&'a str, &'a [Step]>,
        visiting: &mut Vec<&'a str>,
        depth: usize,
        sends: &mut Vec<NonSafeSend>,
    ) {
        // Direct expansion follows Camel's connection by from URI; a
        // cycle or a chain past the bounded depth stops here (the graph
        // checks report the cycle and depth separately).
        if depth > MAX_DIRECT_DEPTH {
            return;
        }
        for step in steps {
            match step {
                Step::To(to) if is_non_safe_to(to) => sends.push(NonSafeSend {
                    endpoint: to.uri.id.clone(),
                    operation: to.parameters.as_ref().and_then(|p| p.operation.clone()),
                    inside_idempotency,
                    repeated,
                }),
                Step::Enrich(enrich)
                    if is_non_safe_upstream(enrich.uri.component, enrich.parameters.as_ref()) =>
                {
                    sends.push(NonSafeSend {
                        endpoint: enrich.uri.id.clone(),
                        operation: enrich
                            .parameters
                            .as_ref()
                            .and_then(|parameters| parameters.operation.clone()),
                        inside_idempotency,
                        repeated,
                    });
                }
                Step::To(to) if to.uri.component == SendComponent::Direct => {
                    expand_direct(
                        &to.uri,
                        bodies,
                        visiting,
                        depth,
                        inside_idempotency,
                        repeated,
                        sends,
                    );
                }
                Step::Enrich(enrich) if enrich.uri.component == SendComponent::Direct => {
                    expand_direct(
                        &enrich.uri,
                        bodies,
                        visiting,
                        depth,
                        inside_idempotency,
                        repeated,
                        sends,
                    );
                }
                Step::IdempotentConsumer(idempotent) => {
                    walk(
                        &idempotent.steps,
                        true,
                        repeated,
                        bodies,
                        visiting,
                        depth,
                        sends,
                    );
                }
                Step::Choice(choice) => {
                    for when in &choice.when {
                        walk(
                            &when.steps,
                            inside_idempotency,
                            repeated,
                            bodies,
                            visiting,
                            depth,
                            sends,
                        );
                    }
                    if let Some(otherwise) = &choice.otherwise {
                        walk(
                            &otherwise.steps,
                            inside_idempotency,
                            repeated,
                            bodies,
                            visiting,
                            depth,
                            sends,
                        );
                    }
                }
                Step::Filter(filter) => walk(
                    &filter.steps,
                    inside_idempotency,
                    repeated,
                    bodies,
                    visiting,
                    depth,
                    sends,
                ),
                Step::Split(split) => walk(
                    &split.steps,
                    inside_idempotency,
                    true,
                    bodies,
                    visiting,
                    depth,
                    sends,
                ),
                Step::Loop(loop_step) => walk(
                    &loop_step.steps,
                    inside_idempotency,
                    true,
                    bodies,
                    visiting,
                    depth,
                    sends,
                ),
                Step::CircuitBreaker(breaker) => {
                    walk(
                        &breaker.steps,
                        inside_idempotency,
                        repeated,
                        bodies,
                        visiting,
                        depth,
                        sends,
                    );
                    if let Some(fallback) = &breaker.on_fallback {
                        walk(
                            &fallback.steps,
                            inside_idempotency,
                            repeated,
                            bodies,
                            visiting,
                            depth,
                            sends,
                        );
                    }
                }
                Step::Throttle(throttle) => walk(
                    &throttle.steps,
                    inside_idempotency,
                    repeated,
                    bodies,
                    visiting,
                    depth,
                    sends,
                ),
                Step::DoTry(do_try) => {
                    walk(
                        &do_try.steps,
                        inside_idempotency,
                        repeated,
                        bodies,
                        visiting,
                        depth,
                        sends,
                    );
                    for catch in &do_try.do_catch {
                        walk(
                            &catch.steps,
                            inside_idempotency,
                            repeated,
                            bodies,
                            visiting,
                            depth,
                            sends,
                        );
                    }
                    if let Some(do_finally) = &do_try.do_finally {
                        walk(
                            &do_finally.steps,
                            inside_idempotency,
                            repeated,
                            bodies,
                            visiting,
                            depth,
                            sends,
                        );
                    }
                }
                Step::OnException(clause) => walk(
                    &clause.steps,
                    inside_idempotency,
                    repeated,
                    bodies,
                    visiting,
                    depth,
                    sends,
                ),
                _ => {}
            }
        }
    }
    fn expand_direct<'a>(
        uri: &'a crate::model::SendUri,
        bodies: &HashMap<&'a str, &'a [Step]>,
        visiting: &mut Vec<&'a str>,
        depth: usize,
        inside_idempotency: bool,
        repeated: bool,
        sends: &mut Vec<NonSafeSend>,
    ) {
        if visiting.contains(&uri.id.as_str()) {
            return;
        }
        if let Some(target) = bodies.get(uri.id.as_str()) {
            visiting.push(uri.id.as_str());
            walk(
                target,
                inside_idempotency,
                repeated,
                bodies,
                visiting,
                depth + 1,
                sends,
            );
            visiting.pop();
        }
    }
    let mut sends = Vec::new();
    walk(steps, false, false, bodies, &mut Vec::new(), 0, &mut sends);
    sends
}

/// Depth-first visit of every step, with the relative step path inside the
/// visited body. Public so adopter tooling reuses one exhaustive walk
/// over `Step` instead of duplicating it.
pub fn walk_steps<'a>(steps: &'a [Step], visit: &mut dyn FnMut(&'a Step, &str)) {
    fn walk<'a>(steps: &'a [Step], prefix: &str, visit: &mut dyn FnMut(&'a Step, &str)) {
        for (index, step) in steps.iter().enumerate() {
            let path = format!("{prefix}/{index}");
            visit(step, &path);
            match step {
                Step::Choice(choice) => {
                    for (when_index, when) in choice.when.iter().enumerate() {
                        walk(
                            &when.steps,
                            &format!("{path}/when/{when_index}/steps"),
                            visit,
                        );
                    }
                    if let Some(otherwise) = &choice.otherwise {
                        walk(&otherwise.steps, &format!("{path}/otherwise/steps"), visit);
                    }
                }
                Step::Filter(filter) => walk(&filter.steps, &format!("{path}/steps"), visit),
                Step::Split(split) => walk(&split.steps, &format!("{path}/steps"), visit),
                Step::Loop(loop_step) => walk(&loop_step.steps, &format!("{path}/steps"), visit),
                Step::CircuitBreaker(breaker) => {
                    walk(&breaker.steps, &format!("{path}/steps"), visit);
                    if let Some(fallback) = &breaker.on_fallback {
                        walk(&fallback.steps, &format!("{path}/onFallback/steps"), visit);
                    }
                }
                Step::Throttle(throttle) => walk(&throttle.steps, &format!("{path}/steps"), visit),
                Step::IdempotentConsumer(idempotent) => {
                    walk(&idempotent.steps, &format!("{path}/steps"), visit)
                }
                Step::OnException(clause) => walk(&clause.steps, &format!("{path}/steps"), visit),
                Step::DoTry(do_try) => {
                    walk(&do_try.steps, &format!("{path}/steps"), visit);
                    for (catch_index, catch) in do_try.do_catch.iter().enumerate() {
                        walk(
                            &catch.steps,
                            &format!("{path}/doCatch/{catch_index}/steps"),
                            visit,
                        );
                    }
                    if let Some(do_finally) = &do_try.do_finally {
                        walk(&do_finally.steps, &format!("{path}/doFinally/steps"), visit);
                    }
                }
                _ => {}
            }
        }
    }
    walk(steps, "", visit);
}

/// The Rhai expression of an aggregation strategy, when it carries one.
fn aggregation_expressions(
    strategy: &Option<crate::model::AggregationStrategy>,
) -> Vec<Expression> {
    strategy
        .as_ref()
        .and_then(|strategy| match strategy {
            crate::model::AggregationStrategy::Rhai { expression } => {
                Some(Expression::Rhai(expression.clone()))
            }
            _ => None,
        })
        .into_iter()
        .collect()
}

/// Every expression a step carries directly, including the optional ones
/// (`onWhen`, `retryWhile`, a send's `body`, `pathParameters`, `query`,
/// Rhai aggregation strategies) and the language members of `split`,
/// `throttle`, and `idempotentConsumer`. Public so
/// adopter tooling reuses one exhaustive extraction instead of
/// duplicating it; pair it with [`walk_steps`] and [`script_references`]
/// to reach every expression and script in a route body.
pub fn step_expressions(step: &Step) -> Vec<Expression> {
    match step {
        Step::SetBody(expression) | Step::Transform(expression) | Step::Script(expression) => {
            vec![expression.clone()]
        }
        Step::SetHeader(header) => vec![header.value.clone()],
        Step::SetProperty(property) => vec![property.value.clone()],
        Step::Validate(validate) => vec![validate.expression.clone()],
        Step::Throttle(throttle) => vec![throttle.limit.clone()],
        Step::IdempotentConsumer(idempotent) => vec![idempotent.expression.clone()],
        Step::Loop(loop_step) => loop_step.expression().into_iter().collect(),
        Step::Split(split) => {
            let mut expressions = vec![split.expression.clone()];
            expressions.extend(aggregation_expressions(&split.aggregation_strategy));
            expressions
        }
        Step::Enrich(enrich) => {
            let mut expressions = aggregation_expressions(&enrich.aggregation_strategy);
            if let Some(parameters) = enrich.parameters.as_ref() {
                expressions.extend(
                    parameters
                        .path_parameters
                        .values()
                        .cloned()
                        .collect::<Vec<_>>(),
                );
                expressions.extend(parameters.query.values().cloned());
                if let Some(body) = &parameters.body {
                    expressions.push(body.clone());
                }
            }
            expressions
        }
        Step::To(to) => {
            let Some(parameters) = to.parameters.as_ref() else {
                return Vec::new();
            };
            let mut expressions = parameters
                .path_parameters
                .values()
                .cloned()
                .collect::<Vec<_>>();
            expressions.extend(parameters.query.values().cloned());
            if let Some(body) = &parameters.body {
                expressions.push(body.clone());
            }
            expressions
        }
        Step::OnException(clause) => {
            let mut expressions = clause.on_when.iter().cloned().collect::<Vec<_>>();
            if let Some(policy) = &clause.redelivery_policy {
                if let Some(retry_while) = &policy.retry_while {
                    expressions.push(retry_while.clone());
                }
            }
            expressions
        }
        Step::DoTry(do_try) => do_try
            .do_catch
            .iter()
            .flat_map(|catch| catch.on_when.iter().cloned())
            .collect(),
        Step::ErrorHandler(handler) => handler
            .default_error_handler
            .as_ref()
            .and_then(|handler| handler.redelivery_policy.as_ref())
            .and_then(|policy| policy.retry_while.clone())
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

/// Verifies a project's profile and pack pins (CFG-ID-4) against
/// caller-computed values: adapterctl reads the artifact bytes, computes
/// their version and digest, and passes them here; core stays no-I/O.
/// Each mismatch is refused at the pin it concerns.
#[must_use]
pub fn check_project_pins(
    project: &AdapterProject,
    computed_profile_version: &str,
    computed_profile_digest: &Digest,
    computed_pack_version: &str,
    computed_pack_digest: &Digest,
) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    if project.profile.version != computed_profile_version {
        findings.push(finding(
            CheckCode::ProjectPinVersionMismatch,
            "/profile/version",
            "the pinned profile version does not match the profile bytes",
            "Pin the version the profile artifact's bytes carry.",
        ));
    }
    if &project.profile.digest != computed_profile_digest {
        findings.push(finding(
            CheckCode::ProjectPinDigestMismatch,
            "/profile/digest",
            "the pinned profile digest does not match the profile bytes",
            "Pin the sha256 digest of the profile artifact's bytes.",
        ));
    }
    if project.pack.version != computed_pack_version {
        findings.push(finding(
            CheckCode::ProjectPinVersionMismatch,
            "/pack/version",
            "the pinned pack version does not match the pack bytes",
            "Pin the version the pack artifact's bytes carry.",
        ));
    }
    if &project.pack.digest != computed_pack_digest {
        findings.push(finding(
            CheckCode::ProjectPinDigestMismatch,
            "/pack/digest",
            "the pinned pack digest does not match the pack bytes",
            "Pin the sha256 digest of the pack artifact's bytes.",
        ));
    }
    findings
}

/// One Rhai script site reachable in a route body.
pub struct ScriptSite {
    /// The relative step path inside the walked body.
    pub path: String,
    /// The pack inventory file the script runs.
    pub file: String,
    /// The function the script calls.
    pub entrypoint: String,
}

/// Every Rhai script site in a route body, covering the language
/// members of predicates (`when` and `filter`) as well as every
/// expression [`step_expressions`] reaches. Public so adopter tooling
/// reuses core's exhaustive walk instead of duplicating it.
pub fn script_references(steps: &[Step]) -> Vec<ScriptSite> {
    fn push(rhai: Option<&crate::model::RhaiExpression>, path: &str, refs: &mut Vec<ScriptSite>) {
        if let Some(rhai) = rhai {
            refs.push(ScriptSite {
                path: path.to_string(),
                file: rhai.file.clone(),
                entrypoint: rhai.entrypoint.clone(),
            });
        }
    }

    let mut refs = Vec::new();
    walk_steps(steps, &mut |step, path| {
        for expression in step_expressions(step) {
            if let Expression::Rhai(rhai) = &expression {
                push(Some(rhai), path, &mut refs);
            }
        }
        match step {
            Step::Choice(choice) => {
                for when in &choice.when {
                    push(when.rhai.as_ref(), path, &mut refs);
                }
            }
            Step::Filter(filter) => push(filter.rhai.as_ref(), path, &mut refs),
            _ => {}
        }
    });
    refs
}

/// The direct: targets a body sends to.
fn collect_direct_targets<'a>(steps: &'a [Step], targets: &mut Vec<&'a str>) {
    walk_steps(steps, &mut |step, _| match step {
        Step::To(to) if to.uri.component == SendComponent::Direct => targets.push(&to.uri.id),
        Step::Enrich(enrich) if enrich.uri.component == SendComponent::Direct => {
            targets.push(&enrich.uri.id)
        }
        _ => {}
    });
}

/// A cycle in the direct graph, if one exists: the node where the back
/// edge lands.
fn find_cycle<'a>(edges: &HashMap<&'a str, Vec<&'a str>>) -> Option<&'a str> {
    fn visit<'a>(
        node: &'a str,
        edges: &HashMap<&'a str, Vec<&'a str>>,
        visiting: &mut HashSet<&'a str>,
        done: &mut HashSet<&'a str>,
    ) -> Option<&'a str> {
        if visiting.contains(&node) {
            return Some(node);
        }
        if done.contains(&node) {
            return None;
        }
        visiting.insert(node);
        if let Some(targets) = edges.get(node) {
            for &target in targets {
                if let Some(cycle) = visit(target, edges, visiting, done) {
                    return Some(cycle);
                }
            }
        }
        visiting.remove(&node);
        done.insert(node);
        None
    }

    let mut visiting = HashSet::new();
    let mut done = HashSet::new();
    let mut nodes: Vec<&str> = edges.keys().copied().collect();
    nodes.sort_unstable();
    for node in nodes {
        if let Some(cycle) = visit(node, edges, &mut visiting, &mut done) {
            return Some(cycle);
        }
    }
    None
}

/// The longest `direct:` chain in the graph; call only on an acyclic
/// graph.
fn longest_chain(edges: &HashMap<&str, Vec<&str>>) -> usize {
    fn chain_from(
        node: &str,
        edges: &HashMap<&str, Vec<&str>>,
        memo: &mut HashMap<String, usize>,
    ) -> usize {
        if let Some(depth) = memo.get(node) {
            return *depth;
        }
        let depth = edges
            .get(node)
            .map(|targets| {
                targets
                    .iter()
                    .map(|target| 1 + chain_from(target, edges, memo))
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        memo.insert(node.to_string(), depth);
        depth
    }

    let mut memo = HashMap::new();
    edges
        .keys()
        .map(|node| chain_from(node, edges, &mut memo))
        .max()
        .unwrap_or(0)
}

/// Project checks over the composed workspace: reference resolution, the
/// duplicated instantiated route ids, the write-route rules, and the
/// static worst-case upstream call count against each binding's budget
/// (`products/adapter/CONCEPT.md` sections 5.5, 7, and 9).
#[must_use]
pub fn check_project(workspace: &Workspace<'_>) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    let project = workspace.project;
    let pack = workspace.pack;
    let bodies = route_bodies(pack, project);
    let bodies_by_id = route_bodies_by_id(pack, project);

    for (index, instantiated) in project.templated_routes.iter().enumerate() {
        let prefix = format!("/templatedRoutes/{index}");
        if pack
            .route_templates
            .get(instantiated.route_template.as_str())
            .is_none()
        {
            findings.push(finding(
                CheckCode::ProjectUnknownTemplate,
                &format!("{prefix}/routeTemplate"),
                "the instantiation references no declared template",
                "Name a template the pinned pack declares.",
            ));
        }
        // Collisions are judged against pack routes and templates only.
        // An instantiation never collides with its own resolved body,
        // which is also in the map for binding resolution; two
        // instantiations cannot share a route id at all, because the
        // unique-list reader refuses duplicates by id.
        if pack.routes.get(instantiated.route_id.as_str()).is_some()
            || pack
                .route_templates
                .get(instantiated.route_id.as_str())
                .is_some()
        {
            findings.push(finding(
                CheckCode::ProjectDuplicateRouteId,
                &format!("{prefix}/routeId"),
                "the instantiated route id collides with a pack route or template",
                "Choose a route id no pack route, template, or other instantiation uses.",
            ));
        }
        if let Some(template) = pack
            .route_templates
            .get(instantiated.route_template.as_str())
        {
            for (name, value) in &instantiated.parameters {
                let Some(parameter) = template
                    .parameters
                    .iter()
                    .find(|parameter| parameter.name.as_str() == name.as_str())
                else {
                    findings.push(finding(
                        CheckCode::ProjectUnknownTemplateParameter,
                        &format!("{prefix}/parameters/{name}"),
                        "the instantiation supplies a parameter the template does not declare",
                        "Supply only parameters the template declares.",
                    ));
                    continue;
                };
                if !value_matches_type(value, parameter.r#type) {
                    findings.push(finding(
                        CheckCode::ProjectParameterTypeMismatch,
                        &format!("{prefix}/parameters/{name}"),
                        "the supplied value does not match the declared parameter type",
                        "Supply a value of the declared type.",
                    ));
                }
            }
            // A default_value fills an omitted optional parameter; a
            // required parameter must be supplied explicitly.
            for parameter in &template.parameters {
                if parameter.required
                    && !instantiated
                        .parameters
                        .contains_key(parameter.name.as_str())
                {
                    findings.push(finding(
                        CheckCode::ProjectRequiredParameterUnbound,
                        &format!("{prefix}/parameters/{}", parameter.name.as_str()),
                        "a required parameter is not bound by the instantiation",
                        "Supply the parameter in the instantiation's parameters.",
                    ));
                }
            }
        }
    }

    for (index, binding) in project.bindings.iter().enumerate() {
        let prefix = format!("/bindings/{index}");
        let operation = workspace.profile.operations.get(binding.operation.as_str());
        if operation.is_none() {
            findings.push(finding(
                CheckCode::ProjectUnknownOperation,
                &format!("{prefix}/operation"),
                "the binding references no declared profile operation",
                "Name an operation the pinned profile declares.",
            ));
        }
        if workspace
            .project
            .record_types
            .get(binding.record_type.as_str())
            .is_none()
        {
            findings.push(finding(
                CheckCode::ProjectUnknownRecordType,
                &format!("{prefix}/recordType"),
                "the binding references no declared record type",
                "Name a record type the project declares.",
            ));
        }
        // A raw template never instantiated has no concrete send shape:
        // the runtime would interpolate nothing and send the placeholder
        // text, so a binding may only name a pack route or an
        // instantiated route.
        let instantiated = project
            .templated_routes
            .iter()
            .any(|instantiated| instantiated.route_id.as_str() == binding.route.as_str());
        if pack.routes.get(binding.route.as_str()).is_none() && !instantiated {
            findings.push(finding(
                CheckCode::ProjectTemplateNotInstantiated,
                &format!("{prefix}/route"),
                "the binding names a raw template that is never instantiated",
                "Name a pack route, or instantiate the template in templatedRoutes and bind its route id.",
            ));
        }
        let route_steps = bodies_by_id.get(binding.route.as_str()).copied();
        if route_steps.is_none() {
            findings.push(finding(
                CheckCode::ProjectUnknownRoute,
                &format!("{prefix}/route"),
                "the binding references no route the pack or project declares",
                "Name an internal route, template, or instantiated route id.",
            ));
        }
        if let (Some(operation), Some(route_steps)) = (operation, route_steps) {
            let oauth_endpoints: HashSet<&str> = pack
                .endpoints
                .iter()
                .filter(|endpoint| {
                    matches!(
                        endpoint.authentication,
                        EndpointAuthentication::Oauth2ClientCredentials { .. }
                            | EndpointAuthentication::Oauth2PrivateKeyJwt { .. }
                    )
                })
                .map(|endpoint| endpoint.id.as_str())
                .collect();
            let (worst, depth_exceeded) = route_worst_case(route_steps, &bodies, &oauth_endpoints);
            if depth_exceeded {
                findings.push(finding(
                    CheckCode::RouteNestingDepthExceeded,
                    &format!("{prefix}/route"),
                    "the route nests past the reader's depth bound, so its worst case is uncountable",
                    "Flatten the nesting; the reader refuses documents deeper than the bound.",
                ));
            }
            if worst > binding.maximum_upstream_calls.get() {
                findings.push(finding(
                    CheckCode::ProjectUpstreamBudgetExceeded,
                    &format!("{prefix}/maximumUpstreamCalls"),
                    "the route's static worst-case upstream call count exceeds the binding's budget",
                    "Raise maximumUpstreamCalls, or bound the sends the route can make.",
                ));
            }
            if !operation.method.is_safe() {
                findings.extend(write_route_checks(&prefix, route_steps, &bodies));
            }
        }
    }

    for (index, access) in project.access_profiles.iter().enumerate() {
        let prefix = format!("/accessProfiles/{index}");
        for (operation_index, operation) in access.operations.iter().enumerate() {
            if workspace
                .profile
                .operations
                .get(operation.as_str())
                .is_none()
            {
                findings.push(finding(
                    CheckCode::ProjectUnknownOperation,
                    &format!("{prefix}/operations/{operation_index}"),
                    "the access profile references no declared profile operation",
                    "Name an operation the pinned profile declares.",
                ));
            }
        }
        for (type_index, record_type) in access.record_types.iter().enumerate() {
            if workspace
                .project
                .record_types
                .get(record_type.as_str())
                .is_none()
            {
                findings.push(finding(
                    CheckCode::ProjectUnknownRecordType,
                    &format!("{prefix}/recordTypes/{type_index}"),
                    "the access profile references no declared record type",
                    "Name a record type the project declares.",
                ));
            }
        }
    }
    findings
}

/// The write-route rules of `products/adapter/CONCEPT.md` section 9: every
/// non-safe send sits inside an `idempotentConsumer`, and a write route
/// carries at most one non-safe send until write resume lands in
/// Increment 3.
fn write_route_checks(
    prefix: &str,
    steps: &[Step],
    bodies: &HashMap<&str, &[Step]>,
) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    let sends = collect_non_safe_sends(steps, bodies);
    if sends.iter().any(|send| !send.inside_idempotency) {
        findings.push(finding(
            CheckCode::RouteWriteWithoutIdempotency,
            &format!("{prefix}/route"),
            "a write route sends outside an idempotentConsumer wrapper",
            "Wrap the write route's sends in idempotentConsumer.",
        ));
    }
    // A send repeated per item or iteration counts as more than one
    // non-safe send.
    if sends.len() > 1 || sends.iter().any(|send| send.repeated) {
        findings.push(finding(
            CheckCode::RouteMultipleNonSafeSends,
            &format!("{prefix}/route"),
            "the write route carries more than one non-safe send before Increment 3",
            "Split the write across bound operations, or wait for write resume.",
        ));
    }
    findings
}

/// The static worst-case upstream call count of a route
/// (`products/adapter/CONCEPT.md` sections 5.5 and 10.2): the route body
/// plus the widest exception-clause body, where a `continued` clause
/// counts its body once per route-body worst-case send because it
/// resumes after the failure point; every send counts one plus the
/// declared `maximumRedeliveries` attempts; and each OAuth endpoint the
/// route touches adds the single resend after a refreshed 401. Token
/// requests themselves sit outside `maximumUpstreamCalls` (CONCEPT
/// section 10.2): the runtime caps them separately.
fn route_worst_case(
    steps: &[Step],
    bodies: &HashMap<&str, &[Step]>,
    oauth_endpoints: &HashSet<&str>,
) -> (u64, bool) {
    let mut walk = WorstCaseWalk {
        bodies,
        oauth_endpoints,
        used_oauth: &mut HashSet::new(),
        clauses: Vec::new(),
        depth_exceeded: false,
    };
    let main = worst_body(steps, &mut walk, 0, declared_redeliveries(steps), false, 1);
    let resends = u64::try_from(walk.used_oauth.len()).unwrap_or(u64::MAX);
    // A `continued` clause resumes after the failure point and can fire
    // once per body failure, so its candidate is the clause worst-case
    // once per route-body send, plus the clause worst-case when the body
    // itself cannot fail; handled and propagated clauses run once.
    let clause_worst = walk
        .clauses
        .iter()
        .map(|(worst, continued)| {
            if *continued {
                worst.saturating_mul(main.saturating_add(1))
            } else {
                *worst
            }
        })
        .max()
        .unwrap_or(0);
    (
        main.saturating_add(clause_worst).saturating_add(resends),
        walk.depth_exceeded,
    )
}

/// The redeliveries a body declares: the widest `maximumRedeliveries`
/// across its error handler and `onException` clauses. A `retryWhile`
/// predicate only stops redelivery earlier; `maximumRedeliveries` remains
/// the hard cap, so every send counts one plus the cap. This diverges
/// from Camel, where `retryWhile` overrides `maximumRedeliveries`;
/// `maximumUpstreamCalls` is a check-time guarantee and stays one.
fn declared_redeliveries(steps: &[Step]) -> u32 {
    let mut maximum = 0u32;
    walk_steps(steps, &mut |step, _| match step {
        Step::ErrorHandler(handler) => {
            if let Some(policy) = handler
                .default_error_handler
                .as_ref()
                .and_then(|handler| handler.redelivery_policy.as_ref())
            {
                maximum = maximum.max(policy.maximum_redeliveries);
            }
        }
        Step::OnException(clause) => {
            if let Some(policy) = &clause.redelivery_policy {
                maximum = maximum.max(policy.maximum_redeliveries);
            }
        }
        _ => {}
    });
    maximum
}

/// The shared state of one worst-case walk: the direct-expansion bodies,
/// the pack endpoints needing the 401 resend, and the accumulators.
struct WorstCaseWalk<'a> {
    bodies: &'a HashMap<&'a str, &'a [Step]>,
    oauth_endpoints: &'a HashSet<&'a str>,
    used_oauth: &'a mut HashSet<String>,
    /// Top-level exception-clause bodies seen so far, as (worst-case
    /// sends, whether the clause resumes with `continued`).
    clauses: Vec<(u64, bool)>,
    /// The walk nested past the reader's depth bound: the count is
    /// uncountable and the caller must refuse.
    depth_exceeded: bool,
}

/// The worst-case upstream send count of one body: `to` and `enrich`
/// count one send times the redelivery attempts in force, `direct:`
/// expands the target (its own redelivery declarations join the widest in
/// force), `split`, `loop`, and an `onException` clause inside them
/// multiply by their bounds, and `choice` takes the widest branch. A
/// `circuitBreaker` adds its body and its fallback, and a `doTry` adds
/// its body, the widest catch, and `doFinally`: the failures the clause
/// and fallback answer are separate worst cases layered on the body's.
/// Exception-clause bodies do not add to the running total; each
/// top-level clause body becomes a separate candidate (multiplied by the
/// route body in [`route_worst_case`] when the clause resumes with
/// `continued`), and a clause nested inside another clause adds to its
/// enclosing clause's body (the runtime can run both). A `filter`
/// wrapper is transparent: its contents count. Past the reader's
/// nesting bound the count is uncountable: the walk saturates at
/// `u64::MAX` and reports the depth, never a silent zero. The
/// `multiplier` carries the enclosing splits' and loops' bounds so a
/// deferred clause candidate carries them too.
fn worst_body(
    steps: &[Step],
    walk: &mut WorstCaseWalk<'_>,
    depth: usize,
    redeliveries: u32,
    in_clause: bool,
    multiplier: u64,
) -> u64 {
    if depth > registry_platform_yaml::MAXIMUM_DEPTH {
        walk.depth_exceeded = true;
        return u64::MAX;
    }
    let attempts = 1u64.saturating_add(u64::from(redeliveries));
    let mut total = 0u64;
    for step in steps {
        match step {
            Step::To(to) => match to.uri.component {
                SendComponent::Http | SendComponent::GraphQl => {
                    if walk.oauth_endpoints.contains(to.uri.id.as_str()) {
                        walk.used_oauth.insert(to.uri.id.to_string());
                    }
                    total = total.saturating_add(attempts.saturating_mul(multiplier));
                }
                SendComponent::Direct => {
                    if let Some(target) = walk.bodies.get(to.uri.id.as_str()) {
                        let target_redeliveries = redeliveries.max(declared_redeliveries(target));
                        total = total.saturating_add(worst_body(
                            target,
                            walk,
                            depth + 1,
                            target_redeliveries,
                            in_clause,
                            multiplier,
                        ));
                    }
                }
            },
            Step::Enrich(enrich) => match enrich.uri.component {
                SendComponent::Http | SendComponent::GraphQl => {
                    if walk.oauth_endpoints.contains(enrich.uri.id.as_str()) {
                        walk.used_oauth.insert(enrich.uri.id.to_string());
                    }
                    total = total.saturating_add(attempts.saturating_mul(multiplier));
                }
                SendComponent::Direct => {
                    if let Some(target) = walk.bodies.get(enrich.uri.id.as_str()) {
                        let target_redeliveries = redeliveries.max(declared_redeliveries(target));
                        total = total.saturating_add(worst_body(
                            target,
                            walk,
                            depth + 1,
                            target_redeliveries,
                            in_clause,
                            multiplier,
                        ));
                    }
                }
            },
            Step::Split(split) => {
                let items = split.maximum_items.map_or(1u64, |bound| bound.get());
                total = total.saturating_add(worst_body(
                    &split.steps,
                    walk,
                    depth + 1,
                    redeliveries,
                    in_clause,
                    multiplier.saturating_mul(items),
                ));
            }
            Step::Loop(loop_step) => {
                let iterations = loop_step
                    .maximum_iterations
                    .map_or(1u64, |bound| bound.get());
                total = total.saturating_add(worst_body(
                    &loop_step.steps,
                    walk,
                    depth + 1,
                    redeliveries,
                    in_clause,
                    multiplier.saturating_mul(iterations),
                ));
            }
            Step::Choice(choice) => {
                let mut widest = 0u64;
                for when in &choice.when {
                    widest = widest.max(worst_body(
                        &when.steps,
                        walk,
                        depth + 1,
                        redeliveries,
                        in_clause,
                        multiplier,
                    ));
                }
                if let Some(otherwise) = &choice.otherwise {
                    widest = widest.max(worst_body(
                        &otherwise.steps,
                        walk,
                        depth + 1,
                        redeliveries,
                        in_clause,
                        multiplier,
                    ));
                }
                total = total.saturating_add(widest);
            }
            Step::CircuitBreaker(breaker) => {
                total = total.saturating_add(worst_body(
                    &breaker.steps,
                    walk,
                    depth + 1,
                    redeliveries,
                    in_clause,
                    multiplier,
                ));
                if let Some(fallback) = &breaker.on_fallback {
                    total = total.saturating_add(worst_body(
                        &fallback.steps,
                        walk,
                        depth + 1,
                        redeliveries,
                        in_clause,
                        multiplier,
                    ));
                }
            }
            Step::Throttle(throttle) => {
                total = total.saturating_add(worst_body(
                    &throttle.steps,
                    walk,
                    depth + 1,
                    redeliveries,
                    in_clause,
                    multiplier,
                ));
            }
            Step::IdempotentConsumer(idempotent) => {
                total = total.saturating_add(worst_body(
                    &idempotent.steps,
                    walk,
                    depth + 1,
                    redeliveries,
                    in_clause,
                    multiplier,
                ));
            }
            Step::DoTry(do_try) => {
                total = total.saturating_add(worst_body(
                    &do_try.steps,
                    walk,
                    depth + 1,
                    redeliveries,
                    in_clause,
                    multiplier,
                ));
                let mut widest = 0u64;
                for catch in &do_try.do_catch {
                    widest = widest.max(worst_body(
                        &catch.steps,
                        walk,
                        depth + 1,
                        redeliveries,
                        in_clause,
                        multiplier,
                    ));
                }
                total = total.saturating_add(widest);
                if let Some(do_finally) = &do_try.do_finally {
                    total = total.saturating_add(worst_body(
                        &do_finally.steps,
                        walk,
                        depth + 1,
                        redeliveries,
                        in_clause,
                        multiplier,
                    ));
                }
            }
            Step::Filter(filter) => {
                total = total.saturating_add(worst_body(
                    &filter.steps,
                    walk,
                    depth + 1,
                    redeliveries,
                    in_clause,
                    multiplier,
                ));
            }
            Step::OnException(clause) => {
                let clause_redeliveries = clause
                    .redelivery_policy
                    .as_ref()
                    .map_or(redeliveries, |policy| {
                        redeliveries.max(policy.maximum_redeliveries)
                    });
                let worst = worst_body(
                    &clause.steps,
                    walk,
                    depth + 1,
                    clause_redeliveries,
                    true,
                    multiplier,
                );
                if in_clause {
                    total = total.saturating_add(worst);
                } else {
                    walk.clauses.push((worst, clause.continued == Some(true)));
                }
            }
            _ => {}
        }
    }
    total
}

/// Runtime checks (`products/adapter/CONCEPT.md` sections 10.2 and 13.7):
/// endpoint coverage, credential-kind match, loopback-only `none`, and the
/// plain-HTTP confinement.
#[must_use]
pub fn check_runtime(workspace: &Workspace<'_>, runtime: &AdapterRuntimeConfig) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    let pack = workspace.pack;

    for (index, binding) in runtime.endpoints.iter().enumerate() {
        let prefix = format!("/endpoints/{index}");
        let endpoint = pack.endpoints.get(binding.endpoint.as_str());
        if endpoint.is_none() {
            findings.push(finding(
                CheckCode::RuntimeUnknownEndpoint,
                &format!("{prefix}/endpoint"),
                "the runtime binds no endpoint the pack declares",
                "Name an endpoint the pinned pack declares.",
            ));
            continue;
        }
        let endpoint = endpoint.expect("checked");
        match &binding.credential {
            Some(credential) => {
                check_credential_pair(
                    &prefix,
                    &endpoint.authentication,
                    credential,
                    binding,
                    &mut findings,
                );
            }
            None => {
                findings.push(finding(
                    CheckCode::AuthKindMismatch,
                    &format!("{prefix}/credential"),
                    "the endpoint declares an authentication kind the runtime does not bind",
                    "Bind a credential of the endpoint's kind in the runtime config.",
                ));
            }
        }
        if is_plain_http(&binding.base_url) {
            findings.push(finding(
                CheckCode::RuntimeInsecureOrigin,
                &format!("{prefix}/baseUrl"),
                "the endpoint's origin is plain HTTP outside the loopback exception",
                "Serve the origin over TLS.",
            ));
        }
    }
    for endpoint in pack.endpoints.iter() {
        if runtime.endpoints.get(endpoint.id.as_str()).is_none() {
            findings.push(finding(
                CheckCode::RuntimeMissingEndpoint,
                "/endpoints",
                "a pack endpoint has no runtime binding",
                "Bind a base URL for every endpoint the pack declares.",
            ));
        }
    }
    if runtime.allowed_private_cidrs.len() > crate::naming::MAX_ALLOWED_PRIVATE_CIDRS {
        findings.push(finding(
            CheckCode::RuntimeInsecureOrigin,
            "/allowedPrivateCidrs",
            "the private allowlist carries more entries than the platform bound",
            "Reduce the allowlist to the platform bound.",
        ));
    }
    findings
}

fn check_credential_pair(
    prefix: &str,
    kind: &EndpointAuthentication,
    credential: &RuntimeCredential,
    binding: &crate::runtime::EndpointBinding,
    findings: &mut Vec<Diagnostic>,
) {
    if kind.kind() != credential.kind() {
        findings.push(finding(
            CheckCode::AuthKindMismatch,
            &format!("{prefix}/credential"),
            "the runtime credential's kind does not match the endpoint's declared kind",
            "Bind a credential whose type equals the endpoint's authentication kind.",
        ));
        return;
    }
    if let (EndpointAuthentication::None {}, RuntimeCredential::None {}) = (kind, credential) {
        let loopback = is_loopback_origin(&binding.base_url);
        if !loopback && binding.mtls_identity.is_none() {
            findings.push(finding(
                CheckCode::AuthNoneNotLoopback,
                &format!("{prefix}/credential"),
                "a none credential reaches a non-loopback origin without an mTLS identity",
                "Add an mTLS client identity, or declare an authentication kind.",
            ));
        }
    }
    // The token endpoint is a fixed destination the engine dials with the
    // shared secret in hand, so it answers to the same origin rule as the
    // binding's base URL (`products/adapter/CONCEPT.md` section 10.2).
    let token_endpoint = match credential {
        RuntimeCredential::Oauth2ClientCredentials { token_endpoint, .. } => token_endpoint,
        RuntimeCredential::Oauth2PrivateKeyJwt { token_endpoint, .. } => token_endpoint,
        _ => return,
    };
    if is_plain_http(token_endpoint) {
        findings.push(finding(
            CheckCode::RuntimeInsecureOrigin,
            &format!("{prefix}/credential/tokenEndpoint"),
            "the token endpoint's origin is plain HTTP outside the loopback exception",
            "Serve the token endpoint over TLS.",
        ));
    }
}

/// Whether a bound origin's host is a numeric loopback address.
fn is_loopback_origin(url: &registry_platform_yaml::Url) -> bool {
    url.to_url()
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
}

/// Whether a bound origin is plain HTTP on a non-loopback host.
fn is_plain_http(url: &registry_platform_yaml::Url) -> bool {
    if url.is_https() {
        return false;
    }
    !is_loopback_origin(url)
}

/// The problem code a non-2xx entry expects is checked against the
/// profile's declared problem codes: the facade's error path emits a code
/// the profile fills its problem envelope with, so an entry expecting an
/// undeclared code can never pass a run. The check sits at the entry; the
/// body shape itself is the response-schema check's concern.
fn problem_code_check(
    entry_pointer: &str,
    expected: &crate::fixture::RecordedResponse,
    profile: &AdapterProfile,
) -> Vec<Diagnostic> {
    let non_2xx =
        registry_platform_yaml::BoundedU32::<200, 299>::new(expected.status.get()).is_err();
    let code = expected
        .body
        .as_ref()
        .and_then(|body| body.get("code"))
        .and_then(|code| code.as_str());
    let (Some(code), true) = (code, non_2xx) else {
        return Vec::new();
    };
    if profile
        .problem_codes
        .iter()
        .any(|declared| declared.as_str() == code)
    {
        Vec::new()
    } else {
        vec![finding(
            CheckCode::FixtureUnknownProblemCode,
            entry_pointer,
            "the entry expects a problem code the bound profile does not declare",
            "Expect a problem code the pinned profile declares, or declare the code in the profile.",
        )]
    }
}

/// Fixture checks (`products/adapter/CONCEPT.md` sections 10.2 and 13.3):
/// intercepts and recorded requests name declared endpoints; a route never
/// declares its own test intercepts, so there is nothing else to refuse.
#[must_use]
pub fn check_fixtures(workspace: &Workspace<'_>) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    let endpoint_ids: HashSet<&str> = workspace
        .pack
        .endpoints
        .iter()
        .map(|endpoint| endpoint.id.as_str())
        .collect();
    for (fixture_index, fixture) in workspace.fixtures.iter().enumerate() {
        let prefix = format!("/fixtures/{fixture_index}");
        for (intercept_index, intercept) in fixture.intercepts.iter().enumerate() {
            let named = match intercept {
                Intercept::Endpoint { endpoint } => endpoint,
                Intercept::TokenEndpoint { endpoint } => endpoint,
            };
            if !endpoint_ids.contains(named.as_str()) {
                findings.push(finding(
                    CheckCode::FixtureUnknownIntercept,
                    &format!("{prefix}/intercepts/{intercept_index}"),
                    "the intercept names no endpoint the pack declares",
                    "Name an endpoint the pinned pack declares.",
                ));
            }
        }
        for (entry_index, entry) in fixture.entries.iter().enumerate() {
            if !endpoint_ids.contains(entry.given.endpoint.as_str()) {
                findings.push(finding(
                    CheckCode::FixtureUnknownEndpoint,
                    &format!("{prefix}/entries/{entry_index}/given/endpoint"),
                    "the recorded request names no endpoint the pack declares",
                    "Record the exchange against an endpoint the pinned pack declares.",
                ));
            }
            // The entry's operation is the facade-side primary key: the
            // deployment must be able to exercise it, so it must be a
            // profile operation the project binds to a route.
            let operation_pointer = &format!("{prefix}/entries/{entry_index}/operation");
            let declared = workspace.profile.operations.get(entry.operation.as_str());
            let bound = workspace
                .project
                .bindings
                .iter()
                .any(|binding| binding.operation.as_str() == entry.operation.as_str());
            match (declared, bound) {
                (None, _) => findings.push(finding(
                    CheckCode::FixtureUnknownOperation,
                    operation_pointer,
                    "the entry names no operation the bound profile declares",
                    "Name an operation id the pinned profile declares.",
                )),
                (Some(_), false) => findings.push(finding(
                    CheckCode::FixtureUnknownOperation,
                    operation_pointer,
                    "the entry names a profile operation the project binds to no route",
                    "Name an operation a binding of the project binds to a route.",
                )),
                (Some(_), true) => {
                    findings.extend(problem_code_check(
                        &format!("{prefix}/entries/{entry_index}"),
                        &entry.expected_facade_response,
                        workspace.profile,
                    ));
                }
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{CredentialPlacement, MtlsIdentity};
    use crate::fixture::{
        AdapterFixture, FixtureEntry, FixtureProvenance, Intercept, RecordedRequest,
        RecordedResponse,
    };
    use crate::model::{ComponentKind, HttpMethod, RhaiExpression, SendUri};
    use crate::pack::{AdapterPack, Capabilities, Endpoint, EndpointOperation};
    use crate::profile::{PaginationParameters, ParameterizedPart, ProfileOperation};
    use crate::project::{
        AccessProfile, Binding, PinnedRef, ProjectIdentity, RecordField, RecordFieldType,
        RecordType,
    };
    use crate::route::{
        ChoiceStep, CircuitBreakerStep, DefaultErrorHandler, DoCatch, DoFinally, DoTryStep,
        EnrichStep, ErrorHandlerStep, FilterStep, IdempotentConsumerStep, LoopStep,
        OnExceptionStep, OnFallback, Percentage, PositiveU32, RedeliveryOptions, RouteDefinition,
        RouteFrom, RouteTemplate, SetHeaderStep, SplitStep, TemplateParameter,
        TemplateParameterType, TemplatedRoute, ThrottleStep, ToParameters, ToStep, When,
    };
    use crate::runtime::{AdapterRuntimeConfig, AuditRetention, EndpointBinding};
    use registry_platform_yaml::Url;
    use registry_platform_yaml::{
        BoundedU32, BoundedU64, Digest, LocalId, SecretReference, UniqueIdList, UniqueList,
    };
    use std::collections::BTreeMap;

    fn digest() -> Digest {
        Digest::new("sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9")
            .expect("digest")
    }

    fn id(text: &str) -> ExternalId {
        ExternalId::new(text).expect("id")
    }

    fn local(text: &str) -> LocalId {
        LocalId::new(text).expect("local id")
    }

    fn send(endpoint: &str) -> SendUri {
        SendUri::parse(&format!("http:{endpoint}")).expect("uri")
    }

    fn direct(route: &str) -> SendUri {
        SendUri::parse(&format!("direct:{route}")).expect("uri")
    }

    fn to_get(endpoint: &str) -> Step {
        Step::To(ToStep {
            uri: send(endpoint),
            parameters: Some(ToParameters {
                http_method: HttpMethod::Get,
                path: None,
                path_parameters: BTreeMap::new(),
                query: BTreeMap::new(),
                body: None,
                operation: None,
                throw_exception_on_failure: true,
                ok_status_code_range: None,
                resume_bindings: Vec::new(),
            }),
        })
    }

    fn to_post(endpoint: &str, operation: &str) -> Step {
        Step::To(ToStep {
            uri: send(endpoint),
            parameters: Some(ToParameters {
                http_method: HttpMethod::Post,
                path: None,
                path_parameters: BTreeMap::new(),
                query: BTreeMap::new(),
                body: None,
                operation: Some(id(operation)),
                throw_exception_on_failure: true,
                ok_status_code_range: None,
                resume_bindings: Vec::new(),
            }),
        })
    }

    fn rhai_expr(file: &str) -> RhaiExpression {
        RhaiExpression {
            file: file.to_string(),
            entrypoint: "main".to_string(),
        }
    }

    fn rhai(file: &str) -> Expression {
        Expression::Rhai(RhaiExpression {
            file: file.to_string(),
            entrypoint: "main".to_string(),
        })
    }

    fn pack_builder(endpoints: Vec<Endpoint>, routes: Vec<RouteDefinition>) -> AdapterPack {
        AdapterPack {
            version: "1.0.0".to_string(),
            id: local("case-api-pack"),
            tested_versions: vec!["2.7".to_string()],
            endpoints: UniqueIdList::new(endpoints).expect("unique"),
            route_templates: UniqueIdList::<RouteTemplate>::new(Vec::new()).expect("empty"),
            routes: UniqueIdList::new(routes).expect("unique"),
            code_maps: UniqueIdList::new(Vec::new()).expect("empty"),
            scripts: UniqueList::new(vec![crate::model::ScriptReference {
                path: "scripts/map.rhai".to_string(),
                digest: digest(),
            }])
            .expect("unique"),
            query_files: UniqueList::new(Vec::new()).expect("empty"),
            capabilities: Capabilities::default(),
        }
    }

    fn oauth_endpoint() -> Endpoint {
        Endpoint {
            id: local("case-api"),
            component: ComponentKind::Http,
            authentication: EndpointAuthentication::Oauth2ClientCredentials {},
            response_headers: UniqueList::new(Vec::new()).expect("empty"),
            operations: vec![EndpointOperation {
                id: local("cases-create"),
                idempotent_upstream: true,
            }],
            tested_versions: vec!["2.7".to_string()],
            query_file: None,
            operation_name: None,
            variables: None,
        }
    }

    fn basic_endpoint() -> Endpoint {
        Endpoint {
            id: local("case-api"),
            component: ComponentKind::Http,
            authentication: EndpointAuthentication::Basic {},
            response_headers: UniqueList::new(Vec::new()).expect("empty"),
            operations: vec![EndpointOperation {
                id: local("cases-find"),
                idempotent_upstream: true,
            }],
            tested_versions: vec!["2.7".to_string()],
            query_file: None,
            operation_name: None,
            variables: None,
        }
    }

    fn profile_builder(operations: Vec<ProfileOperation>) -> AdapterProfile {
        AdapterProfile {
            version: "1.0.0".to_string(),
            id: local("case-api"),
            operations: UniqueIdList::new(operations).expect("unique"),
            problem_codes: UniqueList::new(vec![id("cases.conflict")]).expect("unique"),
            problem_envelope: EnvelopeTemplate(r#"{"code": "{{problemCode}}"}"#.to_string()),
            parameterized_parts: UniqueList::<ParameterizedPart>::new(Vec::new()).expect("empty"),
        }
    }

    fn operation(id_text: &str, method: HttpMethod) -> ProfileOperation {
        ProfileOperation {
            id: local(id_text),
            method,
            path: "/v2/cases/{type}".to_string(),
            request_envelope: None,
            response_envelope: EnvelopeTemplate(r#"{"cases": {{records}}}"#.to_string()),
            pagination: None,
        }
    }

    fn project_builder(pack: &AdapterPack) -> AdapterProject {
        AdapterProject {
            project: ProjectIdentity {
                id: local("case-deployment"),
                version: "1.0.0".to_string(),
            },
            profile: PinnedRef {
                id: local("case-api"),
                version: "1.0.0".to_string(),
                digest: digest(),
            },
            pack: PinnedRef {
                id: pack.id.clone(),
                version: "1.0.0".to_string(),
                digest: digest(),
            },
            record_types: UniqueIdList::new(vec![RecordType {
                name: local("case"),
                fields: UniqueList::new(vec![RecordField {
                    name: local("national_id"),
                    r#type: RecordFieldType::String,
                    required: true,
                }])
                .expect("unique"),
            }])
            .expect("unique"),
            templated_routes: UniqueIdList::<TemplatedRoute>::new(Vec::new()).expect("empty"),
            bindings: UniqueIdList::<Binding>::new(Vec::new()).expect("empty"),
            access_profiles: UniqueIdList::new(vec![AccessProfile {
                id: local("registry-clerk"),
                scopes: UniqueList::new(vec![id("cases:read")]).expect("unique"),
                operations: UniqueList::new(vec![id("cases-find")]).expect("unique"),
                record_types: UniqueList::new(vec![local("case")]).expect("unique"),
            }])
            .expect("unique"),
        }
    }

    fn workspace<'a>(
        profile: &'a AdapterProfile,
        pack: &'a AdapterPack,
        project: &'a AdapterProject,
    ) -> Workspace<'a> {
        Workspace {
            profile,
            pack,
            project,
            runtime: None,
            fixtures: &[],
        }
    }

    fn codes(findings: &[Diagnostic]) -> Vec<&str> {
        findings
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect()
    }

    fn assert_has(findings: &[Diagnostic], code: CheckCode) {
        assert!(
            codes(findings).contains(&code.code()),
            "expected {} in {:?}",
            code.code(),
            codes(findings)
        );
    }

    fn assert_clean(findings: Vec<Diagnostic>) {
        assert!(
            findings.is_empty(),
            "expected no findings, got {:?}",
            findings.iter().map(|f| f.code.as_str()).collect::<Vec<_>>()
        );
    }

    /// The script-uncompilable code exists for the ctl's precompile walk,
    /// and the public walkers expose every expression so the ctl reuses
    /// core's exhaustive walk instead of duplicating it.
    #[test]
    fn script_uncompilable_code_resolves_and_walkers_expose_expressions() {
        assert_eq!(
            CheckCode::from_code("adapter.pack.script-uncompilable"),
            Some(CheckCode::PackScriptUncompilable)
        );
        let steps = vec![
            Step::SetBody(rhai("scripts/map.rhai")),
            Step::Filter(crate::route::FilterStep {
                constant: None,
                header: None,
                exchange_property: None,
                jsonpath: None,
                rhai: Some(RhaiExpression {
                    file: "scripts/guard.rhai".to_string(),
                    entrypoint: "admits".to_string(),
                }),
                steps: vec![],
            }),
        ];
        let files: Vec<String> = script_references(&steps)
            .into_iter()
            .map(|script| script.file)
            .collect();
        assert_eq!(files, ["scripts/map.rhai", "scripts/guard.rhai"]);
        // The expression walk stays public for the ctl's own consumers.
        assert_eq!(step_expressions(&steps[0]), vec![rhai("scripts/map.rhai")]);
    }

    // ----- envelope and profile checks -----

    #[test]
    fn profile_accepts_a_closed_envelope_set() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        assert_clean(check_profile(&profile));
    }

    #[test]
    fn profile_refuses_an_unknown_slot() {
        let profile = profile_builder(vec![ProfileOperation {
            id: local("cases-find"),
            method: HttpMethod::Get,
            path: "/v2/cases/{type}".to_string(),
            request_envelope: None,
            response_envelope: EnvelopeTemplate(r#"{{mysterySlot}}"#.to_string()),
            pagination: None,
        }]);
        assert_has(&check_profile(&profile), CheckCode::ProfileUnknownSlot);
    }

    #[test]
    fn profile_refuses_a_response_envelope_without_its_result_slot() {
        let profile = profile_builder(vec![ProfileOperation {
            id: local("cases-find"),
            method: HttpMethod::Get,
            path: "/v2/cases/{type}".to_string(),
            request_envelope: None,
            response_envelope: EnvelopeTemplate(r#"{"empty": true}"#.to_string()),
            pagination: None,
        }]);
        assert_has(
            &check_profile(&profile),
            CheckCode::ProfileResponseEnvelopeMissingResultSlot,
        );
    }

    #[test]
    fn profile_refuses_a_problem_envelope_without_its_code_slot() {
        let mut profile = profile_builder(vec![]);
        profile.problem_envelope = EnvelopeTemplate(r#"{"title": "{{problemTitle}}"}"#.to_string());
        assert_has(
            &check_profile(&profile),
            CheckCode::ProfileProblemEnvelopeMissingCodeSlot,
        );
    }

    #[test]
    fn profile_refuses_a_malformed_placeholder() {
        let mut profile = profile_builder(vec![]);
        profile.problem_envelope = EnvelopeTemplate(r#"{{not a slot!}}"#.to_string());
        assert_has(
            &check_profile(&profile),
            CheckCode::EnvelopeInvalidPlaceholder,
        );
    }

    /// A write operation needs a request envelope naming the record slot;
    /// a read operation needs none.
    #[test]
    fn profile_refuses_a_write_operation_without_a_record_request_envelope() {
        let without_envelope = profile_builder(vec![operation("cases-create", HttpMethod::Post)]);
        assert_has(
            &check_profile(&without_envelope),
            CheckCode::ProfileRequestEnvelopeMissingRecordSlot,
        );
        let wrong_slot = profile_builder(vec![ProfileOperation {
            id: local("cases-create"),
            method: HttpMethod::Post,
            path: "/v2/cases/{type}".to_string(),
            request_envelope: Some(EnvelopeTemplate(r#"{{records}}"#.to_string())),
            response_envelope: EnvelopeTemplate(r#"{"cases": {{records}}}"#.to_string()),
            pagination: None,
        }]);
        assert_has(
            &check_profile(&wrong_slot),
            CheckCode::ProfileRequestEnvelopeMissingRecordSlot,
        );
        let good = profile_builder(vec![ProfileOperation {
            id: local("cases-create"),
            method: HttpMethod::Post,
            path: "/v2/cases/{type}".to_string(),
            request_envelope: Some(EnvelopeTemplate(r#"{"input": {{record}}}"#.to_string())),
            response_envelope: EnvelopeTemplate(r#"{"cases": {{records}}}"#.to_string()),
            pagination: None,
        }]);
        assert_clean(check_profile(&good));
    }

    #[test]
    fn placeholder_scanner_covers_both_forms_and_refuses_malformed() {
        assert_eq!(
            placeholders("{{record}} {{?nextCursor}}"),
            vec![
                ("record".to_string(), false),
                ("nextCursor".to_string(), true)
            ]
        );
        assert!(has_malformed_placeholder("before {{oops"));
        assert!(!has_malformed_placeholder("plain text"));
    }

    /// An optional pagination block round-trips through the profile checks
    /// untouched.
    #[test]
    fn pagination_parameters_are_accepted() {
        let profile = profile_builder(vec![ProfileOperation {
            id: local("cases-find"),
            method: HttpMethod::Get,
            path: "/v2/cases/{type}".to_string(),
            request_envelope: None,
            response_envelope: EnvelopeTemplate(r#"{"cases": {{records}}}"#.to_string()),
            pagination: Some(PaginationParameters {
                cursor_parameter: id("cursor"),
                page_size_parameter: id("limit"),
                page_size_minimum: BoundedU64::<1, 10_000>::new(1).expect("min"),
                page_size_maximum: BoundedU64::<1, 100_000>::new(500).expect("max"),
            }),
        }]);
        assert_clean(check_profile(&profile));
    }

    // ----- pack checks -----

    #[test]
    fn pack_accepts_producer_endpoints_with_pinned_scripts() {
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        assert_clean(check_pack(&pack));
    }

    #[test]
    fn pack_refuses_a_non_producer_endpoint_component() {
        let mut endpoint = oauth_endpoint();
        endpoint.component = ComponentKind::Direct;
        let findings = check_pack(&pack_builder(vec![endpoint], vec![]));
        assert_has(&findings, CheckCode::PackEndpointComponentInvalid);
    }

    #[test]
    fn pack_refuses_a_reserved_api_key_header_name() {
        let mut endpoint = oauth_endpoint();
        endpoint.authentication = EndpointAuthentication::StaticApiKey {
            header_name: "Authorization".to_string(),
        };
        let findings = check_pack(&pack_builder(vec![endpoint], vec![]));
        assert_has(&findings, CheckCode::PackReservedHeaderName);
        let mut fine = oauth_endpoint();
        fine.authentication = EndpointAuthentication::StaticApiKey {
            header_name: "X-Api-Key".to_string(),
        };
        assert!(!codes(&check_pack(&pack_builder(vec![fine], vec![])))
            .contains(&CheckCode::PackReservedHeaderName.code()));
    }

    #[test]
    fn pack_refuses_a_graphql_endpoint_without_a_query_file() {
        let mut endpoint = oauth_endpoint();
        endpoint.component = ComponentKind::GraphQl;
        let findings = check_pack(&pack_builder(vec![endpoint], vec![]));
        assert_has(&findings, CheckCode::PackGraphQlQueryRequired);
        let mut with_query = oauth_endpoint();
        with_query.component = ComponentKind::GraphQl;
        with_query.query_file = Some("queries/missing.graphql".to_string());
        let findings = check_pack(&pack_builder(vec![with_query], vec![]));
        assert_has(&findings, CheckCode::PackUnknownScript);
    }

    #[test]
    fn pack_refuses_an_unpinned_rhai_reference() {
        let route = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::SetBody(rhai("scripts/unpinned.rhai"))],
        };
        let pack = pack_builder(vec![], vec![route]);
        assert_has(&check_pack(&pack), CheckCode::PackUnknownScript);
        let pinned_route = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::SetBody(rhai("scripts/map.rhai"))],
        };
        let pinned_pack = pack_builder(vec![], vec![pinned_route]);
        assert!(!codes(&check_pack(&pinned_pack)).contains(&CheckCode::PackUnknownScript.code()));
    }

    // ----- route checks -----

    #[test]
    fn routes_accept_a_well_formed_direct_call() {
        let caller = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::Enrich(EnrichStep {
                uri: direct("shared-lookup"),
                aggregation_strategy: None,
                aggregate_on_exception: false,
                parameters: None,
            })],
        };
        let shared = RouteDefinition {
            id: local("shared-lookup"),
            from: RouteFrom {
                uri: direct("shared-lookup"),
            },
            steps: vec![to_get("case-api")],
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![caller, shared]);
        assert_clean(check_routes(&pack, &project_builder(&pack)));
    }

    #[test]
    fn routes_refuse_a_direct_cycle() {
        let first = RouteDefinition {
            id: local("first"),
            from: RouteFrom {
                uri: direct("first"),
            },
            steps: vec![Step::Enrich(EnrichStep {
                uri: direct("second"),
                aggregation_strategy: None,
                aggregate_on_exception: false,
                parameters: None,
            })],
        };
        let second = RouteDefinition {
            id: local("second"),
            from: RouteFrom {
                uri: direct("second"),
            },
            steps: vec![Step::Enrich(EnrichStep {
                uri: direct("first"),
                aggregation_strategy: None,
                aggregate_on_exception: false,
                parameters: None,
            })],
        };
        let pack = pack_builder(vec![], vec![first, second]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteDirectCycle,
        );
    }

    #[test]
    fn routes_refuse_an_unknown_direct_target_and_endpoint() {
        let route = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![
                Step::Enrich(EnrichStep {
                    uri: direct("nowhere"),
                    aggregation_strategy: None,
                    aggregate_on_exception: false,
                    parameters: None,
                }),
                to_get("undeclared-endpoint"),
            ],
        };
        let pack = pack_builder(vec![], vec![route]);
        let findings = check_routes(&pack, &project_builder(&pack));
        assert_has(&findings, CheckCode::RouteUnknownDirectTarget);
        assert_has(&findings, CheckCode::RouteUnknownEndpoint);
    }

    #[test]
    fn routes_refuse_a_from_outside_direct() {
        let route = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: send("case-api"),
            },
            steps: vec![],
        };
        let pack = pack_builder(vec![], vec![route]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteFromNotDirect,
        );
    }

    #[test]
    fn routes_refuse_split_and_loop_without_their_mandatory_bounds() {
        let route = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![
                Step::Split(SplitStep {
                    expression: Expression::JsonPath("$.items".to_string()),
                    maximum_items: None,
                    aggregation_strategy: None,
                    stop_on_exception: false,
                    error_threshold: None,
                    maximum_failed_records: None,
                    steps: vec![],
                }),
                Step::Loop(LoopStep {
                    maximum_iterations: None,
                    constant: None,
                    header: None,
                    exchange_property: None,
                    jsonpath: None,
                    rhai: None,
                    do_while: false,
                    copy: false,
                    steps: vec![],
                }),
            ],
        };
        let pack = pack_builder(vec![], vec![route]);
        let findings = check_routes(&pack, &project_builder(&pack));
        assert_has(&findings, CheckCode::RouteMaximumItemsRequired);
        assert_has(&findings, CheckCode::RouteMaximumIterationsRequired);
        let bounded = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![
                Step::Split(SplitStep {
                    expression: Expression::JsonPath("$.items".to_string()),
                    maximum_items: Some(BoundedU64::<1, 100_000>::new(10).expect("bound")),
                    aggregation_strategy: None,
                    stop_on_exception: false,
                    error_threshold: None,
                    maximum_failed_records: None,
                    steps: vec![],
                }),
                Step::Loop(LoopStep {
                    constant: Some(serde_json::json!(3)),
                    header: None,
                    exchange_property: None,
                    jsonpath: None,
                    rhai: None,
                    do_while: false,
                    maximum_iterations: Some(BoundedU64::<1, 100_000>::new(5).expect("bound")),
                    copy: false,
                    steps: vec![],
                }),
            ],
        };
        let bounded_pack = pack_builder(vec![], vec![bounded]);
        assert_clean(check_routes(&bounded_pack, &project_builder(&bounded_pack)));
    }

    /// A `direct:` send resolves by the target route's `from` URI, as
    /// Camel connects routes, not by the route id: a route whose id and
    /// from differ is reachable by its from name, and an unknown name is
    /// still refused (staff review P1-6).
    #[test]
    fn direct_sends_resolve_by_the_from_uri() {
        let target = || RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-cases"),
            },
            steps: vec![to_get("case-api")],
        };
        let caller = |target_name: &str| RouteDefinition {
            id: local("other"),
            from: RouteFrom {
                uri: direct("other"),
            },
            steps: vec![Step::To(ToStep {
                uri: direct(target_name),
                parameters: None,
            })],
        };
        let pack = pack_builder(vec![], vec![target(), caller("fetch-cases")]);
        assert!(!codes(&check_routes(&pack, &project_builder(&pack)))
            .contains(&CheckCode::RouteUnknownDirectTarget.code()));
        let pack = pack_builder(vec![], vec![target(), caller("fetch-case")]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteUnknownDirectTarget,
        );
    }

    /// The errorHandler carries exactly one handler: none or both refuse
    /// (staff review P1-7).
    #[test]
    fn routes_refuse_an_error_handler_without_exactly_one_handler() {
        let route = |handler: ErrorHandlerStep| RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::ErrorHandler(handler)],
        };
        let empty = pack_builder(
            vec![basic_endpoint()],
            vec![route(ErrorHandlerStep {
                default_error_handler: None,
                no_error_handler: None,
            })],
        );
        assert_has(
            &check_routes(&empty, &project_builder(&empty)),
            CheckCode::RouteErrorHandlerShape,
        );
        let both = pack_builder(
            vec![basic_endpoint()],
            vec![route(ErrorHandlerStep {
                default_error_handler: Some(DefaultErrorHandler {
                    redelivery_policy: None,
                }),
                no_error_handler: Some(crate::route::NoErrorHandler {}),
            })],
        );
        assert_has(
            &check_routes(&both, &project_builder(&both)),
            CheckCode::RouteErrorHandlerShape,
        );
        let one = pack_builder(
            vec![basic_endpoint()],
            vec![route(ErrorHandlerStep {
                default_error_handler: Some(DefaultErrorHandler {
                    redelivery_policy: None,
                }),
                no_error_handler: None,
            })],
        );
        assert!(!codes(&check_routes(&one, &project_builder(&one)))
            .contains(&CheckCode::RouteErrorHandlerShape.code()));
    }

    /// A binding may not name a raw template: only a pack route or an
    /// instantiated route id carries a concrete send shape (staff review
    /// P1-5).
    #[test]
    fn project_refuses_a_binding_of_a_never_instantiated_template() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        let template = RouteTemplate {
            id: local("pager"),
            parameters: Vec::new(),
            steps: vec![to_get("case-api")],
        };
        let mut pack = pack_builder(vec![basic_endpoint()], vec![]);
        pack.route_templates = UniqueIdList::new(vec![template]).expect("unique");
        let binding = |route: registry_platform_yaml::ExternalId| Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route,
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(10).expect("budget"),
        };
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        project.bindings = UniqueIdList::new(vec![binding(id("pager"))]).expect("unique");
        assert_has(
            &check_project(&workspace(&profile, &pack, &project)),
            CheckCode::ProjectTemplateNotInstantiated,
        );
        // Instantiating the template gives the binding a concrete route.
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        project.templated_routes = UniqueIdList::new(vec![TemplatedRoute {
            route_template: id("pager"),
            route_id: id("pager-1"),
            parameters: BTreeMap::new(),
        }])
        .expect("unique");
        project.bindings = UniqueIdList::new(vec![binding(id("pager-1"))]).expect("unique");
        assert!(
            !codes(&check_project(&workspace(&profile, &pack, &project)))
                .contains(&CheckCode::ProjectTemplateNotInstantiated.code())
        );
    }

    /// A send naming no operation is never idempotent by inheritance:
    /// caller redelivery over such a POST refuses (staff review P1-3).
    #[test]
    fn redelivery_refuses_a_post_that_names_no_operation() {
        let post = Step::To(ToStep {
            uri: send("case-api"),
            parameters: Some(ToParameters {
                http_method: HttpMethod::Post,
                path: None,
                path_parameters: BTreeMap::new(),
                query: BTreeMap::new(),
                body: None,
                operation: None,
                throw_exception_on_failure: true,
                ok_status_code_range: None,
                resume_bindings: Vec::new(),
            }),
        });
        let route = RouteDefinition {
            id: local("create-case"),
            from: RouteFrom {
                uri: direct("create-case"),
            },
            steps: vec![
                Step::ErrorHandler(ErrorHandlerStep {
                    default_error_handler: Some(DefaultErrorHandler {
                        redelivery_policy: Some(RedeliveryOptions {
                            maximum_redeliveries: 2,
                            ..Default::default()
                        }),
                    }),
                    no_error_handler: None,
                }),
                post,
            ],
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![route]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteRedeliveryOverNonSafeSend,
        );
    }

    /// The expression walk covers a send's path parameters and query, an
    /// exception policy's retryWhile, and Rhai aggregation strategies
    /// (staff review P1-4).
    #[test]
    fn step_expressions_cover_the_send_and_policy_slots() {
        let steps = [
            Step::To(ToStep {
                uri: send("case-api"),
                parameters: Some(ToParameters {
                    http_method: HttpMethod::Get,
                    path: Some("/v2/cases/{{caseId}}".to_string()),
                    path_parameters: BTreeMap::from([(
                        "caseId".to_string(),
                        rhai("scripts/id.rhai"),
                    )]),
                    query: BTreeMap::from([(id("cursor"), rhai("scripts/page.rhai"))]),
                    body: None,
                    operation: None,
                    throw_exception_on_failure: true,
                    ok_status_code_range: None,
                    resume_bindings: Vec::new(),
                }),
            }),
            Step::OnException(OnExceptionStep {
                exception: UniqueList::new(vec![crate::model::ErrorClass::UpstreamTimeout])
                    .expect("unique"),
                on_when: None,
                handled: None,
                continued: None,
                redelivery_policy: Some(RedeliveryOptions {
                    retry_while: Some(rhai("scripts/again.rhai")),
                    ..Default::default()
                }),
                steps: vec![],
            }),
            Step::Split(SplitStep {
                expression: rhai("scripts/pieces.rhai"),
                maximum_items: None,
                aggregation_strategy: Some(crate::model::AggregationStrategy::Rhai {
                    expression: rhai_expr("scripts/group.rhai"),
                }),
                stop_on_exception: false,
                error_threshold: None,
                maximum_failed_records: None,
                steps: vec![],
            }),
            Step::Enrich(EnrichStep {
                uri: send("case-api"),
                aggregation_strategy: Some(crate::model::AggregationStrategy::Rhai {
                    expression: rhai_expr("scripts/merge.rhai"),
                }),
                aggregate_on_exception: false,
                parameters: None,
            }),
        ];
        let files: Vec<String> = steps
            .iter()
            .flat_map(|step| {
                crate::checks::step_expressions(step)
                    .into_iter()
                    .filter_map(|expression| match expression {
                        Expression::Rhai(rhai) => Some(rhai.file),
                        _ => None,
                    })
            })
            .collect();
        for file in [
            "scripts/id.rhai",
            "scripts/page.rhai",
            "scripts/again.rhai",
            "scripts/pieces.rhai",
            "scripts/group.rhai",
            "scripts/merge.rhai",
        ] {
            assert!(files.contains(&file.to_string()), "missing {file}");
        }
    }

    /// A Rhai aggregation strategy names a digest-pinned script like any
    /// other reference (staff review P1-4).
    #[test]
    fn aggregation_rhai_scripts_resolve_to_the_inventory() {
        let route = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::Split(SplitStep {
                expression: rhai("scripts/pieces.rhai"),
                maximum_items: None,
                aggregation_strategy: Some(crate::model::AggregationStrategy::Rhai {
                    expression: rhai_expr("scripts/unpinned.rhai"),
                }),
                stop_on_exception: false,
                error_threshold: None,
                maximum_failed_records: None,
                steps: vec![to_get("case-api")],
            })],
        };
        let pack = pack_builder(vec![basic_endpoint()], vec![route]);
        assert_has(&check_pack(&pack), CheckCode::PackUnknownScript);
    }

    /// An enrichment classifies like a send once it carries the send
    /// parameters: a GET stays out of the non-safe set, a POST needs the
    /// idempotent claim, a POST naming an undeclared operation refuses,
    /// and its query scripts join the inventory (staff review P1-13).
    #[test]
    fn enrichment_writes_classify_like_sends() {
        let enrich = |http_method: HttpMethod, operation: Option<&str>| {
            Step::Enrich(EnrichStep {
                uri: send("case-api"),
                aggregation_strategy: None,
                aggregate_on_exception: false,
                parameters: Some(ToParameters {
                    http_method,
                    path: None,
                    path_parameters: BTreeMap::new(),
                    query: BTreeMap::new(),
                    body: None,
                    operation: operation.map(id),
                    throw_exception_on_failure: true,
                    ok_status_code_range: None,
                    resume_bindings: Vec::new(),
                }),
            })
        };
        let route = |step: Step| RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![
                Step::ErrorHandler(ErrorHandlerStep {
                    default_error_handler: Some(DefaultErrorHandler {
                        redelivery_policy: Some(RedeliveryOptions {
                            maximum_redeliveries: 2,
                            ..Default::default()
                        }),
                    }),
                    no_error_handler: None,
                }),
                step,
            ],
        };
        // A GET enrichment is not a write; redelivery over it stays clean.
        let read = route(enrich(HttpMethod::Get, Some("cases-find")));
        let pack = pack_builder(vec![oauth_endpoint()], vec![read]);
        assert_clean(check_routes(&pack, &project_builder(&pack)));
        // A POST enrichment needs the idempotentUpstream claim; the
        // endpoint's declared claim covers only the named operation.
        let write = route(enrich(HttpMethod::Post, None));
        let pack = pack_builder(vec![oauth_endpoint()], vec![write]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteRedeliveryOverNonSafeSend,
        );
        // A POST enrichment naming an operation the endpoint does not
        // declare refuses like any send.
        let ghost = route(enrich(HttpMethod::Post, Some("ghost")));
        let pack = pack_builder(vec![oauth_endpoint()], vec![ghost]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteUnknownOperation,
        );
        // Query scripts of an enrichment join the script inventory.
        let unscripted = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::Enrich(EnrichStep {
                uri: send("case-api"),
                aggregation_strategy: None,
                aggregate_on_exception: false,
                parameters: Some(ToParameters {
                    http_method: HttpMethod::Get,
                    path: None,
                    path_parameters: BTreeMap::new(),
                    query: BTreeMap::from([(
                        id("filter"),
                        crate::model::Expression::Rhai(crate::model::RhaiExpression {
                            file: "scripts/unpinned.rhai".to_string(),
                            entrypoint: "main".to_string(),
                        }),
                    )]),
                    body: None,
                    operation: None,
                    throw_exception_on_failure: true,
                    ok_status_code_range: None,
                    resume_bindings: Vec::new(),
                }),
            })],
        };
        let pack = pack_builder(vec![basic_endpoint()], vec![unscripted]);
        assert_has(&check_pack(&pack), CheckCode::PackUnknownScript);
    }

    /// A template send's path references declared parameters like any
    /// other slot: an undeclared `{{placeholder}}` in the path refuses
    /// (staff review P1-4).
    #[test]
    fn template_paths_reference_declared_parameters() {
        let template = |path: Option<String>| RouteTemplate {
            id: local("pager"),
            parameters: vec![TemplateParameter {
                name: local("cursor"),
                r#type: TemplateParameterType::String,
                required: true,
                default_value: None,
                description: None,
            }],
            steps: vec![Step::To(ToStep {
                uri: send("case-api"),
                parameters: Some(ToParameters {
                    http_method: HttpMethod::Get,
                    path,
                    path_parameters: BTreeMap::new(),
                    query: BTreeMap::new(),
                    body: None,
                    operation: None,
                    throw_exception_on_failure: true,
                    ok_status_code_range: None,
                    resume_bindings: Vec::new(),
                }),
            })],
        };
        let mut pack = pack_builder(vec![], vec![]);
        pack.route_templates =
            UniqueIdList::new(vec![template(Some("/v2/cases/{{cursor}}".to_string()))])
                .expect("unique");
        assert!(
            !codes(&check_pack(&pack)).contains(&CheckCode::PackUnknownTemplateParameter.code())
        );
        let mut undeclared = pack_builder(vec![], vec![]);
        undeclared.route_templates =
            UniqueIdList::new(vec![template(Some("/v2/cases/{{page}}".to_string()))])
                .expect("unique");
        assert_has(
            &check_pack(&undeclared),
            CheckCode::PackUnknownTemplateParameter,
        );
    }

    /// Composite nesting does not consume the direct depth bound: a
    /// redelivery over a send nested many composites and one direct hop
    /// deep still reaches its send, while a direct target that resolves
    /// to nothing stays dead config (staff review R2).
    #[test]
    fn redelivery_reaches_a_send_past_deep_composite_nesting() {
        let route = |target: Step| {
            let mut steps = vec![target];
            for _ in 0..17 {
                steps = vec![Step::Filter(FilterStep {
                    constant: None,
                    header: None,
                    exchange_property: None,
                    jsonpath: None,
                    rhai: None,
                    steps,
                })];
            }
            let mut route_steps = vec![Step::ErrorHandler(ErrorHandlerStep {
                default_error_handler: Some(DefaultErrorHandler {
                    redelivery_policy: Some(RedeliveryOptions {
                        maximum_redeliveries: 2,
                        ..Default::default()
                    }),
                }),
                no_error_handler: None,
            })];
            route_steps.extend(steps);
            RouteDefinition {
                id: local("create-case"),
                from: RouteFrom {
                    uri: direct("create-case"),
                },
                steps: route_steps,
            }
        };
        let writer = RouteDefinition {
            id: local("writer"),
            from: RouteFrom {
                uri: direct("writer"),
            },
            steps: vec![to_get("case-api")],
        };
        let pack = pack_builder(
            vec![basic_endpoint()],
            vec![
                writer.clone(),
                route(Step::To(ToStep {
                    uri: direct("writer"),
                    parameters: None,
                })),
            ],
        );
        assert!(!codes(&check_routes(&pack, &project_builder(&pack)))
            .contains(&CheckCode::RouteRedeliveryWithoutUpstreamSend.code()));
        // A direct hop to nothing is still dead config.
        let pack = pack_builder(
            vec![basic_endpoint()],
            vec![
                writer,
                route(Step::To(ToStep {
                    uri: direct("nowhere"),
                    parameters: None,
                })),
            ],
        );
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteRedeliveryWithoutUpstreamSend,
        );
    }

    /// A send naming an operation the endpoint does not declare is a
    /// reference defect refused on its own, redelivery or not (staff
    /// review P1-3).
    #[test]
    fn routes_refuse_a_send_naming_an_undeclared_operation() {
        let pack = |operation: Option<&str>| {
            let post = Step::To(ToStep {
                uri: send("case-api"),
                parameters: Some(ToParameters {
                    http_method: HttpMethod::Post,
                    path: None,
                    path_parameters: BTreeMap::new(),
                    query: BTreeMap::new(),
                    body: None,
                    operation: operation.map(id),
                    throw_exception_on_failure: true,
                    ok_status_code_range: None,
                    resume_bindings: Vec::new(),
                }),
            });
            let route = RouteDefinition {
                id: local("create-case"),
                from: RouteFrom {
                    uri: direct("create-case"),
                },
                steps: vec![post],
            };
            pack_builder(vec![oauth_endpoint()], vec![route])
        };
        assert_has(
            &check_routes(&pack(Some("ghost")), &project_builder(&pack(Some("ghost")))),
            CheckCode::RouteUnknownOperation,
        );
        // The declared operation passes.
        assert!(!codes(&check_routes(
            &pack(Some("cases-create")),
            &project_builder(&pack(Some("cases-create")))
        ))
        .contains(&CheckCode::RouteUnknownOperation.code()));
    }

    /// Write safety looks through `direct:`: two wrapped POSTs reached
    /// through a direct target refuse the one-non-safe-send rule (staff
    /// review P1-2).
    #[test]
    fn write_refuses_two_posts_through_direct() {
        let profile = profile_builder(vec![ProfileOperation {
            id: local("cases-create"),
            method: HttpMethod::Post,
            path: "/v2/cases/{type}".to_string(),
            request_envelope: Some(EnvelopeTemplate(r#"{"input": {{record}}}"#.to_string())),
            response_envelope: EnvelopeTemplate(r#"{"cases": {{records}}}"#.to_string()),
            pagination: None,
        }]);
        let writer = RouteDefinition {
            id: local("writer"),
            from: RouteFrom {
                uri: direct("writer"),
            },
            steps: vec![Step::IdempotentConsumer(IdempotentConsumerStep {
                expression: rhai("scripts/key.rhai"),
                eager: true,
                remove_on_failure: true,
                completion_eager: false,
                steps: vec![
                    to_post("case-api", "cases-create"),
                    to_post("case-api", "cases-create"),
                ],
            })],
        };
        let caller = RouteDefinition {
            id: local("create-case"),
            from: RouteFrom {
                uri: direct("create-case"),
            },
            steps: vec![Step::To(ToStep {
                uri: direct("writer"),
                parameters: None,
            })],
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![writer, caller]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("create-cases"),
            operation: id("cases-create"),
            record_type: local("case"),
            route: id("create-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(10).expect("budget"),
        }])
        .expect("unique");
        assert_has(
            &check_project(&workspace(&profile, &pack, &project)),
            CheckCode::RouteMultipleNonSafeSends,
        );
    }

    /// Caller-level redelivery over a POST inside a `direct:` target
    /// needs the target send's `idempotentUpstream` claim (staff review
    /// P1-2).
    #[test]
    fn write_refuses_caller_redelivery_over_a_post_inside_direct() {
        let writer = RouteDefinition {
            id: local("writer"),
            from: RouteFrom {
                uri: direct("writer"),
            },
            steps: vec![Step::IdempotentConsumer(IdempotentConsumerStep {
                expression: rhai("scripts/key.rhai"),
                eager: true,
                remove_on_failure: true,
                completion_eager: false,
                steps: vec![to_post("case-api", "cases-create")],
            })],
        };
        let caller = RouteDefinition {
            id: local("create-case"),
            from: RouteFrom {
                uri: direct("create-case"),
            },
            steps: vec![
                Step::ErrorHandler(ErrorHandlerStep {
                    default_error_handler: Some(DefaultErrorHandler {
                        redelivery_policy: Some(RedeliveryOptions {
                            maximum_redeliveries: 2,
                            ..Default::default()
                        }),
                    }),
                    no_error_handler: None,
                }),
                Step::To(ToStep {
                    uri: direct("writer"),
                    parameters: None,
                }),
            ],
        };
        let mut unclaimed = oauth_endpoint();
        unclaimed.operations = vec![EndpointOperation {
            id: local("cases-create"),
            idempotent_upstream: false,
        }];
        let pack = pack_builder(vec![unclaimed], vec![writer.clone(), caller.clone()]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteRedeliveryOverNonSafeSend,
        );
        // With the claim, the same shape is admitted.
        let claimed = pack_builder(vec![oauth_endpoint()], vec![writer, caller]);
        assert!(!codes(&check_routes(&claimed, &project_builder(&claimed)))
            .contains(&CheckCode::RouteRedeliveryOverNonSafeSend.code()));
    }

    /// A write `split` of POSTs runs the send per item, so it refuses the
    /// one-non-safe-send rule even wrapped and with `stopOnException`
    /// (staff review P1-2); a split of reads stays admitted.
    #[test]
    fn write_refuses_a_split_of_posts() {
        let route = |inner: Vec<Step>| RouteDefinition {
            id: local("create-case"),
            from: RouteFrom {
                uri: direct("create-case"),
            },
            steps: vec![Step::IdempotentConsumer(IdempotentConsumerStep {
                expression: rhai("scripts/key.rhai"),
                eager: true,
                remove_on_failure: true,
                completion_eager: false,
                steps: vec![Step::Split(SplitStep {
                    expression: rhai("scripts/pieces.rhai"),
                    maximum_items: Some(BoundedU64::<1, 100_000>::new(100).expect("items")),
                    aggregation_strategy: None,
                    stop_on_exception: true,
                    error_threshold: None,
                    maximum_failed_records: None,
                    steps: inner,
                })],
            })],
        };
        let profile = profile_builder(vec![ProfileOperation {
            id: local("cases-create"),
            method: HttpMethod::Post,
            path: "/v2/cases/{type}".to_string(),
            request_envelope: Some(EnvelopeTemplate(r#"{"input": {{record}}}"#.to_string())),
            response_envelope: EnvelopeTemplate(r#"{"cases": {{records}}}"#.to_string()),
            pagination: None,
        }]);
        let pack = pack_builder(
            vec![oauth_endpoint()],
            vec![route(vec![to_post("case-api", "cases-create")])],
        );
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("create-cases"),
            operation: id("cases-create"),
            record_type: local("case"),
            route: id("create-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(10_000).expect("budget"),
        }])
        .expect("unique");
        assert_has(
            &check_project(&workspace(&profile, &pack, &project)),
            CheckCode::RouteMultipleNonSafeSends,
        );
    }

    /// Findings come out in one order for the same input however the
    /// internal maps happen to hash: two runs over a pack whose routes
    /// each carry a finding agree element for element (staff review
    /// P1-12).
    #[test]
    fn findings_come_out_in_a_deterministic_order() {
        let routes: Vec<RouteDefinition> = (0..24)
            .map(|index| RouteDefinition {
                id: local(&format!("route-{index:02}")),
                from: RouteFrom {
                    uri: direct(&format!("route-{index:02}")),
                },
                steps: vec![to_get("not-an-endpoint")],
            })
            .collect();
        let pack = pack_builder(vec![], routes);
        let project = project_builder(&pack);
        let first = check_routes(&pack, &project);
        let second = check_routes(&pack, &project);
        assert_eq!(codes(&first).len(), 24);
        assert_eq!(codes(&first), codes(&second));
        // The pointers name the routes in id order, not hash order.
        let pointers: Vec<&str> = first.iter().map(|f| f.path.as_str()).collect();
        let mut sorted = pointers.clone();
        sorted.sort_unstable();
        assert_eq!(pointers, sorted);
    }

    /// The loop carries the flat single-language-key count or predicate
    /// form: zero keys or several are refused like a `filter` (staff
    /// review P0-3).
    #[test]
    fn loop_requires_exactly_one_language_key() {
        let loop_step =
            |constant: Option<serde_json::Value>, rhai: Option<Expression>| RouteDefinition {
                id: local("fetch-case"),
                from: RouteFrom {
                    uri: direct("fetch-case"),
                },
                steps: vec![Step::Loop(LoopStep {
                    constant,
                    header: None,
                    exchange_property: None,
                    jsonpath: None,
                    rhai: rhai.and_then(|expression| match expression {
                        Expression::Rhai(inner) => Some(inner),
                        _ => None,
                    }),
                    do_while: true,
                    maximum_iterations: Some(BoundedU64::<1, 100_000>::new(20).expect("bound")),
                    copy: false,
                    steps: vec![],
                })],
            };
        let pack = pack_builder(vec![], vec![loop_step(None, None)]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RoutePredicateLanguageRequired,
        );
        let pack = pack_builder(
            vec![],
            vec![loop_step(
                Some(serde_json::json!(3)),
                Some(rhai("scripts/next.rhai")),
            )],
        );
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RoutePredicateAmbiguous,
        );
        let pack = pack_builder(
            vec![],
            vec![loop_step(None, Some(rhai("scripts/next.rhai")))],
        );
        assert_clean(check_routes(&pack, &project_builder(&pack)));
    }

    /// A counted loop whose constant count exceeds its own
    /// `maximumIterations` bound is refused at check; at the bound it
    /// passes, and a `doWhile` predicate form is never a count (staff
    /// review P0-3).
    #[test]
    fn loop_refuses_a_constant_count_above_its_bound() {
        let loop_step = |constant: serde_json::Value, do_while: bool| RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::Loop(LoopStep {
                constant: Some(constant),
                header: None,
                exchange_property: None,
                jsonpath: None,
                rhai: None,
                do_while,
                maximum_iterations: Some(BoundedU64::<1, 100_000>::new(3).expect("bound")),
                copy: false,
                steps: vec![],
            })],
        };
        let pack = pack_builder(vec![], vec![loop_step(serde_json::json!(5), false)]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteLoopCountAboveBound,
        );
        let pack = pack_builder(vec![], vec![loop_step(serde_json::json!(3), false)]);
        assert_clean(check_routes(&pack, &project_builder(&pack)));
        // A `doWhile` constant is a predicate, not a count: no refusal.
        let pack = pack_builder(vec![], vec![loop_step(serde_json::json!(5), true)]);
        assert!(!codes(&check_routes(&pack, &project_builder(&pack)))
            .contains(&CheckCode::RouteLoopCountAboveBound.code()));
    }

    /// A non-safe send inside a split without `stopOnException` is
    /// refused; the same send with it set passes.
    #[test]
    fn routes_refuse_a_non_safe_send_in_a_split_without_stop_on_exception() {
        let split_steps = |stop: bool| -> Vec<Step> {
            vec![Step::Split(SplitStep {
                expression: Expression::JsonPath("$.items".to_string()),
                maximum_items: Some(BoundedU64::<1, 100_000>::new(10).expect("bound")),
                aggregation_strategy: None,
                stop_on_exception: stop,
                error_threshold: None,
                maximum_failed_records: None,
                steps: vec![to_post("case-api", "cases-create")],
            })]
        };
        let without = RouteDefinition {
            id: local("create-case"),
            from: RouteFrom {
                uri: direct("create-case"),
            },
            steps: split_steps(false),
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![without]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteNonSafeSendInSplit,
        );
        let with = RouteDefinition {
            id: local("create-case"),
            from: RouteFrom {
                uri: direct("create-case"),
            },
            steps: split_steps(true),
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![with]);
        assert!(!codes(&check_routes(&pack, &project_builder(&pack)))
            .contains(&CheckCode::RouteNonSafeSendInSplit.code()));
    }

    /// All five uncatchable classes are refused in a clause; a catchable
    /// class passes.
    #[test]
    fn routes_refuse_clauses_naming_any_uncatchable_class() {
        for class in crate::model::ErrorClass::ALL
            .iter()
            .copied()
            .filter(|class| class.is_uncatchable())
        {
            let on_exception = RouteDefinition {
                id: local("fetch-case"),
                from: RouteFrom {
                    uri: direct("fetch-case"),
                },
                steps: vec![Step::OnException(OnExceptionStep {
                    exception: UniqueList::new(vec![class]).expect("unique"),
                    on_when: None,
                    handled: Some(true),
                    continued: None,
                    redelivery_policy: None,
                    steps: vec![],
                })],
            };
            let pack = pack_builder(vec![], vec![on_exception]);
            assert_has(
                &check_routes(&pack, &project_builder(&pack)),
                CheckCode::RouteUncatchableClause,
            );
            let do_try = RouteDefinition {
                id: local("fetch-case"),
                from: RouteFrom {
                    uri: direct("fetch-case"),
                },
                steps: vec![Step::DoTry(DoTryStep {
                    steps: vec![],
                    do_catch: vec![DoCatch {
                        exception: UniqueList::new(vec![class]).expect("unique"),
                        on_when: None,
                        steps: vec![],
                    }],
                    do_finally: Some(DoFinally { steps: vec![] }),
                })],
            };
            let pack = pack_builder(vec![], vec![do_try]);
            assert_has(
                &check_routes(&pack, &project_builder(&pack)),
                CheckCode::RouteUncatchableClause,
            );
        }
        let catchable = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::OnException(OnExceptionStep {
                exception: UniqueList::new(vec![crate::model::ErrorClass::UpstreamHttp])
                    .expect("unique"),
                on_when: None,
                handled: Some(true),
                continued: None,
                redelivery_policy: None,
                steps: vec![],
            })],
        };
        let pack = pack_builder(vec![], vec![catchable]);
        assert!(!codes(&check_routes(&pack, &project_builder(&pack)))
            .contains(&CheckCode::RouteUncatchableClause.code()));
    }

    /// `credential.rejected` joins the other four uncatchable classes in
    /// the clause refusal (coordinator ruling); this pins the kind by
    /// name alongside `budget.exhausted`, `disclosure.violation`,
    /// `egress.refused`, and `script.budget-exceeded` above.
    #[test]
    fn credential_rejected_is_refused_in_a_clause() {
        let route = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::OnException(OnExceptionStep {
                exception: UniqueList::new(vec![crate::model::ErrorClass::CredentialRejected])
                    .expect("unique"),
                on_when: None,
                handled: Some(true),
                continued: None,
                redelivery_policy: None,
                steps: vec![],
            })],
        };
        let pack = pack_builder(vec![], vec![route]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteUncatchableClause,
        );
    }

    /// A predicate carries exactly one language key; zero keys and two
    /// keys are refused under adapter codes naming the clause (the
    /// reader-level unknown-key refusal is `config.unknown-key` per
    /// CFG-SCHEMA-8, so it is pinned in `route.rs` instead).
    #[test]
    fn routes_refuse_predicates_without_exactly_one_language_key() {
        let route = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![
                Step::Choice(ChoiceStep {
                    when: vec![
                        When {
                            constant: None,
                            header: None,
                            exchange_property: None,
                            jsonpath: None,
                            rhai: None,
                            steps: vec![],
                        },
                        When {
                            constant: Some(serde_json::Value::Bool(true)),
                            header: Some("recordId".to_string()),
                            exchange_property: None,
                            jsonpath: None,
                            rhai: None,
                            steps: vec![],
                        },
                    ],
                    otherwise: None,
                }),
                Step::Filter(FilterStep {
                    constant: None,
                    header: None,
                    exchange_property: None,
                    jsonpath: None,
                    rhai: None,
                    steps: vec![],
                }),
            ],
        };
        let pack = pack_builder(vec![], vec![route]);
        let findings = check_routes(&pack, &project_builder(&pack));
        assert_has(&findings, CheckCode::RoutePredicateLanguageRequired);
        assert_has(&findings, CheckCode::RoutePredicateAmbiguous);
    }

    /// A `retryWhile` predicate without redeliveries behind it could
    /// never fire (it only stops redelivery early; `maximumRedeliveries`
    /// stays the hard cap), so it is refused on both the error handler
    /// and an `onException` clause; with redeliveries it passes.
    #[test]
    fn routes_refuse_a_retry_while_without_redeliveries() {
        let clause = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::OnException(OnExceptionStep {
                exception: UniqueList::new(vec![crate::model::ErrorClass::UpstreamTimeout])
                    .expect("unique"),
                on_when: None,
                handled: Some(true),
                continued: None,
                redelivery_policy: Some(RedeliveryOptions {
                    retry_while: Some(rhai("scripts/map.rhai")),
                    ..Default::default()
                }),
                steps: vec![],
            })],
        };
        let pack = pack_builder(vec![], vec![clause]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteRetryWhileWithoutRedeliveries,
        );
        let handler = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::ErrorHandler(ErrorHandlerStep {
                default_error_handler: Some(DefaultErrorHandler {
                    redelivery_policy: Some(RedeliveryOptions {
                        retry_while: Some(rhai("scripts/map.rhai")),
                        ..Default::default()
                    }),
                }),
                no_error_handler: None,
            })],
        };
        let pack = pack_builder(vec![], vec![handler]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteRetryWhileWithoutRedeliveries,
        );
        // With redeliveries behind it and an upstream send to act on, the
        // predicate is admitted.
        let admitted = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![
                Step::OnException(OnExceptionStep {
                    exception: UniqueList::new(vec![crate::model::ErrorClass::UpstreamTimeout])
                        .expect("unique"),
                    on_when: None,
                    handled: Some(true),
                    continued: None,
                    redelivery_policy: Some(RedeliveryOptions {
                        maximum_redeliveries: 2,
                        retry_while: Some(rhai("scripts/map.rhai")),
                        ..Default::default()
                    }),
                    steps: vec![],
                }),
                to_get("case-api"),
            ],
        };
        let pack = pack_builder(vec![basic_endpoint()], vec![admitted]);
        assert_clean(check_routes(&pack, &project_builder(&pack)));
    }

    /// `stopOnException` and Camel's failure accounting are exclusive: a
    /// split that stops on the first failure carries no threshold.
    #[test]
    fn split_refuses_stop_on_exception_with_a_failure_threshold() {
        let split = |stop_on_exception: bool,
                     error_threshold: Option<f64>,
                     maximum_failed_records: Option<u64>| {
            RouteDefinition {
                id: local("fetch-case"),
                from: RouteFrom {
                    uri: direct("fetch-case"),
                },
                steps: vec![Step::Split(SplitStep {
                    expression: rhai("scripts/pieces.rhai"),
                    maximum_items: Some(BoundedU64::<1, 100_000>::new(10).expect("items")),
                    aggregation_strategy: None,
                    stop_on_exception,
                    error_threshold,
                    maximum_failed_records: maximum_failed_records
                        .map(|records| BoundedU64::<1, 100_000>::new(records).expect("records")),
                    steps: vec![],
                })],
            }
        };
        let both = split(true, Some(0.5), None);
        let pack = pack_builder(vec![], vec![both]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteStopOnExceptionExclusive,
        );
        let records = split(true, None, Some(5));
        let pack = pack_builder(vec![], vec![records]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteStopOnExceptionExclusive,
        );
        let accounted = split(false, Some(0.5), None);
        let pack = pack_builder(vec![], vec![accounted]);
        assert_clean(check_routes(&pack, &project_builder(&pack)));
    }

    /// An exception clause naming no class can never match, and `handled`
    /// with `continued` contradicts itself: the clause both consumes the
    /// error and resumes past it.
    #[test]
    fn routes_refuse_an_exception_clause_without_classes_or_with_both_outcomes() {
        let classless = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::OnException(OnExceptionStep {
                exception: UniqueList::new(vec![]).expect("unique"),
                on_when: None,
                handled: Some(true),
                continued: None,
                redelivery_policy: None,
                steps: vec![],
            })],
        };
        let pack = pack_builder(vec![], vec![classless]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteEmptyExceptionList,
        );
        let contradictory = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::OnException(OnExceptionStep {
                exception: UniqueList::new(vec![crate::model::ErrorClass::UpstreamTimeout])
                    .expect("unique"),
                on_when: None,
                handled: Some(true),
                continued: Some(true),
                redelivery_policy: None,
                steps: vec![],
            })],
        };
        let pack = pack_builder(vec![], vec![contradictory]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteHandledAndContinued,
        );
        let unanchored = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::DoTry(crate::route::DoTryStep {
                steps: vec![],
                do_catch: vec![crate::route::DoCatch {
                    exception: UniqueList::new(vec![]).expect("unique"),
                    on_when: None,
                    steps: vec![],
                }],
                do_finally: None,
            })],
        };
        let pack = pack_builder(vec![], vec![unanchored]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteEmptyExceptionList,
        );
        // One class and one outcome stays clean.
        let admitted = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::OnException(OnExceptionStep {
                exception: UniqueList::new(vec![crate::model::ErrorClass::UpstreamTimeout])
                    .expect("unique"),
                on_when: None,
                handled: Some(true),
                continued: None,
                redelivery_policy: None,
                steps: vec![],
            })],
        };
        let pack = pack_builder(vec![], vec![admitted]);
        assert_clean(check_routes(&pack, &project_builder(&pack)));
    }

    #[test]
    fn routes_refuse_redelivery_over_a_non_safe_send_without_the_claim() {
        let route = RouteDefinition {
            id: local("create-case"),
            from: RouteFrom {
                uri: direct("create-case"),
            },
            steps: vec![
                Step::ErrorHandler(ErrorHandlerStep {
                    default_error_handler: Some(DefaultErrorHandler {
                        redelivery_policy: Some(RedeliveryOptions {
                            maximum_redeliveries: 2,
                            ..Default::default()
                        }),
                    }),
                    no_error_handler: None,
                }),
                to_post("case-api", "cases-create"),
            ],
        };
        let mut unclaimed = oauth_endpoint();
        unclaimed.operations = vec![EndpointOperation {
            id: local("cases-create"),
            idempotent_upstream: false,
        }];
        let pack = pack_builder(vec![unclaimed], vec![route.clone()]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteRedeliveryOverNonSafeSend,
        );
        // With the claim on the named operation, redelivery is admitted.
        let claimed_pack = pack_builder(vec![oauth_endpoint()], vec![route]);
        assert!(!codes(&check_routes(
            &claimed_pack,
            &project_builder(&claimed_pack)
        ))
        .contains(&CheckCode::RouteRedeliveryOverNonSafeSend.code()));
    }

    // ----- worst-case walk: one regression per composite step -----

    /// The probes of the Increment 0 staff review, one composite step per
    /// test: every addition and multiplication in the walk must show up
    /// in the binding's budget judgment.
    fn budgeted(steps: Vec<Step>, budget: u64) -> Vec<Diagnostic> {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        let route = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps,
        };
        let pack = pack_builder(vec![basic_endpoint()], vec![route]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("fetch-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(budget).expect("budget"),
        }])
        .expect("unique");
        check_project(&workspace(&profile, &pack, &project))
    }

    fn nested_filters(depth: usize, inner: Vec<Step>) -> Vec<Step> {
        let mut steps = inner;
        for _ in 0..depth {
            steps = vec![Step::Filter(FilterStep {
                constant: None,
                header: None,
                exchange_property: None,
                jsonpath: None,
                rhai: None,
                steps,
            })];
        }
        steps
    }

    fn split_of(maximum: u64, steps: Vec<Step>) -> Step {
        Step::Split(SplitStep {
            expression: rhai("scripts/pieces.rhai"),
            maximum_items: Some(BoundedU64::<1, 100_000>::new(maximum).expect("items")),
            aggregation_strategy: None,
            stop_on_exception: false,
            error_threshold: None,
            maximum_failed_records: None,
            steps,
        })
    }

    fn breaker_of(steps: Vec<Step>, fallback: Option<Vec<Step>>) -> Step {
        Step::CircuitBreaker(CircuitBreakerStep {
            failure_rate_threshold: Percentage::new(50).expect("a percentage"),
            sliding_window_calls: PositiveU32::new(100).expect("a count"),
            minimum_number_of_calls: PositiveU32::new(100).expect("a count"),
            open_state_wait_seconds: PositiveU32::new(60).expect("a count"),
            maximum_half_open_calls: PositiveU32::new(10).expect("a count"),
            automatic_transition_from_open_to_half_open_enabled: false,
            slow_call_rate_threshold: Percentage::new(100).expect("a percentage"),
            slow_call_duration_threshold_seconds: PositiveU32::new(60).expect("a count"),
            steps,
            on_fallback: fallback.map(|steps| OnFallback { steps }),
        })
    }

    /// A breaker adds its body and its fallback to the running total:
    /// `[GET, GET, circuitBreaker{GET} onFallback{GET}]` sends 4, so a
    /// budget of 3 is refused (staff review P0-2a).
    #[test]
    fn breaker_adds_its_fallback_to_the_running_total() {
        let steps = vec![
            to_get("case-api"),
            to_get("case-api"),
            breaker_of(vec![to_get("case-api")], Some(vec![to_get("case-api")])),
        ];
        assert_has(
            &budgeted(steps.clone(), 3),
            CheckCode::ProjectUpstreamBudgetExceeded,
        );
        assert_clean(budgeted(steps, 4));
    }

    /// doTry adds its body, the widest catch, and doFinally: `[GET,
    /// doTry{GET} doCatch{GET, GET}]` sends 4, so a budget of 2 is
    /// refused (staff review P0-2a).
    #[test]
    fn do_try_adds_its_widest_catch_and_finally_to_the_running_total() {
        let steps = vec![
            to_get("case-api"),
            Step::DoTry(DoTryStep {
                steps: vec![to_get("case-api")],
                do_catch: vec![DoCatch {
                    exception: UniqueList::new(vec![crate::model::ErrorClass::UpstreamHttp])
                        .expect("unique"),
                    on_when: None,
                    steps: vec![to_get("case-api"), to_get("case-api")],
                }],
                do_finally: None,
            }),
        ];
        assert_has(
            &budgeted(steps.clone(), 2),
            CheckCode::ProjectUpstreamBudgetExceeded,
        );
        assert_clean(budgeted(steps, 4));
    }

    /// A finally clause adds to the total on top of the widest catch.
    #[test]
    fn do_finally_adds_to_the_running_total() {
        let steps = vec![Step::DoTry(DoTryStep {
            steps: vec![to_get("case-api")],
            do_catch: vec![DoCatch {
                exception: UniqueList::new(vec![crate::model::ErrorClass::UpstreamHttp])
                    .expect("unique"),
                on_when: None,
                steps: vec![to_get("case-api")],
            }],
            do_finally: Some(DoFinally {
                steps: vec![to_get("case-api")],
            }),
        })];
        assert_has(
            &budgeted(steps.clone(), 2),
            CheckCode::ProjectUpstreamBudgetExceeded,
        );
        assert_clean(budgeted(steps, 3));
    }

    /// Choice takes the widest branch, not the sum.
    #[test]
    fn choice_takes_the_widest_branch() {
        let steps = vec![Step::Choice(ChoiceStep {
            when: vec![When {
                rhai: None,
                constant: None,
                header: None,
                exchange_property: None,
                jsonpath: None,
                steps: vec![to_get("case-api"), to_get("case-api")],
            }],
            otherwise: Some(crate::route::Otherwise {
                steps: vec![to_get("case-api")],
            }),
        })];
        assert_has(
            &budgeted(steps.clone(), 1),
            CheckCode::ProjectUpstreamBudgetExceeded,
        );
        assert_clean(budgeted(steps, 2));
    }

    /// Split multiplies by its mandatory bound.
    #[test]
    fn split_multiplies_by_maximum_items() {
        let steps = vec![split_of(1000, vec![to_get("case-api")])];
        assert_has(
            &budgeted(steps.clone(), 999),
            CheckCode::ProjectUpstreamBudgetExceeded,
        );
        assert_clean(budgeted(steps, 1000));
    }

    /// Loop multiplies by its mandatory bound.
    #[test]
    fn loop_multiplies_by_maximum_iterations() {
        let steps = vec![Step::Loop(LoopStep {
            maximum_iterations: Some(BoundedU64::<1, 100_000>::new(50).expect("bound")),
            constant: None,
            header: None,
            exchange_property: None,
            jsonpath: None,
            rhai: None,
            do_while: false,
            copy: false,
            steps: vec![to_get("case-api")],
        })];
        assert_has(
            &budgeted(steps.clone(), 49),
            CheckCode::ProjectUpstreamBudgetExceeded,
        );
        assert_clean(budgeted(steps, 50));
    }

    /// An onException clause inside a split can run once per item, so its
    /// candidate is multiplied by the split's bound (staff review P2-6).
    #[test]
    fn on_exception_inside_split_multiplies_by_maximum_items() {
        let clause = Step::OnException(OnExceptionStep {
            exception: UniqueList::new(vec![crate::model::ErrorClass::UpstreamHttp])
                .expect("unique"),
            on_when: None,
            handled: None,
            continued: Some(true),
            redelivery_policy: None,
            steps: vec![to_get("case-api")],
        });
        let steps = vec![split_of(1000, vec![clause])];
        assert_has(
            &budgeted(steps.clone(), 1),
            CheckCode::ProjectUpstreamBudgetExceeded,
        );
        assert_clean(budgeted(steps, 1000));
    }

    /// A `filter` wrapper is transparent: its inner sends count, at any
    /// depth (staff review P0-2b regression table).
    #[test]
    fn filter_is_transparent_to_the_walk() {
        let steps = nested_filters(3, vec![to_get("case-api"), to_get("case-api")]);
        assert_has(
            &budgeted(steps.clone(), 1),
            CheckCode::ProjectUpstreamBudgetExceeded,
        );
        assert_clean(budgeted(steps, 2));
    }

    /// A `throttle` does not change its body's worst case: the inner
    /// sends count once (staff review P0-2b regression table).
    #[test]
    fn throttle_counts_its_body() {
        let steps = vec![Step::Throttle(ThrottleStep {
            limit: Expression::Constant(serde_json::json!(10)),
            mode: None,
            time_period_milliseconds: PositiveU32::new(1_000).expect("a period"),
            reject_execution: false,
            steps: vec![to_get("case-api"), to_get("case-api")],
        })];
        assert_has(
            &budgeted(steps.clone(), 1),
            CheckCode::ProjectUpstreamBudgetExceeded,
        );
        assert_clean(budgeted(steps, 2));
    }

    /// An `idempotentConsumer` does not change its body's worst case: the
    /// inner sends count once (staff review P0-2b regression table).
    #[test]
    fn idempotent_consumer_counts_its_body() {
        let steps = vec![Step::IdempotentConsumer(IdempotentConsumerStep {
            expression: rhai("scripts/pieces.rhai"),
            eager: true,
            remove_on_failure: true,
            completion_eager: false,
            steps: vec![to_get("case-api"), to_get("case-api")],
        })];
        assert_has(
            &budgeted(steps.clone(), 1),
            CheckCode::ProjectUpstreamBudgetExceeded,
        );
        assert_clean(budgeted(steps, 2));
    }

    /// A walk that runs past the reader's depth bound refuses rather than
    /// silently counting zero: 17 nested filters around a split of 1000
    /// must not pass a budget of 1 (staff review P0-2b), and nesting past
    /// the bound itself carries the depth finding.
    #[test]
    fn walk_beyond_the_reader_depth_refuses_rather_than_passing() {
        let deep = nested_filters(17, vec![split_of(1000, vec![to_get("case-api")])]);
        let findings = budgeted(deep, 1);
        assert_has(&findings, CheckCode::ProjectUpstreamBudgetExceeded);

        let past = nested_filters(
            registry_platform_yaml::MAXIMUM_DEPTH + 1,
            vec![to_get("case-api")],
        );
        let findings = budgeted(past, 100_000);
        assert_has(&findings, CheckCode::RouteNestingDepthExceeded);
        assert_has(&findings, CheckCode::ProjectUpstreamBudgetExceeded);
    }

    // ----- project checks -----

    #[test]
    fn project_accepts_resolved_references_within_budget() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        let route = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![to_get("case-api")],
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![route]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(vec![AccessProfile {
            id: local("registry-clerk"),
            scopes: UniqueList::new(vec![id("cases:read")]).expect("unique"),
            operations: UniqueList::new(vec![id("cases-find")]).expect("unique"),
            record_types: UniqueList::new(vec![local("case")]).expect("unique"),
        }])
        .expect("unique");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("fetch-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(5).expect("budget"),
        }])
        .expect("unique");
        assert_clean(check_project(&workspace(&profile, &pack, &project)));
    }

    #[test]
    fn project_refuses_unknown_operation_record_type_route_and_template() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let mut project = project_builder(&pack);
        project.templated_routes = UniqueIdList::new(vec![TemplatedRoute {
            route_template: id("no-such-template"),
            route_id: id("fresh-route"),
            parameters: BTreeMap::new(),
        }])
        .expect("unique");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("binding"),
            operation: id("cases-missing"),
            record_type: local("ghost"),
            route: id("nowhere"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(1).expect("budget"),
        }])
        .expect("unique");
        let findings = check_project(&workspace(&profile, &pack, &project));
        assert_has(&findings, CheckCode::ProjectUnknownTemplate);
        assert_has(&findings, CheckCode::ProjectUnknownOperation);
        assert_has(&findings, CheckCode::ProjectUnknownRecordType);
        assert_has(&findings, CheckCode::ProjectUnknownRoute);
    }

    /// A valid instantiation resolves into the body map and must be
    /// admitted; its own route id is not a collision. Regression: every
    /// valid instantiation was refused as a duplicate of itself.
    #[test]
    fn project_admits_a_resolved_instantiation_within_budget() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        let template = RouteTemplate {
            id: local("fetch-page"),
            parameters: Vec::new(),
            steps: vec![to_get("case-api")],
        };
        let mut pack = pack_builder(vec![basic_endpoint()], vec![]);
        pack.route_templates = UniqueIdList::new(vec![template]).expect("unique");
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        project.templated_routes = UniqueIdList::new(vec![TemplatedRoute {
            route_template: id("fetch-page"),
            route_id: id("fetch-cases"),
            parameters: BTreeMap::new(),
        }])
        .expect("unique");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("fetch-cases"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(1).expect("budget"),
        }])
        .expect("unique");
        assert_clean(check_project(&workspace(&profile, &pack, &project)));
    }

    /// Two instantiations cannot share one route id at all: the
    /// unique-list reader refuses duplicates by id (CFG-ID-6), so the
    /// check judges a single instantiation against pack ids only.
    #[test]
    fn project_reader_refuses_two_instantiations_with_one_route_id() {
        let a = TemplatedRoute {
            route_template: id("fetch-page"),
            route_id: id("fetch-cases"),
            parameters: BTreeMap::new(),
        };
        let b = TemplatedRoute {
            route_template: id("fetch-page"),
            route_id: id("fetch-cases"),
            parameters: BTreeMap::new(),
        };
        assert!(
            UniqueIdList::new(vec![a, b]).is_err(),
            "two instantiations with one route id are refused at the reader"
        );
    }

    /// A template body placeholder must name a declared parameter: a
    /// body reference with no declaration can never resolve at
    /// instantiation.
    #[test]
    fn pack_refuses_a_template_body_placeholder_without_a_declared_parameter() {
        let body = || {
            Step::SetBody(crate::model::Expression::Constant(serde_json::json!(
                "/v2/cases?region={{region}}"
            )))
        };
        let mut pack = pack_builder(vec![], vec![]);
        pack.route_templates = UniqueIdList::new(vec![RouteTemplate {
            id: local("fetch-page"),
            parameters: Vec::new(),
            steps: vec![body()],
        }])
        .expect("unique");
        assert_has(&check_pack(&pack), CheckCode::PackUnknownTemplateParameter);

        pack.route_templates = UniqueIdList::new(vec![RouteTemplate {
            id: local("fetch-page"),
            parameters: vec![TemplateParameter {
                name: local("region"),
                r#type: TemplateParameterType::String,
                required: true,
                default_value: None,
                description: None,
            }],
            steps: vec![body()],
        }])
        .expect("unique");
        assert_clean(check_pack(&pack));
    }

    /// Typed instantiation checking: an unknown supplied name, a value
    /// whose JSON type does not match the declared parameter type, and a
    /// required parameter left unbound are each refused; a well-typed
    /// instantiation is admitted.
    #[test]
    fn project_checks_templated_parameter_names_types_and_bindings() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        let template = || RouteTemplate {
            id: local("fetch-page"),
            parameters: vec![
                TemplateParameter {
                    name: local("page"),
                    r#type: TemplateParameterType::Integer,
                    required: true,
                    default_value: None,
                    description: None,
                },
                TemplateParameter {
                    name: local("label"),
                    r#type: TemplateParameterType::String,
                    required: false,
                    default_value: None,
                    description: None,
                },
            ],
            steps: vec![to_get("case-api")],
        };
        let instantiate = |parameters: BTreeMap<String, serde_json::Value>| {
            let mut pack = pack_builder(vec![basic_endpoint()], vec![]);
            pack.route_templates = UniqueIdList::new(vec![template()]).expect("unique");
            let mut project = project_builder(&pack);
            project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
            project.templated_routes = UniqueIdList::new(vec![TemplatedRoute {
                route_template: id("fetch-page"),
                route_id: id("fetch-cases"),
                parameters,
            }])
            .expect("unique");
            check_project(&workspace(&profile, &pack, &project))
        };

        let unknown_name = BTreeMap::from([("pag".to_string(), serde_json::json!(3))]);
        assert_has(
            &instantiate(unknown_name),
            CheckCode::ProjectUnknownTemplateParameter,
        );

        let wrong_type = BTreeMap::from([
            ("page".to_string(), serde_json::json!("3")),
            ("label".to_string(), serde_json::json!("weekly")),
        ]);
        assert_has(
            &instantiate(wrong_type),
            CheckCode::ProjectParameterTypeMismatch,
        );

        let unbound_required = BTreeMap::from([("label".to_string(), serde_json::json!("weekly"))]);
        assert_has(
            &instantiate(unbound_required),
            CheckCode::ProjectRequiredParameterUnbound,
        );

        let well_typed = BTreeMap::from([
            ("page".to_string(), serde_json::json!(3)),
            ("label".to_string(), serde_json::json!("weekly")),
        ]);
        assert_clean(instantiate(well_typed));
    }

    /// Pin verification (CFG-ID-4): each declared reference's version and
    /// digest must equal the caller-computed values of the artifact
    /// bytes. Version and digest carry distinct codes; no digest-wins
    /// shortcut. Core stays no-I/O: adapterctl hashes the files and
    /// passes the results in.
    #[test]
    fn project_pins_accept_an_exact_version_and_digest() {
        let pack = pack_builder(vec![], vec![]);
        let project = project_builder(&pack);
        assert_clean(check_project_pins(
            &project,
            "1.0.0",
            &digest(),
            "1.0.0",
            &digest(),
        ));
    }

    /// A version mismatch is refused even when the digest equals the
    /// artifact's real digest; no digest-wins shortcut.
    #[test]
    fn project_pins_refuse_a_version_mismatch_even_when_the_digest_matches() {
        let pack = pack_builder(vec![], vec![]);
        let project = project_builder(&pack);
        let findings = check_project_pins(&project, "2.0.0", &digest(), "1.0.0", &digest());
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].code,
            CheckCode::ProjectPinVersionMismatch.code()
        );
        assert_eq!(findings[0].path, "/profile/version");

        let findings = check_project_pins(&project, "1.0.0", &digest(), "2.0.0", &digest());
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].code,
            CheckCode::ProjectPinVersionMismatch.code()
        );
        assert_eq!(findings[0].path, "/pack/version");
    }

    /// A digest mismatch is refused even when the version matches.
    #[test]
    fn project_pins_refuse_a_digest_mismatch_even_when_the_version_matches() {
        let other_digest =
            Digest::new("sha256:1111111111111111111111111111111111111111111111111111111111111111")
                .expect("digest");
        let pack = pack_builder(vec![], vec![]);
        let project = project_builder(&pack);
        let findings = check_project_pins(&project, "1.0.0", &other_digest, "1.0.0", &digest());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, CheckCode::ProjectPinDigestMismatch.code());
        assert_eq!(findings[0].path, "/profile/digest");

        let findings = check_project_pins(&project, "1.0.0", &digest(), "1.0.0", &other_digest);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, CheckCode::ProjectPinDigestMismatch.code());
        assert_eq!(findings[0].path, "/pack/digest");
    }

    #[test]
    fn project_refuses_an_instantiated_route_id_that_collides() {
        let profile = profile_builder(vec![]);
        let template_route = RouteTemplate {
            id: local("paged-fetch"),
            parameters: Vec::new(),
            steps: vec![],
        };
        let mut pack = pack_builder(vec![], vec![]);
        pack.route_templates = UniqueIdList::new(vec![template_route]).expect("unique");
        let mut project = project_builder(&pack);
        project.templated_routes = UniqueIdList::new(vec![TemplatedRoute {
            route_template: id("paged-fetch"),
            route_id: id("paged-fetch"),
            parameters: BTreeMap::new(),
        }])
        .expect("unique");
        assert_has(
            &check_project(&workspace(&profile, &pack, &project)),
            CheckCode::ProjectDuplicateRouteId,
        );
    }

    #[test]
    fn project_refuses_a_budget_the_route_cannot_meet() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        // A loop of 10 iterations, each fetching one endpoint: worst case 10.
        let route = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::Loop(LoopStep {
                maximum_iterations: Some(BoundedU64::<1, 100_000>::new(10).expect("bound")),
                constant: None,
                header: None,
                exchange_property: None,
                jsonpath: None,
                rhai: None,
                do_while: false,
                copy: false,
                steps: vec![to_get("case-api")],
            })],
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![route]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        // Ten looped sends plus the single resend after a refreshed 401
        // for the one OAuth endpoint (CONCEPT 10.2): eleven; token
        // requests sit outside the budget.
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("fetch-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(3).expect("budget"),
        }])
        .expect("unique");
        let findings = check_project(&workspace(&profile, &pack, &project));
        assert_has(&findings, CheckCode::ProjectUpstreamBudgetExceeded);
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("fetch-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(11).expect("budget"),
        }])
        .expect("unique");
        assert_clean(check_project(&workspace(&profile, &pack, &project)));
    }

    /// Redelivery never applies to a `to: direct:` send, so a
    /// declaration whose reachable sends are all `direct:` is refused;
    /// through direct expansion to an `http:` send it stays valid.
    #[test]
    fn routes_refuse_redelivery_that_reaches_only_direct_sends() {
        let to_direct = |route: &str| {
            Step::To(ToStep {
                uri: direct(route),
                parameters: None,
            })
        };
        let dead = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![
                Step::ErrorHandler(ErrorHandlerStep {
                    default_error_handler: Some(DefaultErrorHandler {
                        redelivery_policy: Some(RedeliveryOptions {
                            maximum_redeliveries: 2,
                            ..Default::default()
                        }),
                    }),
                    no_error_handler: None,
                }),
                to_direct("load-case"),
            ],
        };
        let leaf = RouteDefinition {
            id: local("load-case"),
            from: RouteFrom {
                uri: direct("load-case"),
            },
            steps: vec![Step::SetBody(Expression::Constant(serde_json::Value::Null))],
        };
        let pack = pack_builder(vec![], vec![dead, leaf]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteRedeliveryWithoutUpstreamSend,
        );
        // The same declaration over a body that itself sends upstream is
        // the ordinary shape.
        let ordinary = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![
                Step::ErrorHandler(ErrorHandlerStep {
                    default_error_handler: Some(DefaultErrorHandler {
                        redelivery_policy: Some(RedeliveryOptions {
                            maximum_redeliveries: 2,
                            ..Default::default()
                        }),
                    }),
                    no_error_handler: None,
                }),
                to_get("case-api"),
            ],
        };
        let pack = pack_builder(vec![basic_endpoint()], vec![ordinary]);
        assert_clean(check_routes(&pack, &project_builder(&pack)));
        // Expansion counts: the declaration reaches an http: send through
        // the direct target.
        let expanding = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![
                Step::ErrorHandler(ErrorHandlerStep {
                    default_error_handler: Some(DefaultErrorHandler {
                        redelivery_policy: Some(RedeliveryOptions {
                            maximum_redeliveries: 2,
                            ..Default::default()
                        }),
                    }),
                    no_error_handler: None,
                }),
                to_direct("load-case"),
            ],
        };
        let live_leaf = RouteDefinition {
            id: local("load-case"),
            from: RouteFrom {
                uri: direct("load-case"),
            },
            steps: vec![to_get("case-api")],
        };
        let pack = pack_builder(vec![basic_endpoint()], vec![expanding, live_leaf]);
        assert_clean(check_routes(&pack, &project_builder(&pack)));
    }

    /// A `continued` clause resumes after the failure point and can fire
    /// once per body failure, so over three body sends its one send
    /// counts four times (once standalone, once per body send), pushing
    /// the route past `maximumUpstreamCalls`; the same route passes with
    /// an adequate budget. A clause that does not continue counts once.
    #[test]
    fn project_counts_a_continued_clause_once_per_route_body_send() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        let clause = |continued: bool| {
            Step::OnException(OnExceptionStep {
                exception: UniqueList::new(vec![crate::model::ErrorClass::UpstreamTimeout])
                    .expect("unique"),
                on_when: None,
                handled: Some(true),
                continued: Some(continued),
                redelivery_policy: None,
                steps: vec![to_get("case-api")],
            })
        };
        let route = |continued: bool| RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![
                clause(continued),
                to_get("case-api"),
                to_get("case-api"),
                to_get("case-api"),
            ],
        };
        let pack = pack_builder(vec![basic_endpoint()], vec![route(true)]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        // Three body sends plus the continued-clause send standalone and
        // once per body send: 3 + 1 * (1 + 3) = 7.
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("fetch-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(6).expect("budget"),
        }])
        .expect("unique");
        let findings = check_project(&workspace(&profile, &pack, &project));
        assert_has(&findings, CheckCode::ProjectUpstreamBudgetExceeded);
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("fetch-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(7).expect("budget"),
        }])
        .expect("unique");
        assert_clean(check_project(&workspace(&profile, &pack, &project)));
        // Without `continued`, the clause body counts once: 3 + 1 = 4.
        let pack = pack_builder(vec![basic_endpoint()], vec![route(false)]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("fetch-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(4).expect("budget"),
        }])
        .expect("unique");
        assert_clean(check_project(&workspace(&profile, &pack, &project)));
    }

    /// The budget walk counts exception-clause bodies: a clause body
    /// alone pushes the route past `maximumUpstreamCalls` (Wave 2
    /// ruling). The clause's redeliveries multiply its sends the same
    /// way.
    #[test]
    fn project_refuses_a_budget_exceeded_by_an_exception_clause_body() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        // The route body sends nothing; the clause body sends three times,
        // each with two redeliveries: 3 * (1 + 2) = 9 upstream calls.
        let route = RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps: vec![Step::OnException(OnExceptionStep {
                exception: UniqueList::new(vec![crate::model::ErrorClass::UpstreamTimeout])
                    .expect("unique"),
                on_when: None,
                handled: Some(true),
                continued: None,
                redelivery_policy: Some(RedeliveryOptions {
                    maximum_redeliveries: 2,
                    ..Default::default()
                }),
                steps: vec![to_get("case-api"), to_get("case-api"), to_get("case-api")],
            })],
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![route]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("fetch-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(8).expect("budget"),
        }])
        .expect("unique");
        let findings = check_project(&workspace(&profile, &pack, &project));
        assert_has(&findings, CheckCode::ProjectUpstreamBudgetExceeded);
        // The exact worst case fits: 9 sends + 1 resend.
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("fetch-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(10).expect("budget"),
        }])
        .expect("unique");
        assert_clean(check_project(&workspace(&profile, &pack, &project)));
    }

    /// A write route must wrap its sends in `idempotentConsumer` and carry
    /// at most one non-safe send before Increment 3.
    #[test]
    fn project_refuses_a_write_route_without_idempotency_and_two_non_safe_sends() {
        let profile = profile_builder(vec![ProfileOperation {
            id: local("cases-create"),
            method: HttpMethod::Post,
            path: "/v2/cases/{type}".to_string(),
            request_envelope: Some(EnvelopeTemplate(r#"{"input": {{record}}}"#.to_string())),
            response_envelope: EnvelopeTemplate(r#"{"cases": {{records}}}"#.to_string()),
            pagination: None,
        }]);
        let bare = RouteDefinition {
            id: local("create-case"),
            from: RouteFrom {
                uri: direct("create-case"),
            },
            steps: vec![to_post("case-api", "cases-create")],
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![bare]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("create-cases"),
            operation: id("cases-create"),
            record_type: local("case"),
            route: id("create-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(10).expect("budget"),
        }])
        .expect("unique");
        let findings = check_project(&workspace(&profile, &pack, &project));
        assert_has(&findings, CheckCode::RouteWriteWithoutIdempotency);

        let wrapped = RouteDefinition {
            id: local("create-case"),
            from: RouteFrom {
                uri: direct("create-case"),
            },
            steps: vec![Step::IdempotentConsumer(IdempotentConsumerStep {
                expression: Expression::Header("Idempotency-Key".to_string()),
                eager: true,
                remove_on_failure: true,
                completion_eager: false,
                steps: vec![to_post("case-api", "cases-create")],
            })],
        };
        let wrapped_pack = pack_builder(vec![oauth_endpoint()], vec![wrapped]);
        let mut wrapped_project = project_builder(&wrapped_pack);
        wrapped_project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        wrapped_project.bindings = UniqueIdList::new(vec![Binding {
            id: local("create-cases"),
            operation: id("cases-create"),
            record_type: local("case"),
            route: id("create-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(10).expect("budget"),
        }])
        .expect("unique");
        let findings = check_project(&workspace(&profile, &wrapped_pack, &wrapped_project));
        assert!(
            !codes(&findings).contains(&CheckCode::RouteWriteWithoutIdempotency.code()),
            "a wrapped send passes: {findings:?}"
        );

        let doubled = RouteDefinition {
            id: local("create-case"),
            from: RouteFrom {
                uri: direct("create-case"),
            },
            steps: vec![Step::IdempotentConsumer(IdempotentConsumerStep {
                expression: Expression::Header("Idempotency-Key".to_string()),
                eager: true,
                remove_on_failure: true,
                completion_eager: false,
                steps: vec![
                    to_post("case-api", "cases-create"),
                    to_post("case-api", "cases-create"),
                ],
            })],
        };
        let doubled_pack = pack_builder(vec![oauth_endpoint()], vec![doubled]);
        let mut doubled_project = project_builder(&doubled_pack);
        doubled_project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        doubled_project.bindings = UniqueIdList::new(vec![Binding {
            id: local("create-cases"),
            operation: id("cases-create"),
            record_type: local("case"),
            route: id("create-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(10).expect("budget"),
        }])
        .expect("unique");
        assert_has(
            &check_project(&workspace(&profile, &doubled_pack, &doubled_project)),
            CheckCode::RouteMultipleNonSafeSends,
        );
    }

    #[test]
    fn project_refuses_access_profiles_beyond_the_declared_model() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        let pack = pack_builder(vec![], vec![]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(vec![AccessProfile {
            id: local("registry-clerk"),
            scopes: UniqueList::new(vec![]).expect("unique"),
            operations: UniqueList::new(vec![id("cases-missing")]).expect("unique"),
            record_types: UniqueList::new(vec![local("ghost")]).expect("unique"),
        }])
        .expect("unique");
        let findings = check_project(&workspace(&profile, &pack, &project));
        assert_has(&findings, CheckCode::ProjectUnknownOperation);
        assert_has(&findings, CheckCode::ProjectUnknownRecordType);
    }

    // ----- runtime checks -----

    fn runtime_builder(endpoints: Vec<EndpointBinding>) -> AdapterRuntimeConfig {
        AdapterRuntimeConfig {
            id: local("case-deployment"),
            endpoints: UniqueIdList::new(endpoints).expect("unique"),
            allowed_private_cidrs: UniqueList::new(Vec::new()).expect("empty"),
            listener: serde_json::from_str(r#"{ "bind": "127.0.0.1:8080" }"#).expect("listener"),
            database: serde_json::from_str(
                r#"{
                    "runtimeUrlRef": "secret:env/DB_RUNTIME",
                    "migrationUrlRef": "secret:env/DB_MIGRATION"
                }"#,
            )
            .expect("database"),
            oidc: serde_json::from_str(
                r#"{ "issuer": "https://issuer.example.invalid", "audience": "case-api" }"#,
            )
            .expect("oidc"),
            audit: AuditRetention {
                retention_days: BoundedU32::<1, 3_650>::new(90).expect("retention"),
            },
        }
    }

    fn oauth_binding(base: &str) -> EndpointBinding {
        EndpointBinding {
            endpoint: id("case-api"),
            base_url: Url::new(base).expect("url"),
            credential: Some(RuntimeCredential::Oauth2ClientCredentials {
                token_endpoint: Url::new("https://token.example.invalid/token").expect("url"),
                client_id_ref: SecretReference::new("secret:env/CLIENT_ID").expect("secret"),
                client_secret_ref: SecretReference::new("secret:env/CLIENT_SECRET")
                    .expect("secret"),
                scope: None,
                audience: None,
                resource: None,
                credential_placement: CredentialPlacement::BasicHeader,
                maximum_cache_seconds: BoundedU64::<0, 86_400>::new(3600).expect("cache"),
                assumed_lifetime_seconds: None,
            }),
            ca_bundle_ref: None,
            mtls_identity: None,
        }
    }

    #[test]
    fn runtime_accepts_a_matching_oauth_binding() {
        let profile = profile_builder(vec![]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let project = project_builder(&pack);
        let runtime = runtime_builder(vec![oauth_binding("https://cases.example.invalid")]);
        let mut ws = workspace(&profile, &pack, &project);
        ws.runtime = Some(&runtime);
        assert_clean(check_runtime(&ws, &runtime));
    }

    #[test]
    fn runtime_refuses_a_mismatched_credential_kind_and_a_missing_credential() {
        let profile = profile_builder(vec![]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let project = project_builder(&pack);
        let mut binding = oauth_binding("https://cases.example.invalid");
        binding.credential = Some(RuntimeCredential::None {});
        let runtime = runtime_builder(vec![binding]);
        let mut ws = workspace(&profile, &pack, &project);
        ws.runtime = Some(&runtime);
        assert_has(&check_runtime(&ws, &runtime), CheckCode::AuthKindMismatch);
        let mut unbound = oauth_binding("https://cases.example.invalid");
        unbound.credential = None;
        let runtime = runtime_builder(vec![unbound]);
        let mut ws = workspace(&profile, &pack, &project);
        ws.runtime = Some(&runtime);
        let findings = check_runtime(&ws, &runtime);
        assert_has(&findings, CheckCode::AuthKindMismatch);
    }

    /// A `none` credential is refused on a non-loopback origin without an
    /// mTLS identity, and admitted with one.
    #[test]
    fn runtime_refuses_none_outside_loopback_without_mtls() {
        let profile = profile_builder(vec![]);
        let mut endpoint = oauth_endpoint();
        endpoint.authentication = EndpointAuthentication::None {};
        let pack = pack_builder(vec![endpoint], vec![]);
        let project = project_builder(&pack);
        let public = EndpointBinding {
            endpoint: id("case-api"),
            base_url: Url::new("https://cases.example.invalid").expect("url"),
            credential: Some(RuntimeCredential::None {}),
            ca_bundle_ref: None,
            mtls_identity: None,
        };
        let runtime = runtime_builder(vec![public]);
        let mut ws = workspace(&profile, &pack, &project);
        ws.runtime = Some(&runtime);
        assert_has(
            &check_runtime(&ws, &runtime),
            CheckCode::AuthNoneNotLoopback,
        );
        let with_mtls = EndpointBinding {
            endpoint: id("case-api"),
            base_url: Url::new("https://cases.example.invalid").expect("url"),
            credential: Some(RuntimeCredential::None {}),
            ca_bundle_ref: None,
            mtls_identity: Some(MtlsIdentity {
                certificate_ref: SecretReference::new("secret:env/CERT").expect("secret"),
                key_ref: SecretReference::new("secret:env/KEY").expect("secret"),
            }),
        };
        let runtime = runtime_builder(vec![with_mtls]);
        let mut ws = workspace(&profile, &pack, &project);
        ws.runtime = Some(&runtime);
        assert!(
            !codes(&check_runtime(&ws, &runtime)).contains(&CheckCode::AuthNoneNotLoopback.code())
        );
    }

    #[test]
    fn runtime_refuses_plain_http_outside_loopback() {
        let profile = profile_builder(vec![]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let project = project_builder(&pack);
        let runtime = runtime_builder(vec![oauth_binding("http://cases.example.invalid")]);
        let mut ws = workspace(&profile, &pack, &project);
        ws.runtime = Some(&runtime);
        assert_has(
            &check_runtime(&ws, &runtime),
            CheckCode::RuntimeInsecureOrigin,
        );
        let loopback = runtime_builder(vec![oauth_binding("http://127.0.0.1:8081")]);
        let mut ws = workspace(&profile, &pack, &project);
        ws.runtime = Some(&loopback);
        assert!(!codes(&check_runtime(&ws, &loopback))
            .contains(&CheckCode::RuntimeInsecureOrigin.code()));
    }

    /// A token endpoint answers to the same origin rule as a binding's
    /// base URL: `https` anywhere, plain HTTP on a numeric loopback only.
    #[test]
    fn runtime_refuses_a_plain_http_token_endpoint() {
        let profile = profile_builder(vec![]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let project = project_builder(&pack);
        let with_token = |base: &str, token: &str| {
            let mut binding = oauth_binding(base);
            if let Some(RuntimeCredential::Oauth2ClientCredentials { token_endpoint, .. }) =
                &mut binding.credential
            {
                *token_endpoint = Url::new(token).expect("url");
            }
            let runtime = runtime_builder(vec![binding]);
            let mut ws = workspace(&profile, &pack, &project);
            ws.runtime = Some(&runtime);
            check_runtime(&ws, &runtime)
        };
        let findings = with_token(
            "https://cases.example.invalid",
            "http://token.example.invalid/token",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, CheckCode::RuntimeInsecureOrigin.code());
        assert_eq!(findings[0].path, "/endpoints/0/credential/tokenEndpoint");
        assert_clean(with_token(
            "https://cases.example.invalid",
            "http://127.0.0.1:8081/token",
        ));
    }

    #[test]
    fn runtime_refuses_unknown_and_missing_endpoint_bindings() {
        let profile = profile_builder(vec![]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let project = project_builder(&pack);
        let mut stray = oauth_binding("https://cases.example.invalid");
        stray.endpoint = id("not-in-pack");
        let runtime = runtime_builder(vec![stray]);
        let mut ws = workspace(&profile, &pack, &project);
        ws.runtime = Some(&runtime);
        let findings = check_runtime(&ws, &runtime);
        assert_has(&findings, CheckCode::RuntimeUnknownEndpoint);
        assert_has(&findings, CheckCode::RuntimeMissingEndpoint);
    }

    // ----- origin-relative paths (round 6 C1) -----

    /// An authored operation path is origin-relative: no scheme or
    /// authority, no `..` segment, and a leading slash.
    #[test]
    fn profile_refuses_paths_that_leave_the_origin() {
        for path in [
            "https://cases.example.invalid/v2",
            "//cases.example.invalid/v2",
            "v2/cases",
            "/v2/../admin",
        ] {
            let mut bad = operation("cases-find", HttpMethod::Get);
            bad.path = path.to_string();
            let profile = profile_builder(vec![bad]);
            let findings = check_profile(&profile);
            assert_eq!(findings.len(), 1, "at {path}");
            assert_eq!(findings[0].code, CheckCode::ProfileInvalidPath.code());
            assert_eq!(findings[0].path, "/operations/0/path");
        }
        assert_clean(check_profile(&profile_builder(vec![operation(
            "cases-find",
            HttpMethod::Get,
        )])));
    }

    /// A send's static path answers to the same origin-relative rule,
    /// refused at the step's parameters.
    #[test]
    fn routes_refuse_send_paths_that_leave_the_origin() {
        let to_with_path = |path: &str| {
            let mut step = to_get("case-api");
            if let Step::To(to) = &mut step {
                if let Some(parameters) = &mut to.parameters {
                    parameters.path = Some(path.to_string());
                }
            }
            step
        };
        for path in [
            "https://cases.example.invalid/v2",
            "//cases.example.invalid/v2",
            "v2/cases",
            "/v2/../admin",
        ] {
            let route = RouteDefinition {
                id: local("fetch-case"),
                from: RouteFrom {
                    uri: direct("fetch-case"),
                },
                steps: vec![to_with_path(path)],
            };
            let pack = pack_builder(vec![oauth_endpoint()], vec![route]);
            let findings = check_routes(&pack, &project_builder(&pack));
            assert_eq!(findings.len(), 1, "at {path}: {:?}", codes(&findings));
            assert_eq!(findings[0].code, CheckCode::RouteInvalidPath.code());
            assert_eq!(
                findings[0].path,
                "/routes/fetch-case/steps/0/parameters/path"
            );
        }
    }

    // ----- header hygiene (round 6 C3) -----

    /// A `setHeader` names no credential, cookie, host, hop-by-hop,
    /// engine, or facade-input header, and a `header` expression reads
    /// only a facade input, an engine-placed header, a response header an
    /// endpoint allowlist declares, or a header an earlier step of the
    /// same body set (`products/adapter/CONCEPT.md` section 8.11.4).
    #[test]
    fn header_writes_and_reads_stay_bounded() {
        let route = |steps: Vec<Step>| RouteDefinition {
            id: local("fetch-case"),
            from: RouteFrom {
                uri: direct("fetch-case"),
            },
            steps,
        };
        let set = |name: &str, value: Expression| {
            Step::SetHeader(SetHeaderStep {
                name: name.to_string(),
                value,
            })
        };
        let read = |name: &str| Expression::Header(name.to_string());
        let check = |steps: Vec<Step>, endpoint_headers: &[&str]| {
            let mut endpoint = oauth_endpoint();
            endpoint.response_headers = UniqueList::new(
                endpoint_headers
                    .iter()
                    .map(|header| id(header))
                    .collect::<Vec<_>>(),
            )
            .expect("unique");
            let pack = pack_builder(vec![endpoint], vec![route(steps)]);
            check_routes(&pack, &project_builder(&pack))
        };

        // Credential, cookie, host, hop-by-hop, engine, and facade
        // headers refuse as writes, under one code.
        for name in [
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
            "Host",
            "Transfer-Encoding",
            "Connection",
            "CamelHttpResponseCode",
            "recordId",
        ] {
            let findings = check(vec![set(name, read("recordType"))], &[]);
            assert_has(&findings, CheckCode::RouteReservedHeaderName);
        }
        // A step may set a header the pack defines.
        let findings = check(
            vec![
                set("scratch", read("recordType")),
                Step::SetBody(read("scratch")),
            ],
            &[],
        );
        assert!(
            !codes(&findings).contains(&CheckCode::RouteReservedHeaderName.code()),
            "a pack-defined header sets cleanly: {:?}",
            codes(&findings)
        );

        // A read answers to the facade inputs and the engine headers.
        let findings = check(vec![set("scratch", read("recordId"))], &[]);
        assert_clean(findings);
        let findings = check(vec![set("scratch", read("CamelSplitIndex"))], &[]);
        assert_clean(findings);

        // A read answers to a response allowlist any endpoint declares.
        let findings = check(vec![set("scratch", read("etag"))], &["ETag"]);
        assert_clean(findings);

        // A read of a header nothing places refuses, at the step, and a
        // read before the step that sets it refuses too.
        let findings = check(vec![set("scratch", read("ghost"))], &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, CheckCode::RouteUnknownHeader.code());
        assert_eq!(findings[0].path, "/routes/fetch-case/steps/0");

        let findings = check(
            vec![
                Step::SetBody(read("scratch")),
                set("scratch", read("recordType")),
            ],
            &[],
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, CheckCode::RouteUnknownHeader.code());
    }

    // ----- fixture checks -----

    #[test]
    fn fixtures_accept_declared_intercepts_and_entries() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let mut project = project_builder(&pack);
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("fetch-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(1).expect("budget"),
        }])
        .expect("unique");
        let fixture = AdapterFixture {
            id: local("case-api-fixtures"),
            pack: id("case-api-pack"),
            upstream_version: "2.7".to_string(),
            provenance: FixtureProvenance::Captured {
                reference: "staging".to_string(),
            },
            intercepts: vec![Intercept::Endpoint {
                endpoint: id("case-api"),
            }],
            entries: vec![FixtureEntry {
                operation: id("cases-find"),
                given: RecordedRequest {
                    endpoint: id("case-api"),
                    method: HttpMethod::Get,
                    path: "/v2/cases/person/123".to_string(),
                    query: None,
                    body: None,
                },
                upstream_response: RecordedResponse {
                    status: BoundedU32::new(200).expect("a status"),
                    body: None,
                },
                expected_facade_response: RecordedResponse {
                    status: BoundedU32::new(200).expect("a status"),
                    body: None,
                },
            }],
        };
        let mut ws = workspace(&profile, &pack, &project);
        ws.fixtures = std::slice::from_ref(&fixture);
        assert_clean(check_fixtures(&ws));
    }

    /// An entry's operation is the facade-side primary key (D17): it
    /// must be a profile operation the project binds to a route. Unknown
    /// and known-but-unbound operations are each refused, with distinct
    /// value-free messages under one code.
    #[test]
    fn fixtures_refuse_entries_whose_operation_the_deployment_cannot_exercise() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let mut project = project_builder(&pack);
        let entry = |op: &str| FixtureEntry {
            operation: id(op),
            given: RecordedRequest {
                endpoint: id("case-api"),
                method: HttpMethod::Get,
                path: "/v2/cases/person/123".to_string(),
                query: None,
                body: None,
            },
            upstream_response: RecordedResponse {
                status: BoundedU32::new(200).expect("a status"),
                body: None,
            },
            expected_facade_response: RecordedResponse {
                status: BoundedU32::new(200).expect("a status"),
                body: None,
            },
        };
        let fixture = |op: &str| AdapterFixture {
            id: local("case-api-fixtures"),
            pack: id("case-api-pack"),
            upstream_version: "2.7".to_string(),
            provenance: FixtureProvenance::Captured {
                reference: "staging".to_string(),
            },
            intercepts: vec![],
            entries: vec![entry(op)],
        };

        // Known to the profile but bound by no route: refused.
        let unbound = fixture("cases-find");
        let mut ws = workspace(&profile, &pack, &project);
        ws.fixtures = std::slice::from_ref(&unbound);
        let findings = check_fixtures(&ws);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, CheckCode::FixtureUnknownOperation.code());
        assert_eq!(findings[0].path, "/fixtures/0/entries/0/operation");

        // Unknown to the profile: refused with the same code.
        let unknown = fixture("cases-missing");
        let mut ws = workspace(&profile, &pack, &project);
        ws.fixtures = std::slice::from_ref(&unknown);
        let findings = check_fixtures(&ws);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, CheckCode::FixtureUnknownOperation.code());

        // A binding to a route makes the operation exercisable: passes.
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("fetch-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(1).expect("budget"),
        }])
        .expect("unique");
        let bound = fixture("cases-find");
        let mut ws = workspace(&profile, &pack, &project);
        ws.fixtures = std::slice::from_ref(&bound);
        assert_clean(check_fixtures(&ws));
    }

    /// A non-2xx entry expects a problem code the profile declares: an
    /// undeclared code refuses at the entry, the declared code passes, and
    /// the check stays out of 2xx entries (addendum C).
    #[test]
    fn fixtures_resolve_the_expected_problem_code_against_the_profile() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let mut project = project_builder(&pack);
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("fetch-case"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(1).expect("budget"),
        }])
        .expect("unique");
        let entry = |status: u32, code: Option<&str>| FixtureEntry {
            operation: id("cases-find"),
            given: RecordedRequest {
                endpoint: id("case-api"),
                method: HttpMethod::Get,
                path: "/v2/cases/person/123".to_string(),
                query: None,
                body: None,
            },
            upstream_response: RecordedResponse {
                status: BoundedU32::new(200).expect("a status"),
                body: None,
            },
            expected_facade_response: RecordedResponse {
                status: BoundedU32::new(status).expect("a status"),
                body: code.map(|code| serde_json::json!({ "code": code })),
            },
        };
        let fixture = |status: u32, code: Option<&str>| AdapterFixture {
            id: local("case-api-fixtures"),
            pack: id("case-api-pack"),
            upstream_version: "2.7".to_string(),
            provenance: FixtureProvenance::Captured {
                reference: "staging".to_string(),
            },
            intercepts: vec![],
            entries: vec![entry(status, code)],
        };

        // An undeclared problem code refuses, at the entry.
        let undeclared = fixture(404, Some("cases.smashed"));
        let mut ws = workspace(&profile, &pack, &project);
        ws.fixtures = std::slice::from_ref(&undeclared);
        let findings = check_fixtures(&ws);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].code,
            CheckCode::FixtureUnknownProblemCode.code()
        );
        assert_eq!(findings[0].path, "/fixtures/0/entries/0");

        // The declared code passes; a 2xx entry is not a problem body.
        let declared = fixture(404, Some("cases.conflict"));
        let mut ws = workspace(&profile, &pack, &project);
        ws.fixtures = std::slice::from_ref(&declared);
        assert_clean(check_fixtures(&ws));
        let success = fixture(200, Some("cases.smashed"));
        let mut ws = workspace(&profile, &pack, &project);
        ws.fixtures = std::slice::from_ref(&success);
        assert_clean(check_fixtures(&ws));
    }

    /// The workspace check derives every envelope once, independent of
    /// fixtures: a zero-fixture workspace with a malformed problem
    /// envelope refuses under the profile-level code (addendum D), and a
    /// well-formed one adds no derivation finding.
    #[test]
    fn the_workspace_check_derives_envelopes_without_fixtures() {
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let project = project_builder(&pack);

        let mut broken = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        broken.problem_envelope = EnvelopeTemplate(r#"{"code": "{{problemCode}}""#.to_string());
        let ws = workspace(&broken, &pack, &project);
        let findings = check_workspace(&ws);
        assert_has(&findings, CheckCode::ProfileProblemEnvelopeUncompilable);
        assert_eq!(
            codes(&findings)
                .iter()
                .filter(|code| **code == CheckCode::ProfileProblemEnvelopeUncompilable.code())
                .count(),
            1
        );

        let ws = workspace(&profile, &pack, &project);
        let findings = check_workspace(&ws);
        assert!(!codes(&findings).contains(&CheckCode::ProfileProblemEnvelopeUncompilable.code()));
        assert!(!codes(&findings).contains(&CheckCode::ProfileResponseEnvelopeUncompilable.code()));
    }

    #[test]
    fn fixtures_refuse_unknown_intercepts_and_entries() {
        let profile = profile_builder(vec![]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let project = project_builder(&pack);
        let fixture = AdapterFixture {
            id: local("case-api-fixtures"),
            pack: id("case-api-pack"),
            upstream_version: "2.7".to_string(),
            provenance: FixtureProvenance::Documented {
                reference: "handbook".to_string(),
            },
            intercepts: vec![
                Intercept::Endpoint {
                    endpoint: id("not-in-pack"),
                },
                Intercept::TokenEndpoint {
                    endpoint: id("case-api"),
                },
            ],
            entries: vec![FixtureEntry {
                operation: id("cases-find"),
                given: RecordedRequest {
                    endpoint: id("also-missing"),
                    method: HttpMethod::Get,
                    path: "/".to_string(),
                    query: None,
                    body: None,
                },
                upstream_response: RecordedResponse {
                    status: BoundedU32::new(200).expect("a status"),
                    body: None,
                },
                expected_facade_response: RecordedResponse {
                    status: BoundedU32::new(200).expect("a status"),
                    body: None,
                },
            }],
        };
        let mut ws = workspace(&profile, &pack, &project);
        ws.fixtures = std::slice::from_ref(&fixture);
        let findings = check_fixtures(&ws);
        assert_has(&findings, CheckCode::FixtureUnknownIntercept);
        assert_has(&findings, CheckCode::FixtureUnknownEndpoint);
        // The token-endpoint intercept of a declared endpoint passes.
        assert_eq!(
            codes(&findings)
                .iter()
                .filter(|code| **code == CheckCode::FixtureUnknownIntercept.code())
                .count(),
            1
        );
    }

    // ----- direct graph depth -----

    #[test]
    fn routes_refuse_a_direct_chain_past_the_bounded_depth() {
        let hops = MAX_DIRECT_DEPTH + 2;
        let mut routes = Vec::new();
        for index in 0..hops {
            let id_text = format!("hop{index}");
            let steps = if index + 1 < hops {
                vec![Step::Enrich(EnrichStep {
                    uri: direct(&format!("hop{}", index + 1)),
                    aggregation_strategy: None,
                    aggregate_on_exception: false,
                    parameters: None,
                })]
            } else {
                vec![]
            };
            routes.push(RouteDefinition {
                id: local(&id_text),
                from: RouteFrom {
                    uri: direct(&id_text),
                },
                steps,
            });
        }
        let pack = pack_builder(vec![], routes);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteDirectDepthExceeded,
        );
    }

    /// A chain within the bounded depth passes; the composed workspace
    /// check runs every check at once.
    #[test]
    fn a_chain_within_depth_passes_the_whole_workspace() {
        let hops = 3;
        let mut routes = Vec::new();
        for index in 0..hops {
            let id_text = format!("hop{index}");
            let steps = if index + 1 < hops {
                vec![Step::Enrich(EnrichStep {
                    uri: direct(&format!("hop{}", index + 1)),
                    aggregation_strategy: None,
                    aggregate_on_exception: false,
                    parameters: None,
                })]
            } else {
                vec![to_get("case-api")]
            };
            routes.push(RouteDefinition {
                id: local(&id_text),
                from: RouteFrom {
                    uri: direct(&id_text),
                },
                steps,
            });
        }
        let profile = profile_builder(vec![operation("cases-find", HttpMethod::Get)]);
        let pack = pack_builder(vec![oauth_endpoint()], routes);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: id("cases-find"),
            record_type: local("case"),
            route: id("hop2"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(5).expect("budget"),
        }])
        .expect("unique");
        let ws = workspace(&profile, &pack, &project);
        assert_clean(check_workspace(&ws));
    }
}

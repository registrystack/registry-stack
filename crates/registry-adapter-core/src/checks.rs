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
use crate::route::Step;
use crate::runtime::AdapterRuntimeConfig;
use registry_platform_yaml::{Diagnostic, ExternalId};
use std::collections::{HashMap, HashSet};

/// The deepest `direct:` call chain the graph may form
/// (`products/adapter/CONCEPT.md` section 8.3).
pub const MAX_DIRECT_DEPTH: usize = 16;

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
fn is_placeholder_name(name: &str) -> bool {
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

/// The route bodies an internal id may resolve to: pack routes, pack
/// templates, and instantiated route ids mapped to their template bodies.
fn route_bodies<'a>(
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
            .get(instantiated.route_template_ref.as_str())
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
    findings
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
        walk_steps(steps, &mut |step, path| {
            for expression in step_expressions(step) {
                if let Expression::Rhai(rhai) = expression {
                    if pack.pinned_file(&rhai.file).is_none() {
                        findings.push(finding(
                            CheckCode::PackUnknownScript,
                            &format!("/steps{path}/expression/rhai"),
                            "the script file is not in the pack's digest-pinned inventory",
                            "List the script in scripts with its sha256 digest.",
                        ));
                    }
                }
            }
        });
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

    // Graph shape over direct: edges.
    let mut edges: HashMap<&str, Vec<&str>> = HashMap::new();
    for (id, steps) in &bodies {
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

    for (id, steps) in &bodies {
        let steps: &[Step] = steps;
        let mut route_findings = Vec::new();
        let sends = collect_non_safe_sends(steps);
        walk_steps(steps, &mut |step, path| match step {
            Step::To(to) => {
                let target = &to.uri;
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
            Step::Enrich(enrich) => match enrich.uri.component {
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
            },
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
            Step::Loop(loop_step) if loop_step.maximum_iterations.is_none() => {
                route_findings.push(finding(
                    CheckCode::RouteMaximumIterationsRequired,
                    &format!("/routes/{id}/steps{path}"),
                    "the loop declares no maximumIterations bound",
                    "Declare maximumIterations on every loop.",
                ));
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
            Step::ErrorHandler(handler)
                if handler
                    .default_error_handler
                    .as_ref()
                    .and_then(|handler| handler.redelivery_policy.as_ref())
                    .is_some_and(|policy| {
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
            _ => {}
        });

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

/// Whether a `to` send is a non-safe upstream send.
fn is_non_safe_to(to: &crate::route::ToStep) -> bool {
    to.parameters
        .as_ref()
        .is_some_and(|parameters| !parameters.http_method.is_safe())
        && matches!(
            to.uri.component,
            SendComponent::Http | SendComponent::GraphQl
        )
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

/// Whether the send's endpoint operation declares `idempotentUpstream`; a
/// send that names no operation uses the endpoint-wide verdict.
fn send_claims_idempotent(
    pack: &AdapterPack,
    endpoint_id: &str,
    operation: Option<&ExternalId>,
) -> bool {
    let Some(endpoint) = pack.endpoints.get(endpoint_id) else {
        return false;
    };
    match operation {
        Some(operation_id) => endpoint
            .operations
            .iter()
            .any(|op| op.id.as_str() == operation_id.as_str() && op.idempotent_upstream),
        None => endpoint.operations.iter().any(|op| op.idempotent_upstream),
    }
}

/// Whether any upstream component send (`http:` or `graphql:`) is
/// reachable from the body, through composite steps and `direct:`
/// expansion. Redelivery applies only to component sends, so a
/// declaration whose reachable sends are all `direct:` has no effect.
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
        Step::Split(split) => reaches_component_send(&split.steps, bodies, depth + 1),
        Step::Loop(loop_step) => reaches_component_send(&loop_step.steps, bodies, depth + 1),
        Step::Choice(choice) => {
            choice
                .when
                .iter()
                .any(|when| reaches_component_send(&when.steps, bodies, depth + 1))
                || choice.otherwise.as_ref().is_some_and(|otherwise| {
                    reaches_component_send(&otherwise.steps, bodies, depth + 1)
                })
        }
        Step::CircuitBreaker(breaker) => {
            reaches_component_send(&breaker.steps, bodies, depth + 1)
                || breaker.on_fallback.as_ref().is_some_and(|fallback| {
                    reaches_component_send(&fallback.steps, bodies, depth + 1)
                })
        }
        Step::Throttle(throttle) => reaches_component_send(&throttle.steps, bodies, depth + 1),
        Step::IdempotentConsumer(idempotent) => {
            reaches_component_send(&idempotent.steps, bodies, depth + 1)
        }
        Step::OnException(clause) => reaches_component_send(&clause.steps, bodies, depth + 1),
        Step::DoTry(do_try) => {
            reaches_component_send(&do_try.steps, bodies, depth + 1)
                || do_try
                    .do_catch
                    .iter()
                    .any(|catch| reaches_component_send(&catch.steps, bodies, depth + 1))
                || do_try.do_finally.as_ref().is_some_and(|do_finally| {
                    reaches_component_send(&do_finally.steps, bodies, depth + 1)
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
}

/// Every non-safe upstream send a body can reach, with its enclosing
/// `idempotentConsumer` context.
fn collect_non_safe_sends(steps: &[Step]) -> Vec<NonSafeSend> {
    fn walk(steps: &[Step], inside_idempotency: bool, sends: &mut Vec<NonSafeSend>) {
        for step in steps {
            match step {
                Step::To(to) if is_non_safe_to(to) => sends.push(NonSafeSend {
                    endpoint: to.uri.id.clone(),
                    operation: to.parameters.as_ref().and_then(|p| p.operation.clone()),
                    inside_idempotency,
                }),
                Step::Enrich(enrich)
                    if matches!(
                        enrich.uri.component,
                        SendComponent::Http | SendComponent::GraphQl
                    ) =>
                {
                    sends.push(NonSafeSend {
                        endpoint: enrich.uri.id.clone(),
                        operation: None,
                        inside_idempotency,
                    });
                }
                Step::IdempotentConsumer(idempotent) => {
                    walk(&idempotent.steps, true, sends);
                }
                Step::Choice(choice) => {
                    for when in &choice.when {
                        walk(&when.steps, inside_idempotency, sends);
                    }
                    if let Some(otherwise) = &choice.otherwise {
                        walk(&otherwise.steps, inside_idempotency, sends);
                    }
                }
                Step::Filter(filter) => walk(&filter.steps, inside_idempotency, sends),
                Step::Split(split) => walk(&split.steps, inside_idempotency, sends),
                Step::Loop(loop_step) => walk(&loop_step.steps, inside_idempotency, sends),
                Step::CircuitBreaker(breaker) => {
                    walk(&breaker.steps, inside_idempotency, sends);
                    if let Some(fallback) = &breaker.on_fallback {
                        walk(&fallback.steps, inside_idempotency, sends);
                    }
                }
                Step::Throttle(throttle) => walk(&throttle.steps, inside_idempotency, sends),
                Step::DoTry(do_try) => {
                    walk(&do_try.steps, inside_idempotency, sends);
                    for catch in &do_try.do_catch {
                        walk(&catch.steps, inside_idempotency, sends);
                    }
                    if let Some(do_finally) = &do_try.do_finally {
                        walk(&do_finally.steps, inside_idempotency, sends);
                    }
                }
                Step::OnException(clause) => walk(&clause.steps, inside_idempotency, sends),
                _ => {}
            }
        }
    }
    let mut sends = Vec::new();
    walk(steps, false, &mut sends);
    sends
}

/// Depth-first visit of every step, with the relative step path inside the
/// visited body.
fn walk_steps<'a>(steps: &'a [Step], visit: &mut dyn FnMut(&'a Step, &str)) {
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

/// The expressions a step carries directly.
fn step_expressions(step: &Step) -> Vec<&Expression> {
    match step {
        Step::SetBody(expression) | Step::Transform(expression) | Step::Script(expression) => {
            vec![expression]
        }
        Step::SetHeader(header) => vec![&header.value],
        Step::SetProperty(property) => vec![&property.value],
        Step::Validate(validate) => vec![&validate.expression],
        _ => Vec::new(),
    }
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
    for &node in edges.keys() {
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

    for (index, instantiated) in project.templated_routes.iter().enumerate() {
        let prefix = format!("/templatedRoutes/{index}");
        if pack
            .route_templates
            .get(instantiated.route_template_ref.as_str())
            .is_none()
        {
            findings.push(finding(
                CheckCode::ProjectUnknownTemplate,
                &format!("{prefix}/routeTemplateRef"),
                "the instantiation references no declared template",
                "Name a template the pinned pack declares.",
            ));
        }
        if bodies.contains_key(instantiated.route_id.as_str()) {
            findings.push(finding(
                CheckCode::ProjectDuplicateRouteId,
                &format!("{prefix}/routeId"),
                "the instantiated route id collides with a pack route or template",
                "Choose a route id no pack route, template, or other instantiation uses.",
            ));
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
        let route_steps = bodies.get(binding.route.as_str()).copied();
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
            let worst = route_worst_case(route_steps, &bodies, &oauth_endpoints);
            if worst > binding.maximum_upstream_calls.get() {
                findings.push(finding(
                    CheckCode::ProjectUpstreamBudgetExceeded,
                    &format!("{prefix}/maximumUpstreamCalls"),
                    "the route's static worst-case upstream call count exceeds the binding's budget",
                    "Raise maximumUpstreamCalls, or bound the sends the route can make.",
                ));
            }
            if !operation.method.is_safe() {
                findings.extend(write_route_checks(&prefix, route_steps));
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
fn write_route_checks(prefix: &str, steps: &[Step]) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    let sends = collect_non_safe_sends(steps);
    if sends.iter().any(|send| !send.inside_idempotency) {
        findings.push(finding(
            CheckCode::RouteWriteWithoutIdempotency,
            &format!("{prefix}/route"),
            "a write route sends outside an idempotentConsumer wrapper",
            "Wrap the write route's sends in idempotentConsumer.",
        ));
    }
    if sends.len() > 1 {
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
/// route touches adds at most two token requests per exchange.
fn route_worst_case(
    steps: &[Step],
    bodies: &HashMap<&str, &[Step]>,
    oauth_endpoints: &HashSet<&str>,
) -> u64 {
    let mut walk = WorstCaseWalk {
        bodies,
        oauth_endpoints,
        used_oauth: &mut HashSet::new(),
        clauses: Vec::new(),
    };
    let main = worst_body(steps, &mut walk, 0, declared_redeliveries(steps), false);
    let tokens = 2u64.saturating_mul(u64::try_from(walk.used_oauth.len()).unwrap_or(u64::MAX));
    // A `continued` clause resumes after the failure point, so it can
    // run once per route-body worst-case send; handled and propagated
    // clauses run once.
    let clause_worst = walk
        .clauses
        .iter()
        .map(|(worst, continued)| {
            if *continued {
                worst.saturating_mul(main)
            } else {
                *worst
            }
        })
        .max()
        .unwrap_or(0);
    main.saturating_add(clause_worst).saturating_add(tokens)
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
/// the pack endpoints needing token requests, and the accumulators.
struct WorstCaseWalk<'a> {
    bodies: &'a HashMap<&'a str, &'a [Step]>,
    oauth_endpoints: &'a HashSet<&'a str>,
    used_oauth: &'a mut HashSet<String>,
    /// Top-level exception-clause bodies seen so far, as (worst-case
    /// sends, whether the clause resumes with `continued`).
    clauses: Vec<(u64, bool)>,
}

/// The worst-case upstream send count of one body: `to` and `enrich`
/// count one send times the redelivery attempts in force, `direct:`
/// expands the target (its own redelivery declarations join the widest in
/// force), `split` and `loop` multiply by their mandatory bounds, and
/// `choice` takes the widest branch. Exception-clause bodies do not add
/// to the running total; each top-level clause body becomes a separate
/// candidate (multiplied by the route body in [`route_worst_case`] when
/// the clause resumes with `continued`), and a clause nested inside
/// another clause adds to its enclosing clause's body (the runtime can
/// run both).
fn worst_body(
    steps: &[Step],
    walk: &mut WorstCaseWalk<'_>,
    depth: usize,
    redeliveries: u32,
    in_clause: bool,
) -> u64 {
    if depth > MAX_DIRECT_DEPTH {
        return 0;
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
                    total = total.saturating_add(attempts);
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
                        ));
                    }
                }
            },
            Step::Enrich(enrich) => match enrich.uri.component {
                SendComponent::Http | SendComponent::GraphQl => {
                    if walk.oauth_endpoints.contains(enrich.uri.id.as_str()) {
                        walk.used_oauth.insert(enrich.uri.id.to_string());
                    }
                    total = total.saturating_add(attempts);
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
                        ));
                    }
                }
            },
            Step::Split(split) => {
                let items = split.maximum_items.map_or(1u64, |bound| bound.get());
                total = total.saturating_add(items.saturating_mul(worst_body(
                    &split.steps,
                    walk,
                    depth + 1,
                    redeliveries,
                    in_clause,
                )));
            }
            Step::Loop(loop_step) => {
                let iterations = loop_step
                    .maximum_iterations
                    .map_or(1u64, |bound| bound.get());
                total = total.saturating_add(iterations.saturating_mul(worst_body(
                    &loop_step.steps,
                    walk,
                    depth + 1,
                    redeliveries,
                    in_clause,
                )));
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
                    ));
                }
                if let Some(otherwise) = &choice.otherwise {
                    widest = widest.max(worst_body(
                        &otherwise.steps,
                        walk,
                        depth + 1,
                        redeliveries,
                        in_clause,
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
                ));
                if let Some(fallback) = &breaker.on_fallback {
                    total = total.max(worst_body(
                        &fallback.steps,
                        walk,
                        depth + 1,
                        redeliveries,
                        in_clause,
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
                ));
            }
            Step::IdempotentConsumer(idempotent) => {
                total = total.saturating_add(worst_body(
                    &idempotent.steps,
                    walk,
                    depth + 1,
                    redeliveries,
                    in_clause,
                ));
            }
            Step::DoTry(do_try) => {
                total = total.saturating_add(worst_body(
                    &do_try.steps,
                    walk,
                    depth + 1,
                    redeliveries,
                    in_clause,
                ));
                for catch in &do_try.do_catch {
                    total = total.max(worst_body(
                        &catch.steps,
                        walk,
                        depth + 1,
                        redeliveries,
                        in_clause,
                    ));
                }
                if let Some(do_finally) = &do_try.do_finally {
                    total = total.saturating_add(worst_body(
                        &do_finally.steps,
                        walk,
                        depth + 1,
                        redeliveries,
                        in_clause,
                    ));
                }
            }
            Step::OnException(clause) => {
                let clause_redeliveries = clause
                    .redelivery_policy
                    .as_ref()
                    .map_or(redeliveries, |policy| {
                        redeliveries.max(policy.maximum_redeliveries)
                    });
                let worst = worst_body(&clause.steps, walk, depth + 1, clause_redeliveries, true);
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
        AccessProfile, Binding, PinnedRef, RecordField, RecordFieldType, RecordType,
    };
    use crate::route::{
        ChoiceStep, DefaultErrorHandler, DoCatch, DoFinally, DoTryStep, EnrichStep,
        ErrorHandlerStep, FilterStep, IdempotentConsumerStep, LoopStep, OnExceptionStep,
        RedeliveryOptions, RouteDefinition, RouteFrom, RouteTemplate, SplitStep, TemplatedRoute,
        ToParameters, ToStep, When,
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

    fn rhai(file: &str) -> Expression {
        Expression::Rhai(RhaiExpression {
            file: file.to_string(),
            entrypoint: "main".to_string(),
        })
    }

    fn pack_builder(endpoints: Vec<Endpoint>, routes: Vec<RouteDefinition>) -> AdapterPack {
        AdapterPack {
            id: id("case-api-pack"),
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
            id: id("case-api"),
            component: ComponentKind::Http,
            authentication: EndpointAuthentication::Oauth2ClientCredentials {},
            response_headers: Vec::new(),
            operations: vec![EndpointOperation {
                id: id("cases.create"),
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
            id: id("case-api"),
            component: ComponentKind::Http,
            authentication: EndpointAuthentication::Basic {},
            response_headers: Vec::new(),
            operations: vec![EndpointOperation {
                id: id("cases.find"),
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
            id: id("case-api"),
            operations: UniqueIdList::new(operations).expect("unique"),
            problem_codes: UniqueList::new(vec![id("cases.conflict")]).expect("unique"),
            problem_envelope: EnvelopeTemplate(r#"{"code": "{{problemCode}}"}"#.to_string()),
            parameterized_parts: UniqueList::<ParameterizedPart>::new(Vec::new()).expect("empty"),
        }
    }

    fn operation(id_text: &str, method: HttpMethod) -> ProfileOperation {
        ProfileOperation {
            id: id(id_text),
            method,
            path: "/v2/cases/{type}".to_string(),
            request_envelope: None,
            response_envelope: EnvelopeTemplate(r#"{"cases": {{records}}}"#.to_string()),
            pagination: None,
        }
    }

    fn project_builder(pack: &AdapterPack) -> AdapterProject {
        AdapterProject {
            id: id("case-deployment"),
            profile: PinnedRef {
                id: id("case-api"),
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
                id: id("registry-clerk"),
                scopes: vec![id("cases:read")],
                operations: vec![id("cases.find")],
                record_types: vec![local("case")],
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

    // ----- envelope and profile checks -----

    #[test]
    fn profile_accepts_a_closed_envelope_set() {
        let profile = profile_builder(vec![operation("cases.find", HttpMethod::Get)]);
        assert_clean(check_profile(&profile));
    }

    #[test]
    fn profile_refuses_an_unknown_slot() {
        let profile = profile_builder(vec![ProfileOperation {
            id: id("cases.find"),
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
            id: id("cases.find"),
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
        let without_envelope = profile_builder(vec![operation("cases.create", HttpMethod::Post)]);
        assert_has(
            &check_profile(&without_envelope),
            CheckCode::ProfileRequestEnvelopeMissingRecordSlot,
        );
        let wrong_slot = profile_builder(vec![ProfileOperation {
            id: id("cases.create"),
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
            id: id("cases.create"),
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
            id: id("cases.find"),
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
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
            },
            steps: vec![Step::SetBody(rhai("scripts/unpinned.rhai"))],
        };
        let pack = pack_builder(vec![], vec![route]);
        assert_has(&check_pack(&pack), CheckCode::PackUnknownScript);
        let pinned_route = RouteDefinition {
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
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
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
            },
            steps: vec![Step::Enrich(EnrichStep {
                uri: direct("sharedLookup"),
                aggregation_strategy: None,
                aggregate_on_exception: false,
            })],
        };
        let shared = RouteDefinition {
            id: id("sharedLookup"),
            from: RouteFrom {
                uri: direct("sharedLookup"),
            },
            steps: vec![to_get("case-api")],
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![caller, shared]);
        assert_clean(check_routes(&pack, &project_builder(&pack)));
    }

    #[test]
    fn routes_refuse_a_direct_cycle() {
        let first = RouteDefinition {
            id: id("first"),
            from: RouteFrom {
                uri: direct("first"),
            },
            steps: vec![Step::Enrich(EnrichStep {
                uri: direct("second"),
                aggregation_strategy: None,
                aggregate_on_exception: false,
            })],
        };
        let second = RouteDefinition {
            id: id("second"),
            from: RouteFrom {
                uri: direct("second"),
            },
            steps: vec![Step::Enrich(EnrichStep {
                uri: direct("first"),
                aggregation_strategy: None,
                aggregate_on_exception: false,
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
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
            },
            steps: vec![
                Step::Enrich(EnrichStep {
                    uri: direct("nowhere"),
                    aggregation_strategy: None,
                    aggregate_on_exception: false,
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
            id: id("fetchCase"),
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
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
            },
            steps: vec![
                Step::Split(SplitStep {
                    expression: Expression::JsonPath("$.items".to_string()),
                    maximum_items: None,
                    aggregation_strategy: None,
                    stop_on_exception: false,
                    error_threshold: None,
                    max_failed_records: None,
                    steps: vec![],
                }),
                Step::Loop(LoopStep {
                    maximum_iterations: None,
                    do_while: None,
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
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
            },
            steps: vec![
                Step::Split(SplitStep {
                    expression: Expression::JsonPath("$.items".to_string()),
                    maximum_items: Some(BoundedU64::<1, 100_000>::new(10).expect("bound")),
                    aggregation_strategy: None,
                    stop_on_exception: false,
                    error_threshold: None,
                    max_failed_records: None,
                    steps: vec![],
                }),
                Step::Loop(LoopStep {
                    maximum_iterations: Some(BoundedU64::<1, 100_000>::new(5).expect("bound")),
                    do_while: None,
                    copy: false,
                    steps: vec![],
                }),
            ],
        };
        let bounded_pack = pack_builder(vec![], vec![bounded]);
        assert_clean(check_routes(&bounded_pack, &project_builder(&bounded_pack)));
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
                max_failed_records: None,
                steps: vec![to_post("case-api", "cases.create")],
            })]
        };
        let without = RouteDefinition {
            id: id("createCase"),
            from: RouteFrom {
                uri: direct("createCase"),
            },
            steps: split_steps(false),
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![without]);
        assert_has(
            &check_routes(&pack, &project_builder(&pack)),
            CheckCode::RouteNonSafeSendInSplit,
        );
        let with = RouteDefinition {
            id: id("createCase"),
            from: RouteFrom {
                uri: direct("createCase"),
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
                id: id("fetchCase"),
                from: RouteFrom {
                    uri: direct("fetchCase"),
                },
                steps: vec![Step::OnException(OnExceptionStep {
                    exception: vec![class],
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
                id: id("fetchCase"),
                from: RouteFrom {
                    uri: direct("fetchCase"),
                },
                steps: vec![Step::DoTry(DoTryStep {
                    steps: vec![],
                    do_catch: vec![DoCatch {
                        exception: vec![class],
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
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
            },
            steps: vec![Step::OnException(OnExceptionStep {
                exception: vec![crate::model::ErrorClass::UpstreamHttp],
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
    /// `egress.refused`, and `script.budgetExceeded` above.
    #[test]
    fn credential_rejected_is_refused_in_a_clause() {
        let route = RouteDefinition {
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
            },
            steps: vec![Step::OnException(OnExceptionStep {
                exception: vec![crate::model::ErrorClass::CredentialRejected],
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
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
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
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
            },
            steps: vec![Step::OnException(OnExceptionStep {
                exception: vec![crate::model::ErrorClass::UpstreamTimeout],
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
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
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
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
            },
            steps: vec![
                Step::OnException(OnExceptionStep {
                    exception: vec![crate::model::ErrorClass::UpstreamTimeout],
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

    #[test]
    fn routes_refuse_redelivery_over_a_non_safe_send_without_the_claim() {
        let route = RouteDefinition {
            id: id("createCase"),
            from: RouteFrom {
                uri: direct("createCase"),
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
                to_post("case-api", "cases.create"),
            ],
        };
        let mut unclaimed = oauth_endpoint();
        unclaimed.operations = vec![EndpointOperation {
            id: id("cases.create"),
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

    // ----- project checks -----

    #[test]
    fn project_accepts_resolved_references_within_budget() {
        let profile = profile_builder(vec![operation("cases.find", HttpMethod::Get)]);
        let route = RouteDefinition {
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
            },
            steps: vec![to_get("case-api")],
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![route]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(vec![AccessProfile {
            id: id("registry-clerk"),
            scopes: vec![id("cases:read")],
            operations: vec![id("cases.find")],
            record_types: vec![local("case")],
        }])
        .expect("unique");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: id("find-cases"),
            operation: id("cases.find"),
            record_type: local("case"),
            route: id("fetchCase"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(5).expect("budget"),
        }])
        .expect("unique");
        assert_clean(check_project(&workspace(&profile, &pack, &project)));
    }

    #[test]
    fn project_refuses_unknown_operation_record_type_route_and_template() {
        let profile = profile_builder(vec![operation("cases.find", HttpMethod::Get)]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let mut project = project_builder(&pack);
        project.templated_routes = UniqueIdList::new(vec![TemplatedRoute {
            route_template_ref: id("no-such-template"),
            route_id: id("freshRoute"),
            parameters: BTreeMap::new(),
        }])
        .expect("unique");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: id("binding"),
            operation: id("cases.missing"),
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

    #[test]
    fn project_refuses_an_instantiated_route_id_that_collides() {
        let profile = profile_builder(vec![]);
        let template_route = RouteTemplate {
            id: id("pagedFetch"),
            parameters: Vec::new(),
            steps: vec![],
        };
        let mut pack = pack_builder(vec![], vec![]);
        pack.route_templates = UniqueIdList::new(vec![template_route]).expect("unique");
        let mut project = project_builder(&pack);
        project.templated_routes = UniqueIdList::new(vec![TemplatedRoute {
            route_template_ref: id("pagedFetch"),
            route_id: id("pagedFetch"),
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
        let profile = profile_builder(vec![operation("cases.find", HttpMethod::Get)]);
        // A loop of 10 iterations, each fetching one endpoint: worst case 10.
        let route = RouteDefinition {
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
            },
            steps: vec![Step::Loop(LoopStep {
                maximum_iterations: Some(BoundedU64::<1, 100_000>::new(10).expect("bound")),
                do_while: None,
                copy: false,
                steps: vec![to_get("case-api")],
            })],
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![route]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        // Ten looped sends plus two token requests for the one OAuth
        // endpoint (CONCEPT 10.2): twelve.
        project.bindings = UniqueIdList::new(vec![Binding {
            id: id("find-cases"),
            operation: id("cases.find"),
            record_type: local("case"),
            route: id("fetchCase"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(3).expect("budget"),
        }])
        .expect("unique");
        let findings = check_project(&workspace(&profile, &pack, &project));
        assert_has(&findings, CheckCode::ProjectUpstreamBudgetExceeded);
        project.bindings = UniqueIdList::new(vec![Binding {
            id: id("find-cases"),
            operation: id("cases.find"),
            record_type: local("case"),
            route: id("fetchCase"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(12).expect("budget"),
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
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
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
                to_direct("loadCase"),
            ],
        };
        let leaf = RouteDefinition {
            id: id("loadCase"),
            from: RouteFrom {
                uri: direct("loadCase"),
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
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
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
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
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
                to_direct("loadCase"),
            ],
        };
        let live_leaf = RouteDefinition {
            id: id("loadCase"),
            from: RouteFrom {
                uri: direct("loadCase"),
            },
            steps: vec![to_get("case-api")],
        };
        let pack = pack_builder(vec![basic_endpoint()], vec![expanding, live_leaf]);
        assert_clean(check_routes(&pack, &project_builder(&pack)));
    }

    /// A `continued` clause resumes after the failure point, so its body
    /// counts once per route-body worst-case send: over three body sends
    /// it triples, pushing the route past `maximumUpstreamCalls`; the
    /// same route passes with an adequate budget. A clause that does not
    /// continue counts once.
    #[test]
    fn project_counts_a_continued_clause_once_per_route_body_send() {
        let profile = profile_builder(vec![operation("cases.find", HttpMethod::Get)]);
        let clause = |continued: bool| {
            Step::OnException(OnExceptionStep {
                exception: vec![crate::model::ErrorClass::UpstreamTimeout],
                on_when: None,
                handled: Some(true),
                continued: Some(continued),
                redelivery_policy: None,
                steps: vec![to_get("case-api")],
            })
        };
        let route = |continued: bool| RouteDefinition {
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
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
        // Three body sends plus one continued-clause send per body send:
        // 3 + 1 * 3 = 6.
        project.bindings = UniqueIdList::new(vec![Binding {
            id: id("find-cases"),
            operation: id("cases.find"),
            record_type: local("case"),
            route: id("fetchCase"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(5).expect("budget"),
        }])
        .expect("unique");
        let findings = check_project(&workspace(&profile, &pack, &project));
        assert_has(&findings, CheckCode::ProjectUpstreamBudgetExceeded);
        project.bindings = UniqueIdList::new(vec![Binding {
            id: id("find-cases"),
            operation: id("cases.find"),
            record_type: local("case"),
            route: id("fetchCase"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(6).expect("budget"),
        }])
        .expect("unique");
        assert_clean(check_project(&workspace(&profile, &pack, &project)));
        // Without `continued`, the clause body counts once: 3 + 1 = 4.
        let pack = pack_builder(vec![basic_endpoint()], vec![route(false)]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: id("find-cases"),
            operation: id("cases.find"),
            record_type: local("case"),
            route: id("fetchCase"),
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
        let profile = profile_builder(vec![operation("cases.find", HttpMethod::Get)]);
        // The route body sends nothing; the clause body sends three times,
        // each with two redeliveries: 3 * (1 + 2) = 9 upstream calls.
        let route = RouteDefinition {
            id: id("fetchCase"),
            from: RouteFrom {
                uri: direct("fetchCase"),
            },
            steps: vec![Step::OnException(OnExceptionStep {
                exception: vec![crate::model::ErrorClass::UpstreamTimeout],
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
            id: id("find-cases"),
            operation: id("cases.find"),
            record_type: local("case"),
            route: id("fetchCase"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(8).expect("budget"),
        }])
        .expect("unique");
        let findings = check_project(&workspace(&profile, &pack, &project));
        assert_has(&findings, CheckCode::ProjectUpstreamBudgetExceeded);
        // The exact worst case fits: 9 sends + 2 token requests.
        project.bindings = UniqueIdList::new(vec![Binding {
            id: id("find-cases"),
            operation: id("cases.find"),
            record_type: local("case"),
            route: id("fetchCase"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(11).expect("budget"),
        }])
        .expect("unique");
        assert_clean(check_project(&workspace(&profile, &pack, &project)));
    }

    /// A write route must wrap its sends in `idempotentConsumer` and carry
    /// at most one non-safe send before Increment 3.
    #[test]
    fn project_refuses_a_write_route_without_idempotency_and_two_non_safe_sends() {
        let profile = profile_builder(vec![ProfileOperation {
            id: id("cases.create"),
            method: HttpMethod::Post,
            path: "/v2/cases/{type}".to_string(),
            request_envelope: Some(EnvelopeTemplate(r#"{"input": {{record}}}"#.to_string())),
            response_envelope: EnvelopeTemplate(r#"{"cases": {{records}}}"#.to_string()),
            pagination: None,
        }]);
        let bare = RouteDefinition {
            id: id("createCase"),
            from: RouteFrom {
                uri: direct("createCase"),
            },
            steps: vec![to_post("case-api", "cases.create")],
        };
        let pack = pack_builder(vec![oauth_endpoint()], vec![bare]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: id("create-cases"),
            operation: id("cases.create"),
            record_type: local("case"),
            route: id("createCase"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(10).expect("budget"),
        }])
        .expect("unique");
        let findings = check_project(&workspace(&profile, &pack, &project));
        assert_has(&findings, CheckCode::RouteWriteWithoutIdempotency);

        let wrapped = RouteDefinition {
            id: id("createCase"),
            from: RouteFrom {
                uri: direct("createCase"),
            },
            steps: vec![Step::IdempotentConsumer(IdempotentConsumerStep {
                expression: Expression::Header("Idempotency-Key".to_string()),
                eager: true,
                remove_on_failure: true,
                completion_eager: false,
                steps: vec![to_post("case-api", "cases.create")],
            })],
        };
        let wrapped_pack = pack_builder(vec![oauth_endpoint()], vec![wrapped]);
        let mut wrapped_project = project_builder(&wrapped_pack);
        wrapped_project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        wrapped_project.bindings = UniqueIdList::new(vec![Binding {
            id: id("create-cases"),
            operation: id("cases.create"),
            record_type: local("case"),
            route: id("createCase"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(10).expect("budget"),
        }])
        .expect("unique");
        let findings = check_project(&workspace(&profile, &wrapped_pack, &wrapped_project));
        assert!(
            !codes(&findings).contains(&CheckCode::RouteWriteWithoutIdempotency.code()),
            "a wrapped send passes: {findings:?}"
        );

        let doubled = RouteDefinition {
            id: id("createCase"),
            from: RouteFrom {
                uri: direct("createCase"),
            },
            steps: vec![Step::IdempotentConsumer(IdempotentConsumerStep {
                expression: Expression::Header("Idempotency-Key".to_string()),
                eager: true,
                remove_on_failure: true,
                completion_eager: false,
                steps: vec![
                    to_post("case-api", "cases.create"),
                    to_post("case-api", "cases.create"),
                ],
            })],
        };
        let doubled_pack = pack_builder(vec![oauth_endpoint()], vec![doubled]);
        let mut doubled_project = project_builder(&doubled_pack);
        doubled_project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        doubled_project.bindings = UniqueIdList::new(vec![Binding {
            id: id("create-cases"),
            operation: id("cases.create"),
            record_type: local("case"),
            route: id("createCase"),
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
        let profile = profile_builder(vec![operation("cases.find", HttpMethod::Get)]);
        let pack = pack_builder(vec![], vec![]);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(vec![AccessProfile {
            id: id("registry-clerk"),
            scopes: vec![],
            operations: vec![id("cases.missing")],
            record_types: vec![local("ghost")],
        }])
        .expect("unique");
        let findings = check_project(&workspace(&profile, &pack, &project));
        assert_has(&findings, CheckCode::ProjectUnknownOperation);
        assert_has(&findings, CheckCode::ProjectUnknownRecordType);
    }

    // ----- runtime checks -----

    fn runtime_builder(endpoints: Vec<EndpointBinding>) -> AdapterRuntimeConfig {
        AdapterRuntimeConfig {
            id: id("case-deployment"),
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
                token_endpoint: "https://token.example.invalid/token".to_string(),
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

    // ----- fixture checks -----

    #[test]
    fn fixtures_accept_declared_intercepts_and_entries() {
        let profile = profile_builder(vec![]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let project = project_builder(&pack);
        let fixture = AdapterFixture {
            id: id("case-api-fixtures"),
            pack: id("case-api-pack"),
            upstream_version: "2.7".to_string(),
            provenance: FixtureProvenance::Captured {
                reference: "staging".to_string(),
            },
            intercepts: vec![Intercept::Endpoint {
                endpoint: id("case-api"),
            }],
            entries: vec![FixtureEntry {
                given: RecordedRequest {
                    endpoint: id("case-api"),
                    method: HttpMethod::Get,
                    path: "/v2/cases/person/123".to_string(),
                    query: None,
                    body: None,
                },
                upstream_response: RecordedResponse {
                    status: 200,
                    body: None,
                },
                expected_facade_response: RecordedResponse {
                    status: 200,
                    body: None,
                },
            }],
        };
        let mut ws = workspace(&profile, &pack, &project);
        ws.fixtures = std::slice::from_ref(&fixture);
        assert_clean(check_fixtures(&ws));
    }

    #[test]
    fn fixtures_refuse_unknown_intercepts_and_entries() {
        let profile = profile_builder(vec![]);
        let pack = pack_builder(vec![oauth_endpoint()], vec![]);
        let project = project_builder(&pack);
        let fixture = AdapterFixture {
            id: id("case-api-fixtures"),
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
                given: RecordedRequest {
                    endpoint: id("also-missing"),
                    method: HttpMethod::Get,
                    path: "/".to_string(),
                    query: None,
                    body: None,
                },
                upstream_response: RecordedResponse {
                    status: 200,
                    body: None,
                },
                expected_facade_response: RecordedResponse {
                    status: 200,
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
                })]
            } else {
                vec![]
            };
            routes.push(RouteDefinition {
                id: id(&id_text),
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
                })]
            } else {
                vec![to_get("case-api")]
            };
            routes.push(RouteDefinition {
                id: id(&id_text),
                from: RouteFrom {
                    uri: direct(&id_text),
                },
                steps,
            });
        }
        let profile = profile_builder(vec![operation("cases.find", HttpMethod::Get)]);
        let pack = pack_builder(vec![oauth_endpoint()], routes);
        let mut project = project_builder(&pack);
        project.access_profiles = UniqueIdList::new(Vec::new()).expect("empty");
        project.bindings = UniqueIdList::new(vec![Binding {
            id: id("find-cases"),
            operation: id("cases.find"),
            record_type: local("case"),
            route: id("hop2"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(5).expect("budget"),
        }])
        .expect("unique");
        let ws = workspace(&profile, &pack, &project);
        assert_clean(check_workspace(&ws));
    }
}

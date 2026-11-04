// SPDX-License-Identifier: Apache-2.0

//! Closed linear multi-effect write resume.
//!
//! The authored wire remains `resumeBindings` on `to` steps. Compilation
//! admits only the core-checked flat HTTP form and turns each binding into a
//! bounded singular selector. Runtime extraction returns source identifiers
//! only, never a response body or an arbitrary JSON value.

use std::collections::{BTreeMap, BTreeSet};

use registry_adapter_core::{
    is_non_safe_upstream, send_claims_idempotent, AdapterPack, ErrorClass, HttpMethod,
    OnExceptionStep, ResumeBinding, SendComponent, Step,
};
use serde_json::Value;

use crate::language::{compile_selector, JsonPathResult, JsonPathSelector};
use crate::route::RouteFailure;

pub(crate) const MAXIMUM_RESUME_IDENTIFIER_BYTES: usize = 256;

#[doc(hidden)]
/// Compiled private resume plan retained on a served operation.
pub struct ServedResumeOperation {
    steps: Vec<ServedResumeStep>,
    /// Source-pack normalizations that can prove a returned 4xx was a
    /// terminal non-effect. Empty for the generic linear resume form.
    terminal_source_rejections: BTreeSet<ErrorClass>,
}

impl std::fmt::Debug for ServedResumeOperation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServedResumeOperation")
            .field("step_count", &self.steps.len())
            .finish()
    }
}

struct ServedResumeStep {
    bindings: Vec<CompiledResumeBinding>,
}

struct CompiledResumeBinding {
    name: String,
    selector: JsonPathSelector,
}

#[derive(Clone, Eq, PartialEq)]
/// One bounded source-native identifier checkpointed for a later step.
pub struct ResumeValue {
    name: String,
    value: String,
}

impl std::fmt::Debug for ResumeValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResumeValue")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl ResumeValue {
    /// Construct one already-validated checkpoint value.
    #[must_use]
    pub fn new(name: String, value: String) -> Self {
        Self { name, value }
    }

    /// The route-declared binding name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The bounded source-native identifier.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

pub(crate) fn compile_resume_operation(
    steps: &[Step],
    pack: &AdapterPack,
) -> Result<Option<ServedResumeOperation>, String> {
    let [Step::IdempotentConsumer(consumer)] = steps else {
        return Ok(None);
    };
    let non_safe = consumer
        .steps
        .iter()
        .filter(|step| match step {
            Step::To(to) => is_non_safe_upstream(
                to.uri.component,
                to.uri.id.as_str(),
                to.parameters.as_ref(),
                pack,
            ),
            _ => false,
        })
        .count();
    if non_safe <= 1 {
        return Ok(None);
    }
    if non_safe != consumer.steps.len() {
        return Err("a resumable write is not one flat sequence of non-safe sends".to_owned());
    }
    if !matches!(
        &consumer.expression,
        registry_adapter_core::Expression::Header(name)
            if name.eq_ignore_ascii_case("Idempotency-Key")
    ) {
        return Err("a resumable write does not use the facade idempotency key".to_owned());
    }
    let mut compiled = Vec::with_capacity(consumer.steps.len());
    for step in &consumer.steps {
        let Step::To(to) = step else {
            return Err("a resumable write contains a non-send step".to_owned());
        };
        if to.uri.component != SendComponent::Http {
            return Err("a resumable write contains a non-HTTP send".to_owned());
        }
        let parameters = to
            .parameters
            .as_ref()
            .ok_or("a resumable send has no parameters")?;
        if !parameters.throw_exception_on_failure || parameters.ok_status_code_range.is_some() {
            return Err(
                "a resumable send changes the default HTTP failure classification".to_owned(),
            );
        }
        if pack
            .endpoints
            .get(to.uri.id.as_str())
            .is_some_and(|endpoint| !endpoint.request_headers.is_empty())
        {
            return Err("a resumable send targets an endpoint with request headers".to_owned());
        }
        if !send_claims_idempotent(pack, to.uri.id.as_str(), parameters.operation.as_ref()) {
            return Err(
                "a resumable send lacks the reviewed idempotentUpstream assumption".to_owned(),
            );
        }
        compiled.push(ServedResumeStep {
            bindings: compile_bindings(&parameters.resume_bindings)?,
        });
    }
    Ok(Some(ServedResumeOperation {
        steps: compiled,
        terminal_source_rejections: BTreeSet::new(),
    }))
}

fn terminal_source_rejection(clause: &OnExceptionStep) -> Result<ErrorClass, String> {
    let mut exceptions = clause.exception.iter();
    if exceptions.next() != Some(&ErrorClass::UpstreamHttp) || exceptions.next().is_some() {
        return Err(
            "a source-native terminal rejection clause does not name only upstream.http".to_owned(),
        );
    }
    if clause.on_when.is_none() {
        return Err(
            "a source-native terminal rejection clause has no source-owned predicate".to_owned(),
        );
    }
    if clause.handled.is_some()
        || clause.continued.is_some()
        || clause.retry_while.is_some()
        || clause.redelivery_policy.is_some()
    {
        return Err(
            "a source-native terminal rejection clause changes failure or redelivery flow"
                .to_owned(),
        );
    }
    let [Step::ThrowException(raised)] = clause.steps.as_slice() else {
        return Err(
            "a source-native terminal rejection clause is not one constant throw".to_owned(),
        );
    };
    if raised.data.is_some() {
        return Err(
            "a source-native terminal rejection clause exposes source-derived problem data"
                .to_owned(),
        );
    }
    if !matches!(
        raised.exception_type,
        ErrorClass::OutcomeNotFound
            | ErrorClass::OutcomeConflict
            | ErrorClass::OutcomeInvalidRequest
            | ErrorClass::OutcomeRejected
    ) {
        return Err(
            "a source-native terminal rejection clause does not raise a generic outcome class"
                .to_owned(),
        );
    }
    Ok(raised.exception_type)
}

/// Compile the one-effect source-native replay form explicitly selected by a
/// write host.
///
/// This does not broaden [`compile_resume_operation`]: ordinary single-write
/// routes retain their existing non-resumable status. The opt-in form keeps
/// the existing outer idempotency consumer and admits only deterministic,
/// digest-pinned preparation around one static idempotent HTTP POST. Reviewed
/// source-pack code owns the determinism claim; this compiler closes the EIP
/// and transport shapes that could add another effect or per-attempt header.
pub(crate) fn compile_source_native_single_resume_operation(
    steps: &[Step],
    pack: &AdapterPack,
) -> Result<ServedResumeOperation, String> {
    let mut consumer = None;
    let mut terminal_source_rejections = BTreeSet::new();
    for step in steps {
        match step {
            Step::OnException(clause) => {
                terminal_source_rejections.insert(terminal_source_rejection(clause)?);
            }
            Step::IdempotentConsumer(found) if consumer.is_none() => consumer = Some(found),
            Step::IdempotentConsumer(_) => {
                return Err(
                    "a source-native single replay contains more than one idempotency consumer"
                        .to_owned(),
                )
            }
            _ => {
                return Err(
                    "a source-native single replay has a top-level step outside its terminal clauses and idempotency consumer"
                        .to_owned(),
                )
            }
        }
    }
    let consumer = consumer.ok_or_else(|| {
        "a source-native single replay is not wrapped by one idempotency consumer".to_owned()
    })?;
    if consumer.completion_eager && !terminal_source_rejections.is_empty() {
        return Err(
            "a source-native terminal rejection requires exchange-scoped write completion"
                .to_owned(),
        );
    }
    if !matches!(
        &consumer.expression,
        registry_adapter_core::Expression::Header(name)
            if name.eq_ignore_ascii_case("Idempotency-Key")
    ) {
        return Err(
            "a source-native single replay does not use the facade idempotency key".to_owned(),
        );
    }

    let mut send = None;
    for step in &consumer.steps {
        match step {
            Step::SetBody(_) | Step::SetProperty(_) | Step::Validate(_) => {}
            Step::To(to) if send.is_none() => send = Some(to),
            Step::To(_) => {
                return Err("a source-native single replay contains more than one send".to_owned())
            }
            _ => {
                return Err(
                    "a source-native single replay contains a non-allowlisted step".to_owned(),
                )
            }
        }
    }
    let to = send.ok_or("a source-native single replay contains no send")?;
    if to.uri.component != SendComponent::Http {
        return Err("a source-native single replay contains a non-HTTP send".to_owned());
    }
    let parameters = to
        .parameters
        .as_ref()
        .ok_or("a source-native single replay send has no parameters")?;
    if parameters.http_method.unwrap_or(HttpMethod::Post) != HttpMethod::Post {
        return Err("a source-native single replay send is not HTTP POST".to_owned());
    }
    if !is_non_safe_upstream(to.uri.component, to.uri.id.as_str(), Some(parameters), pack) {
        return Err("a source-native single replay send is not a source effect".to_owned());
    }
    if parameters.http_uri.is_some() {
        return Err("a source-native single replay uses a dynamic HTTP URI".to_owned());
    }
    if !parameters.query_parameters.is_empty() {
        return Err("a source-native single replay carries non-HTTP query parameters".to_owned());
    }
    if !parameters.throw_exception_on_failure || parameters.ok_status_code_range.is_some() {
        return Err(
            "a source-native single replay changes the default HTTP failure classification"
                .to_owned(),
        );
    }
    if !parameters.resume_bindings.is_empty() {
        return Err(
            "a source-native single replay declares terminal-step resume bindings".to_owned(),
        );
    }
    if pack
        .endpoints
        .get(to.uri.id.as_str())
        .is_some_and(|endpoint| !endpoint.request_headers.is_empty())
    {
        return Err(
            "a source-native single replay targets an endpoint with request headers".to_owned(),
        );
    }
    if !send_claims_idempotent(pack, to.uri.id.as_str(), parameters.operation.as_ref()) {
        return Err(
            "a source-native single replay lacks the reviewed idempotentUpstream assumption"
                .to_owned(),
        );
    }

    Ok(ServedResumeOperation {
        steps: vec![ServedResumeStep {
            bindings: Vec::new(),
        }],
        terminal_source_rejections,
    })
}

fn compile_bindings(bindings: &[ResumeBinding]) -> Result<Vec<CompiledResumeBinding>, String> {
    bindings
        .iter()
        .map(|binding| {
            let selector = compile_selector(&binding.path)
                .map_err(|_| "a resume binding selector could not be compiled".to_owned())?;
            if !selector.is_singular() {
                return Err("a resume binding selector is not singular".to_owned());
            }
            Ok(CompiledResumeBinding {
                name: binding.name.as_str().to_owned(),
                selector,
            })
        })
        .collect()
}

impl ServedResumeOperation {
    /// A linear plan of `step_count` sends that checkpoint no bindings.
    #[cfg(test)]
    pub(crate) fn linear_for_tests(step_count: usize) -> Self {
        Self {
            steps: (0..step_count)
                .map(|_| ServedResumeStep {
                    bindings: Vec::new(),
                })
                .collect(),
            terminal_source_rejections: BTreeSet::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn source_native_for_tests(classes: impl IntoIterator<Item = ErrorClass>) -> Self {
        Self {
            steps: vec![ServedResumeStep {
                bindings: Vec::new(),
            }],
            terminal_source_rejections: classes.into_iter().collect(),
        }
    }

    /// Whether a governed source clause normalized this returned client
    /// response into the exact generic outcome class it declares. A missing
    /// response and every 5xx stay ambiguous and therefore resumable.
    #[must_use]
    pub(crate) fn is_definitive_source_rejection(
        &self,
        status: Option<u16>,
        class: ErrorClass,
    ) -> bool {
        status.is_some_and(|status| (400..500).contains(&status))
            && self.terminal_source_rejections.contains(&class)
    }

    #[must_use]
    pub(crate) fn step_count(&self) -> usize {
        self.steps.len()
    }

    pub(crate) fn extract(
        &self,
        ordinal: usize,
        body: &Value,
    ) -> Result<Vec<ResumeValue>, RouteFailure> {
        let step = self
            .steps
            .get(ordinal)
            .ok_or_else(|| RouteFailure::of(registry_adapter_core::ErrorClass::Facade))?;
        step.bindings
            .iter()
            .map(|binding| {
                let value = match binding.selector.evaluate(body) {
                    Ok(JsonPathResult::Singular(Some(Value::String(value))))
                        if valid_identifier(value) =>
                    {
                        value.clone()
                    }
                    _ => {
                        return Err(RouteFailure::of(
                            registry_adapter_core::ErrorClass::UpstreamMalformed,
                        ));
                    }
                };
                Ok(ResumeValue::new(binding.name.clone(), value))
            })
            .collect()
    }

    pub(crate) fn validates_checkpoint(
        &self,
        next_step: usize,
        bindings: &BTreeMap<String, String>,
    ) -> bool {
        if next_step >= self.steps.len() {
            return false;
        }
        let expected: BTreeMap<&str, ()> = self.steps[..next_step]
            .iter()
            .flat_map(|step| step.bindings.iter())
            .map(|binding| (binding.name.as_str(), ()))
            .collect();
        expected.len() == bindings.len()
            && bindings.iter().all(|(name, value)| {
                expected.contains_key(name.as_str()) && valid_identifier(value)
            })
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_RESUME_IDENTIFIER_BYTES
        && value.chars().all(|character| !character.is_control())
}

#[cfg(test)]
mod tests {
    use registry_adapter_core::{
        Expression, IdempotentConsumerStep, SetPropertyStep, ValidateStep,
    };
    use registry_platform_yaml::LocalId;
    use serde_json::json;

    use super::*;

    fn operation(path: &str) -> ServedResumeOperation {
        ServedResumeOperation {
            steps: vec![
                ServedResumeStep {
                    bindings: compile_bindings(&[ResumeBinding {
                        name: LocalId::new("source_id").expect("a local id"),
                        path: path.to_owned(),
                    }])
                    .expect("the selector compiles"),
                },
                ServedResumeStep {
                    bindings: Vec::new(),
                },
            ],
            terminal_source_rejections: BTreeSet::new(),
        }
    }

    fn pack(idempotent_upstream: bool, request_headers: bool) -> AdapterPack {
        serde_json::from_value(json!({
            "id": "source-native-single-replay",
            "version": "1",
            "testedVersions": ["reviewed-test-source"],
            "endpoints": [{
                "id": "registry",
                "component": "http",
                "authentication": {"type": "none"},
                "attemptTimeoutMilliseconds": 1_000,
                "maximumResponseBytes": 4_096,
                "requestHeaders": if request_headers { json!(["x-authored"]) } else { json!([]) },
                "operations": [{
                    "id": "write-batch",
                    "idempotentUpstream": idempotent_upstream
                }],
                "testedVersions": ["reviewed-test-source"]
            }]
        }))
        .expect("the synthetic pack parses")
    }

    fn step(value: Value) -> Step {
        serde_json::from_value(value).expect("the synthetic step parses")
    }

    fn post() -> Step {
        step(json!({
            "to": {
                "uri": "http:registry",
                "parameters": {
                    "httpMethod": "POST",
                    "path": "/batches",
                    "body": {"jsonpath": "$"},
                    "operation": "write-batch"
                }
            }
        }))
    }

    fn outer(inner: Vec<Step>) -> Vec<Step> {
        vec![Step::IdempotentConsumer(IdempotentConsumerStep {
            expression: Expression::Header("Idempotency-Key".to_owned()),
            eager: true,
            remove_on_failure: true,
            completion_eager: false,
            steps: inner,
        })]
    }

    fn terminal_rejection(class: &str) -> Step {
        step(json!({
            "onException": {
                "exception": ["upstream.http"],
                "onWhen": {"constant": true},
                "steps": [{
                    "throwException": {
                        "exceptionType": class,
                        "message": "the source refused the write"
                    }
                }]
            }
        }))
    }

    #[test]
    fn checkpoint_extraction_accepts_only_bounded_identifier_strings() {
        let operation = operation("$.id");
        assert_eq!(
            operation
                .extract(0, &serde_json::json!({"id":"source-17"}))
                .expect("a bounded string identifier extracts"),
            [ResumeValue::new(
                "source_id".to_owned(),
                "source-17".to_owned()
            )]
        );
        for body in [
            serde_json::json!({"id": 17}),
            serde_json::json!({"id": ""}),
            serde_json::json!({"id": "source\n17"}),
            serde_json::json!({"id": "x".repeat(MAXIMUM_RESUME_IDENTIFIER_BYTES + 1)}),
            serde_json::json!({"other": "source-17"}),
        ] {
            assert!(operation.extract(0, &body).is_err(), "{body}");
        }
    }

    #[test]
    fn source_native_single_replay_accepts_only_explicit_opt_in() {
        let mut steps = vec![
            terminal_rejection("outcome.not-found"),
            terminal_rejection("outcome.invalid-request"),
        ];
        steps.extend(outer(vec![
            Step::SetProperty(SetPropertyStep {
                name: "prepared".to_owned(),
                value: Expression::Constant(json!({"records": []})),
            }),
            Step::SetBody(Expression::ExchangeProperty("prepared".to_owned())),
            Step::Validate(ValidateStep {
                expression: Expression::Constant(Value::Bool(true)),
            }),
            post(),
        ]));
        let pack = pack(true, false);

        let operation = compile_source_native_single_resume_operation(&steps, &pack)
            .expect("the source-native single POST compiles");
        assert_eq!(operation.step_count(), 1);
        assert!(operation.is_definitive_source_rejection(
            Some(404),
            registry_adapter_core::ErrorClass::OutcomeNotFound
        ));
        assert!(operation.is_definitive_source_rejection(
            Some(422),
            registry_adapter_core::ErrorClass::OutcomeInvalidRequest
        ));
        assert!(
            compile_resume_operation(&steps, &pack)
                .expect("the legacy compiler still accepts the route as non-resumable")
                .is_none(),
            "legacy single-write status must remain unchanged"
        );
    }

    #[test]
    fn source_native_single_replay_refuses_absent_or_ambiguous_effects() {
        let pack = pack(true, false);
        for inner in [
            Vec::new(),
            vec![Step::SetBody(Expression::Constant(json!({"records": []})))],
            vec![post(), post()],
            vec![
                step(json!({"to": {"uri": "http:registry", "parameters": {
                    "httpMethod": "GET", "path": "/batches", "operation": "write-batch"
                }}})),
                post(),
            ],
        ] {
            assert!(compile_source_native_single_resume_operation(&outer(inner), &pack).is_err());
        }
        assert!(
            compile_source_native_single_resume_operation(&[post()], &pack).is_err(),
            "the source-native opt-in cannot bypass the outer idempotency consumer"
        );
    }

    #[test]
    fn source_native_single_replay_refuses_non_post_or_unreviewed_sends() {
        for method in ["GET", "PUT", "PATCH"] {
            let send = step(json!({"to": {"uri": "http:registry", "parameters": {
                "httpMethod": method,
                "path": "/batches",
                "operation": "write-batch"
            }}}));
            assert!(
                compile_source_native_single_resume_operation(
                    &outer(vec![send]),
                    &pack(true, false)
                )
                .is_err(),
                "{method} is outside the exact single POST contract"
            );
        }
        assert!(
            compile_source_native_single_resume_operation(
                &outer(vec![post()]),
                &pack(false, false)
            )
            .is_err(),
            "the reviewed idempotentUpstream claim is mandatory"
        );
        assert!(
            compile_source_native_single_resume_operation(&outer(vec![post()]), &pack(true, true))
                .is_err(),
            "authored request-header forwarding can make a replay differ"
        );
        let with_bindings = step(json!({"to": {"uri": "http:registry", "parameters": {
            "httpMethod": "POST",
            "path": "/batches",
            "operation": "write-batch",
            "resumeBindings": [{"name": "batch_id", "path": "$.id"}]
        }}}));
        assert!(
            compile_source_native_single_resume_operation(
                &outer(vec![with_bindings]),
                &pack(true, false)
            )
            .is_err(),
            "a terminal single step checkpoints no source values"
        );
    }

    #[test]
    fn source_native_single_replay_refuses_control_flow_headers_and_direct_calls() {
        let forbidden = [
            step(json!({"setHeader": {
                "name": "x-attempt", "value": {"constant": "attempt"}
            }})),
            step(json!({"choice": {"when": [{
                "constant": true, "steps": [{"setBody": {"constant": {}}}]
            }]}})),
            step(json!({"loop": {
                "constant": 1,
                "maximumIterations": 1,
                "steps": [{"setBody": {"constant": {}}}]
            }})),
            step(json!({"to": {"uri": "direct:prepared"}})),
        ];
        for forbidden_step in forbidden {
            assert!(compile_source_native_single_resume_operation(
                &outer(vec![forbidden_step, post()]),
                &pack(true, false)
            )
            .is_err());
        }

        let nested = outer(vec![Step::IdempotentConsumer(IdempotentConsumerStep {
            expression: Expression::Header("Idempotency-Key".to_owned()),
            eager: true,
            remove_on_failure: true,
            completion_eager: false,
            steps: vec![post()],
        })]);
        assert!(
            compile_source_native_single_resume_operation(&nested, &pack(true, false)).is_err()
        );
    }

    #[test]
    fn source_native_single_replay_requires_the_facade_idempotency_key() {
        let steps = vec![Step::IdempotentConsumer(IdempotentConsumerStep {
            expression: Expression::Header("Other-Key".to_owned()),
            eager: true,
            remove_on_failure: true,
            completion_eager: false,
            steps: vec![post()],
        })];
        assert!(compile_source_native_single_resume_operation(&steps, &pack(true, false)).is_err());
    }

    #[test]
    fn source_native_terminal_rejections_are_pure_explicit_and_closed() {
        let one = |clause: Value| {
            let mut steps = vec![step(clause)];
            steps.extend(outer(vec![post()]));
            compile_source_native_single_resume_operation(&steps, &pack(true, false))
        };

        for refused in [
            json!({"onException": {
                "exception": ["upstream.http"],
                "steps": [{"throwException": {"exceptionType": "outcome.not-found"}}]
            }}),
            json!({"onException": {
                "exception": ["upstream.timeout"],
                "onWhen": {"constant": true},
                "steps": [{"throwException": {"exceptionType": "outcome.not-found"}}]
            }}),
            json!({"onException": {
                "exception": ["upstream.http"],
                "onWhen": {"constant": true},
                "handled": true,
                "steps": [{"throwException": {"exceptionType": "outcome.not-found"}}]
            }}),
            json!({"onException": {
                "exception": ["upstream.http"],
                "onWhen": {"constant": true},
                "continued": true,
                "steps": [{"throwException": {"exceptionType": "outcome.not-found"}}]
            }}),
            json!({"onException": {
                "exception": ["upstream.http"],
                "onWhen": {"constant": true},
                "redeliveryPolicy": {"maximumRedeliveries": 1},
                "steps": [{"throwException": {"exceptionType": "outcome.not-found"}}]
            }}),
            json!({"onException": {
                "exception": ["upstream.http"],
                "onWhen": {"constant": true},
                "steps": [{"throwException": {
                    "exceptionType": "outcome.not-found",
                    "data": {"constant": {"field": "private"}}
                }}]
            }}),
            json!({"onException": {
                "exception": ["upstream.http"],
                "onWhen": {"constant": true},
                "steps": [{"throwException": {"exceptionType": "upstream.http"}}]
            }}),
            json!({"onException": {
                "exception": ["upstream.http"],
                "onWhen": {"constant": true},
                "steps": [
                    {"setBody": {"constant": {}}},
                    {"throwException": {"exceptionType": "outcome.not-found"}}
                ]
            }}),
        ] {
            assert!(one(refused).is_err());
        }
    }

    #[test]
    fn source_native_terminal_rejections_require_exchange_scoped_completion() {
        let mut completion_eager = vec![terminal_rejection("outcome.rejected")];
        completion_eager.push(step(json!({
            "idempotentConsumer": {
                "expression": {"header": "Idempotency-Key"},
                "completionEager": true,
                "steps": [post()]
            }
        })));
        assert!(compile_source_native_single_resume_operation(
            &completion_eager,
            &pack(true, false)
        )
        .is_err());

        let without_terminal_clause = vec![step(json!({
            "idempotentConsumer": {
                "expression": {"header": "Idempotency-Key"},
                "completionEager": true,
                "steps": [post()]
            }
        }))];
        compile_source_native_single_resume_operation(&without_terminal_clause, &pack(true, false))
            .expect("ordinary native completion semantics remain unchanged");
    }

    #[test]
    fn source_native_terminal_rejections_never_infer_transport_or_server_failures() {
        let mut steps = vec![terminal_rejection("outcome.invalid-request")];
        steps.extend(outer(vec![post()]));
        let operation = compile_source_native_single_resume_operation(&steps, &pack(true, false))
            .expect("the bounded rejection clause compiles");

        assert!(!operation.is_definitive_source_rejection(
            None,
            registry_adapter_core::ErrorClass::OutcomeInvalidRequest
        ));
        assert!(!operation.is_definitive_source_rejection(
            Some(503),
            registry_adapter_core::ErrorClass::OutcomeInvalidRequest
        ));
        assert!(!operation.is_definitive_source_rejection(
            Some(422),
            registry_adapter_core::ErrorClass::OutcomeNotFound
        ));
        assert!(!operation.is_definitive_source_rejection(
            Some(422),
            registry_adapter_core::ErrorClass::UpstreamHttp
        ));
    }
}

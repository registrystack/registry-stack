// SPDX-License-Identifier: Apache-2.0

//! Closed linear multi-effect write resume.
//!
//! The authored wire remains `resumeBindings` on `to` steps. Compilation
//! admits only the core-checked flat HTTP form and turns each binding into a
//! bounded singular selector. Runtime extraction returns source identifiers
//! only, never a response body or an arbitrary JSON value.

use std::collections::BTreeMap;

use registry_adapter_core::{
    is_non_safe_upstream, send_claims_idempotent, AdapterPack, ResumeBinding, SendComponent, Step,
};
use serde_json::Value;

use crate::language::{compile_selector, JsonPathResult, JsonPathSelector};
use crate::route::RouteFailure;

pub(crate) const MAXIMUM_RESUME_IDENTIFIER_BYTES: usize = 256;

#[doc(hidden)]
/// Compiled private resume plan retained on a served operation.
pub struct ServedResumeOperation {
    steps: Vec<ServedResumeStep>,
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
    Ok(Some(ServedResumeOperation { steps: compiled }))
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
    use registry_platform_yaml::LocalId;

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
        }
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
}

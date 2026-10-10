// SPDX-License-Identifier: Apache-2.0
//! Narrow typed decision protocols. Preparation is offline; dispatch has no retry.
//!
//! Wire contracts: https://api.typesafe.ai/openapi.json and
//! https://developers.openai.com/api/reference/typescript/resources/decisions/methods/create.
//! Model aliases and provider confidence are not immutable or interchangeable.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_platform_config::{SecretReference, SecretResolver};
use registry_platform_httputil::{
    client::BearerToken, read_bounded, FetchUrlError, FetchUrlPolicy, ServiceBaseUrl,
};
use registry_platform_yaml::{BoundedU64, ExternalId, LocalId};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use url::{Host, Url};

use crate::{protocol::CallOutcome, CoordinatorError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum DecisionProtocol {
    SystemOne,
    OpenaiDecisions,
}

/// Explicit service identity. Local authorization is limited to numeric loopback.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum DecisionAuthorization {
    Bearer {
        #[serde(rename = "tokenRef")]
        token_ref: SecretReference,
        principal: ExternalId,
    },
    Local {},
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionConfig {
    pub protocol: DecisionProtocol,
    #[serde(deserialize_with = "endpoint")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    #[cfg_attr(feature = "schema", schemars(extend("pattern" = "^[^\\s\\\\]+$")))]
    pub base_url: Url,
    pub model: ExternalId,
    pub authorization: DecisionAuthorization,
    #[serde(default = "default_timeout")]
    pub attempt_timeout_milliseconds: BoundedU64<1, 8000>,
    #[serde(default = "default_bytes")]
    pub maximum_request_bytes: BoundedU64<1, 65536>,
    #[serde(default = "default_bytes")]
    pub maximum_response_bytes: BoundedU64<1, 65536>,
}

fn endpoint<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Url, D::Error> {
    let written = registry_platform_yaml::Url::deserialize(d)?;
    if written.as_str().contains('\\') || written.as_str().chars().any(char::is_whitespace) {
        return Err(serde::de::Error::custom(
            "use an absolute service URL without whitespace or backslashes",
        ));
    }
    written.as_str().parse().map_err(serde::de::Error::custom)
}

fn default_timeout() -> BoundedU64<1, 8000> {
    BoundedU64::new(8000).expect("bounded default")
}

fn default_bytes() -> BoundedU64<1, 65536> {
    BoundedU64::new(65536).expect("bounded default")
}

impl DecisionConfig {
    pub fn token_ref(&self) -> Option<&SecretReference> {
        match &self.authorization {
            DecisionAuthorization::Bearer { token_ref, .. } => Some(token_ref),
            DecisionAuthorization::Local {} => None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.findings("").into_iter().next().map_or(Ok(()), Err)
    }

    pub fn findings(&self, prefix: &str) -> Vec<CoordinatorError> {
        let loopback = match self.base_url.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        let mut errors = Vec::new();
        let mut refuse = |field: &str, repair: &str| {
            let field = if prefix.is_empty() {
                field.to_owned()
            } else {
                format!("{prefix}.{field}")
            };
            errors.push(
                CoordinatorError::new(
                    "coordinator.decision.configuration",
                    "the configured decision service was refused",
                )
                .at("runtime.yaml", field)
                .suggest(repair),
            );
        };
        if ServiceBaseUrl::new(self.base_url.clone()).is_err()
            || !matches!(self.base_url.scheme(), "https" | "http")
            || (self.base_url.scheme() == "http" && !loopback)
        {
            refuse("baseUrl", "Use HTTPS or explicit numeric loopback HTTP, without credentials, query, fragment or empty interior path segments.");
        }
        if matches!(self.authorization, DecisionAuthorization::Local {}) && !loopback {
            refuse("baseUrl", "Use local authorization only for an explicit numeric loopback destination; otherwise configure a bearer service identity.");
        }
        if self.model.as_str().trim().is_empty() {
            refuse("model", "Specify the provider's model name or alias.");
        }
        if matches!(&self.authorization, DecisionAuthorization::Bearer { principal, .. } if principal.as_str().trim().is_empty())
        {
            refuse(
                "authorization.bearer.principal",
                "Specify the stable service principal represented by the referenced credential.",
            );
        }
        errors
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evaluation {
    state: Value,
    questions: BTreeMap<LocalId, Question>,
}

/// Authored questions are distinct from each provider's external DTO spelling.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum Question {
    Predicate {
        instructions: String,
    },
    Choice {
        instructions: String,
        criteria: BTreeMap<LocalId, String>,
    },
    Score {
        instructions: String,
        criteria: Vec<String>,
    },
}

impl Evaluation {
    fn parse(input: &Value) -> std::result::Result<Self, CallOutcome> {
        let evaluation: Self = serde_json::from_value(input.clone())
            .map_err(|_| refused("decision-invalid-command"))?;
        if !matches!(
            evaluation.state,
            Value::Object(_) | Value::String(_) | Value::Array(_)
        ) || evaluation.questions.is_empty()
            || evaluation.questions.len() > 32
            || evaluation
                .questions
                .values()
                .any(|question| match question {
                    Question::Predicate { instructions } => instructions.trim().is_empty(),
                    Question::Choice {
                        instructions,
                        criteria,
                    } => {
                        instructions.trim().is_empty()
                            || criteria.len() < 2
                            || criteria.len() > 32
                            || criteria.values().any(|text| text.trim().is_empty())
                    }
                    Question::Score {
                        instructions,
                        criteria,
                    } => {
                        instructions.trim().is_empty()
                            || criteria.len() < 2
                            || criteria.len() > 10
                            || criteria.iter().any(|text| text.trim().is_empty())
                    }
                })
        {
            return Err(refused("decision-invalid-command"));
        }
        Ok(evaluation)
    }
}

pub struct DecisionConnection {
    config: DecisionConfig,
    endpoint: Url,
    secrets: Arc<SecretResolver>,
}

impl DecisionConnection {
    pub fn new(config: &DecisionConfig, secrets: Arc<SecretResolver>) -> Result<Self> {
        config.validate()?;
        let path = match config.protocol {
            DecisionProtocol::SystemOne => "v1/systemone",
            DecisionProtocol::OpenaiDecisions => "v1/decisions",
        };
        let base = ServiceBaseUrl::new(config.base_url.clone()).map_err(|_| {
            CoordinatorError::new(
                "coordinator.decision.configuration",
                "invalid decision service URL",
            )
        })?;
        let endpoint = base.join(path).map_err(|_| {
            CoordinatorError::new(
                "coordinator.decision.configuration",
                "invalid decision service URL",
            )
        })?;
        Ok(Self {
            config: config.clone(),
            endpoint,
            secrets,
        })
    }

    /// Exact inert wire body, without secrets, network access or idempotency claims.
    pub fn prepare(&self, input: &Value) -> std::result::Result<Vec<u8>, CallOutcome> {
        let evaluation = Evaluation::parse(input)?;
        let body = match self.config.protocol {
            DecisionProtocol::SystemOne => {
                let questions: BTreeMap<_, _> = evaluation.questions.iter().map(|(name, question)| {
                    let value = match question {
                        Question::Predicate { instructions } => json!({"type":"noul","instructions":instructions}),
                        Question::Choice { instructions, criteria } => json!({"type":"choice","instructions":instructions,"criteria":criteria}),
                        Question::Score { instructions, criteria } => json!({"type":"score","instructions":instructions,"criteria":criteria}),
                    };
                    (name, value)
                }).collect();
                json!({"model":self.config.model,"state":evaluation.state,"questions":questions})
            }
            DecisionProtocol::OpenaiDecisions => {
                let state = match &evaluation.state {
                    Value::String(text) => text.clone(),
                    state => String::from_utf8(
                        canonicalize_json(state)
                            .map_err(|_| refused("decision-invalid-command"))?,
                    )
                    .map_err(|_| refused("decision-invalid-command"))?,
                };
                let questions: Vec<_> = evaluation.questions.iter().map(|(name, question)| match question {
                    Question::Predicate { instructions } => json!({"name":name,"type":"predicate","instructions":instructions}),
                    Question::Choice { instructions, criteria } => {
                        let choices: Vec<_> = criteria.iter().map(|(value, description)| json!({"value":value,"description":description})).collect();
                        json!({"name":name,"type":"choice","instructions":instructions,"choices":choices})
                    }
                    Question::Score { instructions, criteria } => {
                        let levels: Vec<_> = criteria.iter().map(|label| json!({"label":label})).collect();
                        json!({"name":name,"type":"score","instructions":instructions,"levels":levels})
                    }
                }).collect();
                json!({"model":self.config.model,"input":state,"questions":questions})
            }
        };
        let bytes = canonicalize_json(&body).map_err(|_| refused("decision-invalid-command"))?;
        if bytes.len() as u64 > self.config.maximum_request_bytes.get() {
            return Err(refused("decision-invalid-command"));
        }
        Ok(bytes)
    }

    /// The caller must durably hold after dispatch. This method never retries or
    /// looks up an original result; these profiles establish no replay or lookup contract.
    pub async fn call_prepared(&self, input: &Value, prepared: &[u8]) -> CallOutcome {
        if !self
            .prepare(input)
            .is_ok_and(|expected| expected == prepared)
        {
            return refused("decision-invalid-command");
        }
        let timeout = Duration::from_millis(self.config.attempt_timeout_milliseconds.get());
        let deadline = tokio::time::Instant::now() + timeout;
        let request = match tokio::time::timeout_at(deadline, self.request(timeout)).await {
            Ok(Ok(request)) => request,
            Ok(Err(outcome)) => return outcome,
            Err(_) => return unavailable(), // No request has been sent.
        };
        match tokio::time::timeout_at(
            deadline,
            self.dispatch(request.body(prepared.to_vec()), input),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => uncertain("decision-uncertain"),
        }
    }

    async fn request(
        &self,
        timeout: Duration,
    ) -> std::result::Result<reqwest::RequestBuilder, CallOutcome> {
        let policy = if self.endpoint.scheme() == "http" {
            FetchUrlPolicy::dev()
        } else {
            FetchUrlPolicy {
                allowed_schemes: vec!["https".into()],
                allow_localhost: true,
                allow_http_private_network: false,
                deny_private_ranges: false,
                deny_cloud_metadata: true,
            }
        };
        let validated = policy
            .validate_dns_pinned_for_immediate_fetch_with_timeout(&self.endpoint, timeout)
            .await
            .map_err(|error| match error {
                FetchUrlError::Dns { .. }
                | FetchUrlError::NoAddresses
                | FetchUrlError::ValidationTimeout { .. }
                | FetchUrlError::ValidationTask(_) => unavailable(),
                _ => refused("decision-invalid-command"),
            })?;
        let mut request = validated
            .immediate_post_with_timeout(timeout)
            .map_err(|_| refused("decision-invalid-command"))?
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(reference) = self.config.token_ref() {
            let secrets = self.secrets.clone();
            let reference = reference.clone();
            let token = tokio::task::spawn_blocking(move || {
                let secret = secrets.resolve_reference(&reference).map_err(|_| ())?;
                let text = std::str::from_utf8(secret.expose_secret()).map_err(|_| ())?;
                BearerToken::new(text.to_owned()).map_err(|_| ())
            })
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
            request = request.header(
                reqwest::header::AUTHORIZATION,
                token.authorization_header_value(),
            );
        }
        Ok(request)
    }

    async fn dispatch(&self, request: reqwest::RequestBuilder, input: &Value) -> CallOutcome {
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) if error.is_connect() => return unavailable(),
            Err(_) => return uncertain("decision-uncertain"),
        };
        let status = response.status().as_u16();
        if matches!(status, 400 | 401 | 403 | 404 | 405 | 413 | 415 | 422) {
            return refused("decision-refused");
        }
        if !(200..300).contains(&status) {
            // These profiles conservatively hold after dispatch, including
            // rate-limit replies. Retry-After does not add a replay contract.
            return uncertain("decision-uncertain");
        }
        // Same closed media forms as Platform destination responses. That
        // helper is private to its bounded destination wrapper, not reqwest.
        if !json_content_type(response.headers()) {
            return uncertain("decision-invalid-response");
        }
        let bytes = match read_bounded(response, self.config.maximum_response_bytes.get()).await {
            Ok(bytes) => bytes,
            Err(_) => return uncertain("decision-invalid-response"),
        };
        let result = parse_json_strict(&bytes).ok().and_then(|value| {
            let evaluation = Evaluation::parse(input).ok()?;
            normalize(
                self.config.protocol,
                self.config.model.as_str(),
                &evaluation,
                value,
            )
        });
        match result {
            Some(result) => CallOutcome::Success(result),
            None => uncertain("decision-invalid-response"),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum SystemAnswer {
    Noul {
        noul: f64,
    },
    Choice {
        choice: String,
        confidence: f64,
        probabilities: BTreeMap<String, f64>,
    },
    Score {
        score: f64,
        confidence: f64,
        legend: BTreeMap<String, String>,
        probabilities: BTreeMap<String, f64>,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum OpenaiAnswer {
    Predicate {
        name: String,
        probability: f64,
    },
    Choice {
        name: String,
        choice: String,
        confidence: f64,
        probabilities: Vec<ChoiceProbability>,
    },
    Score {
        name: String,
        score: f64,
        confidence: f64,
        probabilities: Vec<ScoreProbability>,
    },
    Refusal {
        name: String,
    },
}

#[derive(Deserialize)]
struct ChoiceProbability {
    value: String,
    probability: f64,
}
#[derive(Deserialize)]
struct ScoreProbability {
    value: usize,
    label: String,
    probability: f64,
}

fn probability(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

fn json_content_type(headers: &reqwest::header::HeaderMap) -> bool {
    let mut values = headers.get_all(reqwest::header::CONTENT_TYPE).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let mut parts = value.split(';');
    if !parts
        .next()
        .is_some_and(|part| part.trim().eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    let Some(parameter) = parts.next() else {
        return true;
    };
    if parts.next().is_some() {
        return false;
    }
    parameter.split_once('=').is_some_and(|(name, value)| {
        name.trim().eq_ignore_ascii_case("charset") && value.trim().eq_ignore_ascii_case("utf-8")
    })
}

fn distribution(probabilities: &BTreeMap<String, f64>) -> bool {
    // Both protocols document approximately unit mass. Allow decimal rounding,
    // while preserving the original numbers rather than renormalizing them.
    probabilities.values().all(|value| probability(*value))
        && (probabilities.values().sum::<f64>() - 1.0).abs() <= 0.001
}

fn choice_result(
    choice: String,
    confidence: f64,
    probabilities: BTreeMap<String, f64>,
    criteria: &BTreeMap<LocalId, String>,
) -> Option<Value> {
    if !probability(confidence)
        || !distribution(&probabilities)
        || !criteria
            .keys()
            .map(LocalId::as_str)
            .eq(probabilities.keys().map(String::as_str))
        || !probabilities.contains_key(&choice)
        || probabilities
            .values()
            .any(|value| *value > probabilities[&choice] + 0.001)
    {
        return None;
    }
    Some(
        json!({"type":"choice","choice":choice,"probabilities":probabilities,"nativeConfidence":confidence}),
    )
}

fn score_result(
    score: f64,
    confidence: f64,
    legend: BTreeMap<String, String>,
    probabilities: BTreeMap<String, f64>,
    criteria: &[String],
) -> Option<Value> {
    let expected: BTreeMap<_, _> = criteria
        .iter()
        .enumerate()
        .map(|(index, label)| (index.to_string(), label.clone()))
        .collect();
    if !score.is_finite()
        || !(0.0..=(criteria.len() - 1) as f64).contains(&score)
        || !probability(confidence)
        || !distribution(&probabilities)
        || legend != expected
        || !legend.keys().eq(probabilities.keys())
    {
        return None;
    }
    let mean: f64 = criteria
        .iter()
        .enumerate()
        .map(|(index, _)| index as f64 * probabilities[&index.to_string()])
        .sum();
    if (score - mean).abs() > 0.001 * criteria.len() as f64 {
        return None;
    }
    Some(
        json!({"type":"score","score":score,"legend":legend,"probabilities":probabilities,"nativeConfidence":confidence}),
    )
}

fn normalize(
    protocol: DecisionProtocol,
    model: &str,
    evaluation: &Evaluation,
    response: Value,
) -> Option<Value> {
    let returned_model = response.get("model")?.as_str()?;
    if returned_model.trim().is_empty() || ExternalId::new(returned_model).is_err() {
        return None;
    }
    // Usage remains provider metadata, not an invented common cost or token
    // contract. OpenAI documents these counters as required members of Usage.
    let usage = response.get("usage")?;
    if !usage.is_object()
        || match protocol {
            DecisionProtocol::SystemOne => ["input_tokens", "output_tokens"]
                .iter()
                .any(|key| usage.get(key).is_some_and(|value| value.as_u64().is_none())),
            DecisionProtocol::OpenaiDecisions => [
                "/input_tokens",
                "/input_tokens_details/cache_write_tokens",
                "/input_tokens_details/cached_tokens",
                "/output_tokens",
                "/output_tokens_details/reasoning_tokens",
                "/total_tokens",
            ]
            .iter()
            .any(|path| usage.pointer(path).and_then(Value::as_u64).is_none()),
        }
    {
        return None;
    }
    let mut answers = BTreeMap::new();
    match protocol {
        DecisionProtocol::SystemOne => {
            let received: BTreeMap<String, SystemAnswer> =
                serde_json::from_value(response.get("answers")?.clone()).ok()?;
            if !evaluation
                .questions
                .keys()
                .map(LocalId::as_str)
                .eq(received.keys().map(String::as_str))
            {
                return None;
            }
            for (name, answer) in received {
                let question = evaluation
                    .questions
                    .get(&LocalId::new(name.clone()).ok()?)?;
                let answer = match (question, answer) {
                    (Question::Predicate { .. }, SystemAnswer::Noul { noul })
                        if probability(noul) =>
                    {
                        json!({"type":"predicate","probability":noul})
                    }
                    (
                        Question::Choice { criteria, .. },
                        SystemAnswer::Choice {
                            choice,
                            confidence,
                            probabilities,
                        },
                    ) => choice_result(choice, confidence, probabilities, criteria)?,
                    (
                        Question::Score { criteria, .. },
                        SystemAnswer::Score {
                            score,
                            confidence,
                            legend,
                            probabilities,
                        },
                    ) => score_result(score, confidence, legend, probabilities, criteria)?,
                    _ => return None,
                };
                answers.insert(name, answer);
            }
        }
        DecisionProtocol::OpenaiDecisions => {
            let received: Vec<OpenaiAnswer> =
                serde_json::from_value(response.get("answers")?.clone()).ok()?;
            if received.len() != evaluation.questions.len() {
                return None;
            }
            for answer in received {
                let name = match &answer {
                    OpenaiAnswer::Predicate { name, .. }
                    | OpenaiAnswer::Choice { name, .. }
                    | OpenaiAnswer::Score { name, .. }
                    | OpenaiAnswer::Refusal { name } => name.clone(),
                };
                let question = evaluation
                    .questions
                    .get(&LocalId::new(name.clone()).ok()?)?;
                let result = match (question, answer) {
                    (_, OpenaiAnswer::Refusal { .. }) => json!({"type":"refusal"}),
                    (
                        Question::Predicate { .. },
                        OpenaiAnswer::Predicate {
                            probability: value, ..
                        },
                    ) if probability(value) => json!({"type":"predicate","probability":value}),
                    (
                        Question::Choice { criteria, .. },
                        OpenaiAnswer::Choice {
                            choice,
                            confidence,
                            probabilities,
                            ..
                        },
                    ) => {
                        let mut distribution = BTreeMap::new();
                        for item in probabilities {
                            if distribution.insert(item.value, item.probability).is_some() {
                                return None;
                            }
                        }
                        choice_result(choice, confidence, distribution, criteria)?
                    }
                    (
                        Question::Score { criteria, .. },
                        OpenaiAnswer::Score {
                            score,
                            confidence,
                            probabilities,
                            ..
                        },
                    ) => {
                        let mut distribution = BTreeMap::new();
                        let mut legend = BTreeMap::new();
                        for item in probabilities {
                            let index = item.value.to_string();
                            if distribution
                                .insert(index.clone(), item.probability)
                                .is_some()
                            {
                                return None;
                            }
                            legend.insert(index, item.label);
                        }
                        score_result(score, confidence, legend, distribution, criteria)?
                    }
                    _ => return None,
                };
                if answers.insert(name, result).is_some() {
                    return None;
                }
            }
        }
    }
    Some(
        json!({"protocol":protocol,"requestedModel":model,"returnedModel":returned_model,"answers":answers,"usage":usage}),
    )
}

fn refused(code: &str) -> CallOutcome {
    CallOutcome::Refused { code: code.into() }
}
fn uncertain(code: &str) -> CallOutcome {
    CallOutcome::Uncertain { code: code.into() }
}
fn unavailable() -> CallOutcome {
    CallOutcome::Retryable {
        code: "decision-unavailable".into(),
    }
}

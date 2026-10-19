// SPDX-License-Identifier: Apache-2.0

//! The one mapping from registry outcomes to stable tool error codes.
//!
//! A chat host sees a closed code and a fixed, neutral sentence. It never sees
//! a registry problem document, a field value, or a credential failure detail,
//! and the same code covers a record that does not exist and one the citizen
//! may not see.

use registry_breg_client::{
    BRegActionError, BRegMetadataSelectionError, BRegMutationRequestError, BRegProblemCode,
    BRegRequestError, BaseRegistryClientError, TokenError,
};
use rmcp::model::CallToolResult;
use serde_json::{json, Value};

use crate::{contract::ContractError, idempotency::IdempotencyError, tools::ArgumentError};

/// A stable tool error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolErrorCode {
    InvalidArguments,
    RecordNotResolved,
    NotFound,
    ApplicationNotEditable,
    StaleApplication,
    ChangeRefused,
    IdempotencyConflict,
    NotPermitted,
    AuthorizationFailed,
    AuthorizationRefused,
    RegistryUnavailable,
    ServiceUnavailable,
    UnexpectedResponse,
}

impl ToolErrorCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid-arguments",
            Self::RecordNotResolved => "record-not-resolved",
            Self::NotFound => "not-found",
            Self::ApplicationNotEditable => "application-not-editable",
            Self::StaleApplication => "stale-application",
            Self::ChangeRefused => "change-refused",
            Self::IdempotencyConflict => "idempotency-conflict",
            Self::NotPermitted => "not-permitted",
            Self::AuthorizationFailed => "authorization-failed",
            Self::AuthorizationRefused => "authorization-refused",
            Self::RegistryUnavailable => "registry-unavailable",
            Self::ServiceUnavailable => "service-unavailable",
            Self::UnexpectedResponse => "unexpected-response",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidArguments => "The arguments do not match what this tool accepts.",
            Self::RecordNotResolved => {
                "The registry could not identify exactly one record for you, so nothing was created."
            }
            Self::NotFound => "No application with that identifier is available to you.",
            Self::ApplicationNotEditable => "The application can no longer be changed here.",
            Self::StaleApplication => {
                "The application or its action definition has changed. \
                 Review the current application before trying again."
            }
            Self::ChangeRefused => {
                "The registry refused this change because a required condition was not met. \
                 Review the request and any existing application; try again only after \
                 correcting the request or permissions."
            }
            Self::IdempotencyConflict => {
                "An earlier identical request is still being processed or differed. Try again."
            }
            Self::NotPermitted => "The registry does not permit this action.",
            Self::AuthorizationFailed => {
                "The registry did not accept the delegated authorization. Sign in again."
            }
            Self::AuthorizationRefused => {
                "Delegated access was refused. Check whether this service is permitted \
                 to act for you before trying again."
            }
            Self::RegistryUnavailable => {
                "The registry or its authorization service is temporarily unavailable. Try again later."
            }
            Self::ServiceUnavailable => "This service is not available right now.",
            Self::UnexpectedResponse => "The registry returned a response this service cannot use.",
        }
    }
}

/// A tool failure: a closed code and, when the registry supplied one, its
/// trace identifier for support.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ToolError {
    pub(crate) code: ToolErrorCode,
    pub(crate) trace_id: Option<String>,
    /// Whether a mutating registry request was sent and its effect is not
    /// known, so the call is audited `unfinished` rather than `refused`.
    pub(crate) effect_unknown: bool,
}

impl ToolError {
    pub(crate) const fn new(code: ToolErrorCode) -> Self {
        Self {
            code,
            trace_id: None,
            effect_unknown: false,
        }
    }

    /// This failure answers a mutating registry request that was sent. A
    /// transport, server, or protocol failure leaves its effect unknown; a
    /// registry refusal is definite.
    pub(crate) const fn after_mutation(mut self) -> Self {
        self.effect_unknown = matches!(
            self.code,
            ToolErrorCode::RegistryUnavailable
                | ToolErrorCode::ServiceUnavailable
                | ToolErrorCode::UnexpectedResponse
        );
        self
    }

    pub(crate) fn into_result(self) -> CallToolResult {
        CallToolResult::structured_error(self.to_value())
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut error = json!({
            "code": self.code.as_str(),
            "message": self.code.message(),
        });
        if let Some(trace_id) = &self.trace_id {
            error["traceId"] = Value::String(trace_id.clone());
        }
        json!({ "error": error })
    }
}

impl From<ArgumentError> for ToolError {
    fn from(_: ArgumentError) -> Self {
        Self::new(ToolErrorCode::InvalidArguments)
    }
}

impl From<ContractError> for ToolError {
    fn from(_: ContractError) -> Self {
        Self::new(ToolErrorCode::ServiceUnavailable)
    }
}

impl From<BRegMetadataSelectionError> for ToolError {
    fn from(_: BRegMetadataSelectionError) -> Self {
        Self::new(ToolErrorCode::ServiceUnavailable)
    }
}

impl From<BRegMutationRequestError> for ToolError {
    fn from(_: BRegMutationRequestError) -> Self {
        Self::new(ToolErrorCode::InvalidArguments)
    }
}

impl From<TokenError> for ToolError {
    fn from(error: TokenError) -> Self {
        Self::new(token_code(&error))
    }
}

impl From<IdempotencyError> for ToolError {
    fn from(_: IdempotencyError) -> Self {
        Self::new(ToolErrorCode::ServiceUnavailable)
    }
}

impl From<BaseRegistryClientError> for ToolError {
    fn from(error: BaseRegistryClientError) -> Self {
        match error {
            BaseRegistryClientError::Problem { code, trace_id, .. } => Self {
                code: problem_code(&code),
                trace_id: Some(trace_id.as_str().to_owned()),
                effect_unknown: false,
            },
            BaseRegistryClientError::InvalidRequest { .. } => {
                Self::new(ToolErrorCode::InvalidArguments)
            }
            BaseRegistryClientError::Token(error) => Self::new(token_code(&error)),
            BaseRegistryClientError::Transport { .. } => {
                Self::new(ToolErrorCode::RegistryUnavailable)
            }
            BaseRegistryClientError::Protocol { trace_id, .. } => Self {
                code: ToolErrorCode::UnexpectedResponse,
                trace_id: trace_id.map(|trace_id| trace_id.as_str().to_owned()),
                effect_unknown: false,
            },
            // A client that cannot be used as configured, or a variant a later
            // client version adds, is a fault of this service.
            _ => Self::new(ToolErrorCode::UnexpectedResponse),
        }
    }
}

fn problem_code(code: &BRegProblemCode) -> ToolErrorCode {
    match code {
        BRegProblemCode::IdempotencyConflict => ToolErrorCode::IdempotencyConflict,
        // These value-free refusals do not establish a stale revision or a
        // withdrawn grant. Only a local revision comparison can name staleness.
        // A failed Action guard is a current business-state refusal of the
        // change, not a stale input.
        BRegProblemCode::IdempotencyExpired
        | BRegProblemCode::ActionGuardFailed
        | BRegProblemCode::PreconditionFailed
        | BRegProblemCode::PreconditionRequired
        | BRegProblemCode::MutationConflict => ToolErrorCode::ChangeRefused,
        BRegProblemCode::ResourceNotFound | BRegProblemCode::LookupUnresolved => {
            ToolErrorCode::NotFound
        }
        BRegProblemCode::AuthenticationRefused => ToolErrorCode::AuthorizationFailed,
        BRegProblemCode::RequestInvalid
        | BRegProblemCode::QueryInvalid
        | BRegProblemCode::QueryCursorInvalid
        | BRegProblemCode::UnsupportedMediaType => ToolErrorCode::InvalidArguments,
        BRegProblemCode::RuntimeNotReady
        | BRegProblemCode::ServiceUnavailable
        | BRegProblemCode::SourceUnavailable
        | BRegProblemCode::RequestTimeout
        | BRegProblemCode::RuntimeFieldEncryptionUnavailable => ToolErrorCode::RegistryUnavailable,
        BRegProblemCode::ActionEvidenceFailed
        | BRegProblemCode::ActionHandlerFailed
        | BRegProblemCode::ActionRefused => ToolErrorCode::NotPermitted,
        // Ingestion problems cannot answer an operation this gateway sends,
        // and a code a later client version adds is not one this gateway knows.
        _ => ToolErrorCode::UnexpectedResponse,
    }
}

fn token_code(error: &TokenError) -> ToolErrorCode {
    match error {
        TokenError::Refused { .. } | TokenError::ScopeNarrowed => {
            ToolErrorCode::AuthorizationRefused
        }
        TokenError::Invalid { .. } | TokenError::Unavailable => ToolErrorCode::AuthorizationFailed,
        TokenError::Transport { .. } | TokenError::Protocol { .. } => {
            ToolErrorCode::RegistryUnavailable
        }
        _ => ToolErrorCode::UnexpectedResponse,
    }
}

impl From<BRegActionError> for ToolError {
    fn from(_: BRegActionError) -> Self {
        Self::new(ToolErrorCode::InvalidArguments)
    }
}

impl From<BRegRequestError> for ToolError {
    fn from(_: BRegRequestError) -> Self {
        Self::new(ToolErrorCode::InvalidArguments)
    }
}

#[cfg(test)]
mod tests {
    use registry_platform_httpsec::TraceId;

    use super::*;

    const TRACE: &str = "01a0d392774c6106ab6716c4bd9a93ed";

    fn problem(code: BRegProblemCode) -> ToolError {
        ToolError::from(BaseRegistryClientError::Problem {
            status: 400,
            code,
            trace_id: TraceId::parse(TRACE).expect("trace id"),
            field_path: None,
            constraint: None,
            refusal_code: None,
        })
    }

    #[test]
    fn every_tool_code_is_kebab_case() {
        let codes = [
            ToolErrorCode::InvalidArguments,
            ToolErrorCode::RecordNotResolved,
            ToolErrorCode::NotFound,
            ToolErrorCode::ApplicationNotEditable,
            ToolErrorCode::StaleApplication,
            ToolErrorCode::ChangeRefused,
            ToolErrorCode::IdempotencyConflict,
            ToolErrorCode::NotPermitted,
            ToolErrorCode::AuthorizationFailed,
            ToolErrorCode::AuthorizationRefused,
            ToolErrorCode::RegistryUnavailable,
            ToolErrorCode::ServiceUnavailable,
            ToolErrorCode::UnexpectedResponse,
        ]
        .map(ToolErrorCode::as_str);
        assert_eq!(
            codes,
            [
                "invalid-arguments",
                "record-not-resolved",
                "not-found",
                "application-not-editable",
                "stale-application",
                "change-refused",
                "idempotency-conflict",
                "not-permitted",
                "authorization-failed",
                "authorization-refused",
                "registry-unavailable",
                "service-unavailable",
                "unexpected-response",
            ]
        );
    }

    #[test]
    fn every_registry_problem_has_one_stable_tool_code() {
        let expected = [
            (BRegProblemCode::IdempotencyConflict, "idempotency-conflict"),
            (BRegProblemCode::IdempotencyExpired, "change-refused"),
            (BRegProblemCode::PreconditionFailed, "change-refused"),
            (BRegProblemCode::PreconditionRequired, "change-refused"),
            (BRegProblemCode::MutationConflict, "change-refused"),
            (BRegProblemCode::ActionGuardFailed, "change-refused"),
            (BRegProblemCode::ResourceNotFound, "not-found"),
            (BRegProblemCode::LookupUnresolved, "not-found"),
            (
                BRegProblemCode::AuthenticationRefused,
                "authorization-failed",
            ),
            (BRegProblemCode::RequestInvalid, "invalid-arguments"),
            (BRegProblemCode::QueryInvalid, "invalid-arguments"),
            (BRegProblemCode::QueryCursorInvalid, "invalid-arguments"),
            (BRegProblemCode::UnsupportedMediaType, "invalid-arguments"),
            (BRegProblemCode::RuntimeNotReady, "registry-unavailable"),
            (BRegProblemCode::ServiceUnavailable, "registry-unavailable"),
            (BRegProblemCode::SourceUnavailable, "registry-unavailable"),
            (BRegProblemCode::RequestTimeout, "registry-unavailable"),
            (
                BRegProblemCode::RuntimeFieldEncryptionUnavailable,
                "registry-unavailable",
            ),
            (BRegProblemCode::ActionEvidenceFailed, "not-permitted"),
            (BRegProblemCode::ActionHandlerFailed, "not-permitted"),
            (BRegProblemCode::ActionRefused, "not-permitted"),
            (BRegProblemCode::IngestionRunBlocked, "unexpected-response"),
        ];
        for (code, tool_code) in expected {
            let error = problem(code);
            assert_eq!(error.code.as_str(), tool_code, "{code:?}");
            assert_eq!(error.trace_id.as_deref(), Some(TRACE));
        }
    }

    #[test]
    fn a_tool_error_carries_only_a_code_a_fixed_message_and_a_trace() {
        let value = problem(BRegProblemCode::PreconditionFailed).to_value();
        let error = value["error"].as_object().expect("error object");
        assert_eq!(
            error.keys().map(String::as_str).collect::<Vec<_>>(),
            ["code", "message", "traceId"]
        );
        assert_eq!(error["code"], "change-refused");
    }

    #[test]
    fn explicit_exchange_refusals_do_not_prescribe_sign_in_or_disclose_provider_codes() {
        use registry_platform_httputil::client::OAuthErrorCode;

        for code in [
            OAuthErrorCode::InvalidRequest,
            OAuthErrorCode::InvalidClient,
            OAuthErrorCode::InvalidGrant,
            OAuthErrorCode::UnauthorizedClient,
            OAuthErrorCode::UnsupportedGrantType,
            OAuthErrorCode::InvalidScope,
            OAuthErrorCode::InvalidTarget,
            OAuthErrorCode::Other,
        ] {
            let error = ToolError::from(TokenError::Refused { code });
            assert_eq!(error.code.as_str(), "authorization-refused");
            assert_eq!(
                error.to_value(),
                json!({"error": {
                    "code": "authorization-refused",
                    "message": "Delegated access was refused. Check whether this service is permitted to act for you before trying again."
                }})
            );
            assert!(!error.effect_unknown);
            assert_eq!(
                ToolError::from(BaseRegistryClientError::Token(TokenError::Refused { code })),
                error
            );
        }
    }

    #[test]
    fn credential_and_exchange_failures_keep_bounded_distinct_recovery() {
        use registry_platform_httputil::client::TransportKind;

        for (token, expected) in [
            (TokenError::Unavailable, "authorization-failed"),
            (
                TokenError::Invalid {
                    reason: "canary-invalid-credential",
                },
                "authorization-failed",
            ),
            (TokenError::ScopeNarrowed, "authorization-refused"),
            (
                TokenError::Transport {
                    kind: TransportKind::Timeout,
                },
                "registry-unavailable",
            ),
            (TokenError::Protocol { status: 503 }, "registry-unavailable"),
            (
                TokenError::Configuration {
                    reason: "canary-provider-configuration",
                },
                "unexpected-response",
            ),
        ] {
            let error = ToolError::from(token);
            assert_eq!(error.code.as_str(), expected);
            assert_eq!(error.trace_id, None);
            assert!(!error.effect_unknown);
            let value = error.to_value();
            assert_eq!(value["error"].as_object().unwrap().len(), 2);
            assert!(!value.to_string().contains("canary"));
            assert_eq!(
                ToolError::from(BaseRegistryClientError::Token(token)),
                error
            );
        }
    }

    #[test]
    fn runtime_conditions_do_not_claim_a_stale_revision_or_withdrawn_authority() {
        let refused = problem(BRegProblemCode::PreconditionFailed);
        assert_eq!(refused.code.as_str(), "change-refused");
        assert_ne!(refused.code, ToolErrorCode::StaleApplication);
        assert_eq!(refused.to_value()["error"]["message"],
            "The registry refused this change because a required condition was not met. Review the request and any existing application; try again only after correcting the request or permissions.");
        assert!(!refused.after_mutation().effect_unknown);
        assert_eq!(
            problem(BRegProblemCode::ResourceNotFound).to_value(),
            problem(BRegProblemCode::LookupUnresolved).to_value()
        );
    }

    #[test]
    fn argument_and_contract_failures_map_to_their_codes() {
        assert_eq!(
            ToolError::from(ArgumentError::FieldNotEditable).code,
            ToolErrorCode::InvalidArguments
        );
        assert_eq!(
            ToolError::from(ContractError::DetailsListMissing).code,
            ToolErrorCode::ServiceUnavailable
        );
        assert_eq!(
            ToolError::from(BRegMutationRequestError::PatchRequiresMutation).code,
            ToolErrorCode::InvalidArguments
        );
    }
}

// SPDX-License-Identifier: Apache-2.0

//! The one mapping from registry outcomes to stable tool error codes.
//!
//! A chat host sees a closed code and a fixed, neutral sentence. It never sees
//! a registry problem document, a field value, or a credential failure detail,
//! and the same code covers a record that does not exist and one the citizen
//! may not see.

use registry_breg_client::{
    BRegLifecycleDecodeError, BRegMetadataSelectionError, BRegMutationRequestError,
    BRegProblemCode, BRegRequestError, BaseRegistryClientError, TokenError,
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
    IdempotencyConflict,
    NotPermitted,
    AuthorizationFailed,
    RegistryUnavailable,
    ServiceUnavailable,
    UnexpectedResponse,
}

impl ToolErrorCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid_arguments",
            Self::RecordNotResolved => "record_not_resolved",
            Self::NotFound => "not_found",
            Self::ApplicationNotEditable => "application_not_editable",
            Self::StaleApplication => "stale_application",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::NotPermitted => "not_permitted",
            Self::AuthorizationFailed => "authorization_failed",
            Self::RegistryUnavailable => "registry_unavailable",
            Self::ServiceUnavailable => "service_unavailable",
            Self::UnexpectedResponse => "unexpected_response",
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
                "The application changed since it was read. Read its status and try again."
            }
            Self::IdempotencyConflict => {
                "An earlier identical request is still being processed or differed. Try again."
            }
            Self::NotPermitted => "The registry does not permit this action.",
            Self::AuthorizationFailed => {
                "The registry did not accept the delegated authorization. Sign in again."
            }
            Self::RegistryUnavailable => "The registry is temporarily unavailable. Try again later.",
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
}

impl ToolError {
    pub(crate) const fn new(code: ToolErrorCode) -> Self {
        Self {
            code,
            trace_id: None,
        }
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

impl From<BRegRequestError> for ToolError {
    fn from(_: BRegRequestError) -> Self {
        Self::new(ToolErrorCode::ServiceUnavailable)
    }
}

impl From<BRegLifecycleDecodeError> for ToolError {
    fn from(_: BRegLifecycleDecodeError) -> Self {
        Self::new(ToolErrorCode::UnexpectedResponse)
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
        BRegProblemCode::PreconditionFailed
        | BRegProblemCode::PreconditionRequired
        | BRegProblemCode::MutationConflict => ToolErrorCode::StaleApplication,
        BRegProblemCode::ResourceNotFound | BRegProblemCode::LookupUnresolved => {
            ToolErrorCode::NotFound
        }
        BRegProblemCode::AuthenticationRefused => ToolErrorCode::AuthorizationFailed,
        BRegProblemCode::RequestInvalid
        | BRegProblemCode::QueryInvalid
        | BRegProblemCode::QueryCursorInvalid
        | BRegProblemCode::UnsupportedMediaType
        | BRegProblemCode::RequestPlanRefused(_) => ToolErrorCode::InvalidArguments,
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
        TokenError::Refused { .. }
        | TokenError::Invalid { .. }
        | TokenError::ScopeNarrowed
        | TokenError::Unavailable => ToolErrorCode::AuthorizationFailed,
        TokenError::Transport { .. } | TokenError::Protocol { .. } => {
            ToolErrorCode::RegistryUnavailable
        }
        _ => ToolErrorCode::UnexpectedResponse,
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
            refusal_code: None,
        })
    }

    #[test]
    fn every_registry_problem_has_one_stable_tool_code() {
        let expected = [
            (BRegProblemCode::IdempotencyConflict, "idempotency_conflict"),
            (BRegProblemCode::PreconditionFailed, "stale_application"),
            (BRegProblemCode::PreconditionRequired, "stale_application"),
            (BRegProblemCode::MutationConflict, "stale_application"),
            (BRegProblemCode::ResourceNotFound, "not_found"),
            (BRegProblemCode::LookupUnresolved, "not_found"),
            (
                BRegProblemCode::AuthenticationRefused,
                "authorization_failed",
            ),
            (BRegProblemCode::RequestInvalid, "invalid_arguments"),
            (BRegProblemCode::QueryInvalid, "invalid_arguments"),
            (BRegProblemCode::QueryCursorInvalid, "invalid_arguments"),
            (BRegProblemCode::UnsupportedMediaType, "invalid_arguments"),
            (BRegProblemCode::RuntimeNotReady, "registry_unavailable"),
            (BRegProblemCode::ServiceUnavailable, "registry_unavailable"),
            (BRegProblemCode::SourceUnavailable, "registry_unavailable"),
            (BRegProblemCode::RequestTimeout, "registry_unavailable"),
            (
                BRegProblemCode::RuntimeFieldEncryptionUnavailable,
                "registry_unavailable",
            ),
            (BRegProblemCode::ActionEvidenceFailed, "not_permitted"),
            (BRegProblemCode::ActionHandlerFailed, "not_permitted"),
            (BRegProblemCode::ActionRefused, "not_permitted"),
            (BRegProblemCode::IngestionRunBlocked, "unexpected_response"),
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
        assert_eq!(error["code"], "stale_application");
    }

    #[test]
    fn credential_failures_are_authorization_failures_without_detail() {
        let refused = ToolError::from(BaseRegistryClientError::Token(TokenError::ScopeNarrowed));
        assert_eq!(refused.code, ToolErrorCode::AuthorizationFailed);
        assert_eq!(refused.trace_id, None);
        let unavailable = ToolError::from(BaseRegistryClientError::Token(TokenError::Unavailable));
        assert_eq!(unavailable.code, ToolErrorCode::AuthorizationFailed);
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

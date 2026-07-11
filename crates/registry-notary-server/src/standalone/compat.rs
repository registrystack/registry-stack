//! Compatibility exports backed by neutral request-context and JSON-path modules.

pub(crate) use crate::json_path::get_json_path;
pub(crate) use crate::request_context::{
    current_request_correlation_id, new_request_correlation_id, with_request_correlation_id,
};

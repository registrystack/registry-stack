//! Compatibility exports backed by the neutral request-context module.

pub(crate) use crate::request_context::{
    current_request_correlation_id, new_request_correlation_id, with_request_correlation_id,
};

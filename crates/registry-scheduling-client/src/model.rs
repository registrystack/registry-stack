// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use registry_platform_httputil::client::BearerToken;
use serde::{Deserialize, Serialize};

/// Authentication for exactly one call: a borrowed bearer token, the only
/// credential Registry Scheduling accepts. Scheduling declares no profile
/// header, so there is nothing else to select.
///
/// The client borrows the token, attaches it to one request, and never
/// retains it in client state or a result.
pub struct SchedulingAuth<'a> {
    pub token: &'a BearerToken,
}

impl<'a> SchedulingAuth<'a> {
    #[must_use]
    pub fn new(token: &'a BearerToken) -> Self {
        Self { token }
    }
}

impl fmt::Debug for SchedulingAuth<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchedulingAuth")
            .field("token", &"<redacted>")
            .finish()
    }
}

/// One completed call: the response document and the response's validated
/// trace identifier, so a caller correlates the answer with its own
/// trace context without re-reading headers.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchedulingComplete<T> {
    pub value: T,
    pub trace_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_the_token() {
        let token = BearerToken::new("secret-token").expect("fixture token");
        let auth = SchedulingAuth::new(&token);
        let debug = format!("{auth:?}");
        assert!(!debug.contains("secret-token"));
    }
}

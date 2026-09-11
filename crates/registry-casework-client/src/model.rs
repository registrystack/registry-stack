use std::fmt;

use registry_platform_httputil::client::BearerToken;
use serde::{Deserialize, Serialize};

/// Authentication and explicit profile selection for exactly one call.
///
/// The client borrows the token, attaches it to one request, and never retains
/// it in client state or a recovery object.
pub struct CaseworkAuth<'a> {
    pub token: &'a BearerToken,
    pub profile: &'a str,
    pub source_profile: Option<&'a str>,
}

impl<'a> CaseworkAuth<'a> {
    #[must_use]
    pub fn new(token: &'a BearerToken, profile: &'a str) -> Self {
        Self {
            token,
            profile,
            source_profile: None,
        }
    }

    #[must_use]
    pub fn with_source_profile(mut self, source_profile: &'a str) -> Self {
        self.source_profile = Some(source_profile);
        self
    }
}

impl fmt::Debug for CaseworkAuth<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaseworkAuth")
            .field("token", &"<redacted>")
            .field("profile", &"<selected>")
            .field("source_profile", &self.source_profile.map(|_| "<selected>"))
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkComplete<T> {
    pub value: T,
    pub trace_id: String,
}

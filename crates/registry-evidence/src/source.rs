//! Evidence source access attribution and captured trust utilities.
//!
//! Provider execution is implemented by the shared Adapter engine and
//! Evidence's pack host. These helpers carry no independent source executor.

use crate::config::OutboundTlsConfig;
use base64::Engine as _;
use http::HeaderValue;
use std::collections::BTreeMap;
const MAXIMUM_ACCESS_ATTRIBUTION_BYTES: usize = 512;
const PRIVATE_CA_MAXIMUM_BYTES: u64 = 1024 * 1024;

/// Verified, authorized caller context that an explicitly opted-in HTTP source
/// receives for its own subject-facing access accounting.
///
/// Values are validated and encoded when an opted-in HTTP source builds its
/// headers, so arbitrary UTF-8 identities cannot become header syntax. The
/// type has no `Debug` implementation because it contains the requester's
/// direct identity.
pub(crate) struct SourceAccessAttribution {
    requester: String,
    purpose: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceAccessAttributionError {
    Invalid,
}

impl SourceAccessAttribution {
    pub(crate) fn new(requester: &str, purpose: &str) -> Self {
        Self {
            requester: requester.to_owned(),
            purpose: purpose.to_owned(),
        }
    }

    fn encoded(value: &str) -> Result<HeaderValue, SourceAccessAttributionError> {
        if value.trim().is_empty()
            || value.len() > MAXIMUM_ACCESS_ATTRIBUTION_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(SourceAccessAttributionError::Invalid);
        }
        let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes());
        HeaderValue::from_bytes(value.as_bytes()).map_err(|_| SourceAccessAttributionError::Invalid)
    }

    pub(crate) fn headers(
        &self,
    ) -> Result<(HeaderValue, HeaderValue), SourceAccessAttributionError> {
        Ok((
            Self::encoded(&self.requester)?,
            Self::encoded(&self.purpose)?,
        ))
    }
}

pub(crate) fn trust_profile_roots(
    profile_name: &str,
    tls: &OutboundTlsConfig,
    captured_ca_bundles: &BTreeMap<String, Vec<u8>>,
) -> Option<Vec<reqwest::Certificate>> {
    if !tls.system_roots {
        return None;
    }
    let binding = tls.trust_profiles.get(profile_name)?;
    if binding.ca_bundle_file.is_empty() {
        return None;
    }
    let pem = captured_ca_bundles.get(profile_name)?;
    if pem.is_empty() || pem.len() as u64 > PRIVATE_CA_MAXIMUM_BYTES {
        return None;
    }
    let certificates = reqwest::Certificate::from_pem_bundle(pem).ok()?;
    if certificates.is_empty() {
        return None;
    }
    Some(certificates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TrustProfileBinding;
    use serde_json::json;

    #[test]
    fn source_access_attribution_is_single_encoded_and_refuses_header_syntax() {
        let attribution = SourceAccessAttribution::new("requester@example.test", "eligibility");
        let (requester, purpose) = attribution.headers().unwrap();
        assert_eq!(
            requester.to_str().unwrap(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("requester@example.test")
        );
        assert_eq!(
            purpose.to_str().unwrap(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("eligibility")
        );

        for invalid in ["", " ", "line\nbreak"] {
            assert_eq!(
                SourceAccessAttribution::new(invalid, "purpose").headers(),
                Err(SourceAccessAttributionError::Invalid)
            );
        }
        let too_long = "x".repeat(MAXIMUM_ACCESS_ATTRIBUTION_BYTES + 1);
        assert_eq!(
            SourceAccessAttribution::new(&too_long, "purpose").headers(),
            Err(SourceAccessAttributionError::Invalid)
        );
    }

    #[test]
    fn captured_trust_roots_require_enabled_system_roots_and_exact_profile_bytes() {
        let enabled: OutboundTlsConfig = serde_json::from_value(json!({
            "systemRoots":true,
            "trustProfiles":{"private-ca":{"caBundleFile":"/etc/evidence/private-ca.pem"}}
        }))
        .unwrap();
        let disabled = OutboundTlsConfig {
            system_roots: false,
            trust_profiles: enabled.trust_profiles.clone(),
        };
        let missing = BTreeMap::new();
        let empty = BTreeMap::from([("private-ca".to_owned(), Vec::new())]);
        assert!(trust_profile_roots("private-ca", &enabled, &missing).is_none());
        assert!(trust_profile_roots("private-ca", &enabled, &empty).is_none());
        assert!(trust_profile_roots("private-ca", &disabled, &empty).is_none());

        let no_path = OutboundTlsConfig {
            system_roots: true,
            trust_profiles: serde_json::from_value(json!({
                "private-ca": TrustProfileBinding { ca_bundle_file: String::new() }
            }))
            .unwrap(),
        };
        assert!(trust_profile_roots("private-ca", &no_path, &empty).is_none());
    }
}

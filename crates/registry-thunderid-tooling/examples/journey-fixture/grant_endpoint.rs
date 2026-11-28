// SPDX-License-Identifier: Apache-2.0
use registry_thunderid_tooling::ToolingError;
use url::Url;

pub(super) fn refused(reason: &'static str) -> ToolingError {
    ToolingError::GrantAcquisition { reason }
}

pub(super) fn endpoint(address: &str) -> Result<Url, ToolingError> {
    let url = Url::parse(address).map_err(|_| refused("invalid numeric loopback HTTP endpoint"))?;
    let host = address
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .and_then(|authority| {
            authority
                .strip_prefix("127.0.0.1:")
                .or_else(|| authority.strip_prefix("[::1]:"))
        });
    if host.is_some_and(|port| {
        !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|port| port > 0)
    }) && url.query().is_none()
        && url.fragment().is_none()
        && !address.contains('\\')
        && !address.chars().any(char::is_whitespace)
    {
        Ok(url)
    } else {
        Err(refused(
            "use a numeric loopback HTTP endpoint with an explicit port",
        ))
    }
}

pub(super) fn validate(
    casework_url: &str,
    token_endpoint: &str,
    assertion_audience: &str,
    issuer: &str,
) -> Result<(), ToolingError> {
    endpoint(casework_url)
        .map_err(|_| refused("set caseworkUrl to a numeric loopback HTTP endpoint with a port"))?;
    let token_endpoint = endpoint(token_endpoint).map_err(|_| {
        refused("set tokenEndpoint to a numeric loopback HTTP endpoint with a port")
    })?;
    let fixture = endpoint(issuer)?;
    if token_endpoint.origin() != fixture.origin() {
        return Err(refused(
            "set tokenEndpoint to the fixture issuer's token endpoint",
        ));
    }
    if assertion_audience != issuer {
        return Err(refused(
            "set clientAssertionAudience to the exact fixture issuer",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_remote_token_endpoints_and_other_assertion_audiences() {
        let issuer = "http://127.0.0.1:8091";
        let casework = "http://127.0.0.1:8090";
        let token_endpoint = format!("{issuer}/oauth2/token");
        validate(casework, &token_endpoint, issuer, issuer).unwrap();
        assert!(validate(
            casework,
            "https://issuer.example.invalid/oauth2/token",
            issuer,
            issuer,
        )
        .unwrap_err()
        .to_string()
        .contains("tokenEndpoint"));
        assert!(
            validate(casework, &token_endpoint, "urn:other:issuer", issuer)
                .unwrap_err()
                .to_string()
                .contains("clientAssertionAudience")
        );
    }
}

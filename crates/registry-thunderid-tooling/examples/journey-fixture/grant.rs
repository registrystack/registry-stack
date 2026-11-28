// SPDX-License-Identifier: Apache-2.0
use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use registry_platform_config::{SecretProvidersConfig, SecretReference};
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::PeerPolicy;
use registry_thunderid_tooling::{
    grant::{GrantConnection, GrantCredential},
    task_connection, ToolingError,
};
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

#[path = "../../src/grant_exchange.rs"]
mod exchange;

fn refused(reason: &'static str) -> ToolingError {
    ToolingError::GrantAcquisition { reason }
}

fn endpoint(address: &str) -> Result<Url, ToolingError> {
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Connection {
    #[serde(rename = "apiVersion")]
    _api_version: String,
    #[serde(rename = "kind")]
    _kind: String,
    casework_url: String,
    token_endpoint: String,
    client_assertion_audience: String,
    bootstrap_resource: String,
    secret_providers: SecretProvidersConfig,
    clients: BTreeMap<String, Client>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Client {
    assertion_key_ref: SecretReference,
    resource: String,
    scopes: Vec<String>,
}

fn validate_fixture_connection(
    connection: &GrantConnection,
    issuer: &str,
) -> Result<(), ToolingError> {
    endpoint(&connection.casework_url)
        .map_err(|_| refused("set caseworkUrl to a numeric loopback HTTP endpoint with a port"))?;
    let token_endpoint = endpoint(&connection.token_endpoint).map_err(|_| {
        refused("set tokenEndpoint to a numeric loopback HTTP endpoint with a port")
    })?;
    let fixture = endpoint(issuer)?;
    if token_endpoint.origin() != fixture.origin() {
        return Err(refused(
            "set tokenEndpoint to the fixture issuer's token endpoint",
        ));
    }
    if connection.client_assertion_audience != issuer {
        return Err(refused(
            "set clientAssertionAudience to the exact fixture issuer",
        ));
    }
    connection.validate()
}

pub(super) async fn acquire_header(
    path: &Path,
    root: &Path,
    client: &str,
    grant: &str,
    issuer: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let valid_client = !client.is_empty()
        && client.len() <= task_connection::MAXIMUM_CLIENT_ID_BYTES
        && client.as_bytes()[0].is_ascii_alphanumeric()
        && client
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte));
    let valid_grant = grant.len() == 36
        && grant.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    if !valid_client || !valid_grant {
        return Err("pass a registered fixture client ID and approved grant UUID".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err("pass a regular fixture connection file writable only by its owner".into());
    }
    let mut bytes = Vec::new();
    file.take(registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES {
        return Err("the fixture connection file exceeds its size bound".into());
    }
    let mut expressions = registry_platform_config::AuthoredExpressions;
    let input = registry_platform_yaml::Reader::new(path.display().to_string())
        .with_hook(&mut expressions)
        .decode::<Connection>(
            &bytes,
            &registry_platform_yaml::Expect::one(&task_connection::FORMAT),
        )
        .map_err(|_| "provide a valid PlatformTaskConnection fixture file")?
        .value;
    let registration = input
        .clients
        .get(client)
        .ok_or("use a client registered in the fixture connection")?;
    let connection = GrantConnection {
        casework_url: input.casework_url,
        token_endpoint: input.token_endpoint,
        client_assertion_audience: input.client_assertion_audience,
        bootstrap_resource: input.bootstrap_resource,
        resource: registration.resource.clone(),
        scopes: registration.scopes.clone(),
    };
    validate_fixture_connection(&connection, issuer)?;
    let key = input
        .secret_providers
        .resolver()?
        .resolve_reference(&registration.assertion_key_ref)
        .map_err(|_| "make the fixture assertion key available through its secret reference")?;
    let key = PrivateJwk::parse(std::str::from_utf8(key.expose_secret())?)
        .map_err(|_| "provide a private JWK for the fixture client")?;
    fn require_private_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err("use an owner-only fixture directory for the grant header".into());
        }
        Ok(())
    }
    require_private_directory(root)?;
    let grants = root.join("grants");
    match DirBuilder::new().mode(0o700).create(&grants) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    require_private_directory(&grants)?;
    let credential = exchange::acquire(
        &connection,
        client,
        key,
        grant,
        PeerPolicy::AcceptDevelopmentPeer,
    )
    .await?;
    let header = credential.token.authorization_header_value();
    let mut bytes = Zeroizing::new(Vec::with_capacity(16 + header.as_bytes().len()));
    bytes.extend_from_slice(b"Authorization: ");
    bytes.extend_from_slice(header.as_bytes());
    bytes.push(b'\n');
    let path = grants.join(format!("{client}-{grant}.header"));
    let mut file = tempfile::NamedTempFile::new_in(&grants)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist(&path).map_err(|error| error.error)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_remote_token_endpoints_and_other_assertion_audiences() {
        let issuer = "http://127.0.0.1:8091";
        let mut connection = GrantConnection {
            casework_url: "http://127.0.0.1:8090".into(),
            token_endpoint: format!("{issuer}/oauth2/token"),
            client_assertion_audience: issuer.into(),
            bootstrap_resource: "urn:registry:casework".into(),
            resource: "urn:registry:breg".into(),
            scopes: vec!["records:get".into()],
        };
        validate_fixture_connection(&connection, issuer).unwrap();
        connection.token_endpoint = "https://issuer.example.invalid/oauth2/token".into();
        assert!(validate_fixture_connection(&connection, issuer)
            .unwrap_err()
            .to_string()
            .contains("tokenEndpoint"));
        connection.token_endpoint = format!("{issuer}/oauth2/token");
        connection.client_assertion_audience = "urn:other:issuer".into();
        assert!(validate_fixture_connection(&connection, issuer)
            .unwrap_err()
            .to_string()
            .contains("clientAssertionAudience"));
    }
}

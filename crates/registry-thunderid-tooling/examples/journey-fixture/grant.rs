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
use zeroize::Zeroizing;

use super::grant_endpoint::{endpoint, refused};

#[path = "../../src/grant_exchange.rs"]
mod exchange;

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
    super::grant_endpoint::validate(
        &connection.casework_url,
        &connection.token_endpoint,
        &connection.client_assertion_audience,
        issuer,
    )?;
    connection.validate()?;
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

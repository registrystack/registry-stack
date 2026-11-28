// SPDX-License-Identifier: Apache-2.0
//! Exact development-only connections to services owned by an external test fixture.

use anyhow::{ensure, Context, Result};
use registry_platform_config::{SecretProvider, SecretReference};
use registry_platform_yaml::{BoundedU32, LocalId, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use zeroize::Zeroizing;

use crate::plan::{
    identifier, numeric_loopback_endpoint, require, SemanticRefusal, SemanticResult,
};

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ExternalBreg {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_authority: Option<ReviewAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_grant: Option<TaskGrant>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::plan::keyed_schema::<LocalId, Hook>")
    )]
    pub hooks: BTreeMap<String, Hook>,
    /// Owner-only bearer header files for the named people in BReg schema rehearsals.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::plan::keyed_schema::<LocalId, SecretReference>")
    )]
    pub schema_test_headers: BTreeMap<String, SecretReference>,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ReviewAuthority {
    pub id: LocalId,
    endpoint: Url,
    profile: String,
    producer_id: String,
    recovery_days: BoundedU32<1, 90>,
    token_endpoint: Url,
    client_id: String,
    assertion_key_ref: SecretReference,
    resource: String,
    scopes: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TaskGrant {
    source_issuer: Url,
    pub assertion_client: String,
    status_url: Url,
    token_endpoint: Url,
    status_client: String,
    status_key_ref: SecretReference,
    status_resource: String,
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Hook {
    pub origin: Url,
    pub path: String,
    pub key_ref: SecretReference,
}

fn private_fixture(root: &Path, reference: &SecretReference) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        reference.provider() == SecretProvider::File,
        "external fixture credentials require a secret:file reference"
    );
    let path = root.join("fixture").join(reference.name());
    let parent = path.parent().expect("fixture path starts at root");
    ensure!(
        parent
            .canonicalize()
            .with_context(|| format!(
                "cannot open fixture directory for {}; use an owner-only directory",
                path.display()
            ))?
            .starts_with(root),
        "fixture file {} must be inside the development project",
        path.display()
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(
            rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32,
        )
        .open(&path)
        .with_context(|| {
            format!(
                "cannot open fixture file {}; use a regular file and chmod 600",
                path.display()
            )
        })?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == rustix::process::getuid().as_raw()
            && metadata.mode() & 0o077 == 0,
        "fixture file {} must be a regular file you own; run chmod 600 on it",
        path.display()
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(16_385).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= 16_384,
        "fixture file {} must hold 1 to 16384 bytes",
        path.display()
    );
    Ok(bytes)
}

impl ExternalBreg {
    pub(super) fn validate(&self, root: &Path) -> SemanticResult<()> {
        let canonical = root.canonicalize().map_err(|_| {
            SemanticRefusal::new(
                "/externalBreg",
                "The development project cannot be resolved.",
                "Use an existing project directory.",
            )
        })?;
        let check_file = |field: &str, reference: &SecretReference| {
            private_fixture(&canonical, reference)
                .map(|_| ())
                .map_err(|error| {
                    SemanticRefusal::new(
                        field,
                        format!("{error:#}"),
                        "Use an owner-only regular file in the project; run chmod 600 on it.",
                    )
                })
        };
        if let Some(review) = &self.review_authority {
            require(
                identifier(review.id.as_str())
                    && identifier(&review.profile)
                    && identifier(&review.producer_id),
                "/externalBreg/reviewAuthority",
                "The external review connection needs local identifiers.",
                "Set the exact BReg authority, Casework profile, producer and endpoints.",
            )?;
            for (field, value) in [
                (
                    "/externalBreg/reviewAuthority/endpoint",
                    review.endpoint.as_str(),
                ),
                (
                    "/externalBreg/reviewAuthority/tokenEndpoint",
                    review.token_endpoint.as_str(),
                ),
            ] {
                require_loopback_endpoint(field, value)?;
            }
            check_file(
                "/externalBreg/reviewAuthority/assertionKeyRef",
                &review.assertion_key_ref,
            )?;
        }
        if let Some(grant) = &self.task_grant {
            require(
                crate::products::is_loopback_run_issuer(grant.source_issuer.as_str()),
                "/externalBreg/taskGrant/sourceIssuer",
                "The source issuer must use a numeric loopback HTTP origin.",
                "Set sourceIssuer to the exact numeric loopback HTTP issuer origin with its port.",
            )?;
            for (field, value) in [
                (
                    "/externalBreg/taskGrant/statusUrl",
                    grant.status_url.as_str(),
                ),
                (
                    "/externalBreg/taskGrant/tokenEndpoint",
                    grant.token_endpoint.as_str(),
                ),
            ] {
                require_loopback_endpoint(field, value)?;
            }
            check_file(
                "/externalBreg/taskGrant/statusKeyRef",
                &grant.status_key_ref,
            )?;
        }
        for (id, hook) in &self.hooks {
            require(
                identifier(id) && crate::products::is_loopback_run_issuer(hook.origin.as_str())
                    && hook.path.starts_with('/') && !hook.path.starts_with("//")
                    && !hook.path.contains(['?', '#', '\\']),
                "/externalBreg/hooks",
                "Each external hook needs a destination ID, numeric loopback origin and absolute path.",
                "Set the exact destination ID and the loopback event proxy URL.",
            )?;
            check_file(&format!("/externalBreg/hooks/{id}/keyRef"), &hook.key_ref)?;
        }
        for (person, path) in &self.schema_test_headers {
            require(
                identifier(person),
                "/externalBreg/schemaTestHeaders",
                "Each schema test header needs a named test person.",
                "Use the corresponding name in people.",
            )?;
            check_file(&format!("/externalBreg/schemaTestHeaders/{person}"), path)?;
        }
        Ok(())
    }

    pub(super) fn configure(
        &self,
        mut store: impl FnMut(&str, &[u8]) -> Result<String>,
        root: &Path,
        issuer: &str,
        config: &mut Value,
    ) -> Result<()> {
        if let Some(review) = &self.review_authority {
            let key = private_fixture(root, &review.assertion_key_ref)?;
            config["reviewAuthorities"][review.id.as_str()] = json!({
                "endpoint": review.endpoint, "profile": review.profile,
                "producerId": review.producer_id, "recoveryDays": review.recovery_days,
                "privateKeyJwt": {
                    "tokenEndpoint": review.token_endpoint,
                    "clientIdRef": store("external-review-client", review.client_id.as_bytes())?,
                    "clientAssertionKeyRef": store("external-review-key", &key)?,
                    "assertionAudience": issuer, "resource": review.resource, "scopes": review.scopes
                }
            });
        }
        if let Some(grant) = &self.task_grant {
            let key = private_fixture(root, &grant.status_key_ref)?;
            config["authentication"]["oidc"]["issuers"]["main"]["assertionIssuers"]
                [&grant.assertion_client] = json!([grant.source_issuer]);
            config["taskGrantStatus"] = json!([{
                "sourceIssuer": grant.source_issuer, "baseUrl": grant.status_url,
                "tokenEndpoint": grant.token_endpoint, "clientAssertionAudience": issuer,
                "clientId": grant.status_client, "privateKeyRef": store("external-task-status-key", &key)?,
                "statusResource": grant.status_resource
            }]);
        }
        Ok(())
    }

    pub(super) fn bearer(root: &Path, path: &SecretReference) -> Result<Zeroizing<String>> {
        let bytes = private_fixture(root, path)?;
        let line = std::str::from_utf8(&bytes).context("schema test header must be UTF-8")?;
        let token = line
            .trim_end_matches('\n')
            .strip_prefix("Authorization: Bearer ")
            .filter(|token| !token.is_empty() && !token.chars().any(char::is_whitespace))
            .context("schema test header must contain one Authorization: Bearer line")?;
        Ok(Zeroizing::new(token.to_owned()))
    }

    pub(super) fn hook_key(root: &Path, hook: &Hook) -> Result<Zeroizing<Vec<u8>>> {
        private_fixture(root, &hook.key_ref)
    }
}

fn require_loopback_endpoint(field: &str, value: &str) -> SemanticResult<()> {
    require(
        numeric_loopback_endpoint(value),
        field,
        "The endpoint must use numeric loopback HTTP.",
        "Set this endpoint to http://127.0.0.1:PORT or http://[::1]:PORT and the service path.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn fixture_keys_refuse_group_access_symlinks_and_paths_outside_the_project() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().canonicalize().unwrap();
        let fixtures = root.join("fixture");
        fs::create_dir(&fixtures).unwrap();
        let key = fixtures.join("status.key");
        let key_ref = SecretReference::parse("secret:file/status.key").unwrap();
        let alias = SecretReference::parse("secret:file/alias.key").unwrap();
        fs::write(&key, b"synthetic-key").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        let error = private_fixture(&root, &key_ref).unwrap_err().to_string();
        assert!(error.contains("status.key") && error.contains("chmod 600"));
        assert!(!error.contains("synthetic-key"));

        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&key, fixtures.join("alias.key")).unwrap();
        assert!(private_fixture(&root, &alias).is_err());
        let environment_ref = SecretReference::parse("secret:env/KEY").unwrap();
        assert!(private_fixture(&root, &environment_ref).is_err());
        assert_eq!(
            &**private_fixture(&root, &key_ref).unwrap(),
            b"synthetic-key"
        );
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ORIGINS_SCHEMA: &str = "registry-discovery/origins/v1alpha1";
pub const MAPPING_SCHEMA: &str = "registry-discovery/evidence-mapping/v1alpha1";
pub const MAX_ORIGINS: usize = 128;
pub const MAX_MAPPINGS: usize = 2_048;
pub const MAX_ALTERNATIVES: usize = 32;
pub const MAX_EVIDENCE_TYPES_PER_ALTERNATIVE: usize = 32;
const MAX_AUTHORING_FILE_BYTES: u64 = 1024 * 1024;
const MAX_IDENTIFIER_CHARACTERS: usize = 4_096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OriginsFile {
    pub schema_version: String,
    pub origins: Vec<ApprovedOrigin>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApprovedOrigin {
    pub origin_id: String,
    pub catalog_url: String,
    pub profile: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthoredEvidenceMapping {
    pub schema_version: String,
    pub mapping_id: String,
    pub mapping_authority_id: String,
    pub requirement_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    pub alternatives: Vec<AuthoredEvidenceTypeAlternative>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthoredEvidenceTypeAlternative {
    pub evidence_type_list_id: String,
    pub evidence_type_ids: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CheckedProject {
    pub origins: Vec<ApprovedOrigin>,
    pub mappings: Vec<AuthoredEvidenceMapping>,
}

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("the Discovery authoring project could not be read")]
    Read,
    #[error("the Discovery authoring project is invalid")]
    Invalid,
}

pub fn check_project(root: &Path, allow_loopback: bool) -> Result<CheckedProject, ProjectError> {
    let origins: OriginsFile = read_yaml(&root.join("origins.yaml"))?;
    if origins.schema_version != ORIGINS_SCHEMA
        || origins.origins.is_empty()
        || origins.origins.len() > MAX_ORIGINS
    {
        return Err(ProjectError::Invalid);
    }

    let mut origin_ids = BTreeSet::new();
    let mut origin_urls = BTreeSet::new();
    for origin in &origins.origins {
        if !valid_short_name(&origin.origin_id)
            || !origin_ids.insert(origin.origin_id.as_str())
            || !origin_urls.insert(origin.catalog_url.as_str())
            || origin.profile != registry_discovery_profile::PROFILE_ID
            || !valid_catalog_url(&origin.catalog_url, allow_loopback)
        {
            return Err(ProjectError::Invalid);
        }
    }

    let mapping_paths = mapping_paths(&root.join("mappings"))?;
    if mapping_paths.len() > MAX_MAPPINGS {
        return Err(ProjectError::Invalid);
    }
    let mut mappings = Vec::with_capacity(mapping_paths.len());
    let mut mapping_ids = BTreeSet::new();
    let mut mapping_keys = BTreeSet::new();
    for path in mapping_paths {
        let mut mapping: AuthoredEvidenceMapping = read_yaml(&path)?;
        validate_mapping(&mapping)?;
        for alternative in &mut mapping.alternatives {
            alternative.evidence_type_ids.sort();
        }
        mapping.alternatives.sort_by(|left, right| {
            left.evidence_type_list_id
                .cmp(&right.evidence_type_list_id)
                .then(left.evidence_type_ids.cmp(&right.evidence_type_ids))
        });
        if !mapping_ids.insert(mapping.mapping_id.clone())
            || !mapping_keys.insert((mapping.requirement_id.clone(), mapping.jurisdiction.clone()))
        {
            return Err(ProjectError::Invalid);
        }
        mappings.push(mapping);
    }
    mappings.sort_by(|left, right| left.mapping_id.cmp(&right.mapping_id));

    Ok(CheckedProject {
        origins: origins.origins,
        mappings,
    })
}

fn mapping_paths(directory: &Path) -> Result<Vec<PathBuf>, ProjectError> {
    let metadata = fs::symlink_metadata(directory).map_err(|_| ProjectError::Read)?;
    if !metadata.file_type().is_dir() {
        return Err(ProjectError::Invalid);
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| ProjectError::Read)? {
        let entry = entry.map_err(|_| ProjectError::Read)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| ProjectError::Read)?;
        let supported_extension = matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("yaml" | "yml")
        );
        if !metadata.file_type().is_file()
            || metadata.len() > MAX_AUTHORING_FILE_BYTES
            || !supported_extension
        {
            return Err(ProjectError::Invalid);
        }
        paths.push(path);
    }
    paths.sort();
    Ok(paths)
}

fn read_yaml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, ProjectError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProjectError::Read)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_AUTHORING_FILE_BYTES {
        return Err(ProjectError::Invalid);
    }
    let bytes = fs::read(path).map_err(|_| ProjectError::Read)?;
    serde_yaml_ng::from_slice(&bytes).map_err(|_| ProjectError::Invalid)
}

fn validate_mapping(mapping: &AuthoredEvidenceMapping) -> Result<(), ProjectError> {
    if mapping.schema_version != MAPPING_SCHEMA
        || !valid_identifier(&mapping.mapping_id)
        || !valid_identifier(&mapping.mapping_authority_id)
        || !valid_identifier(&mapping.requirement_id)
        || mapping
            .jurisdiction
            .as_deref()
            .is_some_and(|value| !valid_identifier(value))
        || mapping.alternatives.is_empty()
        || mapping.alternatives.len() > MAX_ALTERNATIVES
    {
        return Err(ProjectError::Invalid);
    }
    let mut list_ids = BTreeSet::new();
    for alternative in &mapping.alternatives {
        if !valid_identifier(&alternative.evidence_type_list_id)
            || !list_ids.insert(alternative.evidence_type_list_id.as_str())
            || alternative.evidence_type_ids.is_empty()
            || alternative.evidence_type_ids.len() > MAX_EVIDENCE_TYPES_PER_ALTERNATIVE
        {
            return Err(ProjectError::Invalid);
        }
        let mut evidence_types = BTreeSet::new();
        for evidence_type in &alternative.evidence_type_ids {
            if !valid_identifier(evidence_type) || !evidence_types.insert(evidence_type.as_str()) {
                return Err(ProjectError::Invalid);
            }
        }
    }
    Ok(())
}

fn valid_catalog_url(value: &str, allow_loopback: bool) -> bool {
    value.chars().count() <= MAX_IDENTIFIER_CHARACTERS
        && registry_discovery_profile::is_valid_endpoint_url(value, allow_loopback)
}

fn valid_short_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_identifier(value: &str) -> bool {
    value.chars().count() <= MAX_IDENTIFIER_CHARACTERS
        && registry_discovery::valid_uri_identifier(value)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn project(origins: &str, mappings: &[(&str, &str)]) -> TempDir {
        let root = TempDir::new().expect("temporary project");
        fs::write(root.path().join("origins.yaml"), origins).expect("origins");
        fs::create_dir(root.path().join("mappings")).expect("mappings directory");
        for (name, body) in mappings {
            fs::write(root.path().join("mappings").join(name), body).expect("mapping");
        }
        root
    }

    const ORIGINS: &str = r#"schemaVersion: registry-discovery/origins/v1alpha1
origins:
  - originId: evidence-one
    catalogUrl: https://unreachable.example.invalid/catalog.jsonld
    profile: registry-discovery-v1alpha1
    enabled: true
"#;

    #[test]
    fn check_is_offline_and_accepts_an_unreachable_https_origin() {
        let root = project(ORIGINS, &[]);
        let checked = check_project(root.path(), false).expect("offline check");
        assert_eq!(checked.origins.len(), 1);
    }

    #[test]
    fn shipped_authoring_fixture_passes_the_offline_check() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/discovery/fixtures/project");
        let checked = check_project(&root, false).expect("shipped project checks offline");
        assert_eq!(checked.origins.len(), 2);
        assert_eq!(checked.mappings.len(), 1);
    }

    #[test]
    fn duplicate_mapping_keys_are_refused() {
        let mapping = r#"schemaVersion: registry-discovery/evidence-mapping/v1alpha1
mappingId: urn:example:mapping:one
mappingAuthorityId: urn:example:authority
requirementId: urn:example:requirement
alternatives:
  - evidenceTypeListId: urn:example:list
    evidenceTypeIds: [urn:example:evidence]
"#;
        let second = mapping.replace("mapping:one", "mapping:two");
        let root = project(ORIGINS, &[("one.yaml", mapping), ("two.yaml", &second)]);
        assert!(matches!(
            check_project(root.path(), false),
            Err(ProjectError::Invalid)
        ));
    }

    #[test]
    fn loopback_http_requires_the_explicit_development_switch() {
        for endpoint in [
            "http://localhost:8080/catalog.jsonld",
            "http://127.0.0.1:8080/catalog.jsonld",
            "http://[::1]:8080/catalog.jsonld",
        ] {
            let origins = ORIGINS.replace(
                "https://unreachable.example.invalid/catalog.jsonld",
                endpoint,
            );
            let root = project(&origins, &[]);
            assert!(check_project(root.path(), false).is_err(), "{endpoint}");
            assert!(check_project(root.path(), true).is_ok(), "{endpoint}");
        }
    }

    #[test]
    fn catalog_urls_refuse_other_loopbacks_and_preparser_whitespace_or_controls() {
        for endpoint in [
            "http://127.0.0.2:8080/catalog.jsonld",
            "http://127.1:8080/catalog.jsonld",
            "http://LOCALHOST:8080/catalog.jsonld",
            "http://[::2]:8080/catalog.jsonld",
            " https://catalog.example.invalid/catalog.jsonld",
            "https://catalog.example.invalid/catalog.jsonld\n",
            "https://catalog.example.invalid/catalog .jsonld",
            "https://catalog.example.invalid/catalog\u{0007}.jsonld",
        ] {
            assert!(!valid_catalog_url(endpoint, true), "accepted {endpoint:?}");
        }
    }

    #[test]
    fn mapping_semantic_identifiers_accept_rdf_fragment_iris() {
        let mapping = r#"schemaVersion: registry-discovery/evidence-mapping/v1alpha1
mappingId: urn:example:mapping#fragment
mappingAuthorityId: urn:example:authority
requirementId: urn:example:requirement
alternatives:
  - evidenceTypeListId: urn:example:list
    evidenceTypeIds: [urn:example:evidence]
"#;
        let root = project(ORIGINS, &[("fragment.yaml", mapping)]);
        let checked = check_project(root.path(), false).expect("fragment IRI mapping");
        assert_eq!(
            checked.mappings[0].mapping_id,
            "urn:example:mapping#fragment"
        );
    }
}

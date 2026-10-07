// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use registry_discovery::{
    canonical_index_bytes, catalog_revision, mapping_revision, validate_index,
    CompiledEvidenceMapping, DiscoveryIndex, EvidenceTypeAlternative, OriginSummary, ServiceRecord,
    INDEX_FILE, INDEX_SCHEMA, MAXIMUM_INDEX_BYTES, MAXIMUM_PACKAGE_BYTES, MAXIMUM_PACKAGE_DEPTH,
    MAXIMUM_PACKAGE_FILES, PACKAGE_COMMAND,
};
use registry_platform_config::{write_package, PackageError, PackageLimits, VerifiedPackage};
use registry_platform_httputil::{read_bounded, validate_response_headers, FetchUrlPolicy};
use reqwest::header::{ACCEPT, CONTENT_ENCODING, CONTENT_TYPE};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::project::{check_project, AuthoredEvidenceMapping, CheckedProject, ProjectError};

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

fn package_limits() -> PackageLimits {
    PackageLimits {
        max_files: MAXIMUM_PACKAGE_FILES,
        max_file_bytes: MAXIMUM_INDEX_BYTES,
        max_total_bytes: MAXIMUM_PACKAGE_BYTES,
        max_depth: MAXIMUM_PACKAGE_DEPTH,
        ..PackageLimits::default()
    }
}

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("{0}")]
    Project(#[from] ProjectError),
    #[error("an approved Discovery origin could not be fetched safely")]
    Fetch,
    #[error("an approved Discovery origin returned an invalid public description")]
    Description,
    #[error(
        "an approved Discovery origin publishes a retired Relay service; remove Relay origins and package again"
    )]
    RetiredServiceKind,
    #[error("the Discovery index could not be compiled")]
    Compile,
    #[error("{0}")]
    Package(#[from] PackageError),
}

/// The index and shared package identity produced from one collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackagedDiscovery {
    pub index: DiscoveryIndex,
    pub package_digest: String,
}

pub async fn package_project(
    project_root: &Path,
    output: &Path,
    allow_loopback: bool,
    revision: Option<&str>,
) -> Result<PackagedDiscovery, BuildError> {
    package_project_with_timeouts(
        project_root,
        output,
        allow_loopback,
        revision,
        None,
        DNS_TIMEOUT,
        FETCH_TIMEOUT,
    )
    .await
}

pub async fn package_project_at(
    project_root: &Path,
    output: &Path,
    allow_loopback: bool,
    revision: Option<&str>,
    built_at: OffsetDateTime,
) -> Result<PackagedDiscovery, BuildError> {
    package_project_with_timeouts(
        project_root,
        output,
        allow_loopback,
        revision,
        Some(built_at),
        DNS_TIMEOUT,
        FETCH_TIMEOUT,
    )
    .await
}

async fn package_project_with_timeouts(
    project_root: &Path,
    output: &Path,
    allow_loopback: bool,
    revision: Option<&str>,
    fixed_built_at: Option<OffsetDateTime>,
    dns_timeout: Duration,
    fetch_timeout: Duration,
) -> Result<PackagedDiscovery, BuildError> {
    let checked = check_project(project_root, allow_loopback)?;
    let (mut origins, mut services) =
        fetch_origins(&checked, allow_loopback, dns_timeout, fetch_timeout).await?;
    origins.sort_by(|left, right| left.origin_id.cmp(&right.origin_id));
    services.sort_by(|left, right| left.record_id.cmp(&right.record_id));
    let mut mappings = compile_mappings(checked.mappings);
    mappings.sort_by(|left, right| {
        left.requirement_id
            .cmp(&right.requirement_id)
            .then(left.jurisdiction.cmp(&right.jurisdiction))
            .then(left.mapping_id.cmp(&right.mapping_id))
    });
    let catalog_revision = catalog_revision(&services).map_err(|_| BuildError::Compile)?;
    let mapping_revision = mapping_revision(&mappings).map_err(|_| BuildError::Compile)?;
    let timestamp = fixed_built_at
        .unwrap_or_else(OffsetDateTime::now_utc)
        .format(&Rfc3339)
        .map_err(|_| BuildError::Compile)?;

    let index = DiscoveryIndex {
        schema_version: INDEX_SCHEMA.to_owned(),
        catalog_revision,
        mapping_revision,
        built_at: timestamp,
        origins,
        services,
        mappings,
    };
    let package = write_index_package(&index, output, revision, MAXIMUM_INDEX_BYTES)?;
    Ok(PackagedDiscovery {
        index,
        package_digest: package.digest().to_owned(),
    })
}

fn write_index_package(
    index: &DiscoveryIndex,
    output: &Path,
    revision: Option<&str>,
    maximum_index_bytes: u64,
) -> Result<VerifiedPackage, BuildError> {
    validate_index(index).map_err(|_| BuildError::Compile)?;
    let bytes = canonical_index_bytes(index).map_err(|_| BuildError::Compile)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum_index_bytes) {
        return Err(BuildError::Compile);
    }
    let files = BTreeMap::from([(INDEX_FILE.to_owned(), bytes)]);
    write_package(output, &files, revision, &package_limits(), PACKAGE_COMMAND)
        .map_err(BuildError::from)
}

async fn fetch_origins(
    project: &CheckedProject,
    allow_loopback: bool,
    dns_timeout: Duration,
    fetch_timeout: Duration,
) -> Result<(Vec<OriginSummary>, Vec<ServiceRecord>), BuildError> {
    let policy = if allow_loopback {
        FetchUrlPolicy::dev()
    } else {
        FetchUrlPolicy::strict()
    };
    let mut origins = Vec::new();
    let mut services = Vec::new();
    let mut record_ids = BTreeSet::new();

    for approved in project.origins.iter().filter(|origin| origin.enabled) {
        let url = approved.catalog_url.to_url();
        let validated = policy
            .validate_dns_pinned_for_immediate_fetch_with_timeout(&url, dns_timeout)
            .await
            .map_err(|_| BuildError::Fetch)?;
        let response = validated
            .immediate_get_with_timeout(fetch_timeout)
            .map_err(|_| BuildError::Fetch)?
            .header(ACCEPT, registry_discovery_profile::MEDIA_TYPE)
            .send()
            .await
            .map_err(|_| BuildError::Fetch)?;
        validate_response_headers(response.headers()).map_err(|_| BuildError::Fetch)?;
        if response.status() != reqwest::StatusCode::OK
            || !exact_profile_media_type(response.headers())
            || response
                .headers()
                .get(CONTENT_ENCODING)
                .is_some_and(|value| value.as_bytes() != b"identity")
        {
            return Err(BuildError::Fetch);
        }
        let bytes = read_bounded(
            response,
            u64::try_from(registry_discovery_profile::MAX_DESCRIPTION_BYTES)
                .map_err(|_| BuildError::Compile)?,
        )
        .await
        .map_err(|_| BuildError::Fetch)?;
        // Bind provenance to this origin's completed fetch, not to the start
        // of a potentially long sequential build.
        let fetched_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| BuildError::Compile)?;
        let description =
            registry_discovery_profile::parse_description(&bytes).map_err(|error| match error {
                registry_discovery_profile::ProfileError::RetiredServiceKind => {
                    BuildError::RetiredServiceKind
                }
                _ => BuildError::Description,
            })?;
        let content_digest = sha256_digest(&bytes);
        origins.push(OriginSummary {
            origin_id: approved.origin_id.clone(),
            catalog_url: approved.catalog_url.to_string(),
            content_digest: content_digest.clone(),
            fetched_at: fetched_at.clone(),
        });
        for advertised in description.services() {
            let record_id = record_id(&approved.origin_id, advertised.binding_id())?;
            if !record_ids.insert(record_id.clone()) {
                return Err(BuildError::Compile);
            }
            let roles = advertised.roles();
            services.push(ServiceRecord {
                record_id,
                binding_id: advertised.binding_id().to_owned(),
                service_id: advertised.service_id().to_owned(),
                service_kind: advertised.service_kind(),
                title: advertised.title().to_owned(),
                description: advertised.description().to_owned(),
                endpoint_url: advertised.endpoint_url().to_owned(),
                publisher_id: roles.publisher_id.clone(),
                operator_id: roles.operator_id.clone(),
                registry_authority_id: roles.registry_authority_id.clone(),
                legal_issuer_id: roles.legal_issuer_id.clone(),
                technical_provider_id: roles.technical_provider_id.clone(),
                jurisdictions: advertised.jurisdictions().to_vec(),
                conforms_to: advertised.conforms_to().to_vec(),
                evidence_type_ids: advertised.evidence_type_ids().to_vec(),
                semantic_class_ids: advertised.semantic_class_ids().to_vec(),
                operation_family_ids: advertised.operation_family_ids().to_vec(),
                origin_id: approved.origin_id.clone(),
                origin_url: approved.catalog_url.to_string(),
                origin_content_digest: content_digest.clone(),
                origin_fetched_at: fetched_at.clone(),
            });
        }
    }
    Ok((origins, services))
}

fn exact_profile_media_type(headers: &reqwest::header::HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    matches!(
        (values.next(), values.next()),
        (Some(value), None)
            if value.as_bytes() == registry_discovery_profile::MEDIA_TYPE.as_bytes()
    )
}

fn compile_mappings(mappings: Vec<AuthoredEvidenceMapping>) -> Vec<CompiledEvidenceMapping> {
    mappings
        .into_iter()
        .map(|mapping| CompiledEvidenceMapping {
            mapping_id: mapping.mapping_id,
            mapping_authority_id: mapping.mapping_authority_id,
            requirement_id: mapping.requirement_id,
            jurisdiction: mapping.jurisdiction,
            alternatives: mapping
                .alternatives
                .into_iter()
                .map(|alternative| EvidenceTypeAlternative {
                    evidence_type_list_id: alternative.evidence_type_list_id,
                    evidence_type_ids: alternative.evidence_type_ids.into_vec(),
                })
                .collect(),
        })
        .collect()
}

fn record_id(origin_id: &str, binding_id: &str) -> Result<String, BuildError> {
    let value = serde_json::json!({
        "originId": origin_id,
        "bindingId": binding_id,
    });
    let bytes = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| BuildError::Compile)?;
    Ok(format!(
        "urn:registrystack:discovery:record:sha256:{}",
        hex::encode(Sha256::digest(bytes))
    ))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::header::CONTENT_TYPE;
    use axum::http::{Response, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use registry_discovery::{catalog_revision, mapping_revision};
    use registry_discovery_profile::{
        render_description, DiscoveryDescription, ServiceDescription, ServiceKind, ServiceRoles,
        MEDIA_TYPE,
    };
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn compiled_index_byte_overflow_preserves_the_previous_output() {
        let services = Vec::new();
        let mappings = Vec::new();
        let index = DiscoveryIndex {
            schema_version: INDEX_SCHEMA.into(),
            catalog_revision: catalog_revision(&services).expect("catalog revision"),
            mapping_revision: mapping_revision(&mappings).expect("mapping revision"),
            built_at: "2026-08-14T00:00:00Z".into(),
            origins: Vec::new(),
            services,
            mappings,
        };
        let directory = TempDir::new().expect("temporary directory");
        let output = directory.path().join("index.json");
        fs::write(&output, b"previous-index-canary").expect("previous index");

        assert!(matches!(
            write_index_package(&index, &output, None, 1),
            Err(BuildError::Compile)
        ));
        assert_eq!(
            fs::read(&output).expect("previous output"),
            b"previous-index-canary"
        );
    }

    #[test]
    fn packaging_the_same_compiled_index_twice_is_repeatable() {
        let services = Vec::new();
        let mappings = Vec::new();
        let index = DiscoveryIndex {
            schema_version: INDEX_SCHEMA.into(),
            catalog_revision: catalog_revision(&services).expect("catalog revision"),
            mapping_revision: mapping_revision(&mappings).expect("mapping revision"),
            built_at: "2026-08-14T00:00:00Z".into(),
            origins: Vec::new(),
            services,
            mappings,
        };
        let directory = TempDir::new().expect("temporary directory");
        let first = directory.path().join("first-package");
        let second = directory.path().join("second-package");

        let first_package = write_index_package(
            &index,
            &first,
            Some("example-revision"),
            MAXIMUM_INDEX_BYTES,
        )
        .expect("first package");
        let second_package = write_index_package(
            &index,
            &second,
            Some("example-revision"),
            MAXIMUM_INDEX_BYTES,
        )
        .expect("second package");

        assert_eq!(first_package.digest(), second_package.digest());
        assert_eq!(
            fs::read(first.join("SHA256SUMS")).unwrap(),
            fs::read(second.join("SHA256SUMS")).unwrap()
        );
        assert_eq!(
            fs::read(first.join(INDEX_FILE)).unwrap(),
            fs::read(second.join(INDEX_FILE)).unwrap()
        );
    }

    #[tokio::test]
    async fn origin_fetch_timeout_leaves_the_previous_output_untouched() {
        let service = ServiceDescription::new(
            "urn:example:service:evidence".into(),
            ServiceKind::Evidence,
            "Example Evidence".into(),
            "Public minimum-disclosure assertions".into(),
            "https://evidence.example.org".into(),
            ServiceRoles::default(),
            vec!["urn:example:jurisdiction".into()],
            vec!["https://registrystack.org/evidence/profile/v1".into()],
            vec!["urn:example:evidence-type:adult-status".into()],
            Vec::new(),
            Vec::new(),
        )
        .expect("service");
        let body =
            render_description(&DiscoveryDescription::new(vec![service]).expect("description"))
                .expect("render");
        let counter = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(tokio::sync::Notify::new());
        let app = Router::new().route(
            "/catalog.jsonld",
            get({
                let counter = Arc::clone(&counter);
                let entered = Arc::clone(&entered);
                move || {
                    let body = body.clone();
                    let counter = Arc::clone(&counter);
                    let entered = Arc::clone(&entered);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        entered.notify_one();
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, MEDIA_TYPE)
                            .body(Body::from(body))
                            .expect("response")
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("provider server");
        });

        let project = TempDir::new().expect("project");
        fs::write(
            project.path().join("origins.yaml"),
            format!(
                "schemaVersion: registry-discovery/origins/v1alpha1\norigins:\n  - originId: evidence\n    catalogUrl: http://{address}/catalog.jsonld\n    profile: registry-discovery-v1alpha1\n    enabled: true\n"
            ),
        )
        .expect("origins");
        fs::create_dir(project.path().join("mappings")).expect("mappings");
        let output = project.path().join("package");
        fs::write(&output, b"previous-index-canary").expect("previous index");

        let project_path = project.path().to_path_buf();
        let package_output = output.clone();
        let mut package = tokio::spawn(async move {
            package_project_with_timeouts(
                &project_path,
                &package_output,
                true,
                None,
                Some(OffsetDateTime::UNIX_EPOCH),
                DNS_TIMEOUT,
                Duration::from_millis(500),
            )
            .await
        });
        tokio::select! {
            () = entered.notified() => {}
            result = &mut package => panic!("fetch ended before the provider received it: {result:?}"),
            () = tokio::time::sleep(Duration::from_secs(5)) => panic!("provider was not reached"),
        }
        let result = tokio::time::timeout(Duration::from_secs(5), package)
            .await
            .expect("fetch timeout elapsed")
            .expect("package task");

        assert!(matches!(result, Err(BuildError::Fetch)));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(
            fs::read(&output).expect("previous output"),
            b"previous-index-canary"
        );
        server.abort();
    }
}

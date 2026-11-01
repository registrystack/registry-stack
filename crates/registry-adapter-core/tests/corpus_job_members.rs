// SPDX-License-Identifier: Apache-2.0

//! The governed-ingestion corpus members, read through the platform
//! reader and refused through the same checks the job compiler runs
//! (`products/adapter/fixtures/corpus/`). The corpus sweep itself stays
//! with `adapterctl`; this suite pins the members whose defects this
//! crate's vocabulary polices, so a format change here cannot leave a
//! member refusing with the wrong code, with a stale pin shape, or
//! clean.

use std::path::PathBuf;
use std::sync::OnceLock;

use registry_adapter_core::{
    check_job, check_workspace, AdapterJob, AdapterPack, AdapterProfile, AdapterProject, Workspace,
    ADAPTER_JOB_API_VERSION, ADAPTER_JOB_KIND, ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND,
    ADAPTER_PROFILE_API_VERSION, ADAPTER_PROFILE_KIND, ADAPTER_PROJECT_API_VERSION,
    ADAPTER_PROJECT_KIND,
};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec};

fn corpus() -> &'static std::path::Path {
    static CORPUS: OnceLock<PathBuf> = OnceLock::new();
    CORPUS.get_or_init(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter/fixtures/corpus")
    })
}

fn job_format() -> FormatSpec<'static> {
    FormatSpec {
        kind: ADAPTER_JOB_KIND,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: Box::leak(Box::new([ApiVersion::current(ADAPTER_JOB_API_VERSION)])),
            retired_api_versions: &[],
        },
        removed_keys: &[],
    }
}

fn pack_format() -> FormatSpec<'static> {
    FormatSpec {
        kind: ADAPTER_PACK_KIND,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: Box::leak(Box::new([ApiVersion::current(ADAPTER_PACK_API_VERSION)])),
            retired_api_versions: &[],
        },
        removed_keys: &[],
    }
}

fn profile_format() -> FormatSpec<'static> {
    FormatSpec {
        kind: ADAPTER_PROFILE_KIND,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: Box::leak(Box::new([ApiVersion::current(ADAPTER_PROFILE_API_VERSION)])),
            retired_api_versions: &[],
        },
        removed_keys: &[],
    }
}

fn project_format() -> FormatSpec<'static> {
    FormatSpec {
        kind: ADAPTER_PROJECT_KIND,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: Box::leak(Box::new([ApiVersion::current(ADAPTER_PROJECT_API_VERSION)])),
            retired_api_versions: &[],
        },
        removed_keys: &[],
    }
}

fn read<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> T {
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let format = leaked_format::<T>();
    registry_platform_yaml::decode_document::<T>(
        path.display().to_string(),
        &bytes,
        &Expect::one(&format),
    )
    .unwrap_or_else(|refused| panic!("{}: {refused}", path.display()))
    .value
}

// The reader needs one format per call site; the leak mirrors
// `registry-adapter`'s loader, whose format specs are process constants.
fn leaked_format<T>() -> FormatSpec<'static> {
    if std::any::type_name::<T>() == std::any::type_name::<AdapterJob>() {
        job_format()
    } else if std::any::type_name::<T>() == std::any::type_name::<AdapterPack>() {
        pack_format()
    } else if std::any::type_name::<T>() == std::any::type_name::<AdapterProfile>() {
        profile_format()
    } else {
        project_format()
    }
}

fn member(name: &str) -> std::path::PathBuf {
    corpus().join("bad").join(name)
}

fn codes(findings: &[registry_platform_yaml::Diagnostic]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| finding.code.clone())
        .collect()
}

/// The two controls: the facade workspace and the job-mode workspace
/// pass with zero findings, and the clean job passes `check_job`.
#[test]
fn the_corpus_controls_stay_clean() {
    for control in ["base", "base-job"] {
        let dir = corpus().join(control);
        let profile: AdapterProfile = read(&dir.join("profile.yaml"));
        let pack: AdapterPack = read(&dir.join("pack.yaml"));
        let project: AdapterProject = read(&dir.join("project.yaml"));
        let workspace = Workspace {
            profile: &profile,
            pack: &pack,
            project: &project,
            runtime: None,
            fixtures: &[],
        };
        let findings = check_workspace(&workspace);
        assert!(
            findings.is_empty(),
            "the {control} control checks clean: {:?}",
            codes(&findings)
        );
    }
    let dir = corpus().join("base-job");
    let pack: AdapterPack = read(&dir.join("pack.yaml"));
    let job: AdapterJob = read(&dir.join("job.yaml"));
    let findings = check_job(&job, &pack);
    assert!(
        findings.is_empty(),
        "the clean job checks clean: {:?}",
        codes(&findings)
    );
}

/// Every governed-ingestion member refuses with exactly its own code:
/// the workspace-level members through `check_workspace`, the
/// job.yaml-carrying members through `check_job` beside a clean
/// workspace.
#[test]
fn governed_ingestion_members_refuse_with_exactly_their_code() {
    let members = [
        "adapter.job.component-facade-refused",
        "adapter.job.decoder-unknown",
        "adapter.job.endpoint-response-bound",
        "adapter.job.poll-endpoint-kind",
        "adapter.job.poll-endpoint-unknown",
        "adapter.job.poll-facade-refused",
        "adapter.job.poll-timeout",
        "adapter.job.postgres-parameters-unbounded",
        "adapter.job.profile-bound",
        "adapter.job.profile-endpoint-bound",
        "adapter.job.profile-inconsistent",
        "adapter.job.projection-bound",
        "adapter.job.projection-shape",
        "adapter.job.route-unknown",
        "adapter.job.send-component-refused",
        "adapter.job.source-bound-refused",
        "adapter.job.source-called-refused",
        "adapter.job.source-edits-required",
        "adapter.job.source-edits-unknown",
        "adapter.job.source-id-collision",
        "adapter.job.source-recovery-required",
        "adapter.job.source-rescan-delay",
        "adapter.job.source-scan-required",
        "adapter.job.trigger-bound",
        "adapter.job.trigger-hook-unserved",
        "adapter.job.trigger-kind",
        "adapter.job.triggers-required",
        "adapter.job.call-budget",
    ];
    // The structural co-fires the corpus README records: the fault each
    // named member tests is the fault the second check sees too, and the
    // sweep expectation lists both.
    let co_fires: &[(&str, &[&str])] = &[
        (
            "adapter.job.source-bound-refused",
            &[
                "adapter.project.template-not-instantiated",
                "adapter.project.unknown-route",
            ],
        ),
        (
            "adapter.job.source-called-refused",
            &["adapter.route.unknown-direct-target"],
        ),
    ];
    for name in members {
        let dir = member(name);
        let profile: AdapterProfile = read(&dir.join("profile.yaml"));
        let pack: AdapterPack = read(&dir.join("pack.yaml"));
        let project: AdapterProject = read(&dir.join("project.yaml"));
        let workspace = Workspace {
            profile: &profile,
            pack: &pack,
            project: &project,
            runtime: None,
            fixtures: &[],
        };
        let mut all_codes = codes(&check_workspace(&workspace));
        let job_path = dir.join("job.yaml");
        if job_path.exists() {
            let job: AdapterJob = read(&job_path);
            all_codes.extend(codes(&check_job(&job, &pack)));
        }
        all_codes.sort();
        all_codes.dedup();
        let mut expected = vec![name.to_string()];
        if let Some((_, extra)) = co_fires.iter().find(|(member, _)| *member == name) {
            expected.extend(extra.iter().map(|code| code.to_string()));
        }
        expected.sort();
        assert_eq!(
            all_codes, expected,
            "{name} refuses with exactly its own code and its documented co-fires"
        );
    }
}

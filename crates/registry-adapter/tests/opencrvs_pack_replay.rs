// SPDX-License-Identifier: Apache-2.0

//! Every maintained synthetic OpenCRVS fixture through the actual offline
//! route interpreter. This proves engine execution only, never a live
//! OpenCRVS exchange.

use std::path::{Path, PathBuf};

use registry_adapter::engine::replay;
use registry_adapter_core::{
    AdapterFixture, AdapterPack, AdapterProfile, AdapterProject, ADAPTER_FIXTURE_API_VERSION,
    ADAPTER_FIXTURE_KIND, ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND, ADAPTER_PROFILE_API_VERSION,
    ADAPTER_PROFILE_KIND, ADAPTER_PROJECT_API_VERSION, ADAPTER_PROJECT_KIND,
};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
use serde::de::DeserializeOwned;

const PROJECT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROJECT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROJECT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

const PROFILE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PROFILE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PROFILE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

const PACK_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PACK_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PACK_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

const FIXTURE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_FIXTURE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_FIXTURE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn authored<T: DeserializeOwned>(path: &Path, format: &FormatSpec<'static>) -> T {
    let bytes = std::fs::read(path).expect("the authored document is readable");
    Reader::new(path.display().to_string())
        .decode::<T>(&bytes, &Expect::one(format))
        .expect("the authored document passes the platform YAML reader")
        .value
}

#[tokio::test]
async fn all_maintained_opencrvs_fixtures_execute_in_the_engine() {
    let root = repository();
    let pack_path = root.join("products/adapter/packs/opencrvs-events/pack.yaml");
    let pack: AdapterPack = authored(&pack_path, &PACK_FORMAT);
    let profile: AdapterProfile = authored(
        &root.join("products/adapter/profiles/breg-records/profile.yaml"),
        &PROFILE_FORMAT,
    );
    let project: AdapterProject = authored(
        &root.join("products/adapter/examples/opencrvs-events/project.yaml"),
        &PROJECT_FORMAT,
    );
    let mut fixtures = std::fs::read_dir(root.join("products/adapter/fixtures/opencrvs-events"))
        .expect("the fixture directory is readable")
        .map(|entry| entry.expect("a fixture entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .collect::<Vec<_>>();
    fixtures.sort();

    let mut replayed = 0usize;
    for fixture_path in fixtures {
        let fixture: AdapterFixture = authored(&fixture_path, &FIXTURE_FORMAT);
        for entry_index in 0..fixture.entries.len() {
            replay::run(
                &project,
                &profile,
                &pack,
                pack_path.parent().expect("the pack directory"),
                &fixture,
                entry_index,
            )
            .await
            .unwrap_or_else(|failure| {
                panic!(
                    "{} failed actual engine replay: {failure:?}",
                    fixture_path.display()
                )
            });
            replayed += 1;
        }
    }
    assert_eq!(replayed, 10, "every maintained fixture entry ran");
}

// SPDX-License-Identifier: Apache-2.0

//! The maintained DHIS2 pack's source-native exact read remains directly
//! compilable by the listener-free Evidence engine, without a facade profile.

use std::fs;
use std::path::{Path, PathBuf};

use registry_adapter_core::{AdapterPack, ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND};
use registry_adapter_engine::artifacts::PackArtifactBytes;
use registry_adapter_engine::evidence::{compile_evidence_pack, EvidenceLimits};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};

const PACK_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PACK_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PACK_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

fn pack_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter/packs/dhis2-tracker")
}

fn artifact(directory: &Path, path: &str) -> (String, Vec<u8>) {
    (
        path.to_owned(),
        fs::read(directory.join(path)).expect("the maintained pack artifact is readable"),
    )
}

#[test]
fn evidence_compiles_the_same_source_native_dhis2_exact_read() {
    let directory = pack_directory();
    let pack_bytes =
        fs::read(directory.join("pack.yaml")).expect("the maintained pack is readable");
    let pack = Reader::new("products/adapter/packs/dhis2-tracker/pack.yaml")
        .decode::<AdapterPack>(&pack_bytes, &Expect::one(&PACK_FORMAT))
        .expect("the maintained pack follows its typed grammar")
        .value;
    let artifacts = PackArtifactBytes::new([
        artifact(&directory, "schemas/evidence-inputs.json"),
        artifact(&directory, "schemas/evidence-native-entity.json"),
        artifact(&directory, "scripts/evidence-native.rhai"),
        artifact(&directory, "scripts/is-not-found.rhai"),
        artifact(&directory, "scripts/source-identity.rhai"),
    ]);

    let program = compile_evidence_pack(
        &pack,
        "evidence-native-entity",
        &artifacts,
        EvidenceLimits::default(),
    )
    .expect("the source-native exact read compiles without facade metadata");

    assert!(program
        .input_schema()
        .validate(&serde_json::json!({"recordReference": "EeBJ3Sn9uLg"})));
    assert!(program.facts_schema().validate(&serde_json::json!({
        "trackedEntity": "EeBJ3Sn9uLg",
        "trackedEntityType": "cQWYtUfH6Vx",
        "createdAt": "2017-01-20T10:44:02.770",
        "updatedAt": "2017-05-26T11:46:22.372",
        "orgUnit": "slSrf7H9lMf",
        "inactive": false,
        "deleted": false,
        "potentialDuplicate": false,
        "attributes": [{"attribute": "rmeJVy1Rl5V", "value": "PRIVATE-CANARY"}]
    })));
}

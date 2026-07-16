// SPDX-License-Identifier: Apache-2.0
//! Deterministic Registry Stack project authoring for Relay and Notary.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::ValueEnum;
use registry_notary_core::{config::StatePostgresqlConfig, StandaloneRegistryNotaryConfig};
use registry_platform_crypto::{canonicalize_json, parse_json_strict};
use registry_relay::source_plan::{
    authoring::{
        compile_consultation_contract, compile_integration_pack, compile_private_binding,
        AuthoredArtifact, AuthoredConsultationContract,
    },
    EvidenceClass, PinnedEvidenceArtifact, PinnedSourcePlanArtifact, SourcePlanArtifactBundle,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

static PROJECT_STARTERS: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/assets/project-starters");
static DHIS2_TRACKER_STARTER: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/tests/fixtures/project-authoring/dhis2-tracker");
static OPENCRVS_DCI_STARTER: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/tests/fixtures/project-authoring/opencrvs");
static FHIR_R4_STARTER: include_dir::Dir<'_> = include_dir::include_dir!(
    "$CARGO_MANIFEST_DIR/tests/fixtures/project-authoring/fhir-r4-coverage-active"
);
static SNAPSHOT_STARTER: include_dir::Dir<'_> = include_dir::include_dir!(
    "$CARGO_MANIFEST_DIR/tests/fixtures/project-authoring/snapshot-exact"
);

const PROJECT_FILE: &str = "registry-stack.yaml";
const BUILD_ROOT: &str = ".registry-stack/build";
const REVIEW_SCHEMA: &str = "registry.project.review.v1";
const APPROVAL_STATE_SCHEMA: &str = "registry.project.approval-state.v1";
const APPROVAL_REVIEW_PATH: &str = "approval/review.json";
const APPROVAL_STATE_PATH: &str = "approval/project-state.json";
const MAX_AUTHORED_FILE_BYTES: u64 = 1024 * 1024;
const MAX_LIVE_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_FIXTURES: usize = 128;
const MAX_OPERATIONS: usize = 16;
const MAX_OUTPUTS: usize = 64;
const MAX_CLAIMS: usize = 64;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleasedScriptRuntime {
    RhaiV1,
}

const RELEASED_SCRIPT_RUNTIMES: &[ReleasedScriptRuntime] = &[ReleasedScriptRuntime::RhaiV1];

// These ownership-oriented source units share this private module so the
// authoring compiler can retain one closed internal type system without a
// public API or visibility expansion.
include!("project_authoring/model.rs");
include!("project_authoring/authoring_contract.rs");
include!("project_authoring/commands.rs");
include!("project_authoring/compiler/artifacts.rs");
include!("project_authoring/compiler/relay.rs");
include!("project_authoring/compiler/notary.rs");
include!("project_authoring/project.rs");
include!("project_authoring/fixtures.rs");
include!("project_authoring/output.rs");
include!("project_authoring/tests.rs");

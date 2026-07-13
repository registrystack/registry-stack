// SPDX-License-Identifier: Apache-2.0
//! Deterministic country configuration authoring for Relay and Notary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::ValueEnum;
use registry_notary_core::StandaloneRegistryNotaryConfig;
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

static COUNTRY_STARTERS: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/assets/country-starters");
static DHIS2_TRACKER_STARTER: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/tests/fixtures/country-authoring/dhis2-tracker");
static OPENCRVS_STARTER: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/tests/fixtures/country-authoring/opencrvs");
static OPENSPP_STARTER: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/tests/fixtures/country-authoring/openspp-exact");

const PROJECT_FILE: &str = "registry-stack.yaml";
const BUILD_ROOT: &str = ".registry-stack/build";
const REVIEW_SCHEMA: &str = "registry.country.review.v1";
const MAX_AUTHORED_FILE_BYTES: u64 = 1024 * 1024;
const MAX_LIVE_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_FIXTURES: usize = 128;
const MAX_OPERATIONS: usize = 5;
const MAX_FACTS: usize = 64;
const MAX_CLAIMS: usize = 64;
const MAX_BOUNDED_INPUT_BYTES: u16 = 256;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleasedAuthoringCapability {
    SandboxedRhaiV1,
}

const RELEASED_AUTHORING_CAPABILITIES: &[ReleasedAuthoringCapability] =
    &[ReleasedAuthoringCapability::SandboxedRhaiV1];

// These ownership-oriented source units share this private module so the
// authoring compiler can retain one closed internal type system without a
// public API or visibility expansion.
include!("country_authoring/model.rs");
include!("country_authoring/commands.rs");
include!("country_authoring/compiler/artifacts.rs");
include!("country_authoring/compiler/relay.rs");
include!("country_authoring/compiler/notary.rs");
include!("country_authoring/project.rs");
include!("country_authoring/fixtures.rs");
include!("country_authoring/output.rs");
include!("country_authoring/tests.rs");

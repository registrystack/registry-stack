// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use registry_platform_config::{
    canonical_anchor_transition_payload, canonical_trust_anchor, load_trust_anchor,
    trust_anchor_digest, verify_anchor_transition, AnchorTransitionV1, ConfigBundleFile,
    ConfigBundleManifest, ConfigBundleSignature, ConfigBundleSignatureEnvelope, ConfigTrustAnchor,
    ConfigTrustAnchorSigner, ProductAcceptanceIdentityV1, ProductAcceptanceLaneV1,
    ProductAcceptanceProductV1, ProductTrustDomainV1, MAX_BUNDLE_FILE_BYTES,
    MAX_CONFIG_BUNDLE_SEQUENCE,
};
use registry_platform_crypto::{
    canonicalize_json, parse_json_strict, sign as sign_payload, PrivateJwk, PublicJwk,
    SigningAlgorithm, MAX_JWK_JSON_BYTES,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::Zeroizing;

const CONFIG_BUNDLE_SCHEMA: &str = "registry.platform.config_bundle.v1";
const CONFIG_BUNDLE_SIGNATURE_SCHEMA: &str = "registry.platform.config_bundle_signatures.v1";
const CONFIG_TRUST_ANCHOR_SCHEMA: &str = "registry.platform.config_trust_anchor.v1";
pub const SIGNING_INPUT_MARKER_FILE: &str = "signing-input.v1.json";
pub const SIGNING_INPUT_SCHEMA_ID: &str = "registry.stack.signing_input";
pub const SIGNING_INPUT_SCHEMA_VERSION: &str = "1.0";
const TRUST_ANCHOR_CREATE_REPORT_SCHEMA_VERSION: &str = "registryctl.trust_anchor_create_report.v1";
const TRUST_ANCHOR_ROTATE_REPORT_SCHEMA_VERSION: &str = "registryctl.trust_anchor_rotate_report.v1";
const PRODUCT_BUNDLE_SIGN_REPORT_SCHEMA_VERSION: &str = "registryctl.product_bundle_sign_report.v1";
const MAX_SIGNING_INPUT_FILES: usize = 4_096;
const MAX_SIGNING_INPUT_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SIGNING_INPUT_DEPTH: usize = 32;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningInputMarkerV1 {
    pub schema_id: String,
    pub schema_version: String,
    pub acceptance_identity: ProductAcceptanceIdentityV1,
}

impl SigningInputMarkerV1 {
    pub fn governed(acceptance_identity: ProductAcceptanceIdentityV1) -> Result<Self> {
        let marker = Self {
            schema_id: SIGNING_INPUT_SCHEMA_ID.to_string(),
            schema_version: SIGNING_INPUT_SCHEMA_VERSION.to_string(),
            acceptance_identity,
        };
        marker.validate()?;
        Ok(marker)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_id != SIGNING_INPUT_SCHEMA_ID {
            bail!("signing-input marker schema_id is unsupported");
        }
        if self.schema_version != SIGNING_INPUT_SCHEMA_VERSION {
            bail!("signing-input marker schema_version is unsupported");
        }
        self.acceptance_identity
            .validate()
            .context("signing-input acceptance identity is invalid")?;
        if self.acceptance_identity.trust_domain != ProductTrustDomainV1::Governed {
            bail!("signing-input marker must use the governed trust domain");
        }
        Ok(())
    }
}

pub(crate) fn canonical_signing_input_marker(marker: &SigningInputMarkerV1) -> Result<Vec<u8>> {
    marker.validate()?;
    let value = serde_json::to_value(marker).context("failed to serialize signing-input marker")?;
    let mut bytes =
        canonicalize_json(&value).context("failed to canonicalize signing-input marker")?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[derive(Debug, Clone)]
pub struct TrustAnchorCreateOptions {
    pub lane: ProductAcceptanceLaneV1,
    pub input: PathBuf,
    pub public_keys: Vec<PathBuf>,
    pub threshold: u32,
    pub output_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct TrustAnchorRotateOptions {
    pub current_anchor: PathBuf,
    pub next_public_keys: Vec<PathBuf>,
    pub next_threshold: u32,
    pub keys: Vec<String>,
    pub output_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ProductBundleSignOptions {
    pub lane: ProductAcceptanceLaneV1,
    pub input: PathBuf,
    pub anchor: PathBuf,
    pub keys: Vec<String>,
    pub output_dir: PathBuf,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchorCreateReportV1 {
    pub schema_version: &'static str,
    pub lane: ProductAcceptanceLaneV1,
    pub acceptance_identity: ProductAcceptanceIdentityV1,
    pub anchor_version: u64,
    pub threshold: u32,
    pub enabled_signer_kids: Vec<String>,
    pub anchor_digest: String,
    pub output_file: PathBuf,
    pub next_action: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchorRotateReportV1 {
    pub schema_version: &'static str,
    pub lane: ProductAcceptanceLaneV1,
    pub acceptance_identity: ProductAcceptanceIdentityV1,
    pub predecessor_anchor_version: u64,
    pub next_anchor_version: u64,
    pub threshold: u32,
    pub enabled_signer_kids: Vec<String>,
    pub authorizing_signer_kids: Vec<String>,
    pub anchor_digest: String,
    pub output_dir: PathBuf,
    pub next_action: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductBundleSignReportV1 {
    pub schema_version: &'static str,
    pub lane: ProductAcceptanceLaneV1,
    pub acceptance_identity: ProductAcceptanceIdentityV1,
    pub sequence: u64,
    pub config_hash: String,
    pub signer_kids: Vec<String>,
    pub anchor_digest: String,
    pub output_dir: PathBuf,
    pub next_action: &'static str,
}

pub fn create_trust_anchor(
    options: &TrustAnchorCreateOptions,
) -> Result<TrustAnchorCreateReportV1> {
    let marker = load_signing_input_marker(&options.input)?;
    validate_selected_lane(&marker.acceptance_identity, options.lane)?;
    validate_absent_output_file(&options.output_file)?;
    let enabled_signers = load_public_signer_set(&options.public_keys)?;
    let anchor = ConfigTrustAnchor {
        schema: CONFIG_TRUST_ANCHOR_SCHEMA.to_string(),
        acceptance_identity: marker.acceptance_identity.clone(),
        version: 1,
        threshold: options.threshold,
        enabled_signers,
    };
    anchor
        .validate_initial()
        .context("initial trust anchor is invalid")?;
    let bytes = canonical_trust_anchor(&anchor).context("failed to canonicalize trust anchor")?;
    atomic_write_new_file(&options.output_file, &bytes)?;
    Ok(TrustAnchorCreateReportV1 {
        schema_version: TRUST_ANCHOR_CREATE_REPORT_SCHEMA_VERSION,
        lane: options.lane,
        acceptance_identity: anchor.acceptance_identity.clone(),
        anchor_version: anchor.version,
        threshold: anchor.threshold,
        enabled_signer_kids: anchor
            .enabled_signers
            .iter()
            .map(|signer| signer.kid.clone())
            .collect(),
        anchor_digest: trust_anchor_digest(&anchor)
            .context("failed to digest created trust anchor")?,
        output_file: options.output_file.clone(),
        next_action: "sign this lane input with the matching private-key locator",
    })
}

pub fn rotate_trust_anchor(
    options: &TrustAnchorRotateOptions,
) -> Result<TrustAnchorRotateReportV1> {
    rotate_trust_anchor_with_resolver(options, resolve_private_key_locator)
}

fn rotate_trust_anchor_with_resolver(
    options: &TrustAnchorRotateOptions,
    mut resolve: impl FnMut(&KeyLocator) -> Result<Zeroizing<String>>,
) -> Result<TrustAnchorRotateReportV1> {
    let current = load_trust_anchor_input(&options.current_anchor)?;
    if current.acceptance_identity.trust_domain != ProductTrustDomainV1::Governed {
        bail!("current trust anchor must use the governed trust domain");
    }
    let next_version = current
        .version
        .checked_add(1)
        .filter(|version| *version <= MAX_CONFIG_BUNDLE_SEQUENCE)
        .ok_or_else(|| anyhow!("current trust anchor version cannot be advanced"))?;
    let next = ConfigTrustAnchor {
        schema: CONFIG_TRUST_ANCHOR_SCHEMA.to_string(),
        acceptance_identity: current.acceptance_identity.clone(),
        version: next_version,
        threshold: options.next_threshold,
        enabled_signers: load_public_signer_set(&options.next_public_keys)?,
    };
    let mut transition = AnchorTransitionV1::unsigned(&current, &next)
        .context("next trust anchor does not satisfy the authenticated rotation contract")?;
    let locators = parse_key_locators(&options.keys)?;
    if locators.len() < current.threshold as usize {
        bail!("anchor rotation requires at least the current threshold of key locators");
    }
    validate_absent_output_dir(&options.output_dir)?;

    // Identity, version, threshold, signer-set overlap, locator syntax, and
    // output posture are all established before the first private-key lookup.
    let payload = canonical_anchor_transition_payload(&transition)
        .context("failed to canonicalize anchor transition payload")?;
    let current_signer_kids = current
        .enabled_signers
        .iter()
        .map(|signer| signer.kid.as_str())
        .collect::<BTreeSet<_>>();
    let mut signatures = BTreeMap::new();
    for locator in &locators {
        let private_jwk_text = resolve(locator)?;
        let private_jwk =
            PrivateJwk::parse(&private_jwk_text).context("resolved signing key is invalid")?;
        let public_jwk = private_jwk.public();
        let kid = public_jwk
            .jkt()
            .context("failed to identify resolved signing key")?;
        if !current_signer_kids.contains(kid.as_str()) {
            bail!("resolved rotation key is not enabled by the current trust anchor");
        }
        if signatures.contains_key(&kid) {
            bail!("anchor rotation key locators resolved to a duplicate signer");
        }
        let alg =
            signing_algorithm_label(private_jwk.algorithm().context("resolved key is invalid")?);
        let signature =
            sign_payload(&payload, &private_jwk).context("failed to sign anchor transition")?;
        signatures.insert(
            kid.clone(),
            ConfigBundleSignature {
                kid,
                alg: alg.to_string(),
                sig: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature),
            },
        );
    }
    transition.signatures = signatures.into_values().collect();
    let authorizing_signer_kids = verify_anchor_transition(&current, &next, &transition)
        .context("generated anchor transition failed verification")?;

    let anchor_bytes =
        canonical_trust_anchor(&next).context("failed to canonicalize next trust anchor")?;
    let transition_bytes =
        canonical_json_line(&transition).context("failed to canonicalize anchor transition")?;
    atomic_write_new_directory(
        &options.output_dir,
        &[
            ("anchor.json", anchor_bytes.as_slice()),
            ("transition.json", transition_bytes.as_slice()),
        ],
    )?;
    Ok(TrustAnchorRotateReportV1 {
        schema_version: TRUST_ANCHOR_ROTATE_REPORT_SCHEMA_VERSION,
        lane: next.acceptance_identity.lane,
        acceptance_identity: next.acceptance_identity.clone(),
        predecessor_anchor_version: current.version,
        next_anchor_version: next.version,
        threshold: next.threshold,
        enabled_signer_kids: next
            .enabled_signers
            .iter()
            .map(|signer| signer.kid.clone())
            .collect(),
        authorizing_signer_kids,
        anchor_digest: trust_anchor_digest(&next).context("failed to digest next trust anchor")?,
        output_dir: options.output_dir.clone(),
        next_action:
            "retain the transition chain and use the new anchor for the next lane approval",
    })
}

pub fn sign_product_bundle(
    options: &ProductBundleSignOptions,
) -> Result<ProductBundleSignReportV1> {
    sign_product_bundle_with_resolver(options, resolve_private_key_locator)
}

fn sign_product_bundle_with_resolver(
    options: &ProductBundleSignOptions,
    mut resolve: impl FnMut(&KeyLocator) -> Result<Zeroizing<String>>,
) -> Result<ProductBundleSignReportV1> {
    let marker = load_signing_input_marker(&options.input)?;
    validate_selected_lane(&marker.acceptance_identity, options.lane)?;
    let anchor = load_trust_anchor_input(&options.anchor)?;
    if anchor.acceptance_identity != marker.acceptance_identity {
        bail!("signing input and trust anchor acceptance identities do not match");
    }
    let locators = parse_key_locators(&options.keys)?;
    if locators.len() < anchor.threshold as usize {
        bail!("bundle signing requires at least the anchor threshold of key locators");
    }
    validate_absent_output_dir(&options.output_dir)?;
    let file_backed_keys =
        validate_file_backed_keys_outside_signing_input(&locators, &options.input)?;
    let files = collect_signing_input_files(&options.input, &file_backed_keys)?;
    let primary_config_path = primary_config_path(options.lane, &files)?;
    let config_hash = files
        .iter()
        .find(|file| file.relative_path == primary_config_path)
        .map(|file| file.sha256.clone())
        .expect("primary config path is selected from the collected closure");
    let closure_digest = signing_input_closure_digest(&files);
    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("failed to format bundle creation time")?;
    let manifest = ConfigBundleManifest {
        schema: CONFIG_BUNDLE_SCHEMA.to_string(),
        acceptance_identity: marker.acceptance_identity.clone(),
        bundle_id: closure_digest,
        sequence: 1,
        previous_config_hash: None,
        config_hash: config_hash.clone(),
        files: files
            .iter()
            .map(|file| ConfigBundleFile {
                path: file.relative_path.clone(),
                sha256: file.sha256.clone(),
            })
            .collect(),
        created_at,
    };
    manifest
        .validate()
        .context("generated signed bundle manifest is invalid")?;
    let manifest_value =
        serde_json::to_value(&manifest).context("failed to serialize signed bundle manifest")?;
    let canonical_manifest =
        canonicalize_json(&manifest_value).context("failed to canonicalize bundle manifest")?;
    let enabled_signer_kids = anchor
        .enabled_signers
        .iter()
        .map(|signer| signer.kid.as_str())
        .collect::<BTreeSet<_>>();
    let mut signatures = BTreeMap::new();

    // The full identity, input closure, threshold, locator syntax, output
    // posture, and manifest contract are established before the first
    // private-key lookup.
    for locator in &locators {
        let private_jwk_text = resolve(locator)?;
        let private_jwk =
            PrivateJwk::parse(&private_jwk_text).context("resolved signing key is invalid")?;
        let kid = private_jwk
            .public()
            .jkt()
            .context("failed to identify resolved signing key")?;
        if !enabled_signer_kids.contains(kid.as_str()) {
            bail!("resolved signing key is not enabled by the selected lane anchor");
        }
        if signatures.contains_key(&kid) {
            bail!("bundle signing key locators resolved to a duplicate signer");
        }
        let signature = sign_payload(&canonical_manifest, &private_jwk)
            .context("failed to sign bundle manifest")?;
        signatures.insert(
            kid.clone(),
            ConfigBundleSignature {
                kid,
                alg: signing_algorithm_label(
                    private_jwk
                        .algorithm()
                        .context("resolved signing key is invalid")?,
                )
                .to_string(),
                sig: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature),
            },
        );
    }
    let signer_kids = signatures.keys().cloned().collect::<Vec<_>>();
    let envelope = ConfigBundleSignatureEnvelope {
        schema: CONFIG_BUNDLE_SIGNATURE_SCHEMA.to_string(),
        signatures: signatures.into_values().collect(),
    };
    let manifest_bytes =
        canonical_json_line(&manifest).context("failed to canonicalize bundle manifest")?;
    let envelope_bytes =
        canonical_json_line(&envelope).context("failed to canonicalize bundle signatures")?;
    let anchor_bytes =
        canonical_trust_anchor(&anchor).context("failed to canonicalize selected lane anchor")?;

    let staging = stage_output_directory(&options.output_dir)?;
    let bundle_root = staging.path().join("bundle");
    create_owner_only_dir(&bundle_root)?;
    for file in &files {
        write_new_private_file(&bundle_root.join(&file.relative_path), &file.bytes)?;
    }
    write_new_private_file(&bundle_root.join("manifest.json"), &manifest_bytes)?;
    write_new_private_file(&bundle_root.join("manifest.sig.json"), &envelope_bytes)?;
    let staged_anchor = staging.path().join("anchor.json");
    write_new_private_file(&staged_anchor, &anchor_bytes)?;
    let verified = registry_platform_config::verify_config_bundle(&bundle_root, &staged_anchor)
        .context("generated bundle failed pre-publication self-verification")?;
    if verified.signer_kids != signer_kids {
        bail!("generated bundle self-verification returned an inconsistent signer set");
    }
    publish_staged_directory(staging, &options.output_dir)?;

    Ok(ProductBundleSignReportV1 {
        schema_version: PRODUCT_BUNDLE_SIGN_REPORT_SCHEMA_VERSION,
        lane: options.lane,
        acceptance_identity: marker.acceptance_identity,
        sequence: manifest.sequence,
        config_hash,
        signer_kids,
        anchor_digest: trust_anchor_digest(&anchor)
            .context("failed to digest selected lane anchor")?,
        output_dir: options.output_dir.clone(),
        next_action: "assemble or update the three-lane approved set",
    })
}

pub fn load_signing_input_marker(input: &Path) -> Result<SigningInputMarkerV1> {
    let marker: SigningInputMarkerV1 =
        read_bounded_strict_json_file(&input.join(SIGNING_INPUT_MARKER_FILE), 16 * 1024, false)
            .context("failed to load signing-input marker")?;
    marker.validate()?;
    Ok(marker)
}

fn validate_selected_lane(
    identity: &ProductAcceptanceIdentityV1,
    selected: ProductAcceptanceLaneV1,
) -> Result<()> {
    if identity.lane != selected {
        bail!("selected signing lane does not match the signing-input acceptance identity");
    }
    let expected_product = match selected {
        ProductAcceptanceLaneV1::RelayPublic | ProductAcceptanceLaneV1::RelayConsultation => {
            ProductAcceptanceProductV1::RegistryRelay
        }
        ProductAcceptanceLaneV1::Notary => ProductAcceptanceProductV1::RegistryNotary,
    };
    if identity.product != expected_product {
        bail!("selected signing lane does not match the acceptance-identity product");
    }
    if identity.trust_domain != ProductTrustDomainV1::Governed {
        bail!("selected signing input must use the governed trust domain");
    }
    Ok(())
}

fn load_public_signer_set(paths: &[PathBuf]) -> Result<Vec<ConfigTrustAnchorSigner>> {
    if paths.is_empty() {
        bail!("a trust anchor requires at least one public key");
    }
    let mut signers = BTreeMap::new();
    for path in paths {
        let text = read_bounded_utf8_file_no_follow(path, MAX_JWK_JSON_BYTES, false)
            .context("failed to read a public JWK input")?;
        let jwk = PublicJwk::parse(&text).context("public JWK input is invalid")?;
        let kid = jwk.jkt().context("failed to identify public JWK input")?;
        if signers.insert(kid.clone(), jwk).is_some() {
            bail!("public JWK inputs contain a duplicate signer");
        }
    }
    Ok(signers
        .into_iter()
        .map(|(kid, jwk)| ConfigTrustAnchorSigner { kid, jwk })
        .collect())
}

fn load_trust_anchor_input(path: &Path) -> Result<ConfigTrustAnchor> {
    load_trust_anchor(path).context("failed to load bounded trust anchor input")
}

#[derive(Debug)]
struct SigningInputFile {
    relative_path: String,
    bytes: Vec<u8>,
    sha256: String,
}

#[derive(Debug)]
struct SigningInputBudget {
    files: usize,
    total_bytes: u64,
}

impl SigningInputBudget {
    fn add_file(&mut self, bytes: u64) -> Result<()> {
        self.files = self
            .files
            .checked_add(1)
            .ok_or_else(|| anyhow!("signing-input closure file count overflowed"))?;
        if self.files > MAX_SIGNING_INPUT_FILES {
            bail!(
                "signing-input closure exceeds the {MAX_SIGNING_INPUT_FILES}-file limit; remove generated or unrelated files before signing"
            );
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow!("signing-input closure byte count overflowed"))?;
        if self.total_bytes > MAX_SIGNING_INPUT_TOTAL_BYTES {
            bail!(
                "signing-input closure exceeds the {MAX_SIGNING_INPUT_TOTAL_BYTES}-byte total limit; remove generated or unrelated files before signing"
            );
        }
        Ok(())
    }
}

#[derive(Debug)]
struct FileBackedKeyIdentity {
    canonical_path: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl FileBackedKeyIdentity {
    fn matches(&self, path: &Path, metadata: &fs::Metadata) -> Result<bool> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            if self.device == metadata.dev() && self.inode == metadata.ino() {
                return Ok(true);
            }
        }
        Ok(
            fs::canonicalize(path).context("failed to resolve signing-input closure entry")?
                == self.canonical_path,
        )
    }
}

fn validate_file_backed_keys_outside_signing_input(
    locators: &[KeyLocator],
    input: &Path,
) -> Result<Vec<FileBackedKeyIdentity>> {
    let canonical_input =
        fs::canonicalize(input).context("failed to resolve signing-input directory")?;
    let mut identities = Vec::new();
    for locator in locators {
        let KeyLocator::File(path) = locator else {
            continue;
        };
        let file = open_read_only_no_follow(path)
            .context("failed to inspect file: signing key before closure validation")?;
        let metadata = validate_open_regular_file(&file, true)
            .context("file: signing key is unsafe before closure validation")?;
        let canonical_path =
            fs::canonicalize(path).context("failed to resolve file: signing key")?;
        if canonical_path.starts_with(&canonical_input) {
            bail!(
                "file: signing key must be outside the signing-input directory; move the private key outside the generated input and retry"
            );
        }
        identities.push(FileBackedKeyIdentity {
            canonical_path,
            #[cfg(unix)]
            device: {
                use std::os::unix::fs::MetadataExt as _;
                metadata.dev()
            },
            #[cfg(unix)]
            inode: {
                use std::os::unix::fs::MetadataExt as _;
                metadata.ino()
            },
        });
    }
    Ok(identities)
}

fn collect_signing_input_files(
    input: &Path,
    file_backed_keys: &[FileBackedKeyIdentity],
) -> Result<Vec<SigningInputFile>> {
    let mut files = Vec::new();
    let mut budget = SigningInputBudget {
        files: 0,
        total_bytes: 0,
    };
    collect_signing_input_files_under(input, input, 0, file_backed_keys, &mut budget, &mut files)?;
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    if files.is_empty() {
        bail!("signing-input directory contains no regular files");
    }
    if !files
        .iter()
        .any(|file| file.relative_path == SIGNING_INPUT_MARKER_FILE)
    {
        bail!("signing-input closure does not contain its identity marker");
    }
    Ok(files)
}

fn collect_signing_input_files_under(
    root: &Path,
    directory: &Path,
    depth: usize,
    file_backed_keys: &[FileBackedKeyIdentity],
    budget: &mut SigningInputBudget,
    files: &mut Vec<SigningInputFile>,
) -> Result<()> {
    if depth > MAX_SIGNING_INPUT_DEPTH {
        bail!(
            "signing-input closure exceeds the {MAX_SIGNING_INPUT_DEPTH}-directory depth limit; flatten the generated input before signing"
        );
    }
    let metadata =
        fs::symlink_metadata(directory).context("failed to inspect signing-input directory")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("signing-input closure must contain only real directories and regular files");
    }
    let mut entries = fs::read_dir(directory)
        .context("failed to enumerate signing-input directory")?
        .collect::<std::io::Result<Vec<_>>>()
        .context("failed to enumerate signing-input directory")?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).context("failed to inspect signing-input closure entry")?;
        if metadata.file_type().is_symlink() {
            bail!("signing-input closure must not contain symbolic links");
        }
        if metadata.is_dir() {
            collect_signing_input_files_under(
                root,
                &path,
                depth + 1,
                file_backed_keys,
                budget,
                files,
            )?;
            continue;
        }
        if !metadata.is_file() {
            bail!("signing-input closure contains an unsupported file type");
        }
        if metadata.len() > MAX_BUNDLE_FILE_BYTES {
            bail!("signing-input file exceeds the bundle file size limit");
        }
        for key in file_backed_keys {
            if key.matches(&path, &metadata)? {
                bail!(
                    "signing-input closure contains a file: signing key; move the private key outside the generated input and retry"
                );
            }
        }
        budget.add_file(metadata.len())?;
        let relative_path = normalized_relative_path(root, &path)?;
        if matches!(
            relative_path.as_str(),
            "manifest.json" | "manifest.sig.json"
        ) {
            bail!("signing-input closure contains a reserved bundle filename");
        }
        let bytes = read_bounded_file_no_follow(&path, MAX_BUNDLE_FILE_BYTES, false)
            .context("failed to read signing-input closure entry")?;
        if bytes.len() as u64 != metadata.len() {
            bail!("signing-input closure changed while it was being validated; retry with a stable input directory");
        }
        if std::str::from_utf8(&bytes)
            .ok()
            .is_some_and(|text| PrivateJwk::parse(text).is_ok())
        {
            bail!(
                "signing-input closure contains private JWK material; remove the private key from the generated input and retry"
            );
        }
        files.push(SigningInputFile {
            sha256: registry_platform_config::sha256_uri(&bytes),
            relative_path,
            bytes,
        });
    }
    Ok(())
}

fn primary_config_path(
    lane: ProductAcceptanceLaneV1,
    files: &[SigningInputFile],
) -> Result<String> {
    let expected = match lane {
        ProductAcceptanceLaneV1::RelayPublic | ProductAcceptanceLaneV1::RelayConsultation => {
            "config/relay.yaml"
        }
        ProductAcceptanceLaneV1::Notary => "config/notary.yaml",
    };
    if !files.iter().any(|file| file.relative_path == expected) {
        bail!("signing-input closure lacks the selected lane's primary product configuration");
    }
    Ok(expected.to_string())
}

fn signing_input_closure_digest(files: &[SigningInputFile]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.relative_path.as_bytes());
        hasher.update([0]);
        hasher.update(file.sha256.as_bytes());
        hasher.update([b'\n']);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[derive(Debug)]
enum KeyLocator {
    File(PathBuf),
    OnePassword(String),
}

impl KeyLocator {
    fn parse(raw: &str) -> Result<Self> {
        if let Some(path) = raw.strip_prefix("file:") {
            if path.is_empty() {
                bail!("file: signing key locator is empty");
            }
            return Ok(Self::File(PathBuf::from(path)));
        }
        if raw.starts_with("op://") {
            if raw.len() == "op://".len() {
                bail!("op:// signing key locator is empty");
            }
            return Ok(Self::OnePassword(raw.to_string()));
        }
        bail!("signing key locator must use the explicit file: or op:// scheme");
    }
}

fn parse_key_locators(raw: &[String]) -> Result<Vec<KeyLocator>> {
    if raw.is_empty() {
        bail!("at least one signing key locator is required");
    }
    raw.iter().map(|value| KeyLocator::parse(value)).collect()
}

fn resolve_private_key_locator(locator: &KeyLocator) -> Result<Zeroizing<String>> {
    match locator {
        KeyLocator::File(path) => read_bounded_utf8_file_no_follow(path, MAX_JWK_JSON_BYTES, true)
            .context("failed to resolve file: signing key"),
        KeyLocator::OnePassword(reference) => {
            let mut child = Command::new("op")
                .arg("read")
                .arg(reference)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("failed to start op read for signing key")?;
            let Some(stdout) = child.stdout.take() else {
                let _ = child.kill();
                let _ = child.wait();
                bail!("op read did not provide a signing-key output pipe");
            };
            let bytes = match read_bounded_zeroizing(stdout, MAX_JWK_JSON_BYTES) {
                Ok(bytes) => bytes,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error.context("failed to read bounded op signing-key output"));
                }
            };
            let status = child.wait().context("failed to wait for op read")?;
            if !status.success() {
                bail!("op read failed for signing key locator");
            }
            zeroizing_utf8(bytes).context("op signing key is not UTF-8 JSON")
        }
    }
}

fn read_bounded_strict_json_file<T>(path: &Path, max_bytes: u64, owner_only: bool) -> Result<T>
where
    T: DeserializeOwned,
{
    let bytes = read_bounded_file_no_follow(path, max_bytes, owner_only)?;
    let value = parse_json_strict(&bytes).context("JSON input is invalid")?;
    serde_json::from_value(value).context("JSON input has an invalid contract")
}

fn read_bounded_utf8_file_no_follow(
    path: &Path,
    max_bytes: usize,
    owner_only: bool,
) -> Result<Zeroizing<String>> {
    let file = open_read_only_no_follow(path)?;
    validate_open_regular_file(&file, owner_only)?;
    let bytes = read_bounded_zeroizing(file, max_bytes)?;
    zeroizing_utf8(bytes)
}

fn read_bounded_file_no_follow(path: &Path, max_bytes: u64, owner_only: bool) -> Result<Vec<u8>> {
    let mut file = open_read_only_no_follow(path)?;
    let metadata = validate_open_regular_file(&file, owner_only)?;
    if metadata.len() > max_bytes {
        bail!("input file exceeds its size limit");
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .context("failed to read bounded input file")?;
    if bytes.len() as u64 > max_bytes {
        bail!("input file exceeds its size limit");
    }
    Ok(bytes)
}

fn read_bounded_zeroizing(reader: impl Read, max_bytes: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .context("failed to read signing key")?;
    if bytes.len() > max_bytes {
        bail!("signing key exceeds its size limit");
    }
    Ok(bytes)
}

fn zeroizing_utf8(bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>> {
    let text = std::str::from_utf8(&bytes).context("input is not UTF-8")?;
    Ok(Zeroizing::new(text.to_owned()))
}

#[cfg(unix)]
fn open_read_only_no_follow(path: &Path) -> Result<File> {
    use rustix::fs::{Mode, OFlags};

    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .context("failed to open bounded input")?;
    Ok(File::from(fd))
}

#[cfg(not(unix))]
fn open_read_only_no_follow(path: &Path) -> Result<File> {
    let metadata = fs::symlink_metadata(path).context("failed to inspect bounded input")?;
    if metadata.file_type().is_symlink() {
        bail!("bounded input must not be a symbolic link");
    }
    File::open(path).context("failed to open bounded input")
}

fn validate_open_regular_file(file: &File, owner_only: bool) -> Result<fs::Metadata> {
    let metadata = file.metadata().context("failed to inspect open input")?;
    if !metadata.is_file() {
        bail!("bounded input must be a regular file");
    }
    validate_owner_only_permissions(&metadata, owner_only)?;
    Ok(metadata)
}

#[cfg(unix)]
fn validate_owner_only_permissions(metadata: &fs::Metadata, required: bool) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !required {
        return Ok(());
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("file: signing key must be owner-only");
    }
    let current_uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != current_uid {
        bail!("file: signing key must be owned by the current user");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_only_permissions(_metadata: &fs::Metadata, _required: bool) -> Result<()> {
    Ok(())
}

fn normalized_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .context("signing-input closure entry escaped its root")?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            bail!("signing-input closure path is not normalized");
        };
        let part = part
            .to_str()
            .ok_or_else(|| anyhow!("signing-input closure path is not valid UTF-8"))?;
        if part.is_empty() || matches!(part, "." | "..") {
            bail!("signing-input closure path is not normalized");
        }
        parts.push(part);
    }
    if parts.is_empty() {
        bail!("signing-input closure path is empty");
    }
    Ok(parts.join("/"))
}

fn validate_absent_output_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("immutable trust-anchor output file already exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to inspect trust-anchor output"),
    }
}

fn validate_absent_output_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("immutable trust output directory already exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to inspect output directory"),
    }
}

fn atomic_write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    validate_absent_output_file(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        bail!("trust-anchor output parent must already exist");
    }
    let mut staged =
        tempfile::NamedTempFile::new_in(parent).context("failed to stage trust-anchor output")?;
    staged
        .write_all(bytes)
        .context("failed to stage trust-anchor output")?;
    staged
        .as_file()
        .sync_all()
        .context("failed to sync trust-anchor output")?;
    staged
        .persist_noclobber(path)
        .map_err(|error| error.error)
        .context("failed to publish immutable trust-anchor output")?;
    Ok(())
}

fn atomic_write_new_directory(output: &Path, files: &[(&str, &[u8])]) -> Result<()> {
    let staging = stage_output_directory(output)?;
    for (name, bytes) in files {
        write_new_private_file(&staging.path().join(name), bytes)?;
    }
    publish_staged_directory(staging, output)
}

fn stage_output_directory(output: &Path) -> Result<tempfile::TempDir> {
    validate_absent_output_dir(output)?;
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        bail!("output directory parent must already exist");
    }
    tempfile::Builder::new()
        .prefix(".registryctl-trust-stage-")
        .tempdir_in(parent)
        .context("failed to stage immutable trust output")
}

fn publish_staged_directory(staging: tempfile::TempDir, output: &Path) -> Result<()> {
    let staged = staging.keep();
    if let Err(error) = rename_noreplace(&staged, output) {
        let _ = fs::remove_dir_all(&staged);
        return Err(error).context("failed to publish immutable trust output");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

#[cfg(windows)]
fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
fn rename_noreplace(_source: &Path, _destination: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace trust-output publication is unsupported",
    ))
}

fn create_owner_only_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .context("failed to create staged trust-output directory")
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_owner_only_dir(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("failed to create staged trust-output file")?;
    file.write_all(bytes)
        .context("failed to write staged trust-output file")?;
    file.sync_all()
        .context("failed to sync staged trust-output file")
}

fn canonical_json_line<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).context("failed to serialize canonical JSON")?;
    let mut bytes = canonicalize_json(&value).context("failed to canonicalize JSON")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn signing_algorithm_label(algorithm: SigningAlgorithm) -> &'static str {
    match algorithm {
        SigningAlgorithm::EdDsa => "EdDSA",
        SigningAlgorithm::Es256 => "ES256",
        SigningAlgorithm::Rs256 => "RS256",
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use registry_platform_config::parse_anchor_transition;

    const TEST_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;
    const TEST_PRIVATE_JWK_2: &str = r#"{"crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA","kid":"registryctl-test-private-key-2"}"#;

    fn identity(lane: ProductAcceptanceLaneV1) -> ProductAcceptanceIdentityV1 {
        ProductAcceptanceIdentityV1 {
            trust_domain: ProductTrustDomainV1::Governed,
            project: "civil-registry".to_string(),
            environment: "production".to_string(),
            lane,
            product: match lane {
                ProductAcceptanceLaneV1::RelayPublic
                | ProductAcceptanceLaneV1::RelayConsultation => {
                    ProductAcceptanceProductV1::RegistryRelay
                }
                ProductAcceptanceLaneV1::Notary => ProductAcceptanceProductV1::RegistryNotary,
            },
            stream: "civil-registry".to_string(),
            instance: match lane {
                ProductAcceptanceLaneV1::RelayPublic => "relay".to_string(),
                ProductAcceptanceLaneV1::RelayConsultation => "relay-consultation".to_string(),
                ProductAcceptanceLaneV1::Notary => "notary".to_string(),
            },
        }
    }

    fn signer() -> ConfigTrustAnchorSigner {
        signer_from(TEST_PRIVATE_JWK)
    }

    fn signer_from(private_jwk: &str) -> ConfigTrustAnchorSigner {
        let private = PrivateJwk::parse(private_jwk).expect("private key parses");
        let jwk = private.public();
        let kid = jwk.jkt().expect("public key identifies");
        ConfigTrustAnchorSigner { kid, jwk }
    }

    fn write_signing_input(root: &Path, identity: ProductAcceptanceIdentityV1) {
        let config = match identity.lane {
            ProductAcceptanceLaneV1::RelayPublic | ProductAcceptanceLaneV1::RelayConsultation => {
                "config/relay.yaml"
            }
            ProductAcceptanceLaneV1::Notary => "config/notary.yaml",
        };
        fs::create_dir_all(root.join("config")).expect("config directory creates");
        fs::write(root.join(config), b"instance:\n  id: synthetic\n").expect("config writes");
        let marker = SigningInputMarkerV1::governed(identity).expect("marker is valid");
        fs::write(
            root.join(SIGNING_INPUT_MARKER_FILE),
            canonical_signing_input_marker(&marker).expect("marker canonicalizes"),
        )
        .expect("marker writes");
    }

    fn write_anchor(path: &Path, identity: ProductAcceptanceIdentityV1) -> ConfigTrustAnchor {
        let anchor = ConfigTrustAnchor {
            schema: CONFIG_TRUST_ANCHOR_SCHEMA.to_string(),
            acceptance_identity: identity,
            version: 1,
            threshold: 1,
            enabled_signers: vec![signer()],
        };
        fs::write(
            path,
            canonical_trust_anchor(&anchor).expect("anchor canonicalizes"),
        )
        .expect("anchor writes");
        anchor
    }

    #[test]
    fn signing_input_marker_is_canonical_and_binds_every_identity_dimension() {
        let marker =
            SigningInputMarkerV1::governed(identity(ProductAcceptanceLaneV1::Notary)).unwrap();
        let first = canonical_signing_input_marker(&marker).unwrap();
        let second = canonical_signing_input_marker(&marker).unwrap();
        assert_eq!(first, second);
        let value: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(
            value["acceptance_identity"],
            serde_json::json!({
                "trust_domain": "governed",
                "project": "civil-registry",
                "environment": "production",
                "lane": "notary",
                "product": "registry-notary",
                "stream": "civil-registry",
                "instance": "notary",
            })
        );
    }

    #[test]
    fn signing_rejects_swapped_lane_and_every_identity_mismatch_without_key_resolution() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        write_signing_input(&input, identity(ProductAcceptanceLaneV1::Notary));
        let anchor_path = temp.path().join("anchor.json");
        let base = identity(ProductAcceptanceLaneV1::Notary);
        write_anchor(&anchor_path, base.clone());

        let cases = [
            ("trust_domain", {
                let mut value = base.clone();
                value.trust_domain = ProductTrustDomainV1::Development;
                value
            }),
            ("project", {
                let mut value = base.clone();
                value.project.push_str("-other");
                value
            }),
            ("environment", {
                let mut value = base.clone();
                value.environment.push_str("-other");
                value
            }),
            ("lane", identity(ProductAcceptanceLaneV1::RelayPublic)),
            ("product", {
                let mut value = base.clone();
                value.product = ProductAcceptanceProductV1::RegistryRelay;
                value
            }),
            ("stream", {
                let mut value = base.clone();
                value.stream.push_str("-other");
                value
            }),
            ("instance", {
                let mut value = base.clone();
                value.instance.push_str("-other");
                value
            }),
        ];
        for (field, changed) in cases {
            let changed_anchor = temp.path().join(format!("{field}.anchor.json"));
            if changed.validate().is_ok() {
                write_anchor(&changed_anchor, changed);
            } else {
                let mut anchor = write_anchor(&changed_anchor, base.clone());
                anchor.acceptance_identity = changed;
                fs::write(
                    &changed_anchor,
                    canonical_json_line(&anchor).expect("invalid anchor serializes"),
                )
                .unwrap();
            }
            let calls = Cell::new(0);
            let error = sign_product_bundle_with_resolver(
                &ProductBundleSignOptions {
                    lane: ProductAcceptanceLaneV1::Notary,
                    input: input.clone(),
                    anchor: changed_anchor,
                    keys: vec!["op://vault/item/key".to_string()],
                    output_dir: temp.path().join(format!("{field}.output")),
                },
                |_| {
                    calls.set(calls.get() + 1);
                    Ok(Zeroizing::new(TEST_PRIVATE_JWK.to_string()))
                },
            )
            .expect_err("identity mismatch must fail");
            assert_eq!(calls.get(), 0, "{field} resolved a private key: {error:#}");
        }

        let calls = Cell::new(0);
        let error = sign_product_bundle_with_resolver(
            &ProductBundleSignOptions {
                lane: ProductAcceptanceLaneV1::RelayPublic,
                input,
                anchor: anchor_path,
                keys: vec!["op://vault/item/key".to_string()],
                output_dir: temp.path().join("swapped-lane.output"),
            },
            |_| {
                calls.set(calls.get() + 1);
                Ok(Zeroizing::new(TEST_PRIVATE_JWK.to_string()))
            },
        )
        .expect_err("swapped selected lane must fail");
        assert_eq!(calls.get(), 0);
        assert!(format!("{error:#}").contains("selected signing lane"));
    }

    #[test]
    fn anchor_create_sorts_keys_and_refuses_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        write_signing_input(&input, identity(ProductAcceptanceLaneV1::Notary));
        let public = signer().jwk;
        let first = temp.path().join("first.jwk");
        let second = temp.path().join("second.jwk");
        fs::write(&first, serde_json::to_vec(&public).unwrap()).unwrap();
        fs::write(&second, serde_json::to_vec(&public).unwrap()).unwrap();
        let output = temp.path().join("anchor.json");
        let error = create_trust_anchor(&TrustAnchorCreateOptions {
            lane: ProductAcceptanceLaneV1::Notary,
            input: input.clone(),
            public_keys: vec![second, first],
            threshold: 1,
            output_file: output.clone(),
        })
        .expect_err("duplicate key set must fail");
        assert!(format!("{error:#}").contains("duplicate"));

        let public_path = temp.path().join("public.jwk");
        fs::write(&public_path, serde_json::to_vec(&public).unwrap()).unwrap();
        create_trust_anchor(&TrustAnchorCreateOptions {
            lane: ProductAcceptanceLaneV1::Notary,
            input: input.clone(),
            public_keys: vec![public_path.clone()],
            threshold: 1,
            output_file: output.clone(),
        })
        .expect("initial anchor creates");
        let before = fs::read(&output).unwrap();
        create_trust_anchor(&TrustAnchorCreateOptions {
            lane: ProductAcceptanceLaneV1::Notary,
            input,
            public_keys: vec![public_path],
            threshold: 1,
            output_file: output.clone(),
        })
        .expect_err("immutable anchor must not be overwritten");
        assert_eq!(fs::read(output).unwrap(), before);
    }

    #[test]
    fn bundle_signing_enforces_threshold_distinctness_and_self_verifies() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        let identity = identity(ProductAcceptanceLaneV1::Notary);
        write_signing_input(&input, identity.clone());
        let anchor_path = temp.path().join("anchor.json");
        let mut enabled_signers = vec![
            signer_from(TEST_PRIVATE_JWK),
            signer_from(TEST_PRIVATE_JWK_2),
        ];
        enabled_signers.sort_by(|left, right| left.kid.cmp(&right.kid));
        let anchor = ConfigTrustAnchor {
            schema: CONFIG_TRUST_ANCHOR_SCHEMA.to_string(),
            acceptance_identity: identity,
            version: 1,
            threshold: 2,
            enabled_signers,
        };
        fs::write(
            &anchor_path,
            canonical_trust_anchor(&anchor).expect("threshold anchor canonicalizes"),
        )
        .unwrap();

        let calls = Cell::new(0);
        let error = sign_product_bundle_with_resolver(
            &ProductBundleSignOptions {
                lane: ProductAcceptanceLaneV1::Notary,
                input: input.clone(),
                anchor: anchor_path.clone(),
                keys: vec!["op://vault/item/first".to_string()],
                output_dir: temp.path().join("insufficient"),
            },
            |_| {
                calls.set(calls.get() + 1);
                Ok(Zeroizing::new(TEST_PRIVATE_JWK.to_string()))
            },
        )
        .expect_err("fewer locators than the threshold must fail");
        assert_eq!(calls.get(), 0);
        assert!(format!("{error:#}").contains("threshold"));

        let duplicate_output = temp.path().join("duplicate");
        let error = sign_product_bundle_with_resolver(
            &ProductBundleSignOptions {
                lane: ProductAcceptanceLaneV1::Notary,
                input: input.clone(),
                anchor: anchor_path.clone(),
                keys: vec![
                    "op://vault/item/first".to_string(),
                    "op://vault/item/duplicate".to_string(),
                ],
                output_dir: duplicate_output.clone(),
            },
            |_| Ok(Zeroizing::new(TEST_PRIVATE_JWK.to_string())),
        )
        .expect_err("duplicate resolved signer must not satisfy threshold");
        assert!(format!("{error:#}").contains("duplicate signer"));
        assert!(!duplicate_output.exists());

        let output = temp.path().join("signed");
        let report = sign_product_bundle_with_resolver(
            &ProductBundleSignOptions {
                lane: ProductAcceptanceLaneV1::Notary,
                input,
                anchor: anchor_path,
                keys: vec![
                    "op://vault/item/second".to_string(),
                    "op://vault/item/first".to_string(),
                ],
                output_dir: output.clone(),
            },
            |locator| match locator {
                KeyLocator::OnePassword(reference) if reference.ends_with("/first") => {
                    Ok(Zeroizing::new(TEST_PRIVATE_JWK.to_string()))
                }
                KeyLocator::OnePassword(reference) if reference.ends_with("/second") => {
                    Ok(Zeroizing::new(TEST_PRIVATE_JWK_2.to_string()))
                }
                _ => panic!("unexpected test key locator"),
            },
        )
        .expect("threshold bundle signs and self-verifies");
        assert_eq!(report.signer_kids.len(), 2);
        assert!(report.signer_kids.windows(2).all(|pair| pair[0] < pair[1]));
        let verified = registry_platform_config::verify_config_bundle(
            output.join("bundle"),
            output.join("anchor.json"),
        )
        .expect("published threshold bundle verifies");
        assert_eq!(verified.signer_kids, report.signer_kids);
    }

    #[test]
    fn rotation_rejects_bad_threshold_and_overlap_before_key_resolution() {
        let temp = tempfile::tempdir().unwrap();
        let current_path = temp.path().join("current.json");
        let current = write_anchor(
            &current_path,
            identity(ProductAcceptanceLaneV1::RelayConsultation),
        );
        let unrelated_private = PrivateJwk::parse(TEST_PRIVATE_JWK_2).unwrap();
        let unrelated_public = unrelated_private.public();
        let next_public_path = temp.path().join("next.jwk");
        fs::write(
            &next_public_path,
            serde_json::to_vec(&unrelated_public).unwrap(),
        )
        .unwrap();
        let calls = Cell::new(0);
        let error = rotate_trust_anchor_with_resolver(
            &TrustAnchorRotateOptions {
                current_anchor: current_path.clone(),
                next_public_keys: vec![next_public_path.clone()],
                next_threshold: 1,
                keys: vec!["op://vault/item/key".to_string()],
                output_dir: temp.path().join("no-overlap"),
            },
            |_| {
                calls.set(calls.get() + 1);
                Ok(Zeroizing::new(TEST_PRIVATE_JWK.to_string()))
            },
        )
        .expect_err("rotation without current-threshold overlap must fail");
        assert_eq!(calls.get(), 0);
        assert!(format!("{error:#}").contains("overlap"));

        let current_public_path = temp.path().join("current.jwk");
        fs::write(
            &current_public_path,
            serde_json::to_vec(&current.enabled_signers[0].jwk).unwrap(),
        )
        .unwrap();
        let calls = Cell::new(0);
        rotate_trust_anchor_with_resolver(
            &TrustAnchorRotateOptions {
                current_anchor: current_path,
                next_public_keys: vec![current_public_path],
                next_threshold: 2,
                keys: vec!["op://vault/item/key".to_string()],
                output_dir: temp.path().join("bad-threshold"),
            },
            |_| {
                calls.set(calls.get() + 1);
                Ok(Zeroizing::new(TEST_PRIVATE_JWK.to_string()))
            },
        )
        .expect_err("next threshold above signer count must fail");
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn rotation_writes_fresh_verified_transition_and_wrong_predecessor_fails() {
        let temp = tempfile::tempdir().unwrap();
        let current_path = temp.path().join("current.json");
        let current = write_anchor(&current_path, identity(ProductAcceptanceLaneV1::Notary));
        let public_path = temp.path().join("current.jwk");
        fs::write(
            &public_path,
            serde_json::to_vec(&current.enabled_signers[0].jwk).unwrap(),
        )
        .unwrap();
        let output = temp.path().join("rotation");
        let report = rotate_trust_anchor_with_resolver(
            &TrustAnchorRotateOptions {
                current_anchor: current_path,
                next_public_keys: vec![public_path],
                next_threshold: 1,
                keys: vec!["op://vault/item/key".to_string()],
                output_dir: output.clone(),
            },
            |_| Ok(Zeroizing::new(TEST_PRIVATE_JWK.to_string())),
        )
        .expect("overlap rotation succeeds");
        assert_eq!(report.predecessor_anchor_version, 1);
        assert_eq!(report.next_anchor_version, 2);
        let next: ConfigTrustAnchor =
            serde_json::from_slice(&fs::read(output.join("anchor.json")).unwrap()).unwrap();
        let transition =
            parse_anchor_transition(&fs::read(output.join("transition.json")).unwrap()).unwrap();
        verify_anchor_transition(&current, &next, &transition).expect("transition verifies");

        let mut wrong_predecessor = current;
        wrong_predecessor.version = 2;
        let error = verify_anchor_transition(&wrong_predecessor, &next, &transition)
            .expect_err("wrong predecessor must fail");
        assert!(format!("{error}").contains("predecessor"));
    }

    #[test]
    fn key_locator_errors_and_reports_do_not_leak_locator_values() {
        const SENTINEL: &str = "private-path-sentinel";
        let error = KeyLocator::parse(&format!("/tmp/{SENTINEL}.jwk")).unwrap_err();
        assert!(!format!("{error:#}").contains(SENTINEL));

        let locator = KeyLocator::parse(&format!("file:/missing/{SENTINEL}.jwk")).unwrap();
        let error = resolve_private_key_locator(&locator).unwrap_err();
        assert!(!format!("{error:#}").contains(SENTINEL));
    }

    #[test]
    fn file_backed_private_key_inside_signing_input_is_rejected_before_resolution_or_copy() {
        const PRIVATE_KEY_CANARY: &str = "registryctl-private-key-copy-canary";

        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        let acceptance_identity = identity(ProductAcceptanceLaneV1::Notary);
        write_signing_input(&input, acceptance_identity.clone());
        let anchor_path = temp.path().join("anchor.json");
        write_anchor(&anchor_path, acceptance_identity);
        let private_key = input.join("private-key.jwk");
        fs::write(
            &private_key,
            TEST_PRIVATE_JWK.replace("registryctl-test-private-key", PRIVATE_KEY_CANARY),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mut permissions = fs::metadata(&private_key).unwrap().permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&private_key, permissions).unwrap();
        }
        let output = temp.path().join("signed");
        let calls = Cell::new(0);
        let error = sign_product_bundle_with_resolver(
            &ProductBundleSignOptions {
                lane: ProductAcceptanceLaneV1::Notary,
                input,
                anchor: anchor_path,
                keys: vec![format!("file:{}", private_key.display())],
                output_dir: output.clone(),
            },
            |_| {
                calls.set(calls.get() + 1);
                Ok(Zeroizing::new(TEST_PRIVATE_JWK.to_string()))
            },
        )
        .expect_err("private signing key inside the closure must fail closed");
        assert_eq!(calls.get(), 0);
        assert!(format!("{error:#}").contains("outside the signing-input directory"));
        assert!(!output.exists());
    }

    #[test]
    fn copied_file_backed_private_key_is_rejected_before_resolution_or_publication() {
        const PRIVATE_KEY_CANARY: &str = "registryctl-copied-private-key-canary";

        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        let acceptance_identity = identity(ProductAcceptanceLaneV1::Notary);
        write_signing_input(&input, acceptance_identity.clone());
        let anchor_path = temp.path().join("anchor.json");
        write_anchor(&anchor_path, acceptance_identity);
        let private_key = temp.path().join("private-key.jwk");
        fs::write(
            &private_key,
            TEST_PRIVATE_JWK.replace("registryctl-test-private-key", PRIVATE_KEY_CANARY),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mut permissions = fs::metadata(&private_key).unwrap().permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&private_key, permissions).unwrap();
        }
        fs::copy(&private_key, input.join("copied-private-key.jwk")).unwrap();

        let output = temp.path().join("signed");
        let calls = Cell::new(0);
        let error = sign_product_bundle_with_resolver(
            &ProductBundleSignOptions {
                lane: ProductAcceptanceLaneV1::Notary,
                input,
                anchor: anchor_path,
                keys: vec![format!("file:{}", private_key.display())],
                output_dir: output.clone(),
            },
            |_| {
                calls.set(calls.get() + 1);
                Ok(Zeroizing::new(TEST_PRIVATE_JWK.to_string()))
            },
        )
        .expect_err("copied private signing key in the closure must fail closed");
        assert_eq!(calls.get(), 0);
        assert!(format!("{error:#}").contains("private JWK material"));
        assert!(!output.exists());
    }

    #[test]
    fn signing_input_budget_enforces_closure_wide_file_and_byte_caps() {
        let mut file_budget = SigningInputBudget {
            files: MAX_SIGNING_INPUT_FILES,
            total_bytes: 0,
        };
        let error = file_budget
            .add_file(0)
            .expect_err("one file beyond the closure-wide cap must fail");
        assert!(format!("{error:#}").contains("file limit"));

        let mut byte_budget = SigningInputBudget {
            files: 0,
            total_bytes: MAX_SIGNING_INPUT_TOTAL_BYTES,
        };
        let error = byte_budget
            .add_file(1)
            .expect_err("one byte beyond the closure-wide cap must fail");
        assert!(format!("{error:#}").contains("total limit"));
    }

    #[test]
    fn signing_input_closure_enforces_directory_depth_cap() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        write_signing_input(&input, identity(ProductAcceptanceLaneV1::Notary));
        let mut nested = input;
        for index in 0..=MAX_SIGNING_INPUT_DEPTH {
            nested = nested.join(format!("d{index}"));
        }
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("leaf"), b"bounded").unwrap();
        let error = collect_signing_input_files(&temp.path().join("input"), &[])
            .expect_err("closure nesting beyond the depth cap must fail");
        assert!(format!("{error:#}").contains("depth limit"));
    }

    #[test]
    fn immutable_directory_publication_does_not_replace_a_racing_destination() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("published");
        let staging = stage_output_directory(&output).unwrap();
        write_new_private_file(&staging.path().join("staged"), b"staged").unwrap();
        fs::create_dir(&output).unwrap();
        fs::write(output.join("winner"), b"winner").unwrap();

        publish_staged_directory(staging, &output)
            .expect_err("a destination created after staging must win without replacement");
        assert_eq!(fs::read(output.join("winner")).unwrap(), b"winner");
        assert!(!output.join("staged").exists());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_public_and_private_inputs_reject_symlinks_and_shared_private_keys() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.jwk");
        fs::write(&target, TEST_PRIVATE_JWK).unwrap();
        let link = temp.path().join("link.jwk");
        symlink(&target, &link).unwrap();
        assert!(read_bounded_utf8_file_no_follow(&link, MAX_JWK_JSON_BYTES, false).is_err());

        let mut permissions = fs::metadata(&target).unwrap().permissions();
        permissions.set_mode(0o640);
        fs::set_permissions(&target, permissions).unwrap();
        let error = read_bounded_utf8_file_no_follow(&target, MAX_JWK_JSON_BYTES, true)
            .expect_err("shared private key must fail");
        assert!(format!("{error:#}").contains("owner-only"));
    }
}

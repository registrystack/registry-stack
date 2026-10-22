// SPDX-License-Identifier: Apache-2.0
//! Release-pinned bootstrap and component payload staging.

use crate::assets::{checksum_for, verify_bytes, AssetProvider};
use crate::store::{GenerationStore, PublicLinkStatus};
use crate::{Asset, ReleaseManifest, Selection};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;

pub struct BootstrapOptions {
    pub release_manifest: PathBuf,
    pub checksum_file: PathBuf,
    pub launcher_asset: PathBuf,
    pub asset_dir: Option<PathBuf>,
    pub install_root: PathBuf,
    pub bin_dir: PathBuf,
    pub components: Vec<String>,
    pub all: bool,
}

#[derive(Clone, Debug)]
pub struct ManagerOptions {
    pub install_root: PathBuf,
    pub bin_dir: PathBuf,
    pub asset_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallReport {
    pub schema_version: &'static str,
    pub release: String,
    pub generation: String,
    pub components: Vec<String>,
    pub download_bytes: u64,
    pub public_link_created: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UninstallReport {
    pub schema_version: &'static str,
    pub release: String,
    pub generation: String,
    pub components: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UninstallAllReport {
    pub schema_version: &'static str,
    pub removed_generations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateReport {
    pub schema_version: &'static str,
    pub current_release: String,
    pub target_release: String,
    pub generation: Option<String>,
    pub components: Vec<String>,
    pub added_components: Vec<String>,
    pub download_bytes: u64,
    pub preview: bool,
    pub activated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagerErrorClass {
    Domain,
    Operational,
}

#[derive(Debug)]
pub struct ManagerError {
    pub class: ManagerErrorClass,
    pub message: String,
}

impl ManagerError {
    fn domain(message: impl Into<String>) -> Self {
        Self {
            class: ManagerErrorClass::Domain,
            message: message.into(),
        }
    }

    fn operational(message: impl Into<String>) -> Self {
        Self {
            class: ManagerErrorClass::Operational,
            message: message.into(),
        }
    }
}

impl fmt::Display for ManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ManagerError {}

impl From<String> for ManagerError {
    fn from(message: String) -> Self {
        Self::operational(message)
    }
}

impl From<&str> for ManagerError {
    fn from(message: &str) -> Self {
        Self::operational(message)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledSelection {
    pub schema_version: String,
    pub release: String,
    pub platform: String,
    pub components: Vec<String>,
}

pub fn platform() -> Result<&'static str, String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("linux-amd64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        ("macos", "aarch64") => Ok("macos-arm64"),
        _ => Err("no Registry Stack launcher is published for this platform".into()),
    }
}

pub fn bootstrap(options: BootstrapOptions) -> Result<InstallReport, String> {
    if options.all && !options.components.is_empty() {
        return Err("select component names or --all, but not both".into());
    }
    let manifest_bytes = read_small_file(&options.release_manifest)?;
    let checksum_bytes = read_small_file(&options.checksum_file)?;
    let manifest_name = options
        .release_manifest
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("release manifest path has no UTF-8 basename")?;
    let digest = checksum_for(&checksum_bytes, manifest_name)?;
    verify_bytes(manifest_name, &manifest_bytes, &digest)?;
    let manifest = ReleaseManifest::parse(&manifest_bytes)?;
    if manifest_name
        != format!(
            "registry-stack-{}-release-manifest.json",
            manifest.release.tag
        )
    {
        return Err("release manifest filename differs from its exact release".into());
    }
    if manifest.release.version != env!("CARGO_PKG_VERSION") {
        return Err("bootstrap launcher version differs from release manifest".into());
    }
    let target = platform()?;
    let launcher = manifest
        .components
        .launcher
        .get(target)
        .ok_or_else(|| format!("launcher is unavailable on {target}"))?;
    if options
        .launcher_asset
        .file_name()
        .and_then(|name| name.to_str())
        != Some(launcher.name.as_str())
    {
        return Err("launcher asset path differs from release manifest".into());
    }
    let launcher_digest = checksum_for(&checksum_bytes, &launcher.name)?;
    if launcher_digest != launcher.sha256 {
        return Err("launcher checksum disagrees with release manifest".into());
    }
    let plan = if options.all {
        manifest.components.select(target, Selection::All)?
    } else if options.components.is_empty() {
        crate::SelectionPlan {
            components: Vec::new(),
            download_bytes: launcher.size,
        }
    } else {
        manifest
            .components
            .select(target, Selection::Names(options.components.clone()))?
    };

    let store = GenerationStore::new(options.install_root, options.bin_dir);
    let mutation = store.lock_mutation()?;
    if let Some(current) = mutation.current()? {
        let active = read_active_release(current.path())?;
        ensure_not_downgrade(&active.selection.release, &manifest.release.tag)?;
    }
    let name = unique_generation_name(&manifest.release.tag)?;
    let staged = mutation.stage_generation(&name)?;
    let raw_dir = staged.path().join(".assets");
    fs::create_dir(&raw_dir).map_err(|error| format!("cannot stage release assets: {error}"))?;
    let local_launcher = AssetProvider::new(
        &manifest.release.tag,
        Some(
            options
                .launcher_asset
                .parent()
                .ok_or("launcher asset has no parent directory")?
                .to_path_buf(),
        ),
    )?;
    stage_asset(
        &local_launcher,
        launcher,
        &raw_dir,
        staged.path(),
        "rstack",
        &manifest.release.version,
    )?;

    let source = AssetProvider::new(&manifest.release.tag, options.asset_dir)?;
    for component_name in &plan.components {
        let component = &manifest.components.components[component_name];
        let payload = &component.platforms[target];
        for asset in &payload.assets {
            verify_asset_checksum(&checksum_bytes, asset)?;
            let binary = binary_name(&asset.name, &manifest.release.tag, target)?;
            let destination = staged
                .path()
                .join("components")
                .join(component_name)
                .join(&binary);
            fs::create_dir_all(&destination)
                .map_err(|error| format!("cannot stage {component_name}: {error}"))?;
            stage_asset(
                &source,
                asset,
                &raw_dir,
                &destination,
                &binary,
                &manifest.release.version,
            )?;
        }
    }
    fs::remove_dir(&raw_dir).map_err(|error| format!("cannot clear staging area: {error}"))?;
    fs::write(staged.path().join("manifest.json"), &manifest_bytes)
        .map_err(|error| format!("cannot stage release manifest: {error}"))?;
    fs::write(staged.path().join("SHA256SUMS"), &checksum_bytes)
        .map_err(|error| format!("cannot stage release checksums: {error}"))?;
    let selection = InstalledSelection {
        schema_version: "registry-stack.install-selection.v1".into(),
        release: manifest.release.tag.clone(),
        platform: target.into(),
        components: plan.components.clone(),
    };
    fs::write(
        staged.path().join("selection.json"),
        serde_json::to_vec_pretty(&selection)
            .map_err(|error| format!("cannot encode installation selection: {error}"))?,
    )
    .map_err(|error| format!("cannot stage installation selection: {error}"))?;
    let generation = staged.publish_preverified()?;
    let link = mutation.ensure_public_link()?;
    mutation.activate(&generation)?;
    Ok(InstallReport {
        schema_version: "registry.rstack.install.v1",
        release: manifest.release.tag,
        generation: generation.name().to_owned(),
        components: plan.components,
        download_bytes: plan.download_bytes,
        public_link_created: link == PublicLinkStatus::Created,
    })
}

/// Add components to the selected release and atomically activate the complete result.
pub fn install(
    options: ManagerOptions,
    components: Vec<String>,
    all: bool,
) -> Result<InstallReport, ManagerError> {
    if (all && !components.is_empty()) || (!all && components.is_empty()) {
        return Err(ManagerError::domain(
            "select component names or --all, but not both",
        ));
    }
    let store = GenerationStore::new(options.install_root, options.bin_dir);
    let mutation = store.lock_mutation()?;
    let current = mutation
        .current()?
        .ok_or("no installation is selected; run a release-pinned rstack installer")?;
    let active = read_active_release(current.path())?;
    let requested = if all {
        active
            .manifest
            .components
            .select(&active.selection.platform, Selection::All)
            .map_err(manager_selection_error)?
    } else {
        active
            .manifest
            .components
            .select(&active.selection.platform, Selection::Names(components))
            .map_err(manager_selection_error)?
    };
    let desired_names: BTreeSet<_> = active
        .selection
        .components
        .iter()
        .cloned()
        .chain(requested.components)
        .collect();
    let desired = resolve_selection(
        &active.manifest,
        &active.selection.platform,
        desired_names.into_iter().collect(),
    )?;
    if desired == active.selection.components {
        return Ok(InstallReport {
            schema_version: "registry.rstack.install.v1",
            release: active.selection.release,
            generation: current.name().to_owned(),
            components: desired,
            download_bytes: 0,
            public_link_created: false,
        });
    }

    let installed: BTreeSet<_> = active.selection.components.iter().cloned().collect();
    let added: Vec<_> = desired
        .iter()
        .filter(|name| !installed.contains(*name))
        .cloned()
        .collect();
    let download_bytes =
        component_download_bytes(&active.manifest, &active.selection.platform, &added)?;
    let provider = AssetProvider::new(&active.selection.release, options.asset_dir)?;
    let generation_name = unique_generation_name(&active.selection.release)?;
    let staged = mutation.stage_generation(&generation_name)?;
    copy_generation_base(current.path(), staged.path())?;
    copy_components(current.path(), staged.path(), &active.selection.components)?;
    let raw_dir = staged.path().join(".assets");
    fs::create_dir(&raw_dir).map_err(|error| format!("cannot stage release assets: {error}"))?;
    for component_name in &added {
        let component = &active.manifest.components.components[component_name];
        let payload = &component.platforms[&active.selection.platform];
        for asset in &payload.assets {
            verify_asset_checksum(&active.checksums, asset)?;
            let binary = binary_name(
                &asset.name,
                &active.selection.release,
                &active.selection.platform,
            )?;
            let destination = staged
                .path()
                .join("components")
                .join(component_name)
                .join(&binary);
            fs::create_dir_all(&destination)
                .map_err(|error| format!("cannot stage {component_name}: {error}"))?;
            stage_asset(
                &provider,
                asset,
                &raw_dir,
                &destination,
                &binary,
                &active.manifest.release.version,
            )?;
        }
    }
    fs::remove_dir(&raw_dir).map_err(|error| format!("cannot clear staging area: {error}"))?;
    write_selection(staged.path(), &active.selection, desired.clone())?;
    let generation = staged.publish_preverified()?;
    let link = mutation.ensure_public_link()?;
    mutation.activate(&generation)?;
    Ok(InstallReport {
        schema_version: "registry.rstack.install.v1",
        release: active.selection.release,
        generation: generation.name().to_owned(),
        components: desired,
        download_bytes,
        public_link_created: link == PublicLinkStatus::Created,
    })
}

/// Preview or activate an exact newer release while preserving the installed product set.
pub fn update(
    options: &ManagerOptions,
    release: &str,
    preview: bool,
) -> Result<UpdateReport, ManagerError> {
    parse_release_version(release).map_err(ManagerError::domain)?;
    let store = GenerationStore::new(&options.install_root, &options.bin_dir);
    if preview {
        let current = store.acquire_current().map_err(manager_current_error)?;
        let active = read_active_release(current.path())?;
        let plan = prepare_update(&active, release, options.asset_dir.clone())?;
        return Ok(UpdateReport {
            schema_version: "registry.rstack.update.v1",
            current_release: active.selection.release.clone(),
            target_release: release.to_owned(),
            generation: None,
            components: plan.components,
            added_components: plan.added_components,
            download_bytes: if release == active.selection.release {
                0
            } else {
                plan.download_bytes
            },
            preview: true,
            activated: false,
        });
    }

    let mutation = store.lock_mutation()?;
    let current = mutation.current()?.ok_or_else(|| {
        ManagerError::domain("no installation is selected; run a release-pinned rstack installer")
    })?;
    let active = read_active_release(current.path())?;
    let plan = prepare_update(&active, release, options.asset_dir.clone())?;
    if release == active.selection.release {
        return Ok(UpdateReport {
            schema_version: "registry.rstack.update.v1",
            current_release: active.selection.release.clone(),
            target_release: release.to_owned(),
            generation: Some(current.name().to_owned()),
            components: plan.components,
            added_components: Vec::new(),
            download_bytes: 0,
            preview: false,
            activated: false,
        });
    }

    let provider = AssetProvider::new(release, options.asset_dir.clone())?;
    let generation_name = unique_generation_name(release)?;
    let staged = mutation.stage_generation(&generation_name)?;
    let raw_dir = staged.path().join(".assets");
    fs::create_dir(&raw_dir).map_err(|error| format!("cannot stage release assets: {error}"))?;
    let launcher = &plan.target.manifest.components.launcher[&active.selection.platform];
    verify_asset_checksum(&plan.target.checksums, launcher)?;
    stage_asset(
        &provider,
        launcher,
        &raw_dir,
        staged.path(),
        "rstack",
        &plan.target.manifest.release.version,
    )?;
    for component_name in &plan.components {
        let component = &plan.target.manifest.components.components[component_name];
        let payload = &component.platforms[&active.selection.platform];
        for asset in &payload.assets {
            verify_asset_checksum(&plan.target.checksums, asset)?;
            let binary = binary_name(&asset.name, release, &active.selection.platform)?;
            let destination = staged
                .path()
                .join("components")
                .join(component_name)
                .join(&binary);
            fs::create_dir_all(&destination)
                .map_err(|error| format!("cannot stage {component_name}: {error}"))?;
            stage_asset(
                &provider,
                asset,
                &raw_dir,
                &destination,
                &binary,
                &plan.target.manifest.release.version,
            )?;
        }
    }
    fs::remove_dir(&raw_dir).map_err(|error| format!("cannot clear staging area: {error}"))?;
    fs::write(
        staged.path().join("manifest.json"),
        &plan.target.manifest_bytes,
    )
    .map_err(|error| format!("cannot stage release manifest: {error}"))?;
    fs::write(staged.path().join("SHA256SUMS"), &plan.target.checksums)
        .map_err(|error| format!("cannot stage release checksums: {error}"))?;
    write_selection(
        staged.path(),
        &InstalledSelection {
            schema_version: "registry-stack.install-selection.v1".into(),
            release: release.to_owned(),
            platform: active.selection.platform.clone(),
            components: Vec::new(),
        },
        plan.components.clone(),
    )?;
    let generation = staged.publish_preverified()?;
    mutation.ensure_public_link()?;
    mutation.activate(&generation)?;
    Ok(UpdateReport {
        schema_version: "registry.rstack.update.v1",
        current_release: active.selection.release,
        target_release: release.to_owned(),
        generation: Some(generation.name().to_owned()),
        components: plan.components,
        added_components: plan.added_components,
        download_bytes: plan.download_bytes,
        preview: false,
        activated: true,
    })
}

/// Remove selected components while preserving the launcher and all retained payloads.
pub fn uninstall(
    options: ManagerOptions,
    components: Vec<String>,
) -> Result<UninstallReport, ManagerError> {
    if components.is_empty() {
        return Err(ManagerError::domain(
            "select one or more installed components",
        ));
    }
    let store = GenerationStore::new(options.install_root, options.bin_dir);
    let mutation = store.lock_mutation()?;
    let current = mutation
        .current()?
        .ok_or("no installation is selected; run a release-pinned rstack installer")?;
    let active = read_active_release(current.path())?;
    let installed: BTreeSet<_> = active.selection.components.iter().cloned().collect();
    let removed: BTreeSet<_> = components.into_iter().collect();
    for name in &removed {
        if !active.manifest.components.components.contains_key(name) {
            return Err(ManagerError::domain(format!("unknown component {name}")));
        }
        if !installed.contains(name) {
            return Err(ManagerError::domain(format!(
                "component {name} is not installed"
            )));
        }
    }
    let retained: Vec<_> = active
        .selection
        .components
        .iter()
        .filter(|name| !removed.contains(*name))
        .cloned()
        .collect();
    for component_name in &retained {
        let component = &active.manifest.components.components[component_name];
        if let Some(dependency) = component
            .dependencies
            .iter()
            .find(|dependency| removed.contains(*dependency))
        {
            return Err(ManagerError::domain(format!(
                "cannot uninstall {dependency}: it is required by {component_name}"
            )));
        }
    }

    let generation_name = unique_generation_name(&active.selection.release)?;
    let staged = mutation.stage_generation(&generation_name)?;
    copy_generation_base(current.path(), staged.path())?;
    copy_components(current.path(), staged.path(), &retained)?;
    write_selection(staged.path(), &active.selection, retained.clone())?;
    let generation = staged.publish_preverified()?;
    mutation.ensure_public_link()?;
    mutation.activate(&generation)?;
    Ok(UninstallReport {
        schema_version: "registry.rstack.uninstall.v1",
        release: active.selection.release,
        generation: generation.name().to_owned(),
        components: retained,
        removed: removed.into_iter().collect(),
    })
}

/// Remove the complete managed installation after proving every generation is idle and owned.
pub fn uninstall_all(options: ManagerOptions) -> Result<UninstallAllReport, ManagerError> {
    let store = GenerationStore::new(options.install_root, options.bin_dir);
    let mutation = store.lock_mutation()?;
    let report = mutation.remove_installation().map_err(|message| {
        if message.contains(" is in use;") {
            ManagerError::domain(message)
        } else {
            ManagerError::operational(message)
        }
    })?;
    Ok(UninstallAllReport {
        schema_version: "registry.rstack.uninstall-all.v1",
        removed_generations: report.removed_generations,
    })
}

fn manager_selection_error(message: String) -> ManagerError {
    if message.starts_with("unknown component ") || message.contains(" is unavailable on ") {
        ManagerError::domain(message)
    } else {
        ManagerError::operational(message)
    }
}

fn manager_current_error(message: String) -> ManagerError {
    if message == "no Registry Stack installation is selected" {
        ManagerError::domain("no installation is selected; run a release-pinned rstack installer")
    } else {
        ManagerError::operational(message)
    }
}

pub fn read_selection(generation: &Path) -> Result<InstalledSelection, String> {
    let bytes = read_small_file(&generation.join("selection.json"))?;
    let selection: InstalledSelection = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse installation selection: {error}"))?;
    if selection.schema_version != "registry-stack.install-selection.v1" {
        return Err("unsupported installation selection schema".into());
    }
    Ok(selection)
}

struct ActiveRelease {
    manifest: ReleaseManifest,
    manifest_bytes: Vec<u8>,
    checksums: Vec<u8>,
    selection: InstalledSelection,
}

struct ResolvedRelease {
    manifest: ReleaseManifest,
    manifest_bytes: Vec<u8>,
    checksums: Vec<u8>,
}

struct UpdatePlan {
    target: ResolvedRelease,
    components: Vec<String>,
    added_components: Vec<String>,
    download_bytes: u64,
}

fn read_active_release(generation: &Path) -> Result<ActiveRelease, String> {
    let manifest_bytes = read_small_file(&generation.join("manifest.json"))?;
    let checksums = read_small_file(&generation.join("SHA256SUMS"))?;
    let manifest = ReleaseManifest::parse(&manifest_bytes)?;
    let manifest_name = format!(
        "registry-stack-{}-release-manifest.json",
        manifest.release.tag
    );
    let digest = checksum_for(&checksums, &manifest_name)?;
    verify_bytes(&manifest_name, &manifest_bytes, &digest)?;
    let selection = read_selection(generation)?;
    if selection.release != manifest.release.tag {
        return Err("installed selection release differs from its manifest".into());
    }
    if selection.platform != platform()? {
        return Err(format!(
            "installed selection targets {}, not this platform",
            selection.platform
        ));
    }
    let resolved = resolve_selection(&manifest, &selection.platform, selection.components.clone())?;
    if resolved != selection.components {
        return Err("installed component selection is incomplete or noncanonical".into());
    }
    Ok(ActiveRelease {
        manifest,
        manifest_bytes,
        checksums,
        selection,
    })
}

fn prepare_update(
    active: &ActiveRelease,
    release: &str,
    asset_dir: Option<PathBuf>,
) -> Result<UpdatePlan, ManagerError> {
    ensure_not_downgrade(&active.selection.release, release).map_err(ManagerError::domain)?;
    let target = resolve_release(release, asset_dir)?;
    if release == active.selection.release && target.manifest_bytes != active.manifest_bytes {
        return Err(ManagerError::operational(
            "selected release metadata differs from the immutable installed release",
        ));
    }
    let selection = if active.selection.components.is_empty() {
        let launcher = target
            .manifest
            .components
            .launcher
            .get(&active.selection.platform)
            .ok_or_else(|| {
                ManagerError::domain(format!(
                    "launcher is unavailable on {}",
                    active.selection.platform
                ))
            })?;
        crate::SelectionPlan {
            components: Vec::new(),
            download_bytes: launcher.size,
        }
    } else {
        target
            .manifest
            .components
            .select(
                &active.selection.platform,
                Selection::Names(active.selection.components.clone()),
            )
            .map_err(manager_selection_error)?
    };
    let installed: BTreeSet<_> = active.selection.components.iter().cloned().collect();
    let added_components = selection
        .components
        .iter()
        .filter(|component| !installed.contains(*component))
        .cloned()
        .collect();
    Ok(UpdatePlan {
        target,
        components: selection.components,
        added_components,
        download_bytes: selection.download_bytes,
    })
}

fn ensure_not_downgrade(current_release: &str, target_release: &str) -> Result<(), String> {
    let current_version = parse_release_version(current_release)?;
    let target_version = parse_release_version(target_release)?;
    if target_version < current_version {
        return Err(format!(
            "refusing downgrade from {current_release} to {target_release}"
        ));
    }
    Ok(())
}

fn resolve_release(
    release: &str,
    asset_dir: Option<PathBuf>,
) -> Result<ResolvedRelease, ManagerError> {
    let provider = AssetProvider::new(release, asset_dir)?;
    let checksums = provider.fetch_metadata("SHA256SUMS")?;
    let manifest_name = format!("registry-stack-{release}-release-manifest.json");
    let manifest_bytes = provider.fetch_metadata(&manifest_name)?;
    let digest = checksum_for(&checksums, &manifest_name)?;
    verify_bytes(&manifest_name, &manifest_bytes, &digest)?;
    let manifest = ReleaseManifest::parse(&manifest_bytes)?;
    if manifest.release.tag != release {
        return Err(ManagerError::operational(
            "target release manifest differs from the exact requested release",
        ));
    }
    Ok(ResolvedRelease {
        manifest,
        manifest_bytes,
        checksums,
    })
}

fn parse_release_version(release: &str) -> Result<(u64, u64, u64), String> {
    let version = release
        .strip_prefix('v')
        .ok_or("release must start with v")?;
    let mut parts = version.split('.');
    let major = parse_version_part(parts.next(), release)?;
    let minor = parse_version_part(parts.next(), release)?;
    let patch = parse_version_part(parts.next(), release)?;
    if parts.next().is_some() {
        return Err(format!(
            "release {release} must be an exact canonical vX.Y.Z tag"
        ));
    }
    Ok((major, minor, patch))
}

fn parse_version_part(part: Option<&str>, release: &str) -> Result<u64, String> {
    let part =
        part.ok_or_else(|| format!("release {release} must be an exact canonical vX.Y.Z tag"))?;
    if part.is_empty()
        || (part.len() > 1 && part.starts_with('0'))
        || !part.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!(
            "release {release} must be an exact canonical vX.Y.Z tag"
        ));
    }
    part.parse()
        .map_err(|_| format!("release {release} must be an exact canonical vX.Y.Z tag"))
}

fn resolve_selection(
    manifest: &ReleaseManifest,
    platform: &str,
    names: Vec<String>,
) -> Result<Vec<String>, String> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    manifest
        .components
        .select(platform, Selection::Names(names))
        .map(|plan| plan.components)
}

fn component_download_bytes(
    manifest: &ReleaseManifest,
    platform: &str,
    components: &[String],
) -> Result<u64, String> {
    let mut bytes = 0_u64;
    for component_name in components {
        for asset in &manifest.components.components[component_name].platforms[platform].assets {
            bytes = bytes
                .checked_add(asset.size)
                .ok_or("download size overflows u64")?;
        }
    }
    Ok(bytes)
}

fn verify_asset_checksum(checksums: &[u8], asset: &Asset) -> Result<(), String> {
    if checksum_for(checksums, &asset.name)? != asset.sha256 {
        return Err(format!(
            "asset {} checksum disagrees with release manifest",
            asset.name
        ));
    }
    Ok(())
}

fn copy_generation_base(source: &Path, destination: &Path) -> Result<(), String> {
    for entry in fs::read_dir(source)
        .map_err(|error| format!("cannot inspect active generation: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect active generation: {error}"))?;
        let name = entry.file_name();
        if matches!(
            name.to_str(),
            Some(".rstack-ownership.json" | ".rstack-lease" | "selection.json" | "components")
        ) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("cannot inspect active generation entry: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "active generation entry {} is not a regular file",
                entry.path().display()
            ));
        }
        copy_regular_file(&entry.path(), &destination.join(&name))?;
    }
    fs::create_dir(destination.join("components"))
        .map_err(|error| format!("cannot stage component directory: {error}"))
}

fn copy_components(source: &Path, destination: &Path, components: &[String]) -> Result<(), String> {
    for component in components {
        copy_regular_tree(
            &source.join("components").join(component),
            &destination.join("components").join(component),
        )?;
    }
    Ok(())
}

fn copy_regular_tree(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(|error| {
        format!(
            "cannot inspect retained component {}: {error}",
            source.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "retained component {} is not a directory",
            source.display()
        ));
    }
    fs::create_dir(destination)
        .map_err(|error| format!("cannot stage retained component: {error}"))?;
    for entry in fs::read_dir(source)
        .map_err(|error| format!("cannot inspect retained component: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect retained component: {error}"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("cannot inspect retained component entry: {error}"))?;
        let target = destination.join(entry.file_name());
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            copy_regular_tree(&entry.path(), &target)?;
        } else if metadata.file_type().is_file() {
            copy_regular_file(&entry.path(), &target)?;
        } else {
            return Err(format!(
                "retained component entry {} is not a regular file or directory",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

fn copy_regular_file(source: &Path, destination: &Path) -> Result<(), String> {
    fs::copy(source, destination)
        .map_err(|error| format!("cannot copy retained file {}: {error}", source.display()))?;
    let permissions = fs::metadata(source)
        .map_err(|error| format!("cannot inspect retained file {}: {error}", source.display()))?
        .permissions();
    fs::set_permissions(destination, permissions)
        .map_err(|error| format!("cannot preserve retained file permissions: {error}"))
}

fn write_selection(
    generation: &Path,
    previous: &InstalledSelection,
    components: Vec<String>,
) -> Result<(), String> {
    let selection = InstalledSelection {
        schema_version: "registry-stack.install-selection.v1".into(),
        release: previous.release.clone(),
        platform: previous.platform.clone(),
        components,
    };
    fs::write(
        generation.join("selection.json"),
        serde_json::to_vec_pretty(&selection)
            .map_err(|error| format!("cannot encode installation selection: {error}"))?,
    )
    .map_err(|error| format!("cannot stage installation selection: {error}"))
}

fn read_small_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_METADATA_BYTES {
        return Err(format!(
            "{} must be a regular file of at most 16 MiB",
            path.display()
        ));
    }
    let mut file =
        fs::File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(format!("{} exceeds 16 MiB", path.display()));
    }
    Ok(bytes)
}

fn unique_generation_name(release: &str) -> Result<String, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))?;
    Ok(format!(
        "{release}-{}-{}",
        std::process::id(),
        now.as_nanos()
    ))
}

fn binary_name(asset_name: &str, release: &str, platform: &str) -> Result<String, String> {
    let suffix = format!(
        "-{release}-{platform}{}",
        if platform == "macos-arm64" {
            ".tar.gz"
        } else {
            ""
        }
    );
    let binary = asset_name
        .strip_suffix(&suffix)
        .ok_or_else(|| format!("asset {asset_name} has the wrong release/platform suffix"))?;
    if binary.is_empty()
        || !binary
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(format!("asset {asset_name} has an invalid binary name"));
    }
    Ok(binary.to_owned())
}

fn stage_asset(
    provider: &AssetProvider,
    asset: &Asset,
    raw_dir: &Path,
    destination: &Path,
    binary: &str,
    expected_version: &str,
) -> Result<(), String> {
    let raw = raw_dir.join(&asset.name);
    provider.fetch(asset, &raw)?;
    if asset.name.ends_with(".tar.gz") {
        let archived_binary = asset
            .name
            .strip_suffix(".tar.gz")
            .ok_or("archive asset has an invalid name")?;
        extract_macos_archive(&raw, destination, archived_binary)?;
        fs::rename(destination.join(archived_binary), destination.join(binary))
            .map_err(|error| format!("cannot stage executable {binary}: {error}"))?;
        fs::remove_file(&raw)
            .map_err(|error| format!("cannot clear staged archive {}: {error}", asset.name))?;
    } else {
        let executable = destination.join(binary);
        fs::rename(&raw, &executable)
            .map_err(|error| format!("cannot stage executable {binary}: {error}"))?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot mark executable {binary}: {error}"))?;
    }
    smoke_binary(&destination.join(binary), binary, expected_version)?;
    Ok(())
}

fn extract_macos_archive(archive: &Path, destination: &Path, binary: &str) -> Result<(), String> {
    let names = Command::new("tar")
        .arg("-tzf")
        .arg(archive)
        .output()
        .map_err(|error| format!("cannot inspect {binary} archive: {error}"))?;
    if !names.status.success() {
        return Err(format!("cannot list {binary} archive"));
    }
    let listing = Command::new("tar")
        .arg("-tvzf")
        .arg(archive)
        .output()
        .map_err(|error| format!("cannot inspect {binary} archive: {error}"))?;
    if !listing.status.success() {
        return Err(format!("cannot inspect {binary} archive entries"));
    }
    let names = std::str::from_utf8(&names.stdout)
        .map_err(|_| format!("{binary} archive has non-UTF-8 entry names"))?;
    let listing = std::str::from_utf8(&listing.stdout)
        .map_err(|_| format!("{binary} archive has a non-UTF-8 listing"))?;
    let mut seen = BTreeSet::new();
    let mut has_notices = false;
    let mut has_fips = false;
    for name in names.lines() {
        if name == "THIRD_PARTY_NOTICES" {
            has_notices = true;
        } else if name.starts_with("libaws_lc_fips_") && name.ends_with(".dylib") {
            has_fips = true;
        } else if name != binary {
            return Err(format!("{binary} archive has an unsupported entry"));
        }
        if !seen.insert(name.to_owned()) {
            return Err(format!("{binary} archive has a duplicate entry"));
        }
    }
    if !seen.contains(binary) || !has_notices || !has_fips {
        return Err(format!("{binary} archive is incomplete"));
    }
    if listing.lines().count() != seen.len() || listing.lines().any(|line| !line.starts_with('-')) {
        return Err(format!("{binary} archive contains a nonregular entry"));
    }
    let result = Command::new("tar")
        .env("COPYFILE_DISABLE", "1")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(destination)
        .output()
        .map_err(|error| format!("cannot extract {binary} archive: {error}"))?;
    if !result.status.success() {
        return Err(format!("cannot extract {binary} archive"));
    }
    let extracted = fs::read_dir(destination)
        .map_err(|error| format!("cannot inspect extracted {binary}: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot inspect extracted {binary}: {error}"))?;
    let extracted: Vec<_> = extracted
        .into_iter()
        .filter(|entry| entry.file_name() != ".assets")
        .collect();
    if extracted.len() != seen.len() {
        return Err(format!(
            "{binary} archive extraction differs from inspected roster: expected {}, found {:?}",
            seen.len(),
            extracted
                .iter()
                .map(|entry| entry.file_name())
                .collect::<Vec<_>>()
        ));
    }
    for entry in extracted {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !seen.contains(&name)
            || !fs::symlink_metadata(entry.path())
                .map_err(|error| format!("cannot inspect extracted {name}: {error}"))?
                .file_type()
                .is_file()
        {
            return Err(format!("{binary} archive extracted an unsupported entry"));
        }
    }
    Ok(())
}

fn smoke_binary(path: &Path, binary: &str, expected_version: &str) -> Result<(), String> {
    let output = Command::new(path)
        .arg("--version")
        .output()
        .map_err(|error| format!("cannot start staged {binary}: {error}"))?;
    let expected = format!("{binary} {expected_version}\n");
    if !output.status.success() || output.stdout != expected.as_bytes() {
        return Err(format!("staged {binary} reports an unexpected version"));
    }
    Ok(())
}

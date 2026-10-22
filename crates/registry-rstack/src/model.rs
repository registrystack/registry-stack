// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const SCHEMA: &str = "registry-stack.components.v1";
const PLATFORMS: [&str; 3] = ["linux-amd64", "linux-arm64", "macos-arm64"];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentManifest {
    pub schema_version: String,
    pub release: String,
    pub launcher: BTreeMap<String, Asset>,
    pub components: BTreeMap<String, Component>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub entrypoint: String,
    pub dependencies: Vec<String>,
    pub platforms: BTreeMap<String, PlatformPayload>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformPayload {
    pub assets: Vec<Asset>,
    pub capabilities: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseManifest {
    pub schema_version: String,
    pub repository: String,
    pub release: ReleaseIdentity,
    pub payloads: Vec<PublishedPayload>,
    pub components: ComponentManifest,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    pub tag: String,
    pub version: String,
    pub source_sha: String,
    pub release_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedPayload {
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub enum Selection {
    All,
    Names(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionPlan {
    pub components: Vec<String>,
    pub download_bytes: u64,
}

impl ComponentManifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA {
            return Err(format!(
                "unsupported component schema {}",
                self.schema_version
            ));
        }
        let version = self
            .release
            .strip_prefix('v')
            .ok_or("release must use a v-prefixed tag")?;
        if version.split('.').count() != 3
            || version.split('.').any(|part| {
                part.is_empty()
                    || (part.len() > 1 && part.starts_with('0'))
                    || part.parse::<u64>().is_err()
            })
        {
            return Err("release must use a canonical semantic version tag".into());
        }
        for (platform, asset) in &self.launcher {
            if !PLATFORMS.contains(&platform.as_str()) {
                return Err(format!("unsupported launcher platform {platform}"));
            }
            asset.validate()?;
            if asset.name != asset_name("rstack", &self.release, platform) {
                return Err(format!(
                    "launcher asset does not match release and platform: {}",
                    asset.name
                ));
            }
        }
        for (name, component) in &self.components {
            if !valid_component_name(name) {
                return Err(format!("invalid component name {name}"));
            }
            if !valid_component_name(&component.entrypoint) {
                return Err(format!("invalid entrypoint for {name}"));
            }
            if component.platforms.is_empty() {
                return Err(format!("component {name} has no published platform"));
            }
            for dependency in &component.dependencies {
                if !self.components.contains_key(dependency) || dependency == name {
                    return Err(format!(
                        "component {name} has invalid dependency {dependency}"
                    ));
                }
            }
            for (platform, payload) in &component.platforms {
                if !PLATFORMS.contains(&platform.as_str()) {
                    return Err(format!("unsupported platform {platform} for {name}"));
                }
                let mut names = BTreeSet::new();
                for asset in &payload.assets {
                    asset.validate()?;
                    if !names.insert(&asset.name) {
                        return Err(format!("duplicate asset {} for {name}", asset.name));
                    }
                }
                let entrypoint = asset_name(&component.entrypoint, &self.release, platform);
                if !names.contains(&entrypoint) {
                    return Err(format!("component {name} lacks entrypoint {entrypoint}"));
                }
            }
        }
        Ok(())
    }

    pub fn select(&self, platform: &str, selection: Selection) -> Result<SelectionPlan, String> {
        self.validate()?;
        let launcher = self
            .launcher
            .get(platform)
            .ok_or_else(|| format!("launcher unavailable on {platform}"))?;
        let requested: Vec<String> = match selection {
            Selection::All => self
                .components
                .iter()
                .filter(|(_, component)| component.platforms.contains_key(platform))
                .map(|(name, _)| name.clone())
                .collect(),
            Selection::Names(names) if names.is_empty() => {
                return Err("select component names or --all".into());
            }
            Selection::Names(names) => names,
        };
        let mut selected = BTreeSet::new();
        let mut visiting = BTreeSet::new();
        for name in requested {
            self.visit_component(&name, platform, &mut selected, &mut visiting)?;
        }
        let mut asset_names = BTreeSet::new();
        let mut bytes = launcher.size;
        asset_names.insert(&launcher.name);
        for name in &selected {
            let payload = &self.components[name].platforms[platform];
            for asset in &payload.assets {
                if asset_names.insert(&asset.name) {
                    bytes = bytes
                        .checked_add(asset.size)
                        .ok_or("download size overflows u64")?;
                }
            }
        }
        Ok(SelectionPlan {
            components: selected.into_iter().collect(),
            download_bytes: bytes,
        })
    }

    fn visit_component(
        &self,
        name: &str,
        platform: &str,
        selected: &mut BTreeSet<String>,
        visiting: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        let component = self
            .components
            .get(name)
            .ok_or_else(|| format!("unknown component {name}"))?;
        if !component.platforms.contains_key(platform) {
            return Err(format!("component {name} is unavailable on {platform}"));
        }
        if selected.contains(name) {
            return Ok(());
        }
        if !visiting.insert(name.to_owned()) {
            return Err(format!("component dependency cycle at {name}"));
        }
        for dependency in &component.dependencies {
            self.visit_component(dependency, platform, selected, visiting)?;
        }
        visiting.remove(name);
        selected.insert(name.to_owned());
        Ok(())
    }
}

impl ReleaseManifest {
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        let value = registry_platform_canonical_json::parse_json_strict(raw)
            .map_err(|error| format!("cannot parse release manifest: {error}"))?;
        let manifest: Self = serde_json::from_value(value)
            .map_err(|error| format!("cannot parse release manifest: {error}"))?;
        if manifest.schema_version != "registry-stack.release-candidate.v2" {
            return Err("unsupported release-manifest schema".into());
        }
        if manifest.repository != "registrystack/registry-stack" {
            return Err("release manifest names another repository".into());
        }
        if manifest.release.tag != format!("v{}", manifest.release.version)
            || manifest.release.tag != manifest.components.release
        {
            return Err("component release identity differs from public release".into());
        }
        if manifest.release.source_sha.len() != 40
            || !manifest
                .release
                .source_sha
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || manifest.release.release_id.is_empty()
        {
            return Err("release identity is invalid".into());
        }
        manifest.components.validate()?;
        let mut published = BTreeMap::new();
        for payload in &manifest.payloads {
            if published.insert(&payload.name, payload).is_some() {
                return Err(format!("duplicate published payload {}", payload.name));
            }
        }
        let mut covered = BTreeSet::new();
        for asset in manifest.components.launcher.values().chain(
            manifest
                .components
                .components
                .values()
                .flat_map(|component| {
                    component
                        .platforms
                        .values()
                        .flat_map(|platform| &platform.assets)
                }),
        ) {
            let payload = published
                .get(&asset.name)
                .ok_or_else(|| format!("component asset {} is absent from payloads", asset.name))?;
            if payload.kind != "binary"
                || payload.size != asset.size
                || payload.sha256 != asset.sha256
            {
                return Err(format!(
                    "component asset {} disagrees with published payload",
                    asset.name
                ));
            }
            if !covered.insert(&asset.name) {
                return Err(format!(
                    "binary payload {} belongs to multiple components",
                    asset.name
                ));
            }
        }
        for payload in &manifest.payloads {
            if payload.kind == "binary" && !covered.contains(&payload.name) {
                return Err(format!(
                    "binary payload {} is not classified by components",
                    payload.name
                ));
            }
        }
        Ok(manifest)
    }
}

impl Asset {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty()
            || self.name == "."
            || self.name == ".."
            || self.name.contains('/')
            || self.name.contains('\\')
            || self.name.contains('\0')
        {
            return Err("asset name must be a safe basename".into());
        }
        if self.size == 0 {
            return Err(format!("asset {} has zero size", self.name));
        }
        if self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(format!("asset {} has an invalid SHA-256 digest", self.name));
        }
        Ok(())
    }
}

fn valid_component_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

fn asset_name(binary: &str, release: &str, platform: &str) -> String {
    let suffix = if platform == "macos-arm64" {
        ".tar.gz"
    } else {
        ""
    };
    format!("{binary}-{release}-{platform}{suffix}")
}

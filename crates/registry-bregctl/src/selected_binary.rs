// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use std::fs;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy)]
pub(crate) struct HelperSpec {
    pub(crate) binary: &'static str,
    pub(crate) component: &'static str,
    pub(crate) explicit_source: &'static str,
    pub(crate) managed_env: &'static str,
}

pub(crate) const BREG: HelperSpec = HelperSpec {
    binary: "breg",
    component: "breg",
    explicit_source: "--breg-bin or BREG_BIN",
    managed_env: "RSTACK_BREG_BIN",
};

pub(crate) const BREG_MCP: HelperSpec = HelperSpec {
    binary: "breg-mcp",
    component: "breg",
    explicit_source: "--breg-mcp-bin or BREG_MCP_BIN",
    managed_env: "RSTACK_BREG_MCP_BIN",
};

pub(crate) const BREG_REVIEW: HelperSpec = HelperSpec {
    binary: "breg-review",
    component: "breg",
    explicit_source: "--breg-review-bin or BREG_REVIEW_BIN",
    managed_env: "RSTACK_BREG_REVIEW_BIN",
};

pub(crate) const CASEWORKCTL: HelperSpec = HelperSpec {
    binary: "caseworkctl",
    component: "casework",
    explicit_source: "--caseworkctl-bin",
    managed_env: "RSTACK_CASEWORKCTL_BIN",
};

pub(crate) const CASEWORK: HelperSpec = HelperSpec {
    binary: "casework",
    component: "casework",
    explicit_source: "--casework-bin",
    managed_env: "RSTACK_CASEWORK_BIN",
};

pub(crate) fn resolve_managed(
    spec: HelperSpec,
    explicit: Option<&Path>,
) -> Result<Option<PathBuf>> {
    resolve_managed_with_environment(
        spec,
        explicit,
        std::env::var_os("RSTACK_GENERATION_DIR").as_deref(),
        std::env::var_os(spec.managed_env).as_deref(),
        std::env::var_os("RSTACK_RELEASE_TAG").as_deref(),
    )
}

fn resolve_managed_with_environment(
    spec: HelperSpec,
    explicit: Option<&Path>,
    generation_dir: Option<&OsStr>,
    managed_path: Option<&OsStr>,
    release_tag: Option<&OsStr>,
) -> Result<Option<PathBuf>> {
    let Some(generation_dir) = generation_dir else {
        return Ok(None);
    };
    let release = release_tag
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "selected release".to_owned());
    let generation = fs::canonicalize(Path::new(generation_dir)).with_context(|| {
        format!(
            "rstack {release} selected generation {} cannot be resolved",
            Path::new(generation_dir).display()
        )
    })?;
    let layout_path = generation
        .join("components")
        .join(spec.component)
        .join(spec.binary)
        .join(spec.binary);
    let Some(managed_path) = managed_path else {
        return missing_component(spec, &release);
    };
    let selected =
        canonical_helper(Path::new(managed_path)).or_else(|_| missing_component(spec, &release))?;
    let layout = canonical_helper(&layout_path).or_else(|_| missing_component(spec, &release))?;
    if selected != layout {
        bail!(
            "rstack {release} provided {} outside the selected generation helper path at {}; run `rstack install {}` to repair the selected generation",
            spec.managed_env,
            layout_path.display(),
            spec.component
        );
    }
    if let Some(override_path) = explicit {
        let override_identity = canonical_helper(override_path).with_context(|| {
            format!(
                "cannot resolve {} from {}",
                spec.binary, spec.explicit_source
            )
        })?;
        if override_identity != selected {
            bail!(
                "{} points to {} but rstack {release} requires the {} helper from its selected generation at {}; a matching version string does not establish selected generation identity",
                spec.explicit_source,
                override_path.display(),
                spec.binary,
                selected.display()
            );
        }
    }
    Ok(Some(selected))
}

fn canonical_helper(path: &Path) -> Result<PathBuf> {
    if !path.is_file() {
        bail!("helper is not an installed file at {}", path.display());
    }
    Ok(fs::canonicalize(path)?)
}

fn missing_component<T>(spec: HelperSpec, release: &str) -> Result<T> {
    bail!(
        "rstack {release} selected generation has no usable {} helper; run `rstack install {}` and retry, bregctl will not install components automatically",
        spec.binary,
        spec.component
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture(root: &Path, spec: HelperSpec) -> (PathBuf, PathBuf) {
        let generation = root.join("generation");
        let selected = generation
            .join("components")
            .join(spec.component)
            .join(spec.binary)
            .join(spec.binary);
        fs::create_dir_all(selected.parent().unwrap()).unwrap();
        fs::write(&selected, b"same version\n").unwrap();
        (generation, selected)
    }

    #[test]
    fn managed_resolution_uses_the_selected_generation_helper() {
        let root = tempfile::tempdir().unwrap();
        let (generation, selected) = fixture(root.path(), BREG);
        let resolved = resolve_managed_with_environment(
            BREG,
            None,
            Some(generation.as_os_str()),
            Some(selected.as_os_str()),
            Some(OsStr::new("v-test")),
        )
        .unwrap();
        assert_eq!(resolved, Some(fs::canonicalize(selected).unwrap()));
    }

    #[test]
    fn managed_resolution_refuses_a_same_version_runtime_with_wrong_identity() {
        let root = tempfile::tempdir().unwrap();
        let (generation, selected) = fixture(root.path(), CASEWORK);
        let override_path = root.path().join("other-casework");
        fs::write(&override_path, b"same version\n").unwrap();
        let error = resolve_managed_with_environment(
            CASEWORK,
            Some(&override_path),
            Some(generation.as_os_str()),
            Some(selected.as_os_str()),
            Some(OsStr::new("v-test")),
        )
        .unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("--casework-bin"), "{diagnostic}");
        assert!(diagnostic.contains("selected generation"), "{diagnostic}");
        assert!(diagnostic.contains("v-test"), "{diagnostic}");
    }

    #[test]
    fn managed_resolution_refuses_a_runtime_environment_outside_the_generation() {
        let root = tempfile::tempdir().unwrap();
        let (generation, _selected) = fixture(root.path(), BREG);
        let outside = root.path().join("outside-breg");
        fs::write(&outside, b"same version\n").unwrap();
        let error = resolve_managed_with_environment(
            BREG,
            None,
            Some(generation.as_os_str()),
            Some(outside.as_os_str()),
            Some(OsStr::new("v-test")),
        )
        .unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("RSTACK_BREG_BIN"), "{diagnostic}");
        assert!(diagnostic.contains("selected generation"), "{diagnostic}");
    }

    #[test]
    fn managed_resolution_names_the_install_command_when_component_is_missing() {
        let root = tempfile::tempdir().unwrap();
        let generation = root.path().join("generation");
        fs::create_dir(&generation).unwrap();
        let error = resolve_managed_with_environment(
            CASEWORKCTL,
            None,
            Some(generation.as_os_str()),
            None,
            Some(OsStr::new("v-test")),
        )
        .unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains("rstack install casework"),
            "{diagnostic}"
        );
        assert!(diagnostic.contains("will not install"), "{diagnostic}");
    }

    #[test]
    fn unmanaged_resolution_preserves_existing_lookup() {
        assert_eq!(
            resolve_managed_with_environment(BREG, None, None, None, None).unwrap(),
            None
        );
    }
}

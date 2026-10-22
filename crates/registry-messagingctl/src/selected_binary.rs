// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy)]
pub(crate) struct HelperSpec {
    pub(crate) binary: &'static str,
    pub(crate) component: &'static str,
    pub(crate) explicit_source: &'static str,
    pub(crate) managed_env: &'static str,
}

pub(crate) const MESSAGING: HelperSpec = HelperSpec {
    binary: "messaging",
    component: "messaging",
    explicit_source: "--messaging-bin or MESSAGING_BIN",
    managed_env: "RSTACK_MESSAGING_BIN",
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
    let generation = fs::canonicalize(Path::new(generation_dir)).map_err(|_| {
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
        return Err(format!(
            "rstack {release} provided {} outside the selected generation helper path at {}; run `rstack install {}` to repair the selected generation",
            spec.managed_env,
            layout_path.display(),
            spec.component
        ));
    }
    if let Some(override_path) = explicit {
        let override_identity = canonical_helper(override_path).map_err(|_| {
            format!(
                "cannot resolve {} from {}",
                spec.binary, spec.explicit_source
            )
        })?;
        if override_identity != selected {
            return Err(format!(
                "{} points to {} but rstack {release} requires the {} helper from its selected generation at {}; a matching version string does not establish selected generation identity",
                spec.explicit_source,
                override_path.display(),
                spec.binary,
                selected.display()
            ));
        }
    }
    Ok(Some(selected))
}

fn canonical_helper(path: &Path) -> Result<PathBuf> {
    if !path.is_file() {
        return Err(format!(
            "helper is not an installed file at {}",
            path.display()
        ));
    }
    fs::canonicalize(path).map_err(|error| error.to_string())
}

fn missing_component<T>(spec: HelperSpec, release: &str) -> Result<T> {
    Err(format!(
        "rstack {release} selected generation has no usable {} helper; run `rstack install {}` and retry, messagingctl will not install components automatically",
        spec.binary,
        spec.component
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(root: &Path) -> (PathBuf, PathBuf) {
        let generation = root.join("generation");
        let selected = generation.join("components/messaging/messaging/messaging");
        fs::create_dir_all(selected.parent().unwrap()).unwrap();
        fs::write(&selected, b"same version\n").unwrap();
        (generation, selected)
    }

    #[test]
    fn managed_resolution_uses_the_selected_generation_runtime() {
        let root = tempfile::tempdir().unwrap();
        let (generation, selected) = fixture(root.path());
        let resolved = resolve_managed_with_environment(
            MESSAGING,
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
        let (generation, selected) = fixture(root.path());
        let override_path = root.path().join("other-messaging");
        fs::write(&override_path, b"same version\n").unwrap();
        let error = resolve_managed_with_environment(
            MESSAGING,
            Some(&override_path),
            Some(generation.as_os_str()),
            Some(selected.as_os_str()),
            Some(OsStr::new("v-test")),
        )
        .unwrap_err();
        let diagnostic = error;
        assert!(diagnostic.contains("MESSAGING_BIN"), "{diagnostic}");
        assert!(diagnostic.contains("selected generation"), "{diagnostic}");
        assert!(diagnostic.contains("v-test"), "{diagnostic}");
    }

    #[test]
    fn managed_resolution_refuses_a_runtime_environment_outside_the_generation() {
        let root = tempfile::tempdir().unwrap();
        let (generation, _) = fixture(root.path());
        let outside = root.path().join("outside-messaging");
        fs::write(&outside, b"same version\n").unwrap();
        let error = resolve_managed_with_environment(
            MESSAGING,
            None,
            Some(generation.as_os_str()),
            Some(outside.as_os_str()),
            Some(OsStr::new("v-test")),
        )
        .unwrap_err();
        let diagnostic = error;
        assert!(diagnostic.contains("RSTACK_MESSAGING_BIN"), "{diagnostic}");
        assert!(diagnostic.contains("selected generation"), "{diagnostic}");
    }

    #[test]
    fn managed_resolution_names_the_install_command_when_component_is_missing() {
        let root = tempfile::tempdir().unwrap();
        let generation = root.path().join("generation");
        fs::create_dir(&generation).unwrap();
        let error = resolve_managed_with_environment(
            MESSAGING,
            None,
            Some(generation.as_os_str()),
            None,
            Some(OsStr::new("v-test")),
        )
        .unwrap_err();
        let diagnostic = error;
        assert!(
            diagnostic.contains("rstack install messaging"),
            "{diagnostic}"
        );
        assert!(diagnostic.contains("will not install"), "{diagnostic}");
    }

    #[test]
    fn unmanaged_resolution_preserves_existing_lookup() {
        assert_eq!(
            resolve_managed_with_environment(MESSAGING, None, None, None, None).unwrap(),
            None
        );
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Build identity shared by the Registry Stack executables.
//!
//! Every executable that reports a version reports [`DISPLAY_VERSION`] rather
//! than its Cargo package version, so an operator can tell a published release
//! from a build of the same source revision. The Cargo package version stays
//! canonical semantic version text, which the release manifests and candidate
//! schemas require.
//!
//! A numbered release sets `REGISTRY_RELEASE_TAG`. A nightly build instead sets
//! `REGISTRY_NIGHTLY_TAG` to its full dated source identity. The markers are
//! mutually exclusive. Absence of both yields a development version.

pub mod render;

include!(concat!(env!("OUT_DIR"), "/display_version.rs"));

#[cfg(test)]
mod tests {
    use super::{DISPLAY_VERSION, IS_NIGHTLY_BUILD, IS_RELEASE_BUILD};

    #[test]
    fn the_reported_version_matches_how_this_crate_was_built() {
        let package_version = env!("CARGO_PKG_VERSION");
        if IS_RELEASE_BUILD {
            assert_eq!(DISPLAY_VERSION, package_version);
        } else if IS_NIGHTLY_BUILD {
            assert!(DISPLAY_VERSION.starts_with(&format!("{package_version}-nightly.")));
        } else {
            assert_eq!(DISPLAY_VERSION, format!("{package_version}-dev"));
        }
    }

    #[test]
    fn an_ordinary_build_never_reports_a_bare_released_version() {
        assert!(
            IS_RELEASE_BUILD || DISPLAY_VERSION != env!("CARGO_PKG_VERSION"),
            "an unmarked build reported {DISPLAY_VERSION}, which reads as a release"
        );
    }
}

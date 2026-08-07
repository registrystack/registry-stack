// SPDX-License-Identifier: Apache-2.0
//! Build identity shared by the Registry Stack executables.
//!
//! Every executable that reports a version reports [`DISPLAY_VERSION`] rather
//! than its Cargo package version, so an operator can tell a published release
//! from a build of the same source revision. The Cargo package version stays
//! canonical semantic version text, which the release manifests, image locks,
//! and candidate schemas all require.
//!
//! The release build sets `REGISTRY_RELEASE_TAG` to the exact tag it is
//! building. Absence of that marker is the ordinary case and yields a
//! development version; a marker naming another version stops the build.

pub mod render;

include!(concat!(env!("OUT_DIR"), "/display_version.rs"));

#[cfg(test)]
mod tests {
    use super::{DISPLAY_VERSION, IS_RELEASE_BUILD};

    #[test]
    fn the_reported_version_matches_how_this_crate_was_built() {
        let package_version = env!("CARGO_PKG_VERSION");
        if IS_RELEASE_BUILD {
            assert_eq!(DISPLAY_VERSION, package_version);
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

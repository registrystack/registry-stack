// SPDX-License-Identifier: Apache-2.0
//! Build-time rendering of the version text an executable reports.
//!
//! This module is compiled twice: once into the library, and once into the
//! crate's build script through a `#[path]` module. It therefore depends on
//! nothing outside the standard library.

use std::fmt;

/// A release marker that does not name the version being compiled.
///
/// A release build carries an exact tag. Any other value is a
/// misconfigured build rather than a development build, so it stops the
/// compilation instead of quietly producing an unmarked executable.
#[derive(Debug, PartialEq, Eq)]
pub struct ReleaseTagMismatch {
    /// The only tag this source revision may be released under.
    pub expected: String,
    /// The tag the build environment supplied.
    pub found: String,
}

impl fmt::Display for ReleaseTagMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "release tag {} does not match this source revision, which builds {}",
            self.found, self.expected
        )
    }
}

impl std::error::Error for ReleaseTagMismatch {}

/// The suffix that separates an ordinary build from a published release.
///
/// It matches the prerelease segment of the `v<version>-dev.<run>.<attempt>`
/// development tags the Evidence development build already publishes.
pub const DEVELOPMENT_SUFFIX: &str = "-dev";

/// Render the version text an executable built from `package_version` reports.
///
/// Only a build whose `release_tag` is exactly `v{package_version}` reports the
/// bare released version. Every other build reports a development version, so
/// an executable built from a working tree, a fork, or protected `main`
/// between releases cannot be mistaken for a published release.
pub fn display_version(
    package_version: &str,
    release_tag: Option<&str>,
) -> Result<String, ReleaseTagMismatch> {
    let expected = format!("v{package_version}");
    match release_tag.map(str::trim).filter(|tag| !tag.is_empty()) {
        Some(tag) if tag == expected => Ok(package_version.to_owned()),
        Some(tag) => Err(ReleaseTagMismatch {
            expected,
            found: tag.to_owned(),
        }),
        None => Ok(format!("{package_version}{DEVELOPMENT_SUFFIX}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unmarked_build_reports_a_development_version() {
        assert_eq!(display_version("0.17.0", None).unwrap(), "0.17.0-dev");
    }

    #[test]
    fn an_empty_marker_reports_a_development_version() {
        for blank in ["", "  ", "\n"] {
            assert_eq!(
                display_version("0.17.0", Some(blank)).unwrap(),
                "0.17.0-dev",
                "blank marker {blank:?} must not claim a release"
            );
        }
    }

    #[test]
    fn the_exact_release_tag_reports_the_released_version() {
        assert_eq!(
            display_version("0.17.0", Some("v0.17.0")).unwrap(),
            "0.17.0"
        );
    }

    #[test]
    fn surrounding_whitespace_does_not_hide_the_release_tag() {
        assert_eq!(
            display_version("0.17.0", Some(" v0.17.0\n")).unwrap(),
            "0.17.0"
        );
    }

    #[test]
    fn a_tag_for_another_version_stops_the_build() {
        let error = display_version("0.17.0", Some("v0.16.3")).unwrap_err();
        assert_eq!(
            error,
            ReleaseTagMismatch {
                expected: "v0.17.0".to_owned(),
                found: "v0.16.3".to_owned(),
            }
        );
        assert!(
            error.to_string().contains("v0.16.3") && error.to_string().contains("v0.17.0"),
            "the failure must name both tags: {error}"
        );
    }

    #[test]
    fn an_untagged_version_string_stops_the_build() {
        for malformed in ["0.17.0", "release-0.17.0", "v0.17", "v0.17.0-dev"] {
            assert!(
                display_version("0.17.0", Some(malformed)).is_err(),
                "marker {malformed:?} is not the release tag and must not claim a release"
            );
        }
    }
}

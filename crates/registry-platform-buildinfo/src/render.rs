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

/// A supplied build marker cannot describe this build identity.
#[derive(Debug, PartialEq, Eq)]
pub struct BuildIdentityError(pub String);

impl fmt::Display for BuildIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BuildIdentityError {}

/// The suffix that separates an ordinary build from a published release.
///
/// It matches the prerelease segment of the `v<version>-dev.<run>.<attempt>`
/// development tags the Evidence development build already publishes.
pub const DEVELOPMENT_SUFFIX: &str = "-dev";

fn marker(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn valid_date(value: &str) -> bool {
    if value.len() != 8 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let year = value[0..4].parse::<u32>().expect("digits were checked");
    if year == 0 {
        return false;
    }
    let month = value[4..6].parse::<u32>().expect("digits were checked");
    let day = value[6..8].parse::<u32>().expect("digits were checked");
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

fn validate_nightly_tag(package_version: &str, tag: &str) -> Result<(), BuildIdentityError> {
    let expected_prefix = format!("v{package_version}-nightly.");
    let Some(remainder) = tag.strip_prefix(&expected_prefix) else {
        return Err(BuildIdentityError(format!(
            "nightly tag {tag} does not match package version {package_version}"
        )));
    };
    let Some((date, source_sha)) = remainder.split_once('.') else {
        return Err(BuildIdentityError(format!(
            "nightly tag {tag} must end in YYYYMMDD.<40-character lowercase source SHA>"
        )));
    };
    if !valid_date(date) {
        return Err(BuildIdentityError(format!(
            "nightly tag {tag} contains an invalid YYYYMMDD date"
        )));
    }
    if source_sha.len() != 40
        || !source_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BuildIdentityError(format!(
            "nightly tag {tag} must end in a 40-character lowercase source SHA"
        )));
    }
    Ok(())
}

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
    match marker(release_tag) {
        Some(tag) if tag == expected => Ok(package_version.to_owned()),
        Some(tag) => Err(ReleaseTagMismatch {
            expected,
            found: tag.to_owned(),
        }),
        None => Ok(format!("{package_version}{DEVELOPMENT_SUFFIX}")),
    }
}

/// Render a version from mutually exclusive numbered-release and nightly markers.
pub fn display_build_version(
    package_version: &str,
    release_tag: Option<&str>,
    nightly_tag: Option<&str>,
) -> Result<String, BuildIdentityError> {
    let release_tag = marker(release_tag);
    let nightly_tag = marker(nightly_tag);
    if release_tag.is_some() && nightly_tag.is_some() {
        return Err(BuildIdentityError(
            "REGISTRY_RELEASE_TAG and REGISTRY_NIGHTLY_TAG are mutually exclusive".to_owned(),
        ));
    }
    if let Some(tag) = release_tag {
        return display_version(package_version, Some(tag))
            .map_err(|error| BuildIdentityError(error.to_string()));
    }
    if let Some(tag) = nightly_tag {
        validate_nightly_tag(package_version, tag)?;
        return Ok(tag
            .strip_prefix('v')
            .expect("validated nightly tags start with v")
            .to_owned());
    }
    display_version(package_version, None).map_err(|error| BuildIdentityError(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

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
    fn nightly_reports_the_complete_tag_identity_without_the_tag_prefix() {
        let tag = format!("v0.39.0-nightly.20261002.{SHA}");
        assert_eq!(
            display_build_version("0.39.0", None, Some(&tag)).unwrap(),
            tag.strip_prefix('v').unwrap()
        );
    }

    #[test]
    fn release_and_nightly_markers_are_mutually_exclusive() {
        let error = display_build_version(
            "0.39.0",
            Some("v0.39.0"),
            Some(&format!("v0.39.0-nightly.20261002.{SHA}")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn nightly_base_must_match_the_package_version() {
        let error = display_build_version(
            "0.39.0",
            None,
            Some(&format!("v0.38.0-nightly.20261002.{SHA}")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not match package version"));
    }

    #[test]
    fn nightly_requires_a_real_date_and_full_lowercase_sha() {
        for tag in [
            format!("v0.39.0-nightly.20260229.{SHA}"),
            "v0.39.0-nightly.20261002.0123456789abcdef".to_owned(),
            format!("v0.39.0-nightly.20261002.{}", SHA.to_uppercase()),
        ] {
            assert!(
                display_build_version("0.39.0", None, Some(&tag)).is_err(),
                "invalid nightly tag was accepted: {tag}"
            );
        }
        assert!(display_build_version(
            "0.39.0",
            None,
            Some(&format!("v0.39.0-nightly.20240229.{SHA}"))
        )
        .is_ok());
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

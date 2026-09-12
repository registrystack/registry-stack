//! The single upstream version and image pin.
//!
//! `thunderid-version.json`, beside this crate's manifest, is the only
//! maintained input naming an upstream release. Nothing here selects `latest`
//! or an unreviewed branch build, and a newer upstream release is adopted only
//! by changing this file and re-running the integration checks.

use serde::Deserialize;

use crate::ToolingError;

/// The pinned upstream release this tooling renders and runs.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ThunderIdPin {
    /// The upstream semantic version, e.g. `1.0.1`.
    pub version: String,
    /// The exact image reference including the immutable digest.
    pub image: String,
}

#[derive(Deserialize)]
struct PinFile {
    schema: String,
    version: String,
    image: String,
}

const PIN_FILE: &str = include_str!("../thunderid-version.json");
const PIN_SCHEMA: &str = "registry.thunderid-pin/v1";

impl ThunderIdPin {
    /// Load and validate the maintained pin.
    pub fn load() -> Result<Self, ToolingError> {
        Self::parse(PIN_FILE)
    }

    /// Validate pin-file bytes. A reference without an `@sha256:` digest is
    /// refused: it would let the same tag silently name different bytes on a
    /// later pull, which is exactly what a reviewed pin exists to prevent.
    fn parse(text: &str) -> Result<Self, ToolingError> {
        let file: PinFile = serde_json::from_str(text).map_err(|_| ToolingError::InvalidPin {
            reason: "the pin file is not readable JSON",
        })?;
        if file.schema != PIN_SCHEMA {
            return Err(ToolingError::InvalidPin {
                reason: "the pin file names an unknown schema",
            });
        }
        if file.version.is_empty() || !file.image.starts_with("ghcr.io/thunder-id/thunderid:") {
            return Err(ToolingError::InvalidPin {
                reason: "the pin file must name the upstream repository with a version tag",
            });
        }
        let (tag, digest) = file
            .image
            .split_once("@sha256:")
            .ok_or(ToolingError::InvalidPin {
                reason: "the pinned image must carry an immutable sha256 digest",
            })?;
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ToolingError::InvalidPin {
                reason: "the pinned image digest is malformed",
            });
        }
        if !tag.ends_with(&format!(":{}", file.version)) {
            return Err(ToolingError::InvalidPin {
                reason: "the pinned image tag and version disagree",
            });
        }
        Ok(Self {
            version: file.version,
            image: file.image,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "d3c0613ff447a551fd440768a15bdfb6668948e80809cbb50f82d6752f22ab3e";

    fn pin_file(version: &str, image: &str) -> String {
        format!("{{\"schema\":\"{PIN_SCHEMA}\",\"version\":\"{version}\",\"image\":\"{image}\"}}")
    }

    #[test]
    fn the_maintained_pin_loads_with_an_immutable_digest() {
        let pin = ThunderIdPin::load().expect("the maintained pin is valid");
        assert_eq!(pin.version, "1.0.1");
        assert_eq!(
            pin.image,
            format!("ghcr.io/thunder-id/thunderid:1.0.1@sha256:{DIGEST}")
        );
    }

    #[test]
    fn a_floating_or_mismatched_pin_is_refused() {
        for (label, image) in [
            ("a floating tag with no digest", "ghcr.io/thunder-id/thunderid:1.0.1"),
            (
                "a digest under the wrong tag",
                "ghcr.io/thunder-id/thunderid:1.0.2@sha256:d3c0613ff447a551fd440768a15bdfb6668948e80809cbb50f82d6752f22ab3e",
            ),
            ("a truncated digest", "ghcr.io/thunder-id/thunderid:1.0.1@sha256:short"),
            ("a foreign repository", "ghcr.io/other/other:1.0.1@sha256:short"),
        ] {
            let parsed = ThunderIdPin::parse(&pin_file("1.0.1", image));
            assert!(parsed.is_err(), "{label} was accepted: {image}");
        }
        assert!(ThunderIdPin::parse(&pin_file(
            "1.0.1",
            &format!("ghcr.io/thunder-id/thunderid:1.0.1@sha256:{DIGEST}")
        ))
        .is_ok());
    }
}

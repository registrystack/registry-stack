// SPDX-License-Identifier: Apache-2.0
//! Build-script support for independently versioned product executables.

use std::env;
use std::fs;
use std::path::PathBuf;

use crate::render::display_product_build_version;

/// The release marker used for one independently versioned product.
pub const PRODUCT_RELEASE_TAG_VARIABLE: &str = "REGISTRY_PRODUCT_RELEASE_TAG";
/// The legacy release marker used for one Registry Stack release.
pub const RELEASE_TAG_VARIABLE: &str = "REGISTRY_RELEASE_TAG";
/// The common nightly marker used by Registry Stack development builds.
pub const NIGHTLY_TAG_VARIABLE: &str = "REGISTRY_NIGHTLY_TAG";

fn generated_product_build_info(
    display_version: &str,
    is_release_build: bool,
    is_nightly_build: bool,
) -> String {
    format!(
        "/// The product version text this executable reports to an operator.\n\
         pub const DISPLAY_VERSION: &str = {display_version:?};\n\
         \n\
         /// Whether this executable was built as a numbered product release.\n\
         pub const IS_RELEASE_BUILD: bool = {is_release_build};\n\
         \n\
         /// Whether this executable was built by the Registry Stack nightly build.\n\
         pub const IS_NIGHTLY_BUILD: bool = {is_nightly_build};\n"
    )
}

/// Generate build identity constants for one independently versioned product.
///
/// Call this once from the product package's `build.rs`, then include
/// `product_build_info.rs` from that package. Cargo supplies the product
/// package version to the build script; the build-info crate's own package
/// version validates legacy Stack and common nightly markers.
pub fn emit_product_build_info(product: &str) {
    println!("cargo:rerun-if-env-changed={PRODUCT_RELEASE_TAG_VARIABLE}");
    println!("cargo:rerun-if-env-changed={RELEASE_TAG_VARIABLE}");
    println!("cargo:rerun-if-env-changed={NIGHTLY_TAG_VARIABLE}");

    let product_version =
        env::var("CARGO_PKG_VERSION").expect("Cargo must provide CARGO_PKG_VERSION");
    let platform_version = env!("CARGO_PKG_VERSION");
    let product_release_tag = env::var(PRODUCT_RELEASE_TAG_VARIABLE).ok();
    let release_tag = env::var(RELEASE_TAG_VARIABLE).ok();
    let nightly_tag = env::var(NIGHTLY_TAG_VARIABLE).ok();
    let display_version = display_product_build_version(
        product,
        &product_version,
        platform_version,
        product_release_tag.as_deref(),
        release_tag.as_deref(),
        nightly_tag.as_deref(),
    )
    .unwrap_or_else(|error| panic!("invalid {product} build identity: {error}"));
    let is_release_build = display_version == product_version;
    let is_nightly_build = nightly_tag
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    let generated =
        generated_product_build_info(&display_version, is_release_build, is_nightly_build);
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must provide OUT_DIR"))
        .join("product_build_info.rs");
    fs::write(output, generated).expect("product build identity must be writable");
}

#[cfg(test)]
mod tests {
    use super::generated_product_build_info;

    #[test]
    fn generated_constants_preserve_a_divergent_product_identity() {
        let source = generated_product_build_info(
            "1.7.2-nightly.20261002.0123456789abcdef0123456789abcdef01234567",
            false,
            true,
        );

        assert!(source.contains(
            "pub const DISPLAY_VERSION: &str = \"1.7.2-nightly.20261002.0123456789abcdef0123456789abcdef01234567\";"
        ));
        assert!(source.contains("pub const IS_RELEASE_BUILD: bool = false;"));
        assert!(source.contains("pub const IS_NIGHTLY_BUILD: bool = true;"));
    }
}

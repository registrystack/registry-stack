// SPDX-License-Identifier: Apache-2.0

#[path = "src/render.rs"]
mod render;

use std::env;
use std::fs;
use std::path::PathBuf;

/// The build environment variable a Registry Stack release build sets.
const RELEASE_TAG_VARIABLE: &str = "REGISTRY_RELEASE_TAG";
const NIGHTLY_TAG_VARIABLE: &str = "REGISTRY_NIGHTLY_TAG";

fn main() {
    println!("cargo:rerun-if-env-changed={RELEASE_TAG_VARIABLE}");
    println!("cargo:rerun-if-env-changed={NIGHTLY_TAG_VARIABLE}");

    let package_version =
        env::var("CARGO_PKG_VERSION").expect("Cargo must provide CARGO_PKG_VERSION");
    let release_tag = env::var(RELEASE_TAG_VARIABLE).ok();
    let nightly_tag = env::var(NIGHTLY_TAG_VARIABLE).ok();
    let display_version = render::display_build_version(
        &package_version,
        release_tag.as_deref(),
        nightly_tag.as_deref(),
    )
    .unwrap_or_else(|error| panic!("invalid build identity: {error}"));
    let is_release_build = display_version == package_version;
    let is_nightly_build = nightly_tag
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());

    let generated = format!(
        "/// The version text this executable reports to an operator.\n\
         ///\n\
         /// A published release reports the bare released version. A nightly\n\
         /// build reports its full dated source identity, and an unmarked build\n\
         /// reports a development version.\n\
         pub const DISPLAY_VERSION: &str = {display_version:?};\n\
         \n\
         /// Whether this build was produced by the Registry Stack release build.\n\
         pub const IS_RELEASE_BUILD: bool = {is_release_build};\n\
         \n\
         /// Whether this build was produced by the Registry Stack nightly build.\n\
         pub const IS_NIGHTLY_BUILD: bool = {is_nightly_build};\n"
    );
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must provide OUT_DIR"))
        .join("display_version.rs");
    fs::write(output, generated).expect("build identity must be writable");
}

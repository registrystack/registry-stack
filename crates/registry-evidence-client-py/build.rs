// Emits the macOS `-undefined dynamic_lookup` linker argument PyO3's own
// `extension-module` feature needs for a Python-loadable `cdylib`.
//
// The `extension-module` Cargo feature only tells `pyo3`/`pyo3-ffi`'s own
// build scripts to stop linking this crate against libpython (an extension
// module is `dlopen`ed by an already-running Python process, which supplies
// those symbols itself); it does not, on its own, add the linker flag macOS
// needs to accept a `cdylib` whose Python symbols are left unresolved until
// load time. Compare `crates/registry-evidence-client-node/build.rs`, where
// napi-rs's own `napi_build::setup()` handles the equivalent flag for that
// binding.
//
// This must run only when this crate's own `extension-module` feature is
// enabled: the ordinary build (used by `cargo test`, with the
// `auto-initialize` dev-dependency) embeds Python instead, and linking
// directly against libpython is exactly what that mode needs, so adding this
// flag there would break it.
//
// That embedding build is the other branch below. It links against
// `@rpath/libpython3.x.dylib` (`libpython3.x.so` on Linux) but records no
// rpath of its own, so every test binary this crate produces dies at process
// startup on any machine whose interpreter lives outside the dynamic linker's
// default search path: a `mise`-, `pyenv`- or virtualenv-managed Python, which
// is to say most development machines. That failure is not a test failure. It
// happens before any test runs, and because `cargo test --workspace` stops at
// the first non-zero exit, it also silently skips every suite ordered after
// this crate. Recording the interpreter's own library directory as an rpath is
// what `pyo3` recommends for embedding builds; the shipped extension module
// never carries it, since the wheel is always built through the branch above.
fn main() {
    if std::env::var_os("CARGO_FEATURE_EXTENSION_MODULE").is_some() {
        pyo3_build_config::add_extension_module_link_args();
    } else {
        pyo3_build_config::add_libpython_rpath_link_args();
        add_fips_crypto_rpath_link_args();
    }
}

/// Record the AWS-LC FIPS module's build directory as an rpath, for the same
/// reason the interpreter directory is recorded above.
///
/// The workspace builds AWS-LC with the `fips` feature, which links the crypto
/// module as a shared library (`libaws_lc_fips_*_crypto.dylib`) rather than
/// statically, so this crate's embedding build gains a second startup-time
/// dependency next to libpython. Cargo runs test binaries with the module's
/// build directory on the loader fallback path, which is why an ordinary
/// `cargo test` never notices; the re-execution contract test clears those
/// variables, and a binary with no rpath for the module cannot start at all.
///
/// The module's artifacts live under per-fingerprint build-script directories
/// (`aws-lc-fips-sys-<hash>/out/build/artifacts`), and a build script cannot
/// learn which fingerprint its own compilation will link, so every candidate
/// directory is recorded. Stale entries point at directories dyld then skips.
/// Like the interpreter rpath, this applies only to the embedding build: the
/// shipped wheel is always built through the `extension-module` branch and
/// vendors the module at packaging time instead.
fn add_fips_crypto_rpath_link_args() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "macos" && target_os != "linux" {
        return;
    }
    // `OUT_DIR` is `<target>/build/<this package>-<hash>/out`; the directory
    // holding every package's build-script output is two levels up.
    let Some(out_dir) = std::env::var_os("OUT_DIR") else {
        return;
    };
    let Some(build_dir) = std::path::Path::new(&out_dir)
        .ancestors()
        .nth(2)
        .map(std::path::Path::to_path_buf)
    else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(&build_dir) else {
        return;
    };
    let mut artifact_dirs = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("aws-lc-fips-sys-"))
        })
        .map(|path| path.join("out").join("build").join("artifacts"))
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    artifact_dirs.sort();
    for dir in artifact_dirs {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dir.display());
    }
}

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
fn main() {
    if std::env::var_os("CARGO_FEATURE_EXTENSION_MODULE").is_some() {
        pyo3_build_config::add_extension_module_link_args();
    }
}

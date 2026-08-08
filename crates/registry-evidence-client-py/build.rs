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
    }
}

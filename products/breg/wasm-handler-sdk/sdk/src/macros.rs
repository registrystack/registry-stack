//! The export macros: the only code a handler crate writes to become a
//! module.

/// The body both export macros share: the four ABI functions. They live in a
/// generated module so their names never collide with the handler crate's
/// own functions (a handler named `handle` is the natural thing to write);
/// `#[unsafe(no_mangle)]` fixes the exported symbol name regardless of the
/// Rust module that holds it. The handler itself is resolved into a const at
/// the invocation site, before the generated module's own names could
/// shadow its path, and a second macro invocation in one crate is a
/// duplicate-module compile error, which is the one-handler-per-module
/// contract stated as code.
// The shared body, exported (and doc-hidden) only so the two public macros
// can invoke it through `$crate::`.
#[doc(hidden)]
#[macro_export]
macro_rules! breg_wasm_exports {
    ($handler:path) => {
        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        const BREG_WASM_HANDLER: fn(
            $crate::Request,
        ) -> Result<$crate::Outcome, $crate::HandlerFailure> = $handler;

        /// The generated guest byte ABI. Handler authors never call into
        /// this module; the platform executor does, at runtime.
        pub mod breg_wasm_abi {
            #[unsafe(no_mangle)]
            pub extern "C" fn alloc(len: usize) -> *mut u8 {
                $crate::abi::alloc(len)
            }

            #[unsafe(no_mangle)]
            #[allow(clippy::not_unsafe_ptr_arg_deref)]
            pub extern "C" fn handle(pointer: *const u8, len: usize) -> i32 {
                $crate::abi::handle(pointer, len, super::BREG_WASM_HANDLER)
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn result_ptr() -> *const u8 {
                $crate::abi::result_ptr()
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn result_len() -> usize {
                $crate::abi::result_len()
            }
        }
    };
}

/// Export the four guest-ABI functions backed by `$handler`.
///
/// `$handler` is a function `fn(Request) -> Result<Outcome, HandlerFailure>`
/// (or a path to one). The generated module imports nothing and is what the
/// platform executor prepares and runs. Invoke at most once per crate: the
/// macros define the module's ABI exports, and one module carries one handler
/// (the production shape the registry packages).
#[macro_export]
macro_rules! handler {
    ($handler:path) => {
        $crate::breg_wasm_exports!($handler);
    };
}

/// Like [`handler!`], plus an `init` export for build-time
/// pre-initialization: the pre-initializer runs `$init` once at build time
/// and snapshots the initialized memory, so lazily initialized statics (for
/// example, library metadata tables) are warm in every later instantiation.
/// `$init` takes no arguments and returns nothing; its outcomes are
/// discarded, only the warmed statics matter. At ordinary runtime `init` is
/// never called.
#[macro_export]
macro_rules! handler_with_init {
    ($handler:path, $init:path) => {
        $crate::breg_wasm_exports!($handler);

        #[unsafe(no_mangle)]
        pub extern "C" fn init() {
            $init()
        }
    };
}

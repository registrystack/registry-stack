//! `registry-render` — governed, byte-stable PDF documents from registry
//! data, rendered with Typst in library mode.
//!
//! The crate is a pure function at heart: a sealed template bundle plus a
//! validated request in, an identical PDF plus hashes out, every time. The
//! world a template sees contains exactly the bundle, the request's decoded
//! assets, and the vendored packages — no host fonts, no network, no clock
//! except the document's own `issuedAt`.
//!
//! Invariants that hold by construction and are pinned by tests:
//!
//! - **Injected bytes are the hashed bytes**: `sys.inputs.data` is exactly
//!   the RFC 8785 canonicalization of the envelope whose sha256 is
//!   `dataSha256`.
//! - **Fresh world and library per render**: inputs live on the `Library`,
//!   so nothing request-scoped is shared or memoized across renders;
//!   `comemo::evict()` runs after every render.
//! - **Deterministic font order**: the binary's baseline set first, then
//!   bundle fonts sorted by path — mirroring the Typst CLI's book so
//!   library and CLI renders agree byte for byte. Never filesystem
//!   iteration order.
//! - **Path safety is world-enforced**: lexical rejection of `..` and
//!   absolute components, canonicalize-then-contain on every resolution,
//!   symlink escapes included.

pub mod audit;
pub mod bundle;
pub mod check;
pub mod cli;
pub mod envelope;
pub mod hash;
pub mod init;
pub mod manifest;
pub mod openapi;
pub mod problem;
pub mod render;
pub mod runtime;
pub mod server;
pub mod worker;
pub mod world;

pub use bundle::{Bundle, LoadedDocument};
pub use manifest::{DocumentSpec, Manifest, PdfStandardSpec};
pub use problem::{ProblemKind, RenderProblem};
pub use render::{decode_assets, validate_data, DEFAULT_MAX_OUTPUT_BYTES};
pub use render::{render, render_with_limits, RenderRequest, Rendered};

/// The Typst compiler pin this binary renders with. Kept in lockstep with
/// the `typst` entry in the workspace `Cargo.toml`/`Cargo.lock`; the golden
/// hash tests fail if the constant and the dependency drift apart.
pub const TYPST_PIN: &str = "0.15.1";

/// The operator-facing version string: the release version plus the Typst
/// pin. "Pinned binary" is a first-class version fact, reported by
/// `--version`, `/health`, and every audit event.
pub fn display_version() -> String {
    format!(
        "{} (typst {TYPST_PIN})",
        registry_platform_buildinfo::DISPLAY_VERSION
    )
}

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
//!   `comemo::evict()` runs after every compile.
//! - **Deterministic font order**: the binary's baseline set first, then
//!   bundle fonts sorted by path — mirroring the Typst CLI's book so
//!   library and CLI renders agree byte for byte. Never filesystem
//!   iteration order.
//! - **Path safety is world-enforced**: every resolution canonicalizes and
//!   must stay under its root (symlink escapes included), behind a lexical
//!   pre-rejection of `..` and absolute components. Containment is the
//!   check; the lexical pass only fails faster.

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
/// the `typst` entry in the workspace `Cargo.toml`/`Cargo.lock`; the unit
/// test below fails the build if the constant and the linked dependency
/// drift apart, and the golden hash tests fail if output bytes move.
pub const TYPST_PIN: &str = "0.15.1";

/// The fixed, version-free `/Creator` string written into every PDF. The
/// renderer version must appear nowhere in the PDF bytes (PAYLOAD.md), so
/// this string never carries one; `tests/golden.rs` pins its presence.
pub const PDF_CREATOR: &str = "registry-render";

/// The operator-facing version string: the release version plus the Typst
/// pin. "Pinned binary" is a first-class version fact, reported by
/// `--version`, `/health`, and every audit event.
pub fn display_version() -> String {
    format!(
        "{} (typst {TYPST_PIN})",
        registry_platform_buildinfo::DISPLAY_VERSION
    )
}

#[cfg(test)]
mod tests {
    use super::TYPST_PIN;

    #[test]
    fn typst_pin_matches_the_linked_typst() {
        assert_eq!(
            TYPST_PIN,
            typst::utils::version().raw(),
            "TYPST_PIN drifted from the linked typst crate; update the constant or the dependency, then re-review the golden hashes"
        );
    }
}

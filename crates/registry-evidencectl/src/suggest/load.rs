//! Obtains the text of an OpenAPI document so the authoring library can read
//! it.
//!
//! The interpretation of a description lives in `registry-evidence-authoring`,
//! which performs no input or output so that an editor can run it against an
//! unsaved buffer. Something still has to reach the document, and this module
//! is that something: it dispatches a [`SpecSource`] to the filesystem or to
//! [`super::fetch`], applies the size ceiling, and hands the resulting text to
//! [`Spec::parse`].

use std::path::Path;

use anyhow::{bail, Context, Result};

use registry_evidence_authoring::openapi::{openapi::Spec, types::SpecSource};

use super::fetch;

/// OpenAPI documents larger than this are rejected before they are read, the
/// way `sample::load_sample` rejects an oversized sample. The largest published
/// registry API descriptions are a few megabytes; a document past this ceiling
/// is a mistaken path rather than a specification to draft from.
const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

/// Reads and parses the OpenAPI document `source` names, from disk or
/// from the network. Accepts YAML or JSON (YAML is a superset for this
/// purpose, so both are parsed the same way) and requires a top-level
/// `openapi: 3.0.x` or `3.1.x` version string.
pub fn open(source: &SpecSource) -> Result<Spec> {
    open_retained(source).map(|(spec, _)| spec)
}

/// Read and validate a document once while retaining its exact UTF-8 text.
///
/// `evidencectl new` stores this text for the later question-authoring
/// step. Returning it from the same read that produced `Spec` prevents a
/// file change or a second network response from making the retained
/// document differ from the one that was validated.
pub fn open_retained(source: &SpecSource) -> Result<(Spec, String)> {
    let text = match source {
        SpecSource::File(path) => read_local(path)?,
        SpecSource::Url(url) => fetch::get(url, MAX_DOCUMENT_BYTES)?,
    };
    let spec = Spec::parse(&text, &source.display())?;
    Ok((spec, text))
}

/// Reads a local document, refusing one past the size ceiling before any of
/// it is read into memory.
fn read_local(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading OpenAPI document metadata at {}", path.display()))?;
    if metadata.len() > MAX_DOCUMENT_BYTES {
        bail!(
            "OpenAPI document at {} is {} bytes, exceeding the {} byte limit",
            path.display(),
            metadata.len(),
            MAX_DOCUMENT_BYTES
        );
    }
    std::fs::read_to_string(path)
        .with_context(|| format!("reading OpenAPI document at {}", path.display()))
}

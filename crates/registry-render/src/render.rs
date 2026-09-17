//! The render pipeline: validate, canonicalize, compile, export, hash.

use std::collections::BTreeMap;

use base64::Engine as _;
use chrono::{DateTime, Datelike, Timelike, Utc};

use crate::bundle::{
    Bundle, LoadedDocument, DEFAULT_MAX_ASSET_BYTES, DEFAULT_MAX_TOTAL_ASSET_BYTES,
};
use crate::envelope::{build_envelope, canonical_bytes, EnvelopeInput};
use crate::hash::sha256_hex;
use crate::problem::{ProblemKind, RenderProblem};
use crate::world::RenderWorld;

/// Default output ceiling; runtimes may lower it, never raise it past this.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// One render request. `data` must already be parsed JSON; everything else
/// is validated here.
#[derive(Debug, Clone)]
pub struct RenderRequest {
    /// Optional primary locale; must be one of the document's label tables.
    pub locale: Option<String>,
    /// The document data, validated against the document's JSON Schema.
    pub data: serde_json::Value,
    /// Request assets, name -> base64. Decoded bytes are served to the
    /// template as `assets/<name>`; the base64 text is hashed in the envelope.
    pub assets: BTreeMap<String, String>,
    /// Issuance time: the document's claim about when it was issued. It is
    /// the world clock and the PDF creation timestamp, never wall clock.
    pub issued_at: DateTime<Utc>,
}

/// A successfully rendered document.
#[derive(Debug, Clone)]
pub struct Rendered {
    pub pdf: Vec<u8>,
    pub pdf_sha256: String,
    /// sha256 over the exact canonical envelope bytes injected into the
    /// template. Store this on the record.
    pub data_sha256: String,
    /// The exact canonical envelope bytes (for CLI output and tests).
    pub envelope_bytes: Vec<u8>,
    pub document_id: String,
    pub document_version: u32,
    pub bundle_version: u32,
    pub bundle_hash: String,
    /// The virtual file closure this render consumed.
    pub deps: Vec<String>,
    /// Human-readable Typst warnings (missing glyphs, layout notes).
    pub warnings: Vec<String>,
}

/// Validate request data against the document's schema, without rendering.
/// Returns JSON pointers for every violation.
pub fn validate_data(
    document: &LoadedDocument,
    request: &RenderRequest,
) -> Result<(), RenderProblem> {
    if let Some(locale) = &request.locale {
        if !document.labels.contains_key(locale) {
            return Err(RenderProblem::new(
                ProblemKind::DataInvalid,
                format!(
                    "locale {locale:?} is not declared for document {:?}",
                    document.spec.id
                ),
            )
            .with_pointers(vec!["/locale".to_owned()]));
        }
    }
    let schema = match &document.schema {
        None => return Ok(()),
        Some(schema) => schema,
    };
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(schema)
        .map_err(|err| {
            RenderProblem::new(
                ProblemKind::ManifestInvalid,
                format!("document schema does not compile: {err}"),
            )
        })?;
    let outcome = validator.validate(&request.data);
    match outcome {
        Ok(()) => Ok(()),
        Err(errors) => {
            let mut pointers = Vec::new();
            let mut messages = Vec::new();
            for err in errors {
                pointers.push(format!("/data{}", err.instance_path));
                messages.push(err.to_string());
            }
            Err(RenderProblem::new(
                ProblemKind::DataInvalid,
                format!("data does not match the schema: {}", messages.join("; ")),
            )
            .with_pointers(pointers))
        }
    }
}

/// Decode and check request assets: base64, allowed media type (jpeg/png),
/// bounded size. Returns the decoded bytes per asset name.
pub fn decode_assets(
    request: &RenderRequest,
    max_asset: usize,
    max_total: usize,
) -> Result<BTreeMap<String, typst::foundations::Bytes>, RenderProblem> {
    let mut decoded = BTreeMap::new();
    let mut total = 0usize;
    for (name, b64) in &request.assets {
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(RenderProblem::new(
                ProblemKind::AssetInvalid,
                format!("asset name {name:?} must be alphanumeric/kebab"),
            ));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| {
                RenderProblem::new(
                    ProblemKind::AssetInvalid,
                    format!("asset {name:?} is not valid base64"),
                )
            })?;
        if bytes.len() > max_asset {
            return Err(RenderProblem::new(
                ProblemKind::AssetInvalid,
                format!(
                    "asset {name:?} is {} bytes; the limit is {max_asset}",
                    bytes.len()
                ),
            ));
        }
        total += bytes.len();
        if total > max_total {
            return Err(RenderProblem::new(
                ProblemKind::AssetInvalid,
                format!("request assets total over {max_total} bytes"),
            ));
        }
        sniff_media_type(&bytes, name)?;
        decoded.insert(name.clone(), typst::foundations::Bytes::new(bytes));
    }
    Ok(decoded)
}

fn sniff_media_type(bytes: &[u8], name: &str) -> Result<(), RenderProblem> {
    let is_jpeg = bytes.len() > 3 && bytes[0] == 0xFF && bytes[1] == 0xD8;
    let is_png = bytes.len() > 8 && bytes[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if !is_jpeg && !is_png {
        return Err(RenderProblem::new(
            ProblemKind::AssetInvalid,
            format!("asset {name:?} must be a JPEG or PNG image"),
        ));
    }
    Ok(())
}

/// Render one document from one request. Pure: no network, no state outside
/// the bundle and the request.
pub fn render(
    bundle: &Bundle,
    document: &LoadedDocument,
    request: &RenderRequest,
    strict: bool,
) -> Result<Rendered, RenderProblem> {
    render_with_limits(bundle, document, request, strict, DEFAULT_MAX_OUTPUT_BYTES)
}

/// Render with an explicit output ceiling (used by the worker to apply the
/// runtime's limits).
pub fn render_with_limits(
    bundle: &Bundle,
    document: &LoadedDocument,
    request: &RenderRequest,
    strict: bool,
    max_output_bytes: usize,
) -> Result<Rendered, RenderProblem> {
    validate_data(document, request)?;
    let decoded_assets = decode_assets(
        request,
        DEFAULT_MAX_ASSET_BYTES,
        DEFAULT_MAX_TOTAL_ASSET_BYTES,
    )?;

    // Envelope: build, canonicalize, hash. The same bytes are injected.
    let envelope = build_envelope(&EnvelopeInput {
        document_id: &document.spec.id,
        document_version: document.spec.version,
        labels: &document.labels,
        locale: request.locale.as_deref(),
        issued_at: request.issued_at,
        data: &request.data,
        assets: &request.assets,
    });
    let envelope_bytes = canonical_bytes(&envelope)?;
    let data_sha256 = sha256_hex(&envelope_bytes);
    let envelope_json = String::from_utf8(envelope_bytes.clone())
        .map_err(|_| RenderProblem::new(ProblemKind::Internal, "envelope not UTF-8"))?;

    // Fresh world and library per render; inputs ride the library.
    let world = RenderWorld::new(
        &bundle.root,
        bundle.fonts.clone(),
        document.spec.entry.to_string_lossy().as_ref(),
        decoded_assets,
        request.issued_at,
        envelope_json,
    )
    .map_err(|detail| {
        RenderProblem::new(
            ProblemKind::Internal,
            format!("world construction: {detail}"),
        )
    })?;

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| typst::compile(&world)));
    comemo::evict(0);
    let warned = match result {
        Ok(warned) => warned,
        Err(_) => {
            return Err(RenderProblem::new(
                ProblemKind::RenderPanicked,
                "the renderer hit an internal error while compiling; the worker is recycled",
            ))
        }
    };
    let compiled = match warned.output {
        Ok(document) => document,
        Err(errors) => {
            let detail = world.redact_host_paths(&format_diagnostics(&world, &errors));
            return Err(RenderProblem::new(
                ProblemKind::CompileFailed,
                format!("template compile failed: {detail}"),
            ));
        }
    };
    let warnings: Vec<String> = warned
        .warnings
        .iter()
        .map(|diag| world.redact_host_paths(&format_one_diagnostic(&world, diag)))
        .collect();

    // PDF export options otherwise match the Typst CLI defaults (tagged,
    // not pretty); the timestamp is the issuance claim, never wall clock.
    let timestamp_datetime = {
        let naive = request.issued_at.naive_utc();
        typst::foundations::Datetime::from_ymd_hms(
            naive.year(),
            naive.month() as u8,
            naive.day() as u8,
            naive.hour() as u8,
            naive.minute() as u8,
            naive.second() as u8,
        )
    };
    let standards: Vec<typst_pdf::PdfStandard> = document
        .spec
        .pdf_standard
        .iter()
        .map(|spec| spec.to_typst())
        .collect();
    let standards = typst_pdf::PdfStandards::new(&standards).map_err(|err| {
        RenderProblem::new(
            ProblemKind::ManifestInvalid,
            format!("pdf standard combination is invalid: {err:?}"),
        )
    })?;
    // Export options: `ident` is pinned explicitly to Auto (the
    // content-derived PDF id the golden hashes pin) and the creator is the
    // fixed, version-free product string — the renderer version must appear
    // nowhere in the PDF bytes, and a Typst pin bump then changes bytes only
    // when layout changes.
    let options = typst_pdf::PdfOptions {
        timestamp: timestamp_datetime.map(typst_pdf::Timestamp::new_utc),
        standards,
        ident: typst::foundations::Smart::Auto,
        creator: typst::foundations::Smart::Custom(Some(crate::PDF_CREATOR.to_owned())),
        ..typst_pdf::PdfOptions::default()
    };
    // Export sits inside the same panic boundary as the compile: an
    // unwinding typst-pdf panic becomes `render-panicked` (and the worker
    // is recycled by construction) instead of killing the worker mid-frame.
    // Abort-class crashes (stack overflow) still kill the worker; the
    // supervisor maps that to the same problem.
    let export = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        typst_pdf::pdf(&compiled, &options)
    }));
    let pdf = match export {
        Ok(result) => result.map_err(|errors| {
            let detail = world.redact_host_paths(
                &errors
                    .iter()
                    .map(|diag| diag.message.to_string())
                    .collect::<Vec<_>>()
                    .join("; "),
            );
            RenderProblem::new(
                ProblemKind::CompileFailed,
                format!("PDF export failed: {detail}"),
            )
        })?,
        Err(_) => {
            return Err(RenderProblem::new(
                ProblemKind::RenderPanicked,
                "the renderer hit an internal error while exporting the PDF; the worker is recycled",
            ))
        }
    };

    if strict && !warnings.is_empty() {
        return Err(RenderProblem::new(
            ProblemKind::StrictWarnings,
            format!(
                "strict mode refused {} warning(s): {}",
                warnings.len(),
                warnings.join("; ")
            ),
        ));
    }
    if pdf.len() > max_output_bytes {
        return Err(RenderProblem::new(
            ProblemKind::OutputTooLarge,
            format!(
                "rendered PDF is {} bytes; the limit is {max_output_bytes}",
                pdf.len()
            ),
        ));
    }

    Ok(Rendered {
        pdf_sha256: sha256_hex(&pdf),
        pdf,
        data_sha256,
        envelope_bytes,
        document_id: document.spec.id.clone(),
        document_version: document.spec.version,
        bundle_version: bundle.manifest.bundle_version,
        bundle_hash: bundle.bundle_hash.clone(),
        deps: world.closure(),
        warnings,
    })
}

fn format_one_diagnostic(world: &RenderWorld, diag: &typst::diag::SourceDiagnostic) -> String {
    use typst::World;
    use typst::WorldExt;
    let location = diag
        .span
        .id()
        .and_then(|id| world.source(id).ok().map(|source| (id, source)))
        .and_then(|(id, source)| {
            let range = world.range(diag.span)?;
            let line = source.lines().byte_to_line(range.start)? + 1;
            Some(format!("{}:{line}", id.vpath().get_without_slash()))
        });
    match location {
        Some(loc) => format!("{} ({})", loc, diag.message),
        None => diag.message.to_string(),
    }
}

fn format_diagnostics(world: &RenderWorld, errors: &[typst::diag::SourceDiagnostic]) -> String {
    errors
        .iter()
        .map(|diag| format_one_diagnostic(world, diag))
        .collect::<Vec<_>>()
        .join("; ")
}

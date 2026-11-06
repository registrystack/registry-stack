//! PAdES signature fields, written as a PDF incremental update.
//!
//! A seal never changes Render's bytes: it is one incremental update
//! (ISO 32000-2 7.5.6) appended after the exact first revision, so a signed
//! file can always be cut back to the rendered document and hashed.
//!
//! The work splits along the worker boundary:
//!
//! - [`prepare`] runs in the render worker. It reads Render's
//!   single-revision PDF with `hayro-syntax` and appends the catalog
//!   rewritten with an AcroForm and a DocMDP permission, the first page
//!   rewritten with the widget in `/Annots`, an invisible signature field
//!   merged with its widget, an empty appearance stream, and a certification
//!   signature dictionary whose `/Contents` is a run of zero hex digits. The
//!   `/ByteRange` already holds its final values when `prepare` returns.
//! - [`PreparedPdf::check`] runs in the key-holding parent and parses no PDF
//!   objects. It checks the fixed shape by byte offsets only; the parent
//!   then digests [`CheckedPdf::signed_parts`], signs, and splices the CMS
//!   in with [`CheckedPdf::embed`].
//!
//! The fixed shape: the signature dictionary carries
//! `/ByteRange [0 a b c]`, padded with trailing spaces to
//! `BYTE_RANGE_TEXT_LEN` bytes, immediately followed by `/Contents ` and the
//! hex string the byte range leaves out. `/ByteRange` appears once in the
//! update.

mod syntax;

use std::collections::BTreeSet;

use chrono::{DateTime, Datelike, Timelike, Utc};
use hayro_syntax::object::{Array, Dict, MaybeRef, Name, Object, ObjectIdentifier};
use pdf_writer::types::{AnnotationFlags, FieldType};
use pdf_writer::{Chunk, Rect, Ref, Settings, TextStr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::manifest::PdfStandardSpec;

/// The largest CMS signature, in bytes, a field may reserve room for.
pub const MAX_CONTENTS_CAPACITY: usize = 256 * 1024;

/// The longest field name, in bytes, `prepare` writes.
pub const MAX_FIELD_NAME_LEN: usize = 127;

/// Width of the `/ByteRange [...]` text: `/ByteRange [`, four numbers of up
/// to ten digits with three separating spaces, and `]`. Shorter values are
/// padded with trailing spaces, so the final values are written in place.
const BYTE_RANGE_TEXT_LEN: usize = 12 + 4 * 10 + 3 + 1;

const BYTE_RANGE_KEY: &[u8] = b"/ByteRange";

const CONTENTS_KEY: &[u8] = b"/Contents ";

/// Nesting bound when walking from the catalog to the first page.
const MAX_PAGE_TREE_DEPTH: usize = 32;

/// What the signature field carries. The parent fixes these values; the
/// worker writes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureField {
    /// Written as the signature dictionary's `/M`, in UTC. PAdES baseline
    /// signatures carry the claimed signing time here rather than in a CMS
    /// signing-time attribute. Must be a whole second.
    pub signing_time: DateTime<Utc>,
    /// Bytes reserved for the DER CMS signature; `/Contents` holds twice as
    /// many hex digits. At most [`MAX_CONTENTS_CAPACITY`].
    pub contents_capacity: usize,
    /// The field's partial name, `/T`. Non-empty, at most
    /// [`MAX_FIELD_NAME_LEN`] bytes, no period and no control character.
    pub field_name: String,
}

/// Render's PDF with the signature field appended, as the worker returns it.
/// It is untrusted until [`PreparedPdf::check`] accepts it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedPdf {
    /// The whole file: the first revision followed by the update. Serialized
    /// as standard base64.
    #[serde(with = "base64_bytes")]
    pub bytes: Vec<u8>,
    /// The signature dictionary's `/ByteRange`: `[0, gap start, gap end,
    /// bytes after the gap]`, where the gap is the `/Contents` hex string
    /// including its angle brackets.
    pub byte_range: [usize; 4],
}

/// A prepared file whose shape the parent has checked. Only
/// [`PreparedPdf::check`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedPdf {
    bytes: Vec<u8>,
    byte_range: [usize; 4],
}

/// Why a signature field could not be prepared, checked, or filled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PdfSignatureError {
    #[error("the input is not a PDF this signer can read: {0}")]
    Malformed(&'static str),
    #[error("the input PDF is encrypted")]
    Encrypted,
    #[error("the input PDF has more than one revision")]
    NotSingleRevision,
    #[error("the input PDF uses a cross-reference stream; this signer reads cross-reference tables only")]
    CrossReferenceStream,
    #[error("the input PDF already has {0}")]
    AlreadyHas(&'static str),
    #[error("the signature field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("the prepared PDF does not have the expected shape: {0}")]
    BadShape(&'static str),
    #[error("the CMS signature is {len} bytes but the field reserves {capacity}")]
    SignatureTooLarge { len: usize, capacity: usize },
    #[error("the CMS signature is empty")]
    EmptySignature,
}

/// Append a signature field to Render's single-revision PDF.
///
/// Deterministic: the same `first_revision` and `field` give the same bytes.
/// Refuses, without panicking, a file that is not a single-revision PDF with
/// a cross-reference table, an encrypted file, and a file that already has
/// an interactive form, a permissions dictionary, a document security store,
/// or a signature.
pub fn prepare(
    first_revision: &[u8],
    field: &SignatureField,
) -> Result<PreparedPdf, PdfSignatureError> {
    field.validate()?;
    let revision = syntax::read_revision(first_revision)?;
    let original = read_original(first_revision, &revision)?;
    write_update(first_revision, &revision, &original, field)
}

/// Whether a document rendered under `standard` stays conformant once
/// sealed with a field reserving `contents_capacity` bytes, with a short
/// reason when it does not.
///
/// The widget is printable, has only a normal appearance, and has a
/// zero-size rectangle; veraPDF counts such a widget as outside the crop
/// box, so the PDF/UA-1 and accessible PDF/A rules that ask a visible widget
/// to be tagged do not apply to it. What remains is the string-length limit
/// of PDF/A-1 (ISO 19005-1 6.1.12) and of PDF/A-2 and PDF/A-3 (ISO 32000-1
/// Annex C, through ISO 19005-2 and -3 6.1.13): the reserved `/Contents` is
/// one string of `contents_capacity` bytes.
///
/// Conformance holds for the embedded file only: until [`CheckedPdf::embed`]
/// writes a signature, PDF/A-2 and PDF/A-3 (6.4.3) refuse the empty
/// `/Contents`.
pub fn sealable(
    standard: Option<PdfStandardSpec>,
    contents_capacity: usize,
) -> Result<(), &'static str> {
    use PdfStandardSpec as S;
    if contents_capacity == 0 || contents_capacity > MAX_CONTENTS_CAPACITY {
        return Err("contents capacity must be between 1 and 262144 bytes");
    }
    let Some(standard) = standard else {
        return Ok(());
    };
    match standard {
        S::A1a | S::A1b if contents_capacity > 65_535 => Err(
            "PDF/A-1 limits a string to 65535 bytes, so a seal can reserve at most 65535 bytes for the signature",
        ),
        S::A2a | S::A2b | S::A2u | S::A3a | S::A3b | S::A3u if contents_capacity > 32_767 => Err(
            "PDF/A-2 and PDF/A-3 limit a string to 32767 bytes, so a seal can reserve at most 32767 bytes for the signature",
        ),
        S::V1_4
        | S::V1_5
        | S::V1_6
        | S::V1_7
        | S::V2_0
        | S::A1a
        | S::A1b
        | S::A2a
        | S::A2b
        | S::A2u
        | S::A3a
        | S::A3b
        | S::A3u
        | S::A4
        | S::A4f
        | S::A4e
        | S::Ua1 => Ok(()),
    }
}

impl SignatureField {
    fn validate(&self) -> Result<(), PdfSignatureError> {
        if self.contents_capacity == 0 || self.contents_capacity > MAX_CONTENTS_CAPACITY {
            return Err(PdfSignatureError::InvalidField(
                "contents capacity must be between 1 and MAX_CONTENTS_CAPACITY bytes",
            ));
        }
        if self.signing_time.nanosecond() != 0 {
            return Err(PdfSignatureError::InvalidField(
                "signing time must be a whole second",
            ));
        }
        if !(0..=9999).contains(&self.signing_time.year()) {
            return Err(PdfSignatureError::InvalidField(
                "signing time year must have four digits",
            ));
        }
        if self.field_name.is_empty() || self.field_name.len() > MAX_FIELD_NAME_LEN {
            return Err(PdfSignatureError::InvalidField(
                "field name must be between 1 and MAX_FIELD_NAME_LEN bytes",
            ));
        }
        if self.field_name.contains('.') {
            return Err(PdfSignatureError::InvalidField(
                "field name must not contain a period",
            ));
        }
        if self.field_name.chars().any(char::is_control) {
            return Err(PdfSignatureError::InvalidField(
                "field name must not contain a control character",
            ));
        }
        Ok(())
    }
}

impl PreparedPdf {
    /// Check the fixed shape by byte offsets only, without parsing PDF
    /// objects: the byte range starts at zero and ends at the end of the
    /// file; its gap is `<`, an even run of `0` digits, and `>`; the
    /// `/ByteRange` text right before `/Contents ` states exactly these
    /// values and is the update's only `/ByteRange`; and all of it sits
    /// after the first `first_revision_len` bytes, which end with `%%EOF`.
    pub fn check(self, first_revision_len: usize) -> Result<CheckedPdf, PdfSignatureError> {
        let shape = PdfSignatureError::BadShape;
        let [start, gap_start, gap_end, tail] = self.byte_range;
        let len = self.bytes.len();
        if start != 0 {
            return Err(shape("the byte range does not start at zero"));
        }
        if first_revision_len >= len {
            return Err(shape("the file has no update after the first revision"));
        }
        let first_revision = trim_eol(&self.bytes[..first_revision_len]);
        if !first_revision.ends_with(b"%%EOF") {
            return Err(shape("the first revision does not end with %%EOF"));
        }
        if gap_start >= gap_end || gap_end > len {
            return Err(shape("the byte range gap is out of order"));
        }
        if gap_end.checked_add(tail) != Some(len) {
            return Err(shape("the byte range does not end at the end of the file"));
        }
        let gap = &self.bytes[gap_start..gap_end];
        if gap.len() < 4 || gap[0] != b'<' || gap[gap.len() - 1] != b'>' {
            return Err(shape("the byte range gap is not a hex string"));
        }
        let digits = &gap[1..gap.len() - 1];
        if !digits.len().is_multiple_of(2) || !digits.iter().all(|digit| *digit == b'0') {
            return Err(shape(
                "the byte range gap is not an even run of zero digits",
            ));
        }
        let mut expected = byte_range_text(self.byte_range)
            .ok_or(shape("the byte range values are too large"))?
            .to_vec();
        expected.extend_from_slice(CONTENTS_KEY);
        let text_start = gap_start
            .checked_sub(expected.len())
            .ok_or(shape("the ByteRange text does not fit before the gap"))?;
        if text_start < first_revision_len {
            return Err(shape(
                "the signature dictionary sits inside the first revision",
            ));
        }
        if self.bytes[text_start..gap_start] != expected[..] {
            return Err(shape("the ByteRange text does not state the byte range"));
        }
        let update = &self.bytes[first_revision_len..];
        let byte_ranges = update
            .windows(BYTE_RANGE_KEY.len())
            .filter(|window| *window == BYTE_RANGE_KEY)
            .count();
        if byte_ranges != 1 {
            return Err(shape("the update does not name exactly one ByteRange"));
        }
        Ok(CheckedPdf {
            bytes: self.bytes,
            byte_range: self.byte_range,
        })
    }
}

impl CheckedPdf {
    /// The checked `/ByteRange`.
    pub fn byte_range(&self) -> [usize; 4] {
        self.byte_range
    }

    /// Bytes reserved for the DER CMS signature.
    pub fn contents_capacity(&self) -> usize {
        (self.byte_range[2] - self.byte_range[1] - 2) / 2
    }

    /// The two ranges the signature covers, in order: everything before the
    /// `/Contents` hex string and everything after it. The CMS message
    /// digest is computed over their concatenation.
    pub fn signed_parts(&self) -> [&[u8]; 2] {
        [
            &self.bytes[..self.byte_range[1]],
            &self.bytes[self.byte_range[2]..],
        ]
    }

    /// Write `cms_der` as uppercase hex at the start of the reserved
    /// `/Contents` string; the remaining zero digits stay as padding. The
    /// file length and every byte the signature covers are unchanged.
    pub fn embed(self, cms_der: &[u8]) -> Result<Vec<u8>, PdfSignatureError> {
        if cms_der.is_empty() {
            return Err(PdfSignatureError::EmptySignature);
        }
        let capacity = self.contents_capacity();
        if cms_der.len() > capacity {
            return Err(PdfSignatureError::SignatureTooLarge {
                len: cms_der.len(),
                capacity,
            });
        }
        let mut bytes = self.bytes;
        let digits = hex::encode_upper(cms_der);
        let start = self.byte_range[1] + 1;
        bytes[start..start + digits.len()].copy_from_slice(digits.as_bytes());
        Ok(bytes)
    }
}

fn trim_eol(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && matches!(bytes[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    &bytes[..end]
}

/// `/ByteRange [a b c d]` padded with trailing spaces to
/// `BYTE_RANGE_TEXT_LEN` bytes, or `None` when a value has more than ten
/// digits.
fn byte_range_text(range: [usize; 4]) -> Option<[u8; BYTE_RANGE_TEXT_LEN]> {
    const TEN_DIGITS: u64 = 9_999_999_999;
    if range.iter().any(|value| *value as u64 > TEN_DIGITS) {
        return None;
    }
    let text = format!(
        "/ByteRange [{} {} {} {}]",
        range[0], range[1], range[2], range[3]
    );
    if text.len() > BYTE_RANGE_TEXT_LEN {
        return None;
    }
    let mut padded = [b' '; BYTE_RANGE_TEXT_LEN];
    padded[..text.len()].copy_from_slice(text.as_bytes());
    Some(padded)
}

/// What `prepare` takes from the original revision: the catalog and first
/// page as their exact dictionary bytes, and the page's annotations.
struct Original {
    catalog: u32,
    catalog_dict: Vec<u8>,
    page: u32,
    page_dict: Vec<u8>,
    /// The span of the page's `/Annots` value inside `page_dict`, if any.
    page_annots: Option<std::ops::Range<usize>>,
    /// The page's existing annotation references, in order.
    annotations: Vec<(i32, i32)>,
}

fn read_original(
    first_revision: &[u8],
    revision: &syntax::Revision,
) -> Result<Original, PdfSignatureError> {
    let pdf = hayro_syntax::Pdf::new(first_revision.to_vec()).map_err(|error| match error {
        hayro_syntax::LoadPdfError::Decryption(_) => PdfSignatureError::Encrypted,
        hayro_syntax::LoadPdfError::Invalid => {
            PdfSignatureError::Malformed("hayro-syntax cannot read the file")
        }
    })?;
    let xref = pdf.xref();
    let root = xref.root_id();
    if root != ObjectIdentifier::new(revision.root as i32, 0) {
        return Err(PdfSignatureError::Malformed(
            "the trailer and hayro-syntax disagree on the catalog",
        ));
    }
    let catalog: Dict<'_> = xref.get(root).ok_or(PdfSignatureError::Malformed(
        "the catalog is not a dictionary",
    ))?;
    if !has_name(&catalog, b"Type", b"Catalog") {
        return Err(PdfSignatureError::Malformed("the root is not a catalog"));
    }
    for (key, what) in [
        (&b"AcroForm"[..], "an interactive form"),
        (b"Perms", "a permissions dictionary"),
        (b"DSS", "a document security store"),
    ] {
        if catalog.contains_key(key) {
            return Err(PdfSignatureError::AlreadyHas(what));
        }
    }
    refuse_signatures(&pdf)?;

    let page_id = first_page(xref, &catalog)?;
    let hayro_first = pdf.pages().first().and_then(|page| page.raw().obj_id());
    if hayro_first != Some(page_id) {
        return Err(PdfSignatureError::Malformed(
            "the page tree and hayro-syntax disagree on the first page",
        ));
    }
    let page: Dict<'_> = xref.get(page_id).ok_or(PdfSignatureError::Malformed(
        "the first page is not a dictionary",
    ))?;
    let annotations = match page.get_raw::<Object<'_>>(b"Annots") {
        None => Vec::new(),
        Some(_) => {
            let annots: Array<'_> = page.get(b"Annots").ok_or(PdfSignatureError::Malformed(
                "the first page's /Annots is not an array",
            ))?;
            annots
                .raw_iter()
                .map(|item| match item {
                    MaybeRef::Ref(reference) => Ok((reference.obj_number, reference.gen_number)),
                    MaybeRef::NotRef(_) => Err(PdfSignatureError::Malformed(
                        "an annotation on the first page is not an indirect object",
                    )),
                })
                .collect::<Result<Vec<_>, _>>()?
        }
    };

    let catalog_dict = catalog.data().to_vec();
    let page_dict = page.data().to_vec();
    entries_matching(&catalog, &catalog_dict)?;
    let page_entries = entries_matching(&page, &page_dict)?;
    let page_annots = page_entries
        .into_iter()
        .find(|entry| entry.key == b"Annots")
        .map(|entry| entry.value);

    Ok(Original {
        catalog: revision.root,
        catalog_dict,
        page: u32::try_from(page_id.obj_number)
            .map_err(|_| PdfSignatureError::Malformed("the first page has a negative number"))?,
        page_dict,
        page_annots,
        annotations,
    })
}

fn has_name(dict: &Dict<'_>, key: &[u8], value: &[u8]) -> bool {
    dict.get::<Name<'_>>(key)
        .is_some_and(|name| name.as_ref() == value)
}

/// Refuse any object that is or belongs to a signature.
fn refuse_signatures(pdf: &hayro_syntax::Pdf) -> Result<(), PdfSignatureError> {
    for object in pdf.objects() {
        let dict = match &object {
            Object::Dict(dict) => dict,
            Object::Stream(stream) => stream.dict(),
            _ => continue,
        };
        if has_name(dict, b"Type", b"Sig")
            || has_name(dict, b"Type", b"DocTimeStamp")
            || has_name(dict, b"FT", b"Sig")
            || dict.contains_key(b"ByteRange")
        {
            return Err(PdfSignatureError::AlreadyHas("a signature"));
        }
    }
    Ok(())
}

/// Walk `/Pages` down the first kid of each node to the first page.
fn first_page(
    xref: &hayro_syntax::xref::XRef,
    catalog: &Dict<'_>,
) -> Result<ObjectIdentifier, PdfSignatureError> {
    let mut node_ref = catalog
        .get_ref(b"Pages")
        .ok_or(PdfSignatureError::Malformed("the catalog has no page tree"))?;
    for _ in 0..MAX_PAGE_TREE_DEPTH {
        let node: Dict<'_> = xref
            .get(node_ref.into())
            .ok_or(PdfSignatureError::Malformed(
                "a page tree node is not a dictionary",
            ))?;
        if has_name(&node, b"Type", b"Page") {
            return Ok(node_ref.into());
        }
        if !has_name(&node, b"Type", b"Pages") {
            return Err(PdfSignatureError::Malformed(
                "a page tree node is neither a page nor a page tree",
            ));
        }
        let kids: Array<'_> = node.get(b"Kids").ok_or(PdfSignatureError::Malformed(
            "a page tree node has no /Kids",
        ))?;
        node_ref = kids
            .raw_iter()
            .next()
            .and_then(|kid| kid.as_obj_ref())
            .ok_or(PdfSignatureError::Malformed(
                "the document has no first page",
            ))?;
    }
    Err(PdfSignatureError::Malformed(
        "the page tree nests too deeply",
    ))
}

/// Split `raw` (a dictionary's exact bytes) into its top-level entries and
/// check they name the same keys `hayro-syntax` read.
fn entries_matching(dict: &Dict<'_>, raw: &[u8]) -> Result<Vec<syntax::Entry>, PdfSignatureError> {
    let (entries, end) = syntax::dict_entries(raw, 0)?;
    if end != raw.len() {
        return Err(PdfSignatureError::Malformed(
            "a dictionary has bytes after its end",
        ));
    }
    let ours: BTreeSet<&[u8]> = entries.iter().map(|entry| entry.key.as_slice()).collect();
    let theirs: BTreeSet<Vec<u8>> = dict.keys().map(|key| key.to_vec()).collect();
    let theirs: BTreeSet<&[u8]> = theirs.iter().map(Vec::as_slice).collect();
    if ours != theirs {
        return Err(PdfSignatureError::Malformed(
            "a dictionary reads differently byte by byte and with hayro-syntax",
        ));
    }
    Ok(entries)
}

fn write_update(
    first_revision: &[u8],
    revision: &syntax::Revision,
    original: &Original,
    field: &SignatureField,
) -> Result<PreparedPdf, PdfSignatureError> {
    let size = revision.size;
    if size > i32::MAX as u32 - 3 {
        return Err(PdfSignatureError::Malformed(
            "the file has too many objects",
        ));
    }
    let field_id = size;
    let appearance_id = size + 1;
    let signature_id = size + 2;
    let new_size = size + 3;

    let mut out = Vec::with_capacity(first_revision.len() + 2 * field.contents_capacity + 4096);
    out.extend_from_slice(first_revision);
    out.push(b'\n');
    let mut offsets: Vec<(u32, usize)> = Vec::with_capacity(5);

    // The catalog, every original entry kept, with the form and the DocMDP
    // permission appended.
    offsets.push((original.catalog, out.len()));
    let catalog_body = &original.catalog_dict[..original.catalog_dict.len() - 2];
    out.extend_from_slice(format!("{} 0 obj\n", original.catalog).as_bytes());
    out.extend_from_slice(catalog_body);
    out.extend_from_slice(
        format!(
            "/AcroForm<</Fields[{field_id} 0 R]/SigFlags 3>>/Perms<</DocMDP {signature_id} 0 R>>>>\nendobj\n"
        )
        .as_bytes(),
    );

    // The first page, every original entry kept, with the widget appended
    // to its annotations.
    let mut annots = String::from("[");
    for (number, generation) in &original.annotations {
        annots.push_str(&format!("{number} {generation} R "));
    }
    annots.push_str(&format!("{field_id} 0 R]"));
    offsets.push((original.page, out.len()));
    out.extend_from_slice(format!("{} 0 obj\n", original.page).as_bytes());
    let page = &original.page_dict;
    match &original.page_annots {
        Some(span) => {
            out.extend_from_slice(&page[..span.start]);
            out.extend_from_slice(annots.as_bytes());
            out.extend_from_slice(&page[span.end..]);
        }
        None => {
            out.extend_from_slice(&page[..page.len() - 2]);
            out.extend_from_slice(b"/Annots");
            out.extend_from_slice(annots.as_bytes());
            out.extend_from_slice(b">>");
        }
    }
    out.extend_from_slice(b"\nendobj\n");

    // The signature field merged with its widget: invisible (zero-size
    // rectangle), printable as PDF/A-4 6.3.2 requires, locked, on the first
    // page, with an empty appearance stream.
    let settings = Settings { pretty: false };
    let mut widget = Chunk::with_settings(settings);
    {
        let mut form_field = widget.form_field(object_ref(field_id));
        form_field
            .field_type(FieldType::Signature)
            .partial_name(TextStr(&field.field_name));
        form_field.pair(pdf_writer::Name(b"V"), object_ref(signature_id));
        let mut annotation = form_field.into_annotation();
        annotation
            .rect(Rect::new(0.0, 0.0, 0.0, 0.0))
            .flags(AnnotationFlags::PRINT | AnnotationFlags::LOCKED)
            .page(object_ref(original.page));
        annotation
            .appearance()
            .normal()
            .stream(object_ref(appearance_id));
    }
    offsets.push((field_id, out.len()));
    out.extend_from_slice(widget.as_bytes());

    let mut appearance = Chunk::with_settings(settings);
    appearance
        .form_xobject(object_ref(appearance_id), &[])
        .bbox(Rect::new(0.0, 0.0, 0.0, 0.0));
    offsets.push((appearance_id, out.len()));
    out.extend_from_slice(appearance.as_bytes());

    // The certification signature dictionary, in the fixed shape `check`
    // reads: `/ByteRange` text, then `/Contents ` and the zero hex string.
    offsets.push((signature_id, out.len()));
    out.extend_from_slice(
        format!(
            "{signature_id} 0 obj\n<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/ETSI.CAdES.detached/M(D:{}Z)/Reference[<</Type/SigRef/TransformMethod/DocMDP/TransformParams<</Type/TransformParams/P 2/V/1.2>>>>]",
            field.signing_time.format("%Y%m%d%H%M%S")
        )
        .as_bytes(),
    );
    let byte_range_at = out.len();
    out.extend_from_slice(&byte_range_text([0; 4]).expect("zeros fit the ByteRange text"));
    out.extend_from_slice(CONTENTS_KEY);
    let gap_start = out.len();
    out.push(b'<');
    out.resize(out.len() + 2 * field.contents_capacity, b'0');
    out.push(b'>');
    let gap_end = out.len();
    out.extend_from_slice(b">>\nendobj\n");

    // The second file identifier changes with the update (ISO 32000-2
    // 14.4); it is derived from the bytes so far to stay deterministic.
    let second_id = hex::encode_upper(&Sha256::digest(&out)[..16]);

    let xref_at = out.len();
    out.extend_from_slice(b"xref\n");
    offsets.sort_unstable();
    for run in offsets.chunk_by(|a, b| b.0 == a.0 + 1) {
        out.extend_from_slice(format!("{} {}\n", run[0].0, run.len()).as_bytes());
        for (_, offset) in run {
            out.extend_from_slice(format!("{offset:010} 00000 n\r\n").as_bytes());
        }
    }

    // Every original trailer entry, with `/Size` and the second `/ID`
    // updated and `/Prev` added (ISO 32000-2 7.5.6).
    out.extend_from_slice(b"trailer\n<<");
    for entry in &revision.trailer {
        match entry.key.as_slice() {
            b"Size" => out.extend_from_slice(format!("/Size {new_size}").as_bytes()),
            b"ID" => {
                out.extend_from_slice(b"/ID[");
                out.extend_from_slice(&first_revision[revision.id_first.clone()]);
                out.extend_from_slice(format!("<{second_id}>]").as_bytes());
            }
            _ => out.extend_from_slice(&first_revision[entry.start..entry.value.end]),
        }
    }
    out.extend_from_slice(
        format!(
            "/Prev {}>>\nstartxref\n{xref_at}\n%%EOF\n",
            revision.xref_offset
        )
        .as_bytes(),
    );

    let byte_range = [0, gap_start, gap_end, out.len() - gap_end];
    let text = byte_range_text(byte_range).ok_or(PdfSignatureError::Malformed(
        "the file is too large for the ByteRange text",
    ))?;
    out[byte_range_at..byte_range_at + BYTE_RANGE_TEXT_LEN].copy_from_slice(&text);
    Ok(PreparedPdf {
        bytes: out,
        byte_range,
    })
}

/// A `pdf-writer` reference to an object number already checked to be
/// between 1 and `i32::MAX`.
fn object_ref(number: u32) -> Ref {
    Ref::new(i32::try_from(number).expect("object numbers are bounded by write_update"))
}

/// Serde for byte vectors as standard base64, the worker pipe's encoding
/// for PDF bytes.
mod base64_bytes {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use pdf_writer::types::AnnotationType;
    use pdf_writer::{Name as WriterName, Pdf};

    fn field() -> SignatureField {
        SignatureField {
            signing_time: Utc.with_ymd_and_hms(2026, 11, 6, 9, 30, 15).unwrap(),
            contents_capacity: 64,
            field_name: "Seal".to_owned(),
        }
    }

    #[derive(Default, Clone, Copy)]
    struct Fixture {
        inline_link: bool,
        indirect_link: bool,
        acroform: bool,
        perms: bool,
        stray_signature: bool,
        xref_stream: bool,
    }

    const CATALOG: Ref = Ref::new(1);
    const PAGES: Ref = Ref::new(2);
    const PAGE: Ref = Ref::new(3);
    const CONTENT: Ref = Ref::new(4);
    const LINK: Ref = Ref::new(5);
    const ANNOTS: Ref = Ref::new(6);
    const STRAY: Ref = Ref::new(7);

    /// A one-page PDF written by `pdf-writer`, the writer krilla uses.
    fn fixture(options: Fixture) -> Vec<u8> {
        let mut pdf = Pdf::new();
        pdf.set_file_id((b"fixture-id".to_vec(), b"fixture-id".to_vec()));
        {
            let mut catalog = pdf.catalog(CATALOG);
            catalog.pages(PAGES);
            if options.acroform {
                catalog
                    .insert(WriterName(b"AcroForm"))
                    .dict()
                    .insert(WriterName(b"Fields"))
                    .array();
            }
            if options.perms {
                catalog
                    .insert(WriterName(b"Perms"))
                    .dict()
                    .pair(WriterName(b"UR3"), STRAY);
            }
        }
        pdf.pages(PAGES).kids([PAGE]).count(1);
        {
            let mut page = pdf.page(PAGE);
            page.parent(PAGES)
                .media_box(Rect::new(0.0, 0.0, 200.0, 100.0))
                .contents(CONTENT);
            if options.inline_link {
                page.annotations([LINK]);
            }
            if options.indirect_link {
                page.pair(WriterName(b"Annots"), ANNOTS);
            }
        }
        pdf.stream(CONTENT, b"");
        if options.inline_link || options.indirect_link {
            pdf.annotation(LINK)
                .subtype(AnnotationType::Link)
                .rect(Rect::new(10.0, 10.0, 50.0, 20.0))
                .flags(AnnotationFlags::PRINT);
        }
        if options.indirect_link {
            pdf.indirect(ANNOTS).array().item(LINK);
        }
        if options.stray_signature {
            pdf.indirect(STRAY)
                .dict()
                .pair(WriterName(b"Type"), WriterName(b"Sig"));
        }
        if options.xref_stream {
            pdf.finish_with_xref_stream(Ref::new(20))
        } else {
            pdf.finish()
        }
    }

    /// The first object number the update allocates: the field and widget.
    fn next_object(original: &[u8]) -> i32 {
        syntax::read_revision(original).expect("revision").size as i32
    }

    fn page_annotations(bytes: &[u8]) -> Vec<(i32, i32)> {
        let pdf = hayro_syntax::Pdf::new(bytes.to_vec()).expect("reads");
        let page = pdf.pages()[0].raw().clone();
        let annots: Array<'_> = page.get(b"Annots").expect("Annots");
        annots
            .raw_iter()
            .map(|item| {
                let reference = item.as_obj_ref().expect("indirect");
                (reference.obj_number, reference.gen_number)
            })
            .collect()
    }

    #[test]
    fn prepare_appends_the_widget_after_existing_inline_annotations() {
        let original = fixture(Fixture {
            inline_link: true,
            ..Fixture::default()
        });
        let prepared = prepare(&original, &field()).expect("prepare");
        assert!(prepared.bytes.starts_with(&original));
        let widget = (next_object(&original), 0);
        assert_eq!(page_annotations(&prepared.bytes), vec![(5, 0), widget]);
        prepared.check(original.len()).expect("check");
    }

    #[test]
    fn prepare_inlines_an_indirect_annotation_array_with_the_widget() {
        let original = fixture(Fixture {
            indirect_link: true,
            ..Fixture::default()
        });
        let prepared = prepare(&original, &field()).expect("prepare");
        let widget = (next_object(&original), 0);
        assert_eq!(page_annotations(&prepared.bytes), vec![(5, 0), widget]);
    }

    #[test]
    fn prepare_adds_annotations_to_a_page_without_them() {
        let original = fixture(Fixture::default());
        let prepared = prepare(&original, &field()).expect("prepare");
        assert_eq!(
            page_annotations(&prepared.bytes),
            vec![(next_object(&original), 0)]
        );
    }

    #[test]
    fn prepare_refuses_existing_forms_permissions_and_signatures() {
        for (options, what) in [
            (
                Fixture {
                    acroform: true,
                    ..Fixture::default()
                },
                "an interactive form",
            ),
            (
                Fixture {
                    perms: true,
                    stray_signature: true,
                    ..Fixture::default()
                },
                "a permissions dictionary",
            ),
            (
                Fixture {
                    stray_signature: true,
                    ..Fixture::default()
                },
                "a signature",
            ),
        ] {
            assert_eq!(
                prepare(&fixture(options), &field()),
                Err(PdfSignatureError::AlreadyHas(what))
            );
        }
    }

    #[test]
    fn prepare_names_a_cross_reference_stream_and_encryption() {
        let streamed = fixture(Fixture {
            xref_stream: true,
            ..Fixture::default()
        });
        assert_eq!(
            prepare(&streamed, &field()),
            Err(PdfSignatureError::CrossReferenceStream)
        );

        let plain = fixture(Fixture::default());
        let at = plain
            .windows(b"trailer\n<<".len())
            .position(|window| window == b"trailer\n<<")
            .expect("trailer");
        let mut encrypted = plain[..at + b"trailer\n<<".len()].to_vec();
        encrypted.extend_from_slice(b"/Encrypt 9 0 R");
        encrypted.extend_from_slice(&plain[at + b"trailer\n<<".len()..]);
        assert_eq!(
            prepare(&encrypted, &field()),
            Err(PdfSignatureError::Encrypted)
        );
    }

    #[test]
    fn prepare_writes_a_non_ascii_field_name_as_a_text_string() {
        let original = fixture(Fixture::default());
        let mut named = field();
        named.field_name = "Sceau ministériel".to_owned();
        let prepared = prepare(&original, &named).expect("prepare");
        let pdf = hayro_syntax::Pdf::new(prepared.bytes).expect("reads");
        let catalog: Dict<'_> = pdf.xref().get(pdf.xref().root_id()).expect("catalog");
        let form: Dict<'_> = catalog.get(b"AcroForm").expect("form");
        let fields: Array<'_> = form.get(b"Fields").expect("fields");
        let widget = fields.iter::<Dict<'_>>().next().expect("widget");
        let name = widget
            .get::<hayro_syntax::object::String<'_>>(b"T")
            .expect("T");
        let mut expected = vec![0xFE, 0xFF];
        expected.extend(
            "Sceau ministériel"
                .encode_utf16()
                .flat_map(u16::to_be_bytes),
        );
        assert_eq!(name.as_bytes(), expected.as_slice());
    }

    #[test]
    fn field_validation_refuses_each_bad_knob() {
        let mut cases = Vec::new();
        for capacity in [0, MAX_CONTENTS_CAPACITY + 1] {
            let mut bad = field();
            bad.contents_capacity = capacity;
            cases.push(bad);
        }
        let mut fractional = field();
        fractional.signing_time += chrono::Duration::milliseconds(250);
        cases.push(fractional);
        let mut far = field();
        far.signing_time = Utc.with_ymd_and_hms(10_000, 1, 1, 0, 0, 0).unwrap();
        cases.push(far);
        for name in [
            String::new(),
            "Seal.Ministry".to_owned(),
            "Seal\nMinistry".to_owned(),
            "x".repeat(MAX_FIELD_NAME_LEN + 1),
        ] {
            let mut bad = field();
            bad.field_name = name;
            cases.push(bad);
        }
        let original = fixture(Fixture::default());
        for bad in cases {
            assert!(
                matches!(
                    prepare(&original, &bad),
                    Err(PdfSignatureError::InvalidField(_))
                ),
                "{bad:?} should be refused"
            );
        }
        let mut largest = field();
        largest.contents_capacity = MAX_CONTENTS_CAPACITY;
        largest.field_name = "x".repeat(MAX_FIELD_NAME_LEN);
        assert!(prepare(&original, &largest).is_ok());
    }

    #[test]
    fn check_refuses_inconsistent_ranges_without_panicking() {
        let original = fixture(Fixture::default());
        let prepared = prepare(&original, &field()).expect("prepare");
        let len = prepared.bytes.len();
        for byte_range in [
            [0, usize::MAX, 5, 0],
            [0, 5, 3, len - 3],
            [0, 0, 0, len],
            [0, 2, usize::MAX, 2],
            [0, 2, len, usize::MAX],
            [0, len - 2, len, 0],
            [0, usize::MAX - 1, usize::MAX, 1],
        ] {
            let mut candidate = prepared.clone();
            candidate.byte_range = byte_range;
            assert!(
                matches!(
                    candidate.check(original.len()),
                    Err(PdfSignatureError::BadShape(_))
                ),
                "{byte_range:?} should be refused"
            );
        }
    }

    #[test]
    fn byte_range_text_has_a_fixed_width() {
        let zeros = byte_range_text([0; 4]).expect("zeros");
        let widest = byte_range_text([9_999_999_999; 4]).expect("ten digits");
        assert_eq!(zeros.len(), widest.len());
        assert!(zeros.starts_with(b"/ByteRange [0 0 0 0]   "));
        assert_eq!(widest.last(), Some(&b']'));
        assert_eq!(byte_range_text([0, 10_000_000_000, 0, 0]), None);
    }

    const EVERY_STANDARD: [Option<PdfStandardSpec>; 18] = [
        None,
        Some(PdfStandardSpec::V1_4),
        Some(PdfStandardSpec::V1_5),
        Some(PdfStandardSpec::V1_6),
        Some(PdfStandardSpec::V1_7),
        Some(PdfStandardSpec::V2_0),
        Some(PdfStandardSpec::A1b),
        Some(PdfStandardSpec::A1a),
        Some(PdfStandardSpec::A2b),
        Some(PdfStandardSpec::A2u),
        Some(PdfStandardSpec::A2a),
        Some(PdfStandardSpec::A3b),
        Some(PdfStandardSpec::A3u),
        Some(PdfStandardSpec::A3a),
        Some(PdfStandardSpec::A4),
        Some(PdfStandardSpec::A4f),
        Some(PdfStandardSpec::A4e),
        Some(PdfStandardSpec::Ua1),
    ];

    #[test]
    fn every_standard_is_sealable_with_room_for_a_timestamped_signature() {
        for standard in EVERY_STANDARD {
            assert_eq!(sealable(standard, 16 * 1024), Ok(()), "{standard:?}");
        }
    }

    #[test]
    fn sealable_holds_pdf_a_1_2_and_3_to_their_string_length_limits() {
        use PdfStandardSpec as S;
        let limited: [(&[S], usize, &str); 2] = [
            (
                &[S::A1a, S::A1b],
                65_535,
                "PDF/A-1 limits a string to 65535 bytes, so a seal can reserve at most 65535 bytes for the signature",
            ),
            (
                &[S::A2a, S::A2b, S::A2u, S::A3a, S::A3b, S::A3u],
                32_767,
                "PDF/A-2 and PDF/A-3 limit a string to 32767 bytes, so a seal can reserve at most 32767 bytes for the signature",
            ),
        ];
        for (standards, limit, reason) in limited {
            for standard in standards {
                assert_eq!(sealable(Some(*standard), limit), Ok(()), "{standard:?}");
                assert_eq!(
                    sealable(Some(*standard), limit + 1),
                    Err(reason),
                    "{standard:?}"
                );
            }
        }
        for standard in [
            None,
            Some(S::V1_4),
            Some(S::V1_5),
            Some(S::V1_6),
            Some(S::V1_7),
            Some(S::V2_0),
            Some(S::A4),
            Some(S::A4f),
            Some(S::A4e),
            Some(S::Ua1),
        ] {
            assert_eq!(
                sealable(standard, MAX_CONTENTS_CAPACITY),
                Ok(()),
                "{standard:?}"
            );
        }
    }

    #[test]
    fn sealable_refuses_a_capacity_prepare_refuses() {
        for standard in EVERY_STANDARD {
            for capacity in [0, MAX_CONTENTS_CAPACITY + 1] {
                let reason = sealable(standard, capacity).expect_err("out of range");
                assert!(
                    reason.contains(&MAX_CONTENTS_CAPACITY.to_string()),
                    "{reason}"
                );
                let mut bad = field();
                bad.contents_capacity = capacity;
                assert!(bad.validate().is_err());
            }
        }
    }
}

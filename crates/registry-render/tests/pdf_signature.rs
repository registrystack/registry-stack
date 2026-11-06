//! The PAdES signature field on Render's own PDF/A-4 output: `prepare`
//! appends an incremental update after the exact first revision, and
//! `embed` writes the signature into the space it reserved.
//!
//! The certificate bundle is rendered the way `tests/golden.rs` renders it,
//! once per test binary.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use chrono::{TimeZone, Utc};
use hayro_syntax::object::{Array, Dict, Name, Object, ObjectIdentifier};
use registry_render::pdf_signature::{
    prepare, sealable, PdfSignatureError, PreparedPdf, SignatureField,
};
use serde_json::Value;

const CAPACITY: usize = 8192;
const FIELD_NAME: &str = "RegistrySeal";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate sits at crates/registry-render")
        .to_path_buf()
}

fn certificate_root() -> PathBuf {
    repo_root().join("products/render/bundles/certificate")
}

fn certificate_bundle() -> registry_render::Bundle {
    let root = certificate_root();
    let verified = registry_platform_config::package::verify_package(
        &root,
        &registry_render::runtime::package_limits(),
        "registry-render package",
    )
    .expect("shared package envelope");
    registry_render::Bundle::load_package(&root, &verified).expect("bound package bytes")
}

fn certificate_pdf() -> &'static [u8] {
    static PDF: OnceLock<Vec<u8>> = OnceLock::new();
    PDF.get_or_init(|| {
        let root = certificate_root();
        let bundle = certificate_bundle();
        let document = bundle.document("certificate").expect("document");
        let data: Value = serde_json::from_str(
            &std::fs::read_to_string(root.join("fixtures/data.json")).expect("fixture"),
        )
        .expect("fixture json");
        let request = registry_render::RenderRequest {
            locale: None,
            data,
            assets: BTreeMap::new(),
            issued_at: Utc.with_ymd_and_hms(2026, 9, 16, 10, 32, 0).unwrap(),
        };
        registry_render::render(&bundle, document, &request, false)
            .expect("render")
            .pdf
    })
}

fn field() -> SignatureField {
    SignatureField {
        signing_time: Utc.with_ymd_and_hms(2026, 11, 6, 9, 30, 15).unwrap(),
        contents_capacity: CAPACITY,
        field_name: FIELD_NAME.to_owned(),
    }
}

fn prepared() -> PreparedPdf {
    prepare(certificate_pdf(), &field()).expect("prepare Render's certificate")
}

fn name<'a>(dict: &Dict<'a>, key: &[u8]) -> Vec<u8> {
    dict.get::<Name<'_>>(key)
        .unwrap_or_else(|| panic!("{} is a name", String::from_utf8_lossy(key)))
        .to_vec()
}

fn startxref(pdf: &[u8]) -> usize {
    let at = pdf
        .windows(9)
        .rposition(|w| w == b"startxref")
        .expect("startxref");
    std::str::from_utf8(&pdf[at + 9..])
        .expect("ascii tail")
        .split_whitespace()
        .next()
        .expect("offset")
        .parse()
        .expect("numeric offset")
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[test]
fn the_certificate_bundle_standard_is_sealable_at_the_test_capacity() {
    let bundle = certificate_bundle();
    let standard = bundle
        .document("certificate")
        .expect("document")
        .spec
        .pdf_standard;
    assert_eq!(standard.map(|s| s.to_string()).as_deref(), Some("a-4"));
    assert_eq!(sealable(standard, CAPACITY), Ok(()));
}

#[test]
fn prepared_file_starts_with_the_exact_first_revision() {
    let original = certificate_pdf();
    let prepared = prepared();
    assert!(prepared.bytes().len() > original.len());
    assert_eq!(&prepared.bytes()[..original.len()], original);
    assert!(
        prepared.bytes().ends_with(b"%%EOF\n"),
        "the update ends with one end-of-file marker and a single EOL"
    );
}

#[test]
fn prepare_is_deterministic() {
    assert_eq!(prepared(), prepared());
}

#[test]
fn prepared_file_reparses_with_the_field_widget_form_docmdp_and_signature() {
    let prepared = prepared();
    let pdf = hayro_syntax::Pdf::new(prepared.bytes().to_vec()).expect("hayro reads the update");
    let xref = pdf.xref();
    let catalog: Dict<'_> = xref.get(xref.root_id()).expect("catalog");

    let acroform: Dict<'_> = catalog.get(b"AcroForm").expect("AcroForm");
    assert_eq!(acroform.get::<i32>(b"SigFlags"), Some(3));
    assert!(!acroform.contains_key(b"NeedAppearances"));
    let fields: Array<'_> = acroform.get(b"Fields").expect("Fields");
    let fields: Vec<_> = fields
        .raw_iter()
        .map(|f| f.as_obj_ref().expect("field is indirect"))
        .collect();
    assert_eq!(fields.len(), 1);

    let widget: Dict<'_> = xref.get(fields[0].into()).expect("field dictionary");
    assert_eq!(name(&widget, b"FT"), b"Sig");
    assert_eq!(name(&widget, b"Type"), b"Annot");
    assert_eq!(name(&widget, b"Subtype"), b"Widget");
    assert_eq!(
        widget
            .get::<hayro_syntax::object::String<'_>>(b"T")
            .expect("T")
            .as_bytes(),
        FIELD_NAME.as_bytes()
    );
    assert_eq!(widget.get::<[f64; 4]>(b"Rect"), Some([0.0; 4]));
    let flags = widget.get::<u32>(b"F").expect("F");
    assert_eq!(flags & 4, 4, "Print is set (PDF/A-4 6.3.2)");
    assert_eq!(
        flags & (1 | 2 | 32 | 256),
        0,
        "Invisible, Hidden, NoView and ToggleNoView are clear (PDF/A-4 6.3.2)"
    );
    assert!(!widget.contains_key(b"A") && !widget.contains_key(b"AA"));
    let first_page = pdf.pages()[0].raw().obj_id().expect("page is indirect");
    assert_eq!(
        ObjectIdentifier::from(widget.get_ref(b"P").expect("P")),
        first_page
    );
    let appearance: Dict<'_> = widget.get(b"AP").expect("AP");
    assert_eq!(appearance.keys().count(), 1, "AP holds only N");
    let normal = appearance.get::<hayro_syntax::object::Stream<'_>>(b"N");
    assert!(normal.is_some(), "N is a form XObject stream");

    let sig_ref = widget.get_ref(b"V").expect("V is indirect");
    let sig: Dict<'_> = xref.get(sig_ref.into()).expect("signature dictionary");
    assert_eq!(name(&sig, b"Type"), b"Sig");
    assert_eq!(name(&sig, b"Filter"), b"Adobe.PPKLite");
    assert_eq!(name(&sig, b"SubFilter"), b"ETSI.CAdES.detached");
    assert_eq!(
        sig.get::<hayro_syntax::object::String<'_>>(b"M")
            .expect("M")
            .as_bytes(),
        b"D:20261106093015Z"
    );
    let byte_range = sig.get::<[i64; 4]>(b"ByteRange").expect("ByteRange");
    assert_eq!(byte_range.map(|n| n as usize), prepared.byte_range());
    let contents = sig
        .get::<hayro_syntax::object::String<'_>>(b"Contents")
        .expect("Contents");
    assert_eq!(contents.as_bytes(), vec![0u8; CAPACITY].as_slice());

    let reference: Array<'_> = sig.get(b"Reference").expect("Reference");
    let references: Vec<Dict<'_>> = reference.iter::<Dict<'_>>().collect();
    assert_eq!(references.len(), 1);
    assert_eq!(name(&references[0], b"Type"), b"SigRef");
    assert_eq!(name(&references[0], b"TransformMethod"), b"DocMDP");
    let params: Dict<'_> = references[0].get(b"TransformParams").expect("params");
    assert_eq!(name(&params, b"Type"), b"TransformParams");
    assert_eq!(params.get::<i32>(b"P"), Some(2));
    assert_eq!(name(&params, b"V"), b"1.2");
    for refused in [&b"DigestLocation"[..], b"DigestMethod", b"DigestValue"] {
        assert!(!references[0].contains_key(refused));
    }

    let perms: Dict<'_> = catalog.get(b"Perms").expect("Perms");
    assert_eq!(perms.get_ref(b"DocMDP"), Some(sig_ref));
    assert_eq!(perms.keys().count(), 1);

    let page = pdf.pages()[0].raw().clone();
    let annots: Array<'_> = page.get(b"Annots").expect("Annots");
    let annots: Vec<_> = annots.raw_iter().filter_map(|a| a.as_obj_ref()).collect();
    assert_eq!(annots, vec![fields[0]]);
}

#[test]
fn catalog_and_first_page_keep_every_existing_entry() {
    let original_bytes = certificate_pdf().to_vec();
    let original = hayro_syntax::Pdf::new(original_bytes).expect("original");
    let prepared = hayro_syntax::Pdf::new(prepared().bytes().to_vec()).expect("prepared");

    let pairs = [
        (
            original.xref().root_id(),
            prepared.xref().root_id(),
            vec![&b"AcroForm"[..], b"Perms"],
        ),
        (
            original.pages()[0].raw().obj_id().expect("page id"),
            prepared.pages()[0].raw().obj_id().expect("page id"),
            vec![&b"Annots"[..], b"Tabs"],
        ),
    ];
    for (original_id, prepared_id, added) in pairs {
        assert_eq!(
            original_id, prepared_id,
            "the update rewrites the object in place"
        );
        let before: Dict<'_> = original.xref().get(original_id).expect("before");
        let after: Dict<'_> = prepared.xref().get(prepared_id).expect("after");
        for key in before.keys() {
            assert_eq!(
                after.get_raw::<Object<'_>>(&*key),
                before.get_raw::<Object<'_>>(&*key),
                "{} changed",
                key.as_str()
            );
        }
        let mut expected: Vec<Vec<u8>> = before.keys().map(|k| k.to_vec()).collect();
        expected.extend(added.iter().map(|k| k.to_vec()));
        expected.sort();
        let mut actual: Vec<Vec<u8>> = after.keys().map(|k| k.to_vec()).collect();
        actual.sort();
        assert_eq!(actual, expected);
    }

    // PDF/UA-1 orders a page with annotations by structure (ISO 14289-1, 7.18.3).
    assert_eq!(name(prepared.pages()[0].raw(), b"Tabs"), b"S");
}

#[test]
fn update_is_a_cross_reference_table_chained_to_the_original() {
    let original = certificate_pdf();
    let prepared = prepared();
    let update = &prepared.bytes()[original.len()..];

    let xref = startxref(prepared.bytes());
    assert!(xref > original.len());
    assert!(prepared.bytes()[xref..].starts_with(b"xref\n"));

    let trailer_at = find(update, b"trailer\n").expect("trailer keyword");
    let trailer = std::str::from_utf8(&update[trailer_at..]).expect("ascii trailer");
    let trailer = &trailer[..trailer.find("startxref").expect("startxref")];
    assert!(trailer.contains(&format!("/Prev {}", startxref(original))));
    assert!(trailer.contains("/Root 63 0 R"), "{trailer}");
    assert!(trailer.contains("/Size 67"), "{trailer}");
    assert!(
        trailer.contains("/ID[(OTdnCvSjsJVupwEfIuqETA==)<"),
        "first identifier copied verbatim, second one new: {trailer}"
    );
    assert!(!trailer.contains("/Encrypt"));
}

#[test]
fn signed_parts_cover_all_but_the_contents() {
    let original = certificate_pdf();
    let prepared = prepared();
    let [_, gap_start, gap_end, tail] = prepared.byte_range();
    let bytes = prepared.bytes().to_vec();

    let [head, rest] = prepared.signed_parts();
    assert_eq!(head, &bytes[..gap_start]);
    assert_eq!(rest, &bytes[gap_end..]);
    assert_eq!(rest.len(), tail);
    assert!(head.starts_with(original));
    assert_eq!(bytes[gap_start], b'<');
    assert_eq!(bytes[gap_end - 1], b'>');
    assert_eq!(gap_end - gap_start, 2 * CAPACITY + 2);
}

#[test]
fn embed_round_trips_and_keeps_zero_padding() {
    let prepared = prepared();
    let before = prepared.bytes().to_vec();
    let [_, gap_start, gap_end, _] = prepared.byte_range();
    let cms: Vec<u8> = (0..1500u32).map(|i| (i * 7 + 3) as u8).collect();

    let signed = prepared.embed(&cms).expect("embed");
    assert_eq!(signed.len(), before.len());
    assert_eq!(&signed[..=gap_start], &before[..=gap_start]);
    assert_eq!(&signed[gap_end - 1..], &before[gap_end - 1..]);
    let hex_digits = &signed[gap_start + 1..gap_end - 1];
    let decoded = hex::decode(hex_digits).expect("hex");
    assert_eq!(&decoded[..cms.len()], cms.as_slice());
    assert!(decoded[cms.len()..].iter().all(|b| *b == 0));

    let pdf = hayro_syntax::Pdf::new(signed).expect("signed file reads");
    let xref = pdf.xref();
    let catalog: Dict<'_> = xref.get(xref.root_id()).expect("catalog");
    let perms: Dict<'_> = catalog.get(b"Perms").expect("Perms");
    let sig: Dict<'_> = perms.get(b"DocMDP").expect("signature");
    let contents = sig
        .get::<hayro_syntax::object::String<'_>>(b"Contents")
        .expect("Contents");
    assert!(contents.as_bytes().starts_with(&cms));
}

#[test]
fn embed_takes_exactly_the_capacity_and_refuses_more_or_nothing() {
    let fits = vec![0x30u8; CAPACITY];
    assert!(prepared().embed(&fits).is_ok());

    let oversize = vec![0x30u8; CAPACITY + 1];
    match prepared().embed(&oversize) {
        Err(PdfSignatureError::SignatureTooLarge { len, capacity }) => {
            assert_eq!((len, capacity), (CAPACITY + 1, CAPACITY));
        }
        other => panic!("expected a size refusal, got {other:?}"),
    }
    assert!(matches!(
        prepared().embed(&[]),
        Err(PdfSignatureError::EmptySignature)
    ));
}

#[test]
fn prepare_refuses_its_own_output_and_a_signed_file() {
    let prepared = prepared();
    assert!(matches!(
        prepare(prepared.bytes(), &field()),
        Err(PdfSignatureError::NotSingleRevision)
    ));
    let signed = prepared
        .embed(&[0x30, 0x03, 0x02, 0x01, 0x00])
        .expect("embed");
    assert!(matches!(
        prepare(&signed, &field()),
        Err(PdfSignatureError::NotSingleRevision)
    ));
}

#[test]
fn prepare_refuses_garbage_without_panicking() {
    let original = certificate_pdf();
    let mut appended = original.to_vec();
    appended.extend_from_slice(b"\ntrailing bytes");
    let mut flipped_xref = original.to_vec();
    let xref = startxref(original);
    flipped_xref[xref] = b'X';
    let inputs: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("text", b"hello, registry".to_vec()),
        ("header only", b"%PDF-2.0\n%%EOF".to_vec()),
        ("truncated", original[..original.len() - 10].to_vec()),
        ("half", original[..original.len() / 2].to_vec()),
        ("bytes after the end marker", appended),
        ("broken xref keyword", flipped_xref),
    ];
    for (label, input) in inputs {
        match prepare(&input, &field()) {
            Err(PdfSignatureError::Malformed(_)) => {}
            other => panic!("{label}: expected a malformed-input refusal, got {other:?}"),
        }
    }
}

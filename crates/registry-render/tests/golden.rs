//! Golden and determinism acceptance tests for the three coequal example
//! bundles. The pinned hashes live in `products/render/golden.json`; the
//! two-OS CI job re-runs this file so a byte difference anywhere — Typst
//! pin, lockfile (including the deflate stack), bundle content — is a
//! reviewed diff, never a silent pass.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use serde_json::Value;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate sits at crates/registry-render")
        .to_path_buf()
}

struct Case {
    name: &'static str,
    bundle: PathBuf,
    document: &'static str,
    locale: Option<&'static str>,
    asset: Option<(&'static str, PathBuf)>,
}

fn cases() -> Vec<Case> {
    let root = repo_root().join("products/render/bundles");
    vec![
        Case {
            name: "receipt",
            bundle: root.join("receipt"),
            document: "receipt",
            locale: None,
            asset: None,
        },
        Case {
            name: "certificate",
            bundle: root.join("certificate"),
            document: "certificate",
            locale: None,
            asset: None,
        },
        Case {
            name: "card",
            bundle: root.join("card"),
            document: "beneficiary-card",
            locale: Some("ar"),
            asset: Some(("photo", root.join("card/fixtures/photo.b64"))),
        },
    ]
}

fn golden() -> Value {
    let path = repo_root().join("products/render/golden.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("golden.json readable"))
        .expect("golden.json valid")
}

fn issued_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 16, 10, 32, 0).unwrap()
}

fn render_case(case: &Case) -> registry_render::Rendered {
    let bundle = registry_render::Bundle::load_sealed(&case.bundle).expect("sealed bundle");
    let document = bundle.document(case.document).expect("document");
    let data: Value = serde_json::from_str(
        &std::fs::read_to_string(case.bundle.join("fixtures/data.json")).expect("fixture"),
    )
    .expect("fixture json");
    let mut assets = BTreeMap::new();
    if let Some((name, path)) = &case.asset {
        assets.insert(
            (*name).to_owned(),
            std::fs::read_to_string(path)
                .expect("asset b64")
                .trim()
                .to_owned(),
        );
    }
    let request = registry_render::RenderRequest {
        locale: case.locale.map(str::to_owned),
        data,
        assets,
        issued_at: issued_at(),
    };
    registry_render::render(&bundle, document, &request, false).expect("render")
}

#[test]
fn golden_hashes_match() {
    let golden = golden();
    for case in cases() {
        let rendered = render_case(&case);
        let pinned = &golden["documents"][case.name];
        assert_eq!(
            rendered.pdf_sha256,
            pinned["pdfSha256"].as_str().expect("pinned pdf hash"),
            "golden PDF hash drifted for {} — a byte change happened somewhere; review it",
            case.name
        );
        assert_eq!(
            rendered.data_sha256,
            pinned["dataSha256"].as_str().expect("pinned data hash"),
            "golden envelope hash drifted for {}",
            case.name
        );
        assert!(
            rendered.warnings.is_empty(),
            "{} rendered with warnings: {:?}",
            case.name,
            rendered.warnings
        );
        assert!(
            !rendered.deps.is_empty(),
            "{} closure must be captured",
            case.name
        );
    }
}

#[test]
fn rendering_is_deterministic_across_fresh_worlds_and_processes() {
    // Twice in-process (fresh world and library per render by construction),
    // plus the hash equality across separate CLI processes is enforced by
    // the merge-gate evidence in products/render/EVIDENCE.md.
    for case in cases() {
        let first = render_case(&case);
        let second = render_case(&case);
        assert_eq!(
            first.pdf, second.pdf,
            "{} bytes must be identical",
            case.name
        );
    }
}

#[test]
fn injected_bytes_are_the_hashed_canonical_bytes() {
    for case in cases() {
        let rendered = render_case(&case);
        let envelope: Value =
            serde_json::from_slice(&rendered.envelope_bytes).expect("envelope json");
        let recanonicalized =
            registry_render::envelope::canonical_bytes(&envelope).expect("recanonicalize");
        assert_eq!(
            rendered.envelope_bytes, recanonicalized,
            "{} envelope must be exactly RFC 8785 canonical",
            case.name
        );
        assert_eq!(
            rendered.data_sha256,
            registry_render::hash::sha256_hex(&rendered.envelope_bytes),
            "{} dataSha256 must hash the injected bytes",
            case.name
        );
        let text = String::from_utf8(rendered.envelope_bytes).unwrap();
        assert!(
            !text.contains("renderer"),
            "no renderer version in envelope"
        );
        assert!(!text.contains("typst"), "no typst version in envelope");
    }
}

#[test]
fn issued_at_changes_bytes_and_is_the_only_knob() {
    let case = cases().into_iter().find(|c| c.name == "receipt").unwrap();
    let bundle = registry_render::Bundle::load_sealed(&case.bundle).unwrap();
    let document = bundle.document("receipt").unwrap().clone();
    let data: Value = serde_json::from_str(
        &std::fs::read_to_string(case.bundle.join("fixtures/data.json")).unwrap(),
    )
    .unwrap();
    let later = registry_render::RenderRequest {
        locale: None,
        data: data.clone(),
        assets: BTreeMap::new(),
        issued_at: issued_at() + chrono::Duration::seconds(3600),
    };
    let rendered = registry_render::render(&bundle, &document, &later, false).expect("render");
    let baseline = render_case(&case);
    assert_ne!(
        rendered.pdf_sha256, baseline.pdf_sha256,
        "a different issuance time must produce different bytes"
    );
}

#[test]
fn tampered_sealed_bundle_is_refused() {
    let case = cases().into_iter().find(|c| c.name == "receipt").unwrap();
    let copy = tempfile::tempdir().unwrap();
    copy_bundle(&case.bundle, copy.path());
    // Tamper with a governed file after sealing.
    let labels = copy.path().join("labels/ar.yaml");
    let mut text = std::fs::read_to_string(&labels).unwrap();
    text.push_str("extra: tampered\n");
    std::fs::write(&labels, text).unwrap();
    let problem = registry_render::Bundle::load_sealed(copy.path())
        .expect_err("tampered bundle must be refused");
    assert_eq!(
        problem.kind,
        registry_render::ProblemKind::BundleTampered,
        "{problem}"
    );
    assert!(
        problem.locations.iter().any(|l| l.contains("ar.yaml")),
        "the problem names the drifted file: {problem}"
    );
}

#[test]
fn unsealed_bundle_is_refused_for_serving() {
    let case = cases()
        .into_iter()
        .find(|c| c.name == "certificate")
        .unwrap();
    let copy = tempfile::tempdir().unwrap();
    copy_bundle(&case.bundle, copy.path());
    let manifest_path = copy.path().join("manifest.yaml");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    // Strip the hashes block: everything from `hashes:` to EOF.
    let stripped = manifest.split("hashes:").next().unwrap().to_owned();
    std::fs::write(&manifest_path, stripped).unwrap();
    let problem = registry_render::Bundle::load_sealed(copy.path())
        .expect_err("unsealed bundle must be refused for serve");
    assert_eq!(problem.kind, registry_render::ProblemKind::BundleUnsealed);
    // But plain compile loading still works unsealed.
    registry_render::Bundle::load(copy.path()).expect("compile accepts unsealed");
}

#[test]
fn schema_violations_carry_json_pointers() {
    let case = cases().into_iter().find(|c| c.name == "receipt").unwrap();
    let bundle = registry_render::Bundle::load_sealed(&case.bundle).unwrap();
    let document = bundle.document("receipt").unwrap().clone();
    let mut data: Value = serde_json::from_str(
        &std::fs::read_to_string(case.bundle.join("fixtures/data.json")).unwrap(),
    )
    .unwrap();
    data["payer-nni"] = Value::String("not-ten-digits".into());
    data.as_object_mut().unwrap().remove("reference");
    let request = registry_render::RenderRequest {
        locale: None,
        data,
        assets: BTreeMap::new(),
        issued_at: issued_at(),
    };
    let problem = registry_render::validate_data(&document, &request)
        .expect_err("schema violation must be refused");
    assert_eq!(problem.kind, registry_render::ProblemKind::DataInvalid);
    assert!(
        problem.pointers.iter().any(|p| p == "/data/payer-nni"),
        "pointers name the offending field: {:?}",
        problem.pointers
    );
}

#[test]
fn bad_locale_is_refused_with_a_pointer() {
    let case = cases().into_iter().find(|c| c.name == "card").unwrap();
    let bundle = registry_render::Bundle::load_sealed(&case.bundle).unwrap();
    let document = bundle.document("beneficiary-card").unwrap().clone();
    let data: Value = serde_json::from_str(
        &std::fs::read_to_string(case.bundle.join("fixtures/data.json")).unwrap(),
    )
    .unwrap();
    let request = registry_render::RenderRequest {
        locale: Some("zz".into()),
        data,
        assets: BTreeMap::new(),
        issued_at: issued_at(),
    };
    let problem = registry_render::validate_data(&document, &request)
        .expect_err("undeclared locale must be refused");
    assert_eq!(problem.kind, registry_render::ProblemKind::DataInvalid);
    assert!(
        problem.pointers.contains(&"/locale".to_owned()),
        "{problem}"
    );
}

#[test]
fn wrong_media_type_and_oversize_assets_are_refused() {
    let request = |b64: &str| registry_render::RenderRequest {
        locale: None,
        data: serde_json::json!({}),
        assets: BTreeMap::from([("photo".to_owned(), b64.to_owned())]),
        issued_at: issued_at(),
    };
    let text = base64_of(b"plain text, not an image");
    let problem = registry_render::decode_assets(
        &request(&text),
        registry_render::bundle::DEFAULT_MAX_ASSET_BYTES,
        registry_render::bundle::DEFAULT_MAX_TOTAL_ASSET_BYTES,
    )
    .expect_err("non-image assets must be refused");
    assert_eq!(problem.kind, registry_render::ProblemKind::AssetInvalid);

    let big = [0xFFu8, 0xD8]; // JPEG magic
    let big = big.repeat(2 * 1024 * 1024); // > 2 MiB after decode
    let big = base64_of(&big);
    let problem = registry_render::decode_assets(
        &request(&big),
        registry_render::bundle::DEFAULT_MAX_ASSET_BYTES,
        registry_render::bundle::DEFAULT_MAX_TOTAL_ASSET_BYTES,
    )
    .expect_err("oversize assets must be refused");
    assert_eq!(problem.kind, registry_render::ProblemKind::AssetInvalid);
}

#[test]
fn data_paths_cannot_escape_the_bundle() {
    // A reviewed template that passes a data-controlled path to image()
    // must still be contained: path safety is world-enforced.
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path();
    std::fs::write(
        bundle.join("manifest.yaml"),
        "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n  - id: leak\n    version: 1\n    entry: templates/leak.typ\n",
    )
    .unwrap();
    std::fs::create_dir_all(bundle.join("templates")).unwrap();
    std::fs::create_dir_all(bundle.join("fonts")).unwrap();
    std::fs::create_dir_all(bundle.join("labels")).unwrap();
    std::fs::create_dir_all(bundle.join("packages/preview")).unwrap();
    let secrets = tempfile::tempdir().unwrap();
    std::fs::write(secrets.path().join("secret.txt"), "classified").unwrap();
    std::fs::write(
        bundle.join("templates/leak.typ"),
        "#let payload = json(bytes(sys.inputs.data))\n#image(payload.data.path, width: 5mm)\n",
    )
    .unwrap();
    let loaded = registry_render::Bundle::load(bundle).expect("bundle loads");
    let document = loaded.document("leak").unwrap().clone();
    let request = registry_render::RenderRequest {
        locale: None,
        data: serde_json::json!({
            "path": format!("{}", secrets.path().join("secret.txt").display())
        }),
        assets: BTreeMap::new(),
        issued_at: issued_at(),
    };
    let problem = registry_render::render(&loaded, &document, &request, false)
        .expect_err("absolute data path must not load");
    assert_eq!(problem.kind, registry_render::ProblemKind::CompileFailed);
    // Typst virtualizes absolute paths as root-relative before the world
    // sees them; both refusal spellings mean the same thing: contained.
    assert!(
        problem.detail.contains("access denied") || problem.detail.contains("not found"),
        "{problem}"
    );
    // No bytes of the target may appear anywhere in the failure.
    assert!(!problem.detail.contains("classified"));
}

#[test]
fn unvendored_package_import_fails_without_network() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path();
    std::fs::write(
        bundle.join("manifest.yaml"),
        "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n  - id: x\n    version: 1\n    entry: templates/x.typ\n",
    )
    .unwrap();
    std::fs::create_dir_all(bundle.join("templates")).unwrap();
    std::fs::create_dir_all(bundle.join("fonts")).unwrap();
    std::fs::create_dir_all(bundle.join("labels")).unwrap();
    std::fs::create_dir_all(bundle.join("packages/preview")).unwrap();
    std::fs::write(
        bundle.join("templates/x.typ"),
        "#import \"@preview/never-vendored:9.9.9\": does-not-exist\nHello",
    )
    .unwrap();
    let loaded = registry_render::Bundle::load(bundle).unwrap();
    let document = loaded.document("x").unwrap().clone();
    let request = registry_render::RenderRequest {
        locale: None,
        data: serde_json::json!({}),
        assets: BTreeMap::new(),
        issued_at: issued_at(),
    };
    let problem = registry_render::render(&loaded, &document, &request, false)
        .expect_err("unvendored import must fail closed");
    assert_eq!(problem.kind, registry_render::ProblemKind::CompileFailed);
    assert!(problem.detail.contains("not found"), "{problem}");
}

fn copy_bundle(from: &Path, to: &Path) {
    for entry in walkdir(from) {
        let rel = entry.strip_prefix(from).unwrap();
        let target = to.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&target).unwrap();
        } else {
            std::fs::copy(&entry, &target).unwrap();
        }
    }
}

fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![dir.to_path_buf()];
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current).unwrap() {
            let entry = entry.unwrap().path();
            if entry.is_dir() {
                stack.push(entry.clone());
            }
            out.push(entry);
        }
    }
    out
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// SPDX-License-Identifier: Apache-2.0
//! Reading a metadata manifest (`manifest/metadata`) through the shared
//! reader, then the rules `validate_manifest` applies, each placed at the
//! member it names.

use std::path::Path;

use registry_manifest_core::{
    is_runtime_only_key, is_secret_bearing_key, source_manifest_digest, validate_manifest,
    MetadataError, MetadataManifest, MetadataManifestFields,
};
use registry_platform_yaml::{
    escape_pointer_segment, Diagnostic, Document, Expect, Node, NodeValue, Reader, Report, Severity,
};

use crate::{contents, Contents, Findings, METADATA_FORMAT, METADATA_SCHEMA_VERSION};

const RUNTIME_ONLY_MESSAGE: &str =
    "this key configures a running service, and a metadata manifest describes data portably \
     without runtime configuration";
const RUNTIME_ONLY_ACTION: &str =
    "Remove the member, and keep it in the runtime configuration of the service that uses it.";
const SECRET_BEARING_MESSAGE: &str =
    "this key names a credential or secret, which a metadata manifest never carries";
const SECRET_BEARING_ACTION: &str =
    "Remove the member, and keep the credential in the secret provider of the service that \
     uses it.";

/// A metadata manifest the reader and `validate_manifest` accepted, with
/// the document its findings are placed in.
pub struct ReadManifest {
    pub manifest: MetadataManifest,
    pub document: Document,
}

/// Read a metadata manifest. `file` is the name every diagnostic carries.
///
/// The reader refuses `${...}` (CFG-SEC-2), YAML anchors and aliases,
/// unknown and duplicate keys, and nulls. A runtime-only or secret-bearing
/// key is refused at the key, wherever it is written, before the manifest
/// is decoded; every rule `validate_manifest` applies is then reported at
/// the member it names. Warnings travel in the document.
pub fn read_metadata(file: &str, bytes: &[u8]) -> Result<ReadManifest, Vec<Diagnostic>> {
    let mut hook = registry_platform_config::AuthoredExpressions;
    let document = Reader::new(file)
        .with_hook(&mut hook)
        .read(bytes, &Expect::one(&METADATA_FORMAT))
        .map_err(Report::into_diagnostics)?;
    let mut refused = Vec::new();
    if let Some(entry) = document.root().get("schema_version") {
        let current = matches!(
            &entry.value.value,
            NodeValue::String(text) if text.text == METADATA_SCHEMA_VERSION
        );
        if !current {
            refused.push(unsupported_version(&document));
        }
    }
    if refused.is_empty() {
        refused_keys(&document, document.root(), "", &mut refused);
    }
    if !refused.is_empty() {
        let mut diagnostics = document.warnings().into_diagnostics();
        diagnostics.extend(refused);
        return Err(diagnostics);
    }
    let fields = document
        .decode::<MetadataManifestFields>()
        .map_err(Report::into_diagnostics)?;
    let manifest = MetadataManifest::from(fields);
    if let Err(error) = validate_manifest(&manifest) {
        let mut diagnostics = document.warnings().into_diagnostics();
        diagnostics.extend(metadata_error_diagnostics(&document, error));
        return Err(diagnostics);
    }
    Ok(ReadManifest { manifest, document })
}

/// Every runtime-only or secret-bearing key at or below `node`. The value
/// of a refused key is not searched: the whole member goes.
fn refused_keys(document: &Document, node: &Node, pointer: &str, found: &mut Vec<Diagnostic>) {
    match &node.value {
        NodeValue::Mapping(entries) => {
            for entry in entries {
                let child = format!("{pointer}/{}", escape_pointer_segment(&entry.key));
                if is_runtime_only_key(&entry.key) {
                    found.push(document.diagnostic_at_key(
                        Severity::Error,
                        "manifest.metadata.runtime-only-key",
                        &child,
                        RUNTIME_ONLY_MESSAGE,
                        RUNTIME_ONLY_ACTION,
                    ));
                } else if is_secret_bearing_key(&entry.key) {
                    found.push(document.diagnostic_at_key(
                        Severity::Error,
                        "manifest.metadata.secret-bearing-key",
                        &child,
                        SECRET_BEARING_MESSAGE,
                        SECRET_BEARING_ACTION,
                    ));
                } else {
                    refused_keys(document, &entry.value, &child, found);
                }
            }
        }
        NodeValue::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                refused_keys(document, item, &format!("{pointer}/{index}"), found);
            }
        }
        _ => {}
    }
}

fn unsupported_version(document: &Document) -> Diagnostic {
    document.diagnostic_at_value(
        Severity::Error,
        "manifest.metadata.unsupported-version",
        "/schema_version",
        "this release reads metadata manifests whose schema_version is registry-manifest/v1",
        "Set schema_version to registry-manifest/v1, and write the manifest in that version's \
         shape.",
    )
}

/// The diagnostics for a manifest `validate_manifest` or `compile_manifest`
/// refused. Each rule's code is `manifest.metadata.<condition>`; it is
/// placed at the member it names, or at the nearest enclosing member the
/// file writes when the member is absent, and its path is always the
/// member's own.
pub fn metadata_error_diagnostics(document: &Document, error: MetadataError) -> Vec<Diagnostic> {
    match error {
        MetadataError::VersionUnsupported => vec![unsupported_version(document)],
        MetadataError::Validation { errors } => errors
            .into_iter()
            .map(|error| {
                let pointer = validation_pointer(&error.path);
                let mut written = pointer.as_str();
                while document.root().pointer(written).is_none() {
                    written = written.rfind('/').map_or("", |at| &written[..at]);
                }
                let mut diagnostic = document.diagnostic_at_value(
                    Severity::Error,
                    &format!("manifest.metadata.{}", error.condition.code()),
                    written,
                    &error.message,
                    error.condition.suggested_action(),
                );
                diagnostic.path = pointer;
                diagnostic
            })
            .collect(),
    }
}

/// The RFC 6901 pointer for a `validate_manifest` path:
/// `datasets[0].entities[1].name` is `/datasets/0/entities/1/name`, and a
/// vocabulary prefix stays one segment however it is written.
pub fn validation_pointer(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    if let Some(prefix) = path.strip_prefix("vocabularies.") {
        return format!("/vocabularies/{}", escape_pointer_segment(prefix));
    }
    let mut pointer = String::new();
    for segment in path.split('.') {
        let (name, indexes) = segment.split_at(segment.find('[').unwrap_or(segment.len()));
        pointer.push('/');
        pointer.push_str(&escape_pointer_segment(name));
        for index in indexes.split(['[', ']']).filter(|index| !index.is_empty()) {
            pointer.push('/');
            pointer.push_str(index);
        }
    }
    pointer
}

/// The `source_manifest_digest` of an accepted manifest, or the diagnostic
/// that says why it cannot be computed.
pub fn manifest_digest(read: &ReadManifest) -> Result<String, Box<Diagnostic>> {
    source_manifest_digest(&read.manifest).map_err(|_| {
        Box::new(read.document.diagnostic_at_value(
            Severity::Error,
            "manifest.metadata.not-canonicalizable",
            "",
            "the manifest holds a number canonical JSON cannot represent, so its source \
             digest cannot be computed",
            "Write every number in the manifest as a finite value that IEEE 754 binary64 \
             represents exactly.",
        ))
    })
}

/// What `validate` found in one metadata manifest file.
pub struct MetadataCheck {
    /// The manifest, when nothing refused it.
    pub manifest: Option<ReadManifest>,
    pub report: Report,
    /// The file could not be read, so the check is incomplete.
    pub unavailable: bool,
}

/// Read and check the metadata manifest at `path`.
pub fn check_metadata_file(path: &Path) -> MetadataCheck {
    let mut findings = Findings::default();
    let manifest = match contents(path) {
        Contents::Missing => {
            findings.unreadable(
                "manifest.metadata.missing-file",
                path,
                "the metadata manifest does not exist",
                "Pass the path of an existing metadata manifest.",
            );
            None
        }
        Contents::Unreadable => {
            findings.unreadable(
                "manifest.metadata.unreadable",
                path,
                "the metadata manifest is not a regular file this process can read",
                "Pass a regular file, and give this process permission to read it.",
            );
            None
        }
        Contents::Bytes(bytes) => {
            findings.files = 1;
            match read_metadata(&path.display().to_string(), &bytes) {
                Ok(read) => {
                    findings.extend(read.document.warnings().into_diagnostics());
                    Some(read)
                }
                Err(diagnostics) => {
                    findings.extend(diagnostics);
                    None
                }
            }
        }
    };
    let (report, unavailable) = findings.into_report();
    MetadataCheck {
        manifest,
        report,
        unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "schema_version: registry-manifest/v1\ncatalog:\n  id: demo\n  \
                           base_url: https://metadata.example.test\n  title: Demo\n  \
                           publisher:\n    name: Publisher\n";

    fn refused(text: &str) -> Vec<Diagnostic> {
        match read_metadata("metadata.yaml", text.as_bytes()) {
            Ok(_) => panic!("the manifest was accepted"),
            Err(diagnostics) => diagnostics,
        }
    }

    #[test]
    fn validation_paths_become_pointers() {
        assert_eq!(validation_pointer(""), "");
        assert_eq!(validation_pointer("catalog.base_url"), "/catalog/base_url");
        assert_eq!(
            validation_pointer("datasets[0].entities[12].fields[3].name"),
            "/datasets/0/entities/12/fields/3/name"
        );
        assert_eq!(
            validation_pointer("vocabularies.a.b/c~d"),
            "/vocabularies/a.b~1c~0d"
        );
    }

    #[test]
    fn a_minimal_manifest_is_accepted() {
        let read = read_metadata("metadata.yaml", MINIMAL.as_bytes())
            .unwrap_or_else(|diagnostics| panic!("refused: {diagnostics:#?}"));
        assert_eq!(read.manifest.catalog.id, "demo");
        assert!(manifest_digest(&read).is_ok());
    }

    #[test]
    fn a_rule_is_placed_at_the_member_it_names() {
        let text = MINIMAL.replace("https://metadata.example.test", "metadata.example.test");
        let diagnostics = refused(&text);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic.code, "manifest.metadata.invalid-url");
        assert_eq!(diagnostic.path, "/catalog/base_url");
        let source = diagnostic.source.as_ref().expect("a position");
        assert_eq!((source.line, source.column), (Some(4), Some(13)));
        assert!(!diagnostic.message.contains("metadata.example.test"));
    }

    #[test]
    fn an_absent_member_is_placed_at_its_nearest_written_parent() {
        let text = format!(
            "{MINIMAL}ecosystem_bindings:\n  - id: binding\n    version: \"1\"\n    \
             profile: demo\n    type: governed-evidence\n"
        );
        let diagnostics = refused(&text);
        let missing = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.path == "/ecosystem_bindings/0/evidence_pack")
            .unwrap_or_else(|| panic!("no finding names the evidence pack: {diagnostics:#?}"));
        assert_eq!(missing.code, "manifest.metadata.missing-member");
        let source = missing.source.as_ref().expect("a position");
        assert_eq!((source.line, source.column), (Some(9), Some(5)));
    }

    #[test]
    fn runtime_only_and_secret_bearing_keys_are_refused_at_the_key() {
        let text = format!(
            "{MINIMAL}datasets:\n  - id: people\n    title: People\n    source: table\n    \
             policy:\n      api_key: planted\n"
        );
        let diagnostics = refused(&text);
        let codes = diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            [
                ("manifest.metadata.runtime-only-key", "/datasets/0/source"),
                (
                    "manifest.metadata.secret-bearing-key",
                    "/datasets/0/policy/api_key"
                ),
            ]
        );
        let source = diagnostics[0].source.as_ref().expect("a position");
        assert_eq!((source.line, source.column), (Some(11), Some(5)));
        assert!(diagnostics
            .iter()
            .all(|diagnostic| !diagnostic.message.contains("planted")));
    }

    #[test]
    fn cfg_id_5_a_repeated_id_in_a_named_item_list_is_refused_at_the_copy() {
        for (list, item) in [
            ("profiles", "{id: p, version: \"1\"}"),
            (
                "evaluation_profiles",
                "{id: e, ruleset: r, claim_id: c, subject_id_type: s}",
            ),
            ("requirements", "{id: r, title: R}"),
            ("evidence_types", "{id: t, title: T}"),
            ("authorities", "{id: a, name: A}"),
            ("public_services", "{id: s, title: S}"),
            ("data_services", "{id: d, title: D}"),
            ("distributions", "{id: x, dataset: people}"),
            ("forms", "{id: f, title: F, service: s}"),
            ("datasets", "{id: people, title: People}"),
            (
                "codelists",
                "{id: c, scheme_iri: https://codelists.example.test/c}",
            ),
        ] {
            let text = format!("{MINIMAL}{list}:\n  - {item}\n  - {item}\n");
            let diagnostics = refused(&text);
            let found = diagnostics
                .iter()
                .map(|diagnostic| {
                    (
                        diagnostic.code.as_str(),
                        diagnostic.path.as_str(),
                        diagnostic
                            .related
                            .iter()
                            .map(|related| related.path.as_str())
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                found,
                [(
                    "config.duplicate-id",
                    format!("/{list}/1/id").as_str(),
                    vec![format!("/{list}/0/id").as_str()],
                )],
                "{list}"
            );
        }
    }

    #[test]
    fn another_schema_version_is_refused_before_its_shape_is_read() {
        let text = MINIMAL.replace("registry-manifest/v1", "registry-manifest/v0")
            + "retired_member: true\n";
        let diagnostics = refused(&text);
        assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
        assert_eq!(diagnostics[0].code, "manifest.metadata.unsupported-version");
        assert_eq!(diagnostics[0].path, "/schema_version");
    }

    #[test]
    fn substitution_is_refused_in_a_manifest() {
        let text = MINIMAL.replace("title: Demo", "title: ${TITLE}");
        let diagnostics = refused(&text);
        assert_eq!(diagnostics[0].code, "config.substitution-not-allowed");
        assert_eq!(diagnostics[0].path, "/catalog/title");
    }
}

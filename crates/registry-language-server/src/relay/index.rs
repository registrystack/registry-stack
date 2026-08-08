// SPDX-License-Identifier: Apache-2.0
//! Loads Relay project documents from disk and walks them into symbols and references.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use tower_lsp_server::ls_types::{DiagnosticSeverity, Position, Range};

use crate::{
    refs::{
        bounded_value, document_diagnostic, IndexedDiagnostic, IndexedLocation, IndexedReference,
        IndexedSymbol, RelayKind, SymbolKey, SymbolQuery,
    },
    safety::{secure_directory, secure_regular_file},
    workspace::LoadedProjectDocuments,
    yaml::{ParsedDocument, YamlValue},
};

pub(crate) const PROJECT_FILE: &str = "registry-stack.yaml";
const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;

pub(crate) fn is_project_document(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let components = relative.components().collect::<Vec<_>>();
    let normal = |component: &Component<'_>| matches!(component, Component::Normal(_));
    let extension_is_yaml = || {
        relative
            .extension()
            .is_some_and(|extension| extension == "yaml")
    };

    match components.as_slice() {
        [Component::Normal(file)] => file == &PROJECT_FILE,
        [first, second] if normal(first) && normal(second) => {
            matches!(first, Component::Normal(name) if *name == "entities" || *name == "environments")
                && extension_is_yaml()
        }
        [Component::Normal(integrations), integration, Component::Normal(file)] => {
            *integrations == "integrations" && normal(integration) && *file == "integration.yaml"
        }
        [Component::Normal(integrations), integration, Component::Normal(fixtures), fixture] => {
            *integrations == "integrations"
                && normal(integration)
                && *fixtures == "fixtures"
                && normal(fixture)
                && extension_is_yaml()
        }
        _ => false,
    }
}

pub(crate) fn load_project_documents(root: &Path) -> Result<LoadedProjectDocuments> {
    let mut candidates = vec![root.join(PROJECT_FILE)];
    add_yaml_files(root, &root.join("entities"), &mut candidates)?;
    add_yaml_files(root, &root.join("environments"), &mut candidates)?;

    let integrations = root.join("integrations");
    if secure_directory(root, &integrations)? {
        let entries = fs::read_dir(&integrations)
            .with_context(|| format!("failed to inspect integrations under {}", root.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| {
                format!("failed to inspect integrations under {}", root.display())
            })?;
            let directory = entry.path();
            if secure_directory(root, &directory)? {
                candidates.push(directory.join("integration.yaml"));
                add_yaml_files(root, &directory.join("fixtures"), &mut candidates)?;
            }
        }
    }

    candidates.sort();
    candidates.dedup();
    let mut documents = BTreeMap::new();
    let mut diagnostics = Vec::new();
    for path in candidates {
        let Some(metadata) = secure_regular_file(root, &path)? else {
            continue;
        };
        if metadata.len() > MAX_DOCUMENT_BYTES {
            diagnostics.push(document_diagnostic(
                &path,
                "Project document exceeds the 1 MiB indexing limit",
            ));
            continue;
        }
        match fs::read(&path) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(source) => {
                    documents.insert(path, source);
                }
                Err(_) => diagnostics.push(document_diagnostic(
                    &path,
                    "Project document is not valid UTF-8 and cannot be indexed",
                )),
            },
            Err(error) if path.ends_with(PROJECT_FILE) => {
                return Err(error).context("failed to read registry-stack.yaml")
            }
            Err(_) => diagnostics.push(document_diagnostic(
                &path,
                "Project document could not be read; check its permissions",
            )),
        }
    }
    if !documents.contains_key(&root.join(PROJECT_FILE)) {
        anyhow::bail!("registry-stack.yaml is missing, unsafe, oversized, or not valid UTF-8");
    }
    Ok(LoadedProjectDocuments {
        documents,
        diagnostics,
    })
}

fn add_yaml_files(root: &Path, directory: &Path, candidates: &mut Vec<PathBuf>) -> Result<()> {
    if !secure_directory(root, directory)? {
        return Ok(());
    }
    let entries = fs::read_dir(directory).with_context(|| {
        format!(
            "failed to inspect a project directory under {}",
            root.display()
        )
    })?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "failed to inspect an entry in a project directory under {}",
                root.display()
            )
        })?;
        if entry.path().extension().is_some_and(|ext| ext == "yaml")
            && secure_regular_file(root, &entry.path())?.is_some()
        {
            candidates.push(entry.path());
        }
    }
    Ok(())
}

/// Walks the parsed Relay documents of one project root into symbols, references, and the
/// diagnostics only the walker can report.
pub(crate) fn build_index(
    root: &Path,
    parsed: &BTreeMap<PathBuf, ParsedDocument>,
) -> (
    Vec<IndexedSymbol>,
    Vec<IndexedReference>,
    Vec<IndexedDiagnostic>,
) {
    let mut builder = IndexBuilder {
        root,
        parsed,
        symbols: Vec::new(),
        references: Vec::new(),
        diagnostics: Vec::new(),
    };
    builder.build();
    (builder.symbols, builder.references, builder.diagnostics)
}

struct IndexBuilder<'a> {
    root: &'a Path,
    parsed: &'a BTreeMap<PathBuf, ParsedDocument>,
    symbols: Vec<IndexedSymbol>,
    references: Vec<IndexedReference>,
    diagnostics: Vec<IndexedDiagnostic>,
}

impl IndexBuilder<'_> {
    fn build(&mut self) {
        let manifest_path = self.root.join(PROJECT_FILE);
        let mut claimed_definition_files = BTreeSet::new();
        if let Some(manifest) = self.parsed.get(&manifest_path) {
            self.extract_manifest(
                &manifest_path,
                &manifest.value,
                &mut claimed_definition_files,
            );
        }

        for (path, document) in self.parsed {
            if path == &manifest_path {
                continue;
            }
            let Ok(relative) = path.strip_prefix(self.root) else {
                continue;
            };
            if is_fixture_path(relative) {
                self.extract_fixture(path, &document.value);
            } else if is_environment_path(relative) {
                self.extract_environment(path, relative, &document.value);
            } else if !claimed_definition_files.contains(path) {
                if is_integration_path(relative) {
                    self.extract_orphan_definition(path, &document.value, RelayKind::Integration);
                } else if is_entity_path(relative) {
                    self.extract_orphan_definition(path, &document.value, RelayKind::Entity);
                }
            }
        }
    }

    fn extract_manifest(
        &mut self,
        path: &Path,
        manifest: &YamlValue,
        claimed_definition_files: &mut BTreeSet<PathBuf>,
    ) {
        if let Some(registry_id) = manifest
            .get("registry")
            .and_then(|registry| registry.get_scalar("id"))
        {
            self.add_resolvable_symbol(
                SymbolKey::global(RelayKind::Registry, &registry_id.value),
                None,
                path,
                registry_id.range,
            );
        }

        self.extract_aliases(
            path,
            manifest,
            "integrations",
            RelayKind::Integration,
            claimed_definition_files,
        );
        self.extract_aliases(
            path,
            manifest,
            "entities",
            RelayKind::Entity,
            claimed_definition_files,
        );

        let Some(services) = manifest.get("services").and_then(YamlValue::as_mapping) else {
            return;
        };
        for service in services {
            let service_name = service.key.value.clone();
            self.add_resolvable_symbol(
                SymbolKey::global(RelayKind::Service, &service_name),
                None,
                path,
                service.key.range,
            );

            if let Some(entity) = service.value.get_scalar("entity") {
                self.add_reference(
                    SymbolQuery::global(RelayKind::Entity, &entity.value),
                    path,
                    entity.range,
                );
            }

            if let Some(consultations) = service
                .value
                .get("consultations")
                .and_then(YamlValue::as_mapping)
            {
                for consultation in consultations {
                    self.add_resolvable_symbol(
                        SymbolKey::scoped(
                            RelayKind::Consultation,
                            &service_name,
                            &consultation.key.value,
                        ),
                        Some(service_name.clone()),
                        path,
                        consultation.key.range,
                    );
                    if let Some(integration) = consultation.value.get_scalar("integration") {
                        self.add_reference(
                            SymbolQuery::global(RelayKind::Integration, &integration.value),
                            path,
                            integration.range,
                        );
                    }
                }
            }
        }
    }

    fn extract_aliases(
        &mut self,
        manifest_path: &Path,
        manifest: &YamlValue,
        field: &str,
        kind: RelayKind,
        claimed_definition_files: &mut BTreeSet<PathBuf>,
    ) {
        let Some(aliases) = manifest.get(field).and_then(YamlValue::as_mapping) else {
            return;
        };
        for alias in aliases {
            let key = SymbolKey::global(kind, &alias.key.value);
            let file = alias.value.get_scalar("file");
            let definition_path =
                file.and_then(|file| safe_definition_path(self.root, &file.value, kind));
            let external_id = definition_path
                .as_ref()
                .and_then(|path| self.parsed.get(path).map(|document| (path, document)))
                .and_then(|(path, document)| document.value.get_scalar("id").map(|id| (path, id)));

            if let Some((path, id)) = external_id {
                claimed_definition_files.insert(path.clone());
                self.add_resolvable_symbol(key, None, path, id.range);
                self.add_reference(
                    SymbolQuery::global(kind, &alias.key.value),
                    manifest_path,
                    alias.key.range,
                );
                continue;
            }

            let problem = match (file, definition_path.as_ref()) {
                (None, _) => "does not declare a file",
                (Some(_), None) => "declares a file outside the supported project layout",
                (Some(_), Some(path))
                    if self
                        .parsed
                        .get(path)
                        .is_some_and(|document| document.syntax_error.is_some()) =>
                {
                    "targets invalid YAML"
                }
                (Some(_), Some(path)) if self.parsed.contains_key(path) => {
                    "targets a document without a scalar id"
                }
                (Some(_), Some(_)) => {
                    "targets a missing, unreadable, unsafe, oversized, or non-UTF-8 file"
                }
            };
            self.diagnostics.push(IndexedDiagnostic {
                path: manifest_path.to_path_buf(),
                range: file.map_or(alias.key.range, |file| file.range),
                severity: DiagnosticSeverity::ERROR,
                message: format!(
                    "Declared {} '{}' {problem}; use a regular UTF-8 YAML file inside the documented project layout",
                    kind.label(),
                    bounded_value(&alias.key.value),
                ),
            });
            if let Some(path) = definition_path {
                if self.parsed.contains_key(&path) {
                    claimed_definition_files.insert(path);
                }
            }
        }
    }

    fn extract_orphan_definition(&mut self, path: &Path, document: &YamlValue, kind: RelayKind) {
        if let Some(id) = document.get_scalar("id") {
            self.add_non_resolving_symbol(SymbolKey::global(kind, &id.value), None, path, id.range);
        }
    }

    fn extract_fixture(&mut self, path: &Path, document: &YamlValue) {
        if let Some(name) = document.get_scalar("name") {
            self.add_resolvable_symbol(
                SymbolKey::global(RelayKind::Fixture, &name.value),
                None,
                path,
                name.range,
            );
        }
    }

    fn extract_environment(&mut self, path: &Path, relative: &Path, document: &YamlValue) {
        if let Some(name) = relative.file_stem().and_then(|name| name.to_str()) {
            let range = Range::new(Position::new(0, 0), Position::new(0, 0));
            self.add_resolvable_symbol(
                SymbolKey::global(RelayKind::Environment, name),
                None,
                path,
                range,
            );
        }
        for (field, kind) in [
            ("integrations", RelayKind::Integration),
            ("entities", RelayKind::Entity),
        ] {
            if let Some(entries) = document.get(field).and_then(YamlValue::as_mapping) {
                for entry in entries {
                    self.add_reference(
                        SymbolQuery::global(kind, &entry.key.value),
                        path,
                        entry.key.range,
                    );
                }
            }
        }
    }

    fn add_resolvable_symbol(
        &mut self,
        key: SymbolKey,
        container_name: Option<String>,
        path: &Path,
        range: Range,
    ) {
        self.add_symbol(key, container_name, path, range, true);
    }

    fn add_non_resolving_symbol(
        &mut self,
        key: SymbolKey,
        container_name: Option<String>,
        path: &Path,
        range: Range,
    ) {
        self.add_symbol(key, container_name, path, range, false);
    }

    fn add_symbol(
        &mut self,
        key: SymbolKey,
        container_name: Option<String>,
        path: &Path,
        range: Range,
        resolvable: bool,
    ) {
        self.symbols.push(IndexedSymbol {
            name: key.name.clone(),
            kind: key.kind,
            container_name,
            location: IndexedLocation {
                path: path.to_path_buf(),
                range,
            },
            key,
            resolvable,
        });
    }

    fn add_reference(&mut self, target: SymbolQuery, path: &Path, range: Range) {
        self.references.push(IndexedReference {
            target,
            location: IndexedLocation {
                path: path.to_path_buf(),
                range,
            },
        });
    }
}

fn safe_definition_path(root: &Path, relative: &str, kind: RelayKind) -> Option<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    let candidate = root.join(path);
    let supported = match kind {
        RelayKind::Integration => is_integration_path(path),
        RelayKind::Entity => is_entity_path(path),
        _ => false,
    };
    supported.then_some(candidate)
}

fn is_integration_path(relative: &Path) -> bool {
    let components = relative.components().collect::<Vec<_>>();
    matches!(
        components.as_slice(),
        [Component::Normal(integrations), Component::Normal(_), Component::Normal(file)]
            if *integrations == "integrations" && *file == "integration.yaml"
    )
}

fn is_entity_path(relative: &Path) -> bool {
    let components = relative.components().collect::<Vec<_>>();
    matches!(
        components.as_slice(),
        [Component::Normal(entities), Component::Normal(file)]
            if *entities == "entities" && Path::new(file).extension().is_some_and(|ext| ext == "yaml")
    )
}

fn is_environment_path(relative: &Path) -> bool {
    let components = relative.components().collect::<Vec<_>>();
    matches!(
        components.as_slice(),
        [Component::Normal(environments), Component::Normal(file)]
            if *environments == "environments" && Path::new(file).extension().is_some_and(|ext| ext == "yaml")
    )
}

fn is_fixture_path(relative: &Path) -> bool {
    let components = relative.components().collect::<Vec<_>>();
    matches!(
        components.as_slice(),
        [Component::Normal(integrations), Component::Normal(_), Component::Normal(fixtures), Component::Normal(file)]
            if *integrations == "integrations" && *fixtures == "fixtures" && Path::new(file).extension().is_some_and(|ext| ext == "yaml")
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::{
        refs::{ProjectIndex, SymbolKind},
        yaml::{parse_yaml, YamlValue},
    };
    use tempfile::TempDir;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("fixture path has parent")).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn fixture_project() -> TempDir {
        let temp = TempDir::new().unwrap();
        write(
            temp.path(),
            PROJECT_FILE,
            r#"version: 1
registry: { id: "fictional-😀-registry" }
integrations:
  people: { file: integrations/people/integration.yaml }
entities:
  residents: { file: entities/residents.yaml }
services:
  person-check:
    kind: consultation_api
    consultations:
      person_record: { integration: people }
  records:
    kind: records_api
    entity: residents
"#,
        );
        write(
            temp.path(),
            "integrations/people/integration.yaml",
            "version: 1\nid: people-source\n",
        );
        write(
            temp.path(),
            "entities/residents.yaml",
            "version: 1\nid: resident-entity\n",
        );
        write(
            temp.path(),
            "environments/local.yaml",
            "version: 1\nintegrations: { people: { source: {} } }\nentities:\n  residents: { provider: {} }\n",
        );
        write(
            temp.path(),
            "integrations/people/fixtures/active.yaml",
            "name: active-person\n",
        );
        temp
    }

    #[test]
    fn indexes_block_and_flow_yaml_and_resolves_cross_file_definitions() {
        let temp = fixture_project();
        let index = ProjectIndex::load(temp.path()).unwrap();

        assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
        assert!(index.symbols().iter().any(|symbol| {
            symbol.kind == SymbolKind::Relay(RelayKind::Integration)
                && symbol.name == "people"
                && symbol.location.path.ends_with("integration.yaml")
        }));
        assert!(index.symbols().iter().any(|symbol| {
            symbol.kind == SymbolKind::Relay(RelayKind::Entity)
                && symbol.name == "residents"
                && symbol.location.path.ends_with("residents.yaml")
        }));
        assert!(index.symbols().iter().any(|symbol| {
            symbol.kind == SymbolKind::Relay(RelayKind::Consultation)
                && symbol.name == "person_record"
        }));

        let manifest = temp.path().canonicalize().unwrap().join(PROJECT_FILE);
        let locations = index.definitions_at(&manifest, Position::new(10, 38));
        assert_eq!(locations.len(), 1);
        assert!(locations[0].path.ends_with("integration.yaml"));
    }

    #[test]
    fn reports_missing_and_duplicate_references() {
        let temp = fixture_project();
        write(
            temp.path(),
            PROJECT_FILE,
            r#"version: 1
registry: { id: demo }
integrations:
  people: { file: integrations/people/integration.yaml }
services:
  first:
    consultations:
      lookup: { integration: missing }
      lookup: { integration: people }
"#,
        );
        let index = ProjectIndex::load(temp.path()).unwrap();
        let messages = index
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.message.as_str())
            .collect::<Vec<_>>();

        assert!(messages
            .iter()
            .any(|message| message.contains("Unknown integration")));
        assert!(messages
            .iter()
            .any(|message| message.contains("Duplicate consultation")));
    }

    #[test]
    fn orphan_files_never_satisfy_manifest_or_environment_references() {
        let temp = TempDir::new().unwrap();
        write(
            temp.path(),
            PROJECT_FILE,
            r#"version: 1
registry: { id: demo }
services:
  evidence:
    consultations:
      lookup: { integration: orphan-integration }
  records:
    entity: orphan-entity
"#,
        );
        write(
            temp.path(),
            "integrations/orphan/integration.yaml",
            "version: 1\nid: orphan-integration\n",
        );
        write(
            temp.path(),
            "entities/orphan.yaml",
            "version: 1\nid: orphan-entity\n",
        );
        write(
            temp.path(),
            "environments/local.yaml",
            "version: 1\nintegrations: { orphan-integration: {} }\nentities: { orphan-entity: {} }\n",
        );

        let index = ProjectIndex::load(temp.path()).unwrap();
        let messages = index
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.message.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            messages
                .iter()
                .filter(|message| message.contains("Unknown integration reference"))
                .count(),
            2
        );
        assert_eq!(
            messages
                .iter()
                .filter(|message| message.contains("Unknown entity reference"))
                .count(),
            2
        );
        assert!(index
            .workspace_symbols("orphan-integration")
            .iter()
            .any(|symbol| symbol.location.path.ends_with("integration.yaml")));
        assert!(index
            .workspace_symbols("orphan-entity")
            .iter()
            .any(|symbol| symbol.location.path.ends_with("orphan.yaml")));
        assert!(index
            .definitions_at(&temp.path().join(PROJECT_FILE), Position::new(6, 38),)
            .is_empty());
        assert!(index
            .references_at(
                &temp.path().join("integrations/orphan/integration.yaml"),
                Position::new(1, 5),
                true,
            )
            .is_empty());
    }

    #[test]
    fn a_document_that_stops_parsing_still_satisfies_other_documents() {
        let temp = TempDir::new().unwrap();
        write(
            temp.path(),
            PROJECT_FILE,
            r#"version: 1
registry: { id: demo }
entities:
  people: { file: entities/people.yaml }
services:
  records:
    entity: people
"#,
        );
        write(
            temp.path(),
            "entities/people.yaml",
            "version: 1\nid: people\nfields: [\n",
        );

        let index = ProjectIndex::load(temp.path()).unwrap();
        let entity = temp
            .path()
            .canonicalize()
            .unwrap()
            .join("entities/people.yaml");

        assert!(index
            .symbols()
            .iter()
            .any(|symbol| symbol.name == "people" && symbol.location.path == entity));
        assert!(!index
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.message.starts_with("Unknown ")));
        let own = index
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.path == entity)
            .collect::<Vec<_>>();
        assert_eq!(own.len(), 1, "{own:?}");
        assert!(own[0].message.starts_with("Invalid YAML syntax"));
        assert_eq!(own[0].range.start, Position::new(2, 8));
    }

    #[test]
    fn declared_alias_targets_must_be_valid_indexable_documents() {
        let temp = TempDir::new().unwrap();
        write(
            temp.path(),
            PROJECT_FILE,
            r#"version: 1
registry: { id: demo }
integrations:
  missing: { file: integrations/missing/integration.yaml }
  malformed: { file: integrations/malformed/integration.yaml }
  non-utf8: { file: integrations/non-utf8/integration.yaml }
entities:
  missing-entity: { file: entities/missing.yaml }
services:
  evidence:
    consultations:
      one: { integration: missing }
      two: { integration: malformed }
      three: { integration: non-utf8 }
  records:
    entity: missing-entity
"#,
        );
        write(
            temp.path(),
            "integrations/malformed/integration.yaml",
            "id: [\n",
        );
        let non_utf8 = temp.path().join("integrations/non-utf8/integration.yaml");
        fs::create_dir_all(non_utf8.parent().unwrap()).unwrap();
        fs::write(&non_utf8, [0xff, 0xfe]).unwrap();

        let index = ProjectIndex::load(temp.path()).unwrap();
        for alias in ["missing", "malformed", "non-utf8"] {
            assert!(index.diagnostics().iter().any(|diagnostic| {
                diagnostic.message.contains("Declared integration")
                    && diagnostic.message.contains(alias)
            }));
            assert!(index.diagnostics().iter().any(|diagnostic| {
                diagnostic
                    .message
                    .contains(&format!("Unknown integration reference '{alias}'"))
            }));
        }
        assert!(index.diagnostics().iter().any(|diagnostic| diagnostic
            .message
            .contains("Declared entity 'missing-entity'")));
        assert!(index.diagnostics().iter().any(|diagnostic| diagnostic
            .message
            .contains("Unknown entity reference 'missing-entity'")));
        assert!(index.diagnostics().iter().any(|diagnostic| diagnostic
            .message
            .contains("Project document is not valid UTF-8")));
        assert!(index
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.message.contains("Invalid YAML syntax")));
    }

    #[test]
    fn rejects_unrelated_and_nested_project_documents() {
        let root = Path::new("/project");
        assert!(is_project_document(
            root,
            Path::new("/project/registry-stack.yaml")
        ));
        assert!(is_project_document(
            root,
            Path::new("/project/integrations/people/integration.yaml")
        ));
        assert!(!is_project_document(
            root,
            Path::new("/project/integrations/people/fixtures/bodies/response.yaml")
        ));
        assert!(!is_project_document(root, Path::new("/project/other.yaml")));
    }

    #[test]
    fn indexes_the_bundled_http_starter_without_reference_errors() {
        let starter = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../registryctl/assets/project-starters/bounded-http");
        let index = ProjectIndex::load(&starter).unwrap();

        assert!(index.diagnostics().is_empty(), "{:?}", index.diagnostics());
        for (kind, name) in [
            (RelayKind::Registry, "fictional-citizen-registry"),
            (RelayKind::Integration, "person-record"),
            (RelayKind::Service, "person-verification"),
            (RelayKind::Consultation, "person_record"),
            (RelayKind::Fixture, "active-person"),
            (RelayKind::Environment, "local"),
        ] {
            assert!(
                index
                    .symbols()
                    .iter()
                    .any(|symbol| symbol.kind == SymbolKind::Relay(kind) && symbol.name == name),
                "missing {kind:?} {name}"
            );
        }
    }

    #[test]
    fn retired_notary_authoring_fields_are_not_indexed() {
        let temp = TempDir::new().unwrap();
        write(
            temp.path(),
            PROJECT_FILE,
            r#"version: 1
registry: { id: demo }
services:
  retired:
    claims:
      active: { cel: true }
    credential_profiles:
      status: { claims: [active] }
"#,
        );

        let index = ProjectIndex::load(temp.path()).unwrap();
        assert!(
            index
                .symbols()
                .iter()
                .all(|symbol| symbol.name != "active" && symbol.name != "status"),
            "retired Notary authoring fields must not remain in the current editor surface"
        );
    }

    #[test]
    fn maintained_authoring_catalog_workspaces_have_no_reference_diagnostics() {
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let catalog_path = repository_root
            .join("crates/registryctl/tests/fixtures/project-authoring-journeys.yaml");
        let catalog = parse_yaml(&fs::read_to_string(catalog_path).unwrap())
            .unwrap()
            .value;
        let workspaces = catalog
            .get("workspaces")
            .and_then(YamlValue::as_sequence)
            .unwrap();
        let mut maintained = 0;
        for workspace in workspaces {
            if workspace
                .get_scalar("classification")
                .is_none_or(|classification| classification.value != "maintained")
            {
                continue;
            }
            maintained += 1;
            let id = &workspace.get_scalar("id").unwrap().value;
            let source = &workspace.get_scalar("source").unwrap().value;
            let index = ProjectIndex::load(&repository_root.join(source)).unwrap();
            let reference_diagnostics = index
                .diagnostics()
                .iter()
                .filter(|diagnostic| {
                    diagnostic.message.starts_with("Unknown ")
                        || diagnostic.message.starts_with("Ambiguous ")
                })
                .collect::<Vec<_>>();
            assert!(
                reference_diagnostics.is_empty(),
                "{id} has false reference diagnostics: {reference_diagnostics:?}"
            );
        }
        assert_eq!(maintained, 12, "catalog maintenance coverage changed");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_at_every_authored_directory_layer() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        write(
            temp.path(),
            PROJECT_FILE,
            r#"version: 1
registry: { id: demo }
integrations:
  linked-file: { file: integrations/real/integration.yaml }
services:
  check:
    consultations:
      linked: { integration: linked-file }
"#,
        );

        write(outside.path(), "entity.yaml", "id: outside-entity\n");
        write(
            outside.path(),
            "environment.yaml",
            "id: outside-environment\n",
        );
        write(
            outside.path(),
            "integration.yaml",
            "id: outside-integration\n",
        );
        write(outside.path(), "fixture.yaml", "name: outside-fixture\n");

        fs::create_dir_all(temp.path().join("entities")).unwrap();
        symlink(
            outside.path().join("entity.yaml"),
            temp.path().join("entities/linked.yaml"),
        )
        .unwrap();
        fs::create_dir_all(temp.path().join("environments")).unwrap();
        symlink(
            outside.path().join("environment.yaml"),
            temp.path().join("environments/linked.yaml"),
        )
        .unwrap();
        fs::create_dir_all(temp.path().join("integrations/real/fixtures")).unwrap();
        symlink(
            outside.path().join("integration.yaml"),
            temp.path().join("integrations/real/integration.yaml"),
        )
        .unwrap();
        symlink(
            outside.path().join("fixture.yaml"),
            temp.path().join("integrations/real/fixtures/linked.yaml"),
        )
        .unwrap();

        let index = ProjectIndex::load(temp.path()).unwrap();
        for outside_name in [
            "outside-entity",
            "outside-environment",
            "outside-integration",
            "outside-fixture",
        ] {
            assert!(index.workspace_symbols(outside_name).is_empty());
        }
        assert!(index.diagnostics().iter().any(|diagnostic| diagnostic
            .message
            .contains("Declared integration 'linked-file'")));

        let nested_project = TempDir::new().unwrap();
        write(
            nested_project.path(),
            PROJECT_FILE,
            "version: 1\nregistry: { id: nested }\nservices: {}\n",
        );
        symlink(outside.path(), nested_project.path().join("entities")).unwrap();
        symlink(outside.path(), nested_project.path().join("environments")).unwrap();
        symlink(outside.path(), nested_project.path().join("integrations")).unwrap();
        let nested_index = ProjectIndex::load(nested_project.path()).unwrap();
        assert_eq!(nested_index.symbols().len(), 1);

        let integration_directory_project = TempDir::new().unwrap();
        write(
            integration_directory_project.path(),
            PROJECT_FILE,
            "version: 1\nregistry: { id: nested-integration }\nservices: {}\n",
        );
        fs::create_dir(integration_directory_project.path().join("integrations")).unwrap();
        symlink(
            outside.path(),
            integration_directory_project
                .path()
                .join("integrations/linked"),
        )
        .unwrap();
        let nested_index = ProjectIndex::load(integration_directory_project.path()).unwrap();
        assert_eq!(nested_index.symbols().len(), 1);

        let fixture_directory_project = TempDir::new().unwrap();
        write(
            fixture_directory_project.path(),
            PROJECT_FILE,
            "version: 1\nregistry: { id: nested-fixture }\nservices: {}\n",
        );
        write(
            fixture_directory_project.path(),
            "integrations/real/integration.yaml",
            "id: unclaimed\n",
        );
        symlink(
            outside.path(),
            fixture_directory_project
                .path()
                .join("integrations/real/fixtures"),
        )
        .unwrap();
        let nested_index = ProjectIndex::load(fixture_directory_project.path()).unwrap();
        assert!(nested_index.workspace_symbols("outside-fixture").is_empty());
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Product-specific authoring edges over a shared tolerant syntax index.
//! This module does not load runtimes, resolve secrets, or contact services.

mod catalog;
mod catalog_extra;
mod file_candidates;
mod spec;

use crate::{
    refs::{
        document_rule_diagnostic, IndexedLocation, IndexedProject, IndexedReference, IndexedSymbol,
        SymbolKey, SymbolKind, SymbolQuery,
    },
    safety::{is_safe_authored_file, plain_directory, secure_regular_file, SecureFileRead},
    workspace::{
        LoadedProjectDocuments, MAX_INDEXED_PROJECT_BYTES, MAX_INDEXED_PROJECT_DOCUMENTS,
        PROJECT_CEILING_MESSAGE,
    },
    yaml::{parse_yaml, ParsedDocument, YamlScalar, YamlValue},
};
use anyhow::Result;
pub use spec::ProductKind;
use spec::{DocumentRules, FileRule, NameRule, ProductSpec, Scope};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};
use tower_lsp_server::ls_types::{Position, Range};

const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;
const EXPLICIT_MARKER: &str = ".registry-stack-editor/project.json";
const AUTHORING_EXTENSIONS: &[&str] = &["yaml", "yml", "json"];

/// File changes in retained authoring formats refresh their owned project inputs.
pub(crate) fn watched_globs() -> impl Iterator<Item = String> {
    AUTHORING_EXTENSIONS
        .iter()
        .map(|extension| format!("**/*.{extension}"))
}

fn spec(product: ProductKind) -> ProductSpec {
    let specification = catalog::spec(product)
        .or_else(|| catalog_extra::spec(product))
        .expect("every product has an authoring specification");
    debug_assert_eq!(specification.product, product);
    specification
}

fn read_text(root: &Path, path: &Path) -> Option<String> {
    let file = secure_regular_file(root, path).ok()??;
    let SecureFileRead::Bytes(bytes) = file.read_bounded(MAX_DOCUMENT_BYTES).ok()? else {
        return None;
    };
    String::from_utf8(bytes).ok()
}

/// Governed authoring documents are YAML or JSON. A file with any other extension, whether a
/// rule follows it or a pattern scans it, is never read: keys, scripts, and fonts named from a
/// project stay navigation targets.
fn is_authoring_document(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| AUTHORING_EXTENSIONS.contains(&extension))
}

fn safe_relative(value: &str) -> Option<PathBuf> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return None;
    }
    Some(path.to_path_buf())
}

pub(crate) fn entry_path(root: &Path, product: ProductKind) -> Option<PathBuf> {
    if matches!(
        product,
        ProductKind::Manifest | ProductKind::EvidenceOid4vci
    ) {
        if let Some(source) = read_text(root, &root.join(EXPLICIT_MARKER)) {
            let marker: serde_json::Value = serde_json::from_str(&source).ok()?;
            if marker.get("product")?.as_str()? == product.name() {
                let relative = safe_relative(marker.get("document")?.as_str()?)?;
                if !relative
                    .extension()
                    .is_some_and(|value| value == "yaml" || value == "yml")
                {
                    return None;
                }
                let path = root.join(relative);
                return is_safe_authored_file(root, &path).then_some(path);
            }
        }
        if product == ProductKind::EvidenceOid4vci {
            return None;
        }
    }
    Some(root.join(spec(product).marker))
}

pub(crate) fn declares_root(root: &Path, product: ProductKind) -> bool {
    let Some(path) = entry_path(root, product) else {
        return false;
    };
    let Some(source) = read_text(root, &path) else {
        return false;
    };
    if matches!(
        product,
        ProductKind::Manifest | ProductKind::EvidenceOid4vci
    ) && path != root.join(spec(product).marker)
    {
        return true;
    }
    // An explicit marker also declares a default-named entry while it is being edited.
    if matches!(
        product,
        ProductKind::Manifest | ProductKind::EvidenceOid4vci
    ) && read_text(root, &root.join(EXPLICIT_MARKER))
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .is_some_and(|marker| {
            marker.get("product").and_then(serde_json::Value::as_str) == Some(product.name())
        })
    {
        return true;
    }
    let Ok(document) = parse_yaml(&source) else {
        return false;
    };
    let rules = spec(product);
    (!rules.kind.is_empty()
        && document
            .value
            .get_scalar("kind")
            .is_some_and(|kind| kind.value == rules.kind))
        || (!rules.version_prefix.is_empty()
            && document
                .value
                .get_scalar(rules.discriminator)
                .is_some_and(|value| {
                    if product == ProductKind::Manifest || product == ProductKind::Breg {
                        value.value == rules.version_prefix
                    } else {
                        value.value.starts_with(rules.version_prefix)
                    }
                }))
}

fn component_matches(pattern: &str, value: &str) -> bool {
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        value.starts_with(prefix)
            && value.ends_with(suffix)
            && value.len() >= prefix.len() + suffix.len()
    } else {
        pattern == value
    }
}

fn matches_pattern(pattern: &str, path: &str) -> bool {
    fn matches(parts: &[&str], values: &[&str]) -> bool {
        match parts.first() {
            None => values.is_empty(),
            Some(&"**") => {
                matches(&parts[1..], values) || (!values.is_empty() && matches(parts, &values[1..]))
            }
            Some(part) => {
                !values.is_empty()
                    && component_matches(part, values[0])
                    && matches(&parts[1..], &values[1..])
            }
        }
    }
    matches(
        &pattern.split('/').collect::<Vec<_>>(),
        &path.split('/').collect::<Vec<_>>(),
    )
}

fn document_rules(
    root: &Path,
    path: &Path,
    entry: &Path,
    product: ProductKind,
) -> Vec<DocumentRules> {
    let relative = path
        .strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .unwrap_or("");
    spec(product)
        .documents
        .iter()
        .copied()
        .filter(|rules| {
            if rules.pattern == "@document" {
                path == entry
            } else if rules.pattern == "@source-description" {
                path != entry
                    && relative != "runtime.yaml"
                    && relative != "dev-clients.yaml"
                    && !relative.starts_with("fixtures/")
            } else {
                matches_pattern(rules.pattern, relative)
            }
        })
        .collect()
}

pub(crate) fn is_project_document(
    root: &Path,
    path: &Path,
    product: ProductKind,
    documents: &BTreeMap<PathBuf, String>,
) -> bool {
    let Some(entry) = entry_path(root, product) else {
        return false;
    };
    is_authoring_document(path)
        && is_safe_authored_file(root, path)
        && (documents.contains_key(path)
            || document_rules(root, path, &entry, product)
                .iter()
                .any(|rules| rules.pattern != "@source-description"))
}

struct Match<'a> {
    scalar: &'a YamlScalar,
    parents: Vec<&'a YamlValue>,
}

fn at_path<'a>(value: &'a YamlValue, path: &str) -> Vec<Match<'a>> {
    fn walk<'a>(
        value: &'a YamlValue,
        parts: &[&str],
        parents: &mut Vec<&'a YamlValue>,
        output: &mut Vec<Match<'a>>,
    ) {
        if parts.is_empty() {
            if let Some(scalar) = value.as_scalar() {
                output.push(Match {
                    scalar,
                    parents: parents.iter().rev().copied().collect(),
                });
            }
            return;
        }
        parents.push(value);
        match parts[0] {
            "$key" if parts.len() == 1 => {
                if let Some(mapping) = value.as_mapping() {
                    for pair in mapping {
                        output.push(Match {
                            scalar: &pair.key,
                            parents: parents.iter().rev().copied().collect(),
                        });
                    }
                }
            }
            "*" => match value {
                YamlValue::Sequence(items) => {
                    for item in items {
                        walk(item, &parts[1..], parents, output);
                    }
                }
                YamlValue::Mapping(items) => {
                    for item in items {
                        walk(&item.value, &parts[1..], parents, output);
                    }
                }
                _ => {}
            },
            key => {
                if let Some(child) = value.get(key) {
                    walk(child, &parts[1..], parents, output);
                }
            }
        }
        parents.pop();
    }
    let mut output = Vec::new();
    walk(
        value,
        &path.split('/').collect::<Vec<_>>(),
        &mut Vec::new(),
        &mut output,
    );
    output
}

fn ancestor_field(found: &Match<'_>, skip: usize, field: &str) -> Option<String> {
    found.parents.iter().skip(skip).find_map(|parent| {
        let mut value = *parent;
        for key in field.split('.') {
            value = value.get(key)?;
        }
        value.as_scalar().map(|value| value.value.clone())
    })
}

fn scope(found: &Match<'_>, rule: Scope, path: &Path) -> Option<Option<String>> {
    match rule {
        Scope::Global => Some(None),
        Scope::Document => Some(Some(path.to_string_lossy().into_owned())),
        Scope::Ancestor { skip, field } => Some(Some(ancestor_field(found, skip, field)?)),
        Scope::Composite(fields) => {
            let values = fields
                .iter()
                .map(|(skip, field)| ancestor_field(found, *skip, field))
                .collect::<Option<Vec<_>>>()?;
            Some(Some(serde_json::to_string(&values).ok()?))
        }
    }
}

fn name(found: &Match<'_>, rule: NameRule) -> Option<String> {
    if rule.only_when.is_some_and(|(field, expected)| {
        !found.parents.first().is_some_and(|parent| {
            parent
                .get_scalar(field)
                .is_some_and(|value| value.value == expected)
        })
    }) {
        return None;
    }
    if rule.ignored_when_present.is_some_and(|field| {
        found
            .parents
            .first()
            .is_some_and(|parent| parent.get(field).is_some())
    }) {
        return None;
    }
    let mut name = found.scalar.value.clone();
    if let Some(suffix) = rule.suffix {
        name.push('/');
        name.push_str(&ancestor_field(found, 0, suffix)?);
    }
    Some(name)
}

fn file_target(root: &Path, path: &Path, found: &Match<'_>, rule: FileRule) -> Option<PathBuf> {
    fn expand(template: &str, found: &Match<'_>) -> Option<String> {
        let mut output = String::new();
        let mut rest = template;
        while let Some(start) = rest.find('{') {
            output.push_str(&rest[..start]);
            let end = rest[start..].find('}')? + start;
            output.push_str(&ancestor_field(found, 0, &rest[start + 1..end])?);
            rest = &rest[end + 1..];
        }
        output.push_str(rest);
        Some(output)
    }
    let value = format!(
        "{}{}{}",
        expand(rule.prefix, found)?,
        found.scalar.value,
        expand(rule.suffix, found)?
    );
    let target = if rule.relative_to_document {
        if value.is_empty() || value.contains('\\') || Path::new(&value).is_absolute() {
            return None;
        }
        let mut target = path.parent()?.to_path_buf();
        for component in Path::new(&value).components() {
            match component {
                Component::Normal(segment) => target.push(segment),
                Component::CurDir => {}
                Component::ParentDir => {
                    if target == root || !target.pop() {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        target
    } else {
        root.join(safe_relative(&value)?)
    };
    target.starts_with(root).then_some(target)
}

fn scan_pattern(
    root: &Path,
    pattern: &str,
    output: &mut BTreeSet<PathBuf>,
    visited: &mut usize,
) -> Result<()> {
    fn scan(
        dir: &Path,
        parts: &[&str],
        output: &mut BTreeSet<PathBuf>,
        visited: &mut usize,
    ) -> Result<()> {
        if *visited > MAX_INDEXED_PROJECT_DOCUMENTS || parts.is_empty() {
            return Ok(());
        }
        if !plain_directory(dir) {
            return Ok(());
        }
        if parts[0] == "**" {
            scan(dir, &parts[1..], output, visited)?;
        }
        if !parts[0].contains('*') {
            let path = dir.join(parts[0]);
            if parts.len() == 1 {
                output.insert(path);
            } else {
                scan(&path, &parts[1..], output, visited)?;
            }
        } else {
            let mut entries = fs::read_dir(dir)?
                .take(MAX_INDEXED_PROJECT_DOCUMENTS.saturating_sub(*visited) + 1)
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .collect::<Vec<_>>();
            entries.sort();
            for path in entries {
                *visited += 1;
                if *visited > MAX_INDEXED_PROJECT_DOCUMENTS {
                    break;
                }
                if parts[0] == "**" {
                    scan(&path, parts, output, visited)?;
                } else if component_matches(
                    parts[0],
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or(""),
                ) {
                    if parts.len() == 1 {
                        output.insert(path);
                    } else {
                        scan(&path, &parts[1..], output, visited)?;
                    }
                }
            }
        }
        Ok(())
    }
    scan(
        root,
        &pattern.split('/').collect::<Vec<_>>(),
        output,
        visited,
    )
}

pub(crate) fn load_documents(
    root: &Path,
    product: ProductKind,
    overrides: &BTreeMap<PathBuf, String>,
) -> Result<LoadedProjectDocuments> {
    let mut loaded = LoadedProjectDocuments {
        documents: BTreeMap::new(),
        diagnostics: Vec::new(),
        indexing_ceiling_path: None,
    };
    let Some(entry) = entry_path(root, product) else {
        return Ok(loaded);
    };
    let mut pending = BTreeSet::from([entry.clone()]);
    let mut visited = 0;
    let patterns = spec(product)
        .documents
        .iter()
        .map(|rules| rules.pattern)
        .filter(|pattern| !pattern.starts_with('@'))
        .collect::<BTreeSet<_>>();
    for pattern in patterns {
        scan_pattern(root, pattern, &mut pending, &mut visited)?;
    }
    let mut seen = BTreeSet::new();
    let mut bytes = 0usize;
    while let Some(path) = pending.pop_first() {
        if !is_authoring_document(&path) || !seen.insert(path.clone()) {
            continue;
        }
        if seen.len() > MAX_INDEXED_PROJECT_DOCUMENTS
            || visited > MAX_INDEXED_PROJECT_DOCUMENTS
            || bytes > MAX_INDEXED_PROJECT_BYTES
        {
            loaded.indexing_ceiling_path = Some(path.clone());
            loaded.documents.clear();
            loaded.diagnostics.push(document_rule_diagnostic(
                &path,
                Some(format!("{}/project-ceiling", product.name())),
                PROJECT_CEILING_MESSAGE,
            ));
            break;
        }
        let Some(file) = secure_regular_file(root, &path)? else {
            continue;
        };
        let source = if let Some(source) = overrides.get(&path) {
            source.clone()
        } else {
            match file.read_bounded(MAX_DOCUMENT_BYTES)? {
                SecureFileRead::Bytes(bytes) => match String::from_utf8(bytes) {
                    Ok(source) => source,
                    Err(_) => continue,
                },
                SecureFileRead::TooLarge => {
                    loaded.diagnostics.push(document_rule_diagnostic(
                        &path,
                        Some(format!("{}/document-ceiling", product.name())),
                        "Authoring document exceeds the 1 MiB editor indexing limit",
                    ));
                    continue;
                }
            }
        };
        bytes = bytes.saturating_add(source.len());
        if let Ok(document) = parse_yaml(&source) {
            for rules in document_rules(root, &path, &entry, product) {
                for rule in rules.files.iter().filter(|rule| rule.index_target) {
                    for found in at_path(&document.value, rule.path) {
                        if let Some(target) = file_target(root, &path, &found, *rule) {
                            pending.insert(target);
                        }
                    }
                }
            }
        }
        loaded.documents.insert(path, source);
    }
    if loaded.indexing_ceiling_path.is_none() && bytes > MAX_INDEXED_PROJECT_BYTES {
        loaded.indexing_ceiling_path = Some(entry.clone());
        loaded.documents.clear();
        loaded.diagnostics.push(document_rule_diagnostic(
            &entry,
            Some(format!("{}/project-ceiling", product.name())),
            PROJECT_CEILING_MESSAGE,
        ));
    }
    Ok(loaded)
}

pub(crate) fn build_index(
    root: &Path,
    product: ProductKind,
    parsed: &BTreeMap<PathBuf, ParsedDocument>,
) -> IndexedProject {
    let mut output = IndexedProject::default();
    let Some(entry) = entry_path(root, product) else {
        return output;
    };
    if product == ProductKind::Breg {
        if let Some(document) = parsed.get(&entry) {
            for (name, field) in [
                ("registry-recipients", "recipients"),
                ("registry-consent-scopes", "accessProfiles"),
            ] {
                if let Some(pair) = document
                    .value
                    .as_mapping()
                    .and_then(|pairs| pairs.iter().find(|pair| pair.key.value == field))
                {
                    let kind = SymbolKind::Product(product, "BReg vocabulary");
                    output.symbols.push(IndexedSymbol {
                        name: name.to_owned(),
                        kind,
                        container_name: None,
                        key: SymbolKey::global(kind, name),
                        resolvable: true,
                        location: IndexedLocation {
                            path: entry.clone(),
                            range: pair.key.range,
                        },
                    });
                }
            }
        }
    }

    for (path, document) in parsed {
        if product == ProductKind::Messaging
            && path
                .strip_prefix(root)
                .ok()
                .and_then(Path::to_str)
                .is_some_and(|relative| matches_pattern("templates/*/*/template.yaml", relative))
        {
            messaging_template_files(root, path, &document.value, &mut output);
        }
        if product == ProductKind::Breg {
            for entity in at_path(&document.value, "entities/*/id") {
                let kind = SymbolKind::Product(product, "BReg field");
                if !at_path(&document.value, "entities/*/fields/*/id")
                    .iter()
                    .any(|field| {
                        field.scalar.value == "id"
                            && ancestor_field(field, 1, "id").as_deref()
                                == Some(entity.scalar.value.as_str())
                    })
                {
                    output.symbols.push(IndexedSymbol {
                        name: "id".to_owned(),
                        kind,
                        container_name: Some(entity.scalar.value.clone()),
                        key: SymbolKey::scoped(kind, &entity.scalar.value, "id"),
                        resolvable: true,
                        location: IndexedLocation {
                            path: path.clone(),
                            range: entity.scalar.range,
                        },
                    });
                }
            }
        }
        for rules in document_rules(root, path, &entry, product) {
            for rule in rules.declarations {
                for found in at_path(&document.value, rule.path) {
                    let (Some(name), Some(scope)) =
                        (name(&found, *rule), scope(&found, rule.scope, path))
                    else {
                        continue;
                    };
                    let kind = SymbolKind::Product(product, rule.kind);
                    let key = SymbolKey {
                        kind,
                        scope: scope.clone(),
                        name: name.clone(),
                    };
                    if kind != SymbolKind::Product(ProductKind::Messaging, "Messaging template")
                        || !output.symbols.iter().any(|symbol| symbol.key == key)
                    {
                        output.symbols.push(IndexedSymbol {
                            name,
                            kind,
                            container_name: scope,
                            key,
                            resolvable: true,
                            location: IndexedLocation {
                                path: path.clone(),
                                range: found.scalar.range,
                            },
                        });
                    }
                }
            }
            for rule in rules.references {
                for found in at_path(&document.value, rule.path) {
                    let (Some(name), Some(scope)) =
                        (name(&found, *rule), scope(&found, rule.scope, path))
                    else {
                        continue;
                    };
                    output.references.push(IndexedReference {
                        target: SymbolQuery {
                            kind: SymbolKind::Product(product, rule.kind),
                            scope,
                            name,
                        },
                        location: IndexedLocation {
                            path: path.clone(),
                            range: found.scalar.range,
                        },
                        reports_unresolved: rule.reports_unresolved,
                        style: found.scalar.style,
                        offers: None,
                    });
                }
            }
            for rule in rules.files {
                for found in at_path(&document.value, rule.path) {
                    let Some(target) = file_target(root, path, &found, *rule) else {
                        continue;
                    };
                    let kind = SymbolKind::Product(product, "authored file");
                    let scope = Some(
                        serde_json::to_string(&(
                            if rule.relative_to_document {
                                path.parent().unwrap_or(root)
                            } else {
                                root
                            },
                            rule.prefix,
                            rule.suffix,
                            target.parent(),
                            target.extension(),
                        ))
                        .unwrap_or_default(),
                    );
                    for candidate in file_candidates::sibling_candidates(
                        root,
                        &target,
                        &found.scalar.value,
                        *rule,
                    ) {
                        let key = SymbolKey {
                            kind,
                            scope: scope.clone(),
                            name: candidate.name.clone(),
                        };
                        if !output.symbols.iter().any(|symbol| symbol.key == key) {
                            output.symbols.push(IndexedSymbol {
                                name: candidate.name,
                                kind,
                                container_name: scope.clone(),
                                key,
                                resolvable: true,
                                location: IndexedLocation {
                                    path: candidate.path,
                                    range: Range::new(Position::new(0, 0), Position::new(0, 0)),
                                },
                            });
                        }
                    }
                    let key = SymbolKey {
                        kind,
                        scope: scope.clone(),
                        name: found.scalar.value.clone(),
                    };
                    if is_safe_authored_file(root, &target)
                        && !output.symbols.iter().any(|symbol| symbol.key == key)
                    {
                        output.symbols.push(IndexedSymbol {
                            name: found.scalar.value.clone(),
                            kind,
                            container_name: scope.clone(),
                            key,
                            resolvable: true,
                            location: IndexedLocation {
                                path: target,
                                range: Range::new(Position::new(0, 0), Position::new(0, 0)),
                            },
                        });
                    }
                    output.references.push(IndexedReference {
                        target: SymbolQuery {
                            kind,
                            scope,
                            name: found.scalar.value.clone(),
                        },
                        location: IndexedLocation {
                            path: path.clone(),
                            range: found.scalar.range,
                        },
                        reports_unresolved: product != ProductKind::Casework,
                        style: found.scalar.style,
                        offers: None,
                    });
                }
            }
        }
    }
    output
}

/// TemplateDocument names locales and parts; the product fixes the schema/sample basenames.
/// Body bytes belong to Jinja tooling and are never interpreted by this YAML server.
fn messaging_template_files(
    root: &Path,
    path: &Path,
    document: &YamlValue,
    output: &mut IndexedProject,
) {
    let Some(directory) = path.parent() else {
        return;
    };
    let locales = at_path(document, "locales/*");
    let parts = at_path(document, "parts/*");
    for locale in &locales {
        for part in &parts {
            let Some(relative) =
                safe_relative(&format!("{}/{}.j2", locale.scalar.value, part.scalar.value))
            else {
                continue;
            };
            let target = directory.join(relative);
            for (scalar, kind, scope) in [
                (
                    locale.scalar,
                    "Messaging locale files",
                    format!("{}:{}", path.display(), part.scalar.value),
                ),
                (
                    part.scalar,
                    "Messaging template part",
                    format!("{}:{}", path.display(), locale.scalar.value),
                ),
            ] {
                let kind = SymbolKind::Product(ProductKind::Messaging, kind);
                let key = SymbolKey::scoped(kind, &scope, &scalar.value);
                if is_safe_authored_file(root, &target) {
                    output.symbols.push(IndexedSymbol {
                        name: scalar.value.clone(),
                        kind,
                        container_name: Some(scope.clone()),
                        key,
                        resolvable: true,
                        location: IndexedLocation {
                            path: target.clone(),
                            range: Range::new(Position::new(0, 0), Position::new(0, 0)),
                        },
                    });
                }
                output.references.push(IndexedReference {
                    target: SymbolQuery::scoped(kind, scope, &scalar.value),
                    location: IndexedLocation {
                        path: path.to_path_buf(),
                        range: scalar.range,
                    },
                    reports_unresolved: true,
                    style: scalar.style,
                    offers: None,
                });
            }
        }
    }
    for basename in ["schema.json", "sample.json"] {
        let target = directory.join(basename);
        if is_safe_authored_file(root, &target) {
            let kind = SymbolKind::Product(ProductKind::Messaging, "authored file");
            output.symbols.push(IndexedSymbol {
                name: basename.to_owned(),
                kind,
                container_name: Some(directory.to_string_lossy().into_owned()),
                key: SymbolKey::scoped(kind, directory.to_string_lossy(), basename),
                resolvable: true,
                location: IndexedLocation {
                    path: target,
                    range: Range::new(Position::new(0, 0), Position::new(0, 0)),
                },
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn watchers_cover_retained_yaml_yml_and_json_authoring() {
        let globs = watched_globs().collect::<Vec<_>>();
        for path in [
            "casework.yaml",
            "mappings/other.yml",
            "imports/source-description.json",
            ".registry-stack-editor/project.json",
        ] {
            assert!(is_authoring_document(Path::new(path)));
            assert!(
                globs.iter().any(|glob| matches_pattern(glob, path)),
                "{path}"
            );
        }
        assert!(!globs
            .iter()
            .any(|glob| matches_pattern(glob, "signing.key")));
    }

    fn project(files: &[(&str, &str)]) -> TempDir {
        let directory = TempDir::new().unwrap();
        for (relative, contents) in files {
            let path = directory.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        directory
    }

    fn loaded(directory: &TempDir, product: ProductKind) -> BTreeSet<String> {
        let root = directory.path().canonicalize().unwrap();
        load_documents(&root, product, &BTreeMap::new())
            .unwrap()
            .documents
            .into_keys()
            .map(|path| {
                path.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    #[test]
    fn casework_follows_only_authoring_source_descriptions() {
        for (description, followed) in [
            ("keys/signing.key", false),
            ("keys/signing.pem", false),
            ("imports/source-description", false),
            ("imports/source-description.yaml", true),
            ("imports/source-description.yml", true),
            ("imports/source-description.json", true),
        ] {
            let directory = project(&[
                (
                    "casework.yaml",
                    &format!(
                        "kind: CaseworkProject\n\
                         sources: [{{id: regional, description: {description}}}]\n"
                    ),
                ),
                (description, "sourceId: regional\n"),
            ]);
            assert_eq!(
                loaded(&directory, ProductKind::Casework).contains(description),
                followed,
                "{description}"
            );
        }
    }

    #[test]
    fn discovery_reads_only_authoring_mappings() {
        let directory = project(&[
            (
                "origins.yaml",
                "schemaVersion: registry-discovery/origins/v1alpha1\n",
            ),
            ("mappings/adult.yaml", "mappingId: adult\n"),
            ("mappings/other.yml", "mappingId: other\n"),
            ("mappings/signing.key", "mappingId: key\n"),
            ("mappings/README", "mappingId: readme\n"),
        ]);
        assert_eq!(
            loaded(&directory, ProductKind::Discovery),
            BTreeSet::from([
                "origins.yaml".to_owned(),
                "mappings/adult.yaml".to_owned(),
                "mappings/other.yml".to_owned(),
            ])
        );
    }
}

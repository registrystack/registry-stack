// SPDX-License-Identifier: Apache-2.0
//! Isolated reader and source-preserving rewrite for the retired singular project dialect.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_norway::Value;

use registry_breg::contract::ModuleLockSource;
use registry_breg::{parse_project_yaml, Diagnostic, DiagnosticSeverity};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyProject {
    registry: LegacyRegistry,
    manifest_projection: LegacyManifestProjection,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyRegistry {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyManifestProjection {
    catalog: LegacyCatalog,
    dataset: Value,
    #[serde(default)]
    data_service: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyCatalog {
    base_url: String,
}

pub(crate) struct MigratedProject {
    pub bytes: Vec<u8>,
    pub dataset_id: String,
    pub authority_id: String,
    pub public_service_id: String,
}

#[derive(Clone, Copy)]
struct Block {
    start: usize,
    end: usize,
    indent: usize,
}

pub(crate) fn migrate_registry_yaml(bytes: &[u8]) -> Result<MigratedProject, Diagnostic> {
    let legacy: LegacyProject = serde_norway::from_slice(bytes).map_err(|_| invalid_legacy())?;
    let source = source_lines(bytes)?;
    let dataset_id = legacy
        .manifest_projection
        .dataset
        .as_mapping()
        .and_then(|dataset| dataset.get(Value::String("id".to_owned())))
        .and_then(Value::as_str)
        .unwrap_or(&legacy.registry.id)
        .to_owned();
    let authority_id = format!("{}-authority", legacy.registry.id);
    let public_service_id = format!("{}-service", legacy.registry.id);

    // Parsing above proves the legacy semantics. The edits below deliberately support only the
    // ordinary block-style YAML dialect emitted by Base Registry Engine examples. Ambiguous flow-style
    // or partially migrated input fails closed instead of being normalized or reformatted.
    let mut lines = source.lines;
    insert_registry_identity(&mut lines, &legacy.manifest_projection.catalog.base_url)?;
    insert_publisher_id(&mut lines, &authority_id)?;
    replace_dataset(&mut lines, &dataset_id)?;
    replace_data_service(&mut lines, &legacy, &dataset_id)?;
    insert_public_service_and_distributions(&mut lines, &public_service_id)?;
    add_entity_membership_lines(&mut lines, &dataset_id)?;

    let rendered = render_lines(lines, source.trailing_newline);
    parse_project_yaml(rendered.as_bytes()).map_err(|failure| {
        failure
            .diagnostics()
            .first()
            .cloned()
            .unwrap_or_else(invalid_legacy)
    })?;
    Ok(MigratedProject {
        bytes: rendered.into_bytes(),
        dataset_id,
        authority_id,
        public_service_id,
    })
}

pub(crate) fn add_module_entity_membership(
    bytes: &[u8],
    dataset_id: &str,
) -> Result<Option<Vec<u8>>, Diagnostic> {
    let source = source_lines(bytes)?;
    let mut lines = source.lines;
    if !add_entity_membership_lines(&mut lines, dataset_id)? {
        return Ok(None);
    }
    Ok(Some(
        render_lines(lines, source.trailing_newline).into_bytes(),
    ))
}

pub(crate) fn update_module_locks(
    bytes: &[u8],
    locks: &[ModuleLockSource],
) -> Result<Vec<u8>, Diagnostic> {
    let project = parse_project_yaml(bytes).map_err(|failure| {
        failure
            .diagnostics()
            .first()
            .cloned()
            .unwrap_or_else(invalid_legacy)
    })?;
    if project.modules.len() != locks.len() {
        return Err(unsafe_source(
            "module locks must already contain exactly the discovered module ids",
        ));
    }
    let source = source_lines(bytes)?;
    let mut lines = source.lines;
    let modules = required_mapping(&lines, 0, lines.len(), "modules")?;
    let item_indent = modules.indent + 2;
    let item_starts = (modules.start + 1..modules.end)
        .filter(|index| {
            indentation(&lines[*index]) == item_indent
                && lines[*index][item_indent..].starts_with("- id:")
        })
        .collect::<Vec<_>>();
    if item_starts.len() != project.modules.len() {
        return Err(unsafe_source(
            "module locks must use block list items beginning with `- id:`",
        ));
    }

    let mut replacements = Vec::new();
    for (index, authored) in project.modules.iter().enumerate() {
        let expected = locks
            .iter()
            .find(|lock| lock.id == authored.id)
            .ok_or_else(|| unsafe_source("the discovered module ids do not match the lock file"))?;
        let item_end = item_starts.get(index + 1).copied().unwrap_or(modules.end);
        let item = Block {
            start: item_starts[index],
            end: item_end,
            indent: item_indent,
        };
        let version_line = required_key(&lines, item, "version")?;
        if authored.version != expected.version {
            replacements.push((
                version_line,
                format!(
                    "{}version: {}",
                    " ".repeat(item_indent + 2),
                    yaml_scalar(&expected.version)
                ),
            ));
        }
        match (
            optional_key(&lines, item, "digest")?,
            expected.digest.as_ref(),
        ) {
            (Some(digest_line), Some(digest)) if authored.digest.as_ref() != Some(digest) => {
                replacements.push((
                    digest_line,
                    format!(
                        "{}digest: {}",
                        " ".repeat(item_indent + 2),
                        yaml_scalar(digest)
                    ),
                ));
            }
            (None, Some(digest)) => replacements.push((
                item.end,
                format!(
                    "{}digest: {}",
                    " ".repeat(item_indent + 2),
                    yaml_scalar(digest)
                ),
            )),
            _ => {}
        }
    }
    replacements.sort_by_key(|(index, _)| *index);
    for (index, replacement) in replacements.into_iter().rev() {
        if index < lines.len() && line_value(&lines[index], item_indent + 2, "digest").is_some()
            || index < lines.len()
                && line_value(&lines[index], item_indent + 2, "version").is_some()
        {
            lines[index] = replacement;
        } else {
            lines.insert(index, replacement);
        }
    }
    let rendered = render_lines(lines, source.trailing_newline);
    parse_project_yaml(rendered.as_bytes()).map_err(|failure| {
        failure
            .diagnostics()
            .first()
            .cloned()
            .unwrap_or_else(invalid_legacy)
    })?;
    Ok(rendered.into_bytes())
}

fn insert_registry_identity(
    lines: &mut Vec<String>,
    canonical_base_iri: &str,
) -> Result<(), Diagnostic> {
    let registry = required_mapping(lines, 0, lines.len(), "registry")?;
    reject_key(lines, registry, "canonicalBaseIri")?;
    let id = required_key(lines, registry, "id")?;
    lines.insert(
        id + 1,
        format!("  canonicalBaseIri: {}", yaml_scalar(canonical_base_iri)),
    );
    Ok(())
}

fn insert_publisher_id(lines: &mut Vec<String>, authority_id: &str) -> Result<(), Diagnostic> {
    let projection = required_mapping(lines, 0, lines.len(), "manifestProjection")?;
    let catalog = required_mapping(lines, projection.start + 1, projection.end, "catalog")?;
    let publisher = required_mapping(lines, catalog.start + 1, catalog.end, "publisher")?;
    reject_key(lines, publisher, "id")?;
    lines.insert(
        publisher.start + 1,
        format!(
            "{}id: {}",
            " ".repeat(publisher.indent + 2),
            yaml_scalar(authority_id)
        ),
    );
    Ok(())
}

fn replace_dataset(lines: &mut Vec<String>, dataset_id: &str) -> Result<(), Diagnostic> {
    let projection = required_mapping(lines, 0, lines.len(), "manifestProjection")?;
    for key in ["datasets", "publicService", "dataServices", "distributions"] {
        reject_key(lines, projection, key)?;
    }
    let dataset = required_mapping(lines, projection.start + 1, projection.end, "dataset")?;
    let explicit_id = optional_key(lines, dataset, "id")?.is_some();
    let mut replacement = vec![format!("{}datasets:", " ".repeat(dataset.indent))];
    replacement.push(format!("{}-", " ".repeat(dataset.indent + 2)));
    if !explicit_id {
        replacement.push(format!(
            "{}id: {}",
            " ".repeat(dataset.indent + 4),
            yaml_scalar(dataset_id)
        ));
    }
    replacement.extend(
        lines[dataset.start + 1..dataset.end]
            .iter()
            .map(|line| indent_line(line, 2)),
    );
    lines.splice(dataset.start..dataset.end, replacement);
    Ok(())
}

fn replace_data_service(
    lines: &mut Vec<String>,
    legacy: &LegacyProject,
    dataset_id: &str,
) -> Result<(), Diagnostic> {
    let projection = required_mapping(lines, 0, lines.len(), "manifestProjection")?;
    let title = copied_catalog_title(lines, projection)?;
    if legacy.manifest_projection.data_service.is_some() {
        let service = required_mapping(lines, projection.start + 1, projection.end, "dataService")?;
        reject_key(lines, service, "servesDatasets")?;
        let mut replacement = vec![format!("{}dataServices:", " ".repeat(service.indent))];
        replacement.push(format!("{}-", " ".repeat(service.indent + 2)));
        replacement.extend(
            lines[service.start + 1..service.end]
                .iter()
                .map(|line| indent_line(line, 2)),
        );
        replacement.push(format!("{}servesDatasets:", " ".repeat(service.indent + 4)));
        replacement.push(format!(
            "{}- {}",
            " ".repeat(service.indent + 6),
            yaml_scalar(dataset_id)
        ));
        lines.splice(service.start..service.end, replacement);
        return Ok(());
    }

    reject_key(lines, projection, "dataService")?;
    let insertion = projection.end;
    let indent = projection.indent + 2;
    let mut replacement = vec![
        format!("{}dataServices:", " ".repeat(indent)),
        format!("{}-", " ".repeat(indent + 2)),
        format!(
            "{}id: {}",
            " ".repeat(indent + 4),
            yaml_scalar(&format!("{}-data-service", legacy.registry.id))
        ),
    ];
    replacement.extend(shift_key_block(&title, indent + 4, "title"));
    replacement.extend([
        format!(
            "{}endpointUrl: {}",
            " ".repeat(indent + 4),
            yaml_scalar(&legacy.manifest_projection.catalog.base_url)
        ),
        format!("{}servesDatasets:", " ".repeat(indent + 4)),
        format!("{}- {}", " ".repeat(indent + 6), yaml_scalar(dataset_id)),
    ]);
    lines.splice(insertion..insertion, replacement);
    Ok(())
}

fn insert_public_service_and_distributions(
    lines: &mut Vec<String>,
    public_service_id: &str,
) -> Result<(), Diagnostic> {
    let projection = required_mapping(lines, 0, lines.len(), "manifestProjection")?;
    let title = copied_catalog_title(lines, projection)?;
    let indent = projection.indent + 2;
    let mut addition = vec![
        format!("{}publicService:", " ".repeat(indent)),
        format!(
            "{}id: {}",
            " ".repeat(indent + 2),
            yaml_scalar(public_service_id)
        ),
    ];
    addition.extend(shift_key_block(&title, indent + 2, "title"));
    addition.push(format!("{}distributions: []", " ".repeat(indent)));
    lines.splice(projection.end..projection.end, addition);
    Ok(())
}

fn copied_catalog_title(lines: &[String], projection: Block) -> Result<Vec<String>, Diagnostic> {
    let catalog = required_mapping(lines, projection.start + 1, projection.end, "catalog")?;
    let start = required_key(lines, catalog, "title")?;
    let end = key_value_end(lines, start, catalog.end);
    Ok(lines[start..end].to_vec())
}

fn shift_key_block(lines: &[String], target_indent: usize, target_key: &str) -> Vec<String> {
    let source_indent = indentation(&lines[0]);
    lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let shifted = if line.trim().is_empty() {
                line.clone()
            } else {
                format!("{}{}", " ".repeat(target_indent), &line[source_indent..])
            };
            if index == 0 {
                replace_key_name(&shifted, target_indent, target_key)
            } else {
                shifted
            }
        })
        .collect()
}

fn replace_key_name(line: &str, indent: usize, key: &str) -> String {
    let value = line[indent..]
        .split_once(':')
        .map(|(_, value)| value)
        .unwrap_or("");
    format!("{}{key}:{value}", " ".repeat(indent))
}

fn add_entity_membership_lines(
    lines: &mut Vec<String>,
    dataset_id: &str,
) -> Result<bool, Diagnostic> {
    let Some(entities) = optional_mapping(lines, 0, lines.len(), "entities")? else {
        return Ok(false);
    };
    let item_indent = entities.indent + 2;
    let mut insertions = Vec::new();
    for index in entities.start + 1..entities.end {
        let line = &lines[index];
        if indentation(line) != item_indent || !line[item_indent..].starts_with("- ") {
            continue;
        }
        if !line[item_indent + 2..].starts_with("id:") {
            return Err(unsafe_source("each entity must use block form `- id: ...`"));
        }
        let end = (index + 1..entities.end)
            .find(|candidate| {
                indentation(&lines[*candidate]) == item_indent
                    && lines[*candidate][item_indent..].starts_with("- ")
            })
            .unwrap_or(entities.end);
        if find_key(lines, index + 1, end, item_indent + 2, "primaryDataset")?.is_none() {
            insertions.push(index + 1);
        }
    }
    for index in insertions.iter().rev() {
        lines.insert(
            *index,
            format!(
                "{}primaryDataset: {}",
                " ".repeat(item_indent + 2),
                yaml_scalar(dataset_id)
            ),
        );
    }
    Ok(!insertions.is_empty())
}

pub(crate) fn review_diff(files: &BTreeMap<String, (Vec<u8>, Vec<u8>)>) -> String {
    let mut diff = String::new();
    for (path, (before, after)) in files {
        diff.push_str(&format!("--- a/{path}\n+++ b/{path}\n"));
        diff.push_str(&unified_hunks(
            &String::from_utf8_lossy(before).lines().collect::<Vec<_>>(),
            &String::from_utf8_lossy(after).lines().collect::<Vec<_>>(),
        ));
    }
    diff
}

#[derive(Clone, Copy)]
enum DiffLine<'a> {
    Equal(&'a str),
    Remove(&'a str),
    Add(&'a str),
}

fn unified_hunks(before: &[&str], after: &[&str]) -> String {
    let operations = align_lines(before, after);
    let changed = operations
        .iter()
        .enumerate()
        .filter_map(|(index, operation)| {
            (!matches!(operation, DiffLine::Equal(_))).then_some(index)
        })
        .collect::<Vec<_>>();
    if changed.is_empty() {
        return String::new();
    }
    let mut positions = Vec::with_capacity(operations.len() + 1);
    let (mut old_line, mut new_line) = (1usize, 1usize);
    for operation in &operations {
        positions.push((old_line, new_line));
        match operation {
            DiffLine::Equal(_) => {
                old_line += 1;
                new_line += 1;
            }
            DiffLine::Remove(_) => old_line += 1,
            DiffLine::Add(_) => new_line += 1,
        }
    }
    positions.push((old_line, new_line));

    let mut ranges = Vec::new();
    for index in changed {
        let start = index.saturating_sub(3);
        let end = (index + 4).min(operations.len());
        match ranges.last_mut() {
            Some((_, previous_end)) if start <= *previous_end => *previous_end = end,
            _ => ranges.push((start, end)),
        }
    }
    let mut output = String::new();
    for (start, end) in ranges {
        let old_count = operations[start..end]
            .iter()
            .filter(|line| !matches!(line, DiffLine::Add(_)))
            .count();
        let new_count = operations[start..end]
            .iter()
            .filter(|line| !matches!(line, DiffLine::Remove(_)))
            .count();
        let (old_start, new_start) = positions[start];
        output.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            old_start, old_count, new_start, new_count
        ));
        for operation in &operations[start..end] {
            match operation {
                DiffLine::Equal(line) => output.push_str(&format!(" {line}\n")),
                DiffLine::Remove(line) => output.push_str(&format!("-{line}\n")),
                DiffLine::Add(line) => output.push_str(&format!("+{line}\n")),
            }
        }
    }
    output
}

fn align_lines<'a>(before: &'a [&'a str], after: &'a [&'a str]) -> Vec<DiffLine<'a>> {
    const LOOKAHEAD: usize = 512;
    let (mut old, mut new) = (0usize, 0usize);
    let mut operations = Vec::new();
    while old < before.len() && new < after.len() {
        if before[old] == after[new] {
            operations.push(DiffLine::Equal(before[old]));
            old += 1;
            new += 1;
            continue;
        }
        let mut match_at = None;
        for distance in 1..=LOOKAHEAD {
            for old_delta in 0..=distance {
                let new_delta = distance - old_delta;
                if old + old_delta < before.len()
                    && new + new_delta < after.len()
                    && before[old + old_delta] == after[new + new_delta]
                {
                    match_at = Some((old_delta, new_delta));
                    break;
                }
            }
            if match_at.is_some() {
                break;
            }
        }
        let Some((old_delta, new_delta)) = match_at else {
            break;
        };
        for line in &before[old..old + old_delta] {
            operations.push(DiffLine::Remove(line));
        }
        for line in &after[new..new + new_delta] {
            operations.push(DiffLine::Add(line));
        }
        old += old_delta;
        new += new_delta;
    }
    operations.extend(before[old..].iter().map(|line| DiffLine::Remove(line)));
    operations.extend(after[new..].iter().map(|line| DiffLine::Add(line)));
    operations
}

struct SourceLines {
    lines: Vec<String>,
    trailing_newline: bool,
}

fn source_lines(bytes: &[u8]) -> Result<SourceLines, Diagnostic> {
    let source = std::str::from_utf8(bytes).map_err(|_| invalid_legacy())?;
    if source.contains('\r') || source.lines().any(|line| line.contains('\t')) {
        return Err(unsafe_source(
            "only UTF-8 YAML with LF line endings and spaces is supported",
        ));
    }
    Ok(SourceLines {
        lines: source.lines().map(str::to_owned).collect(),
        trailing_newline: source.ends_with('\n'),
    })
}

fn render_lines(lines: Vec<String>, trailing_newline: bool) -> String {
    let mut rendered = lines.join("\n");
    if trailing_newline {
        rendered.push('\n');
    }
    rendered
}

fn required_mapping(
    lines: &[String],
    start: usize,
    end: usize,
    key: &str,
) -> Result<Block, Diagnostic> {
    optional_mapping(lines, start, end, key)?.ok_or_else(invalid_legacy)
}

fn optional_mapping(
    lines: &[String],
    start: usize,
    end: usize,
    key: &str,
) -> Result<Option<Block>, Diagnostic> {
    let indent = if start == 0 {
        0
    } else {
        indentation(&lines[start - 1]) + 2
    };
    let Some(key_line) = find_key(lines, start, end, indent, key)? else {
        return Ok(None);
    };
    if !line_value(&lines[key_line], indent, key)
        .is_some_and(|value| value.is_empty() || value.starts_with('#'))
    {
        return Err(unsafe_source("flow-style mappings are not supported"));
    }
    let block_end = key_value_end(lines, key_line, end);
    Ok(Some(Block {
        start: key_line,
        end: block_end,
        indent,
    }))
}

fn required_key(lines: &[String], block: Block, key: &str) -> Result<usize, Diagnostic> {
    optional_key(lines, block, key)?.ok_or_else(invalid_legacy)
}

fn optional_key(lines: &[String], block: Block, key: &str) -> Result<Option<usize>, Diagnostic> {
    find_key(lines, block.start + 1, block.end, block.indent + 2, key)
}

fn reject_key(lines: &[String], block: Block, key: &str) -> Result<(), Diagnostic> {
    if optional_key(lines, block, key)?.is_some() {
        return Err(unsafe_source(
            "partially migrated authoring is not rewritten automatically",
        ));
    }
    Ok(())
}

fn find_key(
    lines: &[String],
    start: usize,
    end: usize,
    indent: usize,
    key: &str,
) -> Result<Option<usize>, Diagnostic> {
    let found = (start..end)
        .filter(|index| line_value(&lines[*index], indent, key).is_some())
        .collect::<Vec<_>>();
    match found.as_slice() {
        [] => Ok(None),
        [index] => Ok(Some(*index)),
        _ => Err(unsafe_source(
            "duplicate mapping keys are not safe to rewrite",
        )),
    }
}

fn line_value<'a>(line: &'a str, indent: usize, key: &str) -> Option<&'a str> {
    if indentation(line) != indent {
        return None;
    }
    let rest = &line[indent..];
    rest.strip_prefix(key)?
        .strip_prefix(':')
        .map(str::trim_start)
}

fn key_value_end(lines: &[String], key_line: usize, limit: usize) -> usize {
    let indent = indentation(&lines[key_line]);
    (key_line + 1..limit)
        .find(|index| {
            let line = lines[*index].trim();
            !line.is_empty() && indentation(&lines[*index]) <= indent
        })
        .unwrap_or(limit)
}

fn indentation(line: &str) -> usize {
    line.bytes().take_while(|byte| *byte == b' ').count()
}

fn indent_line(line: &str, amount: usize) -> String {
    if line.is_empty() {
        String::new()
    } else {
        format!("{}{}", " ".repeat(amount), line)
    }
}

fn yaml_scalar(value: &str) -> String {
    serde_json::to_string(value).expect("strings serialize")
}

fn unsafe_source(reason: &str) -> Diagnostic {
    Diagnostic {
        severity: DiagnosticSeverity::Error,
        code: "project.migrate.source_unsafe".to_owned(),
        path: "registry.yaml".to_owned(),
        message: format!(
            "the legacy project uses a YAML shape that cannot be patched without reformatting: {reason}; rewrite the singular keys manually or normalize the file before retrying"
        ),
    }
}

fn invalid_legacy() -> Diagnostic {
    Diagnostic {
        severity: DiagnosticSeverity::Error,
        code: "project.migrate.legacy_invalid".to_owned(),
        path: "registry.yaml".to_owned(),
        message: "the project is not a valid singular Base Registry Engine authoring document"
            .to_owned(),
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Source-preserving, in-place patch of the module lock entries in `registry.yaml`.

use registry_breg::contract::ModuleLockSource;
use registry_breg::parse_project_yaml;

#[derive(Clone, Copy)]
struct Block {
    start: usize,
    end: usize,
    indent: usize,
}

/// Patches the version and digest lines of each authored module lock entry
/// where they stand, so every comment and scalar style around them survives.
///
/// `None` means the in-place patch does not apply: the authored entries do not
/// name exactly the ids in `locks`, or the `modules` block is not the ordinary
/// block-style list the patch understands. The caller then rewrites the whole
/// block instead.
pub(crate) fn patch_module_locks(bytes: &[u8], locks: &[ModuleLockSource]) -> Option<Vec<u8>> {
    let project = parse_project_yaml(bytes).ok()?;
    if project.modules.len() != locks.len() {
        return None;
    }
    let source = source_lines(bytes)?;
    let mut lines = source.lines;
    let modules = mapping(&lines, "modules")?;
    let item_indent = modules.indent + 2;
    let item_starts = (modules.start + 1..modules.end)
        .filter(|index| {
            indentation(&lines[*index]) == item_indent
                && lines[*index][item_indent..].starts_with("- id:")
        })
        .collect::<Vec<_>>();
    if item_starts.len() != project.modules.len() {
        return None;
    }

    let mut replacements = Vec::new();
    for (index, authored) in project.modules.iter().enumerate() {
        let expected = locks.iter().find(|lock| lock.id == authored.id)?;
        let item_end = item_starts.get(index + 1).copied().unwrap_or(modules.end);
        let item = Block {
            start: item_starts[index],
            end: item_end,
            indent: item_indent,
        };
        let version_line = optional_key(&lines, item, "version")??;
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
    parse_project_yaml(rendered.as_bytes()).ok()?;
    Some(rendered.into_bytes())
}

struct SourceLines {
    lines: Vec<String>,
    trailing_newline: bool,
}

fn source_lines(bytes: &[u8]) -> Option<SourceLines> {
    let source = std::str::from_utf8(bytes).ok()?;
    if source.contains('\r') || source.lines().any(|line| line.contains('\t')) {
        return None;
    }
    Some(SourceLines {
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

/// The top-level block mapping `key` opens, or `None` when it is absent,
/// duplicated, or written in flow style.
fn mapping(lines: &[String], key: &str) -> Option<Block> {
    let key_line = find_key(lines, 0, lines.len(), 0, key)??;
    if !line_value(&lines[key_line], 0, key)
        .is_some_and(|value| value.is_empty() || value.starts_with('#'))
    {
        return None;
    }
    Some(Block {
        start: key_line,
        end: key_value_end(lines, key_line, lines.len()),
        indent: 0,
    })
}

/// The line holding `key` directly inside `block`: `Some(None)` when it is
/// absent, `None` when it is duplicated.
fn optional_key(lines: &[String], block: Block, key: &str) -> Option<Option<usize>> {
    find_key(lines, block.start + 1, block.end, block.indent + 2, key)
}

fn find_key(
    lines: &[String],
    start: usize,
    end: usize,
    indent: usize,
    key: &str,
) -> Option<Option<usize>> {
    let found = (start..end)
        .filter(|index| line_value(&lines[*index], indent, key).is_some())
        .collect::<Vec<_>>();
    match found.as_slice() {
        [] => Some(None),
        [index] => Some(Some(*index)),
        _ => None,
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

fn yaml_scalar(value: &str) -> String {
    serde_json::to_string(value).expect("strings serialize")
}

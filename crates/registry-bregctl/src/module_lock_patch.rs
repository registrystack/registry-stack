// SPDX-License-Identifier: Apache-2.0
//! Source-preserving, in-place patch of the module lock entries in `registry.yaml`.

use registry_breg::contract::ModuleLockSource;
use registry_breg::parse_project_yaml;
use registry_platform_yaml::{Position, Reader};

/// Replaces a flow-style `modules` sequence using the shared reader's exact
/// source span. JSON is valid YAML here; changing only this value keeps its
/// enclosing mapping, punctuation, comments, and unrelated formatting intact.
pub(crate) fn patch_flow_module_locks(bytes: &[u8], locks: &[ModuleLockSource]) -> Option<Vec<u8>> {
    let source = std::str::from_utf8(bytes).ok()?;
    let root = Reader::new("registry.yaml").scan(bytes).ok()??;
    let modules = &root.get("modules")?.value;
    let start = source_offset(source, modules.span.start)?;
    let end = source_offset(source, modules.span.end)?;
    let value = source.get(start..end)?;
    if !value.starts_with('[') || !value.ends_with(']') {
        return None;
    }
    let replacement = serde_json::to_vec(locks).ok()?;
    let mut rendered = Vec::with_capacity(bytes.len() - value.len() + replacement.len());
    rendered.extend_from_slice(&bytes[..start]);
    rendered.extend_from_slice(&replacement);
    rendered.extend_from_slice(&bytes[end..]);
    let parsed = parse_project_yaml(&rendered).ok()?;
    (parsed.modules == locks).then_some(rendered)
}

/// Reader columns count Unicode scalar values, not UTF-8 bytes, and omit a
/// leading BOM. CR, LF, and CRLF each end one line in the shared reader.
/// Convert those positions without reinterpreting YAML syntax.
fn source_offset(source: &str, position: Position) -> Option<usize> {
    let line_start = if position.line == 1 {
        0
    } else {
        let bytes = source.as_bytes();
        source
            .char_indices()
            .filter_map(|(index, character)| match character {
                '\r' => Some(index + 1 + usize::from(bytes.get(index + 1) == Some(&b'\n'))),
                '\n' if index == 0 || bytes[index - 1] != b'\r' => Some(index + 1),
                _ => None,
            })
            .nth(position.line.checked_sub(2)?)?
    };
    let line = source.get(line_start..)?.split(['\r', '\n']).next()?;
    let bom_bytes = if position.line == 1 && line.starts_with('\u{feff}') {
        '\u{feff}'.len_utf8()
    } else {
        0
    };
    let text = &line[bom_bytes..];
    let column = position.column.checked_sub(1)?;
    let byte = text
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(text.len()))
        .nth(column)?;
    Some(line_start + bom_bytes + byte)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(id: &str) -> ModuleLockSource {
        ModuleLockSource {
            id: id.to_owned(),
            version: "1".to_owned(),
            digest: Some(format!("sha256:{}", "a".repeat(64))),
        }
    }

    #[test]
    fn flow_module_locks_preserve_json_and_unicode_surroundings() {
        let prefix = "\u{feff}{\"apiVersion\":\"id.registrystack.org/formats/breg/project/v1alpha1\",\"kind\":\"BRegProject\",\"project\":{\"id\":\"flow-lock\",\"canonicalBaseIri\":\"https://example.test/é\",\"version\":\"1\",\"defaultLanguage\":\"en\"},\"modules\":";
        let suffix = ",\"datasets\":[{\"id\":\"records\"}]}\n";
        let source = format!("{prefix}[{{\"id\":\"core\",\"version\":\"1\"}}]{suffix}");
        let locks = [lock("core")];
        let rendered =
            patch_flow_module_locks(source.as_bytes(), &locks).expect("JSON module locks patch");
        assert_eq!(
            String::from_utf8(rendered).expect("UTF-8"),
            format!("{prefix}{}{suffix}", serde_json::to_string(&locks).unwrap())
        );
    }

    #[test]
    fn flow_module_locks_preserve_yaml_surroundings_and_refresh_inventory() {
        let prefix = "# retained project comment\napiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject:\n  id: flow-lock\n  canonicalBaseIri: https://example.test\n  version: \"1\"\n  defaultLanguage: en\nmodules: ";
        let suffix = " # retained lock comment with ] and [\ndatasets: [{id: records}]\n";
        let source = format!("{prefix}[{{id: retired, version: \"1\"}}]{suffix}");
        let locks = [lock("core"), lock("extra")];
        let rendered = patch_flow_module_locks(source.as_bytes(), &locks)
            .expect("YAML flow module locks patch");
        assert_eq!(
            String::from_utf8(rendered).expect("UTF-8"),
            format!("{prefix}{}{suffix}", serde_json::to_string(&locks).unwrap())
        );
    }

    #[test]
    fn flow_module_locks_preserve_cr_and_crlf_surroundings() {
        for newline in ["\r", "\r\n"] {
            let prefix = "# retained project comment\napiVersion: id.registrystack.org/formats/breg/project/v1alpha1\nkind: BRegProject\nproject:\n  id: flow-lock\n  canonicalBaseIri: https://example.test\n  version: \"1\"\n  defaultLanguage: en\nmodules: ".replace('\n', newline);
            let suffix = " # retained lock comment with ] and [\ndatasets: [{id: records}]\n"
                .replace('\n', newline);
            let source =
                format!("{prefix}[{newline}  {{id: core, version: \"1\"}}{newline}]{suffix}");
            let locks = [lock("core")];
            let rendered = patch_flow_module_locks(source.as_bytes(), &locks)
                .expect("flow locks patch across accepted line endings");
            assert_eq!(
                String::from_utf8(rendered).expect("UTF-8"),
                format!("{prefix}{}{suffix}", serde_json::to_string(&locks).unwrap()),
                "surrounding source must retain {newline:?} line endings"
            );
        }
    }
}

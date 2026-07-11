use crate::*;

#[derive(Debug, Default, Clone)]
pub(crate) struct EnvFileReport {
    pub(crate) loaded: BTreeSet<String>,
    pub(crate) skipped_existing: BTreeSet<String>,
}

impl EnvFileReport {
    pub(crate) fn contains(&self, key: &str) -> bool {
        self.loaded.contains(key) || self.skipped_existing.contains(key)
    }
}

#[derive(Debug)]
pub(crate) struct EnvFileError {
    pub(crate) line: usize,
    pub(crate) reason: String,
}

impl fmt::Display for EnvFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid env file at line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for EnvFileError {}

pub(crate) fn load_env_file_arg(
    env_file: Option<&Path>,
    override_existing: bool,
) -> Result<EnvFileReport, Box<dyn std::error::Error>> {
    let Some(path) = env_file else {
        return Ok(EnvFileReport::default());
    };
    let raw = fs::read_to_string(path)?;
    apply_env_file(&raw, override_existing).map_err(Into::into)
}

pub(crate) fn apply_env_file(
    raw: &str,
    override_existing: bool,
) -> Result<EnvFileReport, EnvFileError> {
    let mut report = EnvFileReport::default();
    for (key, value) in parse_env_file(raw)? {
        if std::env::var_os(&key).is_some() && !override_existing {
            report.skipped_existing.insert(key);
        } else {
            std::env::set_var(&key, value);
            report.loaded.insert(key);
        }
    }
    Ok(report)
}

pub(crate) fn parse_env_file(raw: &str) -> Result<Vec<(String, String)>, EnvFileError> {
    let mut values = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let line_no = idx + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            return Err(env_file_error(line_no, "expected KEY=VALUE"));
        };
        let key = key.trim();
        if !valid_env_key(key) {
            return Err(env_file_error(line_no, "invalid env var name"));
        }
        values.push((key.to_string(), parse_env_value(value.trim(), line_no)?));
    }
    Ok(values)
}

pub(crate) fn parse_env_value(value: &str, line: usize) -> Result<String, EnvFileError> {
    if let Some(rest) = value.strip_prefix('"') {
        let Some(end) = closing_quote_index(rest, '"', true) else {
            return Err(env_file_error(line, "unterminated double-quoted value"));
        };
        if !rest[end + 1..].trim().is_empty() && !rest[end + 1..].trim().starts_with('#') {
            return Err(env_file_error(line, "unexpected text after quoted value"));
        }
        return Ok(rest[..end]
            .replace("\\n", "\n")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\"));
    }
    if let Some(rest) = value.strip_prefix('\'') {
        let Some(end) = closing_quote_index(rest, '\'', false) else {
            return Err(env_file_error(line, "unterminated single-quoted value"));
        };
        if !rest[end + 1..].trim().is_empty() && !rest[end + 1..].trim().starts_with('#') {
            return Err(env_file_error(line, "unexpected text after quoted value"));
        }
        return Ok(rest[..end].to_string());
    }
    Ok(value
        .split_once(" #")
        .map(|(before, _)| before)
        .unwrap_or(value)
        .trim()
        .to_string())
}

pub(crate) fn closing_quote_index(rest: &str, quote: char, allow_escape: bool) -> Option<usize> {
    let mut chars = rest.char_indices();
    while let Some((idx, ch)) = chars.next() {
        if allow_escape && ch == '\\' {
            let _ = chars.next();
            continue;
        }
        if ch == quote {
            return Some(idx);
        }
    }
    None
}

pub(crate) fn valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some('_') | Some('A'..='Z') | Some('a'..='z'))
        && chars.all(|ch| matches!(ch, '_' | 'A'..='Z' | 'a'..='z' | '0'..='9'))
}

pub(crate) fn env_file_error(line: usize, reason: &str) -> EnvFileError {
    EnvFileError {
        line,
        reason: reason.to_string(),
    }
}
#[cfg(test)]
#[path = "env_file/tests.rs"]
mod tests;

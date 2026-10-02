//! Bounded, redacted diagnostics from a `caseworkctl dev` session directory,
//! printed by a test when a dev command fails so a CI log names the cause.
//!
//! Only the session's own diagnostics are read: the `status` and `failure`
//! fields of `state.json` and the tail of each retained `logs/*.log`. Every
//! secret-bearing file the session keeps (database passwords, keys, tokens,
//! grants, client credentials, the issuer's secrets) is read only to redact
//! its values from that output, and is never printed.
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::Path,
};

/// Bytes kept from the end of each log. The supervisor and Casework service
/// journals always show their tails; of the per-command prerequisite logs,
/// only the newest show theirs. Every other non-empty log is still named with
/// its size, and empty prerequisite logs are only counted.
const TAIL_BYTES: u64 = 4 * 1024;
const SERVICE_LOGS: [&str; 2] = ["supervisor.log", "casework.log"];
const MAX_PREREQUISITE_TAILS: usize = 12;
/// Directories under the session root whose files hold secret material.
const SECRET_DIRS: [&str; 7] = [
    "secrets",
    "credentials",
    "database",
    "tls",
    "grants",
    "task-authority",
    "issuer/secrets",
];
/// Largest secret file read for redaction, and the shortest run of its
/// characters treated as secret. Generated passwords, keys, and tokens are
/// all longer; shorter runs are field names and fixed labels.
const MAX_SECRET_FILE: u64 = 64 * 1024;
const MIN_SECRET: usize = 12;
const REDACTED: &str = "[redacted]";

/// Describe the session under `root` (a project's `.casework/dev`).
pub(super) fn diagnostics(root: &Path) -> String {
    let secrets = secret_values(root);
    let mut out = format!(
        "=== caseworkctl dev session diagnostics: {} ===\n",
        root.display()
    );
    match fs::read(root.join("state.json")) {
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(state) => out.push_str(&format!(
                "state.json: status={} failure={}\n",
                state["status"], state["failure"]
            )),
            Err(error) => out.push_str(&format!("state.json: unreadable ({error})\n")),
        },
        Err(error) => out.push_str(&format!("state.json: {error}\n")),
    }
    let mut logs = match fs::read_dir(root.join("logs")) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let metadata = entry.metadata().ok()?;
                let name = entry.file_name().into_string().ok()?;
                (metadata.is_file() && name.ends_with(".log"))
                    .then(|| (metadata.modified().ok(), name, metadata.len()))
            })
            .collect::<Vec<_>>(),
        Err(error) => {
            out.push_str(&format!("logs: {error}\n"));
            Vec::new()
        }
    };
    // The two service journals come first; prerequisite logs follow newest
    // first, and only the newest of those show their tails.
    logs.sort_by_key(|(modified, name, _)| {
        (
            !SERVICE_LOGS.contains(&name.as_str()),
            std::cmp::Reverse(*modified),
        )
    });
    let (mut prerequisites, mut empty) = (0, 0);
    for (_, name, length) in &logs {
        let service = SERVICE_LOGS.contains(&name.as_str());
        if !service && *length == 0 {
            empty += 1;
            continue;
        }
        out.push_str(&format!("--- logs/{name} ({length} bytes) ---\n"));
        if *length == 0 {
            continue;
        }
        if !service {
            if prerequisites == MAX_PREREQUISITE_TAILS {
                continue;
            }
            prerequisites += 1;
        }
        match tail(&root.join("logs").join(name), TAIL_BYTES) {
            Ok(text) => {
                out.push_str(&text);
                if !text.ends_with('\n') {
                    out.push('\n');
                }
            }
            Err(error) => out.push_str(&format!("unreadable ({error})\n")),
        }
    }
    out.push_str(&format!("({empty} empty prerequisite logs not shown)\n"));
    out.push_str("=== end caseworkctl dev session diagnostics ===\n");
    redact(&out, &secrets)
}

/// The last `limit` bytes of `path`, marked when earlier bytes were dropped.
fn tail(path: &Path, limit: u64) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let start = file.metadata()?.len().saturating_sub(limit);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Ok(if start > 0 {
        format!("[... {start} earlier bytes omitted]\n{text}")
    } else {
        text
    })
}

/// Every run of token characters in the session's secret files, longest
/// first so a longer value is never left partly visible by a shorter one.
fn secret_values(root: &Path) -> Vec<String> {
    let mut files = SECRET_DIRS.map(|dir| root.join(dir)).to_vec();
    let mut values = Vec::new();
    while let Some(path) = files.pop() {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            if let Ok(entries) = fs::read_dir(&path) {
                files.extend(entries.filter_map(Result::ok).map(|entry| entry.path()));
            }
        } else if metadata.is_file() && metadata.len() <= MAX_SECRET_FILE {
            if let Ok(bytes) = fs::read(&path) {
                values.extend(secret_runs(&String::from_utf8_lossy(&bytes)));
            }
        }
    }
    values.sort_by(|left, right| right.len().cmp(&left.len()).then(left.cmp(right)));
    values.dedup();
    values
}

/// Runs of base64, base64url, hex, and identifier characters long enough to
/// be a credential. `=` and `.` separate runs, so an environment assignment
/// yields its value and a compact JWT yields each of its segments.
fn secret_runs(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '_' | '-'))
    })
    .filter(|run| run.len() >= MIN_SECRET)
    .map(str::to_owned)
}

fn redact(text: &str, secrets: &[String]) -> String {
    secrets.iter().fold(text.to_owned(), |text, secret| {
        text.replace(secret, REDACTED)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn diagnostics_show_state_cause_and_log_tails_without_session_secrets() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let password = "0123456789abcdef0123456789abcdef";
        let key = "kq3Zp1rL8vN2xW5yB7cD9eF0gH4jK6mQ";
        let token =
            "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzdGFmZi1zdWJqZWN0In0.c2lnbmF0dXJlLWJ5dGVzLXZhbHVl";
        write(
            &root.join("database/postgres.env"),
            format!("POSTGRES_USER=postgres\nPOSTGRES_PASSWORD={password}\n").as_bytes(),
        );
        write(
            &root.join("credentials/staff/assertion-key.jwk"),
            format!(r#"{{"kty":"OKP","crv":"Ed25519","d":"{key}"}}"#).as_bytes(),
        );
        write(
            &root.join("secrets/staff.header"),
            format!("Authorization: Bearer {token}\n").as_bytes(),
        );
        write(
            &root.join("state.json"),
            br#"{"status":"failed","failure":"database readiness timed out","clients":[]}"#,
        );
        write(
            &root.join("logs/casework.log"),
            format!(
                "connecting to postgres://postgres:{password}@127.0.0.1/casework\n\
                 bearer {token} refused; key {key}\n\
                 listener failed: address in use\n"
            )
            .as_bytes(),
        );
        write(&root.join("logs/supervisor.log"), b"");

        let out = diagnostics(root);

        assert!(out.contains("status=\"failed\" failure=\"database readiness timed out\""));
        assert!(out.contains("listener failed: address in use"));
        assert!(out.contains("--- logs/supervisor.log (0 bytes) ---"));
        for secret in [password, key, token] {
            assert!(!out.contains(secret), "{secret} leaked:\n{out}");
        }
        for segment in token.split('.') {
            assert!(!out.contains(segment), "{segment} leaked:\n{out}");
        }
        assert!(!out.contains("clients"), "only status and failure:\n{out}");
    }

    #[test]
    fn diagnostics_bound_each_tail_and_the_number_of_tails() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut long = "early-line\n".repeat(1024);
        long.push_str("latest-line\n");
        write(&root.join("logs/casework.log"), long.as_bytes());
        for index in 0..MAX_PREREQUISITE_TAILS + 3 {
            write(
                &root.join(format!("logs/prerequisite-{index:02}.log")),
                format!("body-{index:02}\n").as_bytes(),
            );
        }

        write(&root.join("logs/inspect-list-0.log"), b"");
        write(&root.join("logs/inspect-list-1.log"), b"");

        let out = diagnostics(root);

        assert!(out.contains("latest-line"));
        assert!(out.contains("earlier bytes omitted"));
        assert!(out.matches("early-line").count() <= TAIL_BYTES as usize / 11 + 1);
        assert_eq!(out.matches("body-").count(), MAX_PREREQUISITE_TAILS);
        assert_eq!(out.matches("--- logs/").count(), MAX_PREREQUISITE_TAILS + 4);
        assert!(out.contains("(2 empty prerequisite logs not shown)"));
        assert!(!out.contains("inspect-list"));
        assert!(out.contains("state.json: "));
    }
}

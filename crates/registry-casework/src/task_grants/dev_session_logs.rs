//! Bounded, redacted diagnostics from a `caseworkctl dev` session directory,
//! printed by a test when a dev command fails so a CI log names the cause.
//!
//! Only the session's own diagnostics are read: the `status` and `failure`
//! fields of `state.json` and the tail of each retained `logs/*.log`. Every
//! secret-bearing file the session keeps (database passwords, keys, tokens,
//! grants, client credentials, the issuer's secrets) is read only to redact
//! its values from that output, and is never printed.
//!
//! Redaction is matched to the sessions these tests build: generated
//! credentials, which are long token runs, and fixture secret files of at
//! least four bytes. It is not a general redactor for arbitrary operator
//! secrets, and must not be reused as one.
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
/// Directories under the project's `.casework` whose files hold secret
/// material: the session's own, and the grant headers `caseworkctl dev
/// token` keeps beside the session.
const SECRET_DIRS: [&str; 8] = [
    "dev/secrets",
    "dev/credentials",
    "dev/database",
    "dev/tls",
    "dev/grants",
    "dev/task-authority",
    "dev/issuer/secrets",
    "grants",
];
/// Largest secret file read for redaction, and the shortest run of its
/// characters treated as secret. Generated passwords, keys, and tokens are
/// all longer; shorter runs are field names and fixed labels.
const MAX_SECRET_FILE: u64 = 64 * 1024;
const MIN_SECRET: usize = 12;
/// The directory holding operator-supplied secret files, whose values may be
/// any shape and are redacted whole. Generated credentials elsewhere are long
/// token runs, and their files also hold identifiers that are not secret.
const WHOLE_VALUE_DIR: &str = "dev/secrets";
/// The shortest whole line or assigned value treated as secret, so a line
/// holding only JSON punctuation does not redact that punctuation everywhere.
const MIN_WHOLE_SECRET: usize = 4;
const REDACTED: &str = "[redacted]";

/// Describe the session under `root` (a project's `.casework/dev`).
pub(super) fn diagnostics(root: &Path) -> String {
    let mut out = format!(
        "=== caseworkctl dev session diagnostics: {} ===\n",
        root.display()
    );
    let secrets = match secret_values(root) {
        Ok(secrets) => secrets,
        Err(reason) => {
            out.push_str(&format!("diagnostics withheld: {reason}\n"));
            out.push_str("=== end caseworkctl dev session diagnostics ===\n");
            return out;
        }
    };
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

/// The complete lines within the last `limit` bytes of `path`, marked when
/// earlier bytes were dropped. A line the cut falls inside is dropped whole:
/// a secret value never spans a line, so one the cut splits lies in that
/// line, where redaction could no longer match it. The byte before the cut
/// is read too, so a cut on a line boundary keeps its first line.
fn tail(path: &Path, limit: u64) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut start = file.metadata()?.len().saturating_sub(limit + 1);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        let partial = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |newline| newline + 1);
        bytes.drain(..partial);
        start += partial as u64;
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Ok(if start > 0 {
        format!("[... {start} earlier bytes omitted]\n{text}")
    } else {
        text
    })
}

/// Every run of token characters in the session's secret files, longest
/// first so a longer value is never left partly visible by a shorter one.
/// Redaction fails closed: a secret path that cannot be read in full is an
/// error naming that path, and the caller then prints nothing it would have
/// redacted. Only a secret directory the session never created is skipped.
fn secret_values(root: &Path) -> Result<Vec<String>, String> {
    let base = root.parent().unwrap_or(root);
    let mut files = SECRET_DIRS.map(|dir| base.join(dir)).to_vec();
    let mut values = Vec::new();
    while let Some(path) = files.pop() {
        let unreadable = |reason: String| {
            let shown = path.strip_prefix(base).unwrap_or(&path);
            format!("cannot read {} for redaction ({reason})", shown.display())
        };
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(unreadable(error.to_string())),
        };
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).map_err(|error| unreadable(error.to_string()))? {
                files.push(entry.map_err(|error| unreadable(error.to_string()))?.path());
            }
        } else if !metadata.is_file() {
            return Err(unreadable("not a regular file".to_owned()));
        } else if metadata.len() > MAX_SECRET_FILE {
            return Err(unreadable(format!("larger than {MAX_SECRET_FILE} bytes")));
        } else {
            let bytes = fs::read(&path).map_err(|error| unreadable(error.to_string()))?;
            let text = String::from_utf8_lossy(&bytes);
            if path.starts_with(base.join(WHOLE_VALUE_DIR)) {
                values.extend(whole_values(&text));
            }
            values.extend(secret_runs(&text));
        }
    }
    values.sort_by(|left, right| right.len().cmp(&left.len()).then(left.cmp(right)));
    values.dedup();
    Ok(values)
}

/// Each trimmed line, and the trimmed value after a line's first `=` or `:`,
/// so a secret file's value is redacted whole whatever characters it holds.
fn whole_values(text: &str) -> impl Iterator<Item = String> + '_ {
    text.lines()
        .flat_map(|line| {
            let assigned = line.split_once(['=', ':']).map(|(_, value)| value);
            std::iter::once(line).chain(assigned)
        })
        .map(str::trim)
        .filter(|value| value.len() >= MIN_WHOLE_SECRET)
        .map(str::to_owned)
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
        let root = &root.path().join("dev");
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
    fn whole_secret_values_and_retained_grant_headers_are_redacted() {
        let root = tempfile::tempdir().unwrap();
        let root = &root.path().join("dev");
        let short_parts = "alpha-bravo-charlie";
        let spaced = "correct horse battery";
        let grant = "eyJhbGciOiJFUzI1NiJ9.eyJncmFudCI6InRhc2sifQ.Z3JhbnQtc2lnbmF0dXJl";
        write(
            &root.join("secrets/integration-token"),
            short_parts.as_bytes(),
        );
        write(
            &root.join("secrets/integration.env"),
            format!("PASSPHRASE = {spaced}\n").as_bytes(),
        );
        write(
            &root.join("credentials/supervisor/client-id"),
            b"supervisor",
        );
        write(
            &root.join("../grants/staff-review.header"),
            format!("Authorization: Bearer {grant}\n").as_bytes(),
        );
        write(
            &root.join("logs/casework.log"),
            format!("echo {short_parts}; phrase {spaced}; grant {grant}\nready\n").as_bytes(),
        );
        write(&root.join("logs/supervisor.log"), b"");

        let out = diagnostics(root);

        assert!(out.contains("ready"), "{out}");
        // A generated credential's identifier is not redacted as a whole value.
        assert!(out.contains("--- logs/supervisor.log"), "{out}");
        for secret in [short_parts, spaced, grant] {
            assert!(!out.contains(secret), "{secret} leaked:\n{out}");
        }
        for segment in grant.split('.') {
            assert!(!out.contains(segment), "{segment} leaked:\n{out}");
        }
    }

    #[test]
    fn a_secret_the_tail_boundary_cuts_through_is_not_printed_in_part() {
        let root = tempfile::tempdir().unwrap();
        let root = &root.path().join("dev");
        let password = "0123456789abcdef0123456789abcdef";
        write(
            &root.join("database/postgres.env"),
            format!("POSTGRES_PASSWORD={password}\n").as_bytes(),
        );
        // The tail starts halfway through the echoed password.
        let after = format!("\n{}\nlatest-line\n", "x".repeat(TAIL_BYTES as usize - 30));
        write(
            &root.join("logs/casework.log"),
            format!("early-line\nconnecting with {password}{after}").as_bytes(),
        );

        let out = diagnostics(root);

        assert!(out.contains("latest-line"), "{out}");
        assert!(out.contains("earlier bytes omitted"), "{out}");
        assert!(
            !out.contains(&password[16..]),
            "password suffix leaked:\n{out}"
        );
    }

    #[test]
    fn a_tail_that_starts_on_a_line_boundary_keeps_its_first_line() {
        let root = tempfile::tempdir().unwrap();
        let root = &root.path().join("dev");
        let first = "root-cause line\n";
        let last = "latest-line\n";
        let filler = "x".repeat(TAIL_BYTES as usize - first.len() - last.len() - 1);
        let kept = format!("{first}{filler}\n{last}");
        assert_eq!(kept.len() as u64, TAIL_BYTES);
        write(
            &root.join("logs/casework.log"),
            format!("early-line\n{kept}").as_bytes(),
        );

        let out = diagnostics(root);

        assert!(out.contains("root-cause line"), "{out}");
        assert!(out.contains("[... 11 earlier bytes omitted]"), "{out}");
    }

    #[test]
    fn diagnostics_are_withheld_when_a_secret_file_cannot_be_read_for_redaction() {
        let root = tempfile::tempdir().unwrap();
        let root = &root.path().join("dev");
        let password = "0123456789abcdef0123456789abcdef";
        let mut oversized = format!("POSTGRES_PASSWORD={password}\n");
        oversized.push_str(&"#".repeat(MAX_SECRET_FILE as usize));
        write(&root.join("database/postgres.env"), oversized.as_bytes());
        write(
            &root.join("state.json"),
            format!(r#"{{"status":"failed","failure":"password {password}"}}"#).as_bytes(),
        );
        write(
            &root.join("logs/casework.log"),
            format!("connecting with {password}\n").as_bytes(),
        );

        let out = diagnostics(root);

        assert!(!out.contains(password), "{password} leaked:\n{out}");
        assert!(out.contains("diagnostics withheld"), "{out}");
        assert!(out.contains("database/postgres.env"), "{out}");
    }

    #[test]
    fn diagnostics_bound_each_tail_and_the_number_of_tails() {
        let root = tempfile::tempdir().unwrap();
        let root = &root.path().join("dev");
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

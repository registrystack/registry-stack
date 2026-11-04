//! `evidencectl pack lock`: rewrite a reviewed Adapter pack's digest pins from
//! the bytes of the files beside it, the way `adapterctl project lock` does for
//! an Adapter project. An author edits a pinned script, query, or schema, runs
//! the lock, and commits pins that match the bytes; `package` and `check`
//! hold every pin against those same bytes.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write as _,
    ops::Range,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context as _, Result};
use clap::{Args, Subcommand};
use registry_adapter_core::AdapterPack;
use registry_evidence_authoring::compile::sha256_uri;

use crate::{authored, normalized};

/// The file name a pack document has inside its pack directory.
const PACK_FILE: &str = "pack.yaml";

/// The deepest nesting the pin scanner follows. A pack nests routes, steps and
/// control bodies, so the bound is generous; it only keeps a hostile document
/// from exhausting the stack.
const MAXIMUM_DEPTH: usize = 128;

#[derive(Debug, Subcommand)]
pub(crate) enum PackCommand {
    /// Recompute the digest pins of a pack's files and write them to pack.yaml.
    Lock(LockArgs),
}

#[derive(Debug, Args)]
pub(crate) struct LockArgs {
    /// Pack directory holding pack.yaml, or the pack.yaml file itself.
    ///
    /// A project keeps its packs at adapter-packs/<id>/. Lock rewrites the
    /// digest of every pinned file that exists in the pack directory and
    /// changed; it never adds or removes a pin, so declare a new file in
    /// pack.yaml first, with any well-formed placeholder digest.
    #[arg(value_name = "PACK")]
    pub pack: PathBuf,
}

pub(crate) fn run(command: PackCommand) -> Result<ExitCode> {
    match command {
        PackCommand::Lock(args) => lock(&args),
    }
}

fn lock(args: &LockArgs) -> Result<ExitCode> {
    let pack_path = if args.pack.is_dir() {
        args.pack.join(PACK_FILE)
    } else {
        args.pack.clone()
    };
    let bytes = authored::read_authored_file(&pack_path, "Adapter pack")?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("Adapter pack {} must be UTF-8", pack_path.display()))?;
    let pack = normalized::decode_adapter_pack(PACK_FILE, &bytes).map_err(|report| {
        anyhow::anyhow!(
            "{} does not satisfy the current AdapterPack contract, so its pins cannot be located; correct it, then run pack lock again\n{}",
            pack_path.display(),
            report.render_human().trim_end()
        )
    })?;
    let pack_root = pack_path
        .parent()
        .context("Adapter pack requires a parent directory")?;

    let digests = member_digests(pack_root, &pack)?;
    let (rewritten, changes) =
        repin(text, &pack, &digests).with_context(|| format!("locking {}", pack_path.display()))?;

    if changes.is_empty() {
        println!(
            "{}: all {} pins already match their files; nothing changed",
            pack_path.display(),
            digests.len()
        );
        return Ok(ExitCode::SUCCESS);
    }
    replace_pack_file(&pack_path, rewritten.as_bytes())?;
    println!("Locked {}", pack_path.display());
    for change in &changes {
        println!(
            "  {}: {} -> {}",
            change.path,
            short(&change.old),
            short(&change.new)
        );
    }
    let count = changes.len();
    println!("{count} pin{} updated", if count == 1 { "" } else { "s" });
    Ok(ExitCode::SUCCESS)
}

/// The digest of every file the pack pins, keyed by its pack-relative path.
///
/// Every member that cannot be locked is reported at once, so one run shows
/// the author everything to correct.
fn member_digests(pack_root: &Path, pack: &AdapterPack) -> Result<BTreeMap<String, String>> {
    let paths = pack
        .pinned_files()
        .into_iter()
        .map(|reference| reference.path.clone())
        .collect::<BTreeSet<_>>();
    let mut digests = BTreeMap::new();
    let mut problems = Vec::new();
    for path in paths {
        match read_member(pack_root, &path) {
            Ok(bytes) => {
                digests.insert(path, sha256_uri(&bytes));
            }
            Err(problem) => problems.push(problem),
        }
    }
    if !problems.is_empty() {
        bail!(
            "pack lock changed nothing; correct {} pinned file{} first:\n  {}",
            problems.len(),
            if problems.len() == 1 { "" } else { "s" },
            problems.join("\n  ")
        );
    }
    Ok(digests)
}

/// One pinned file's bytes, or the sentence that says why it cannot be pinned.
fn read_member(pack_root: &Path, path: &str) -> std::result::Result<Vec<u8>, String> {
    let outside = || {
        format!(
            "`{path}` must be a relative path inside the pack directory, with no leading `/`, `\\`, or `..`"
        )
    };
    if path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(outside());
    }
    let resolved = normalized::safe_asset(pack_root, path).map_err(|error| {
        let missing = error
            .root_cause()
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound);
        if missing {
            format!("`{path}` is pinned in pack.yaml but is not in the pack directory")
        } else {
            format!(
                "`{path}` passes through a symbolic link, so it could resolve outside the pack directory"
            )
        }
    })?;
    authored::read_authored_file(&resolved, "pinned pack file")
        .map_err(|error| format!("`{path}` cannot be pinned: {error:#}"))
}

/// One pin that moved.
#[derive(Debug, PartialEq, Eq)]
struct PinChange {
    path: String,
    old: String,
    new: String,
}

/// A `{path, digest}` object found in the pack text, with the byte range of
/// the digest's characters between its quotes.
#[derive(Debug)]
struct PinSpan {
    path: String,
    digest: String,
    digest_text: Range<usize>,
}

/// Rewrite the digest of every pin whose file changed and return the new text
/// with the pins that moved. Only the characters of each stale digest are
/// replaced, so the document keeps its layout, key order, and every other byte.
fn repin(
    text: &str,
    pack: &AdapterPack,
    digests: &BTreeMap<String, String>,
) -> Result<(String, Vec<PinChange>)> {
    let spans = scan_pins(text)?;

    // The typed collector is the authority on what a pin is. The scan locates
    // them; if the two disagree, the layout holds something the scan cannot
    // tell apart from a pin, and editing it blind could change the wrong text.
    let mut declared = pack
        .pinned_files()
        .into_iter()
        .map(|reference| (reference.path.clone(), reference.digest.as_str().to_owned()))
        .collect::<Vec<_>>();
    let mut found = spans
        .iter()
        .map(|span| (span.path.clone(), span.digest.clone()))
        .collect::<Vec<_>>();
    declared.sort();
    found.sort();
    if declared != found {
        bail!(
            "pack.yaml has {} objects shaped like a pin but the pack contract declares {}; lock edits only packs whose pins are plain `path` and `digest` members, so pin the files by hand",
            found.len(),
            declared.len()
        );
    }

    let mut rewritten = text.to_owned();
    let mut changes = Vec::new();
    let mut seen = BTreeSet::new();
    // Back to front keeps the earlier ranges valid as the text changes length.
    for span in spans.iter().rev() {
        let new = &digests[&span.path];
        if *new == span.digest {
            continue;
        }
        rewritten.replace_range(span.digest_text.clone(), new);
        if seen.insert((span.path.clone(), span.digest.clone())) {
            changes.push(PinChange {
                path: span.path.clone(),
                old: span.digest.clone(),
                new: new.clone(),
            });
        }
    }
    changes.sort_by(|left, right| left.path.cmp(&right.path).then(left.old.cmp(&right.old)));
    Ok((rewritten, changes))
}

/// `sha256:` and the first twelve hex digits, enough to tell two pins apart.
fn short(digest: &str) -> String {
    digest.chars().take("sha256:".len() + 12).collect()
}

/// Find every object whose only members are a string `path` and a string
/// `digest`, anywhere in a JSON document.
fn scan_pins(text: &str) -> Result<Vec<PinSpan>> {
    let mut scanner = Scanner {
        text,
        at: 0,
        pins: Vec::new(),
    };
    scanner.value(0).map_err(|problem| {
        anyhow::anyhow!(
            "pack.yaml is not written as JSON ({problem}); lock edits packs in the JSON form evidencectl writes, so pin the files by hand"
        )
    })?;
    scanner.skip_space();
    if scanner.at != text.len() {
        bail!("pack.yaml has content after its document; lock edits packs in the JSON form evidencectl writes");
    }
    Ok(scanner.pins)
}

/// What the scanner needs to know of a parsed value: a string's characters and
/// where they sit, or that it was something else.
enum Scanned {
    Text { value: String, range: Range<usize> },
    Other,
}

/// A recursive reader over JSON text that records the position of pin digests.
struct Scanner<'a> {
    text: &'a str,
    at: usize,
    pins: Vec<PinSpan>,
}

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.at).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> std::result::Result<(), String> {
        self.skip_space();
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(format!(
                "expected `{}` at byte {}",
                char::from(byte),
                self.at
            ))
        }
    }

    fn value(&mut self, depth: usize) -> std::result::Result<Scanned, String> {
        if depth > MAXIMUM_DEPTH {
            return Err("nesting is too deep".to_owned());
        }
        self.skip_space();
        match self.peek() {
            Some(b'{') => self.object(depth).map(|()| Scanned::Other),
            Some(b'[') => self.array(depth).map(|()| Scanned::Other),
            Some(b'"') => {
                let (value, range) = self.string()?;
                Ok(Scanned::Text { value, range })
            }
            Some(_) => {
                let start = self.at;
                while !matches!(
                    self.peek(),
                    None | Some(b',' | b']' | b'}' | b' ' | b'\t' | b'\n' | b'\r')
                ) {
                    self.at += 1;
                }
                serde_json::from_str::<serde_json::Value>(&self.text[start..self.at])
                    .map(|_| Scanned::Other)
                    .map_err(|_| format!("unexpected content at byte {start}"))
            }
            None => Err("the document ends early".to_owned()),
        }
    }

    fn array(&mut self, depth: usize) -> std::result::Result<(), String> {
        self.expect(b'[')?;
        self.skip_space();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(());
        }
        loop {
            self.value(depth + 1)?;
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(());
                }
                _ => return Err(format!("expected `,` or `]` at byte {}", self.at)),
            }
        }
    }

    fn object(&mut self, depth: usize) -> std::result::Result<(), String> {
        self.expect(b'{')?;
        let mut members = Vec::<(String, Scanned)>::new();
        self.skip_space();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(());
        }
        loop {
            self.skip_space();
            if self.peek() != Some(b'"') {
                return Err(format!("expected a member name at byte {}", self.at));
            }
            let (key, _) = self.string()?;
            self.expect(b':')?;
            let value = self.value(depth + 1)?;
            members.push((key, value));
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    break;
                }
                _ => return Err(format!("expected `,` or `}}` at byte {}", self.at)),
            }
        }
        let member = |name: &str| {
            members
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value)
        };
        if members.len() == 2 {
            if let (
                Some(Scanned::Text { value: path, .. }),
                Some(Scanned::Text {
                    value: digest,
                    range,
                }),
            ) = (member("path"), member("digest"))
            {
                self.pins.push(PinSpan {
                    path: path.clone(),
                    digest: digest.clone(),
                    digest_text: range.clone(),
                });
            }
        }
        Ok(())
    }

    /// A string literal's decoded value and the range of the characters
    /// between its quotes.
    fn string(&mut self) -> std::result::Result<(String, Range<usize>), String> {
        let start = self.at;
        self.at += 1;
        loop {
            match self.peek() {
                Some(b'"') => break,
                Some(b'\\') => self.at += 2,
                Some(_) => self.at += 1,
                None => return Err("a string is not closed".to_owned()),
            }
        }
        self.at += 1;
        let value = serde_json::from_str::<String>(&self.text[start..self.at])
            .map_err(|_| format!("invalid string at byte {start}"))?;
        Ok((value, start + 1..self.at - 1))
    }
}

/// Replace `pack.yaml` through a staged file in its own directory, so a reader
/// sees the old pack or the new one and never a partial write.
fn replace_pack_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{} must remain a plain file", path.display());
    }
    let parent = path.parent().context("pack.yaml requires a parent")?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("staging {}", path.display()))?;
    staged.as_file().set_permissions(metadata.permissions())?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged
        .persist(path)
        .with_context(|| format!("publishing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_A: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn the_scan_finds_pins_in_either_member_order_and_ignores_other_objects() {
        let text = format!(
            "{{\n  \"literal\": {{\"path\": \"$.x\", \"other\": 1}},\n  \"a\": {{\"digest\": \"{DIGEST_A}\", \"path\": \"one.rhai\"}},\n  \"b\": [{{\"path\": \"two.sql\", \"digest\": \"{DIGEST_B}\"}}]\n}}"
        );
        let pins = scan_pins(&text).expect("scan");
        let found = pins
            .iter()
            .map(|pin| (pin.path.as_str(), pin.digest.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(found, [("one.rhai", DIGEST_A), ("two.sql", DIGEST_B)]);
        for pin in &pins {
            assert_eq!(&text[pin.digest_text.clone()], pin.digest);
        }
    }

    #[test]
    fn the_scan_refuses_a_document_that_is_not_json() {
        let error = scan_pins("id: starter\nversion: '1'\n").unwrap_err();
        assert!(
            error.to_string().contains("not written as JSON"),
            "{error:#}"
        );
        let error = scan_pins("{\"a\": 1} trailing").unwrap_err();
        assert!(
            error.to_string().contains("after its document"),
            "{error:#}"
        );
    }

    fn pack_of(text: &str) -> AdapterPack {
        serde_json::from_str(text).expect("a minimal pack decodes")
    }

    #[test]
    fn repin_replaces_only_the_stale_digest_characters_and_keeps_the_layout() {
        let text = format!(
            "{{\"id\":\"p\",\"version\":\"1\",\"testedVersions\":[],\n \"scripts\":[{{\"path\":\"a.rhai\",\"digest\":\"{DIGEST_A}\"}}],\n \"queryFiles\":[{{\"digest\":\"{DIGEST_A}\",\"path\":\"b.sql\"}}]}}"
        );
        let digests = BTreeMap::from([
            ("a.rhai".to_owned(), DIGEST_A.to_owned()),
            ("b.sql".to_owned(), DIGEST_B.to_owned()),
        ]);

        let (rewritten, changes) = repin(&text, &pack_of(&text), &digests).expect("repin");

        assert_eq!(
            rewritten,
            // Only the last digest, the stale one of `b.sql`, differs.
            {
                let (head, tail) = text.rsplit_once(DIGEST_A).expect("two digests");
                format!("{head}{DIGEST_B}{tail}")
            }
        );
        assert_eq!(
            changes,
            [PinChange {
                path: "b.sql".to_owned(),
                old: DIGEST_A.to_owned(),
                new: DIGEST_B.to_owned(),
            }]
        );
    }

    #[test]
    fn repin_refuses_a_pin_shaped_object_the_contract_does_not_declare() {
        let text = format!(
            "{{\"id\":\"p\",\"version\":\"1\",\"testedVersions\":[],\"scripts\":[{{\"path\":\"a.rhai\",\"digest\":\"{DIGEST_A}\"}}],\"capabilities\":{{}},\"note\":{{\"path\":\"x\",\"digest\":\"{DIGEST_A}\"}}}}"
        );
        let digests = BTreeMap::from([("a.rhai".to_owned(), DIGEST_B.to_owned())]);
        let pack = serde_json::from_str::<AdapterPack>(&text);
        // The contract rejects the unknown member itself; the scan guard is
        // reached with the typed pack that omits it.
        assert!(
            pack.is_err(),
            "unknown members are not part of the contract"
        );
        let declared = text.replace(",\"note\":{\"path\":\"x\",\"digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}", "");
        let error = repin(&text, &pack_of(&declared), &digests).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("2 objects shaped like a pin but the pack contract declares 1"),
            "{error:#}"
        );
    }

    #[test]
    fn short_digests_keep_the_scheme_and_twelve_hex_digits() {
        assert_eq!(short(DIGEST_A), "sha256:aaaaaaaaaaaa");
    }
}

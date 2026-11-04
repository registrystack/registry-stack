//! Acceptance tests for `evidencectl pack lock`: a pack's digest pins follow the
//! bytes of the files beside it, and nothing else in pack.yaml moves.

#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

const SCRIPT: &str = "scripts/extract.rhai";
const QUERY: &str = "queries/record-status.sql";

/// A fresh SQLite starter and the directory of the pack it ships.
struct Starter {
    _workspace: TempDir,
    root: PathBuf,
    project: PathBuf,
    pack: PathBuf,
}

impl Starter {
    fn new() -> Self {
        let workspace = TempDir::new().expect("temporary directory");
        let root = fs::canonicalize(workspace.path()).expect("canonical temporary directory");
        let project = root.join("project");
        let created = evidencectl(&[
            "init",
            path(&project),
            "--transport",
            "sqlite-extract",
            "--profile",
            "local",
        ]);
        assert!(created.status.success(), "{}", stderr(&created));
        let pack = project.join("adapter-packs/starter-source");
        Self {
            _workspace: workspace,
            root,
            project,
            pack,
        }
    }

    fn pack_file(&self) -> PathBuf {
        self.pack.join("pack.yaml")
    }

    fn pack_text(&self) -> String {
        fs::read_to_string(self.pack_file()).expect("read pack.yaml")
    }

    fn lock(&self) -> Output {
        evidencectl(&["pack", "lock", path(&self.pack)])
    }

    /// Offline `check` of the project, which holds every pin against its bytes.
    fn check(&self) -> Output {
        let stub = self.root.join("evidence");
        fs::write(
            &stub,
            "#!/bin/sh\nif [ \"${1:-}\" = \"--version\" ]; then printf 'evidence %s\\n' \"$VERSION\"; fi\nif [ \"$1\" = \"render-discovery-description\" ]; then printf '{}\\n'; fi\nexit 0\n",
        )
        .expect("write stub evidence");
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).expect("chmod stub");
        Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args(["check", path(&self.project)])
            .env("EVIDENCE_BIN", &stub)
            .env("VERSION", registry_platform_buildinfo::DISPLAY_VERSION)
            .output()
            .expect("check the project")
    }
}

#[test]
fn a_stale_pin_is_rewritten_and_only_its_digest_changes() {
    let starter = Starter::new();
    let before = starter.pack_text();
    let script = starter.pack.join(SCRIPT);
    fs::write(
        &script,
        format!(
            "{}\n// reviewed again\n",
            fs::read_to_string(&script).unwrap()
        ),
    )
    .unwrap();
    let stale = starter.check();
    assert!(
        !stale.status.success() && stdout(&stale).contains("does not match its pinned digest"),
        "a changed file must not pass check before the lock: {}{}",
        stdout(&stale),
        stderr(&stale)
    );

    let locked = starter.lock();

    assert!(locked.status.success(), "{}", stderr(&locked));
    let after = starter.pack_text();
    let changed = before
        .lines()
        .zip(after.lines())
        .filter(|(old, new)| old != new)
        .collect::<Vec<_>>();
    assert_eq!(before.lines().count(), after.lines().count());
    assert_eq!(changed.len(), 1, "only one line moves: {changed:?}");
    assert!(
        changed[0]
            .0
            .trim_start()
            .starts_with("\"digest\": \"sha256:")
            && changed[0]
                .1
                .trim_start()
                .starts_with("\"digest\": \"sha256:"),
        "the line that moves is a digest: {changed:?}"
    );
    let printed = stdout(&locked);
    let old = &changed[0].0.trim()[11..11 + 19];
    let new = &changed[0].1.trim()[11..11 + 19];
    assert!(
        printed.contains(&format!("{SCRIPT}: {old} -> {new}")),
        "the old and new pin are reported in short form: {printed}"
    );
    assert!(printed.contains("1 pin updated"), "{printed}");

    let checked = starter.check();
    assert!(
        checked.status.success(),
        "the project compiles after the lock: {}{}",
        stdout(&checked),
        stderr(&checked)
    );
}

#[test]
fn a_current_pack_reports_no_change_and_is_not_rewritten() {
    let starter = Starter::new();
    let before = fs::read(starter.pack_file()).unwrap();
    let modified = fs::metadata(starter.pack_file())
        .unwrap()
        .modified()
        .unwrap();

    let locked = starter.lock();

    assert!(locked.status.success(), "{}", stderr(&locked));
    assert!(
        stdout(&locked).contains("already match their files; nothing changed"),
        "{}",
        stdout(&locked)
    );
    assert_eq!(fs::read(starter.pack_file()).unwrap(), before);
    assert_eq!(
        fs::metadata(starter.pack_file())
            .unwrap()
            .modified()
            .unwrap(),
        modified,
        "an unchanged pack is not written"
    );
}

#[test]
fn the_pack_file_may_be_named_directly() {
    let starter = Starter::new();
    let locked = evidencectl(&["pack", "lock", path(&starter.pack_file())]);
    assert!(locked.status.success(), "{}", stderr(&locked));
    assert!(stdout(&locked).contains("nothing changed"));
}

#[test]
fn several_stale_pins_are_all_reported_in_path_order() {
    let starter = Starter::new();
    for member in [SCRIPT, QUERY] {
        let file = starter.pack.join(member);
        fs::write(
            &file,
            format!("{}\n-- edited\n", fs::read_to_string(&file).unwrap()),
        )
        .unwrap();
    }

    let locked = starter.lock();

    assert!(locked.status.success(), "{}", stderr(&locked));
    let printed = stdout(&locked);
    assert!(printed.contains("2 pins updated"), "{printed}");
    let query = printed.find(QUERY).expect("query reported");
    let script = printed.find(SCRIPT).expect("script reported");
    assert!(query < script, "{printed}");
    assert!(starter.check().status.success());
}

#[test]
fn a_member_that_escapes_through_a_symbolic_link_is_refused_and_nothing_is_written() {
    let starter = Starter::new();
    let before = fs::read(starter.pack_file()).unwrap();
    let outside = starter.root.join("outside.rhai");
    fs::write(&outside, "fn extract() { 1 }\n").unwrap();
    let script = starter.pack.join(SCRIPT);
    fs::remove_file(&script).unwrap();
    symlink(&outside, &script).unwrap();

    let locked = starter.lock();

    assert!(!locked.status.success());
    let message = stderr(&locked);
    assert!(
        message.contains(&format!("`{SCRIPT}` passes through a symbolic link")),
        "{message}"
    );
    assert_eq!(fs::read(starter.pack_file()).unwrap(), before);
}

#[test]
fn a_member_that_names_a_parent_directory_is_refused_and_nothing_is_written() {
    let starter = Starter::new();
    fs::write(starter.pack.join("../outside.sql"), "select 1;\n").unwrap();
    let text = starter.pack_text().replace(QUERY, "../outside.sql");
    fs::write(starter.pack_file(), &text).unwrap();

    let locked = starter.lock();

    assert!(!locked.status.success());
    let message = stderr(&locked);
    assert!(
        message.contains("`../outside.sql` must be a relative path inside the pack directory"),
        "{message}"
    );
    assert_eq!(starter.pack_text(), text);
}

#[test]
fn every_missing_member_is_named_in_one_refusal() {
    let starter = Starter::new();
    let before = fs::read(starter.pack_file()).unwrap();
    fs::remove_file(starter.pack.join(SCRIPT)).unwrap();
    fs::remove_file(starter.pack.join(QUERY)).unwrap();

    let locked = starter.lock();

    assert!(!locked.status.success());
    let message = stderr(&locked);
    assert!(
        message.contains("correct 2 pinned files first"),
        "{message}"
    );
    for member in [SCRIPT, QUERY] {
        assert!(
            message.contains(&format!(
                "`{member}` is pinned in pack.yaml but is not in the pack directory"
            )),
            "{message}"
        );
    }
    assert_eq!(fs::read(starter.pack_file()).unwrap(), before);
}

#[test]
fn a_pack_that_is_not_json_is_refused_without_being_changed() {
    let starter = Starter::new();
    let text = format!("# reviewed by hand\n{}", yaml_form(&starter.pack_text()));
    fs::write(starter.pack_file(), &text).unwrap();

    let locked = starter.lock();

    assert!(!locked.status.success());
    assert!(
        stderr(&locked).contains("not written as JSON"),
        "{}",
        stderr(&locked)
    );
    assert_eq!(starter.pack_text(), text);
}

#[test]
fn a_document_that_is_not_an_adapter_pack_is_refused() {
    let starter = Starter::new();
    fs::write(starter.pack_file(), "{\"kind\": \"AdapterPack\"}\n").unwrap();

    let locked = starter.lock();

    assert!(!locked.status.success());
    assert!(
        stderr(&locked).contains("does not satisfy the current AdapterPack contract"),
        "{}",
        stderr(&locked)
    );
}

#[test]
fn a_pack_directory_without_a_pack_document_is_refused() {
    let starter = Starter::new();
    let empty = starter.root.join("empty");
    fs::create_dir(&empty).unwrap();

    let locked = evidencectl(&["pack", "lock", path(&empty)]);

    assert!(!locked.status.success());
    assert!(stderr(&locked).contains("pack.yaml"), "{}", stderr(&locked));
}

/// The same document with a YAML comment after its opening brace: still a
/// valid pack, but not JSON.
fn yaml_form(json: &str) -> String {
    json.replacen("{\n", "{ # the pack\n", 1)
}

fn evidencectl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .output()
        .expect("running evidencectl")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

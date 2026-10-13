// SPDX-License-Identifier: Apache-2.0

//! The `bregctl` subprocess boundary, driven through a stand-in executable.
//! The stand-in is a shell script each test writes, so no Base Registry
//! Engine crate is linked and no issuer, container, or key is involved.

use std::ffi::OsStr;
use std::fs;
use std::io::Write as _;

use clap::Parser as _;
use serde_json::json;

use super::*;
use crate::dev::{
    docker, fresh_session, install_project, read_session, run_session, token, DevFailure, Session,
    TokenArgs,
};
use crate::{starter, Cli, OutputFormat};

const ISSUER: &str = "http://127.0.0.1:18095";
const RESOURCE: &str = "urn:registrystack:messaging:notices";

/// How every stand-in begins: it accepts only the one public command
/// Messaging runs, then offers the two files that command writes and its
/// report. A test changes a report member by assigning its shell variable
/// before calling `report`.
const PREAMBLE: &str = r#"#!/bin/sh
[ "$#" -eq 11 ] || exit 64
[ "$1 $2 $3 $4 $6 $8 ${10}" = "--format json dev export-client --client --client-id-file --assertion-key-file" ] || exit 64
project=$5
client=$7
id=$9
key=${11}
ok=true
reported_client=$client
reported_id=$id
reported_key=$key
export_files() {
    (umask 077 && printf '%s' "$client" > "$id" && printf 'synthetic, not a key' > "$key")
}
report() {
    printf '{"ok":%s,"command":"dev export-client","client":"%s","clientIdFile":"%s","assertionKeyFile":"%s","issuer":"%s","tokenEndpoint":"%s","clientAssertionAudience":"%s"}\n' \
        "$ok" "$reported_client" "$reported_id" "$reported_key" "$issuer" \
        "${token_endpoint-$issuer/oauth2/token}" "${audience-$issuer}"
}
"#;

/// A stand-in body that exports both files and reports them truthfully.
const HONEST: &str = "export_files\nreport";

/// A session as a start leaves it when the issuer preflight begins, beside
/// the directory standing for the issuer owner's project.
struct Fixture {
    _temporary: tempfile::TempDir,
    project: PathBuf,
    root: PathBuf,
    owner: PathBuf,
    loaded: LoadedPackage,
}

fn fixture() -> Fixture {
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let base = fs::canonicalize(temporary.path()).unwrap();
    let project = base.join("project");
    starter::write(&project).unwrap();
    let docker = docker::Docker::new(PathBuf::from("/nonexistent/docker"));
    let (lock, root) = fresh_session(&project, &docker).unwrap();
    drop(lock);
    let loaded = install_project(&project, &root).unwrap();
    let owner = base.join("owner");
    fs::create_dir(&owner).unwrap();
    Fixture {
        _temporary: temporary,
        project,
        root,
        owner,
        loaded,
    }
}

impl Fixture {
    /// Write an executable beside the owner project. This process never
    /// holds the file open for writing: a descriptor inherited by a
    /// concurrent test's fork would make the kernel refuse to run it as busy.
    fn script(&self, text: &str) -> PathBuf {
        let path = self.owner.with_file_name("bregctl");
        let mut writer = Command::new("/bin/sh")
            .args(["-c", r#"umask 077 && cat > "$1" && chmod 700 "$1""#, "sh"])
            .arg(&path)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        writer
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        assert!(writer.wait().unwrap().success());
        path
    }

    /// A stand-in `bregctl` that runs `body` after the preamble.
    fn stand_in(&self, body: &str) -> PathBuf {
        self.script(&format!("{PREAMBLE}issuer={ISSUER}\n{body}\n"))
    }

    fn capture(&self, bregctl: &Path, stop: &AtomicBool) -> DevResult<Binding> {
        capture(
            &self.root,
            &self.loaded,
            &self.owner,
            RESOURCE,
            bregctl,
            stop,
        )
    }

    /// The failure of a capture through a stand-in running `body`.
    fn capture_failure(&self, body: &str) -> DevFailure {
        self.capture(&self.stand_in(body), &AtomicBool::new(false))
            .err()
            .expect("the capture does not succeed")
    }

    /// The binding a ready session retains for `case-system`.
    fn binding(&self, bregctl: PathBuf) -> Binding {
        Binding {
            project: self.owner.clone(),
            bregctl,
            issuer: ISSUER.to_owned(),
            token_endpoint: format!("{ISSUER}/oauth2/token"),
            resource: RESOURCE.to_owned(),
            clients: BTreeMap::from([(
                "case-system".to_owned(),
                CallerPin {
                    principal: "case-system".to_owned(),
                    profile: "case-notices".to_owned(),
                    actor_kind: Some(ActorKind::Service),
                },
            )]),
        }
    }

    /// Record a ready borrowed session and ask it for a `case-system` token.
    fn token_failure(&self, bregctl: PathBuf) -> DevFailure {
        Session {
            root: self.root.clone(),
            owner: uuid::Uuid::new_v4().to_string(),
            containers: vec![],
            borrowed: Some(self.binding(bregctl)),
        }
        .write("ready", &json!({}))
        .unwrap();
        token(&TokenArgs {
            client: "case-system".to_owned(),
            project: self.project.clone(),
        })
        .err()
        .expect("the token is not issued")
    }

    /// The private directory a capture exports one client's credential into.
    fn credentials(&self, client: &str) -> PathBuf {
        private::directory(&self.root.join("credentials")).unwrap();
        client_directory(&self.root, client).unwrap()
    }

    /// Every file an export left in the session's credential directories.
    fn exported_files(&self) -> Vec<PathBuf> {
        let Ok(clients) = fs::read_dir(self.root.join("credentials")) else {
            return Vec::new();
        };
        clients
            .flat_map(|client| fs::read_dir(client.unwrap().path()).unwrap())
            .map(|file| file.unwrap().path())
            .collect()
    }

    /// Every scratch copy a token refresh left in the session directory.
    fn scratch_copies(&self) -> Vec<PathBuf> {
        fs::read_dir(&self.root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".client-check-"))
            })
            .collect()
    }

    /// The issuer key snapshot a runtime would trust.
    fn snapshot(&self) -> PathBuf {
        self.root.join("secrets/jwks.json")
    }
}

#[track_caller]
fn assert_refused(failure: &DevFailure, expected: &str) {
    assert_eq!(failure.code, "dev.refused", "{}", failure.message);
    assert!(failure.message.contains(expected), "{}", failure.message);
}

/// The process a stand-in recorded in `file`.
fn recorded(file: &Path) -> rustix::process::Pid {
    rustix::process::Pid::from_raw(fs::read_to_string(file).unwrap().parse().unwrap()).unwrap()
}

/// Whether the process a stand-in recorded in `file` still exists.
fn alive(file: &Path) -> bool {
    rustix::process::test_kill_process(recorded(file)).is_ok()
}

#[test]
fn an_honest_report_is_accepted() {
    let fixture = fixture();
    let directory = fixture.credentials("case-system");
    let exported = export(
        &fixture.stand_in(HONEST),
        &fixture.owner,
        "case-system",
        &directory,
        &AtomicBool::new(false),
    )
    .expect("the export is accepted");
    assert_eq!(exported.issuer, ISSUER);
    assert_eq!(exported.token_endpoint, format!("{ISSUER}/oauth2/token"));
    assert_eq!(
        private::read(&directory.join("client-id"), 4096).unwrap(),
        b"case-system"
    );
    private::check(&directory.join("assertion-key.jwk"), false).unwrap();
}

#[test]
fn every_client_is_exported_before_the_issuer_is_asked_for_its_keys() {
    let fixture = fixture();
    // Nothing listens on a port that was bound and released.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let failure = fixture.capture_failure(&format!("issuer=http://127.0.0.1:{port}\n{HONEST}"));
    assert_refused(&failure, "the borrowed issuer is unavailable");
    for client in ["case-system", "operations-console"] {
        assert!(fixture
            .root
            .join("credentials")
            .join(client)
            .join("client-id")
            .exists());
    }
    assert!(!fixture.snapshot().exists());
}

#[test]
fn bregctl_is_found_on_path_by_name() {
    let found = executable(Path::new("sh")).expect("sh is on PATH");
    assert!(found.is_absolute());
}

#[test]
fn a_bregctl_that_is_not_installed_is_refused_before_any_export() {
    let fixture = fixture();
    for bregctl in [
        PathBuf::from("bregctl-that-no-path-directory-holds"),
        fixture.owner.join("absent/bregctl"),
    ] {
        let failure = fixture
            .capture(&bregctl, &AtomicBool::new(false))
            .err()
            .expect("the capture does not succeed");
        assert_refused(
            &failure,
            "put the bregctl of this Registry Stack release on PATH",
        );
        // The operator is never pointed at an option the help does not list.
        assert!(!failure.message.contains("--"));
        assert!(!fixture.root.join("credentials").exists());
        assert!(!fixture.snapshot().exists());
    }
}

#[test]
fn a_bregctl_that_cannot_be_spawned_is_refused() {
    let fixture = fixture();
    let missing_interpreter = fixture.script("#!/nonexistent/interpreter\n");
    let not_executable = fixture.owner.join("bregctl");
    fs::write(
        &not_executable,
        format!("{PREAMBLE}issuer={ISSUER}\n{HONEST}\n"),
    )
    .unwrap();
    fs::set_permissions(&not_executable, fs::Permissions::from_mode(0o600)).unwrap();
    for bregctl in [missing_interpreter, not_executable] {
        let failure = fixture
            .capture(&bregctl, &AtomicBool::new(false))
            .err()
            .expect("the capture does not succeed");
        assert_refused(&failure, "bregctl could not run");
        assert!(fixture.exported_files().is_empty());
        assert!(!fixture.snapshot().exists());
    }
}

#[test]
fn a_non_zero_exit_is_refused_even_with_a_valid_report() {
    let fixture = fixture();
    let failure = fixture.capture_failure(&format!("{HONEST}\nexit 3"));
    assert_refused(&failure, "bregctl credential export failed or timed out");
    assert!(!fixture.snapshot().exists());
}

#[test]
fn a_bregctl_that_outlives_its_timeout_is_refused() {
    let fixture = fixture();
    let slow = fixture.script("#!/bin/sh\nexec sleep 60\n");
    let failure = public_command(
        &mut Command::new(slow),
        &AtomicBool::new(false),
        Duration::from_millis(200),
        REPORT_DRAIN,
    )
    .unwrap_err();
    assert_refused(&failure, "bregctl credential export failed or timed out");
}

#[test]
fn a_report_is_accepted_up_to_its_size_bound_and_refused_beyond_it() {
    let fixture = fixture();
    let limit = "dd if=/dev/zero bs=65536 count=1 2>/dev/null | tr '\\000' ' '";
    let exact = fixture.script(&format!("#!/bin/sh\n{limit}\n"));
    let bytes = public_command(
        &mut Command::new(exact),
        &AtomicBool::new(false),
        EXPORT_TIMEOUT,
        REPORT_DRAIN,
    )
    .unwrap();
    assert_eq!(bytes.len(), EXPORT_LIMIT);
    let oversized = fixture.script(&format!("#!/bin/sh\n{limit}\nprintf ' '\n"));
    let failure = public_command(
        &mut Command::new(oversized),
        &AtomicBool::new(false),
        EXPORT_TIMEOUT,
        REPORT_DRAIN,
    )
    .unwrap_err();
    assert_refused(&failure, "oversized or unreadable public report");
}

#[test]
fn a_report_held_open_after_bregctl_exits_is_refused_without_waiting_for_it() {
    let fixture = fixture();
    let holder = fixture.owner.join("holder");
    // A background process inherits the report pipe and outlives bregctl.
    for (exit, expected) in [
        (0, "oversized or unreadable public report"),
        (3, "bregctl credential export failed or timed out"),
    ] {
        let bregctl = fixture.script(&format!(
            "#!/bin/sh\nsleep 60 &\nprintf '%s' \"$!\" > '{}'\nprintf '{{}}\\n'\nexit {exit}\n",
            holder.display()
        ));
        let started = Instant::now();
        let failure = public_command(
            &mut Command::new(bregctl),
            &AtomicBool::new(false),
            EXPORT_TIMEOUT,
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert_refused(&failure, expected);
        assert!(started.elapsed() < Duration::from_secs(30));
        assert!(alive(&holder));
        rustix::process::kill_process(recorded(&holder), rustix::process::Signal::KILL).unwrap();
    }
}

#[test]
fn output_that_is_not_a_json_report_is_refused() {
    let fixture = fixture();
    for body in ["export_files", "export_files\nprintf 'exported\\n'"] {
        let failure = fixture.capture_failure(body);
        assert_refused(&failure, "no usable public credential report");
        assert!(!fixture.snapshot().exists());
    }
}

#[test]
fn a_report_that_is_not_ok_is_refused() {
    let fixture = fixture();
    let failure = fixture.capture_failure(&format!("ok=false\n{HONEST}"));
    assert_refused(&failure, "a different client or credential output");
    assert!(!fixture.snapshot().exists());
}

#[test]
fn a_report_naming_another_client_is_refused() {
    let fixture = fixture();
    let failure = fixture.capture_failure(&format!("reported_client=another-client\n{HONEST}"));
    assert_refused(&failure, "a different client or credential output");
    assert!(!fixture.snapshot().exists());
}

#[test]
fn a_report_naming_other_output_files_is_refused() {
    let fixture = fixture();
    for assignment in [
        "reported_id=$project/client-id",
        "reported_key=$project/assertion-key.jwk",
    ] {
        let failure = fixture.capture_failure(&format!("{assignment}\n{HONEST}"));
        assert_refused(&failure, "a different client or credential output");
        assert!(!fixture.snapshot().exists());
    }
}

#[test]
fn a_report_without_an_issuer_is_refused() {
    let fixture = fixture();
    let failure = fixture.capture_failure(
        r#"export_files
printf '{"ok":true,"client":"%s","clientIdFile":"%s","assertionKeyFile":"%s"}\n' "$client" "$id" "$key""#,
    );
    assert_refused(&failure, "the borrowed client could not authenticate");
    assert!(!fixture.snapshot().exists());
}

#[test]
fn an_issuer_that_is_not_one_exact_loopback_origin_is_refused() {
    let fixture = fixture();
    for issuer in [
        "http://localhost:18095",
        "http://192.0.2.1:18095",
        "http://[::1]:18095",
        "https://127.0.0.1:18095",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:018095",
        "http://127.0.0.1:18095/",
        "http://127.0.0.1:18095/realm",
        "http://127.0.0.1:65536",
    ] {
        let failure = fixture.capture_failure(&format!("issuer={issuer}\n{HONEST}"));
        assert_refused(&failure, "one exact numeric-loopback HTTP origin");
        assert!(!fixture.snapshot().exists(), "{issuer}");
    }
}

#[test]
fn a_token_endpoint_off_the_issuer_is_refused() {
    let fixture = fixture();
    for endpoint in ["http://127.0.0.1:18096/oauth2/token", "$issuer/token"] {
        let failure = fixture.capture_failure(&format!("token_endpoint={endpoint}\n{HONEST}"));
        assert_refused(&failure, "do not match the local issuer");
        assert!(!fixture.snapshot().exists());
    }
}

#[test]
fn an_assertion_audience_off_the_issuer_is_refused() {
    let fixture = fixture();
    for audience in ["http://127.0.0.1:18096", "$issuer/oauth2/token"] {
        let failure = fixture.capture_failure(&format!("audience={audience}\n{HONEST}"));
        assert_refused(&failure, "do not match the local issuer");
        assert!(!fixture.snapshot().exists());
    }
}

#[test]
fn an_exported_client_id_file_that_is_not_the_client_is_refused() {
    let fixture = fixture();
    for body in [
        // Never written.
        "report",
        // Written for another client.
        "export_files\nprintf another-client > \"$id\"\nreport",
        // Written for this client, readable by other users.
        "export_files\nchmod 644 \"$id\"\nreport",
    ] {
        let failure = fixture.capture_failure(body);
        assert_refused(&failure, "the borrowed client could not authenticate");
        assert!(!fixture.snapshot().exists());
    }
}

#[test]
fn clients_reporting_different_issuers_are_refused() {
    let fixture = fixture();
    let failure = fixture.capture_failure(&format!(
        "[ \"$client\" = case-system ] || issuer=http://127.0.0.1:18096\n{HONEST}"
    ));
    assert_refused(&failure, "the clients do not share one exact issuer");
    assert!(!fixture.snapshot().exists());
}

#[test]
fn an_issuer_project_that_cannot_be_read_is_refused_before_bregctl_runs() {
    let fixture = fixture();
    let ran = fixture.owner.join("ran");
    let bregctl = fixture.stand_in(&format!("touch \"$project/ran\"\n{HONEST}"));
    let failure = capture(
        &fixture.root,
        &fixture.loaded,
        &fixture.owner.join("absent"),
        RESOURCE,
        &bregctl,
        &AtomicBool::new(false),
    )
    .err()
    .expect("the capture does not succeed");
    assert_refused(&failure, "the issuer project cannot be read");
    assert!(!ran.exists());
    assert!(!fixture.root.join("credentials").exists());
}

#[test]
fn a_refused_borrow_records_no_issuer_and_starts_no_container() {
    let fixture = fixture();
    let bregctl = fixture.stand_in(&format!("issuer=http://192.0.2.1:18095\n{HONEST}"));
    let cli = Cli::try_parse_from([
        OsStr::new("messagingctl"),
        OsStr::new("dev"),
        fixture.project.as_os_str(),
        OsStr::new("--issuer-project"),
        fixture.owner.as_os_str(),
        OsStr::new("--resource"),
        OsStr::new(RESOURCE),
        OsStr::new("--bregctl-bin"),
        bregctl.as_os_str(),
    ])
    .unwrap();
    let crate::Command::Dev(args) = cli.command else {
        panic!("dev command");
    };
    let mut session = Session {
        root: fixture.root.clone(),
        owner: uuid::Uuid::new_v4().simple().to_string(),
        containers: Vec::new(),
        borrowed: None,
    };
    // A Docker call would fail as an operational failure naming Docker.
    let failure = run_session(
        &args.start,
        &fixture.loaded,
        &docker::Docker::new(PathBuf::from("/nonexistent/docker")),
        &mut session,
        &AtomicBool::new(false),
        OutputFormat::Json,
        &mut Vec::<u8>::new(),
        &mut Vec::<u8>::new(),
    )
    .unwrap_err();
    assert_refused(&failure, "one exact numeric-loopback HTTP origin");
    assert!(session.borrowed.is_none());
    assert!(session.containers.is_empty());
    let record = read_session(&fixture.root).unwrap();
    assert_eq!(record.state, "starting");
    assert!(record.borrowed_issuer.is_none());
    assert!(!fixture.snapshot().exists());
}

#[test]
fn a_refused_token_refresh_writes_no_header_and_keeps_no_scratch_copy() {
    let fixture = fixture();
    for (body, expected) in [
        (
            format!("issuer=http://127.0.0.1:18096\n{HONEST}"),
            "the borrowed issuer endpoints changed",
        ),
        (
            "exit 3".to_owned(),
            "bregctl credential export failed or timed out",
        ),
    ] {
        let failure = fixture.token_failure(fixture.stand_in(&body));
        assert_refused(&failure, expected);
        assert!(!fixture.root.join("tokens/case-system.header").exists());
        assert!(fixture.scratch_copies().is_empty());
    }
}

#[test]
fn a_token_refresh_refuses_credentials_that_differ_from_the_captured_ones() {
    let fixture = fixture();
    let retained = fixture.credentials("case-system");
    private::create(&retained.join("client-id"), b"case-system").unwrap();
    private::create(&retained.join("assertion-key.jwk"), b"captured, not a key").unwrap();
    let failure = fixture.token_failure(fixture.stand_in(HONEST));
    assert_refused(&failure, "the borrowed client credentials changed");
    assert!(!fixture.root.join("tokens/case-system.header").exists());
    assert!(fixture.scratch_copies().is_empty());
}

#[test]
fn a_token_refresh_for_a_client_the_session_did_not_capture_never_runs_bregctl() {
    let fixture = fixture();
    let ran = fixture.owner.join("ran");
    let bregctl = fixture.stand_in(&format!("touch \"$project/ran\"\n{HONEST}"));
    let binding = fixture.binding(bregctl);
    for client in ["operations-console", "a-client-no-profile-names"] {
        let Err(failure) = refresh(&fixture.root, &fixture.loaded, &binding, client) else {
            panic!("the token is not issued");
        };
        assert_eq!(failure.code, "dev.refused", "{}", failure.message);
        assert!(!ran.exists());
        assert!(fixture.scratch_copies().is_empty());
    }
}

#[test]
fn a_stop_request_before_the_export_never_runs_bregctl() {
    let fixture = fixture();
    let ran = fixture.owner.join("ran");
    let bregctl = fixture.stand_in(&format!("touch \"$project/ran\"\n{HONEST}"));
    let failure = fixture
        .capture(&bregctl, &AtomicBool::new(true))
        .err()
        .expect("the capture does not succeed");
    assert_eq!(failure.code, "dev.interrupted", "{}", failure.message);
    assert!(!ran.exists());
    assert!(fixture.exported_files().is_empty());
    assert!(!fixture.snapshot().exists());
}

#[test]
fn a_stop_request_during_the_export_stops_bregctl() {
    let fixture = fixture();
    let pid = fixture.owner.join("pid");
    let bregctl = fixture.stand_in("printf '%s' \"$$\" > \"$project/pid\"\nexec sleep 60");
    let stop = AtomicBool::new(false);
    let failure = std::thread::scope(|scope| {
        scope.spawn(|| {
            // The stand-in holds the export open until it is stopped; the
            // bound only ends a run in which it never started.
            let deadline = Instant::now() + Duration::from_secs(30);
            while fs::read(&pid).map_or(true, |bytes| bytes.is_empty()) && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            stop.store(true, Ordering::SeqCst);
        });
        fixture
            .capture(&bregctl, &stop)
            .err()
            .expect("the capture does not succeed")
    });
    assert_eq!(failure.code, "dev.interrupted", "{}", failure.message);
    assert!(!alive(&pid));
    assert!(fixture.exported_files().is_empty());
    assert!(!fixture.snapshot().exists());
}

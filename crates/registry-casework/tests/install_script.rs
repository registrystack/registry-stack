// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const TEST_VERSION: &str = "v9.8.7";
const BINARIES: [&str; 3] = ["casework", "caseworkctl", "mint"];

// Distinguishes fixture roots built within the same process. The wall clock alone is not
// enough: macOS reports CLOCK_REALTIME at 1 microsecond resolution, so two fixtures built in
// close succession within the same test binary can otherwise land on the same nanosecond
// reading and share a root.
static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn installer_switches_both_commands_through_one_toolset_pointer() {
    let fixture = InstallerFixture::new();

    let output = fixture.run(false);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_release_toolset_active();
    for binary in BINARIES {
        assert_eq!(
            fs::read_link(fixture.install_dir.join(binary)).unwrap(),
            PathBuf::from(format!(".casework-current/{binary}"))
        );
    }
    assert!(
        fs::symlink_metadata(fixture.install_dir.join(".casework-current"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    fixture.assert_active_toolset_is_traversable();
}

#[test]
fn failed_atomic_pointer_switch_preserves_the_previous_toolset() {
    let fixture = InstallerFixture::new();
    fixture.preinstall_previous_toolset();

    let output = fixture.run(true);
    assert!(!output.status.success());
    for binary in BINARIES {
        assert_eq!(
            fs::read_to_string(fixture.install_dir.join(binary)).unwrap(),
            format!("{binary} previous binary\n")
        );
    }
    fixture.assert_active_toolset_is_traversable();
}

#[test]
fn failed_atomic_pointer_switch_preserves_a_command_the_pointer_does_not_carry() {
    let fixture = InstallerFixture::new();
    fixture.preinstall_pointer_toolset_without_mint();

    // The pointer is already a symbolic link, so no migration precedes the
    // switch and the switch is the first rename onto it.
    let output = fixture.run_failing_pointer_switch(1);

    assert!(!output.status.success());
    for binary in BINARIES {
        assert_eq!(
            fs::read_to_string(fixture.install_dir.join(binary)).unwrap(),
            format!("{binary} previous binary\n"),
            "{binary} must still resolve to the file it resolved to before"
        );
    }
}

#[test]
fn failed_atomic_pointer_switch_preserves_bregs_mint_link() {
    let fixture = InstallerFixture::new();
    fixture.preinstall_casework_with_breg_mint();
    let mint_link = fixture.install_dir.join("mint");
    let previous_mint_target = fs::read_link(&mint_link).unwrap();
    assert_eq!(previous_mint_target, PathBuf::from(".breg-current/mint"));
    let previous_casework_target =
        fs::read_link(fixture.install_dir.join(".casework-current")).unwrap();

    // The pointer is already a symbolic link, so the injected failure is the
    // first rename onto it.
    let output = fixture.run_failing_pointer_switch(1);

    assert!(!output.status.success());
    assert_eq!(fs::read_link(&mint_link).unwrap(), previous_mint_target);
    assert_eq!(
        fs::read_to_string(&mint_link).unwrap(),
        "mint other product binary\n"
    );
    assert_eq!(
        fs::read_link(fixture.install_dir.join(".casework-current")).unwrap(),
        previous_casework_target
    );
}

#[test]
fn successful_pointer_switch_adopts_another_products_mint_link() {
    let fixture = InstallerFixture::new();
    fixture.preinstall_casework_with_breg_mint();

    let output = fixture.run(false);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_release_toolset_active();
    assert_eq!(
        fs::read_link(fixture.install_dir.join("mint")).unwrap(),
        PathBuf::from(".casework-current/mint")
    );
}

#[test]
fn failed_post_switch_adoption_restores_every_changed_command_and_pointer() {
    for signal in [None, Some(("INT", 130)), Some(("TERM", 143))] {
        let fixture = InstallerFixture::new();
        fixture.preinstall_casework_with_breg_mint();
        let caseworkctl = fixture.install_dir.join("caseworkctl");
        fs::remove_file(&caseworkctl).unwrap();
        fs::write(&caseworkctl, "caseworkctl local wrapper\n").unwrap();
        fs::set_permissions(&caseworkctl, fs::Permissions::from_mode(0o740)).unwrap();
        let previous_casework_target =
            fs::read_link(fixture.install_dir.join(".casework-current")).unwrap();
        let previous_mint_target = fs::read_link(fixture.install_dir.join("mint")).unwrap();
        let previous_caseworkctl_mode = fs::metadata(&caseworkctl).unwrap().permissions().mode();

        // `caseworkctl` is adopted first. The injected second adoption moves
        // the staged `mint` link into place and then either reports failure or
        // terminates the installer, so both EXIT paths must roll back.
        let output = match signal {
            Some((name, _)) => fixture.run_signalled_command_adoption(2, name),
            None => fixture.run_failing_command_adoption(2),
        };

        assert!(!output.status.success());
        if let Some((_, code)) = signal {
            assert_eq!(output.status.code(), Some(code));
        }
        assert_eq!(
            fs::read_link(fixture.install_dir.join(".casework-current")).unwrap(),
            previous_casework_target
        );
        assert_eq!(
            fs::read_to_string(fixture.install_dir.join("casework")).unwrap(),
            "casework previous binary\n"
        );
        assert!(!caseworkctl.is_symlink());
        assert_eq!(
            fs::read(&caseworkctl).unwrap(),
            b"caseworkctl local wrapper\n"
        );
        assert_eq!(
            fs::metadata(&caseworkctl).unwrap().permissions().mode(),
            previous_caseworkctl_mode
        );
        assert_eq!(
            fs::read_link(fixture.install_dir.join("mint")).unwrap(),
            previous_mint_target
        );
        assert_eq!(
            fs::read_to_string(fixture.install_dir.join("mint")).unwrap(),
            "mint other product binary\n"
        );
    }
}

#[test]
fn a_command_the_pointer_does_not_carry_is_adopted_after_the_switch() {
    let fixture = InstallerFixture::new();
    fixture.preinstall_pointer_toolset_without_mint();

    let output = fixture.run(false);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_release_toolset_active();
    assert!(
        fixture.install_dir.join("mint").is_symlink(),
        "an adopted command must become a stable command link"
    );
}

#[test]
fn musl_system_refuses_before_installing() {
    let fixture = InstallerFixture::linux();
    let mut command = fixture.command();
    command.env("FAKE_LIBC_MUSL", "1");
    let output = command.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No musl build of Registry Casework is published"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("container images"), "stderr: {stderr}");
    assert!(
        !fixture.install_dir.exists(),
        "nothing may reach the install directory"
    );
}

#[test]
fn glibc_below_the_floor_refuses_before_installing() {
    let (major, minor) = glibc_floor();
    let fixture = InstallerFixture::linux();
    let mut command = fixture.command();
    command.env("FAKE_GLIBC", format!("{major}.{}", minor - 1));
    let output = command.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("This system has GNU libc {major}.{}", minor - 1)),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!("need {major}.{minor} or newer")),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("Nothing was installed"), "stderr: {stderr}");
    assert!(
        !fixture.install_dir.exists(),
        "nothing may reach the install directory"
    );
}

#[test]
fn glibc_at_the_floor_installs_both_commands() {
    let (major, minor) = glibc_floor();
    let fixture = InstallerFixture::linux();
    let mut command = fixture.command();
    command.env("FAKE_GLIBC", format!("{major}.{minor}"));
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_release_toolset_active();
}

#[test]
fn installer_carries_the_shared_glibc_floor() {
    let (major, minor) = glibc_floor();
    let source = fs::read_to_string(installer_path()).unwrap();
    assert!(
        source.contains(&format!("libc_floor=\"{major}.{minor}\"")),
        "install.sh must carry the generated floor from release/glibc-floor.env"
    );
    assert!(
        source.contains("BEGIN generated libc preflight"),
        "install.sh must carry the generated preflight block"
    );
}

struct InstallerFixture {
    root: PathBuf,
    release_dir: PathBuf,
    install_dir: PathBuf,
    fake_bin: PathBuf,
    asset_suffix: String,
    forced_uname: Option<(String, String)>,
}

impl InstallerFixture {
    fn new() -> Self {
        Self::build(None)
    }

    /// A fixture that presents a Linux host whatever the workstation runs, so
    /// the Linux-only libc preflight is exercised on macOS as well.
    fn linux() -> Self {
        Self::build(Some(("Linux".to_owned(), "x86_64".to_owned())))
    }

    fn build(forced_uname: Option<(String, String)>) -> Self {
        let unique = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "registry-casework-installer-test-{}-{unique}",
            std::process::id()
        ));
        let release_dir = root.join("release");
        let install_dir = root.join("install");
        let fake_bin = root.join("fake-bin");
        fs::create_dir_all(&release_dir).unwrap();
        fs::create_dir_all(&fake_bin).unwrap();
        // The platform and the libc preflight are read through these three
        // commands. Faking all of them keeps the test identical on a macOS
        // workstation and on a Linux runner, where the real ones differ.
        write_executable(
            &fake_bin.join("uname"),
            r#"#!/usr/bin/env bash
case "${1:-}" in
  -s) printf '%s\n' "${FAKE_UNAME_S:-$(/usr/bin/uname -s)}" ;;
  -m) printf '%s\n' "${FAKE_UNAME_M:-$(/usr/bin/uname -m)}" ;;
  *) exec /usr/bin/uname "$@" ;;
esac
"#,
        );
        write_executable(
            &fake_bin.join("getconf"),
            r#"#!/usr/bin/env bash
if [[ "${1:-}" == GNU_LIBC_VERSION && "${FAKE_LIBC_MUSL:-0}" -ne 1 ]]; then
  printf 'glibc %s\n' "${FAKE_GLIBC:-2.41}"
  exit 0
fi
exit 1
"#,
        );
        write_executable(
            &fake_bin.join("ldd"),
            r#"#!/usr/bin/env bash
if [[ "${FAKE_LIBC_MUSL:-0}" -eq 1 ]]; then
  printf 'musl libc (x86_64)\n' >&2
  printf 'Version 1.2.5\n' >&2
  exit 1
fi
printf 'ldd (GNU libc) %s\n' "${FAKE_GLIBC:-2.41}"
"#,
        );
        let asset_suffix = match &forced_uname {
            Some(_) => "linux-amd64".to_owned(),
            None => platform_suffix().to_owned(),
        };
        if forced_uname.is_some() {
            // A forced Linux run reaches the installer's GNU pointer switch,
            // which asks for mv -T. A macOS workstation spells that same
            // guarantee mv -h, so translate it there and pass it through
            // untouched on a Linux runner.
            write_executable(
                &fake_bin.join("mv"),
                r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$(/usr/bin/uname -s)" != Darwin ]]; then
  exec /bin/mv "$@"
fi
arguments=()
for argument in "$@"; do
  case "$argument" in
    -Tf | -fT) arguments+=(-f -h) ;;
    -T) arguments+=(-h) ;;
    *) arguments+=("$argument") ;;
  esac
done
exec /bin/mv "${arguments[@]}"
"#,
            );
        }
        let fixture = Self {
            root,
            release_dir,
            install_dir,
            fake_bin,
            asset_suffix,
            forced_uname,
        };
        fixture.write_release_assets();
        fixture
    }

    fn write_release_assets(&self) {
        let suffix = &self.asset_suffix;
        let mut sums = String::new();
        for binary in BINARIES {
            let asset = format!("{binary}-{TEST_VERSION}-{suffix}");
            let path = self.release_dir.join(&asset);
            fs::write(&path, format!("{binary} release binary\n")).unwrap();
            sums.push_str(&format!("{}  {asset}\n", sha256(&path)));
        }
        fs::write(self.release_dir.join("SHA256SUMS"), sums).unwrap();
    }

    fn preinstall_previous_toolset(&self) {
        fs::create_dir_all(&self.install_dir).unwrap();
        for binary in BINARIES {
            fs::write(
                self.install_dir.join(binary),
                format!("{binary} previous binary\n"),
            )
            .unwrap();
        }
    }

    /// A machine an earlier toolset installed through the pointer, carrying a
    /// `mint` that another product's installer wrote directly. The pointer is
    /// already a symbolic link, so the one-time migration does not run.
    fn preinstall_pointer_toolset_without_mint(&self) {
        let toolset = self.install_dir.join(".casework-toolset.earlier");
        fs::create_dir_all(&toolset).unwrap();
        for binary in ["casework", "caseworkctl"] {
            let path = toolset.join(binary);
            fs::write(&path, format!("{binary} previous binary\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            std::os::unix::fs::symlink(
                format!(".casework-current/{binary}"),
                self.install_dir.join(binary),
            )
            .unwrap();
        }
        std::os::unix::fs::symlink(
            ".casework-toolset.earlier",
            self.install_dir.join(".casework-current"),
        )
        .unwrap();
        fs::write(self.install_dir.join("mint"), "mint previous binary\n").unwrap();
    }

    /// An existing Casework toolset that carries `mint`, while another product
    /// owns the public shared `mint` command through its own toolset pointer.
    fn preinstall_casework_with_breg_mint(&self) {
        let casework_toolset = self.install_dir.join(".casework-toolset.earlier");
        let breg_toolset = self.install_dir.join(".breg-toolset.earlier");
        fs::create_dir_all(&casework_toolset).unwrap();
        fs::create_dir_all(&breg_toolset).unwrap();
        for binary in BINARIES {
            let path = casework_toolset.join(binary);
            fs::write(&path, format!("{binary} previous binary\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let breg_mint = breg_toolset.join("mint");
        fs::write(&breg_mint, "mint other product binary\n").unwrap();
        fs::set_permissions(&breg_mint, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(
            ".casework-toolset.earlier",
            self.install_dir.join(".casework-current"),
        )
        .unwrap();
        for binary in ["casework", "caseworkctl"] {
            std::os::unix::fs::symlink(
                format!(".casework-current/{binary}"),
                self.install_dir.join(binary),
            )
            .unwrap();
        }
        std::os::unix::fs::symlink(
            ".breg-toolset.earlier",
            self.install_dir.join(".breg-current"),
        )
        .unwrap();
        std::os::unix::fs::symlink(".breg-current/mint", self.install_dir.join("mint")).unwrap();
    }

    fn command(&self) -> Command {
        let path = format!(
            "{}:{}",
            self.fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut command = Command::new("bash");
        command
            .arg(installer_path())
            .env("PATH", path)
            .env("CASEWORK_VERSION", TEST_VERSION)
            .env("CASEWORK_ASSET_DIR", &self.release_dir)
            .env("CASEWORK_INSTALL_DIR", &self.install_dir);
        if let Some((system, machine)) = &self.forced_uname {
            command
                .env("FAKE_UNAME_S", system)
                .env("FAKE_UNAME_M", machine);
        }
        command
    }

    fn run(&self, fail_final_pointer_switch: bool) -> Output {
        if fail_final_pointer_switch {
            // Migrating direct binaries renames the pointer once before the
            // switch, so on such a fixture the switch is the second rename.
            return self.run_failing_pointer_switch(2);
        }
        self.command().output().unwrap()
    }

    /// Runs an install whose `nth` rename onto the toolset pointer fails.
    fn run_failing_pointer_switch(&self, nth: u32) -> Output {
        self.install_failing_mv();
        self.command()
            .env("REAL_MV", "/bin/mv")
            .env("FAKE_MV_COUNT", self.root.join("mv-count"))
            .env("FAKE_MV_FAIL_AT", nth.to_string())
            .output()
            .unwrap()
    }

    /// Runs an install whose `nth` post-pointer command adoption moves the new
    /// link into place and then reports failure.
    fn run_failing_command_adoption(&self, nth: u32) -> Output {
        self.install_failing_mv();
        self.command()
            .env("REAL_MV", "/bin/mv")
            .env("FAKE_MV_COMMAND_COUNT", self.root.join("mv-command-count"))
            .env("FAKE_MV_COMMAND_FAIL_AT", nth.to_string())
            .output()
            .unwrap()
    }

    /// Runs an install terminated immediately after the `nth` post-pointer
    /// command adoption has moved the new link into place.
    fn run_signalled_command_adoption(&self, nth: u32, signal: &str) -> Output {
        self.install_failing_mv();
        self.command()
            .env("REAL_MV", "/bin/mv")
            .env("FAKE_MV_COMMAND_COUNT", self.root.join("mv-command-count"))
            .env("FAKE_MV_COMMAND_SIGNAL_AT", nth.to_string())
            .env("FAKE_MV_COMMAND_SIGNAL", signal)
            .output()
            .unwrap()
    }

    fn install_failing_mv(&self) {
        write_executable(
            &self.fake_bin.join("mv"),
            r#"#!/usr/bin/env bash
set -euo pipefail
destination="${@: -1}"
if [[ "$destination" == */.casework-current && -n "${FAKE_MV_FAIL_AT:-}" ]]; then
  count=0
  if [[ -f "$FAKE_MV_COUNT" ]]; then
    read -r count < "$FAKE_MV_COUNT"
  fi
  count=$((count + 1))
  printf '%s\n' "$count" > "$FAKE_MV_COUNT"
  if [[ "$count" -eq "$FAKE_MV_FAIL_AT" ]]; then
    exit 73
  fi
fi
if [[ "$destination" != */.casework-current &&
      ( -n "${FAKE_MV_COMMAND_FAIL_AT:-}" || -n "${FAKE_MV_COMMAND_SIGNAL_AT:-}" ) ]]; then
  count=0
  if [[ -f "$FAKE_MV_COMMAND_COUNT" ]]; then
    read -r count < "$FAKE_MV_COMMAND_COUNT"
  fi
  count=$((count + 1))
  printf '%s\n' "$count" > "$FAKE_MV_COMMAND_COUNT"
  if [[ "$count" -eq "${FAKE_MV_COMMAND_FAIL_AT:-0}" ]]; then
    "$REAL_MV" "$@"
    exit 73
  fi
  if [[ "$count" -eq "${FAKE_MV_COMMAND_SIGNAL_AT:-0}" ]]; then
    "$REAL_MV" "$@"
    kill -s "$FAKE_MV_COMMAND_SIGNAL" "$PPID"
    exit 0
  fi
fi
exec "$REAL_MV" "$@"
"#,
        );
    }

    fn assert_release_toolset_active(&self) {
        for binary in BINARIES {
            assert_eq!(
                fs::read_to_string(self.install_dir.join(binary)).unwrap(),
                format!("{binary} release binary\n")
            );
        }
    }

    fn assert_active_toolset_is_traversable(&self) {
        let permissions = fs::metadata(self.install_dir.join(".casework-current"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(permissions & 0o111, 0o111);
    }
}

impl Drop for InstallerFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn installer_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh")
}

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn platform_suffix() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-amd64",
        ("linux", "aarch64") => "linux-arm64",
        ("macos", "aarch64") => "macos-arm64",
        platform => panic!("installer test runs on a supported platform, got {platform:?}"),
    }
}

fn sha256(path: &Path) -> String {
    for (program, args) in [("shasum", &["-a", "256"][..]), ("sha256sum", &[][..])] {
        if let Ok(output) = Command::new(program).args(args).arg(path).output() {
            if output.status.success() {
                return String::from_utf8(output.stdout)
                    .unwrap()
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .to_owned();
            }
        }
    }
    panic!("installer test needs shasum or sha256sum");
}

/// The single home of the floor, read rather than repeated, so a change to
/// release/glibc-floor.env has to travel through the generator to reach here.
fn glibc_floor() -> (u32, u32) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../release/glibc-floor.env");
    let text = fs::read_to_string(&path).unwrap();
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix("REGISTRY_GLIBC_FLOOR="))
        .expect("release/glibc-floor.env declares REGISTRY_GLIBC_FLOOR");
    let (major, minor) = value.trim().split_once('.').unwrap();
    (major.parse().unwrap(), minor.parse().unwrap())
}

// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

const TEST_RELEASE: &str = "v9.8.7";

#[test]
fn help_does_not_require_home() {
    let output = Command::new("bash")
        .arg(installer_path())
        .arg("--help")
        .env_remove("HOME")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("--install-root DIR"));
}

#[test]
fn explicit_install_paths_do_not_require_home() {
    let fixture = InstallerFixture::new();
    let output = fixture.command().output().unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let arguments = fs::read_to_string(&fixture.arguments).unwrap();
    assert!(
        arguments.contains(&format!("--bin-dir\n{}\n", fixture.bin_dir.display())),
        "launcher arguments: {arguments}"
    );
    assert!(
        arguments.contains(&format!(
            "--install-root\n{}\n",
            fixture.install_root.display()
        )),
        "launcher arguments: {arguments}"
    );
}

struct InstallerFixture {
    _temp: TempDir,
    assets: PathBuf,
    tools: PathBuf,
    arguments: PathBuf,
    bin_dir: PathBuf,
    install_root: PathBuf,
}

impl InstallerFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let assets = temp.path().join("assets");
        let tools = temp.path().join("tools");
        let archive_root = temp.path().join("archive");
        fs::create_dir_all(&assets).unwrap();
        fs::create_dir_all(&tools).unwrap();
        fs::create_dir_all(&archive_root).unwrap();

        write_executable(
            &tools.join("uname"),
            "#!/bin/sh\ncase \"$1\" in -s) printf 'Darwin\\n' ;; -m) printf 'arm64\\n' ;; *) exit 1 ;; esac\n",
        );
        write_executable(
            &tools.join("shasum"),
            &format!(
                "#!/bin/sh\ncase \"$3\" in *release-manifest.json) printf '{}  %s\\n' \"$3\" ;; *rstack-{TEST_RELEASE}-macos-arm64.tar.gz) printf '{}  %s\\n' \"$3\" ;; *) exit 1 ;; esac\n",
                "a".repeat(64),
                "b".repeat(64),
            ),
        );

        let launcher_name = format!("rstack-{TEST_RELEASE}-macos-arm64");
        let launcher = archive_root.join(&launcher_name);
        write_executable(
            &launcher,
            "#!/bin/sh\nif [ \"${1:-}\" = --version ]; then printf 'rstack 9.8.7\\n'; exit 0; fi\nprintf '%s\\n' \"$@\" > \"${RSTACK_TEST_ARGUMENTS:?}\"\n",
        );
        fs::write(archive_root.join("THIRD_PARTY_NOTICES"), "test notices\n").unwrap();
        fs::write(
            archive_root.join("libaws_lc_fips_test.dylib"),
            "test module\n",
        )
        .unwrap();
        let archive = assets.join(format!("{launcher_name}.tar.gz"));
        let status = Command::new("tar")
            .args(["-czf"])
            .arg(&archive)
            .arg("-C")
            .arg(&archive_root)
            .args([
                &launcher_name,
                "THIRD_PARTY_NOTICES",
                "libaws_lc_fips_test.dylib",
            ])
            .status()
            .unwrap();
        assert!(status.success());

        let manifest_name = format!("registry-stack-{TEST_RELEASE}-release-manifest.json");
        fs::write(assets.join(&manifest_name), "{}\n").unwrap();
        fs::write(
            assets.join("SHA256SUMS"),
            format!(
                "{}  {manifest_name}\n{}  {launcher_name}.tar.gz\n",
                "a".repeat(64),
                "b".repeat(64),
            ),
        )
        .unwrap();

        let arguments = temp.path().join("arguments");
        let bin_dir = temp.path().join("public-bin");
        let install_root = temp.path().join("install-root");
        Self {
            _temp: temp,
            assets,
            tools,
            arguments,
            bin_dir,
            install_root,
        }
    }

    fn command(&self) -> Command {
        let mut paths = vec![self.tools.clone()];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let mut command = Command::new("bash");
        command
            .arg(installer_path())
            .args(["--release", TEST_RELEASE, "--asset-dir"])
            .arg(&self.assets)
            .arg("--bin-dir")
            .arg(&self.bin_dir)
            .arg("--install-root")
            .arg(&self.install_root)
            .env("PATH", std::env::join_paths(paths).unwrap())
            .env("RSTACK_TEST_ARGUMENTS", &self.arguments)
            .env_remove("HOME")
            .env_remove("RSTACK_RELEASE");
        command
    }
}

fn installer_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh")
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

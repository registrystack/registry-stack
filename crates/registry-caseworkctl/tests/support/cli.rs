// SPDX-License-Identifier: Apache-2.0

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

pub(crate) fn caseworkctl(arguments: &[&str]) -> Output {
    let dependencies = dependency_directory();
    let candidate = std::env::var_os("CASEWORKCTL_BIN")
        .or_else(|| option_env!("CARGO_BIN_EXE_caseworkctl").map(std::ffi::OsString::from))
        .expect("CASEWORKCTL_BIN must name the candidate outside the caseworkctl crate");
    let mut command = Command::new(candidate);
    command.args(arguments);
    configure_library_path(&mut command, &dependencies);
    command.output().expect("caseworkctl starts")
}

pub(crate) fn dependency_directory() -> PathBuf {
    std::env::current_exe()
        .expect("test executable is known")
        .parent()
        .expect("test executable has a dependency directory")
        .to_owned()
}

pub(crate) fn configure_library_path(command: &mut Command, dependencies: &Path) {
    #[cfg(target_os = "macos")]
    {
        use std::fs;

        let mut paths = vec![dependencies.to_owned()];
        if let Some(debug) = dependencies.parent() {
            let build = debug.join("build");
            if let Ok(entries) = fs::read_dir(build) {
                let mut artifacts = entries
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with("aws-lc-fips-sys-")
                    })
                    .map(|entry| entry.path().join("out/build/artifacts"))
                    .filter(|directory| {
                        fs::read_dir(directory).is_ok_and(|files| {
                            files.filter_map(Result::ok).any(|file| {
                                let name = file.file_name();
                                let name = name.to_string_lossy();
                                name.starts_with("libaws_lc_fips_")
                                    && name.ends_with("_crypto.dylib")
                            })
                        })
                    })
                    .collect::<Vec<_>>();
                artifacts.sort();
                paths.extend(artifacts);
            }
        }
        command.env(
            "DYLD_LIBRARY_PATH",
            std::env::join_paths(paths).expect("dynamic library paths are valid"),
        );
    }
    #[cfg(target_os = "linux")]
    command.env("LD_LIBRARY_PATH", dependencies);
}

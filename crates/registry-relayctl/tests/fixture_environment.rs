// SPDX-License-Identifier: Apache-2.0

#[cfg(unix)]
mod unix {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        os::unix::fs::PermissionsExt as _,
        path::{Path, PathBuf},
        process::{Command, Output},
    };

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, current: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(current).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    visit(root, &entry.path(), files);
                } else {
                    files.insert(
                        entry.path().strip_prefix(root).unwrap().to_path_buf(),
                        fs::read(entry.path()).unwrap(),
                    );
                }
            }
        }

        let mut files = BTreeMap::new();
        visit(root, root, &mut files);
        files
    }

    fn relayctl_test(
        project: &Path,
        temporary_directory: Option<&Path>,
    ) -> std::io::Result<Output> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_relayctl"));
        command
            .args(["--json", "test"])
            .arg(project)
            .args(["--fixture", "identifier-read"])
            .env_remove("TMPDIR");
        if let Some(temporary_directory) = temporary_directory {
            command.env("TMPDIR", temporary_directory);
        }
        command.output()
    }

    #[test]
    fn fixture_testing_ignores_ambient_temp_configuration_and_leaves_no_residue() {
        let workspace = tempfile::tempdir().unwrap();
        let projects = workspace.path().join("projects");
        let ambient = workspace.path().join("ambient");
        fs::create_dir(&projects).unwrap();
        fs::create_dir(&ambient).unwrap();
        let first_ambient = ambient.join("first");
        let second_ambient = ambient.join("second");
        fs::create_dir(&first_ambient).unwrap();
        fs::create_dir(&second_ambient).unwrap();

        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/relay-v2/acceptance/business-registry");
        let project = projects.join("authoring");
        copy_tree(&source, &project);
        let before = snapshot(&project);

        let original_mode = fs::metadata(&project).unwrap().permissions().mode() & 0o777;
        fs::set_permissions(&project, fs::Permissions::from_mode(0o555)).unwrap();
        let attempts = [
            relayctl_test(&project, None),
            relayctl_test(&project, Some(&ambient.join("missing"))),
            relayctl_test(&project, Some(&first_ambient)),
            relayctl_test(&project, Some(&second_ambient)),
        ];
        fs::set_permissions(&project, fs::Permissions::from_mode(original_mode)).unwrap();

        let outputs = attempts.into_iter().map(Result::unwrap).collect::<Vec<_>>();
        let expected = &outputs[0].stdout;
        for output in &outputs {
            assert!(output.status.success(), "{:?}", output.stderr);
            assert!(output.stderr.is_empty());
            assert_eq!(&output.stdout, expected);
        }

        assert_eq!(snapshot(&project), before);
        assert!(!project.join("fixture.sqlite").exists());
        assert!(!project.join("audit.jsonl").exists());
        assert!(fs::read_dir(&first_ambient).unwrap().next().is_none());
        assert!(fs::read_dir(&second_ambient).unwrap().next().is_none());
        assert!(!ambient.join("missing").exists());
        assert_eq!(
            fs::read_dir(&projects)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([project.file_name().unwrap().to_owned()])
        );
    }
}

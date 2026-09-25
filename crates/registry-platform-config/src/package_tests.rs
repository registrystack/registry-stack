use std::fs;
use std::path::Path;

use super::*;
use crate::blocks::PackageConfig;

const FIX: &str = "examplectl package";

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("parent")).expect("directories");
    fs::write(path, bytes).expect("file");
}

fn populated() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temporary directory");
    write(directory.path(), "policy.yaml", b"name: example\n");
    write(directory.path(), "rules/b.rhai", b"let b = 2;\n");
    write(directory.path(), "rules/a.rhai", b"let a = 1;\n");
    directory
}

fn packaged(revision: Option<&str>) -> (tempfile::TempDir, VerifiedPackage) {
    let directory = populated();
    let package = write_sum_file(directory.path(), revision, &PackageLimits::default(), FIX)
        .expect("the package is written");
    (directory, package)
}

fn verify(root: &Path) -> Result<VerifiedPackage, PackageError> {
    verify_package(root, &PackageLimits::default(), FIX)
}

#[test]
fn the_sum_file_lists_every_file_sorted_in_the_sha256sum_format() {
    let (directory, package) = packaged(None);
    let sums = fs::read_to_string(directory.path().join(SUM_FILE)).expect("sum file");
    let expected = format!(
        "{}  policy.yaml\n{}  rules/a.rhai\n{}  rules/b.rhai\n",
        hex(b"name: example\n"),
        hex(b"let a = 1;\n"),
        hex(b"let b = 2;\n"),
    );
    assert_eq!(sums, expected);
    assert_eq!(package.digest(), crate::sha256_uri(expected.as_bytes()));
    assert_eq!(package.revision(), None);
    assert_eq!(
        package.files().collect::<Vec<_>>(),
        ["policy.yaml", "rules/a.rhai", "rules/b.rhai"]
    );
}

#[test]
fn packaging_the_same_content_twice_gives_the_same_digest() {
    let (_first, first) = packaged(Some("release 7"));
    let (_second, second) = packaged(Some("release 7"));
    assert_eq!(first.digest(), second.digest());
    let (_other, other) = packaged(Some("release 8"));
    assert_ne!(first.digest(), other.digest());
    let (_none, none) = packaged(None);
    assert_ne!(first.digest(), none.digest());
}

#[test]
fn the_revision_is_recorded_as_a_hashed_file_and_read_back() {
    let (directory, package) = packaged(Some("0123abcd"));
    assert_eq!(
        fs::read(directory.path().join(REVISION_FILE)).expect("revision"),
        b"0123abcd\n"
    );
    assert_eq!(package.revision(), Some("0123abcd"));
    let verified = verify(directory.path()).expect("the package verifies");
    assert_eq!(verified.revision(), Some("0123abcd"));
    assert_eq!(verified.digest(), package.digest());
    assert!(verified.files().any(|path| path == REVISION_FILE));
}

#[test]
fn a_verified_package_reports_the_digest_the_writer_reported() {
    let (directory, package) = packaged(None);
    let verified = verify(directory.path()).expect("the package verifies");
    assert_eq!(verified, package);
}

#[test]
fn a_changed_file_is_refused_by_name() {
    let (directory, _) = packaged(None);
    write(directory.path(), "rules/a.rhai", b"let a = 3;\n");
    let error = verify(directory.path()).expect_err("a changed file");
    assert_eq!(
        error.kind(),
        &PackageErrorKind::Mismatch {
            changed: vec!["rules/a.rhai".to_owned()],
            missing: Vec::new(),
            extra: Vec::new(),
        }
    );
    let message = error.to_string();
    assert!(message.contains("changed: rules/a.rhai"), "{message}");
    assert!(message.contains("SHA256SUMS"), "{message}");
    assert!(message.contains(FIX), "{message}");
}

#[test]
fn a_missing_file_is_refused_by_name() {
    let (directory, _) = packaged(None);
    fs::remove_file(directory.path().join("rules/b.rhai")).expect("remove");
    let error = verify(directory.path()).expect_err("a missing file");
    assert_eq!(
        error.kind(),
        &PackageErrorKind::Mismatch {
            changed: Vec::new(),
            missing: vec!["rules/b.rhai".to_owned()],
            extra: Vec::new(),
        }
    );
    assert!(error.to_string().contains("missing: rules/b.rhai"));
}

#[test]
fn an_extra_file_or_empty_directory_is_refused_by_name() {
    let (directory, _) = packaged(None);
    write(directory.path(), "rules/.DS_Store", b"x");
    fs::create_dir(directory.path().join("empty")).expect("directory");
    let error = verify(directory.path()).expect_err("extra entries");
    assert_eq!(
        error.kind(),
        &PackageErrorKind::Mismatch {
            changed: Vec::new(),
            missing: Vec::new(),
            extra: vec!["empty/".to_owned(), "rules/.DS_Store".to_owned()],
        }
    );
    assert!(error.to_string().contains("extra: empty/, rules/.DS_Store"));
}

#[test]
fn every_discrepancy_is_reported_together() {
    let (directory, _) = packaged(None);
    write(directory.path(), "policy.yaml", b"name: other\n");
    fs::remove_file(directory.path().join("rules/a.rhai")).expect("remove");
    write(directory.path(), "notes.txt", b"x");
    let error = verify(directory.path()).expect_err("three discrepancies");
    let message = error.to_string();
    assert!(message.contains("changed: policy.yaml"), "{message}");
    assert!(message.contains("missing: rules/a.rhai"), "{message}");
    assert!(message.contains("extra: notes.txt"), "{message}");
}

#[test]
fn a_directory_without_a_sum_file_is_refused_with_the_package_command() {
    let directory = populated();
    let error = verify(directory.path()).expect_err("no sum file");
    assert_eq!(error.kind(), &PackageErrorKind::SumFileMissing);
    assert!(error.to_string().contains(FIX));
    let absent = directory.path().join("absent");
    let error = verify(&absent).expect_err("no package directory");
    assert!(matches!(error.kind(), PackageErrorKind::RootInvalid { .. }));
    assert!(error.to_string().contains(FIX));
}

#[test]
fn a_malformed_sum_file_is_refused_with_its_line() {
    for (sums, line) in [
        ("not a sum line\n".to_owned(), 1),
        (format!("{}  a\n{}  a\n", "0".repeat(64), "0".repeat(64)), 2),
        (format!("{}  b\n{}  a\n", "0".repeat(64), "0".repeat(64)), 2),
        (format!("{}  a", "0".repeat(64)), 1),
        (format!("{}  a\r\n", "0".repeat(64)), 1),
        (format!("{} *a\n", "0".repeat(64)), 1),
        (format!("{}  a\n", "A".repeat(64)), 1),
        (format!("{}  ../a\n", "0".repeat(64)), 1),
        (format!("{}  /a\n", "0".repeat(64)), 1),
        (format!("{}  SHA256SUMS\n", "0".repeat(64)), 1),
        (String::new(), 1),
    ] {
        let directory = populated();
        fs::write(directory.path().join(SUM_FILE), &sums).expect("sum file");
        let error = verify(directory.path()).expect_err("a malformed sum file");
        match error.kind() {
            PackageErrorKind::SumFileInvalid { line: found, .. } => {
                assert_eq!(*found, line, "{sums:?}");
            }
            other => panic!("{sums:?} gave {other:?}"),
        }
        assert!(error.to_string().contains(FIX));
    }
}

#[test]
fn an_invalid_revision_file_is_refused() {
    let (directory, _) = packaged(None);
    fs::remove_file(directory.path().join(SUM_FILE)).expect("remove");
    fs::write(directory.path().join(REVISION_FILE), b"two\nlines\n").expect("revision");
    let error = write_sum_file(directory.path(), None, &PackageLimits::default(), FIX)
        .expect_err("REVISION is reserved");
    assert!(matches!(error.kind(), PackageErrorKind::Reserved { .. }));
}

#[test]
fn a_revision_must_be_one_printable_line() {
    for revision in [
        "",
        " leading",
        "trailing ",
        "two\nlines",
        "tab\there",
        &"x".repeat(MAX_REVISION_BYTES + 1),
    ] {
        let directory = populated();
        let error = write_sum_file(
            directory.path(),
            Some(revision),
            &PackageLimits::default(),
            FIX,
        )
        .expect_err("an invalid revision");
        assert!(
            matches!(error.kind(), PackageErrorKind::Revision { .. }),
            "{revision:?}"
        );
        assert!(!directory.path().join(REVISION_FILE).exists());
        assert!(!directory.path().join(SUM_FILE).exists());
    }
    assert!(check_revision(&"x".repeat(MAX_REVISION_BYTES)).is_ok());
    assert!(check_revision("v1.2.3 (git 0123abcd)").is_ok());
}

#[test]
fn a_package_is_written_once() {
    let (directory, _) = packaged(None);
    let error = write_sum_file(directory.path(), None, &PackageLimits::default(), FIX)
        .expect_err("already packaged");
    assert!(matches!(error.kind(), PackageErrorKind::Reserved { .. }));
}

#[test]
fn an_empty_package_is_refused() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let error = write_sum_file(directory.path(), None, &PackageLimits::default(), FIX)
        .expect_err("nothing to package");
    assert_eq!(error.kind(), &PackageErrorKind::Empty);
}

#[test]
fn an_empty_directory_is_refused_when_packaging() {
    let directory = populated();
    fs::create_dir(directory.path().join("empty")).expect("directory");
    let error = write_sum_file(directory.path(), None, &PackageLimits::default(), FIX)
        .expect_err("an empty directory");
    assert_eq!(
        error.kind(),
        &PackageErrorKind::UnsafeEntry {
            path: "empty/".to_owned(),
            reason: "is an empty directory",
        }
    );
}

#[cfg(unix)]
#[test]
fn symbolic_links_are_refused_inside_and_at_the_root() {
    let directory = populated();
    std::os::unix::fs::symlink("policy.yaml", directory.path().join("link.yaml")).expect("link");
    let error = write_sum_file(directory.path(), None, &PackageLimits::default(), FIX)
        .expect_err("a symbolic link");
    assert_eq!(
        error.kind(),
        &PackageErrorKind::UnsafeEntry {
            path: "link.yaml".to_owned(),
            reason: "is a symbolic link",
        }
    );

    let (packaged, _) = packaged(None);
    let outside = tempfile::tempdir().expect("outside");
    std::os::unix::fs::symlink(packaged.path(), outside.path().join("current")).expect("link");
    let error = verify(&outside.path().join("current")).expect_err("a linked root");
    assert!(matches!(error.kind(), PackageErrorKind::RootInvalid { .. }));

    fs::remove_file(packaged.path().join("rules/a.rhai")).expect("remove");
    std::os::unix::fs::symlink("../policy.yaml", packaged.path().join("rules/a.rhai"))
        .expect("link");
    let error = verify(packaged.path()).expect_err("a listed file became a link");
    assert_eq!(
        error.kind(),
        &PackageErrorKind::UnsafeEntry {
            path: "rules/a.rhai".to_owned(),
            reason: "is a symbolic link",
        }
    );
}

#[test]
fn names_that_cannot_travel_are_refused() {
    for name in ["back\\slash", "new\nline", "UPPER.yaml"] {
        let directory = populated();
        write(directory.path(), "upper.yaml", b"x");
        if fs::write(directory.path().join(name), b"x").is_err() {
            continue;
        }
        if fs::read_dir(directory.path()).expect("listing").count() < 4 {
            // A case-insensitive filesystem folded the two names into one file.
            continue;
        }
        let error = write_sum_file(directory.path(), None, &PackageLimits::default(), FIX)
            .expect_err("an unportable name");
        assert!(
            matches!(error.kind(), PackageErrorKind::UnsafeEntry { .. }),
            "{name:?}: {error}"
        );
    }
}

#[test]
fn limits_bound_files_bytes_and_depth() {
    let directory = populated();
    let limits = PackageLimits {
        max_files: 2,
        ..PackageLimits::default()
    };
    let error = write_sum_file(directory.path(), None, &limits, FIX).expect_err("too many files");
    assert!(matches!(error.kind(), PackageErrorKind::Bound { .. }));

    let directory = populated();
    let limits = PackageLimits {
        max_file_bytes: 12,
        ..PackageLimits::default()
    };
    let error = write_sum_file(directory.path(), None, &limits, FIX).expect_err("a large file");
    assert_eq!(
        error.kind(),
        &PackageErrorKind::Bound {
            path: Some("policy.yaml".to_owned()),
            reason: "a file is larger than the package allows",
        }
    );

    let directory = populated();
    let limits = PackageLimits {
        max_total_bytes: 20,
        ..PackageLimits::default()
    };
    let error = write_sum_file(directory.path(), None, &limits, FIX).expect_err("too many bytes");
    assert!(matches!(error.kind(), PackageErrorKind::Bound { .. }));

    let directory = populated();
    write(directory.path(), "a/b/c/d.yaml", b"x");
    let limits = PackageLimits {
        max_depth: 3,
        ..PackageLimits::default()
    };
    let error = write_sum_file(directory.path(), None, &limits, FIX).expect_err("too deep");
    assert!(matches!(error.kind(), PackageErrorKind::Bound { .. }));
}

#[test]
fn the_package_config_verifies_the_directory_and_the_pin_together() {
    let (directory, package) = packaged(None);
    let unpinned = PackageConfig {
        root: directory.path().to_path_buf(),
        expected_digest: None,
    };
    assert_eq!(
        unpinned
            .verify_package(&PackageLimits::default(), FIX)
            .expect("no pin"),
        package
    );
    let pinned = PackageConfig {
        expected_digest: Some(package.digest().to_owned()),
        ..unpinned.clone()
    };
    assert_eq!(
        pinned
            .verify_package(&PackageLimits::default(), FIX)
            .expect("the pin matches"),
        package
    );
    let other = format!("sha256:{}", "0".repeat(64));
    let mismatched = PackageConfig {
        expected_digest: Some(other.clone()),
        ..unpinned
    };
    let error = mismatched
        .verify_package(&PackageLimits::default(), FIX)
        .expect_err("the pin differs");
    assert_eq!(
        error.kind(),
        &PackageErrorKind::DigestMismatch(PackageDigestMismatch {
            expected: other.clone(),
            found: package.digest().to_owned(),
        })
    );
    let message = error.to_string();
    assert!(message.contains(&other), "{message}");
    assert!(message.contains(package.digest()), "{message}");
    assert!(message.contains("package.expectedDigest"), "{message}");
}

#[test]
fn envelope_files_are_named_for_product_loaders() {
    assert!(is_envelope_file(SUM_FILE));
    assert!(is_envelope_file(REVISION_FILE));
    assert!(!is_envelope_file("rules/SHA256SUMS"));
    assert!(!is_envelope_file("policy.yaml"));
}

fn in_memory() -> std::collections::BTreeMap<String, Vec<u8>> {
    [
        ("policy.yaml", b"name: example\n".as_slice()),
        ("rules/b.rhai", b"let b = 2;\n"),
        ("rules/a.rhai", b"let a = 1;\n"),
    ]
    .into_iter()
    .map(|(path, bytes)| (path.to_owned(), bytes.to_vec()))
    .collect()
}

#[test]
fn a_planned_package_has_the_digest_the_written_package_has() {
    let limits = PackageLimits::default();
    for revision in [None, Some("release 7")] {
        let (_directory, on_disk) = packaged(revision);
        let planned = plan_package(Path::new("project"), &in_memory(), revision, &limits, FIX)
            .expect("the plan is valid");
        assert_eq!(planned, on_disk.digest());

        let parent = tempfile::tempdir().expect("temporary directory");
        let output = parent.path().join("nested/package");
        let written = write_package(&output, &in_memory(), revision, &limits, FIX)
            .expect("the package is written");
        assert_eq!(written, on_disk);
        assert_eq!(verify(&output).expect("verifies"), on_disk);
    }
}

#[test]
fn a_planned_package_refuses_what_the_writer_would_refuse() {
    let limits = PackageLimits::default();
    let plan = |files: &[(&str, &[u8])], revision| {
        let files = files
            .iter()
            .map(|(path, bytes)| ((*path).to_owned(), bytes.to_vec()))
            .collect();
        plan_package(Path::new("project"), &files, revision, &limits, FIX)
            .expect_err("refused")
            .kind()
            .clone()
    };
    assert_eq!(plan(&[], None), PackageErrorKind::Empty);
    assert!(matches!(
        plan(&[("../a", b"")], None),
        PackageErrorKind::UnsafeEntry { .. }
    ));
    assert!(matches!(
        plan(&[("a", b""), ("a/b", b"")], None),
        PackageErrorKind::UnsafeEntry { .. }
    ));
    assert!(matches!(
        plan(&[("Policy.yaml", b""), ("policy.yaml", b"")], None),
        PackageErrorKind::UnsafeEntry { .. }
    ));
    assert!(matches!(
        plan(&[(SUM_FILE, b"")], None),
        PackageErrorKind::Reserved { .. }
    ));
    assert!(matches!(
        plan(&[(REVISION_FILE, b"")], None),
        PackageErrorKind::Reserved { .. }
    ));
    assert!(matches!(
        plan(&[("a", b"")], Some(" padded")),
        PackageErrorKind::Revision { .. }
    ));
}

#[test]
fn a_package_is_written_into_a_new_directory_only() {
    let existing = tempfile::tempdir().expect("temporary directory");
    let error = write_package(
        existing.path(),
        &in_memory(),
        None,
        &PackageLimits::default(),
        FIX,
    )
    .expect_err("an existing directory is refused");
    assert!(matches!(error.kind(), PackageErrorKind::OutputExists));
    assert!(error.to_string().contains(FIX), "{error}");
    assert_eq!(fs::read_dir(existing.path()).expect("list").count(), 0);
}

fn hex(bytes: &[u8]) -> String {
    crate::sha256_uri(bytes)
        .strip_prefix("sha256:")
        .expect("label")
        .to_owned()
}

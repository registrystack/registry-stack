//! Acceptance fixtures carry their own copy of each Adapter pack under
//! `adapter-packs/<pack>/<digest>/`. A copy is addressed by its digest, so
//! every copy under the same `<pack>/<digest>` must hold the same bytes.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

type PackFiles = BTreeMap<PathBuf, Vec<u8>>;

fn acceptance_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/fixtures/acceptance")
}

fn sorted_dirs(dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn collect_files(base: &Path, dir: &Path, files: &mut PackFiles) {
    for entry in fs::read_dir(dir).unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
    {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect_files(base, &path, files);
        } else {
            let bytes =
                fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            files.insert(path.strip_prefix(base).unwrap().to_path_buf(), bytes);
        }
    }
}

/// Returns one message per pack copy that differs from the first copy of the
/// same `<pack>/<digest>`, and the number of `<pack>/<digest>` groups that
/// have more than one copy.
fn pack_copy_drift(root: &Path) -> (Vec<String>, usize) {
    let mut groups: BTreeMap<(String, String), Vec<(String, PackFiles)>> = BTreeMap::new();
    for fixture in sorted_dirs(root) {
        let packs = fixture.join("adapter-packs");
        if !packs.is_dir() {
            continue;
        }
        let fixture_name = fixture.file_name().unwrap().to_string_lossy().into_owned();
        for pack in sorted_dirs(&packs) {
            let pack_name = pack.file_name().unwrap().to_string_lossy().into_owned();
            for digest in sorted_dirs(&pack) {
                let digest_name = digest.file_name().unwrap().to_string_lossy().into_owned();
                let mut files = PackFiles::new();
                collect_files(&digest, &digest, &mut files);
                groups
                    .entry((pack_name.clone(), digest_name))
                    .or_default()
                    .push((fixture_name.clone(), files));
            }
        }
    }

    let mut drift = Vec::new();
    let mut shared = 0;
    for ((pack, digest), copies) in &groups {
        if copies.len() > 1 {
            shared += 1;
        }
        let (first_fixture, first_files) = &copies[0];
        for (fixture, files) in &copies[1..] {
            let paths: std::collections::BTreeSet<&PathBuf> =
                first_files.keys().chain(files.keys()).collect();
            let differing: Vec<String> = paths
                .into_iter()
                .filter(|path| first_files.get(*path) != files.get(*path))
                .map(|path| path.display().to_string())
                .collect();
            if !differing.is_empty() {
                drift.push(format!(
                    "adapter-packs/{pack}/{digest} differs between {first_fixture} and {fixture} in {}; \
                     make every copy identical, or give the changed pack its own digest directory",
                    differing.join(", ")
                ));
            }
        }
    }
    (drift, shared)
}

#[test]
fn acceptance_copies_of_one_pack_digest_are_byte_identical() {
    let (drift, shared) = pack_copy_drift(&acceptance_root());
    assert!(
        shared > 0,
        "expected acceptance fixtures to share at least one pack digest"
    );
    assert!(drift.is_empty(), "{}", drift.join("\n"));
}

#[test]
fn a_drifted_pack_copy_is_reported_with_the_differing_file() {
    let root = std::env::temp_dir().join(format!("acceptance-pack-copies-{}", std::process::id()));
    for (fixture, script) in [("first", "one"), ("second", "two")] {
        let pack = root.join(fixture).join("adapter-packs/demo/abc");
        fs::create_dir_all(pack.join("scripts")).unwrap();
        fs::write(pack.join("pack.yaml"), "id: demo\n").unwrap();
        fs::write(pack.join("scripts/provider.rhai"), script).unwrap();
    }

    let (drift, shared) = pack_copy_drift(&root);
    fs::remove_dir_all(&root).unwrap();

    assert_eq!(shared, 1);
    assert_eq!(drift.len(), 1, "{drift:?}");
    assert!(drift[0].contains("adapter-packs/demo/abc"), "{}", drift[0]);
    assert!(drift[0].contains("first and second"), "{}", drift[0]);
    assert!(drift[0].contains("scripts/provider.rhai"), "{}", drift[0]);
    assert!(!drift[0].contains("pack.yaml"), "{}", drift[0]);
}

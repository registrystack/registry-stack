// SPDX-License-Identifier: Apache-2.0
//! The secret-file rule: the pure decision table and the filesystem walk.

use super::*;
use SecretFileCheck::*;

/// Row name, process euid, file uid, mode, kind, link count, then the
/// outcome in production and in development.
type Row = (&'static str, u32, u32, u32, FileKind, u64, Outcome, Outcome);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Load,
    Warn(&'static [SecretFileCheck]),
    Refuse(SecretFileCheck),
}

fn facts(kind: FileKind, uid: u32, mode: u32, nlink: u64) -> Facts {
    Facts {
        kind,
        uid,
        mode,
        nlink,
    }
}

fn observed(result: Result<Vec<SecretFileCheck>, SecretFileCheck>) -> Outcome {
    match result {
        Err(check) => Outcome::Refuse(check),
        Ok(warnings) if warnings.is_empty() => Outcome::Load,
        Ok(warnings) => Outcome::Warn(Box::leak(warnings.into_boxed_slice())),
    }
}

#[test]
fn the_decision_table_gives_one_answer_per_owner_mode_and_posture() {
    use FileKind::{Directory, Regular};
    use Outcome::{Load, Refuse, Warn};
    const APP: u32 = 10001;
    #[rustfmt::skip]
    let rows: &[Row] = &[
        ("A1",   APP, APP, 0o400,  Regular, 1, Load, Load),
        ("A2",   APP, APP, 0o600,  Regular, 1, Load, Load),
        ("A3",   APP, APP, 0o440,  Regular, 1, Refuse(GroupAccess), Warn(&[GroupAccess])),
        ("A4",   APP, APP, 0o640,  Regular, 1, Refuse(GroupAccess), Warn(&[GroupAccess])),
        ("A5",   APP, APP, 0o620,  Regular, 1, Refuse(GroupAccess), Warn(&[GroupAccess])),
        ("A6",   APP, APP, 0o644,  Regular, 1, Refuse(WorldReadable), Warn(&[WorldReadable, GroupAccess])),
        ("A7",   APP, APP, 0o604,  Regular, 1, Refuse(WorldReadable), Warn(&[WorldReadable])),
        ("A8",   APP, APP, 0o444,  Regular, 1, Refuse(WorldReadable), Warn(&[WorldReadable, GroupAccess])),
        ("A9a",  APP, APP, 0o602,  Regular, 1, Refuse(WorldWritable), Refuse(WorldWritable)),
        ("A9b",  APP, APP, 0o666,  Regular, 1, Refuse(WorldWritable), Refuse(WorldWritable)),
        ("A10a", APP, APP, 0o500,  Regular, 1, Refuse(ModeBits), Warn(&[ModeBits])),
        ("A10b", APP, APP, 0o700,  Regular, 1, Refuse(ModeBits), Warn(&[ModeBits])),
        ("A10c", APP, APP, 0o4600, Regular, 1, Refuse(ModeBits), Warn(&[ModeBits])),
        ("A12",  APP, 0,   0o440,  Regular, 1, Load, Load),
        ("A13",  APP, 0,   0o640,  Regular, 1, Load, Load),
        ("A14",  APP, 0,   0o400,  Regular, 1, Load, Load),
        ("A15a", APP, 0,   0o460,  Regular, 1, Refuse(GroupAccess), Warn(&[GroupAccess])),
        ("A15b", APP, 0,   0o450,  Regular, 1, Refuse(GroupAccess), Warn(&[GroupAccess])),
        ("A16a", APP, 0,   0o444,  Regular, 1, Refuse(WorldReadable), Warn(&[WorldReadable])),
        ("A16b", APP, 0,   0o644,  Regular, 1, Refuse(WorldReadable), Warn(&[WorldReadable])),
        ("A17",  APP, 0,   0o446,  Regular, 1, Refuse(WorldWritable), Refuse(WorldWritable)),
        ("A19",  APP, 10002, 0o644, Regular, 1, Refuse(Owner), Refuse(Owner)),
        ("A20a", 0,   0,   0o400,  Regular, 1, Load, Load),
        ("A20b", 0,   0,   0o600,  Regular, 1, Load, Load),
        ("A21",  0,   0,   0o440,  Regular, 1, Refuse(GroupAccess), Warn(&[GroupAccess])),
        ("A22",  0,   0,   0o644,  Regular, 1, Refuse(WorldReadable), Warn(&[WorldReadable, GroupAccess])),
        ("A23",  0,   APP, 0o600,  Regular, 1, Refuse(Owner), Refuse(Owner)),
        ("A24",  APP, APP, 0o400,  Regular, 2, Refuse(HardLinked), Refuse(HardLinked)),
        ("A25",  APP, APP, 0o400,  Directory, 1, Refuse(NotRegular), Refuse(NotRegular)),
        ("A25f", APP, APP, 0o400,  FileKind::Fifo, 1, Refuse(NotRegular), Refuse(NotRegular)),
        ("A25s", APP, APP, 0o400,  FileKind::Socket, 1, Refuse(NotRegular), Refuse(NotRegular)),
        ("A25d", APP, APP, 0o400,  FileKind::Device, 1, Refuse(NotRegular), Refuse(NotRegular)),
        // Observed mounts (m0 secret-mounts), by their observed owner and mode.
        ("C-b",  APP, APP, 0o644,  Regular, 1, Refuse(WorldReadable), Warn(&[WorldReadable, GroupAccess])),
        ("C-eb", APP, 0,   0o444,  Regular, 1, Refuse(WorldReadable), Warn(&[WorldReadable])),
        ("C-el", APP, APP, 0o400,  Regular, 1, Load, Load),
        ("vu/root640", APP, 0, 0o640, Regular, 1, Load, Load),
        ("vu/root644", APP, 0, 0o644, Regular, 1, Refuse(WorldReadable), Warn(&[WorldReadable])),
        ("vu/app440", APP, APP, 0o440, Regular, 1, Refuse(GroupAccess), Warn(&[GroupAccess])),
        ("K-a",  0,   0,   0o644,  Regular, 1, Refuse(WorldReadable), Warn(&[WorldReadable, GroupAccess])),
        ("K-b",  APP, 0,   0o644,  Regular, 1, Refuse(WorldReadable), Warn(&[WorldReadable])),
        ("K-d",  APP, 0,   0o440,  Regular, 1, Load, Load),
        ("K-f",  APP, 0,   0o440,  Regular, 1, Load, Load),
        ("K-g2", APP, 0,   0o440,  Regular, 1, Load, Load),
        ("K-root-0440", 0, 0, 0o440, Regular, 1, Refuse(GroupAccess), Warn(&[GroupAccess])),
    ];
    for (row, euid, uid, mode, kind, nlink, production, development) in rows {
        let f = facts(*kind, *uid, *mode, *nlink);
        assert_eq!(
            observed(judge(f, *euid, false)),
            *production,
            "{row} in production"
        );
        assert_eq!(
            observed(judge(f, *euid, true)),
            *development,
            "{row} in development"
        );
    }
}

#[test]
fn every_check_has_a_unique_code_a_value_free_message_and_a_full_stop_fix() {
    let all = [
        LinkLeavesRoot,
        TooManyLinks,
        CannotOpen,
        NotRegular,
        HardLinked,
        Owner,
        WorldWritable,
        WorldReadable,
        GroupAccess,
        ModeBits,
    ];
    let mut codes = std::collections::BTreeSet::new();
    for check in all {
        let code = check.code();
        assert!(code.starts_with("platform.secret-file."), "{code}");
        assert!(
            code["platform.secret-file.".len()..]
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'-'),
            "{code}"
        );
        assert!(codes.insert(code), "{code} repeats");
        assert!(check.suggested_action().ends_with('.'), "{code}");
        for text in [check.message(), check.suggested_action()] {
            assert!(!text.contains("/run/") && !text.contains("/etc/"), "{text}");
            assert!(!text.contains("secret:"), "{text}");
        }
    }
    for check in [CannotOpen, WorldReadable] {
        let action = check.suggested_action();
        assert!(action.contains("defaultMode"), "{action}");
        assert!(action.contains("fsGroup"), "{action}");
    }
    for check in all {
        assert!(!check.suggested_action().contains("runAsUser"));
    }
}

#[test]
fn the_development_split_lives_in_one_place() {
    for check in [WorldReadable, GroupAccess, ModeBits] {
        assert!(check.warns_in_development(), "{check:?}");
    }
    for check in [
        LinkLeavesRoot,
        TooManyLinks,
        CannotOpen,
        NotRegular,
        HardLinked,
        Owner,
        WorldWritable,
    ] {
        assert!(!check.warns_in_development(), "{check:?}");
    }
}

#[test]
fn a_check_warns_once_per_process_however_often_it_fires() {
    let warned = WarnedChecks::default();
    assert!(warned.first(WorldReadable));
    assert!(!warned.first(WorldReadable));
    assert!(warned.first(GroupAccess));
    assert!(!warned.first(GroupAccess));
    assert!(!warned.first(WorldReadable));
}

#[test]
fn error_fixes_come_from_the_error() {
    assert_eq!(
        SecretError::UnsafeFile(HardLinked).suggested_action(),
        HardLinked.suggested_action()
    );
    for error in [
        SecretError::InvalidReference,
        SecretError::ProviderDisabled,
        SecretError::InvalidProviderConfiguration,
        SecretError::Unavailable,
        SecretError::Read,
        SecretError::InvalidValue,
    ] {
        assert!(error.suggested_action().ends_with('.'), "{error:?}");
    }
}

#[cfg(unix)]
mod filesystem {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt as _},
        path::Path,
    };

    fn write(root: &Path, name: &str, mode: u32) {
        let path = root.join(name);
        fs::write(&path, b"file-canary").expect("write");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode");
    }

    fn resolver(root: &Path) -> SecretResolver {
        SecretResolver::new([SecretProvider::File], root).expect("resolver")
    }

    fn development(root: &Path) -> SecretResolver {
        resolver(root).in_development(Some(&DevelopmentWitness::issue()))
    }

    fn load(resolver: &SecretResolver, name: &str) -> Result<Vec<u8>, SecretError> {
        resolver
            .resolve(&format!("secret:file/{name}"))
            .map(|secret| secret.expose_secret().to_vec())
    }

    #[test]
    fn a_relative_link_inside_the_root_loads_the_file_it_names() {
        let root = tempfile::tempdir().expect("root");
        write(root.path(), "target", 0o400);
        symlink("target", root.path().join("name")).expect("link");
        fs::create_dir(root.path().join("sub")).expect("dir");
        write(&root.path().join("sub"), "token", 0o400);
        symlink("sub/token", root.path().join("nested")).expect("link");
        let resolver = resolver(root.path());
        assert_eq!(load(&resolver, "name").expect("loads"), b"file-canary");
        assert_eq!(load(&resolver, "nested").expect("loads"), b"file-canary");
    }

    fn kubernetes_layout(root: &Path, mode: u32) {
        fs::create_dir(root.join("..ts")).expect("dir");
        write(&root.join("..ts"), "token", mode);
        symlink("..ts", root.join("..data")).expect("link");
        symlink("..data/token", root.join("token")).expect("link");
    }

    #[test]
    fn the_kubernetes_link_chain_loads_and_the_target_is_judged_not_the_links() {
        let root = tempfile::tempdir().expect("root");
        kubernetes_layout(root.path(), 0o400);
        assert_eq!(
            load(&resolver(root.path()), "token").expect("loads"),
            b"file-canary"
        );

        let loose = tempfile::tempdir().expect("root");
        kubernetes_layout(loose.path(), 0o644);
        assert_eq!(
            load(&resolver(loose.path()), "token"),
            Err(SecretError::UnsafeFile(WorldReadable))
        );
        assert_eq!(
            load(&development(loose.path()), "token").expect("warns and loads"),
            b"file-canary"
        );
    }

    #[test]
    fn a_chain_of_eight_links_loads_and_nine_or_a_loop_is_refused() {
        let root = tempfile::tempdir().expect("root");
        write(root.path(), "end", 0o400);
        let mut previous = "end".to_owned();
        for index in 1..=9 {
            let name = format!("l{index}");
            symlink(&previous, root.path().join(&name)).expect("link");
            previous = name;
        }
        let resolver = resolver(root.path());
        assert_eq!(load(&resolver, "l8").expect("8 links load"), b"file-canary");
        assert_eq!(
            load(&resolver, "l9"),
            Err(SecretError::UnsafeFile(TooManyLinks))
        );
        symlink("loop-b", root.path().join("loop-a")).expect("link");
        symlink("loop-a", root.path().join("loop-b")).expect("link");
        assert_eq!(
            load(&resolver, "loop-a"),
            Err(SecretError::UnsafeFile(TooManyLinks))
        );
    }

    #[test]
    fn a_link_that_could_leave_the_root_is_refused_in_both_postures() {
        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        write(outside.path(), "token", 0o400);
        write(root.path(), "inside", 0o400);
        fs::create_dir(root.path().join("sub")).expect("dir");
        write(&root.path().join("sub"), "token", 0o400);
        symlink(outside.path().join("token"), root.path().join("absolute")).expect("link");
        symlink(
            root.path().join("inside"),
            root.path().join("absolute-inside"),
        )
        .expect("link");
        symlink("../x", root.path().join("parent")).expect("link");
        symlink("sub/../inside", root.path().join("dotdot")).expect("link");
        symlink(outside.path(), root.path().join("elsewhere")).expect("link");
        symlink("elsewhere/token", root.path().join("through")).expect("link");
        for resolver in [resolver(root.path()), development(root.path())] {
            for name in ["absolute", "absolute-inside", "parent", "dotdot", "through"] {
                assert_eq!(
                    load(&resolver, name),
                    Err(SecretError::UnsafeFile(LinkLeavesRoot)),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn a_link_to_a_directory_or_a_dangling_link_is_refused() {
        let root = tempfile::tempdir().expect("root");
        fs::create_dir(root.path().join("sub")).expect("dir");
        symlink("sub", root.path().join("to-dir")).expect("link");
        symlink("missing", root.path().join("dangling")).expect("link");
        let resolver = resolver(root.path());
        assert_eq!(
            load(&resolver, "to-dir"),
            Err(SecretError::UnsafeFile(NotRegular))
        );
        assert_eq!(load(&resolver, "dangling"), Err(SecretError::Unavailable));
        assert_eq!(load(&resolver, "absent"), Err(SecretError::Unavailable));
    }

    #[test]
    fn a_link_in_the_root_path_itself_is_refused_and_its_parents_are_not_checked() {
        let real = tempfile::tempdir().expect("real");
        write(real.path(), "token", 0o400);
        let holder = tempfile::tempdir().expect("holder");
        let linked_root = holder.path().join("root-link");
        symlink(real.path(), &linked_root).expect("link");
        assert_eq!(
            load(&resolver(&linked_root), "token"),
            Err(SecretError::Unavailable)
        );
        let parent_link = holder.path().join("parent-link");
        symlink(holder.path(), &parent_link).expect("link");
        fs::create_dir(holder.path().join("child")).expect("dir");
        write(&holder.path().join("child"), "token", 0o400);
        assert!(load(&resolver(&parent_link.join("child")), "token").is_ok());
    }

    #[test]
    fn the_roots_own_mode_is_not_checked() {
        let root = tempfile::tempdir().expect("root");
        write(root.path(), "token", 0o400);
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o1777)).expect("mode");
        assert!(load(&resolver(root.path()), "token").is_ok());
    }

    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let root = tempfile::tempdir().expect("root");
        let status = std::process::Command::new("mkfifo")
            .arg(root.path().join("pipe"))
            .status()
            .expect("mkfifo runs");
        assert!(status.success());
        assert_eq!(
            load(&resolver(root.path()), "pipe"),
            Err(SecretError::UnsafeFile(NotRegular))
        );
    }

    #[test]
    fn a_directory_is_not_a_secret() {
        let root = tempfile::tempdir().expect("root");
        fs::create_dir(root.path().join("directory")).expect("dir");
        assert_eq!(
            load(&resolver(root.path()), "directory"),
            Err(SecretError::UnsafeFile(NotRegular))
        );
    }

    #[test]
    fn a_file_the_runtime_cannot_open_is_cannot_open_not_unavailable() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let root = tempfile::tempdir().expect("root");
        write(root.path(), "locked", 0o000);
        assert_eq!(
            load(&resolver(root.path()), "locked"),
            Err(SecretError::UnsafeFile(CannotOpen))
        );
        assert_eq!(
            load(&development(root.path()), "locked"),
            Err(SecretError::UnsafeFile(CannotOpen))
        );
    }

    #[test]
    fn development_warns_for_loose_modes_and_still_refuses_shape_owner_and_write() {
        let root = tempfile::tempdir().expect("root");
        write(root.path(), "world-readable", 0o644);
        write(root.path(), "group", 0o440);
        write(root.path(), "executable", 0o500);
        write(root.path(), "world-writable", 0o666);
        symlink("/etc/hosts", root.path().join("absolute")).expect("link");
        let production = resolver(root.path());
        let development = development(root.path());
        for (name, check) in [
            ("world-readable", WorldReadable),
            ("group", GroupAccess),
            ("executable", ModeBits),
        ] {
            assert_eq!(load(&production, name), Err(SecretError::UnsafeFile(check)));
            assert_eq!(load(&development, name).expect("warns"), b"file-canary");
        }
        for (name, check) in [
            ("world-writable", WorldWritable),
            ("absolute", LinkLeavesRoot),
        ] {
            assert_eq!(load(&production, name), Err(SecretError::UnsafeFile(check)));
            assert_eq!(
                load(&development, name),
                Err(SecretError::UnsafeFile(check))
            );
        }
    }

    #[test]
    fn a_resolver_without_the_witness_applies_the_production_rule() {
        let root = tempfile::tempdir().expect("root");
        write(root.path(), "token", 0o644);
        let resolver = resolver(root.path()).in_development(None);
        assert_eq!(
            load(&resolver, "token"),
            Err(SecretError::UnsafeFile(WorldReadable))
        );
    }

    #[test]
    fn inspecting_a_reference_gives_the_verdict_without_the_bytes() {
        let root = tempfile::tempdir().expect("root");
        write(root.path(), "good", 0o400);
        write(root.path(), "loose", 0o644);
        let resolver = resolver(root.path());
        let good = SecretReference::parse("secret:file/good").unwrap();
        let loose = SecretReference::parse("secret:file/loose").unwrap();
        let absent = SecretReference::parse("secret:file/absent").unwrap();
        assert_eq!(resolver.inspect_reference(&good), Ok(()));
        assert_eq!(
            resolver.inspect_reference(&loose),
            Err(SecretError::UnsafeFile(WorldReadable))
        );
        assert_eq!(
            resolver.inspect_reference(&absent),
            Err(SecretError::Unavailable)
        );
    }
}

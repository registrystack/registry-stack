// SPDX-License-Identifier: Apache-2.0
//! Descriptor-relative path resolution for the bregctl surfaces that refuse
//! symbolic links.
//!
//! Checking each path component with `lstat` and then opening, creating,
//! renaming, or publishing by pathname is a time-of-check to time-of-use race.
//! `O_NOFOLLOW` covers the final component only, so in a directory tree another
//! process can write, an ancestor can be renamed away and replaced with a
//! symbolic link between the check and the use, and the operation then reaches
//! a different tree.
//!
//! [`SafeDir::resolve`] and [`SafeEntry::resolve`] walk a path one component at
//! a time with `openat` and `O_NOFOLLOW`, so the kernel refuses a symbolic link
//! at every component, and they keep the resolved directory descriptor open.
//! Every later open, create, hard link, rename, unlink, directory read, and
//! directory sync runs relative to that descriptor, so replacing an ancestor
//! after resolution cannot redirect the operation.
//!
//! Descriptor-relative resolution is implemented for Linux and macOS, the
//! platforms bregctl is released for. Every other platform fails closed:
//! resolution returns [`SafePathError::Unsupported`], so a surface that
//! promises a no-symlink path opens, creates, and publishes nothing.

/// Why a path could not be resolved without traversing a symbolic link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// Only `Unsupported` is reachable on a platform without a kernel-enforced
// primitive, so the refusals the resolver would have raised are unused there.
#[cfg_attr(
    not(any(target_os = "linux", target_vendor = "apple")),
    allow(dead_code)
)]
pub(crate) enum SafePathError {
    /// The path is empty, holds a parent-directory component, or names no
    /// final entry to act on.
    Path,
    /// A component is a symbolic link, or an ancestor is not a directory.
    Symlink,
    /// A component does not exist.
    NotFound,
    /// A component cannot be inspected or opened safely.
    Unavailable,
    /// This platform has no descriptor-relative no-symlink resolution, so the
    /// surface refuses rather than falling back to pathname resolution. Only
    /// the fail-closed stand-in constructs it, so a supported build never does.
    #[cfg_attr(any(target_os = "linux", target_vendor = "apple"), allow(dead_code))]
    Unsupported,
}

impl SafePathError {
    /// Report whether the refusal was a missing component, which callers with a
    /// distinct "not present" outcome report separately from a refusal.
    pub(crate) fn is_not_found(self) -> bool {
        matches!(self, SafePathError::NotFound)
    }

    /// Convert to the `io::Error` shape the byte-reading helpers return.
    pub(crate) fn into_io(self) -> std::io::Error {
        match self {
            SafePathError::NotFound => {
                std::io::Error::new(std::io::ErrorKind::NotFound, "path component is missing")
            }
            SafePathError::Path => std::io::Error::other("unsafe path shape"),
            SafePathError::Symlink => std::io::Error::other("path traverses a symbolic link"),
            SafePathError::Unavailable => std::io::Error::other("path cannot be resolved safely"),
            SafePathError::Unsupported => std::io::Error::other(
                "descriptor-relative path resolution is unavailable on this platform",
            ),
        }
    }
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
mod descriptor {
    use std::ffi::{OsStr, OsString};
    use std::fs::{File, Metadata};
    use std::io;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path};

    use rustix::fs::{
        linkat, mkdirat, openat, renameat, renameat_with, statat, unlinkat, AtFlags, Dir, FileType,
        Mode, OFlags, RawMode, RenameFlags, CWD,
    };

    use super::SafePathError;

    /// Flags every directory descriptor in a resolved chain is opened with. The
    /// kernel refuses a symbolic link component and refuses a non-directory.
    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);

    /// Flags every leaf open shares. `NONBLOCK` keeps a FIFO planted at the
    /// leaf from blocking the open before the file-type check runs.
    const LEAF_FLAGS: OFlags = OFlags::NOFOLLOW
        .union(OFlags::CLOEXEC)
        .union(OFlags::NONBLOCK);

    /// The identity and kind of a directory entry, read with `fstatat` and
    /// `AT_SYMLINK_NOFOLLOW` relative to a resolved directory descriptor.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct EntryStat {
        file_type: FileType,
        len: u64,
        mode: u32,
        dev: u64,
        ino: u64,
    }

    impl EntryStat {
        pub(crate) fn is_symlink(self) -> bool {
            self.file_type == FileType::Symlink
        }

        pub(crate) fn is_file(self) -> bool {
            self.file_type == FileType::RegularFile
        }

        pub(crate) fn is_dir(self) -> bool {
            self.file_type == FileType::Directory
        }

        pub(crate) fn len(self) -> u64 {
            self.len
        }

        /// The permission bits, for the owner-only and unchanged-permission
        /// checks the project-migration surface applies.
        pub(crate) fn permission_bits(self) -> u32 {
            self.mode & 0o7777
        }

        /// Report whether an opened descriptor is the same file this entry
        /// named, by device and inode.
        pub(crate) fn is_same_file_as(self, metadata: &Metadata) -> bool {
            self.dev == metadata.dev() && self.ino == metadata.ino()
        }
    }

    /// A directory reached without traversing a symbolic link, held open so the
    /// entries resolved through it cannot be redirected.
    #[derive(Debug)]
    pub(crate) struct SafeDir {
        fd: OwnedFd,
    }

    /// A resolved parent directory plus the final component to act on.
    #[derive(Debug)]
    pub(crate) struct SafeEntry {
        parent: SafeDir,
        name: OsString,
    }

    impl SafeDir {
        /// Resolve `path` to an open directory descriptor, refusing a symbolic
        /// link at every component including the last.
        pub(crate) fn resolve(path: &Path) -> Result<Self, SafePathError> {
            let (mut dir, components) = anchor(path)?;
            for name in components {
                dir = dir.open_directory(name)?;
            }
            fire_race_hook();
            Ok(dir)
        }

        /// Open a child directory through this descriptor, refusing a symbolic
        /// link.
        pub(crate) fn open_directory(&self, name: &OsStr) -> Result<Self, SafePathError> {
            openat(&self.fd, name, DIRECTORY_FLAGS, Mode::empty())
                .map(|fd| SafeDir { fd })
                .map_err(component_error)
        }

        /// Reopen this directory as an independent descriptor, so a caller can
        /// keep one handle while walking deeper with another.
        pub(crate) fn try_clone(&self) -> Result<Self, SafePathError> {
            openat(&self.fd, ".", DIRECTORY_FLAGS, Mode::empty())
                .map(|fd| SafeDir { fd })
                .map_err(component_error)
        }

        /// Open a child directory through this descriptor, creating it when it
        /// is absent. A child that exists as anything but a directory, a
        /// symbolic link included, is refused.
        pub(crate) fn open_or_create_directory(
            &self,
            name: &OsStr,
            mode: u32,
        ) -> Result<Self, SafePathError> {
            match self.open_directory(name) {
                Ok(directory) => Ok(directory),
                Err(SafePathError::NotFound) => {
                    match mkdirat(&self.fd, name, Mode::from_bits_truncate(mode as RawMode)) {
                        Ok(()) => {}
                        // Another writer may have won the create; the reopen
                        // below still refuses anything but a real directory.
                        Err(rustix::io::Errno::EXIST) => {}
                        Err(errno) => return Err(component_error(errno)),
                    }
                    self.open_directory(name)
                }
                Err(error) => Err(error),
            }
        }

        /// Read a bounded regular file relative to this descriptor.
        pub(crate) fn open_read(&self, name: &OsStr) -> io::Result<File> {
            self.open_leaf(name, OFlags::RDONLY, Mode::empty())
        }

        /// Append to an existing file relative to this descriptor.
        pub(crate) fn open_append(&self, name: &OsStr) -> io::Result<File> {
            self.open_leaf(name, OFlags::WRONLY | OFlags::APPEND, Mode::empty())
        }

        /// Create a new file relative to this descriptor, refusing to clobber an
        /// existing entry of any kind.
        pub(crate) fn create_new(&self, name: &OsStr, mode: u32) -> io::Result<File> {
            self.open_leaf(
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
                Mode::from_bits_truncate(mode as RawMode),
            )
        }

        fn open_leaf(&self, name: &OsStr, extra: OFlags, mode: Mode) -> io::Result<File> {
            openat(&self.fd, name, LEAF_FLAGS | extra, mode)
                .map(File::from)
                .map_err(io::Error::from)
        }

        /// Create a new directory relative to this descriptor.
        pub(crate) fn create_directory(&self, name: &OsStr, mode: u32) -> io::Result<()> {
            mkdirat(&self.fd, name, Mode::from_bits_truncate(mode as RawMode))
                .map_err(io::Error::from)
        }

        /// Stat an entry relative to this descriptor without following a final
        /// symbolic link.
        pub(crate) fn entry_stat(&self, name: &OsStr) -> io::Result<EntryStat> {
            let stat = statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW)?;
            Ok(EntryStat {
                file_type: FileType::from_raw_mode(stat.st_mode as _),
                len: u64::try_from(stat.st_size).unwrap_or(u64::MAX),
                mode: stat.st_mode as u32,
                dev: stat.st_dev as u64,
                ino: stat.st_ino as u64,
            })
        }

        /// Report whether an entry exists relative to this descriptor.
        pub(crate) fn entry_exists(&self, name: &OsStr) -> io::Result<bool> {
            match self.entry_stat(name) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error),
            }
        }

        /// Rename within this directory, replacing an existing destination.
        pub(crate) fn rename(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
            renameat(&self.fd, from, &self.fd, to).map_err(io::Error::from)
        }

        /// Rename within this directory, refusing to replace an existing
        /// destination. This is the atomic no-clobber publication step.
        /// Rename an entry out of this directory into `destination`, replacing
        /// an existing entry there. Both ends are descriptors, so neither side
        /// can be redirected by a path change.
        pub(crate) fn rename_into(
            &self,
            from: &OsStr,
            destination: &SafeDir,
            to: &OsStr,
        ) -> io::Result<()> {
            renameat(&self.fd, from, &destination.fd, to).map_err(io::Error::from)
        }

        pub(crate) fn publish(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
            renameat_with(&self.fd, from, &self.fd, to, RenameFlags::NOREPLACE)
                .map_err(io::Error::from)
        }

        /// Hard link within this directory, which creates the destination only
        /// when it does not already exist.
        pub(crate) fn link(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
            linkat(&self.fd, from, &self.fd, to, AtFlags::empty()).map_err(io::Error::from)
        }

        /// Unlink a non-directory entry relative to this descriptor.
        pub(crate) fn remove_file(&self, name: &OsStr) -> io::Result<()> {
            unlinkat(&self.fd, name, AtFlags::empty()).map_err(io::Error::from)
        }

        /// Remove a directory subtree relative to this descriptor. Every level
        /// is opened with `O_NOFOLLOW`, so the removal cannot escape into a
        /// tree an ancestor symbolic link points at.
        pub(crate) fn remove_tree(&self, name: &OsStr) -> io::Result<()> {
            let child = self.open_directory(name).map_err(SafePathError::into_io)?;
            child.remove_contents(MAX_REMOVE_TREE_DEPTH)?;
            unlinkat(&self.fd, name, AtFlags::REMOVEDIR).map_err(io::Error::from)
        }

        fn remove_contents(&self, depth: u32) -> io::Result<()> {
            if depth == 0 {
                return Err(io::Error::other(
                    "directory tree is deeper than this tool removes",
                ));
            }
            for entry in self.read_entries()? {
                if entry.is_dir {
                    let child = self
                        .open_directory(&entry.name)
                        .map_err(SafePathError::into_io)?;
                    child.remove_contents(depth - 1)?;
                    unlinkat(&self.fd, &entry.name, AtFlags::REMOVEDIR)?;
                } else {
                    unlinkat(&self.fd, &entry.name, AtFlags::empty())?;
                }
            }
            Ok(())
        }

        /// List the entries of this directory, excluding `.` and `..`.
        pub(crate) fn read_entries(&self) -> io::Result<Vec<SafeDirEntry>> {
            let mut entries = Vec::new();
            for entry in Dir::read_from(&self.fd)? {
                let entry = entry?;
                let name = OsStr::from_bytes(entry.file_name().to_bytes()).to_owned();
                if name == "." || name == ".." {
                    continue;
                }
                // `d_type` is advisory: a filesystem may report `Unknown`, and a
                // symbolic link must never be mistaken for the directory it
                // points at, so fall back to a no-follow stat.
                let (is_dir, is_file, is_symlink) = match entry.file_type() {
                    FileType::Directory => (true, false, false),
                    FileType::Symlink => (false, false, true),
                    FileType::RegularFile => (false, true, false),
                    _ => {
                        let stat = self.entry_stat(&name)?;
                        (stat.is_dir(), stat.is_file(), stat.is_symlink())
                    }
                };
                entries.push(SafeDirEntry {
                    name,
                    is_dir,
                    is_file,
                    is_symlink,
                });
            }
            entries.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(entries)
        }

        /// Flush this directory's own metadata, so a publication survives a
        /// crash.
        pub(crate) fn sync(&self) -> io::Result<()> {
            rustix::fs::fsync(&self.fd).map_err(io::Error::from)
        }
    }

    /// One entry of a resolved directory.
    #[derive(Clone, Debug)]
    pub(crate) struct SafeDirEntry {
        pub(crate) name: OsString,
        pub(crate) is_dir: bool,
        pub(crate) is_file: bool,
        pub(crate) is_symlink: bool,
    }

    impl SafeEntry {
        /// Resolve every ancestor of `path` to open directory descriptors,
        /// refusing a symbolic link at each one, and keep the final component
        /// name for descriptor-relative use.
        pub(crate) fn resolve(path: &Path) -> Result<Self, SafePathError> {
            let (mut dir, components) = anchor(path)?;
            let mut components = components.into_iter();
            let mut name = components.next().ok_or(SafePathError::Path)?;
            for next in components {
                dir = dir.open_directory(name)?;
                name = next;
            }
            fire_race_hook();
            Ok(SafeEntry {
                parent: dir,
                name: name.to_owned(),
            })
        }

        pub(crate) fn parent(&self) -> &SafeDir {
            &self.parent
        }

        pub(crate) fn name(&self) -> &OsStr {
            &self.name
        }

        pub(crate) fn open_read(&self) -> io::Result<File> {
            self.parent.open_read(&self.name)
        }

        pub(crate) fn open_append(&self) -> io::Result<File> {
            self.parent.open_append(&self.name)
        }

        pub(crate) fn create_new(&self, mode: u32) -> io::Result<File> {
            self.parent.create_new(&self.name, mode)
        }

        pub(crate) fn stat(&self) -> io::Result<EntryStat> {
            self.parent.entry_stat(&self.name)
        }

        pub(crate) fn exists(&self) -> io::Result<bool> {
            self.parent.entry_exists(&self.name)
        }

        pub(crate) fn remove_file(&self) -> io::Result<()> {
            self.parent.remove_file(&self.name)
        }

        /// Publish `temporary`, a sibling in the same resolved directory, onto
        /// this entry without replacing an existing destination.
        pub(crate) fn publish_from(&self, temporary: &OsStr) -> io::Result<()> {
            self.parent.publish(temporary, &self.name)
        }

        /// Rename `temporary`, a sibling in the same resolved directory, onto
        /// this entry, replacing an existing destination.
        pub(crate) fn replace_from(&self, temporary: &OsStr) -> io::Result<()> {
            self.parent.rename(temporary, &self.name)
        }
    }

    /// The deepest tree [`SafeDir::remove_tree`] walks. Staged output trees are
    /// generated by this tool and are far shallower; the bound keeps a hostile
    /// tree from exhausting the stack.
    const MAX_REMOVE_TREE_DEPTH: u32 = 32;

    /// Open the directory a path is resolved from and split off its normal
    /// components. Absolute paths anchor at the filesystem root, relative paths
    /// at the working directory.
    fn anchor(path: &Path) -> Result<(SafeDir, Vec<&OsStr>), SafePathError> {
        if path.as_os_str().is_empty() {
            return Err(SafePathError::Path);
        }
        let mut names = Vec::new();
        let mut absolute = false;
        for component in path.components() {
            match component {
                Component::RootDir => absolute = true,
                Component::CurDir => {}
                Component::Normal(name) => names.push(name),
                Component::ParentDir | Component::Prefix(_) => return Err(SafePathError::Path),
            }
        }
        let start = if absolute {
            openat(CWD, "/", DIRECTORY_FLAGS, Mode::empty()).map_err(component_error)?
        } else {
            openat(CWD, ".", DIRECTORY_FLAGS, Mode::empty()).map_err(component_error)?
        };
        Ok((SafeDir { fd: start }, names))
    }

    fn component_error(errno: rustix::io::Errno) -> SafePathError {
        match errno {
            rustix::io::Errno::NOENT => SafePathError::NotFound,
            // `O_NOFOLLOW` reports a symbolic link component as `ELOOP`, and a
            // component that is not a directory as `ENOTDIR`.
            rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => SafePathError::Symlink,
            _ => SafePathError::Unavailable,
        }
    }

    // Test-only seam that stands in for another process acting between
    // resolution and use. It runs after every ancestor descriptor is held and
    // before the first descriptor-relative operation, which is exactly the
    // window a pathname-based implementation loses.
    #[cfg(test)]
    thread_local! {
        static RACE_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
            const { std::cell::RefCell::new(None) };
    }

    #[cfg(test)]
    fn fire_race_hook() {
        // Taking the hook out for the call keeps a hook that touches the
        // filesystem from re-entering the cell, and reinstalling it lets one
        // hook cover a surface that resolves several paths.
        let taken = RACE_HOOK.with(|slot| slot.borrow_mut().take());
        if let Some(mut hook) = taken {
            hook();
            RACE_HOOK.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot.is_none() {
                    *slot = Some(hook);
                }
            });
        }
    }

    #[cfg(not(test))]
    fn fire_race_hook() {}

    /// Install a callback that runs once, after the next resolution captures
    /// its directory descriptors and before the caller uses them.
    #[cfg(test)]
    pub(crate) fn install_race_hook(hook: impl FnMut() + 'static) -> RaceHookGuard {
        RACE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        RaceHookGuard
    }

    /// Clears any race hook the test did not consume, so one test cannot leak a
    /// hook into the next test on the same thread.
    #[cfg(test)]
    pub(crate) struct RaceHookGuard;

    #[cfg(test)]
    impl Drop for RaceHookGuard {
        fn drop(&mut self) {
            RACE_HOOK.with(|slot| *slot.borrow_mut() = None);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
// The operations below are unreachable by construction here, which is the
// point, so their being unused is not a defect to warn about.
#[allow(dead_code)]
mod descriptor {
    //! Fail-closed stand-in for platforms without descriptor-relative
    //! no-symlink resolution. Resolution always refuses, so no surface that
    //! promises a no-symlink path reads, creates, or publishes anything, and
    //! the operations below are unreachable by construction.

    use std::convert::Infallible;
    use std::ffi::{OsStr, OsString};
    use std::fs::{File, Metadata};
    use std::io;
    use std::path::Path;

    use super::SafePathError;

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct EntryStat(Infallible);

    impl EntryStat {
        pub(crate) fn is_symlink(self) -> bool {
            match self.0 {}
        }

        pub(crate) fn is_file(self) -> bool {
            match self.0 {}
        }

        pub(crate) fn is_dir(self) -> bool {
            match self.0 {}
        }

        pub(crate) fn len(self) -> u64 {
            match self.0 {}
        }

        pub(crate) fn permission_bits(self) -> u32 {
            match self.0 {}
        }

        pub(crate) fn is_same_file_as(self, _metadata: &Metadata) -> bool {
            match self.0 {}
        }
    }

    #[derive(Debug)]
    pub(crate) struct SafeDir(Infallible);

    #[derive(Debug)]
    pub(crate) struct SafeEntry(Infallible);

    #[derive(Clone, Debug)]
    pub(crate) struct SafeDirEntry {
        pub(crate) name: OsString,
        pub(crate) is_dir: bool,
        pub(crate) is_file: bool,
        pub(crate) is_symlink: bool,
    }

    impl SafeDir {
        pub(crate) fn resolve(_path: &Path) -> Result<Self, SafePathError> {
            Err(SafePathError::Unsupported)
        }

        pub(crate) fn open_directory(&self, _name: &OsStr) -> Result<Self, SafePathError> {
            match self.0 {}
        }

        pub(crate) fn try_clone(&self) -> Result<Self, SafePathError> {
            match self.0 {}
        }

        pub(crate) fn open_or_create_directory(
            &self,
            _name: &OsStr,
            _mode: u32,
        ) -> Result<Self, SafePathError> {
            match self.0 {}
        }

        pub(crate) fn open_read(&self, _name: &OsStr) -> io::Result<File> {
            match self.0 {}
        }

        pub(crate) fn open_append(&self, _name: &OsStr) -> io::Result<File> {
            match self.0 {}
        }

        pub(crate) fn create_new(&self, _name: &OsStr, _mode: u32) -> io::Result<File> {
            match self.0 {}
        }

        pub(crate) fn create_directory(&self, _name: &OsStr, _mode: u32) -> io::Result<()> {
            match self.0 {}
        }

        pub(crate) fn entry_stat(&self, _name: &OsStr) -> io::Result<EntryStat> {
            match self.0 {}
        }

        pub(crate) fn entry_exists(&self, _name: &OsStr) -> io::Result<bool> {
            match self.0 {}
        }

        pub(crate) fn rename(&self, _from: &OsStr, _to: &OsStr) -> io::Result<()> {
            match self.0 {}
        }

        pub(crate) fn rename_into(
            &self,
            _from: &OsStr,
            _destination: &SafeDir,
            _to: &OsStr,
        ) -> io::Result<()> {
            match self.0 {}
        }

        pub(crate) fn publish(&self, _from: &OsStr, _to: &OsStr) -> io::Result<()> {
            match self.0 {}
        }

        pub(crate) fn link(&self, _from: &OsStr, _to: &OsStr) -> io::Result<()> {
            match self.0 {}
        }

        pub(crate) fn remove_file(&self, _name: &OsStr) -> io::Result<()> {
            match self.0 {}
        }

        pub(crate) fn remove_tree(&self, _name: &OsStr) -> io::Result<()> {
            match self.0 {}
        }

        pub(crate) fn read_entries(&self) -> io::Result<Vec<SafeDirEntry>> {
            match self.0 {}
        }

        pub(crate) fn sync(&self) -> io::Result<()> {
            match self.0 {}
        }
    }

    impl SafeEntry {
        pub(crate) fn resolve(_path: &Path) -> Result<Self, SafePathError> {
            Err(SafePathError::Unsupported)
        }

        pub(crate) fn parent(&self) -> &SafeDir {
            match self.0 {}
        }

        pub(crate) fn name(&self) -> &OsStr {
            match self.0 {}
        }

        pub(crate) fn open_read(&self) -> io::Result<File> {
            match self.0 {}
        }

        pub(crate) fn open_append(&self) -> io::Result<File> {
            match self.0 {}
        }

        pub(crate) fn create_new(&self, _mode: u32) -> io::Result<File> {
            match self.0 {}
        }

        pub(crate) fn stat(&self) -> io::Result<EntryStat> {
            match self.0 {}
        }

        pub(crate) fn exists(&self) -> io::Result<bool> {
            match self.0 {}
        }

        pub(crate) fn remove_file(&self) -> io::Result<()> {
            match self.0 {}
        }

        pub(crate) fn publish_from(&self, _temporary: &OsStr) -> io::Result<()> {
            match self.0 {}
        }

        pub(crate) fn replace_from(&self, _temporary: &OsStr) -> io::Result<()> {
            match self.0 {}
        }
    }
}

pub(crate) use descriptor::{EntryStat, SafeDir, SafeEntry};

#[cfg(all(test, any(target_os = "linux", target_vendor = "apple")))]
pub(crate) use descriptor::{install_race_hook, RaceHookGuard};

/// The deterministic ancestor-swap fixture the race regressions share.
///
/// It plants two sibling trees under a temporary root: `genuine`, whose paths
/// the operator names, and `attacker`, which the operator never names. Arming
/// the swap renames `genuine` to `genuine-moved` and leaves a symbolic link to
/// `attacker` in its place, so every pathname the operator supplied now reaches
/// the attacker tree. Running that from the resolution race hook places it
/// exactly where a real racing process would land: after a surface holds its
/// descriptors and before its first descriptor-relative operation.
#[cfg(all(test, any(target_os = "linux", target_vendor = "apple")))]
pub(crate) mod race_fixture {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::{install_race_hook, RaceHookGuard};

    pub(crate) struct RaceTree {
        _directory: TempDir,
        root: PathBuf,
    }

    /// Plant the fixture under a temporary root whose own path traverses no
    /// symbolic link, since the platform temporary directory is itself reached
    /// through one on macOS. Each tree holds a `target` file, so a test that
    /// asserts nothing outside was read or overwritten has bytes to compare.
    pub(crate) fn race_tree() -> RaceTree {
        let directory = TempDir::new().expect("temporary root");
        let root = directory
            .path()
            .canonicalize()
            .expect("the temporary root has a symlink-free path");
        fs::create_dir_all(root.join("genuine/inner")).expect("genuine tree");
        fs::create_dir_all(root.join("attacker/inner")).expect("attacker tree");
        fs::write(root.join("genuine/inner/target"), b"genuine").expect("genuine file");
        fs::write(root.join("attacker/inner/target"), b"attacker").expect("attacker file");
        RaceTree {
            _directory: directory,
            root,
        }
    }

    impl RaceTree {
        pub(crate) fn root(&self) -> &Path {
            &self.root
        }

        /// The directory whose paths the operator names.
        pub(crate) fn named_directory(&self) -> PathBuf {
            self.root.join("genuine/inner")
        }

        pub(crate) fn named(&self, relative: &str) -> PathBuf {
            self.named_directory().join(relative)
        }

        /// Where the named tree actually lives once the ancestor is swapped.
        pub(crate) fn moved_directory(&self) -> PathBuf {
            self.root.join("genuine-moved/inner")
        }

        pub(crate) fn moved(&self, relative: &str) -> PathBuf {
            self.moved_directory().join(relative)
        }

        /// The tree the operator never named, which the swapped ancestor points
        /// at.
        pub(crate) fn outside_directory(&self) -> PathBuf {
            self.root.join("attacker/inner")
        }

        pub(crate) fn outside(&self, relative: &str) -> PathBuf {
            self.outside_directory().join(relative)
        }

        /// Replace the resolved ancestor with a symbolic link into the tree the
        /// operator never named.
        pub(crate) fn swap_ancestor(&self) {
            swap(&self.root);
        }

        /// Arm the swap on the resolution race hook. It runs once, however many
        /// paths the surface resolves.
        pub(crate) fn arm(&self) -> RaceHookGuard {
            let root = self.root.clone();
            let mut swapped = false;
            install_race_hook(move || {
                if swapped {
                    return;
                }
                swapped = true;
                swap(&root);
            })
        }

        /// Every path that now exists under the tree the operator never named,
        /// relative to it and sorted, so a test can pin that the surface added
        /// nothing there.
        pub(crate) fn outside_entries(&self) -> Vec<String> {
            let mut found = Vec::new();
            collect(&self.outside_directory(), PathBuf::new(), &mut found);
            found.sort();
            found
        }
    }

    fn swap(root: &Path) {
        fs::rename(root.join("genuine"), root.join("genuine-moved")).expect("ancestor renamed");
        symlink(root.join("attacker"), root.join("genuine")).expect("ancestor replaced");
    }

    fn collect(directory: &Path, prefix: PathBuf, found: &mut Vec<String>) {
        for entry in fs::read_dir(directory).expect("the outside tree lists") {
            let entry = entry.expect("the outside tree lists");
            let relative = prefix.join(entry.file_name());
            let file_type = entry.file_type().expect("the outside entry has a type");
            if file_type.is_dir() {
                collect(&entry.path(), relative.clone(), found);
            }
            found.push(relative.to_string_lossy().into_owned());
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_vendor = "apple")))]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::io::{Read, Write};

    use super::race_fixture::race_tree;
    use super::{SafeDir, SafeEntry, SafePathError};

    #[test]
    fn resolution_refuses_an_ancestor_symbolic_link() {
        let tree = race_tree();
        let named = tree.named("target");
        tree.swap_ancestor();

        let refused = SafeEntry::resolve(&named).expect_err("an ancestor symlink is refused");
        assert_eq!(refused, SafePathError::Symlink);
    }

    #[test]
    fn resolution_refuses_a_parent_directory_component() {
        let tree = race_tree();
        let refused = SafeEntry::resolve(&tree.root().join("genuine/../attacker/inner/target"))
            .expect_err("a parent component is refused");
        assert_eq!(refused, SafePathError::Path);
    }

    #[test]
    fn a_read_after_an_ancestor_is_replaced_still_reads_the_named_file() {
        let tree = race_tree();
        let named = tree.named("target");
        let _guard = tree.arm();

        let entry = SafeEntry::resolve(&named).expect("the path resolves before the swap");
        let mut bytes = Vec::new();
        entry
            .open_read()
            .expect("the held descriptor opens the named file")
            .read_to_end(&mut bytes)
            .expect("the named file reads");

        assert_eq!(bytes, b"genuine");
        // The window is real: the same pathname now reaches the attacker tree.
        assert_eq!(
            fs::read(&named).expect("the pathname still resolves"),
            b"attacker"
        );
    }

    #[test]
    fn a_create_after_an_ancestor_is_replaced_never_writes_outside_the_named_tree() {
        let tree = race_tree();
        let named = tree.named("created");
        let _guard = tree.arm();

        let entry = SafeEntry::resolve(&named).expect("the path resolves before the swap");
        entry
            .create_new(0o600)
            .expect("the held descriptor creates the named file")
            .write_all(b"generated")
            .expect("the created file writes");

        assert_eq!(
            fs::read(tree.moved("created")).expect("the file lands in the named tree"),
            b"generated"
        );
        assert_eq!(tree.outside_entries(), vec!["target".to_owned()]);
    }

    #[test]
    fn a_publication_after_an_ancestor_is_replaced_never_publishes_outside_the_named_tree() {
        let tree = race_tree();
        let named = tree.named("published");
        let _guard = tree.arm();

        let entry = SafeEntry::resolve(&named).expect("the path resolves before the swap");
        entry
            .parent()
            .create_new(OsStr::new("staged.tmp"), 0o600)
            .expect("the staged sibling is created")
            .write_all(b"published")
            .expect("the staged sibling writes");
        entry
            .publish_from(OsStr::new("staged.tmp"))
            .expect("the staged sibling publishes");

        assert_eq!(
            fs::read(tree.moved("published")).expect("the publication lands in the named tree"),
            b"published"
        );
        assert_eq!(tree.outside_entries(), vec!["target".to_owned()]);
    }

    #[test]
    fn publication_refuses_to_replace_an_existing_destination() {
        let tree = race_tree();
        let entry = SafeEntry::resolve(&tree.named("target")).expect("the path resolves");
        entry
            .parent()
            .create_new(OsStr::new("staged.tmp"), 0o600)
            .expect("the staged sibling is created");

        entry
            .publish_from(OsStr::new("staged.tmp"))
            .expect_err("publication never replaces an existing destination");
        assert_eq!(
            fs::read(tree.named("target")).expect("the destination survives"),
            b"genuine"
        );
    }

    #[test]
    fn a_directory_read_after_an_ancestor_is_replaced_lists_the_named_directory() {
        let tree = race_tree();
        let named = tree.named_directory();
        fs::write(tree.outside("planted"), b"planted").expect("planted entry");
        let _guard = tree.arm();

        let directory = SafeDir::resolve(&named).expect("the directory resolves before the swap");
        let names: Vec<_> = directory
            .read_entries()
            .expect("the held descriptor lists the named directory")
            .into_iter()
            .map(|entry| entry.name)
            .collect();

        assert_eq!(names, vec![OsStr::new("target").to_owned()]);
    }

    #[test]
    fn a_tree_removal_after_an_ancestor_is_replaced_never_removes_outside_the_named_tree() {
        let tree = race_tree();
        fs::create_dir_all(tree.root().join("genuine/staged/nested")).expect("staged tree");
        fs::write(tree.root().join("genuine/staged/nested/file"), b"staged").expect("staged file");
        fs::create_dir_all(tree.root().join("attacker/staged/nested")).expect("decoy tree");
        fs::write(tree.root().join("attacker/staged/nested/file"), b"decoy").expect("decoy file");
        let _guard = tree.arm();

        let directory = SafeDir::resolve(&tree.root().join("genuine"))
            .expect("the directory resolves before the swap");
        directory
            .remove_tree(OsStr::new("staged"))
            .expect("the held descriptor removes the named tree");

        assert!(!tree.root().join("genuine-moved/staged").exists());
        assert!(tree.root().join("attacker/staged/nested/file").exists());
    }

    #[test]
    fn an_unsupported_platform_refusal_reports_a_closed_path() {
        let refused = SafePathError::Unsupported.into_io();
        assert_eq!(refused.kind(), std::io::ErrorKind::Other);
        assert!(refused.to_string().contains("unavailable on this platform"));
        assert!(!SafePathError::Unsupported.is_not_found());
    }
}

#[cfg(all(test, not(any(target_os = "linux", target_vendor = "apple"))))]
mod unsupported_tests {
    use std::path::Path;

    use super::{SafeDir, SafeEntry, SafePathError};

    #[test]
    fn every_resolution_fails_closed_without_a_kernel_enforced_primitive() {
        assert_eq!(
            SafeEntry::resolve(Path::new("/tmp/example")).expect_err("resolution refuses"),
            SafePathError::Unsupported
        );
        assert_eq!(
            SafeDir::resolve(Path::new("/tmp")).expect_err("resolution refuses"),
            SafePathError::Unsupported
        );
    }
}

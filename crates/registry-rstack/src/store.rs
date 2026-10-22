// SPDX-License-Identifier: Apache-2.0
//! User-local immutable installation generations, activation, and invocation leases.

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const OWNERSHIP_SCHEMA: &str = "registry-stack.generation-ownership.v1";
const OWNERSHIP_FILE: &str = ".rstack-ownership.json";
const LEASE_FILE: &str = ".rstack-lease";
const MUTATION_LOCK: &str = ".mutation.lock";
const REMOVAL_DIR: &str = ".removing";
const MAX_OWNERSHIP_BYTES: u64 = 16 * 1024 * 1024;

static UNIQUE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct GenerationStore {
    install_root: PathBuf,
    bin_dir: PathBuf,
}

#[derive(Debug)]
pub struct MutationGuard<'store> {
    store: &'store GenerationStore,
    _lock: File,
}

#[derive(Debug)]
pub struct StagedGeneration<'mutation, 'store> {
    mutation: &'mutation MutationGuard<'store>,
    name: String,
    path: PathBuf,
    published: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Generation {
    name: String,
    path: PathBuf,
}

#[derive(Debug)]
pub struct InvocationLease {
    generation: Generation,
    lease: File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicLinkStatus {
    Created,
    AlreadyOwned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreserveReason {
    Active,
    InUse,
    Modified,
    Unowned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreservedGeneration {
    pub name: String,
    pub reason: PreserveReason,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CleanupReport {
    pub removed: Vec<String>,
    pub preserved: Vec<PreservedGeneration>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FullRemovalReport {
    pub removed_generations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnershipInventory {
    schema_version: String,
    generation: String,
    files: BTreeMap<String, OwnedFile>,
    directories: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnedFile {
    size: u64,
    sha256: String,
    mode: u32,
}

struct RemovalGeneration {
    name: String,
    path: PathBuf,
    inventory: Option<OwnershipInventory>,
    lease: Option<File>,
    staged_for_removal: bool,
}

impl GenerationStore {
    pub fn new(install_root: impl Into<PathBuf>, bin_dir: impl Into<PathBuf>) -> Self {
        Self {
            install_root: install_root.into(),
            bin_dir: bin_dir.into(),
        }
    }

    pub fn install_root(&self) -> &Path {
        &self.install_root
    }

    pub fn generations_dir(&self) -> PathBuf {
        self.install_root.join("generations")
    }

    pub fn current_link(&self) -> PathBuf {
        self.install_root.join("current")
    }

    pub fn public_link(&self) -> PathBuf {
        self.bin_dir.join("rstack")
    }

    pub(crate) fn public_link_target(&self) -> Result<PathBuf, String> {
        let target = self.current_link().join("rstack");
        if target.is_absolute() {
            return Ok(target);
        }
        std::env::current_dir()
            .map(|directory| directory.join(target))
            .map_err(|error| format!("cannot resolve public rstack link target: {error}"))
    }

    /// Report whether a complete current installation is selected without
    /// creating directories, lock files, or any other local state.
    pub fn has_installation(&self) -> Result<bool, String> {
        match fs::symlink_metadata(&self.install_root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(format!(
                    "installation root {} must be a directory",
                    self.install_root.display()
                ))
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(format!("cannot inspect installation root: {error}")),
        }
        match fs::symlink_metadata(self.current_link()) {
            Ok(_) => {
                self.inspect_existing_layout()?;
                let selection_lock = open_existing_lock(&self.install_root.join(MUTATION_LOCK))?;
                FileExt::lock_shared(&selection_lock)
                    .map_err(|error| format!("cannot lock Registry Stack installation: {error}"))?;
                self.resolve_current().map(|_| true)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!("cannot inspect current generation: {error}")),
        }
    }

    /// Serialize an installation mutation. Installation state must be read only
    /// after this guard has been acquired.
    pub fn lock_mutation(&self) -> Result<MutationGuard<'_>, String> {
        self.ensure_layout()?;
        let lock = open_lock(&self.install_root.join(MUTATION_LOCK))?;
        FileExt::lock_exclusive(&lock)
            .map_err(|error| format!("cannot lock Registry Stack installation: {error}"))?;
        Ok(MutationGuard {
            store: self,
            _lock: lock,
        })
    }

    /// Select the current generation and acquire its shared lease under one
    /// shared mutation lock, so cleanup cannot pass between those operations.
    pub fn acquire_current(&self) -> Result<InvocationLease, String> {
        self.inspect_existing_layout()?;
        let selection_lock = open_existing_lock(&self.install_root.join(MUTATION_LOCK))?;
        FileExt::lock_shared(&selection_lock)
            .map_err(|error| format!("cannot lock Registry Stack installation: {error}"))?;
        let generation = self.resolve_current()?;
        let lease_path = generation.path.join(LEASE_FILE);
        let metadata = fs::symlink_metadata(&lease_path)
            .map_err(|error| format!("cannot inspect generation lease: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err("selected generation lease is not a regular file".into());
        }
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lease_path)
            .map_err(|error| format!("cannot open generation lease: {error}"))?;
        FileExt::lock_shared(&lease)
            .map_err(|error| format!("cannot acquire generation lease: {error}"))?;
        drop(selection_lock);
        Ok(InvocationLease { generation, lease })
    }

    fn ensure_layout(&self) -> Result<(), String> {
        ensure_directory(&self.install_root, "installation root")?;
        ensure_directory(&self.generations_dir(), "generation directory")
    }

    fn inspect_existing_layout(&self) -> Result<(), String> {
        let generations = self.generations_dir();
        for (path, description) in [
            (&self.install_root, "installation root"),
            (&generations, "generation directory"),
        ] {
            let metadata = fs::symlink_metadata(path).map_err(|error| {
                if error.kind() == ErrorKind::NotFound {
                    "no Registry Stack installation is selected".to_owned()
                } else {
                    format!("cannot inspect {description}: {error}")
                }
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "{description} {} must be a directory",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    fn resolve_current(&self) -> Result<Generation, String> {
        let current = self.current_link();
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                "no Registry Stack installation is selected".to_owned()
            } else {
                format!("cannot inspect current generation: {error}")
            }
        })?;
        if !metadata.file_type().is_symlink() {
            return Err("current installation entry is unrelated; refusing to use it".into());
        }
        let target = fs::read_link(&current)
            .map_err(|error| format!("cannot read current generation: {error}"))?;
        let name = generation_name_from_target(&target)?;
        let path = self.generations_dir().join(&name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("current generation {name} is unavailable: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "current generation {name} is not an owned directory"
            ));
        }
        let inventory = read_inventory(&path, &name)?;
        let observed = inventory_generation(&path, &name)?;
        if observed != inventory {
            return Err(format!(
                "selected generation {name} changed after installation"
            ));
        }
        Ok(Generation { name, path })
    }
}

impl MutationGuard<'_> {
    /// Re-read the selected generation after acquiring the mutation lock.
    pub fn current(&self) -> Result<Option<Generation>, String> {
        match fs::symlink_metadata(self.store.current_link()) {
            Ok(_) => self.store.resolve_current().map(Some),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("cannot inspect current generation: {error}")),
        }
    }

    pub fn stage_generation(&self, name: &str) -> Result<StagedGeneration<'_, '_>, String> {
        validate_generation_name(name)?;
        let destination = self.store.generations_dir().join(name);
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                return Err(format!(
                    "generation {name} already exists; refusing to replace it"
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect generation {name}: {error}")),
        }
        let staging_root = self.store.install_root.join(".staging");
        ensure_directory(&staging_root, "generation staging directory")?;
        let path = staging_root.join(format!("{name}.{}", unique_suffix()));
        fs::create_dir(&path)
            .map_err(|error| format!("cannot create generation staging directory: {error}"))?;
        Ok(StagedGeneration {
            mutation: self,
            name: name.to_owned(),
            path,
            published: false,
        })
    }

    /// Atomically switch `current` to a complete generation published by this store.
    pub fn activate(&self, generation: &Generation) -> Result<(), String> {
        let expected = self.store.generations_dir().join(&generation.name);
        if generation.path != expected {
            return Err("generation belongs to another installation".into());
        }
        let inventory = read_inventory(&generation.path, &generation.name)?;
        let observed = inventory_generation(&generation.path, &generation.name)?;
        if inventory != observed {
            return Err(format!(
                "generation {} changed after it was staged; refusing activation",
                generation.name
            ));
        }

        let current = self.store.current_link();
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if !metadata.file_type().is_symlink() {
                    return Err(
                        "current installation entry is unrelated; refusing to replace it".into(),
                    );
                }
                let target = fs::read_link(&current)
                    .map_err(|error| format!("cannot read current generation: {error}"))?;
                let old_name = generation_name_from_target(&target)?;
                read_inventory(&self.store.generations_dir().join(&old_name), &old_name).map_err(
                    |_| "current installation link is unrelated; refusing to replace it".to_owned(),
                )?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect current generation: {error}")),
        }

        let temporary = self
            .store
            .install_root
            .join(format!(".current.{}", unique_suffix()));
        let target = PathBuf::from("generations").join(&generation.name);
        create_symlink(&target, &temporary)?;
        if let Err(error) = fs::rename(&temporary, &current) {
            let cleanup = fs::remove_file(&temporary);
            return match cleanup {
                Ok(()) => Err(format!(
                    "cannot activate generation {}: {error}",
                    generation.name
                )),
                Err(cleanup) => Err(format!(
                    "cannot activate generation {}: {error}; cannot remove temporary link: {cleanup}",
                    generation.name
                )),
            };
        }
        sync_directory(&self.store.install_root, "installation root")
    }

    /// Create the single public executable link, while preserving every other
    /// pre-existing file or link at that path.
    pub fn ensure_public_link(&self) -> Result<PublicLinkStatus, String> {
        ensure_directory(&self.store.bin_dir, "public binary directory")?;
        let link = self.store.public_link();
        let target = self.store.public_link_target()?;
        match fs::symlink_metadata(&link) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    && fs::read_link(&link)
                        .map_err(|error| format!("cannot read public rstack link: {error}"))?
                        == target
                {
                    return Ok(PublicLinkStatus::AlreadyOwned);
                }
                return Err(format!(
                    "{} is unrelated; refusing to replace it",
                    link.display()
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect {}: {error}", link.display())),
        }
        create_symlink(&target, &link)?;
        sync_directory(&self.store.bin_dir, "public binary directory")?;
        Ok(PublicLinkStatus::Created)
    }

    /// Remove only inactive generations whose complete recorded identity still
    /// matches and whose kernel lease can be acquired exclusively.
    pub fn cleanup(&self) -> Result<CleanupReport, String> {
        let active = match fs::symlink_metadata(self.store.current_link()) {
            Ok(_) => Some(self.store.resolve_current()?.name),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(format!("cannot inspect current generation: {error}")),
        };
        let mut entries = fs::read_dir(self.store.generations_dir())
            .map_err(|error| format!("cannot list installation generations: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot list installation generations: {error}"))?;
        entries.sort_by_key(|entry| entry.file_name());
        let mut report = CleanupReport::default();

        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect generation {name}: {error}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                report.preserve(name, PreserveReason::Unowned);
                continue;
            }
            if active.as_deref() == Some(name.as_str()) {
                report.preserve(name, PreserveReason::Active);
                continue;
            }
            let inventory = match read_inventory(&path, &name) {
                Ok(inventory) => inventory,
                Err(_) => {
                    report.preserve(name, PreserveReason::Unowned);
                    continue;
                }
            };
            let lease_path = path.join(LEASE_FILE);
            match fs::symlink_metadata(&lease_path) {
                Ok(metadata) if metadata.file_type().is_file() => {}
                _ => {
                    report.preserve(name, PreserveReason::Modified);
                    continue;
                }
            }
            let lease = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lease_path)
                .map_err(|error| format!("cannot open lease for generation {name}: {error}"))?;
            match FileExt::try_lock_exclusive(&lease) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    report.preserve(name, PreserveReason::InUse);
                    continue;
                }
                Err(error) => {
                    return Err(format!(
                        "cannot inspect lease for generation {name}: {error}"
                    ));
                }
            }
            let observed = match inventory_generation(&path, &name) {
                Ok(observed) => observed,
                Err(_) => {
                    report.preserve(name, PreserveReason::Modified);
                    continue;
                }
            };
            if observed != inventory {
                report.preserve(name, PreserveReason::Modified);
                continue;
            }
            remove_owned_generation(&path, &inventory, lease)?;
            report.removed.push(name);
        }
        if !report.removed.is_empty() {
            sync_directory(&self.store.generations_dir(), "generation directory")?;
        }
        Ok(report)
    }

    /// Remove the owned public entry and every owned generation after proving
    /// that none are in use or changed. The mutation lock and its directory
    /// remain as the serialization point for a later reinstall.
    pub fn remove_installation(&self) -> Result<FullRemovalReport, String> {
        self.preflight_removal_layout()?;
        match fs::symlink_metadata(self.store.current_link()) {
            Ok(_) => {
                self.current()?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect current generation: {error}")),
        }

        let public_link = self.store.public_link();
        let remove_public_link = match fs::symlink_metadata(&public_link) {
            Ok(metadata) => {
                if !metadata.file_type().is_symlink()
                    || fs::read_link(&public_link)
                        .map_err(|error| format!("cannot read public rstack link: {error}"))?
                        != self.store.public_link_target()?
                {
                    return Err(format!(
                        "{} is unrelated; refusing to remove it",
                        public_link.display()
                    ));
                }
                true
            }
            Err(error) if error.kind() == ErrorKind::NotFound => false,
            Err(error) => {
                return Err(format!(
                    "cannot inspect public rstack link {}: {error}",
                    public_link.display()
                ));
            }
        };

        let mut entries = fs::read_dir(self.store.generations_dir())
            .map_err(|error| format!("cannot list installation generations: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot list installation generations: {error}"))?;
        entries.sort_by_key(|entry| entry.file_name());
        let mut owned = Vec::new();
        for entry in entries {
            let name = entry
                .file_name()
                .to_str()
                .ok_or("generation name is not UTF-8")?
                .to_owned();
            validate_generation_name(&name)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect generation {name}: {error}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "generation {name} is unowned; refusing full uninstall"
                ));
            }
            let inventory = read_inventory(&path, &name).map_err(|error| {
                format!("{error}; refusing full uninstall while unowned files remain")
            })?;
            let observed = inventory_generation(&path, &name)?;
            if observed != inventory {
                return Err(format!(
                    "generation {name} changed after installation; refusing full uninstall"
                ));
            }
            let lease = lock_generation_lease(&path, &name, true)?;
            owned.push(RemovalGeneration {
                name,
                path,
                inventory: Some(inventory),
                lease,
                staged_for_removal: false,
            });
        }

        let removal_root = self.store.install_root.join(REMOVAL_DIR);
        if removal_root.exists() {
            let mut entries = fs::read_dir(&removal_root)
                .map_err(|error| format!("cannot inspect removal recovery: {error}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("cannot inspect removal recovery: {error}"))?;
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let name = entry
                    .file_name()
                    .to_str()
                    .ok_or("removal generation name is not UTF-8")?
                    .to_owned();
                validate_generation_name(&name)?;
                if owned.iter().any(|generation| generation.name == name) {
                    return Err(format!(
                        "generation {name} appears in active and removal storage"
                    ));
                }
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).map_err(|error| {
                    format!("cannot inspect removal generation {name}: {error}")
                })?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "removal generation {name} is unowned; refusing full uninstall"
                    ));
                }
                let inventory = match read_inventory(&path, &name) {
                    Ok(inventory) => {
                        if !remaining_generation_matches(&path, &name, &inventory)? {
                            return Err(format!(
                                "removal generation {name} contains changed or unrelated files"
                            ));
                        }
                        Some(inventory)
                    }
                    Err(_)
                        if fs::read_dir(&path)
                            .map_err(|error| {
                                format!("cannot inspect removal generation {name}: {error}")
                            })?
                            .next()
                            .is_none() =>
                    {
                        None
                    }
                    Err(error) => {
                        return Err(format!(
                            "{error}; refusing full uninstall while unowned files remain"
                        ));
                    }
                };
                let lease = lock_generation_lease(&path, &name, false)?;
                owned.push(RemovalGeneration {
                    name,
                    path,
                    inventory,
                    lease,
                    staged_for_removal: true,
                });
            }
        }
        if owned.is_empty() {
            return Err("no Registry Stack installation is selected".into());
        }

        if remove_public_link {
            fs::remove_file(&public_link).map_err(|error| {
                format!(
                    "cannot remove public link {}: {error}",
                    public_link.display()
                )
            })?;
            sync_directory(&self.store.bin_dir, "public binary directory")?;
        }
        match fs::symlink_metadata(self.store.current_link()) {
            Ok(_) => {
                fs::remove_file(self.store.current_link())
                    .map_err(|error| format!("cannot remove current generation link: {error}"))?;
                sync_directory(&self.store.install_root, "installation root")?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect current generation: {error}")),
        }

        ensure_directory(&removal_root, "removal recovery directory")?;
        sync_directory(&self.store.install_root, "installation root")?;
        for generation in &mut owned {
            if !generation.staged_for_removal {
                let destination = removal_root.join(&generation.name);
                fs::rename(&generation.path, &destination).map_err(|error| {
                    format!(
                        "cannot stage generation {} for removal: {error}",
                        generation.name
                    )
                })?;
                generation.path = destination;
                generation.staged_for_removal = true;
            }
        }
        sync_directory(&self.store.generations_dir(), "generation directory")?;
        sync_directory(&removal_root, "removal recovery directory")?;

        let mut report = FullRemovalReport::default();
        for generation in owned {
            if let Some(inventory) = generation.inventory {
                remove_owned_generation_recoverable(
                    &generation.path,
                    &inventory,
                    generation.lease,
                )?;
            } else {
                fs::remove_dir(&generation.path).map_err(|error| {
                    format!(
                        "cannot remove empty generation recovery {}: {error}",
                        generation.path.display()
                    )
                })?;
            }
            report.removed_generations.push(generation.name);
        }
        fs::remove_dir(&removal_root)
            .map_err(|error| format!("cannot remove recovery directory: {error}"))?;
        fs::remove_dir(self.store.generations_dir())
            .map_err(|error| format!("cannot remove generation directory: {error}"))?;
        let staging = self.store.install_root.join(".staging");
        if staging.exists() {
            fs::remove_dir(&staging)
                .map_err(|error| format!("cannot remove empty staging directory: {error}"))?;
        }
        sync_directory(&self.store.install_root, "installation root")?;
        Ok(report)
    }

    fn preflight_removal_layout(&self) -> Result<(), String> {
        for entry in fs::read_dir(&self.store.install_root)
            .map_err(|error| format!("cannot inspect installation root: {error}"))?
        {
            let entry =
                entry.map_err(|error| format!("cannot inspect installation root: {error}"))?;
            let name = entry.file_name();
            match name.to_str() {
                Some("current" | "generations" | MUTATION_LOCK) => {}
                Some(REMOVAL_DIR) => {
                    let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                        format!("cannot inspect removal recovery directory: {error}")
                    })?;
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        return Err(
                            "removal recovery entry is unrelated; refusing full uninstall".into(),
                        );
                    }
                }
                Some(".staging") => {
                    let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                        format!("cannot inspect generation staging directory: {error}")
                    })?;
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        return Err(
                            "generation staging entry is unrelated; refusing full uninstall".into(),
                        );
                    }
                    if fs::read_dir(entry.path())
                        .map_err(|error| {
                            format!("cannot inspect generation staging directory: {error}")
                        })?
                        .next()
                        .is_some()
                    {
                        return Err(
                            "incomplete generation staging remains; refusing full uninstall".into(),
                        );
                    }
                }
                _ => {
                    return Err(format!(
                        "installation root contains unrelated entry {}; refusing full uninstall",
                        entry.path().display()
                    ));
                }
            }
        }
        Ok(())
    }
}

impl StagedGeneration<'_, '_> {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Publish a generation only after the caller has verified every release
    /// asset. This method independently verifies the complete local shape,
    /// records its identity, syncs it, and exposes it under `generations/`.
    pub fn publish_preverified(mut self) -> Result<Generation, String> {
        validate_required_generation_files(&self.path)?;
        for reserved in [OWNERSHIP_FILE, LEASE_FILE] {
            match fs::symlink_metadata(self.path.join(reserved)) {
                Ok(_) => {
                    return Err(format!(
                        "staged generation contains reserved entry {reserved}"
                    ));
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(format!("cannot inspect staged generation: {error}")),
            }
        }
        let inventory = inventory_generation(&self.path, &self.name)?;
        let lease_path = self.path.join(LEASE_FILE);
        let lease = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lease_path)
            .map_err(|error| format!("cannot create generation lease: {error}"))?;
        lease
            .sync_all()
            .map_err(|error| format!("cannot sync generation lease: {error}"))?;
        let ownership_path = self.path.join(OWNERSHIP_FILE);
        let encoded = serde_json::to_vec_pretty(&inventory)
            .map_err(|error| format!("cannot encode generation ownership: {error}"))?;
        let mut ownership = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&ownership_path)
            .map_err(|error| format!("cannot create generation ownership: {error}"))?;
        ownership
            .write_all(&encoded)
            .and_then(|()| ownership.write_all(b"\n"))
            .and_then(|()| ownership.sync_all())
            .map_err(|error| format!("cannot write generation ownership: {error}"))?;
        sync_tree(&self.path)?;

        let destination = self.mutation.store.generations_dir().join(&self.name);
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                return Err(format!(
                    "generation {} already exists; refusing to replace it",
                    self.name
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect generation {}: {error}", self.name)),
        }
        fs::rename(&self.path, &destination)
            .map_err(|error| format!("cannot publish generation {}: {error}", self.name))?;
        sync_directory(
            &self.mutation.store.generations_dir(),
            "generation directory",
        )?;
        self.published = true;
        Ok(Generation {
            name: self.name.clone(),
            path: destination,
        })
    }
}

impl Drop for StagedGeneration<'_, '_> {
    fn drop(&mut self) {
        if !self.published {
            if let Err(error) = remove_staging_tree(&self.path) {
                eprintln!(
                    "rstack: {error}; incomplete staging remains at {}",
                    self.path.display()
                );
            }
        }
    }
}

impl Generation {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl InvocationLease {
    pub fn generation(&self) -> &Generation {
        &self.generation
    }

    pub fn path(&self) -> &Path {
        self.generation.path()
    }

    pub fn lease_file(&self) -> &File {
        &self.lease
    }

    /// The descriptor that must be made inheritable immediately before exec.
    /// Keeping it open in the executed product and its nested helpers retains
    /// the kernel lease even after the launcher process is replaced.
    #[cfg(unix)]
    pub fn lease_fd(&self) -> RawFd {
        self.lease.as_raw_fd()
    }
}

impl CleanupReport {
    pub fn reason_for(&self, name: &str) -> Option<PreserveReason> {
        self.preserved
            .iter()
            .find(|generation| generation.name == name)
            .map(|generation| generation.reason)
    }

    fn preserve(&mut self, name: String, reason: PreserveReason) {
        self.preserved.push(PreservedGeneration { name, reason });
    }
}

fn validate_generation_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err("generation name must be a safe ASCII basename".into());
    }
    Ok(())
}

fn generation_name_from_target(target: &Path) -> Result<String, String> {
    let mut components = target.components();
    if components.next() != Some(Component::Normal("generations".as_ref())) {
        return Err("current installation link is unrelated; refusing to follow it".into());
    }
    let name = match components.next() {
        Some(Component::Normal(name)) => name
            .to_str()
            .ok_or("current generation name is not UTF-8")?
            .to_owned(),
        _ => return Err("current installation link is unrelated; refusing to follow it".into()),
    };
    if components.next().is_some() {
        return Err("current installation link is unrelated; refusing to follow it".into());
    }
    validate_generation_name(&name)?;
    Ok(name)
}

fn validate_required_generation_files(path: &Path) -> Result<(), String> {
    for name in ["rstack", "manifest.json"] {
        let candidate = path.join(name);
        let metadata = fs::symlink_metadata(&candidate)
            .map_err(|error| format!("staged generation lacks regular {name}: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err(format!("staged generation {name} must be a regular file"));
        }
    }
    #[cfg(unix)]
    if fs::symlink_metadata(path.join("rstack"))
        .map_err(|error| format!("cannot inspect staged rstack: {error}"))?
        .permissions()
        .mode()
        & 0o111
        == 0
    {
        return Err("staged generation rstack is not executable".into());
    }
    Ok(())
}

fn inventory_generation(path: &Path, name: &str) -> Result<OwnershipInventory, String> {
    let mut files = BTreeMap::new();
    let mut directories = Vec::new();
    inventory_directory(path, path, &mut files, &mut directories)?;
    directories.sort();
    Ok(OwnershipInventory {
        schema_version: OWNERSHIP_SCHEMA.to_owned(),
        generation: name.to_owned(),
        files,
        directories,
    })
}

fn inventory_directory(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, OwnedFile>,
    directories: &mut Vec<String>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot inspect staged generation: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot inspect staged generation: {error}"))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "generation entry escaped its root")?;
        if relative.components().count() == 1
            && matches!(relative.to_str(), Some(OWNERSHIP_FILE) | Some(LEASE_FILE))
        {
            continue;
        }
        let relative_text = relative_path_text(relative)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect generation entry {relative_text}: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "generation entry {relative_text} must not be a symlink"
            ));
        }
        if metadata.is_dir() {
            directories.push(relative_text);
            inventory_directory(root, &path, files, directories)?;
        } else if metadata.file_type().is_file() {
            let mut file = File::open(&path).map_err(|error| {
                format!("cannot read generation entry {relative_text}: {error}")
            })?;
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = file.read(&mut buffer).map_err(|error| {
                    format!("cannot read generation entry {relative_text}: {error}")
                })?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
            }
            let owned = OwnedFile {
                size: metadata.len(),
                sha256: hex::encode(hash.finalize()),
                mode: file_mode(&metadata),
            };
            if files.insert(relative_text.clone(), owned).is_some() {
                return Err(format!("generation repeats entry {relative_text}"));
            }
        } else {
            return Err(format!(
                "generation entry {relative_text} has an unsupported type"
            ));
        }
    }
    Ok(())
}

fn read_inventory(path: &Path, name: &str) -> Result<OwnershipInventory, String> {
    let ownership_path = path.join(OWNERSHIP_FILE);
    let metadata = fs::symlink_metadata(&ownership_path)
        .map_err(|error| format!("generation {name} has no ownership record: {error}"))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_OWNERSHIP_BYTES {
        return Err(format!("generation {name} has an invalid ownership record"));
    }
    let raw = fs::read(&ownership_path)
        .map_err(|error| format!("cannot read generation {name} ownership: {error}"))?;
    let inventory: OwnershipInventory = serde_json::from_slice(&raw)
        .map_err(|error| format!("cannot parse generation {name} ownership: {error}"))?;
    if inventory.schema_version != OWNERSHIP_SCHEMA || inventory.generation != name {
        return Err(format!("generation {name} ownership identity is invalid"));
    }
    for path in inventory.files.keys().chain(inventory.directories.iter()) {
        validate_inventory_path(path)?;
    }
    Ok(inventory)
}

fn validate_inventory_path(path: &str) -> Result<(), String> {
    let candidate = Path::new(path);
    if path.is_empty()
        || candidate.is_absolute()
        || candidate
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || matches!(path, OWNERSHIP_FILE | LEASE_FILE)
    {
        return Err(format!(
            "generation ownership contains an unsafe path: {path}"
        ));
    }
    Ok(())
}

fn remove_owned_generation(
    path: &Path,
    inventory: &OwnershipInventory,
    lease: File,
) -> Result<(), String> {
    for relative in inventory.files.keys() {
        fs::remove_file(path.join(relative)).map_err(|error| {
            format!(
                "cannot remove owned generation file {}: {error}",
                path.join(relative).display()
            )
        })?;
    }
    fs::remove_file(path.join(OWNERSHIP_FILE))
        .map_err(|error| format!("cannot remove generation ownership record: {error}"))?;
    fs::remove_file(path.join(LEASE_FILE))
        .map_err(|error| format!("cannot remove generation lease: {error}"))?;
    drop(lease);
    let mut directories = inventory.directories.clone();
    directories
        .sort_by_key(|directory| std::cmp::Reverse(Path::new(directory).components().count()));
    for relative in directories {
        fs::remove_dir(path.join(&relative)).map_err(|error| {
            format!(
                "cannot remove owned generation directory {}: {error}",
                path.join(relative).display()
            )
        })?;
    }
    fs::remove_dir(path)
        .map_err(|error| format!("cannot remove owned generation {}: {error}", path.display()))
}

fn lock_generation_lease(path: &Path, name: &str, required: bool) -> Result<Option<File>, String> {
    let lease_path = path.join(LEASE_FILE);
    match fs::symlink_metadata(&lease_path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => {
            return Err(format!(
                "generation {name} lease changed; refusing full uninstall"
            ));
        }
        Err(error) if error.kind() == ErrorKind::NotFound && !required => return Ok(None),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(format!(
                "generation {name} lease changed; refusing full uninstall"
            ));
        }
        Err(error) => {
            return Err(format!(
                "cannot inspect lease for generation {name}: {error}"
            ))
        }
    }
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lease_path)
        .map_err(|error| format!("cannot open lease for generation {name}: {error}"))?;
    match FileExt::try_lock_exclusive(&lease) {
        Ok(()) => Ok(Some(lease)),
        Err(error) if error.kind() == ErrorKind::WouldBlock => Err(format!(
            "generation {name} is in use; refusing full uninstall"
        )),
        Err(error) => Err(format!(
            "cannot inspect lease for generation {name}: {error}"
        )),
    }
}

fn remaining_generation_matches(
    path: &Path,
    name: &str,
    inventory: &OwnershipInventory,
) -> Result<bool, String> {
    let observed = inventory_generation(path, name)?;
    if observed
        .files
        .iter()
        .any(|(file, identity)| inventory.files.get(file) != Some(identity))
    {
        return Ok(false);
    }
    Ok(observed
        .directories
        .iter()
        .all(|directory| inventory.directories.contains(directory)))
}

fn remove_owned_generation_recoverable(
    path: &Path,
    inventory: &OwnershipInventory,
    lease: Option<File>,
) -> Result<(), String> {
    if !remaining_generation_matches(path, &inventory.generation, inventory)? {
        return Err(format!(
            "removal generation {} contains changed or unrelated files",
            inventory.generation
        ));
    }
    for relative in inventory.files.keys() {
        match fs::remove_file(path.join(relative)) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot remove owned generation file {}: {error}",
                    path.join(relative).display()
                ));
            }
        }
    }
    let mut directories = inventory.directories.clone();
    directories
        .sort_by_key(|directory| std::cmp::Reverse(Path::new(directory).components().count()));
    for relative in directories {
        match fs::remove_dir(path.join(&relative)) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot remove owned generation directory {}: {error}",
                    path.join(relative).display()
                ));
            }
        }
    }
    drop(lease);
    for reserved in [LEASE_FILE, OWNERSHIP_FILE] {
        match fs::remove_file(path.join(reserved)) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot remove generation metadata {reserved}: {error}"
                ));
            }
        }
    }
    fs::remove_dir(path)
        .map_err(|error| format!("cannot remove owned generation {}: {error}", path.display()))
}

fn remove_staging_tree(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("cannot inspect staging directory: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("generation staging path is not a directory".into());
    }
    let entries = fs::read_dir(path)
        .map_err(|error| format!("cannot inspect staging directory: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot inspect staging directory: {error}"))?;
    for entry in entries {
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child)
            .map_err(|error| format!("cannot inspect staging entry: {error}"))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            remove_staging_tree(&child)?;
        } else {
            fs::remove_file(&child)
                .map_err(|error| format!("cannot remove staging entry: {error}"))?;
        }
    }
    fs::remove_dir(path).map_err(|error| format!("cannot remove staging directory: {error}"))
}

fn sync_tree(path: &Path) -> Result<(), String> {
    let entries = fs::read_dir(path)
        .map_err(|error| format!("cannot sync staged generation: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot sync staged generation: {error}"))?;
    for entry in entries {
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child)
            .map_err(|error| format!("cannot sync staged generation: {error}"))?;
        if metadata.is_dir() {
            sync_tree(&child)?;
        } else if metadata.file_type().is_file() {
            File::open(&child)
                .and_then(|file| file.sync_all())
                .map_err(|error| format!("cannot sync {}: {error}", child.display()))?;
        }
    }
    sync_directory(path, "staged generation directory")
}

fn ensure_directory(path: &Path, description: &str) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("cannot create {description} {}: {error}", path.display()))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {description} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "{description} {} must be a directory",
            path.display()
        ));
    }
    Ok(())
}

fn open_lock(path: &Path) -> Result<File, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err("installation mutation lock is not a regular file".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect installation mutation lock: {error}"
            ));
        }
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|error| format!("cannot open installation mutation lock: {error}"))
}

fn open_existing_lock(path: &Path) -> Result<File, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            "no Registry Stack installation is selected".to_owned()
        } else {
            format!("cannot inspect installation mutation lock: {error}")
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err("installation mutation lock is not a regular file".into());
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("cannot open installation mutation lock: {error}"))
}

fn relative_path_text(path: &Path) -> Result<String, String> {
    let text = path
        .to_str()
        .ok_or("generation entry path is not UTF-8")?
        .to_owned();
    validate_inventory_path(&text)?;
    Ok(text)
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = UNIQUE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{}-{nanos}-{sequence}", std::process::id())
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    metadata.mode() & 0o7777
}

#[cfg(not(unix))]
fn file_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> Result<(), String> {
    symlink(target, link).map_err(|error| format!("cannot create link {}: {error}", link.display()))
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, _link: &Path) -> Result<(), String> {
    Err("generation links are unsupported on this platform".into())
}

fn sync_directory(path: &Path, description: &str) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync {description} {}: {error}", path.display()))
}

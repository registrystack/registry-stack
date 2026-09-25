// SPDX-License-Identifier: Apache-2.0

//! Offline audit journal verification, export, and restore acknowledgement.
//!
//! Verification and export read the chain the runtime configuration names
//! under the key `audit.hashKeyRef` resolves, and neither writes to the journal
//! nor takes the writer's place. Acknowledging a restore takes the writer's
//! place while every runtime is stopped, and appends one acknowledgement
//! record. Chain traversal, verification, and the acknowledgement stay in the
//! runtime crate; this module owns argument handling, the owner-only export
//! file, and the refusal an operator reads.

use std::fs::{self, File, OpenOptions};
use std::io::BufWriter;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use registry_casework::{
    acknowledge_audit_restore, export_audit_journal, secret_resolver, verify_audit_journal,
    AuditHead, RuntimeConfig, RuntimeError,
};
use serde_json::{json, Value};

/// Owner-only permissions for an export the operator has not yet placed.
const EXPORT_FILE_MODE: u32 = 0o600;

/// An audit command refusal an operator can act on, reported under its own
/// code with the step that resolves it.
#[derive(Debug)]
pub(crate) struct AuditRefusal {
    pub(crate) message: String,
    pub(crate) path: &'static str,
    pub(crate) action: &'static str,
}

impl std::fmt::Display for AuditRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AuditRefusal {}

const AUDIT_CHAIN_ACTION: &str = "Restore audit.path and the segments beside it from the \
     backup taken with this runtime configuration, or verify with the audit.hashKeyRef that \
     wrote the chain, then retry.";
const AUDIT_OUTPUT_ACTION: &str = "Choose an absolute --output path in an existing directory \
     that does not exist yet, then retry.";
const AUDIT_HEAD_ACTION: &str = "Pass the headHash an earlier audit verify or export reported \
     for this journal, or restore audit.path and the segments beside it from the backup that \
     holds that head, then retry.";
const AUDIT_RUNNING_ACTION: &str = "Stop every Casework runtime that uses this database and \
     audit.path, then retry.";
const AUDIT_CHAIN_PATH: &str = "runtime.yaml:/audit/path";
const AUDIT_HEAD_PATH: &str = "audit verify --from-head";
const AUDIT_OUTPUT_PATH: &str = "audit export --output";

pub(crate) fn verify(runtime_config: &Path, from_head: Option<&str>) -> Result<Value> {
    let from_head = from_head
        .map(|head| {
            AuditHead::parse(head)
                .map(|parsed| (parsed, head))
                .ok_or_else(|| {
                    refusal(
                        "--from-head is not a 64-character lowercase hexadecimal audit record hash"
                            .to_owned(),
                        AUDIT_HEAD_PATH,
                        AUDIT_HEAD_ACTION,
                    )
                })
        })
        .transpose()?;
    let (config, runtime_config) = load(runtime_config)?;
    let resolver = secret_resolver(&config).context("configuring Casework secret providers")?;
    let verification = verify_audit_journal(
        &config.audit.path,
        &resolver,
        &config.audit.hash_key_ref,
        from_head.map(|(head, _)| head),
    )
    .map_err(chain_failure)?;
    Ok(json!({
        "ok": true,
        "command": "audit verify",
        "runtimeConfig": runtime_config,
        "fromHead": from_head.map(|(_, head)| head),
        "auditChain": verification,
    }))
}

pub(crate) fn export(runtime_config: &Path, output: &Path) -> Result<Value> {
    if !output.is_absolute() {
        return Err(refusal(
            "--output must be an absolute path".to_owned(),
            AUDIT_OUTPUT_PATH,
            AUDIT_OUTPUT_ACTION,
        ));
    }
    let (config, runtime_config) = load(runtime_config)?;
    let resolver = secret_resolver(&config).context("configuring Casework secret providers")?;
    let mut staged = StagedExport::create(output)?;
    let verification = {
        let mut sink = BufWriter::new(&mut staged.file);
        let verification = export_audit_journal(
            &config.audit.path,
            &resolver,
            &config.audit.hash_key_ref,
            &mut sink,
        )
        .map_err(chain_failure)?;
        let file = sink
            .into_inner()
            .map_err(|error| error.into_error())
            .context("writing the audit export")?;
        file.sync_all().context("writing the audit export")?;
        verification
    };
    staged.publish()?;
    Ok(json!({
        "ok": true,
        "command": "audit export",
        "runtimeConfig": runtime_config,
        "output": output,
        "auditChain": verification,
    }))
}

pub(crate) fn acknowledge_restore(runtime_config: &Path) -> Result<Value> {
    let (config, runtime_config) = load(runtime_config)?;
    let acknowledgement = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the Casework operator runtime")?
        .block_on(acknowledge_audit_restore(&config))
        .map_err(acknowledgement_failure)?;
    Ok(json!({
        "ok": true,
        "command": "audit acknowledge-restore",
        "runtimeConfig": runtime_config,
        "acknowledgement": acknowledgement,
    }))
}

fn load(runtime_config: &Path) -> Result<(RuntimeConfig, PathBuf)> {
    let config =
        RuntimeConfig::load(runtime_config).context("loading Casework runtime configuration")?;
    let runtime_config =
        fs::canonicalize(runtime_config).context("resolving Casework runtime configuration")?;
    Ok((config, runtime_config))
}

fn refusal(message: String, path: &'static str, action: &'static str) -> anyhow::Error {
    anyhow::Error::new(AuditRefusal {
        message,
        path,
        action,
    })
}

/// A chain that does not verify, or does not hold the named head, is a
/// refusal the operator acts on. An export the filesystem would not take is a
/// filesystem failure, not a finding about the journal.
fn chain_failure(error: RuntimeError) -> anyhow::Error {
    match error {
        RuntimeError::AuditExport(_) => {
            anyhow::Error::new(std::io::Error::other(error.to_string()))
                .context("writing the audit export")
        }
        RuntimeError::AuditSecret(_) => refusal(
            error.to_string(),
            "runtime.yaml:/audit/hashKeyRef",
            "Provision the owner-only secret audit.hashKeyRef names, then retry.",
        ),
        RuntimeError::AuditHeadMissing => {
            refusal(error.to_string(), AUDIT_HEAD_PATH, AUDIT_HEAD_ACTION)
        }
        error => refusal(error.to_string(), AUDIT_CHAIN_PATH, AUDIT_CHAIN_ACTION),
    }
}

/// A running Casework runtime holds the lease or the journal, which the
/// operator resolves by stopping it, and a journal that does not open under
/// the configured key is refused as verification refuses it. Every other
/// failure keeps its own error so it is classified as the configuration or
/// runtime dependency it is.
fn acknowledgement_failure(error: RuntimeError) -> anyhow::Error {
    match error {
        RuntimeError::AuditPublicationLeaseHeld | RuntimeError::AuditJournalLocked => {
            refusal(error.to_string(), AUDIT_CHAIN_PATH, AUDIT_RUNNING_ACTION)
        }
        RuntimeError::Store(error) => {
            anyhow::Error::new(error).context("acknowledging the Casework audit restore")
        }
        RuntimeError::Config(error) => {
            anyhow::Error::new(error).context("acknowledging the Casework audit restore")
        }
        RuntimeError::Audit | RuntimeError::AuditSecret(_) | RuntimeError::AuditJournal(_) => {
            chain_failure(error)
        }
        error => anyhow::Error::new(error).context("acknowledging the Casework audit restore"),
    }
}

/// An export written beside its destination and linked into place only once
/// it is complete and durable, so a reader never sees a partial export and an
/// existing file is never replaced.
///
/// The staging file belongs to this value: every outcome that is not a
/// publication removes it as the value drops.
struct StagedExport {
    destination: PathBuf,
    temporary: PathBuf,
    file: File,
    published: bool,
}

impl StagedExport {
    fn create(destination: &Path) -> Result<Self> {
        let parent = destination
            .parent()
            .filter(|parent| parent.is_dir())
            .ok_or_else(|| {
                refusal(
                    "the directory named by --output does not exist".to_owned(),
                    AUDIT_OUTPUT_PATH,
                    AUDIT_OUTPUT_ACTION,
                )
            })?;
        let Some(name) = destination.file_name().and_then(|name| name.to_str()) else {
            return Err(refusal(
                "--output does not name a file".to_owned(),
                AUDIT_OUTPUT_PATH,
                AUDIT_OUTPUT_ACTION,
            ));
        };
        if fs::symlink_metadata(destination).is_ok() {
            return Err(output_exists());
        }
        let temporary = parent.join(format!(".{name}.caseworkctl-{}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(EXPORT_FILE_MODE);
        let file = options
            .open(&temporary)
            .context("creating the audit export")?;
        let staged = Self {
            destination: destination.to_path_buf(),
            temporary,
            file,
            published: false,
        };
        // The create mode is filtered by the process umask, so restate the
        // owner-only permissions on the descriptor itself.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            staged
                .file
                .set_permissions(fs::Permissions::from_mode(EXPORT_FILE_MODE))
                .context("creating the audit export")?;
        }
        Ok(staged)
    }

    fn publish(mut self) -> Result<()> {
        // A hard link refuses an existing destination, so a file that appeared
        // after staging is never replaced.
        match fs::hard_link(&self.temporary, &self.destination) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(output_exists());
            }
            Err(error) => return Err(error).context("publishing the audit export"),
        }
        self.published = true;
        fs::remove_file(&self.temporary).context("removing the audit export staging file")?;
        if let Some(parent) = self.destination.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .context("making the audit export durable")?;
        }
        Ok(())
    }
}

impl Drop for StagedExport {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // The refusal that ended this export is already on its way to the
        // operator, and an unlink the kernel refuses leaves nothing further
        // to do about the staging name.
        let _ = fs::remove_file(&self.temporary);
    }
}

fn output_exists() -> anyhow::Error {
    refusal(
        "the file named by --output already exists; an export never replaces a file".to_owned(),
        AUDIT_OUTPUT_PATH,
        AUDIT_OUTPUT_ACTION,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn a_destination_that_appears_after_staging_is_never_replaced() {
        let directory = tempfile::tempdir().expect("export directory");
        let destination = directory.path().join("casework-audit.jsonl");
        let mut staged = StagedExport::create(&destination).expect("staging starts");
        staged.file.write_all(b"staged\n").expect("staging writes");
        fs::write(&destination, b"operator file\n").expect("destination appears");

        let refused = staged
            .publish()
            .expect_err("an existing file is never replaced");
        let refusal = refused
            .downcast_ref::<AuditRefusal>()
            .expect("the refusal names the output");
        assert_eq!(refusal.path, AUDIT_OUTPUT_PATH);
        assert_eq!(
            fs::read(&destination).expect("destination reads"),
            b"operator file\n"
        );
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("directory lists")
                .count(),
            1,
            "the staging file is removed"
        );
    }
}

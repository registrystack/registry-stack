// SPDX-License-Identifier: Apache-2.0
//! Explicit copies of retained credentials, with complete no-replace publication.
use super::*;
use crate::safe_path::{SafeEntry, SafePathError};
use std::ffi::OsString;

#[derive(Debug, Args)]
pub(super) struct ExportClientArgs {
    /// Registry project containing the retained development session.
    #[arg(value_name = "PROJECT", default_value = ".")]
    pub project: PathBuf,
    /// Explicit local client label from the retained session.
    #[arg(long)]
    pub client: String,
    /// Client ID destination in an existing owner-only directory.
    #[arg(long, value_name = "FILE")]
    pub client_id_file: PathBuf,
    /// Assertion key destination in an existing owner-only directory.
    #[arg(long, value_name = "FILE")]
    pub assertion_key_file: PathBuf,
}

pub(super) fn run(args: ExportClientArgs) -> Result<Value> {
    let project = project(&args.project)?;
    let parent = project.join(".breg");
    let root = parent.join("dev");
    if !root.exists() {
        bail!("no retained local development session exists; check the project path or first run bregctl dev");
    }
    private::check(&parent, true)?;
    let _lock = private::lock(&parent.join("dev.lock"))?;
    let state = read_state(&root)?;
    let clients: Clients =
        serde_json::from_slice(&private::read(&root.join("clients.json"), MAX_BYTES)?).map_err(
            |_| {
                anyhow::anyhow!("retained clients are invalid; preserve the session for inspection")
            },
        )?;
    let client = clients.clients.iter().find(|client| client.id == args.client)
        .context("selected client is absent from the retained session; select an existing local client label")?;
    if !config::identifier(&client.id) {
        bail!("retained client label is invalid; preserve the session for inspection");
    }
    let credentials = root.join("credentials").join(&client.id);
    private::check(&root.join("credentials"), true)?;
    private::check(&credentials, true)?;
    let id = Zeroizing::new(private::read(&credentials.join("client-id"), MAX_BYTES)
        .context("retained client ID is missing or unsafe; preserve the session and inspect its credentials")?);
    let key = Zeroizing::new(private::read(&credentials.join("assertion-key.jwk"), MAX_BYTES)
        .context("retained assertion key is missing or unsafe; preserve the session and inspect its credentials")?);
    validate_pair(&id, &key, &client.id)?;
    let id_path = output_path(&args.client_id_file)?;
    let key_path = output_path(&args.assertion_key_file)?;
    if id_path == key_path {
        bail!("credential outputs must name two distinct files");
    }
    let id_output = Output::prepare(&id_path, &id)?;
    let key_output = Output::prepare(&key_path, &key)?;
    // Both complete files are staged before either destination is published.
    let id_stage = id_output.stage(&id)?;
    let key_stage = key_output.stage(&key)?;
    id_stage.publish()?;
    key_stage.publish()?;
    Ok(
        json!({"ok":true,"command":"dev export-client","project":project,
        "client":client.id,"accessProfiles":client.access_profiles,
        "accessProfilesText":client.access_profiles.join(", "),
        "clientIdFile":id_path,"assertionKeyFile":key_path,
        "bregUrl":state.breg_origin(),
        "issuer":state.issuer_origin(),
        "tokenEndpoint":format!("{}/oauth2/token",state.issuer_origin()),
        "clientAssertionAudience":state.issuer_origin(),
        "resource":state.audience(),
        "scopes":client.scopes,
        "audience":state.audience()}),
    )
}

fn validate_pair(id: &[u8], key: &[u8], label: &str) -> Result<()> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let valid = (|| -> Option<()> {
        if id != label.as_bytes() {
            return None;
        }
        let jwk: Value = serde_json::from_slice(key).ok()?;
        if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["alg"] != "ES256" {
            return None;
        }
        let d = Zeroizing::new(URL_SAFE_NO_PAD.decode(jwk["d"].as_str()?).ok()?);
        let signing = p256::ecdsa::SigningKey::from_slice(&d).ok()?;
        let point = signing.verifying_key().to_encoded_point(false);
        if jwk["x"].as_str()? != URL_SAFE_NO_PAD.encode(point.x()?)
            || jwk["y"].as_str()? != URL_SAFE_NO_PAD.encode(point.y()?)
        {
            return None;
        }
        Some(())
    })();
    valid.context("retained credential pair is incomplete or invalid; preserve the session and inspect its credentials")
}

fn output_path(path: &Path) -> Result<PathBuf> {
    // Refuse unsafe components; preserve the path for descriptor-relative resolution.
    SafeEntry::resolve(path).map_err(SafePathError::into_io)
        .context("credential output needs a prepared directory without symbolic links or parent-directory components")?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        fs::canonicalize(std::env::current_dir()?)?.join(path)
    };
    Ok(absolute.components().collect())
}

struct Output {
    entry: SafeEntry,
    exists: bool,
}
impl Output {
    fn prepare(path: &Path, bytes: &[u8]) -> Result<Self> {
        let entry = SafeEntry::resolve(path).map_err(SafePathError::into_io)?;
        private::check_metadata(
            &entry
                .parent()
                .open_read(std::ffi::OsStr::new("."))?
                .metadata()?,
            true,
        )?;
        let exists = entry.exists()?;
        if exists {
            let mut file = entry.open_read()?;
            let metadata = file.metadata()?;
            private::check_metadata(&metadata, false)?;
            if !matches!(metadata.mode() & 0o7777, 0o400 | 0o600) {
                bail!("existing credential outputs require mode 0400 or 0600; correct their permissions or choose fresh output paths; existing files were preserved");
            }
            let mut existing = Zeroizing::new(Vec::new());
            (&mut file).take(MAX_BYTES + 1).read_to_end(&mut existing)?;
            if existing.as_slice() != bytes {
                bail!("credential output conflicts with the retained pair; choose fresh output paths and update the consuming target; existing files were preserved");
            }
        }
        Ok(Self { entry, exists })
    }
    fn stage(&self, bytes: &[u8]) -> Result<Stage<'_>> {
        let mut stage = Stage {
            output: self,
            name: None,
        };
        if !self.exists {
            let name = OsString::from(format!(".credential-{}", uuid::Uuid::new_v4()));
            let mut file = self.entry.parent().create_new(&name, 0o600)?;
            stage.name = Some(name);
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        Ok(stage)
    }
}
struct Stage<'a> {
    output: &'a Output,
    name: Option<OsString>,
}
impl Stage<'_> {
    fn publish(mut self) -> Result<()> {
        if let Some(name) = &self.name {
            self.output.entry.publish_from(name)
                .context("credential publication could not complete without replacement; preserve outputs and retry the same command")?;
            self.name = None;
            self.output.entry.parent().sync().context(
                "credential published but directory sync failed; retry the same command",
            )?;
        }
        Ok(())
    }
}
impl Drop for Stage<'_> {
    fn drop(&mut self) {
        if let Some(name) = &self.name {
            let _ = self.output.entry.parent().remove_file(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_never_exposes_partial_files_and_publication_never_replaces() {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("credential");
        let output = Output::prepare(&path, b"complete").unwrap();
        let stage = output.stage(b"complete").unwrap();
        assert!(!path.exists());
        drop(stage);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        let stage = output.stage(b"complete").unwrap();
        private::create(&path, b"other-writer").unwrap();
        assert!(stage.publish().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"other-writer");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    }

    #[test]
    fn relative_outputs_resolve_without_a_current_directory_change() {
        let cwd = std::env::current_dir().unwrap();
        let relative = Path::new("./credential-output-test");
        assert_eq!(
            output_path(relative).unwrap(),
            fs::canonicalize(cwd)
                .unwrap()
                .join("credential-output-test")
        );
    }
}

//! Deployment-project scaffolding. Emits a neutral, tutorial-shaped project
//! that passes `evidence check` and `evidence evaluate` after one keygen pass.

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context as _};
use clap::Args;

/// Governed identifiers the scaffold stamps into the bundle. They are all in
/// the reserved example namespace so a generated project can never be mistaken
/// for a governed deployment, and every one of them is meant to be replaced.
const TRUST_DOMAIN: &str = "urn:example:scaffold:trust-domain";
const REQUIREMENT_ID: &str = "urn:example:scaffold:requirement:example-flag:v1";
const FRAMEWORK_ID: &str = "urn:example:scaffold:framework:example-flag:v1";
const EVIDENCE_TYPE_ID: &str = "urn:example:scaffold:evidence-type:example-flag:v1";
const CONCEPT_ID: &str = "urn:example:scaffold:concept:example-flag";
const DISCLOSURE_FAMILY_ID: &str = "urn:example:scaffold:disclosure-family:example-flag";

/// The requester tag the bundle's authority profile admits, and the one a
/// paired Mint registration mints for its caller.
const REQUESTER_TAG: &str = "scaffold-agency";

/// The signing key identifier the bundle declares. `keygen signing --kid`
/// takes the same value, so the scaffolded project needs no edit to sign.
const SIGNING_KEY_ID: &str = "scaffold-signing-key-1";

/// The access-token contract, written into the bundle's `authentication` block
/// and, when a Mint configuration is rendered beside it, into that document
/// too. One source for both sides is what stops the pairing drifting.
const TOKEN_AUDIENCE: &str = "evidence-scaffold";
const TOKEN_ALGORITHM: &str = "EdDSA";
const TOKEN_JWKS_PATH: &str = "/.well-known/jwks.json";
const PRINCIPAL_CLAIM: &str = "sub";
const REQUESTER_TAGS_CLAIM: &str = "evidence_tags";
const EVIDENCE_AUDIENCE_CLAIM: &str = "evidence_audience";
const GRANT_ID_CLAIM: &str = "evidence_grant_id";
const GRANT_AUTHORITY_CLAIM: &str = "evidence_authority";

/// The token issuer the bundle trusts. A standalone project names a placeholder
/// identity provider; a paired one names the Mint deployment beside it.
const IDENTITY_ISSUER: &str = "https://identity.invalid";
const MINT_ISSUER: &str = "https://mint.invalid";

/// Identifiers a paired Mint deployment is scaffolded with. Like every other
/// identifier here they are meant to be replaced.
const MINT_SIGNING_KEY_ID: &str = "scaffold-mint-key-1";
const MINT_CLIENT_ID: &str = "scaffold-client";
const MINT_CLIENT_KEY_ID: &str = "scaffold-client-key-1";
const MINT_CLIENT_PRINCIPAL: &str = "urn:example:scaffold:client";
const MINT_CLIENT_AUDIENCE: &str = "https://requester.invalid";

/// The comment above the bundle's `authentication` block. It is the one part of
/// that block whose wording depends on where the tokens come from.
const AUTHENTICATION_NOTE: &str = "\
# Requesters present an OIDC access token. Replace the issuer, the JWKS URI and
# the audience with the identity provider that serves this deployment.";
const MINT_AUTHENTICATION_NOTE: &str = "\
# Requesters present an OIDC access token minted by the Registry Mint
# deployment in mint/. Every value below is mirrored in mint/mint.yaml, and a
# single-sided edit produces tokens Mint issues and this deployment refuses.";

/// Project-relative locations the scaffold owns.
const BUNDLE_DIRECTORY: &str = "bundle";
const SECRET_DIRECTORY: &str = "secrets";
const AUDIT_DIRECTORY: &str = "audit";
const AUDIT_FILE: &str = "audit/evidence.jsonl";
const RUNTIME_FILE: &str = "runtime.yaml";
const MINT_DIRECTORY: &str = "mint";
const MINT_CONFIG_FILE: &str = "mint/mint.yaml";
const MINT_CLIENT_DIRECTORY: &str = "mint/clients";
const MINT_SECRET_DIRECTORY: &str = "mint/secrets";
/// The example caller's key is not Mint's own, so it sits beside rather than in
/// the secret root Mint reads. Both are under a `secrets` path component, which
/// is what the generated `.gitignore` excludes.
const MINT_CALLER_SECRET_DIRECTORY: &str = "mint/secrets/caller";

/// One rendered file: where it lands in the project, and its template bytes.
struct ProjectFile {
    relative: &'static str,
    template: &'static str,
}

const PROJECT_FILES: [ProjectFile; 10] = [
    ProjectFile {
        relative: "README.md",
        template: include_str!("../templates/README.md"),
    },
    ProjectFile {
        relative: ".gitignore",
        template: include_str!("../templates/gitignore"),
    },
    ProjectFile {
        relative: RUNTIME_FILE,
        template: include_str!("../templates/runtime.yaml"),
    },
    ProjectFile {
        relative: "bundle/evidence.yaml",
        template: include_str!("../templates/bundle/evidence.yaml"),
    },
    ProjectFile {
        relative: "bundle/adapters/source-a-prepare.rhai",
        template: include_str!("../templates/bundle/adapters/source-a-prepare.rhai"),
    },
    ProjectFile {
        relative: "bundle/adapters/source-a-extract.rhai",
        template: include_str!("../templates/bundle/adapters/source-a-extract.rhai"),
    },
    ProjectFile {
        relative: "bundle/derivations/example-flag.rhai",
        template: include_str!("../templates/bundle/derivations/example-flag.rhai"),
    },
    ProjectFile {
        relative: "bundle/schemas/adapter-parameters.schema.yaml",
        template: include_str!("../templates/bundle/schemas/adapter-parameters.schema.yaml"),
    },
    ProjectFile {
        relative: "bundle/schemas/facts.schema.yaml",
        template: include_str!("../templates/bundle/schemas/facts.schema.yaml"),
    },
    ProjectFile {
        relative: "bundle/fixtures/cases.yaml",
        template: include_str!("../templates/bundle/fixtures/cases.yaml"),
    },
];

/// The paired Registry Mint deployment, rendered only for `--with-mint`.
///
/// The registration is written under a name Mint's registry loader ignores. It
/// needs the caller's public key before it can serve, and the scaffold has no
/// key to put there: it never generates key material.
const MINT_FILES: [ProjectFile; 2] = [
    ProjectFile {
        relative: MINT_CONFIG_FILE,
        template: include_str!("../templates/mint/mint.yaml"),
    },
    ProjectFile {
        relative: "mint/clients/scaffold-client.yaml.example",
        template: include_str!("../templates/mint/client.yaml.example"),
    },
];

/// Appended to the rendered README when a Mint configuration is rendered.
const MINT_README_SECTION: &str = include_str!("../templates/mint/README-section.md");

#[derive(Debug, Args)]
pub struct NewArgs {
    /// Directory to create the deployment project in.
    pub directory: PathBuf,

    /// Evidence provider identifier stamped into the bundle.
    #[arg(long, default_value = "urn:example:scaffold:provider")]
    pub provider_id: String,

    /// Issuing authority identifier stamped into the bundle.
    #[arg(long, default_value = "urn:example:scaffold:issuer")]
    pub issuer_id: String,

    /// Also render a paired Registry Mint configuration for the project.
    #[arg(long)]
    pub with_mint: bool,

    /// Scaffold into a non-empty directory.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: NewArgs) -> anyhow::Result<ExitCode> {
    if directory_has_entries(&args.directory)? && !args.force {
        bail!(
            "refusing to scaffold into the non-empty directory {}; pass --force to proceed",
            args.directory.display()
        );
    }

    fs::create_dir_all(&args.directory).with_context(|| {
        format!(
            "creating the project directory {}",
            args.directory.display()
        )
    })?;
    // Absolute paths belong in runtime.yaml, so the generated project runs from
    // any working directory. Canonicalizing after creation resolves symlinked
    // parents such as a temporary directory on macOS.
    let root = fs::canonicalize(&args.directory).with_context(|| {
        format!(
            "resolving the project directory {}",
            args.directory.display()
        )
    })?;
    // A rewrite has to clear the immutability the documented freeze applies,
    // otherwise the read-only bundle from an earlier run rejects every write.
    restore_writable(&root)?;

    // A rewrite that drops --with-mint must not leave the earlier run's mint/
    // tree behind: it would keep documenting and registering a token issuer
    // the freshly rendered bundle no longer pairs with.
    if !args.with_mint && root.join(MINT_CONFIG_FILE).is_file() {
        bail!(
            "{} already has a mint/ tree rendered by an earlier `--with-mint` scaffold; \
             pass --with-mint to re-render it in sync, or delete mint/ first",
            root.display()
        );
    }

    let placeholders = placeholders(&root, &args)?;
    for file in &PROJECT_FILES {
        let path = root.join(file.relative);
        let mut rendered = render(file.template, &placeholders)
            .with_context(|| format!("rendering {}", file.relative))?;
        // The Mint steps are the tail of the README rather than a second file,
        // so an adopter reads one document either way.
        if args.with_mint && file.relative == "README.md" {
            rendered.push_str(
                &render(MINT_README_SECTION, &placeholders)
                    .context("rendering the Mint README section")?,
            );
        }
        write_project_file(&path, &rendered)?;
    }

    let secret_root = root.join(SECRET_DIRECTORY);
    create_secret_directory(&secret_root)?;
    let audit_root = root.join(AUDIT_DIRECTORY);
    fs::create_dir_all(&audit_root)
        .with_context(|| format!("creating {}", audit_root.display()))?;

    if args.with_mint {
        for file in &MINT_FILES {
            let path = root.join(file.relative);
            let rendered = render(file.template, &placeholders)
                .with_context(|| format!("rendering {}", file.relative))?;
            write_project_file(&path, &rendered)?;
        }
        create_secret_directory(&root.join(MINT_SECRET_DIRECTORY))?;
    }

    report(&root, &secret_root, args.with_mint);
    Ok(ExitCode::SUCCESS)
}

/// The substitutions every template shares. Values are computed once so the
/// bundle, the runtime file, the README and any paired Mint configuration
/// cannot drift from each other.
fn placeholders(root: &Path, args: &NewArgs) -> anyhow::Result<Vec<(&'static str, String)>> {
    let token_issuer = if args.with_mint {
        MINT_ISSUER
    } else {
        IDENTITY_ISSUER
    };
    let authentication_note = if args.with_mint {
        MINT_AUTHENTICATION_NOTE
    } else {
        AUTHENTICATION_NOTE
    };
    Ok(vec![
        ("project_root", path_string(root)?),
        (
            "bundle_directory",
            path_string(&root.join(BUNDLE_DIRECTORY))?,
        ),
        ("secret_root", path_string(&root.join(SECRET_DIRECTORY))?),
        ("audit_path", path_string(&root.join(AUDIT_FILE))?),
        ("provider_id", args.provider_id.clone()),
        ("issuer_id", args.issuer_id.clone()),
        ("trust_domain", TRUST_DOMAIN.to_owned()),
        ("requirement_id", REQUIREMENT_ID.to_owned()),
        ("framework_id", FRAMEWORK_ID.to_owned()),
        ("evidence_type_id", EVIDENCE_TYPE_ID.to_owned()),
        ("concept_id", CONCEPT_ID.to_owned()),
        ("disclosure_family_id", DISCLOSURE_FAMILY_ID.to_owned()),
        ("signing_key_id", SIGNING_KEY_ID.to_owned()),
        ("requester_tag", REQUESTER_TAG.to_owned()),
        ("authentication_note", authentication_note.to_owned()),
        ("token_issuer", token_issuer.to_owned()),
        ("token_audience", TOKEN_AUDIENCE.to_owned()),
        ("token_algorithm", TOKEN_ALGORITHM.to_owned()),
        ("token_jwks_path", TOKEN_JWKS_PATH.to_owned()),
        ("token_jwks_uri", format!("{token_issuer}{TOKEN_JWKS_PATH}")),
        ("principal_claim", PRINCIPAL_CLAIM.to_owned()),
        ("requester_tags_claim", REQUESTER_TAGS_CLAIM.to_owned()),
        (
            "evidence_audience_claim",
            EVIDENCE_AUDIENCE_CLAIM.to_owned(),
        ),
        ("grant_id_claim", GRANT_ID_CLAIM.to_owned()),
        ("grant_authority_claim", GRANT_AUTHORITY_CLAIM.to_owned()),
        (
            "mint_config_path",
            path_string(&root.join(MINT_CONFIG_FILE))?,
        ),
        (
            "mint_clients_directory",
            path_string(&root.join(MINT_CLIENT_DIRECTORY))?,
        ),
        (
            "mint_secret_root",
            path_string(&root.join(MINT_SECRET_DIRECTORY))?,
        ),
        (
            "mint_caller_secret_root",
            path_string(&root.join(MINT_CALLER_SECRET_DIRECTORY))?,
        ),
        ("mint_signing_key_id", MINT_SIGNING_KEY_ID.to_owned()),
        ("mint_client_id", MINT_CLIENT_ID.to_owned()),
        ("mint_client_key_id", MINT_CLIENT_KEY_ID.to_owned()),
        ("mint_client_principal", MINT_CLIENT_PRINCIPAL.to_owned()),
        ("mint_client_audience", MINT_CLIENT_AUDIENCE.to_owned()),
        ("mint_token_endpoint", format!("{token_issuer}/token")),
    ])
}

/// Substitute every `{{name}}` marker, then refuse output that still holds one.
/// A silently unrendered marker would produce a project that fails much later,
/// in `evidence check`, with a far less obvious cause.
fn render(template: &str, placeholders: &[(&'static str, String)]) -> anyhow::Result<String> {
    let mut rendered = template.to_owned();
    for (name, value) in placeholders {
        rendered = rendered.replace(&format!("{{{{{name}}}}}"), value);
    }
    if rendered.contains("{{") {
        bail!("the template contains a placeholder the scaffold does not define");
    }
    Ok(rendered)
}

fn path_string(path: &Path) -> anyhow::Result<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .with_context(|| format!("the path {} is not valid UTF-8", path.display()))
}

fn directory_has_entries(path: &Path) -> anyhow::Result<bool> {
    match fs::read_dir(path) {
        Ok(mut entries) => Ok(entries.next().transpose()?.is_some()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("reading the directory {}", path.display()))
        }
    }
}

fn write_project_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating the directory {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

/// Create the secret root the runtime file names, owner-only and empty. Keys
/// are generated by `evidencectl keygen`, never here.
fn create_secret_directory(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restricting {} to its owner", path.display()))?;
    Ok(())
}

/// Give the owner write permission back across an existing project tree.
fn restore_writable(root: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("reading the permissions of {}", root.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    let mode = metadata.permissions().mode();
    if mode & 0o200 == 0 {
        fs::set_permissions(root, fs::Permissions::from_mode(mode | 0o200))
            .with_context(|| format!("restoring write permission on {}", root.display()))?;
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    for entry in
        fs::read_dir(root).with_context(|| format!("reading the directory {}", root.display()))?
    {
        let entry = entry.with_context(|| format!("reading the directory {}", root.display()))?;
        restore_writable(&entry.path())?;
    }
    Ok(())
}

/// Report paths only. No key material exists yet, and none is ever printed.
fn report(root: &Path, secret_root: &Path, with_mint: bool) {
    println!(
        "Scaffolded an Evidence deployment project in {}",
        root.display()
    );
    println!("  bundle:   {}", root.join(BUNDLE_DIRECTORY).display());
    println!("  runtime:  {}", root.join(RUNTIME_FILE).display());
    println!("  secrets:  {} (empty, owner-only)", secret_root.display());
    println!("  audit:    {}", root.join(AUDIT_DIRECTORY).display());
    if with_mint {
        println!(
            "  mint:     {} (paired token issuer)",
            root.join(MINT_DIRECTORY).display()
        );
    }
    println!();
    println!("Next steps:");
    println!(
        "  evidencectl keygen signing --out-dir {} --kid {SIGNING_KEY_ID}",
        secret_root.display()
    );
    println!(
        "  evidencectl keygen secret --out {}",
        secret_root.join("audit-hmac-key").display()
    );
    println!(
        "  evidencectl keygen secret --out {}",
        secret_root.join("subject-binding-hmac-key").display()
    );
    println!(
        "  # obtain the source system's own bearer token and write it to {},",
        secret_root.join("source-bearer-token").display()
    );
    println!("  # mode 0600. check, the fixtures and startup all pass without it; the");
    println!("  # first live request is where a missing token is discovered.");
    println!(
        "  chmod -R a-w {} && chmod 444 {}",
        root.join(BUNDLE_DIRECTORY).display(),
        root.join(RUNTIME_FILE).display()
    );
    println!(
        "  evidence check --runtime {}",
        root.join(RUNTIME_FILE).display()
    );
    println!(
        "  evidence evaluate --runtime {} --fixture fixtures/cases.yaml",
        root.join(RUNTIME_FILE).display()
    );
    if with_mint {
        println!();
        println!("Next steps for the paired Registry Mint deployment:");
        println!(
            "  evidencectl keygen signing --out-dir {} --kid {MINT_SIGNING_KEY_ID}",
            root.join(MINT_SECRET_DIRECTORY).display()
        );
        println!(
            "  evidencectl keygen signing --out-dir {} --kid {MINT_CLIENT_KEY_ID}",
            root.join(MINT_CALLER_SECRET_DIRECTORY).display()
        );
        println!(
            "  # copy the caller public key into {}/{MINT_CLIENT_ID}.yaml.example,",
            root.join(MINT_CLIENT_DIRECTORY).display()
        );
        println!("  # then rename that file to {MINT_CLIENT_ID}.yaml to register the caller");
        println!(
            "  mint check --config {}",
            root.join(MINT_CONFIG_FILE).display()
        );
    }
    println!();
    println!("{} explains the rest.", root.join("README.md").display());
}

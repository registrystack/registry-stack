//! Acceptance gate for `evidencectl new`.
//!
//! A scaffolded project must satisfy the real `evidence` binary with no edits:
//! add key material, apply the documented freeze, and both `check` and every
//! scaffolded fixture must pass. Nothing in this file prints key material.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use tempfile::TempDir;

const SECRET_FILES: [&str; 2] = ["audit-hmac-key", "subject-binding-hmac-key"];

/// Project-relative paths the paired Registry Mint configuration occupies.
const MINT_CONFIG: &str = "mint/mint.yaml";
const MINT_CLIENT_REGISTRATION: &str = "mint/clients/scaffold-client.yaml.example";
const MINT_SECRETS: &str = "mint/secrets";

#[test]
fn a_scaffolded_project_passes_check_and_every_fixture() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    scaffold(&[project.to_str().expect("project path")]);

    passes_check_and_every_fixture(&project);
}

/// The paired variant changes the authentication block, which `check` loads and
/// validates, so it earns the same gate rather than only a file listing.
#[test]
fn a_mint_paired_project_passes_check_and_every_fixture() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    scaffold(&[project.to_str().expect("project path"), "--with-mint"]);

    passes_check_and_every_fixture(&project);
}

/// The scaffolded source authenticates with a bearer token the source system
/// issues and nothing here generates. `check` and every fixture pass without
/// it, and the service starts without it, so a reader who follows only the
/// printed steps first discovers it missing at the first live request. The
/// printed steps must name it, as the generated README already does.
#[test]
fn the_printed_next_steps_name_the_source_bearer_token() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    let outcome = evidencectl(&["new", project.to_str().expect("project path")]);
    assert!(
        outcome.status.success(),
        "evidencectl new failed: {}",
        String::from_utf8_lossy(&outcome.stderr)
    );

    let printed = String::from_utf8_lossy(&outcome.stdout);
    assert!(
        printed.contains("source-bearer-token"),
        "the printed next steps never mention the source bearer token:\n{printed}"
    );
}

/// Anyone standing the project up against a stand-in source has to invent that
/// token, and the neighbouring `keygen secret` lines make it the obvious tool.
/// It is the wrong one: it writes raw bytes, and a bearer token ends up in an
/// HTTP header. The step that names the token must name the generator that
/// suits it.
#[test]
fn the_printed_next_steps_offer_a_generator_for_a_stand_in_sources_token() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    let outcome = evidencectl(&["new", project.to_str().expect("project path")]);
    assert!(
        outcome.status.success(),
        "evidencectl new failed: {}",
        String::from_utf8_lossy(&outcome.stderr)
    );

    let printed = String::from_utf8_lossy(&outcome.stdout);
    let token_step = printed
        .lines()
        .find(|line| line.contains("keygen token"))
        .unwrap_or_else(|| panic!("no printed step generates a bearer token:\n{printed}"));
    assert!(
        token_step.contains("source-bearer-token"),
        "the token generator step does not write the token the bundle reads: {token_step}"
    );
}

fn passes_check_and_every_fixture(project: &Path) {
    provision_secrets(project);
    let fixtures = scaffolded_fixtures(project);
    assert!(
        !fixtures.is_empty(),
        "the scaffold must generate at least one fixture"
    );

    let runtime = project.join("runtime.yaml");
    freeze(project);
    let check = evidence(&[
        "check",
        "--runtime",
        runtime.to_str().expect("runtime path"),
    ]);
    let evaluations = fixtures
        .iter()
        .map(|fixture| {
            (
                fixture.clone(),
                evidence(&[
                    "evaluate",
                    "--runtime",
                    runtime.to_str().expect("runtime path"),
                    "--fixture",
                    fixture,
                ]),
            )
        })
        .collect::<Vec<_>>();
    unfreeze(project);

    assert!(
        check.status.success(),
        "evidence check failed: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    assert!(
        String::from_utf8_lossy(&check.stdout).contains("passed check"),
        "unexpected evidence check output"
    );
    for (fixture, outcome) in evaluations {
        assert!(
            outcome.status.success(),
            "evidence evaluate failed for {fixture}: {}",
            String::from_utf8_lossy(&outcome.stderr)
        );
        assert!(
            String::from_utf8_lossy(&outcome.stdout).contains("Evidence fixture passed ("),
            "unexpected evidence evaluate output for {fixture}"
        );
    }
}

#[test]
fn a_non_empty_directory_is_refused_without_force() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    fs::create_dir_all(&project).expect("project directory");
    fs::write(project.join("occupied.txt"), "existing\n").expect("existing file");

    let refusal = evidencectl(&["new", project.to_str().expect("project path")]);
    assert!(
        !refusal.status.success(),
        "scaffolding a non-empty directory must fail without --force"
    );
    assert!(
        String::from_utf8_lossy(&refusal.stderr).contains("--force"),
        "the refusal must name the flag that overrides it"
    );
    assert!(
        !project.join("runtime.yaml").exists(),
        "a refused scaffold must not write into the directory"
    );

    scaffold(&[project.to_str().expect("project path"), "--force"]);
    assert!(project.join("runtime.yaml").is_file());
    assert!(project.join("bundle/evidence.yaml").is_file());
    assert!(
        project.join("occupied.txt").is_file(),
        "--force must not delete unrelated files"
    );
}

#[test]
fn a_frozen_project_can_be_scaffolded_again_with_force() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    scaffold(&[project.to_str().expect("project path")]);
    freeze(&project);

    let rewrite = evidencectl(&[
        "new",
        project.to_str().expect("project path"),
        "--force",
        "--provider-id",
        "urn:example:scaffold:provider:second",
    ]);
    let outcome = rewrite.status.success();
    unfreeze(&project);
    assert!(
        outcome,
        "rewriting a frozen project failed: {}",
        String::from_utf8_lossy(&rewrite.stderr)
    );
    let bundle = fs::read_to_string(project.join("bundle/evidence.yaml")).expect("bundle");
    assert!(bundle.contains("urn:example:scaffold:provider:second"));
}

#[test]
fn re_scaffolding_without_with_mint_over_a_stale_mint_tree_fails() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    scaffold(&[project.to_str().expect("project path"), "--with-mint"]);
    assert!(project.join(MINT_CONFIG).is_file());

    let rewrite = evidencectl(&["new", project.to_str().expect("project path"), "--force"]);
    assert!(
        !rewrite.status.success(),
        "re-scaffolding without --with-mint over a stale mint/ tree must fail"
    );
    let stderr = String::from_utf8_lossy(&rewrite.stderr);
    assert!(
        stderr.contains("mint/"),
        "the refusal must name the mint/ directory: {stderr}"
    );
    assert!(
        project.join(MINT_CONFIG).is_file(),
        "a refused rewrite must not disturb the existing mint/ tree"
    );

    scaffold(&[
        project.to_str().expect("project path"),
        "--force",
        "--with-mint",
    ]);
    assert!(project.join(MINT_CONFIG).is_file());
}

#[test]
fn generated_state_is_excluded_from_version_control() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    scaffold(&[project.to_str().expect("project path")]);

    let ignored = fs::read_to_string(project.join(".gitignore")).expect("gitignore");
    for entry in ["secrets/", "audit/", "out/"] {
        assert!(
            ignored.lines().any(|line| line.trim() == entry),
            "the generated .gitignore must exclude {entry}"
        );
    }
}

#[test]
fn the_secret_directory_is_owner_only_and_empty() {
    use std::os::unix::fs::PermissionsExt as _;

    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    scaffold(&[project.to_str().expect("project path")]);

    let secrets = project.join("secrets");
    let metadata = fs::metadata(&secrets).expect("secret directory");
    assert!(metadata.is_dir());
    assert_eq!(
        metadata.permissions().mode() & 0o777,
        0o700,
        "the secret directory must be owner-only"
    );
    assert_eq!(
        fs::read_dir(&secrets).expect("secret directory").count(),
        0,
        "the scaffold must not generate key material"
    );
    assert!(project.join("audit").is_dir());
}

#[test]
fn the_mint_configuration_is_rendered_only_when_it_is_asked_for() {
    use std::os::unix::fs::PermissionsExt as _;

    let workspace = TempDir::new().expect("temporary directory");
    let standalone = workspace.path().join("standalone");
    scaffold(&[standalone.to_str().expect("project path")]);
    assert!(
        !standalone.join("mint").exists(),
        "the default scaffold must not render a Mint configuration"
    );
    assert!(
        !fs::read_to_string(standalone.join("README.md"))
            .expect("readme")
            .contains("Registry Mint"),
        "the default README must not document a Mint pairing"
    );

    let paired = workspace.path().join("paired");
    scaffold(&[paired.to_str().expect("project path"), "--with-mint"]);
    assert!(paired.join(MINT_CONFIG).is_file());
    assert!(paired.join(MINT_CLIENT_REGISTRATION).is_file());

    // The registration is inert until an operator supplies a key and renames
    // it: Mint loads `*.yaml` only.
    assert_eq!(
        fs::read_dir(paired.join("mint/clients"))
            .expect("client registry directory")
            .filter_map(|entry| entry.expect("client entry").file_name().into_string().ok())
            .filter(|name| name.ends_with(".yaml"))
            .count(),
        0,
        "the scaffold must not register a client it has no key for"
    );

    let secrets = paired.join(MINT_SECRETS);
    let metadata = fs::metadata(&secrets).expect("mint secret directory");
    assert!(metadata.is_dir());
    assert_eq!(
        metadata.permissions().mode() & 0o777,
        0o700,
        "the Mint secret directory must be owner-only"
    );
    assert_eq!(
        fs::read_dir(&secrets)
            .expect("mint secret directory")
            .count(),
        0,
        "the scaffold must not generate Mint key material"
    );

    let readme = fs::read_to_string(paired.join("README.md")).expect("readme");
    for expected in ["Registry Mint", "mint check", "evidencectl keygen signing"] {
        assert!(
            readme.contains(expected),
            "the paired README must document {expected}"
        );
    }
    assert!(
        !readme.contains("\"d\":") && !readme.contains("PRIVATE"),
        "the README must never carry key material"
    );
}

/// A scaffold is what adopters copy structure from, so where it puts a key is
/// a claim about who owns it. The caller is not Mint, and `mint/` is the unit
/// an operator promotes to the Mint host.
#[test]
fn the_example_callers_key_lives_outside_the_mint_deployment() {
    use std::os::unix::fs::PermissionsExt as _;

    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    scaffold(&[project.to_str().expect("project path"), "--with-mint"]);

    let caller = project.join("caller");
    let metadata = fs::metadata(&caller).expect("the caller key directory exists");
    assert!(metadata.is_dir());
    assert_eq!(
        metadata.permissions().mode() & 0o777,
        0o700,
        "the caller key directory must be owner-only"
    );
    assert_eq!(
        fs::read_dir(&caller).expect("caller key directory").count(),
        0,
        "the scaffold must not generate the caller's key material"
    );

    // Nothing the operator is told to put under mint/ is the caller's private
    // half. `mint/secrets/` is Mint's own signing key and nothing else.
    let readme = fs::read_to_string(project.join("README.md")).expect("readme");
    // The rendered paths are the canonical ones the scaffold wrote, which on
    // this platform resolves the temporary directory's symlinked parent.
    let rendered_caller = fs::canonicalize(&caller).expect("canonical caller path");
    assert!(
        readme.contains(&format!(
            "keygen signing --out-dir {}",
            rendered_caller.to_str().expect("caller path")
        )),
        "the README must generate the caller's key outside mint/"
    );
    assert!(
        !readme.contains("mint/secrets/caller"),
        "no step may put the caller's key inside the Mint deployment"
    );

    // The generated ignore rules have to cover the new location, or the first
    // commit of a scaffolded project carries a private key.
    assert!(
        fs::read_to_string(project.join(".gitignore"))
            .expect("gitignore")
            .lines()
            .any(|line| line.trim() == "caller/"),
        "the caller key directory must be excluded from version control"
    );
}

/// The two documents are rendered from one set of values, and this is what says
/// so: every value the pairing depends on has to agree on both sides.
#[test]
fn the_mint_pairing_values_mirror_the_evidence_bundle() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    scaffold(&[project.to_str().expect("project path"), "--with-mint"]);

    let bundle = yaml(&project.join("bundle/evidence.yaml"));
    let mint = yaml(&project.join(MINT_CONFIG));
    let authentication = &bundle["authentication"];
    let access_tokens = &mint["accessTokens"];

    assert_eq!(
        authentication["issuer"], mint["issuer"],
        "Evidence must trust the issuer Mint stamps into its tokens"
    );
    assert_eq!(
        authentication["audiences"], access_tokens["audiences"],
        "Evidence must accept the audience Mint mints for"
    );
    assert_eq!(
        authentication["jwksUri"]
            .as_str()
            .expect("the bundle names a JWKS URI"),
        format!(
            "{}{}",
            mint["issuer"].as_str().expect("Mint names an issuer"),
            mint["signing"]["jwksPath"]
                .as_str()
                .expect("Mint names a JWKS path")
        ),
        "Evidence must fetch the key set Mint publishes"
    );
    assert!(
        authentication["algorithms"]
            .as_sequence()
            .expect("the bundle names token algorithms")
            .contains(&mint["signing"]["algorithm"]),
        "Evidence must accept the algorithm Mint signs with"
    );

    for (evidence_field, mint_field) in [
        ("principalClaim", "principal"),
        ("requesterTagsClaim", "requesterTags"),
        ("evidenceAudienceClaim", "evidenceAudience"),
        ("grantIdClaim", "grantId"),
        ("grantAuthorityClaim", "grantAuthority"),
    ] {
        assert_eq!(
            authentication[evidence_field], access_tokens["claims"][mint_field],
            "{evidence_field} and claims.{mint_field} name the same claim"
        );
    }

    // The registration side of the pairing: a caller whose tags match no
    // authority profile authenticates and is then refused everything.
    let profiles = bundle["authorityProfiles"]
        .as_mapping()
        .expect("the bundle declares authority profiles");
    assert_eq!(profiles.len(), 1, "the scaffold declares one profile");
    let profile = profiles.values().next().expect("the authority profile");
    let client = yaml(&project.join(MINT_CLIENT_REGISTRATION));
    assert_eq!(
        client["requesterTags"], profile["requesterTags"],
        "the registered caller must carry the profile's requester tags"
    );

    let endpoint = mint["clientAssertion"]["audience"]
        .as_str()
        .expect("Mint names an assertion audience");
    assert!(
        endpoint.starts_with(mint["issuer"].as_str().expect("Mint names an issuer")),
        "the token endpoint must live under the issuer"
    );
}

/// The real `mint` binary loads what the scaffold wrote, over a registry with
/// one registered caller. Anything the two documents disagree about that
/// `mint check` can see fails here.
#[test]
fn the_rendered_mint_configuration_passes_mint_check() {
    let workspace = TempDir::new().expect("temporary directory");
    let project = workspace.path().join("project");
    scaffold(&[project.to_str().expect("project path"), "--with-mint"]);
    provision_mint_secrets(&project);

    let outcome = mint(&[
        "check",
        "--config",
        project.join(MINT_CONFIG).to_str().expect("config path"),
    ]);
    let logged = format!(
        "{}{}",
        String::from_utf8_lossy(&outcome.stdout),
        String::from_utf8_lossy(&outcome.stderr)
    );
    assert!(outcome.status.success(), "mint check failed: {logged}");
    assert!(
        logged.contains("configuration is valid"),
        "unexpected mint check output: {logged}"
    );
    assert!(
        logged.contains("\"clients\":1"),
        "mint check must have loaded the registered caller: {logged}"
    );
}

/// The runtime file is frozen at mode 444 before the project is ever served,
/// so a port chosen after the fact costs an unfreeze. The flag exists so the
/// second project on a host never has to enter that state.
#[test]
fn the_listener_port_is_chosen_when_the_project_is_generated() {
    let workspace = TempDir::new().expect("temporary directory");

    let defaulted = workspace.path().join("defaulted");
    scaffold(&[defaulted.to_str().expect("project path")]);
    assert_eq!(
        yaml(&defaulted.join("runtime.yaml"))["listener"]["port"],
        serde_norway::Value::from(8080),
        "an unspecified port keeps the documented default"
    );

    let chosen = workspace.path().join("chosen");
    scaffold(&[chosen.to_str().expect("project path"), "--port", "9443"]);
    assert_eq!(
        yaml(&chosen.join("runtime.yaml"))["listener"]["port"],
        serde_norway::Value::from(9443)
    );

    // A paired project runs both processes at once, so the one collision the
    // scaffold can see is the one it refuses rather than renders.
    let paired = workspace.path().join("paired");
    let refused = evidencectl(&[
        "new",
        paired.to_str().expect("project path"),
        "--with-mint",
        "--port",
        "8081",
    ]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("the paired Mint deployment binds"),
        "the refusal must name why 8081 is taken: {}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let paired = workspace.path().join("paired-ok");
    scaffold(&[
        paired.to_str().expect("project path"),
        "--with-mint",
        "--port",
        "9443",
    ]);
    assert_eq!(
        yaml(&paired.join("runtime.yaml"))["listener"]["port"],
        serde_norway::Value::from(9443)
    );
    assert_eq!(
        yaml(&paired.join(MINT_CONFIG))["listener"]["port"],
        serde_norway::Value::from(8081),
        "Mint keeps its own port"
    );
}

/// Run `evidencectl new` and require success.
fn scaffold(arguments: &[&str]) {
    let mut invocation = vec!["new"];
    invocation.extend_from_slice(arguments);
    let outcome = evidencectl(&invocation);
    assert!(
        outcome.status.success(),
        "evidencectl new failed: {}",
        String::from_utf8_lossy(&outcome.stderr)
    );
}

fn evidencectl(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .output()
        .expect("running evidencectl")
}

fn evidence(arguments: &[&str]) -> std::process::Output {
    Command::new(evidence_binary())
        .args(arguments)
        .output()
        .expect("running evidence")
}

fn mint(arguments: &[&str]) -> std::process::Output {
    Command::new(mint_binary())
        .args(arguments)
        .output()
        .expect("running mint")
}

/// Locate the `evidence` binary this acceptance gate drives.
fn evidence_binary() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| workspace_binary("EVIDENCE_BIN", "registry-evidence", "evidence"))
}

/// Locate the `mint` binary the paired configuration is checked against.
fn mint_binary() -> &'static Path {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY.get_or_init(|| workspace_binary("MINT_BIN", "registry-mint", "mint"))
}

/// Resolve a workspace binary. The environment variable wins when the caller
/// already built one. Otherwise the binary is built once from this workspace
/// and reused by every test in this file.
fn workspace_binary(variable: &str, package: &str, name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os(variable) {
        return PathBuf::from(path);
    }
    let build = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .current_dir(workspace_root())
        .args([
            "build",
            "--locked",
            "-p",
            package,
            "--bin",
            name,
            "--profile",
            &current_test_profile(),
            "--message-format",
            "json-render-diagnostics",
        ])
        .output()
        .unwrap_or_else(|error| panic!("building the {name} binary: {error}"));
    assert!(
        build.status.success(),
        "building the {name} binary failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    String::from_utf8_lossy(&build.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|message| {
            message.get("reason").and_then(serde_json::Value::as_str) == Some("compiler-artifact")
        })
        .filter_map(|message| {
            message
                .get("executable")
                .and_then(serde_json::Value::as_str)
                .map(PathBuf::from)
        })
        .find(|executable| executable.file_name().is_some_and(|found| found == name))
        .unwrap_or_else(|| panic!("the {name} binary path"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

/// The profile this test binary was itself built with, read from its own
/// path (`target/<profile>/deps/<binary>`) rather than assumed. A nested
/// `cargo build` passes this back with `--profile` so it reuses the artifacts
/// the outer build already produced (e.g. CI's `--profile ci`) instead of
/// triggering a second full build under the default `dev` profile.
fn current_test_profile() -> String {
    let exe = std::env::current_exe().expect("current test executable path");
    let deps_dir = exe
        .parent()
        .expect("test executable has a parent directory");
    let profile_dir = deps_dir
        .parent()
        .expect("the deps directory has a parent directory");
    let profile = profile_dir
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .expect("the profile directory name is valid UTF-8");
    if profile == "debug" {
        "dev".to_owned()
    } else {
        profile.to_owned()
    }
}

/// Write the key material the scaffolded runtime expects, owner-read-only.
///
/// The signing key identifier is taken from the generated bundle, so a scaffold
/// that stops declaring one fails here rather than silently signing with a key
/// the deployment does not know.
fn provision_secrets(project: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let secrets = project.join("secrets");
    let bundle = yaml(&project.join("bundle/evidence.yaml"));
    let key_id = bundle["signing"]["activeKeyId"]
        .as_str()
        .expect("active signing key id");

    let (private_jwk, _) = ed25519_key(key_id);
    write_secret(
        &secrets.join("signing-ed25519-private-jwk"),
        private_jwk.as_bytes(),
    );
    for name in SECRET_FILES {
        // Regenerate until no byte is zero: the runtime rejects secret
        // material containing NUL bytes, exactly as `keygen secret` does.
        let mut material = [0_u8; 32];
        loop {
            getrandom::fill(&mut material).expect("random secret");
            if !material.contains(&0) {
                break;
            }
        }
        write_secret(&secrets.join(name), &material);
    }
    assert_eq!(
        fs::metadata(&secrets)
            .expect("secret directory")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

fn write_secret(path: &Path, material: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("key material directory");
    }
    fs::write(path, material).expect("writing key material");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("restricting key material");
}

/// A fresh Ed25519 keypair as its private JWK document and its public `x`
/// member. Nothing here is printed; the private half only ever reaches an
/// owner-only file under a temporary directory.
fn ed25519_key(key_id: &str) -> (String, String) {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).expect("random signing seed");
    let signing_key = SigningKey::from_bytes(&seed);
    let public = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    let private = format!(
        r#"{{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"{key_id}","d":"{}","x":"{public}"}}"#,
        URL_SAFE_NO_PAD.encode(signing_key.to_bytes())
    );
    (private, public)
}

/// Give the scaffolded Mint deployment the key material and the one registered
/// caller its README tells an operator to produce.
///
/// The scaffold renders the registration with a placeholder key and the
/// `.yaml.example` name Mint's registry loader ignores, so this is the step
/// that turns it into a registration: a real public key, under the real name.
fn provision_mint_secrets(project: &Path) {
    let root = project.join("mint");
    let config = yaml(&project.join(MINT_CONFIG));
    let (signing_jwk, _) = ed25519_key(
        config["signing"]["activeKeyId"]
            .as_str()
            .expect("active key id"),
    );
    write_secret(
        &root.join(
            config["signing"]["activeKeyFile"]
                .as_str()
                .expect("active key file"),
        ),
        signing_jwk.as_bytes(),
    );

    let example = project.join(MINT_CLIENT_REGISTRATION);
    let mut registration = yaml(&example);
    let caller_key_id = registration["keys"][0]["kid"]
        .as_str()
        .expect("the registration names a caller key id")
        .to_owned();
    let (caller_jwk, caller_public) = ed25519_key(&caller_key_id);
    assert!(
        !registration["keys"][0]["x"]
            .as_str()
            .expect("the registration carries a placeholder key")
            .is_empty(),
        "the placeholder key must be a value an operator can recognise"
    );
    registration["keys"][0]["x"] = serde_norway::Value::String(caller_public);

    // The caller's own key belongs to the caller, so it lands where the README
    // says it does rather than beside Mint's.
    write_secret(
        &project.join("caller/signing-ed25519-private-jwk"),
        caller_jwk.as_bytes(),
    );
    fs::write(
        example.with_file_name("scaffold-client.yaml"),
        serde_norway::to_string(&registration).expect("registration YAML"),
    )
    .expect("writing the client registration");
}

fn yaml(path: &Path) -> serde_norway::Value {
    serde_norway::from_str(
        &fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parsing {}: {error}", path.display()))
}

/// The bundle-relative fixture paths the scaffold generated.
fn scaffolded_fixtures(project: &Path) -> Vec<String> {
    let mut fixtures = fs::read_dir(project.join("bundle/fixtures"))
        .expect("fixtures directory")
        .map(|entry| entry.expect("fixture entry").file_name())
        .filter_map(|name| name.to_str().map(ToOwned::to_owned))
        .filter(|name| name.ends_with(".yaml"))
        .map(|name| format!("fixtures/{name}"))
        .collect::<Vec<_>>();
    fixtures.sort();
    fixtures
}

/// The documented freeze: no write bits anywhere in the bundle, and a
/// read-only runtime file. Evidence refuses a deployment input it could write.
fn freeze(project: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    set_tree_mode(&project.join("bundle"), 0o555, 0o444);
    fs::set_permissions(
        project.join("runtime.yaml"),
        fs::Permissions::from_mode(0o444),
    )
    .expect("freezing the runtime file");
}

/// Restore write permissions so the temporary directory can be removed.
fn unfreeze(project: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    set_tree_mode(&project.join("bundle"), 0o755, 0o644);
    fs::set_permissions(
        project.join("runtime.yaml"),
        fs::Permissions::from_mode(0o644),
    )
    .expect("unfreezing the runtime file");
}

fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(path).expect("tree entry");
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("opening a directory");
        for entry in fs::read_dir(path).expect("reading a directory") {
            set_tree_mode(
                &entry.expect("tree entry").path(),
                directory_mode,
                file_mode,
            );
        }
        fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))
            .expect("setting a directory mode");
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(file_mode))
            .expect("setting a file mode");
    }
}

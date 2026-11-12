//! A byte-level golden over the whole development render: every file a full
//! description produces, hashed in path order. Development output must not
//! change when the renderer's internals do.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::description::{
    ExchangeIssuer, ExchangeMapping, InteractiveApplication, SyntheticUser, TokenExchangeClient,
};

/// sha256 over `relative path NUL bytes NUL` for every file, in path order.
const DEVELOPMENT_RENDER_DIGEST: &str =
    "f72ce1a797e11e9db5ecc8d59248041310bc27cc09fc001dd1b71d74d03a847c";

fn walk(root: &Path, directory: &Path, hasher: &mut Sha256) {
    let mut entries: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            walk(root, &path, hasher);
        } else {
            hasher.update(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .as_bytes(),
            );
            hasher.update([0]);
            hasher.update(fs::read(&path).unwrap());
            hasher.update([0]);
        }
    }
}

#[test]
fn the_development_render_of_a_full_description_is_byte_stable() {
    let mut description = crate::testing::synthetic_description();
    let root = std::env::temp_dir().join(format!(
        "registry-render-golden-{}",
        crate::container::random_urlsafe(16).unwrap()
    ));
    description.state_root = root.clone();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(root.join("secrets")).unwrap();
    for (name, value) in [
        ("compatibility-client-secret", "fixture-compat-secret"),
        ("app", "synthetic-application-secret"),
        ("user", "synthetic-user-password"),
    ] {
        fs::write(root.join("secrets").join(name), value).unwrap();
    }
    description
        .interactive_applications
        .push(InteractiveApplication {
            id: "0197aaaa-0000-7000-8000-0000000000e1".into(),
            client_id: "synthetic-browser".into(),
            client_secret_file: "secrets/app".into(),
            origin: "http://127.0.0.1:3000".into(),
            redirect_uris: vec!["http://127.0.0.1:3000/auth/callback".into()],
            audience: description.resource_servers[0].identifier.clone(),
            token_attributes: vec!["registry_role".into()],
            refresh_tokens: false,
        });
    description.synthetic_users.push(SyntheticUser {
        id: "0197aaaa-0000-7000-8000-0000000000e2".into(),
        username: "staff-one".into(),
        email: "staff-one@example.test".into(),
        password_file: "secrets/user".into(),
        attributes: [("registry_role".to_owned(), "staff".to_owned())].into(),
    });
    description.roles[0]
        .assigned_users
        .push("0197aaaa-0000-7000-8000-0000000000e2".into());
    description.roles[0]
        .assigned_applications
        .push("0197aaaa-0000-7000-8000-0000000000e1".into());
    description.exchange_issuers.push(ExchangeIssuer {
        id: "0197aaaa-0000-7000-8000-0000000000d1".into(),
        name: "Synthetic Authority".into(),
        issuer: "https://authority.example".into(),
        jwks_endpoint: "https://authority.example/jwks".into(),
        mapping: ExchangeMapping::InstitutionalGrant,
        clients: vec![],
        token_attributes: Default::default(),
    });
    description.machine_clients[0].token_exchange = Some(TokenExchangeClient {
        assertion_resource_server_id: description.resource_servers[0].id.clone(),
        assertion_scope: "evidence:invoke".into(),
        ordinary_resource_permissions: Vec::new(),
    });
    crate::render::render(&description).unwrap();
    let mut hasher = Sha256::new();
    walk(&root, &root, &mut hasher);
    // The secrets directory is input, not output: hashing it too is harmless
    // because it is fixed above.
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    fs::remove_dir_all(&root).unwrap();
    assert_eq!(digest, DEVELOPMENT_RENDER_DIGEST);
}

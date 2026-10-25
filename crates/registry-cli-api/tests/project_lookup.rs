use std::{cell::Cell, fs};

use registry_cli_api::{run_api, ApiArgs, LocalConnection};
use tempfile::TempDir;

#[test]
fn local_client_discovers_the_exact_product_root_from_a_subdirectory() {
    let temporary = TempDir::new().unwrap();
    let project = temporary.path().join("project");
    let nested = project.join("modules/contacts");
    fs::create_dir_all(&nested).unwrap();
    fs::write(project.join("registry.yaml"), "marker").unwrap();
    fs::write(project.join("casework.yaml"), "other product").unwrap();
    let output = temporary.path().join("out");
    let called = Cell::new(false);
    let args = ApiArgs {
        path: "v1/status".to_owned(),
        project: Some(nested),
        client: Some("operator".to_owned()),
        connection: None,
        url: None,
        token_file: None,
        ca_file: None,
        method: None,
        input: None,
        header: Vec::new(),
        accept: None,
        output: Some(output),
        include: false,
        idempotency_key: None,
        if_match: None,
    };
    let error = run_api("breg", args, |found, client| {
        called.set(true);
        assert_eq!(found, project.canonicalize().unwrap());
        assert_eq!(client, "operator");
        LocalConnection::anonymous("http://127.0.0.1:9".to_owned())
            .map_err(|error| error.to_string())
    })
    .unwrap_err();
    assert!(called.get());
    assert_ne!(error.exit_code(), 2);
}

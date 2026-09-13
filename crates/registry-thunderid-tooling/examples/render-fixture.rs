//! Regenerate the stored synthetic session fixture. Output is deterministic
//! for a pinned release and a fixed description; committed copies under
//! `products/identity/thunderid/fixtures/` must come from this command.
use std::path::PathBuf;

fn main() {
    let out = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: render-fixture OUTPUT_DIR");
    let mut description = registry_thunderid_tooling::testing::synthetic_description();
    description.state_root = out;
    std::fs::create_dir_all(description.state_root.join("secrets")).expect("secrets dir");
    std::fs::write(
        description
            .state_root
            .join("secrets/compatibility-client-secret"),
        "fixture-secret-not-a-real-credential",
    )
    .expect("fixture secret");
    let _ = std::fs::remove_dir_all(description.state_root.join("resources"));
    let _ = std::fs::remove_dir_all(description.state_root.join("registry-schema"));
    let rendered = registry_thunderid_tooling::render::render(&description).expect("render");
    println!("resources: {}", rendered.resources_dir.display());
    println!("schema:    {}", rendered.bootstrap_dir.display());
    println!("schema sha256: {}", rendered.agent_type_sha256);
}

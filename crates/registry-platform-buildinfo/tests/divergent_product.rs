use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PRODUCT_VERSION: &str = "1.7.2";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn run_fixture(
    project: &Path,
    target: &Path,
    product_tag: Option<&str>,
    release_tag: Option<&str>,
    nightly_tag: Option<&str>,
) -> Output {
    let mut command = Command::new(env!("CARGO"));
    command
        .args([
            "run",
            "--quiet",
            "--offline",
            "--manifest-path",
            project.join("Cargo.toml").to_str().unwrap(),
            "-p",
            "divergent-consumer",
        ])
        .env("CARGO_TARGET_DIR", target)
        .env_remove("REGISTRY_PRODUCT_RELEASE_TAG")
        .env_remove("REGISTRY_RELEASE_TAG")
        .env_remove("REGISTRY_NIGHTLY_TAG");
    if let Some(tag) = product_tag {
        command.env("REGISTRY_PRODUCT_RELEASE_TAG", tag);
    }
    if let Some(tag) = release_tag {
        command.env("REGISTRY_RELEASE_TAG", tag);
    }
    if let Some(tag) = nightly_tag {
        command.env("REGISTRY_NIGHTLY_TAG", tag);
    }
    command.output().expect("the fixture Cargo build runs")
}

#[test]
fn a_real_product_build_can_diverge_from_the_platform_package_version() {
    assert_ne!(
        PRODUCT_VERSION,
        env!("CARGO_PKG_VERSION"),
        "the fixture must exercise divergent product and platform versions"
    );

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is after the Unix epoch")
        .as_nanos();
    let target_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let scratch = target_root.join(format!(
        "buildinfo-product-fixture-{}-{nonce}",
        std::process::id()
    ));
    let project = scratch.join("project");
    let product = project.join("product");
    let consumer = project.join("consumer");
    let fixture_target = scratch.join("target");
    fs::create_dir_all(product.join("src")).expect("the product source directory is created");
    fs::create_dir_all(consumer.join("src")).expect("the consumer source directory is created");
    let buildinfo_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fs::write(
        project.join("Cargo.toml"),
        "[workspace]\nmembers = [\"product\", \"consumer\"]\nresolver = \"2\"\n",
    )
    .expect("the fixture workspace manifest is written");
    fs::write(
        product.join("Cargo.toml"),
        format!(
            "[package]\nname = \"divergent-product\"\nversion = \"{PRODUCT_VERSION}\"\nedition = \"2021\"\nbuild = \"build.rs\"\n\n[build-dependencies]\nregistry-platform-buildinfo = {{ path = {buildinfo_path:?} }}\n"
        ),
    )
    .expect("the product manifest is written");
    fs::write(
        product.join("build.rs"),
        "fn main() { registry_platform_buildinfo::product::emit_product_build_info(\"discovery\"); }\n",
    )
    .expect("the product build script is written");
    fs::write(
        product.join("src/lib.rs"),
        "include!(concat!(env!(\"OUT_DIR\"), \"/product_build_info.rs\"));\n",
    )
    .expect("the product library is written");
    fs::write(
        consumer.join("Cargo.toml"),
        "[package]\nname = \"divergent-consumer\"\nversion = \"0.44.0\"\nedition = \"2021\"\n\n[dependencies]\ndivergent-product = { path = \"../product\" }\n",
    )
    .expect("the consumer manifest is written");
    fs::write(
        consumer.join("src/main.rs"),
        "fn main() { println!(\"{}\", divergent_product::DISPLAY_VERSION); }\n",
    )
    .expect("the consumer executable is written");

    let product_release = run_fixture(
        &project,
        &fixture_target,
        Some("discovery/v1.7.2"),
        None,
        None,
    );
    assert!(
        product_release.status.success(),
        "scoped product build failed: {}",
        String::from_utf8_lossy(&product_release.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&product_release.stdout), "1.7.2\n");

    let nightly_tag = format!("v{}-nightly.20261002.{SHA}", env!("CARGO_PKG_VERSION"));
    let nightly = run_fixture(&project, &fixture_target, None, None, Some(&nightly_tag));
    assert!(
        nightly.status.success(),
        "divergent nightly build failed: {}",
        String::from_utf8_lossy(&nightly.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&nightly.stdout),
        format!("{PRODUCT_VERSION}-nightly.20261002.{SHA}\n")
    );

    let stack_release_tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let stack_release = run_fixture(
        &project,
        &fixture_target,
        None,
        Some(&stack_release_tag),
        None,
    );
    assert!(
        stack_release.status.success(),
        "Stack consumer build failed: {}",
        String::from_utf8_lossy(&stack_release.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&stack_release.stdout),
        format!("{PRODUCT_VERSION}-dev\n")
    );

    fs::remove_dir_all(&scratch).expect("the fixture scratch directory is removed");
}

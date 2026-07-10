// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::Command;

#[test]
fn installer_rejects_shell_active_and_noncanonical_release_tags() {
    let installer = Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh");
    let hostile = "v999.0.0-$(touch${IFS}/tmp/registryctl-owned)";

    for version in [hostile, "latest", "v1.2.3-rc1", "v01.2.3"] {
        let output = Command::new("bash")
            .arg(&installer)
            .env("REGISTRYCTL_VERSION", version)
            .output()
            .unwrap_or_else(|err| panic!("installer runs for rejected tag: {err}"));
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(!output.status.success(), "installer accepted {version}");
        assert!(
            stderr.contains("Refusing non-canonical registryctl release tag."),
            "unexpected rejection for {version}: {stderr}"
        );
        assert!(
            !stderr.contains(version),
            "installer echoed rejected tag {version}"
        );
        assert!(
            !stderr.contains("cargo install"),
            "installer emitted a fallback command"
        );
    }
}

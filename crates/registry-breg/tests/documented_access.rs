#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
// SPDX-License-Identifier: Apache-2.0

use serde_json::{json, Value};

fn fragment(page: &str, marker: &str) -> Value {
    // A fence may carry a title or runner attribute after the language, so
    // the YAML starts after the line break that ends the fence line.
    let fragments: Vec<_> = page
        .split("```yaml")
        .skip(1)
        .filter_map(|rest| rest.split_once('\n').map(|(_, body)| body))
        .filter_map(|rest| rest.split_once("\n```").map(|(yaml, _)| yaml))
        .filter(|yaml| yaml.contains(marker))
        .collect();
    assert_eq!(
        fragments.len(),
        1,
        "expected one example containing {marker}"
    );
    serde_norway::from_str(fragments[0]).unwrap()
}

#[cfg(feature = "runtime")]
#[test]
fn documented_runtime_config_parses_after_filling_the_package_digest() {
    let page = include_str!("../../../docs/site/src/content/docs/operate/breg.mdx");
    let mut source = fragment(
        page,
        "apiVersion: id.registrystack.org/formats/breg/runtime/v1alpha1",
    );
    // The page documents the digest pin as optional and leaves it out of the
    // example; the example must parse as shown and with the pin an operator
    // adds, retaining every authored key, kind, token-verifier setting, and
    // secret reference.
    registry_breg::runtime_config::parse_runtime_config_with_env(
        &serde_norway::to_string(&source).unwrap(),
        |_| None,
    )
    .expect("documented runtime config parses as shown");
    source["package"]["expectedDigest"] = json!(format!("sha256:{}", "b".repeat(64)));
    registry_breg::runtime_config::parse_runtime_config_with_env(
        &serde_norway::to_string(&source).unwrap(),
        |_| None,
    )
    .expect("documented runtime config parses without resolving secrets or connecting to services");
}

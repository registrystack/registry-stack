//! A product that holds `assertionIssuers` in its own issuer entry reads it
//! through the shared decode rule, so an empty map or an empty client list is
//! refused the way the shared clients block refuses it (CFG-EMPTY-2).

use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    #[serde(
        default,
        deserialize_with = "registry_platform_config::non_empty_assertion_issuers"
    )]
    assertion_issuers: BTreeMap<String, Vec<String>>,
}

fn read(json: &str) -> Result<Entry, String> {
    serde_json::from_str(json).map_err(|error| error.to_string())
}

#[test]
fn an_empty_assertion_issuer_map_is_refused() {
    let refused = read(r#"{"assertionIssuers": {}}"#).unwrap_err();
    assert!(refused.contains("at least one client"), "{refused}");
}

#[test]
fn a_client_with_no_assertion_issuer_is_refused() {
    let refused = read(r#"{"assertionIssuers": {"portal": []}}"#).unwrap_err();
    assert!(
        refused.contains("at least one assertion issuer"),
        "{refused}"
    );
}

#[test]
fn an_omitted_member_and_a_listed_client_are_read() {
    assert!(read("{}").unwrap().assertion_issuers.is_empty());
    let listed = read(r#"{"assertionIssuers": {"portal": ["https://idp.example"]}}"#).unwrap();
    assert_eq!(
        listed.assertion_issuers["portal"],
        vec!["https://idp.example".to_owned()]
    );
}

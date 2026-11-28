use super::*;
use crate::{
    collect_posture_settings, CollectedSettings, RuntimeConfigLoader, RuntimeEnvelope, Stated,
};
use serde::Deserialize;

const ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: "registry.registrystack.org/example-runtime/v1alpha1",
    kind: "ExampleRuntimeConfig",
};

const HEAD: &str =
    "apiVersion: registry.registrystack.org/example-runtime/v1alpha1\nkind: ExampleRuntimeConfig\n";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Block {
    #[serde(default)]
    transport: Option<Stated<DestinationTransport>>,
    #[serde(default)]
    allowed_private_cidrs: Option<PrivateRanges>,
}

#[derive(Debug, Deserialize)]
struct Example {
    hook: Block,
}

fn load(body: &str) -> (Result<Example, String>, CollectedSettings) {
    let text = format!("{HEAD}hook:\n{body}");
    let (result, collected) = collect_posture_settings(|| {
        RuntimeConfigLoader::new_without_posture(ENVELOPE).parse_str::<Example>(&text, |_| None)
    });
    (
        result
            .map(|loaded| loaded.config)
            .map_err(|e| format!("{e:#}")),
        collected,
    )
}

fn ranges(list: &str) -> String {
    format!("  allowedPrivateCidrs: {list}\n")
}

const LIST: &str = "/hook/allowedPrivateCidrs";

fn check_offline(body: &str) -> crate::RuntimeFileCheck<Example> {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let path = directory.path().join("runtime.yaml");
    std::fs::write(&path, format!("{HEAD}hook:\n{body}")).unwrap();
    RuntimeConfigLoader::new_without_posture(ENVELOPE).check_offline::<Example>(
        &path,
        false,
        |_| crate::DEFAULT_STAND_IN,
    )
}

/// What the offline check reports for the list: each diagnostic's code and
/// path, read from the diagnostic members and not from the rendered text.
fn findings(list: &str) -> Vec<(String, String)> {
    let file = check_offline(&ranges(list));
    let config = &file.loaded.as_ref().expect("the list decodes").config;
    config
        .hook
        .allowed_private_cidrs
        .as_ref()
        .unwrap()
        .check_file(LIST, &file, "ExampleRuntimeConfig")
        .into_iter()
        .map(|d| (d.code, d.path))
        .collect()
}

fn refused(list: &str, code: &str, index: usize) {
    assert_eq!(
        findings(list),
        [(code.to_owned(), format!("{LIST}/{index}"))],
        "{list}"
    );
}

/// The code and path of the diagnostic that decides a refusal at decode time.
fn decode_refusal(list: &str) -> (String, String) {
    let text = format!("{HEAD}hook:\n{}", ranges(list));
    let error = RuntimeConfigLoader::new_without_posture(ENVELOPE)
        .parse_str::<Example>(&text, |_| None)
        .expect_err("the document is refused");
    let decider = error.deciding_diagnostic();
    (decider.code.clone(), decider.path.clone())
}

#[test]
fn each_transport_converts_to_its_class() {
    assert_eq!(
        TransportClass::from(DestinationTransport::VerifiedTls),
        TransportClass::VerifiedTls
    );
    assert_eq!(
        TransportClass::from(DestinationTransport::LoopbackPlaintext),
        TransportClass::LoopbackPlaintext
    );
    assert_eq!(
        TransportClass::from(DestinationTransport::PrivateNetworkPlaintext),
        TransportClass::PrivateNetworkPlaintext
    );
}

#[test]
fn only_private_network_plaintext_is_an_explicit_setting() {
    assert_eq!(DestinationTransport::VerifiedTls.explicit_setting(), None);
    assert_eq!(
        DestinationTransport::LoopbackPlaintext.explicit_setting(),
        None
    );
    let setting = DestinationTransport::PrivateNetworkPlaintext
        .explicit_setting()
        .expect("private plain text is explicit");
    assert_eq!(
        setting.code,
        "platform.posture.destination-private-plaintext"
    );
    assert_eq!(setting.key, "transport");
    assert_eq!(<DestinationTransport as ExplicitClass>::SETTINGS.len(), 1);
}

#[test]
fn the_explicit_summary_carries_no_value() {
    let setting = DestinationTransport::PrivateNetworkPlaintext
        .explicit_setting()
        .unwrap();
    for word in ["http://", "10.", "172.", "192.168."] {
        assert!(!setting.summary.contains(word), "{}", setting.summary);
    }
}

#[test]
fn private_network_plaintext_records_the_setting_with_its_pointer() {
    let (result, collected) = load("  transport: private-network-plaintext\n");
    let config = result.expect("an explicit setting never refuses");
    assert_eq!(
        config.hook.transport.as_ref().map(|t| *t.get()),
        Some(DestinationTransport::PrivateNetworkPlaintext)
    );
    assert_eq!(collected.explicit.len(), 1);
    let found = &collected.explicit[0];
    assert_eq!(
        found.setting.code,
        "platform.posture.destination-private-plaintext"
    );
    assert_eq!(found.pointer.as_deref(), Some("/hook/transport"));
    assert_eq!(found.position.map(|position| position.line), Some(4));
    assert!(collected.development.is_empty());
}

#[test]
fn the_other_two_transports_record_nothing() {
    for value in ["verified-tls", "loopback-plaintext"] {
        let (result, collected) = load(&format!("  transport: {value}\n"));
        assert!(result.is_ok(), "{value}");
        assert!(collected.explicit.is_empty(), "{value}");
    }
}

#[test]
fn transport_spellings_are_kebab_case_and_an_unknown_value_is_refused() {
    for (text, expected) in [
        ("verified-tls", DestinationTransport::VerifiedTls),
        (
            "loopback-plaintext",
            DestinationTransport::LoopbackPlaintext,
        ),
        (
            "private-network-plaintext",
            DestinationTransport::PrivateNetworkPlaintext,
        ),
    ] {
        let (result, _) = load(&format!("  transport: {text}\n"));
        let config = result.unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(config.hook.transport.map(|t| *t.get()), Some(expected));
        assert_eq!(
            serde_json::to_string(&expected).unwrap(),
            format!("\"{text}\"")
        );
    }
    for text in [
        "VerifiedTls",
        "verified_tls",
        "any-private",
        "private-network",
        "plaintext",
        "",
    ] {
        let (result, _) = load(&format!("  transport: \"{text}\"\n"));
        assert!(result.is_err(), "{text:?} is refused");
    }
}

#[test]
fn an_accepted_list_decodes_and_keeps_its_order() {
    let (result, _) = load(&ranges(
        "[172.16.0.0/12, 10.0.0.0/8, 100.64.0.0/10, fd12:3456::/32]",
    ));
    let config = result.expect("a list of private ranges is accepted");
    let listed = config.hook.allowed_private_cidrs.unwrap();
    let texts: Vec<String> = listed
        .ranges()
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        texts,
        [
            "172.16.0.0/12",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "fd12:3456::/32"
        ]
    );
    assert_eq!(listed.len(), 4);
    assert!(findings("[172.16.0.0/12, 10.0.0.0/8]").is_empty());
}

#[test]
fn an_empty_list_is_accepted_and_means_none() {
    let (result, _) = load(&ranges("[]"));
    let listed = result.unwrap().hook.allowed_private_cidrs.unwrap();
    assert!(listed.is_empty());
    assert!(listed.ranges().unwrap().is_empty());
}

#[test]
fn a_single_host_range_inside_private_space_is_accepted() {
    assert!(findings("[172.31.255.255/32, 100.127.255.255/32, fd00::1/128]").is_empty());
}

#[test]
fn ranges_that_contain_a_metadata_address_but_are_not_one_are_accepted() {
    assert!(findings("[fd00:ec2::/32, fd00:ec2::254/127, 100.100.100.0/24, fd00::/8]").is_empty());
}

#[test]
fn t12_a_link_local_range_is_not_private() {
    refused(
        "[169.254.0.0/16]",
        "platform.destination.range-not-private",
        0,
    );
}

#[test]
fn t13_the_whole_address_space_is_not_private() {
    for list in [
        "[0.0.0.0/0]",
        "[::/0]",
        "[10.0.0.0/7]",
        "[100.0.0.0/9]",
        "[127.0.0.0/8]",
        "[::ffff:10.0.0.0/104]",
    ] {
        refused(list, "platform.destination.range-not-private", 0);
    }
}

#[test]
fn the_metadata_singletons_are_refused_as_a_metadata_address_and_not_as_a_range() {
    for list in ["[100.100.100.200/32]", "[fd00:ec2::254/128]"] {
        refused(list, "platform.destination.range-not-private", 0);
        let file = check_offline(&ranges(list));
        let listed = file
            .loaded
            .as_ref()
            .unwrap()
            .config
            .hook
            .allowed_private_cidrs
            .as_ref()
            .unwrap();
        let found = &listed.check_file(LIST, &file, "ExampleRuntimeConfig")[0];
        assert!(
            found.message.contains("cloud metadata address"),
            "{}",
            found.message
        );
        assert!(
            !found.message.contains("not inside private space"),
            "{}",
            found.message
        );
        assert!(found
            .suggested_action
            .contains("Remove the metadata address"));
    }
    refused(
        "[169.254.169.254/32]",
        "platform.destination.range-not-private",
        0,
    );
    refused(
        "[::ffff:100.100.100.200/128]",
        "platform.destination.range-not-private",
        0,
    );
}

#[test]
fn t14_host_bits_make_a_range_not_canonical() {
    for list in [
        "[10.0.0.1/8]",
        "[172.16.0.1/12]",
        "[fd00::1/8]",
        "[10.0.0.0/0]",
    ] {
        refused(list, "platform.destination.range-not-canonical", 0);
    }
}

#[test]
fn a_range_with_host_bits_that_is_also_not_private_is_reported_as_not_canonical_first() {
    refused(
        "[192.168.1.1/8]",
        "platform.destination.range-not-canonical",
        0,
    );
    refused("[0.0.0.0/32]", "platform.destination.range-not-private", 0);
}

#[test]
fn t15_more_than_sixteen_ranges_are_refused_and_sixteen_are_accepted() {
    let many = |count: usize| {
        let items: Vec<String> = (0..count).map(|i| format!("10.{i}.0.0/16")).collect();
        format!("[{}]", items.join(", "))
    };
    assert_eq!(
        findings(&many(17)),
        [(
            "platform.destination.too-many-ranges".to_owned(),
            LIST.to_owned()
        )]
    );
    assert!(findings(&many(16)).is_empty());
    let (result, _) = load(&ranges(&many(17)));
    let listed = result.unwrap().hook.allowed_private_cidrs.unwrap();
    assert_eq!(listed.ranges(), Err(PrivateRangeRefusal::TooMany));
}

#[test]
fn a_repeated_range_is_refused_at_the_second_item() {
    for list in [
        "[10.0.0.0/8, 172.16.0.0/12, 10.0.0.0/8]",
        "[fd00::/8, FD00::/8]",
        "[fd00::/8, \"fd00:0:0:0:0:0:0:0/8\"]",
    ] {
        let (code, path) = decode_refusal(list);
        assert_eq!(code, "config.duplicate-item", "{list}");
        let index = if list.starts_with("[10") { 2 } else { 1 };
        assert_eq!(path, format!("{LIST}/{index}"), "{list}");
    }
}

#[test]
fn text_that_is_not_a_range_is_malformed() {
    for text in [
        "10.0.0.0",
        "10.0.0.0/33",
        "10.0.0.0/",
        "hooks/8",
        "fd00::/129",
        "/8",
        "",
        "10.0.0.0/+8",
        "10.0.0.0/08",
        "10.0.0.0/0000000008",
        "fd00::%eth0/8",
        "fd00::%1/8",
        " 10.0.0.0/8",
        "10.0.0.0/8 ",
        "10.0.0.0 /8",
        "[fd00::]/8",
        "010.0.0.0/8",
        "10.0.0.0/8/8",
    ] {
        refused(
            &format!("[\"{text}\"]"),
            "platform.destination.range-malformed",
            0,
        );
    }
}

#[test]
fn every_refusal_names_its_fix_and_never_repeats_the_value() {
    let items: Vec<String> = (0..17).map(|i| format!("10.{i}.0.0/16")).collect();
    for (list, fix) in [
        (
            "[\"hooks/8\"]",
            "Write each range as a network address and a prefix length",
        ),
        ("[169.254.0.0/16]", "Name only private ranges"),
        ("[10.0.0.1/8]", "Write the network address"),
        (&format!("[{}]", items.join(", ")), "Merge ranges"),
    ] {
        let file = check_offline(&ranges(list));
        let listed = file
            .loaded
            .as_ref()
            .unwrap()
            .config
            .hook
            .allowed_private_cidrs
            .as_ref()
            .unwrap();
        let found = listed.check_file(LIST, &file, "ExampleRuntimeConfig");
        assert_eq!(found.len(), 1, "{list}");
        assert!(
            found[0].suggested_action.contains(fix),
            "{}",
            found[0].suggested_action
        );
        for text in ["hooks", "169.254", "10.0.0.1"] {
            assert!(!found[0].message.contains(text), "{}", found[0].message);
        }
    }
}

#[test]
fn a_refusal_is_positioned_at_its_item_in_the_file() {
    let file = check_offline(&ranges("[10.0.0.0/8, 169.254.0.0/16]"));
    let listed = file
        .loaded
        .as_ref()
        .unwrap()
        .config
        .hook
        .allowed_private_cidrs
        .as_ref()
        .unwrap();
    let found = listed.check_file(LIST, &file, "ExampleRuntimeConfig");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].artifact.as_deref(), Some("ExampleRuntimeConfig"));
    let source = found[0].source.as_ref().expect("positioned");
    assert_eq!(source.line, Some(4));
}

#[test]
fn the_check_without_a_file_reports_the_same_codes_and_paths() {
    let (result, _) = load(&ranges("[10.0.0.0/8, 169.254.0.0/16, \"x\"]"));
    let listed = result.unwrap().hook.allowed_private_cidrs.unwrap();
    let found: Vec<(String, String)> = listed
        .check(LIST)
        .into_iter()
        .map(|d| (d.code, d.path))
        .collect();
    assert_eq!(
        found,
        [
            (
                "platform.destination.range-not-private".to_owned(),
                format!("{LIST}/1")
            ),
            (
                "platform.destination.range-malformed".to_owned(),
                format!("{LIST}/2")
            ),
        ]
    );
    assert_eq!(listed.ranges(), Err(PrivateRangeRefusal::NotPrivate));
}

#[test]
fn a_deferred_expression_is_not_read_as_a_range() {
    let file = check_offline(&ranges("[\"${PRIVATE_RANGE}\", 169.254.0.0/16]"));
    let listed = file
        .loaded
        .as_ref()
        .unwrap()
        .config
        .hook
        .allowed_private_cidrs
        .as_ref()
        .unwrap();
    let found: Vec<String> = listed
        .check_file(LIST, &file, "ExampleRuntimeConfig")
        .into_iter()
        .map(|d| d.path)
        .collect();
    assert_eq!(found, [format!("{LIST}/1")]);
}

#[test]
fn wrong_shapes_are_refused_at_decode_with_the_readers_codes() {
    for (list, code, path) in [
        ("[8]", "config.expected-string", format!("{LIST}/0")),
        ("[{}]", "config.expected-string", format!("{LIST}/0")),
        ("10.0.0.0/8", "config.invalid-type", LIST.to_owned()),
        ("null", "config.null-value", LIST.to_owned()),
    ] {
        assert_eq!(decode_refusal(list), (code.to_owned(), path), "{list}");
    }
    let text = format!("{HEAD}hook:\n  transport: null\n");
    let error = RuntimeConfigLoader::new_without_posture(ENVELOPE)
        .parse_str::<Example>(&text, |_| None)
        .expect_err("a null transport is refused");
    let decider = error.deciding_diagnostic();
    assert_eq!(decider.code, "config.null-value");
    assert_eq!(decider.path, "/hook/transport");
}

#[test]
fn a_list_with_a_refused_range_does_not_serialise() {
    let (result, _) = load(&ranges("[10.0.0.0/8, 169.254.0.0/16]"));
    let listed = result.unwrap().hook.allowed_private_cidrs.unwrap();
    assert!(serde_json::to_string(&listed).is_err());
    let (result, _) = load(&ranges("[10.0.0.0/8, fd00::/8]"));
    let listed = result.unwrap().hook.allowed_private_cidrs.unwrap();
    assert_eq!(
        serde_json::to_string(&listed).unwrap(),
        "[\"10.0.0.0/8\",\"fd00::/8\"]"
    );
}

#[test]
fn a_range_reports_its_network_and_prefix() {
    let (result, _) = load(&ranges("[172.16.0.0/12, fd12:3456::/32]"));
    let config = result.unwrap().hook.allowed_private_cidrs.unwrap();
    let listed = config.into_ranges().unwrap();
    assert_eq!(
        listed[0].network(),
        "172.16.0.0".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(listed[0].prefix(), 12);
    assert_eq!(listed[1].prefix(), 32);
}

#[cfg(feature = "schema")]
#[test]
fn the_schemas_describe_the_members() {
    let mut generator = schemars::generate::SchemaSettings::draft2020_12().into_generator();
    let transport =
        serde_json::to_value(generator.subschema_for::<Stated<DestinationTransport>>()).unwrap();
    assert_eq!(
        transport["x-registry-explicit-production"],
        serde_json::json!(["platform.posture.destination-private-plaintext"])
    );
    let ranges = serde_json::to_value(generator.subschema_for::<PrivateRanges>()).unwrap();
    assert_eq!(ranges["type"], "array");
    assert_eq!(ranges["maxItems"], 16);
    assert_eq!(ranges["uniqueItems"], true);
    assert_eq!(ranges["items"]["type"], "string");
    assert_eq!(
        ranges["items"]["pattern"],
        "^[0-9a-fA-F.:]+/(0|[1-9][0-9]{0,2})$"
    );
}

use super::*;
use serde::Deserialize;
use std::collections::BTreeMap;

const ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: "registry.registrystack.org/example-runtime/v1alpha1",
    kind: "ExampleRuntimeConfig",
};

const REMOVED: &[RemovedKey] = &[
    RemovedKey {
        path: "server.bind",
        replacement: "use listener.bind",
    },
    RemovedKey {
        path: "sources.*.file",
        replacement: "use sources.<id>.path",
    },
];

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Example {
    api_version: String,
    kind: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    port: Option<String>,
    #[serde(default)]
    count: Option<u16>,
    #[serde(default)]
    flag: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    list: Vec<String>,
    #[serde(default)]
    audit: Option<Audit>,
    #[serde(default)]
    sources: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    mode: Option<Mode>,
    #[serde(default)]
    secret_providers: Option<BTreeMap<String, BTreeMap<String, String>>>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
enum Mode {
    Strict,
    Relaxed,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Audit {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    hash_key_ref: Option<String>,
    #[serde(default)]
    allowed_key_refs: Vec<String>,
}

fn loader() -> RuntimeConfigLoader {
    RuntimeConfigLoader::new(ENVELOPE).removed_keys(REMOVED)
}

fn header() -> String {
    format!(
        "apiVersion: {}\nkind: {}\n",
        ENVELOPE.api_version, ENVELOPE.kind
    )
}

fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    move |name| {
        pairs
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| (*value).to_owned())
    }
}

fn parse(text: &str) -> Result<LoadedRuntimeConfig<Example>, RuntimeConfigError> {
    loader().parse_str(text, env(&[("NAME", "north"), ("EMPTY", "")]))
}

#[test]
fn substitution_applies_to_string_values_after_parsing() {
    let loaded = parse(&format!(
        "{}name: \"${{NAME}}-counter\"\nlist: [\"${{NAME}}\", plain]\n",
        header()
    ))
    .expect("substitutes");
    assert_eq!(loaded.config.name.as_deref(), Some("north-counter"));
    assert_eq!(loaded.config.list, ["north", "plain"]);
}

#[test]
fn substitution_leaves_comments_and_keys_untouched() {
    // A comment naming an unset variable is not substituted, so it cannot
    // refuse the document; a key is never substituted either, and one that
    // holds an expression is refused rather than resolved (CFG-SEC-2).
    let loaded = parse(&format!("{}# ${{UNSET_IN_COMMENT}}\nname: x\n", header()))
        .expect("comment is not substituted");
    assert_eq!(loaded.config.name.as_deref(), Some("x"));

    let error = parse(&format!("{}\"${{NAME}}\": x\n", header())).expect_err("key stays literal");
    assert_eq!(
        error.kind(),
        RuntimeConfigErrorKind::SubstitutionInReference
    );
    assert_eq!(error.field(), "${NAME}");
}

#[test]
fn substituted_values_stay_strings_even_when_they_look_like_yaml() {
    let loaded = loader()
        .parse_str::<Example>(
            &format!(
                "{}port: ${{PORT}}\nflag: ${{FLAG}}\nname: ${{DOC}}\n",
                header()
            ),
            env(&[
                ("PORT", "8080"),
                ("FLAG", "true"),
                ("DOC", "{a: [1, 2]}\n- x"),
            ]),
        )
        .expect("values stay strings");
    assert_eq!(loaded.config.port.as_deref(), Some("8080"));
    assert_eq!(loaded.config.flag.as_deref(), Some("true"));
    assert_eq!(loaded.config.name.as_deref(), Some("{a: [1, 2]}\n- x"));

    let error = loader()
        .parse_str::<Example>(
            &format!("{}count: ${{COUNT}}\n", header()),
            env(&[("COUNT", "3")]),
        )
        .expect_err("a substituted number is still a string");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::InvalidValue);
    assert_eq!(error.field(), "count");
}

#[test]
fn substitution_supports_default_and_required_message_forms() {
    let loaded = parse(&format!(
        "{}name: \"${{MISSING:-fallback}}\"\nflag: \"${{EMPTY:-}}\"\n",
        header()
    ))
    .expect("defaults apply");
    assert_eq!(loaded.config.name.as_deref(), Some("fallback"));
    assert_eq!(loaded.config.flag.as_deref(), Some(""));

    let error = parse(&format!(
        "{}name: \"${{MISSING:?set MISSING to the counter name}}\"\n",
        header()
    ))
    .expect_err("required message form refuses");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::Substitution);
    assert_eq!(error.field(), "name");
    // The operator-authored message is configuration too, so the refusal
    // names the variable and withholds the message.
    assert!(error.message().contains("MISSING"), "{error}");
    assert!(error.message().contains("withheld"), "{error}");
    assert!(!error.message().contains("counter name"), "{error}");
}

#[test]
fn substitution_refuses_an_unset_or_empty_variable_without_default() {
    for text in ["name: ${MISSING}\n", "name: ${EMPTY}\n"] {
        let error = parse(&format!("{}{text}", header())).expect_err("unset refuses");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::Substitution);
        assert_eq!(error.code(), "runtime_config.substitution");
        assert_eq!(error.field(), "name");
    }
}

#[test]
fn substitution_refuses_malformed_expressions() {
    for text in [
        "name: \"${NAME\"\n",
        "name: \"${1BAD}\"\n",
        "name: \"${}\"\n",
    ] {
        let error = parse(&format!("{}{text}", header())).expect_err("malformed refuses");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::Substitution, "{text}");
    }
}

#[test]
fn substitution_is_single_pass() {
    let loaded = loader()
        .parse_str::<Example>(
            &format!("{}name: ${{OUTER}}\n", header()),
            env(&[("OUTER", "${INNER}"), ("INNER", "leak")]),
        )
        .expect("substitutes once");
    assert_eq!(loaded.config.name.as_deref(), Some("${INNER}"));
}

#[test]
fn substitution_refuses_a_nul_byte() {
    let error = loader()
        .parse_str::<Example>(
            &format!("{}name: ${{NUL}}\n", header()),
            env(&[("NUL", "a\0b")]),
        )
        .expect_err("NUL refuses");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::Substitution);
}

#[test]
fn substitution_is_refused_in_every_reference_field() {
    for (text, field) in [
        ("audit:\n  hashKeyRef: ${NAME}\n", "audit.hashKeyRef"),
        (
            "audit:\n  hashKeyRef: \"secret:env/${NAME}\"\n",
            "audit.hashKeyRef",
        ),
        (
            "audit:\n  allowedKeyRefs: [\"secret:file/a\", \"${NAME}\"]\n",
            "audit.allowedKeyRefs.1",
        ),
        // A reference field that the variable would resolve fine for is still
        // refused: the rule is about the field, not the value.
        (
            "audit:\n  hashKeyRef: \"${MISSING:-secret:env/X}\"\n",
            "audit.hashKeyRef",
        ),
    ] {
        let error = parse(&format!("{}{text}", header())).expect_err("reference refuses");
        assert_eq!(
            error.kind(),
            RuntimeConfigErrorKind::SubstitutionInReference,
            "{text}"
        );
        assert_eq!(error.code(), "runtime_config.substitution_in_reference");
        assert_eq!(error.field(), field);
        assert!(error.message().contains("secret:env/NAME"), "{error}");
    }

    let loaded = parse(&format!(
        "{}audit:\n  path: \"/var/${{NAME}}/audit\"\n  hashKeyRef: secret:file/audit-key\n",
        header()
    ))
    .expect("a sibling that is not a reference substitutes");
    assert_eq!(
        loaded.config.audit.and_then(|audit| audit.path).as_deref(),
        Some("/var/north/audit")
    );
}

#[test]
fn removed_keys_are_refused_with_their_replacement_named() {
    let error = parse(&format!("{}server:\n  bind: 127.0.0.1:1\n", header()))
        .expect_err("removed key refuses");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::RemovedKey);
    assert_eq!(error.code(), "runtime_config.removed_key");
    assert_eq!(error.field(), "server.bind");
    assert_eq!(
        error.message(),
        "server.bind: `bind` is no longer accepted; next: use listener.bind."
    );
    // `server` is not a member either, so it is reported beside the removed
    // key below it.
    assert!(has_code(&error, "config.removed-key"), "{error}");

    let error = parse(&format!(
        "{}sources:\n  people:\n    file: /data/people.sqlite\n",
        header()
    ))
    .expect_err("wildcard removed key refuses");
    assert_eq!(error.field(), "sources.people.file");
    assert!(error.message().contains("sources.<id>.path"));
}

#[test]
fn cfg_diag_5_the_envelope_is_checked_before_removed_keys() {
    // Removed keys belong to a format, so they are looked for only once the
    // envelope names the format; a document with an envelope refusal is not
    // decoded.
    let error = loader()
        .parse_str::<Example>(
            "apiVersion: old/v1\nkind: Old\nserver:\n  bind: x\n",
            env(&[]),
        )
        .expect_err("envelope first");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::Envelope);
    assert!(error
        .diagnostics()
        .iter()
        .all(|diagnostic| diagnostic.code != "config.removed-key"));
}

#[test]
fn a_listener_address_or_secret_reference_refusal_keeps_its_own_wording() {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    #[allow(dead_code)]
    struct Shared {
        api_version: String,
        kind: String,
        listener: crate::ListenerConfig,
        key_ref: crate::SecretReference,
    }
    let document = |bind: &str, reference: &str| {
        format!(
            "{}listener:\n  bind: {bind}\nkeyRef: {reference}\n",
            header()
        )
    };
    loader()
        .parse_str::<Shared>(&document("127.0.0.1:8080", "secret:file/key"), env(&[]))
        .expect("a valid address and reference load");

    let error = loader()
        .parse_str::<Shared>(
            &document("canary-host.internal:8080", "secret:file/key"),
            env(&[]),
        )
        .expect_err("a host name is not an IP address");
    let deciding = error.deciding_diagnostic();
    assert_eq!(deciding.code, "config.invalid-value");
    assert_eq!(deciding.path, "/listener/bind");
    assert!(
        deciding
            .message
            .contains("host:port with an IP address host"),
        "{deciding:?}"
    );
    assert!(!error.to_string().contains("canary-host"), "{error}");

    let error = loader()
        .parse_str::<Shared>(&document("127.0.0.1:8080", "canary-literal"), env(&[]))
        .expect_err("a literal is not a reference");
    let deciding = error.deciding_diagnostic();
    assert_eq!(deciding.code, "config.invalid-value");
    assert_eq!(deciding.path, "/keyRef");
    assert!(
        deciding
            .message
            .contains("secret:env/NAME or secret:file/name"),
        "{deciding:?}"
    );
    assert!(!error.to_string().contains("canary-literal"), "{error}");
}

#[test]
fn the_deciding_diagnostic_is_the_one_the_kind_and_field_come_from() {
    // An unknown key and a removed key: the removed key decides, so a
    // consumer can classify the refusal by the code of that one diagnostic.
    let error = loader()
        .parse_str::<Example>(
            &format!("{}bogus: x\nserver:\n  bind: x\n", header()),
            env(&[]),
        )
        .expect_err("removed key");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::RemovedKey);
    assert!(error
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "config.unknown-key"));
    let deciding = error.deciding_diagnostic();
    assert_eq!(deciding.code, "config.removed-key");
    assert_eq!(deciding.path, "/server/bind");
    assert_eq!(error.field(), "server.bind");

    let error = loader()
        .parse_str::<Example>(&format!("{}count: many\n", header()), env(&[]))
        .expect_err("wrong type");
    assert_eq!(error.deciding_diagnostic().code, "config.expected-integer");
    assert_eq!(error.deciding_diagnostic().path, "/count");
}

#[test]
fn the_envelope_must_be_literal() {
    for text in [
        "kind: ExampleRuntimeConfig\n".to_owned(),
        format!("apiVersion: {}\nkind: Other\n", ENVELOPE.api_version),
        format!("apiVersion: ${{API}}\nkind: {}\n", ENVELOPE.kind),
    ] {
        let error = loader()
            .parse_str::<Example>(&text, env(&[("API", ENVELOPE.api_version)]))
            .expect_err("envelope refuses");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::Envelope, "{text}");
    }
}

#[test]
fn an_envelope_refusal_names_the_member_at_fault_as_its_field() {
    // The reader reports a missing member at the mapping that lacks it, so
    // the diagnostic points at the root; the loader's field still names the
    // member, apiVersion first, as consumers match on it.
    for (text, field) in [
        (format!("kind: {}\n", ENVELOPE.kind), "apiVersion"),
        (format!("apiVersion: {}\n", ENVELOPE.api_version), "kind"),
        ("name: x\n".to_owned(), "apiVersion"),
        (
            format!("apiVersion: other/v1\nkind: {}\n", ENVELOPE.kind),
            "apiVersion",
        ),
        (
            format!("apiVersion: {}\nkind: Other\n", ENVELOPE.api_version),
            "kind",
        ),
    ] {
        let error = parse(&text).expect_err("envelope refuses");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::Envelope, "{text}");
        assert_eq!(error.field(), field, "{text}");
    }
    let missing = parse(&format!("kind: {}\n", ENVELOPE.kind)).expect_err("refuses");
    assert_eq!(missing.diagnostics()[0].code, "config.missing-envelope");
    assert_eq!(missing.diagnostics()[0].path, "");
}

#[test]
fn a_refusal_is_small_enough_for_the_products_to_carry_in_their_errors() {
    // Products wrap the refusal in their own error enums, which clippy's
    // result_large_err holds under 128 bytes.
    assert!(std::mem::size_of::<RuntimeConfigError>() <= 16);
}

#[test]
fn the_document_must_be_one_mapping_with_string_keys_and_no_tags() {
    for text in [
        format!("{}name: [unterminated\n", header()),
        format!("{}---\n{}", header(), header()),
        "- a\n- b\n".to_owned(),
        format!("{}1: x\n", header()),
        format!("{}name: !custom x\n", header()),
        format!("{}name: a\nname: b\n", header()),
    ] {
        let error = parse(&text).expect_err("syntax refuses");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::Syntax, "{text}");
    }
}

#[test]
fn a_typed_refusal_names_the_field_without_the_value() {
    let error = parse(&format!(
        "{}count: DO_NOT_DISCLOSE_RUNTIME_VALUE\n",
        header()
    ))
    .expect_err("type refuses");
    assert_eq!(error.field(), "count");
    assert!(!error.to_string().contains("DO_NOT_DISCLOSE"), "{error}");
}

#[test]
fn a_substitution_refusal_never_echoes_a_value() {
    let error = loader()
        .parse_str::<Example>(
            &format!("{}count: ${{SECRETISH}}\n", header()),
            env(&[("SECRETISH", "DO_NOT_DISCLOSE_RUNTIME_VALUE")]),
        )
        .expect_err("typed refusal after substitution");
    assert!(!error.to_string().contains("DO_NOT_DISCLOSE"), "{error}");
}

#[test]
fn no_refusal_echoes_an_invalid_name_or_an_unknown_variant() {
    let error = parse(&format!("{}name: \"${{DO_NOT DISCLOSE}}\"\n", header()))
        .expect_err("invalid name refuses");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::Substitution);
    assert!(!error.to_string().contains("DISCLOSE"), "{error}");

    let error = parse(&format!("{}mode: DO_NOT_DISCLOSE\n", header()))
        .expect_err("unknown variant refuses");
    assert_eq!(error.field(), "mode");
    assert_eq!(error.diagnostics()[0].code, "config.unknown-variant");
    assert!(error.message().contains("strict"), "{error}");
    assert!(!error.to_string().contains("DISCLOSE"), "{error}");

    let error = loader()
        .parse_str::<Example>(
            &format!("{}mode: ${{MODE}}\n", header()),
            env(&[("MODE", "DO_NOT_DISCLOSE")]),
        )
        .expect_err("a substituted unknown variant refuses");
    assert!(!error.to_string().contains("DISCLOSE"), "{error}");
}

#[test]
fn substitution_is_refused_under_secret_providers() {
    // A provider setting chooses which secret a reference resolves to, so the
    // environment may not redirect it any more than it may rewrite a reference.
    for (text, field) in [
        (
            "secretProviders:\n  file:\n    root: \"${NAME}\"\n",
            "secretProviders.file.root",
        ),
        (
            "secretProviders:\n  file:\n    root: \"/run/${NAME}/secrets\"\n",
            "secretProviders.file.root",
        ),
        (
            "secretProviders:\n  env:\n    prefix: \"${MISSING:-X}\"\n",
            "secretProviders.env.prefix",
        ),
    ] {
        let error = parse(&format!("{}{text}", header())).expect_err("provider refuses");
        assert_eq!(
            error.kind(),
            RuntimeConfigErrorKind::SubstitutionInReference,
            "{text}"
        );
        assert_eq!(error.field(), field);
        assert!(error.message().contains("secret provider"), "{error}");
    }
    let loaded = parse(&format!(
        "{}secretProviders:\n  file:\n    root: /run/secrets\n",
        header()
    ))
    .expect("a literal provider setting loads");
    assert!(loaded.config.secret_providers.is_some());
}

#[test]
fn the_effective_digest_ignores_layout_and_comments() {
    let compact = parse(&format!("{}name: north\n", header())).expect("loads");
    let spaced = parse(&format!(
        "# operator note\n{}\nname:   \"${{NAME}}\"\n",
        header()
    ))
    .expect("loads");
    assert_eq!(compact.effective_digest, spaced.effective_digest);
    assert!(compact.effective_digest.starts_with("sha256:"));
    let other = parse(&format!("{}name: south\n", header())).expect("loads");
    assert_ne!(compact.effective_digest, other.effective_digest);
}

#[test]
fn environment_expressions_are_detected_in_authored_yaml() {
    assert!(contains_environment_expression("${A}"));
    assert!(contains_environment_expression("x ${A_1:-y} z"));
    assert!(contains_environment_expression("${A:?m}"));
    assert!(!contains_environment_expression("$A"));
    assert!(!contains_environment_expression("${1A}"));
    assert!(!contains_environment_expression("${a b}"));
    assert!(!contains_environment_expression("cost: $5 {x}"));

    reject_environment_expressions_in_authored_yaml("a: plain\n# ${A}\n").expect("comment ok");
    let error = reject_environment_expressions_in_authored_yaml("a:\n  b: [x, \"${HOST}\"]\n")
        .expect_err("value refuses");
    assert_eq!(error.field(), "a.b.1");
    assert!(error.message().contains("runtime.yaml only"));
    let error = reject_environment_expressions_in_authored_yaml("\"${HOST}\": x\n")
        .expect_err("key refuses");
    assert_eq!(error.field(), "${HOST}");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::AuthoredExpression);
    assert_eq!(error.code(), "authored_config.environment_expression");
}

#[test]
fn the_authored_check_fails_closed_on_text_that_does_not_parse() {
    // An authored file the check cannot read is refused, never waved through
    // to a parser that might accept what this reader could not.
    for text in [
        "a: [unterminated ${HOST}\n",
        "a: b\n  c: d\n",
        "a: 1\na: 2\n",
    ] {
        let error =
            reject_environment_expressions_in_authored_yaml(text).expect_err("unparsed refuses");
        assert_eq!(
            error.kind(),
            RuntimeConfigErrorKind::AuthoredSyntax,
            "{text}"
        );
        assert_eq!(error.code(), "authored_config.syntax");
        assert!(!error.message().contains("HOST"), "{error}");
    }
}

mod files {
    use super::*;

    fn directory() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical tempdir");
        (directory, root)
    }

    #[test]
    fn a_file_loads_and_errors_name_the_file() {
        let (_guard, root) = directory();
        let path = root.join("runtime.yaml");
        std::fs::write(&path, format!("{}name: ${{MISSING}}\n", header())).unwrap();
        let error = loader()
            .load_with::<Example>(&path, env(&[]))
            .expect_err("unset refuses");
        assert_eq!(error.file(), Some(path.as_path()));
        let source = error.diagnostics()[0].source.as_ref().expect("source");
        assert_eq!(source.file, path.display().to_string());
        assert_eq!((source.line, source.column), (Some(3), Some(7)));
        assert!(error.to_string().starts_with(&format!(
            "error[config.substitution] {}:3:7 /name\n",
            path.display()
        )));

        std::fs::write(&path, format!("{}name: x\n", header())).unwrap();
        let loaded = loader()
            .load_with::<Example>(&path, env(&[]))
            .expect("loads");
        assert_eq!(loaded.config.name.as_deref(), Some("x"));
    }

    #[test]
    fn cfg_diag_3_a_file_refusal_carries_a_platform_code_and_a_fix() {
        let (_guard, root) = directory();
        let empty = root.join("empty.yaml");
        std::fs::write(&empty, "").unwrap();
        for (path, code) in [
            (
                PathBuf::from("runtime.yaml"),
                "platform.runtime-config.path",
            ),
            (root.clone(), "platform.runtime-config.unsafe-file"),
            (
                root.join("absent.yaml"),
                "platform.runtime-config.unavailable",
            ),
            (empty, "platform.runtime-config.size"),
        ] {
            let error = loader()
                .load_with::<Example>(&path, env(&[]))
                .expect_err("file refuses");
            assert_eq!(error.field(), "/");
            let [diagnostic] = error.diagnostics() else {
                panic!("one diagnostic: {error}");
            };
            assert_eq!(diagnostic.code, code);
            assert!(!diagnostic.suggested_action.is_empty());
            let source = diagnostic.source.as_ref().expect("source");
            assert_eq!(source.file, path.display().to_string());
            assert_eq!((source.line, source.column), (None, None));
            assert!(error
                .to_string()
                .starts_with(&format!("error[{code}] {}\n", path.display())));
            assert!(error.message().contains("; next: "), "{error}");
        }
    }

    #[test]
    fn a_relative_or_unnormal_path_is_refused() {
        let (_guard, root) = directory();
        for path in [
            PathBuf::from("runtime.yaml"),
            root.join(".").join("runtime.yaml"),
            root.join("..").join("runtime.yaml"),
        ] {
            let error = loader()
                .load_with::<Example>(&path, env(&[]))
                .expect_err("path refuses");
            assert_eq!(error.kind(), RuntimeConfigErrorKind::Path, "{path:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_anywhere_in_the_path_is_refused() {
        let (_guard, root) = directory();
        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("runtime.yaml"), header()).unwrap();
        std::os::unix::fs::symlink(&real, root.join("linked-dir")).unwrap();
        std::os::unix::fs::symlink(real.join("runtime.yaml"), root.join("linked.yaml")).unwrap();
        for path in [
            root.join("linked-dir").join("runtime.yaml"),
            root.join("linked.yaml"),
        ] {
            let error = loader()
                .load_with::<Example>(&path, env(&[]))
                .expect_err("symlink refuses");
            assert_eq!(error.kind(), RuntimeConfigErrorKind::UnsafeFile, "{path:?}");
        }
    }

    #[test]
    fn a_directory_missing_file_empty_file_or_oversized_file_is_refused() {
        let (_guard, root) = directory();
        let error = loader()
            .load_with::<Example>(&root, env(&[]))
            .expect_err("directory refuses");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::UnsafeFile);

        let error = loader()
            .load_with::<Example>(&root.join("absent.yaml"), env(&[]))
            .expect_err("absent refuses");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::Unavailable);

        let empty = root.join("empty.yaml");
        std::fs::write(&empty, "").unwrap();
        let error = loader()
            .load_with::<Example>(&empty, env(&[]))
            .expect_err("empty refuses");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::Bounds);

        let large = root.join("large.yaml");
        std::fs::write(&large, format!("{}name: {}\n", header(), "x".repeat(200))).unwrap();
        let error = loader()
            .max_bytes(128)
            .load_with::<Example>(&large, env(&[]))
            .expect_err("oversized refuses");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::Bounds);
        assert_eq!(error.code(), "runtime_config.bounds");
    }

    #[test]
    fn a_file_that_is_not_utf8_is_refused() {
        let (_guard, root) = directory();
        let path = root.join("runtime.yaml");
        std::fs::write(&path, b"apiVersion: \xff\n").unwrap();
        let error = loader()
            .load_with::<Example>(&path, env(&[]))
            .expect_err("encoding refuses");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::Encoding);
    }

    #[cfg(unix)]
    #[test]
    fn trusted_ownership_refuses_a_file_writable_by_others() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_guard, root) = directory();
        let path = root.join("runtime.yaml");
        std::fs::write(&path, header()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        loader()
            .require_trusted_ownership()
            .load_with::<Example>(&path, env(&[]))
            .expect("owner-only file loads");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let error = loader()
            .require_trusted_ownership()
            .load_with::<Example>(&path, env(&[]))
            .expect_err("world-writable refuses");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::UnsafeFile);
        loader()
            .load_with::<Example>(&path, env(&[]))
            .expect("the ownership rule is opt-in");
    }
}

#[test]
fn the_shared_removed_jwks_uri_key_names_jwks_source() {
    let loader = RuntimeConfigLoader::new(ENVELOPE)
        .removed_keys(std::slice::from_ref(&REMOVED_OIDC_JWKS_URI));
    let error = loader
        .parse_str::<serde_json::Value>(
            &format!(
                "{}authentication:\n  oidc:\n    jwksUri: https://issuer.example.test/jwks\n",
                header()
            ),
            env(&[]),
        )
        .unwrap_err();
    assert_eq!(error.kind(), RuntimeConfigErrorKind::RemovedKey);
    assert_eq!(error.field(), "authentication.oidc.jwksUri");
    assert!(error.to_string().contains("authentication.oidc.jwksSource"));
    assert!(!error.to_string().contains("issuer.example.test"));
}

/// The code, line and column of the first diagnostic.
fn located(error: &RuntimeConfigError) -> (&str, Option<usize>, Option<usize>) {
    let diagnostic = &error.diagnostics()[0];
    let source = diagnostic
        .source
        .as_ref()
        .expect("a reader diagnostic has a source");
    (diagnostic.code.as_str(), source.line, source.column)
}

fn has_code(error: &RuntimeConfigError, code: &str) -> bool {
    error
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == code)
}

#[test]
fn cfg_sec_2_a_key_is_never_substituted() {
    for (text, field) in [
        ("\"${NAME}\": x\n", "${NAME}"),
        ("audit:\n  \"x${NAME:-y}\": a\n", "audit.x${NAME:-y}"),
    ] {
        let error = parse(&format!("{}{text}", header())).expect_err("key refuses");
        assert_eq!(
            error.kind(),
            RuntimeConfigErrorKind::SubstitutionInReference,
            "{text}"
        );
        assert_eq!(error.field(), field);
        assert_eq!(
            error.diagnostics()[0].code,
            "config.substitution-not-allowed"
        );
        assert!(
            error
                .message()
                .contains("a key is never filled by substitution"),
            "{error}"
        );
    }
}

#[test]
fn cfg_sec_2_api_version_and_kind_are_never_substituted() {
    let lookup = || env(&[("API", ENVELOPE.api_version), ("KIND", ENVELOPE.kind)]);
    for (text, member) in [
        (
            format!("apiVersion: ${{API}}\nkind: {}\n", ENVELOPE.kind),
            "apiVersion",
        ),
        (
            format!(
                "apiVersion: {}\nkind: \"${{KIND}}\"\n",
                ENVELOPE.api_version
            ),
            "kind",
        ),
    ] {
        let error = loader()
            .parse_str::<Example>(&text, lookup())
            .expect_err("envelope refuses");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::Envelope, "{text}");
        assert_eq!(error.field(), member);
        assert!(
            has_code(&error, "config.substitution-not-allowed"),
            "{error}"
        );
        assert!(
            error.message().contains("is never filled by substitution"),
            "{error}"
        );
    }

    // A member named `kind` below the root is an ordinary string value.
    let loaded = parse(&format!(
        "{}sources:\n  people:\n    kind: \"${{NAME}}\"\n",
        header()
    ))
    .expect("a nested kind substitutes");
    assert_eq!(loaded.config.sources["people"]["kind"], "north");
}

#[test]
fn cfg_sec_2_a_ref_member_is_never_substituted() {
    let error = parse(&format!(
        "{}audit:\n  hashKeyRef: \"${{NAME}}\"\n",
        header()
    ))
    .expect_err("reference refuses");
    assert_eq!(
        error.kind(),
        RuntimeConfigErrorKind::SubstitutionInReference
    );
    assert_eq!(error.field(), "audit.hashKeyRef");
    assert_eq!(
        located(&error),
        ("config.substitution-not-allowed", Some(4), Some(15))
    );
    assert!(error.message().contains("`hashKeyRef`"), "{error}");
    assert!(error.message().contains("secret:env/NAME"), "{error}");
    assert!(!error.to_string().contains("north"), "{error}");
}

#[test]
fn cfg_sec_2_a_refs_member_and_everything_below_it_is_never_substituted() {
    for (text, field, key) in [
        (
            "audit:\n  allowedKeyRefs: [\"secret:file/a\", \"${NAME}\"]\n",
            "audit.allowedKeyRefs.1",
            "`allowedKeyRefs`",
        ),
        (
            "sources:\n  credentialRefs:\n    primary: \"${NAME}\"\n",
            "sources.credentialRefs.primary",
            "`credentialRefs`",
        ),
    ] {
        let error = parse(&format!("{}{text}", header())).expect_err("references refuse");
        assert_eq!(
            error.kind(),
            RuntimeConfigErrorKind::SubstitutionInReference,
            "{text}"
        );
        assert_eq!(error.field(), field);
        assert_eq!(
            error.diagnostics()[0].code,
            "config.substitution-not-allowed"
        );
        assert!(error.message().contains(key), "{error}");
    }
}

#[test]
fn cfg_sec_2_nothing_under_secret_providers_is_substituted() {
    let error = parse(&format!(
        "{}secretProviders:\n  file:\n    root: \"${{NAME}}\"\n",
        header()
    ))
    .expect_err("provider setting refuses");
    assert_eq!(
        error.kind(),
        RuntimeConfigErrorKind::SubstitutionInReference
    );
    assert_eq!(error.field(), "secretProviders.file.root");
    let diagnostic = &error.diagnostics()[0];
    assert_eq!(diagnostic.code, "config.substitution-not-allowed");
    assert_eq!(
        diagnostic.message,
        "a secret provider setting is never filled by substitution"
    );
    assert_eq!(
        diagnostic.suggested_action,
        "Write the setting in runtime.yaml as plain text."
    );
}

#[test]
fn cfg_sec_2_an_unset_or_empty_variable_is_refused_naming_only_the_variable() {
    for text in ["name: ${MISSING}\n", "name: \"${EMPTY}\"\n"] {
        let error = parse(&format!("{}{text}", header())).expect_err("unset refuses");
        let diagnostic = &error.diagnostics()[0];
        assert_eq!(diagnostic.code, "config.substitution");
        assert!(diagnostic.message.ends_with("is unset or empty"), "{error}");
        assert!(
            diagnostic.suggested_action.contains(":-fallback"),
            "{error}"
        );
    }

    // `${NAME:?}` with no message has nothing to withhold.
    let error =
        parse(&format!("{}name: \"${{MISSING:?}}\"\n", header())).expect_err("required refuses");
    assert_eq!(
        error.diagnostics()[0].message,
        "the environment variable MISSING is unset or empty"
    );
}

#[test]
fn cfg_sec_2_a_required_message_is_withheld() {
    let error = parse(&format!(
        "{}name: \"${{MISSING:?DO_NOT_DISCLOSE the counter}}\"\n",
        header()
    ))
    .expect_err("required refuses");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::Substitution);
    assert_eq!(
        error.diagnostics()[0].message,
        "the environment variable MISSING is unset or empty; the message written for it is \
         withheld"
    );
    assert!(!error.to_string().contains("DO_NOT_DISCLOSE"), "{error}");
}

#[test]
fn cfg_sec_2_a_nul_byte_is_refused_by_the_variable_name() {
    let error = loader()
        .parse_str::<Example>(
            &format!("{}name: ${{NULLED}}\n", header()),
            env(&[("NULLED", "DO_NOT_DISCLOSE\0b")]),
        )
        .expect_err("NUL refuses");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::Substitution);
    assert_eq!(
        error.diagnostics()[0].message,
        "the environment variable NULLED holds a NUL byte"
    );
    assert!(!error.to_string().contains("DO_NOT_DISCLOSE"), "{error}");
}

#[test]
fn cfg_sec_2_a_malformed_expression_is_refused_without_repeating_it() {
    for text in [
        "name: \"${NAME\"\n",
        "name: \"${NAME:-unterminated\"\n",
        "name: \"${1DO_NOT_DISCLOSE}\"\n",
        "name: \"${}\"\n",
        "name: \"${DO_NOT DISCLOSE}\"\n",
    ] {
        let error = parse(&format!("{}{text}", header())).expect_err("malformed refuses");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::Substitution, "{text}");
        let diagnostic = &error.diagnostics()[0];
        assert_eq!(diagnostic.code, "config.substitution", "{text}");
        assert_eq!(
            diagnostic.message, "the `${...}` expression is not well formed",
            "{text}"
        );
        assert!(!error.to_string().contains("DISCLOSE"), "{error}");
    }
}

#[test]
fn cfg_sec_2_text_that_is_not_an_expression_is_accepted() {
    for value in [
        "cost ${ x",
        "a${-b}",
        "trailing ${",
        "${{x}}",
        "$NAME",
        "${",
    ] {
        let loaded = parse(&format!("{}name: \"{value}\"\n", header()))
            .unwrap_or_else(|error| panic!("{value}: {error}"));
        assert_eq!(loaded.config.name.as_deref(), Some(value));
        reject_environment_expressions_in_authored_yaml(&format!(
            "title: \"{value}\"\n\"{value}\": x\n"
        ))
        .unwrap_or_else(|error| panic!("{value}: {error}"));
    }
}

#[test]
fn cfg_sec_2_an_authored_expression_is_refused_with_the_remedy() {
    let error = reject_environment_expressions_in_authored_yaml("title: x\nhost: \"${HOST:-a}\"\n")
        .expect_err("authored expression refuses");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::AuthoredExpression);
    assert_eq!(error.field(), "host");
    assert_eq!(
        located(&error),
        ("config.substitution-not-allowed", Some(2), Some(7))
    );
    let diagnostic = &error.diagnostics()[0];
    assert!(diagnostic.message.contains("runtime.yaml only"), "{error}");
    assert_eq!(
        diagnostic.suggested_action,
        "Write the value in the authored file directly."
    );
    assert!(!error.to_string().contains("HOST"), "{error}");
}

#[test]
fn cfg_sec_2_a_diagnostic_on_a_substituted_value_points_at_the_expression() {
    // The value is filled in place in the node the reader built, so a
    // refusal of what it was filled with points at the expression as written.
    let error = loader()
        .parse_str::<Example>(
            &format!("{}name: x\nmode: \"${{MODE}}\"\n", header()),
            env(&[("MODE", "DO_NOT_DISCLOSE")]),
        )
        .expect_err("unknown variant refuses");
    assert_eq!(
        located(&error),
        ("config.unknown-variant", Some(4), Some(7))
    );
    assert_eq!(
        error.diagnostics()[0]
            .source
            .as_ref()
            .map(|source| source.file.as_str()),
        Some("runtime.yaml")
    );

    // A value much longer than its expression moves nothing after it.
    let error = loader()
        .parse_str::<Example>(
            &format!(
                "{}list:\n  - \"${{LONG}}${{LONG}}\"\n  - plain\ncount: \"${{LONG}}\"\n",
                header()
            ),
            env(&[("LONG", "a much longer value\nwith a line break")]),
        )
        .expect_err("text is not a count");
    assert_eq!(
        located(&error),
        ("config.expected-integer", Some(6), Some(8))
    );

    // A refusal by the substitution itself points at the expression too.
    let error =
        parse(&format!("{}name: x\nflag:   ${{MISSING}}\n", header())).expect_err("unset refuses");
    assert_eq!(located(&error), ("config.substitution", Some(4), Some(9)));
}

#[test]
fn cfg_val_3_a_substituted_value_never_fills_an_integer_or_boolean() {
    for (text, field, code, column) in [
        ("count: ${COUNT}\n", "count", "config.expected-integer", 8),
        (
            "enabled: ${ENABLED}\n",
            "enabled",
            "config.expected-boolean",
            10,
        ),
    ] {
        let error = loader()
            .parse_str::<Example>(
                &format!("{}{text}", header()),
                env(&[("COUNT", "3"), ("ENABLED", "true")]),
            )
            .expect_err("a substituted value is text");
        assert_eq!(error.kind(), RuntimeConfigErrorKind::InvalidValue, "{text}");
        assert_eq!(error.field(), field);
        assert_eq!(located(&error), (code, Some(3), Some(column)));
    }

    let loaded =
        parse(&format!("{}count: 3\nenabled: true\n", header())).expect("written values fill them");
    assert_eq!(loaded.config.count, Some(3));
    assert_eq!(loaded.config.enabled, Some(true));
}

#[test]
fn cfg_diag_2_display_renders_every_diagnostic_in_the_human_form() {
    let error = parse(&format!(
        "{}nmae: x\ncolour: y\nsources:\n  people:\n    file: /data/people.sqlite\n",
        header()
    ))
    .expect_err("unknown and removed keys refuse");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::RemovedKey);
    assert_eq!(error.field(), "sources.people.file");
    let mut codes: Vec<&str> = error
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect();
    codes.sort_unstable();
    assert_eq!(
        codes,
        [
            "config.removed-key",
            "config.unknown-key",
            "config.unknown-key"
        ]
    );
    let rendered = error.to_string();
    assert_eq!(rendered.matches("error[").count(), 3, "{rendered}");
    for diagnostic in error.diagnostics() {
        assert!(
            rendered.contains(diagnostic.render_human().trim_end()),
            "{rendered}"
        );
    }
    assert!(!rendered.ends_with('\n'));
}

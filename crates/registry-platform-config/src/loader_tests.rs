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
    list: Vec<String>,
    #[serde(default)]
    audit: Option<Audit>,
    #[serde(default)]
    sources: BTreeMap<String, BTreeMap<String, String>>,
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
    // refuse the document; a key is never substituted either, so the typed
    // configuration refuses it as an unknown field rather than resolving it.
    let loaded = parse(&format!("{}# ${{UNSET_IN_COMMENT}}\nname: x\n", header()))
        .expect("comment is not substituted");
    assert_eq!(loaded.config.name.as_deref(), Some("x"));

    let error = parse(&format!("{}\"${{NAME}}\": x\n", header())).expect_err("key stays literal");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::InvalidValue);
    assert!(error.message().contains("${NAME}"), "{error}");
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
    assert!(error.message().contains("set MISSING to the counter name"));
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
        "server.bind is no longer accepted; use listener.bind"
    );

    let error = parse(&format!(
        "{}sources:\n  people:\n    file: /data/people.sqlite\n",
        header()
    ))
    .expect_err("wildcard removed key refuses");
    assert_eq!(error.field(), "sources.people.file");
    assert!(error.message().contains("sources.<id>.path"));
}

#[test]
fn removed_keys_are_reported_before_the_envelope() {
    let error = loader()
        .parse_str::<Example>(
            "apiVersion: old/v1\nkind: Old\nserver:\n  bind: x\n",
            env(&[]),
        )
        .expect_err("removed key first");
    assert_eq!(error.kind(), RuntimeConfigErrorKind::RemovedKey);
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
        assert!(error.to_string().starts_with(&path.display().to_string()));

        std::fs::write(&path, format!("{}name: x\n", header())).unwrap();
        let loaded = loader()
            .load_with::<Example>(&path, env(&[]))
            .expect("loads");
        assert_eq!(loaded.config.name.as_deref(), Some("x"));
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

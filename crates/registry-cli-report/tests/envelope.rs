// SPDX-License-Identifier: Apache-2.0

use registry_cli_report::{json_requested, ExplicitSettingLine, Report, Status};
use registry_platform_posture::{DeclaredPosture, Posture, PostureSource};
use serde_json::{json, Value};

fn members() -> Value {
    json!({"ok":true,"command":"check","status":"complete","apiVersion":"format/v1","kind":"CtlReport","filesChecked":2})
}

#[test]
fn every_report_has_the_same_order_diagnostics_and_binary_version() {
    let value = members();
    let rendered = serde_json::to_string(&Report::new(&value, "1.0.0-dev").unwrap()).unwrap();
    assert!(
        rendered.starts_with(concat!(
            r#"{"ok":true,"command":"check","status":"complete","#,
            r#""apiVersion":"format/v1","kind":"CtlReport","#
        )),
        "{rendered}"
    );
    let report: Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(report["diagnostics"], json!([]));
    assert_eq!(report["version"], "1.0.0-dev");
    assert_eq!(report["filesChecked"], 2);
    assert!(report.get("data").is_none());
}

#[test]
fn command_words_are_outcomes_and_status_follows_the_exit_class() {
    for (ok, word, expected) in [
        (true, "declined", "complete"),
        (false, "failed", "domain-refusal"),
    ] {
        let mut value = members();
        value["ok"] = json!(ok);
        value["status"] = json!(word);
        value["diagnostics"] = if ok {
            json!([])
        } else {
            json!([{"code":"ctl.refused"}])
        };
        let report = serde_json::to_value(Report::new(&value, "1.0.0").unwrap()).unwrap();
        assert_eq!(report["status"], expected);
        assert_eq!(report["outcome"], word);
    }
    for (exit, expected) in [
        (0, "complete"),
        (1, "domain-refusal"),
        (2, "usage-error"),
        (3, "operational-failure"),
    ] {
        assert_eq!(Status::from_exit(exit).as_str(), expected);
    }
}

#[test]
fn a_malformed_envelope_is_an_explicit_programming_error() {
    for key in ["ok", "command", "apiVersion", "kind"] {
        let mut value = members();
        value.as_object_mut().unwrap().remove(key);
        assert!(Report::new(&value, "1.0.0").is_err(), "{key}");
    }
    let mut value = members();
    value["diagnostics"] = json!({});
    assert!(Report::new(&value, "1.0.0").is_err());
    value["diagnostics"] = json!([]);
    value["status"] = json!("usage-error");
    assert!(Report::new(&value, "1.0.0").is_err());
}

#[test]
fn panic_output_selection_understands_both_format_spellings_and_the_terminator() {
    for args in [
        vec!["ctl", "--format", "json"],
        vec!["ctl", "--format=json"],
        vec!["ctl", "--json"],
    ] {
        assert!(json_requested(
            args.into_iter().map(std::ffi::OsString::from)
        ));
    }
    for args in [
        vec!["ctl", "--format", "human"],
        vec!["ctl", "--", "--format=json"],
        vec!["ctl", "--output=json"],
    ] {
        assert!(!json_requested(
            args.into_iter().map(std::ffi::OsString::from)
        ));
    }
}

fn declared(posture: Posture, source: PostureSource) -> DeclaredPosture {
    DeclaredPosture { posture, source }
}

#[test]
fn a_report_without_posture_is_unchanged() {
    let value = members();
    let rendered = serde_json::to_string(&Report::new(&value, "1.0.0-dev").unwrap()).unwrap();
    assert_eq!(
        rendered,
        concat!(
            r#"{"ok":true,"command":"check","status":"complete","#,
            r#""apiVersion":"format/v1","kind":"CtlReport","version":"1.0.0-dev","#,
            r#""filesChecked":2,"diagnostics":[]}"#
        )
    );
}

#[test]
fn with_posture_adds_value_and_source_after_the_command_members() {
    let value = members();
    let report = Report::new(&value, "1.0.0-dev")
        .unwrap()
        .with_posture(declared(Posture::Production, PostureSource::Default));
    let rendered = serde_json::to_string(&report).unwrap();
    assert_eq!(
        rendered,
        concat!(
            r#"{"ok":true,"command":"check","status":"complete","#,
            r#""apiVersion":"format/v1","kind":"CtlReport","version":"1.0.0-dev","#,
            r#""filesChecked":2,"posture":{"value":"production","source":"default"},"#,
            r#""diagnostics":[]}"#
        )
    );
}

#[test]
fn posture_value_and_source_use_the_documented_spellings() {
    for (posture, value) in [
        (Posture::Development, "development"),
        (Posture::Production, "production"),
    ] {
        for (source, word) in [
            (PostureSource::Flag, "flag"),
            (PostureSource::Environment, "environment"),
            (PostureSource::Default, "default"),
        ] {
            let envelope = members();
            let report = serde_json::to_value(
                Report::new(&envelope, "1.0.0")
                    .unwrap()
                    .with_posture(declared(posture, source)),
            )
            .unwrap();
            assert_eq!(report["posture"], json!({"value": value, "source": word}));
        }
    }
}

#[test]
fn the_declared_posture_replaces_a_command_member_of_the_same_name() {
    let mut envelope = members();
    envelope["posture"] = json!("free text");
    let rendered = serde_json::to_string(
        &Report::new(&envelope, "1.0.0")
            .unwrap()
            .with_posture(declared(Posture::Development, PostureSource::Flag)),
    )
    .unwrap();
    assert_eq!(rendered.matches("\"posture\"").count(), 1, "{rendered}");
    let report: Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(
        report["posture"],
        json!({"value": "development", "source": "flag"})
    );
}

fn explicit_line(pointer: &str, line: Option<usize>) -> ExplicitSettingLine {
    ExplicitSettingLine {
        code: "platform.posture.jwt-access-token".to_owned(),
        file: None,
        pointer: Some(pointer.to_owned()),
        line,
        column: line.map(|_| 7),
        summary: "admits access tokens typed JWT. ID tokens stay refused".to_owned(),
    }
}

#[test]
fn explicit_settings_follow_the_posture_as_their_own_list_and_never_as_a_diagnostic() {
    let value = members();
    let report = Report::new(&value, "1.0.0-dev")
        .unwrap()
        .with_posture(declared(Posture::Production, PostureSource::Default))
        .explicit_settings(vec![
            explicit_line(
                "/authentication/oidc/issuers/staff/accessTokenType",
                Some(12),
            ),
            explicit_line(
                "/authentication/oidc/issuers/partners/accessTokenType",
                None,
            ),
        ]);
    let rendered = serde_json::to_value(&report).unwrap();
    assert_eq!(rendered["diagnostics"], json!([]));
    assert_eq!(
        rendered["explicitProductionSettings"],
        json!([
            {
                "code": "platform.posture.jwt-access-token",
                "pointer": "/authentication/oidc/issuers/staff/accessTokenType",
                "line": 12,
                "column": 7,
                "summary": "admits access tokens typed JWT. ID tokens stay refused"
            },
            {
                "code": "platform.posture.jwt-access-token",
                "pointer": "/authentication/oidc/issuers/partners/accessTokenType",
                "summary": "admits access tokens typed JWT. ID tokens stay refused"
            }
        ])
    );
    let text = serde_json::to_string(&report).unwrap();
    let posture = text.find(r#""posture""#).unwrap();
    let explicit = text.find(r#""explicitProductionSettings""#).unwrap();
    let diagnostics = text.find(r#""diagnostics""#).unwrap();
    assert!(posture < explicit && explicit < diagnostics, "{text}");
}

#[test]
fn an_explicit_setting_line_names_its_file_and_leaves_out_an_unknown_pointer() {
    let value = members();
    let report = Report::new(&value, "1.0.0-dev")
        .unwrap()
        .explicit_settings(vec![
            ExplicitSettingLine {
                file: Some("package/registry.yaml".to_owned()),
                ..explicit_line("/oidc/issuers/staff/accessTokenType", Some(4))
            },
            ExplicitSettingLine {
                pointer: None,
                ..explicit_line("", None)
            },
        ]);
    let rendered = serde_json::to_value(&report).unwrap();
    assert_eq!(
        rendered["explicitProductionSettings"],
        json!([
            {
                "code": "platform.posture.jwt-access-token",
                "file": "package/registry.yaml",
                "pointer": "/oidc/issuers/staff/accessTokenType",
                "line": 4,
                "column": 7,
                "summary": "admits access tokens typed JWT. ID tokens stay refused"
            },
            {
                "code": "platform.posture.jwt-access-token",
                "summary": "admits access tokens typed JWT. ID tokens stay refused"
            }
        ])
    );
}

#[test]
fn a_report_that_names_no_explicit_list_is_unchanged() {
    let value = members();
    let rendered = serde_json::to_string(&Report::new(&value, "1.0.0-dev").unwrap()).unwrap();
    assert!(
        !rendered.contains("explicitProductionSettings"),
        "{rendered}"
    );
}

#[test]
fn an_empty_explicit_list_is_written_so_a_reader_can_tell_none_from_unreported() {
    let value = members();
    let report = Report::new(&value, "1.0.0-dev")
        .unwrap()
        .explicit_settings(Vec::new());
    let rendered = serde_json::to_value(&report).unwrap();
    assert_eq!(rendered["explicitProductionSettings"], json!([]));
}

#[test]
fn an_explicit_setting_becomes_the_report_line_for_its_file() {
    use registry_platform_config::{
        collect_posture_settings, ExplicitClass, ExplicitProductionSetting, FoundExplicitSetting,
        RuntimeConfigLoader, RuntimeEnvelope, Stated,
    };
    use serde::Deserialize;

    static LENIENT: ExplicitProductionSetting = ExplicitProductionSetting {
        code: "platform.posture.example-lenient",
        key: "format",
        summary: "admits a lenient format",
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    enum Format {
        Strict,
        Lenient,
    }

    impl ExplicitClass for Format {
        const SETTINGS: &'static [&'static ExplicitProductionSetting] = &[&LENIENT];

        fn explicit_setting(&self) -> Option<&'static ExplicitProductionSetting> {
            match self {
                Format::Strict => None,
                Format::Lenient => Some(&LENIENT),
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct Tokens {
        format: Stated<Format>,
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct StatedExample {
        direct: Tokens,
    }

    const ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
        api_version: "example/v1",
        kind: "ExampleRuntimeConfig",
    };

    let text = "apiVersion: example/v1\nkind: ExampleRuntimeConfig\ndirect:\n  format: lenient\n";
    let (result, collected) = collect_posture_settings(|| {
        RuntimeConfigLoader::new_without_posture(ENVELOPE)
            .parse_str::<StatedExample>(text, |_| None)
    });
    result.expect("an explicit setting never refuses");
    let found = &collected.explicit[0];
    let line = ExplicitSettingLine::from_found(found, Some("runtime.yaml"));
    assert_eq!(line.code, "platform.posture.example-lenient");
    assert_eq!(line.file.as_deref(), Some("runtime.yaml"));
    assert_eq!(line.pointer.as_deref(), Some("/direct/format"));
    assert_eq!(line.line, Some(4));
    assert_eq!(line.column, found.position.map(|position| position.column));
    assert!(line.column.is_some());
    assert_eq!(line.summary, found.setting.summary);
    let unplaced = FoundExplicitSetting {
        pointer: None,
        position: None,
        ..found.clone()
    };
    let line = ExplicitSettingLine::from_found(&unplaced, None);
    assert_eq!(
        (line.file, line.pointer, line.line, line.column),
        (None, None, None, None)
    );
}

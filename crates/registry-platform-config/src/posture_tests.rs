use super::*;
use crate::{RuntimeConfigLoader, RuntimeEnvelope};
use registry_platform_yaml::Severity;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

const ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: "registry.registrystack.org/example-runtime/v1alpha1",
    kind: "ExampleRuntimeConfig",
};

const HEAD: &str =
    "apiVersion: registry.registrystack.org/example-runtime/v1alpha1\nkind: ExampleRuntimeConfig\n";

static PLAINTEXT: DevelopmentSetting = DevelopmentSetting {
    code: "platform.posture.example-plaintext",
    key: "transport",
    summary: "The database connection is not encrypted",
    production: "Write transport: tls.",
};

static INSECURE: DevelopmentSetting = DevelopmentSetting {
    code: "platform.posture.example-insecure",
    key: "allow",
    summary: "The issuer is reached over plain HTTP",
    production: "Write allow: false.",
};

static COMBINATION: DevelopmentSetting = DevelopmentSetting {
    code: "evidence.posture.example-combination",
    key: "assuranceProfile",
    summary: "Development is declared with a production profile",
    production: "Write assuranceProfile: local.",
};

static UNRESTRICTED: ExplicitProductionSetting = ExplicitProductionSetting {
    code: "adapter.posture.example-unrestricted",
    key: "allowedClients",
    summary: "Every client is admitted, which the operator states deliberately",
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
enum Transport {
    Tls,
    Plaintext,
}

impl DevelopmentClass for Transport {
    const SETTINGS: &'static [&'static DevelopmentSetting] = &[&PLAINTEXT];

    fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
        match self {
            Transport::Tls => None,
            Transport::Plaintext => Some(&PLAINTEXT),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(transparent)]
struct Insecure(bool);

impl DevelopmentClass for Insecure {
    const SETTINGS: &'static [&'static DevelopmentSetting] = &[&INSECURE];

    fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
        self.0.then_some(&INSECURE)
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Database {
    transport: Gated<Transport>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Shared {
    allow: Gated<Insecure>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Issuer {
    #[serde(flatten)]
    shared: Shared,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
#[serde(rename_all = "camelCase")]
struct Example {
    database: Database,
    #[serde(default)]
    issuer: Option<Issuer>,
    #[serde(default)]
    replicas: Vec<Database>,
}

fn declared(posture: Posture) -> DeclaredPosture {
    DeclaredPosture {
        posture,
        source: PostureSource::Flag,
    }
}

fn load(body: &str) -> (Result<(), String>, Vec<FoundSetting>) {
    let text = format!("{HEAD}{body}");
    let (result, found) = collect_development_settings(|| {
        RuntimeConfigLoader::new_without_posture(ENVELOPE).parse_str::<Example>(&text, |_| None)
    });
    (result.map(|_| ()).map_err(|error| error.to_string()), found)
}

fn found(setting: &'static DevelopmentSetting, pointer: Option<&str>) -> FoundSetting {
    FoundSetting {
        setting,
        pointer: pointer.map(str::to_owned),
        position: Some(Position { line: 7, column: 5 }),
        origin: SettingOrigin::RuntimeFile,
    }
}

// Gated

#[test]
fn get_without_a_witness_refuses_a_development_value_and_with_one_returns_it() {
    let value = Gated::for_tests(Transport::Plaintext);
    let witness = DevelopmentWitness::issue();
    assert_eq!(
        value.get(None).unwrap_err(),
        DevelopmentOnlyRefused {
            setting: &PLAINTEXT
        }
    );
    assert_eq!(value.get(Some(&witness)).unwrap(), &Transport::Plaintext);
}

#[test]
fn get_returns_a_value_valid_everywhere_with_or_without_a_witness() {
    let value = Gated::everywhere(Transport::Tls).unwrap();
    let witness = DevelopmentWitness::issue();
    assert_eq!(value.get(None).unwrap(), &Transport::Tls);
    assert_eq!(value.get(Some(&witness)).unwrap(), &Transport::Tls);
    assert_eq!(value.development_setting(), None);
}

#[test]
fn everywhere_refuses_a_development_value() {
    let refused = Gated::everywhere(Transport::Plaintext).unwrap_err();
    assert_eq!(refused.setting.code, "platform.posture.example-plaintext");
    assert_eq!(
        refused.to_string(),
        "the setting platform.posture.example-plaintext is accepted only when the process declares development"
    );
}

#[test]
fn a_gated_value_serializes_as_its_inner_value_and_debug_delegates() {
    let value = Gated::for_tests(Transport::Plaintext);
    assert_eq!(serde_json::to_string(&value).unwrap(), "\"plaintext\"");
    assert_eq!(format!("{value:?}"), "Plaintext");
    assert_eq!(value.clone(), value);
    assert_ne!(value, Gated::for_tests(Transport::Tls));
}

#[test]
fn the_development_setting_names_what_a_value_selects() {
    assert_eq!(
        Gated::for_tests(Transport::Plaintext).development_setting(),
        Some(&PLAINTEXT)
    );
}

// Collecting

#[test]
fn a_decode_records_a_member_a_list_item_and_a_flattened_member() {
    let (result, found) = load(concat!(
        "database:\n  transport: plaintext\n",
        "issuer:\n  allow: true\n",
        "replicas:\n  - transport: tls\n  - transport: plaintext\n",
    ));
    assert_eq!(result, Ok(()), "a development value never fails the decode");
    let pointers: Vec<_> = found
        .iter()
        .map(|found| (found.setting.code, found.pointer.as_deref()))
        .collect();
    assert_eq!(
        pointers,
        [
            (
                "platform.posture.example-plaintext",
                Some("/database/transport")
            ),
            ("platform.posture.example-insecure", Some("/issuer/allow")),
            (
                "platform.posture.example-plaintext",
                Some("/replicas/1/transport")
            ),
        ]
    );
    assert!(found.iter().all(|found| found.position.is_some()));
    assert!(found
        .iter()
        .all(|found| found.origin == SettingOrigin::RuntimeFile));
}

#[test]
fn the_position_of_an_exact_site_is_the_value() {
    let (_, found) = load("database:\n  transport: plaintext\n");
    assert_eq!(
        found[0].position,
        Some(Position {
            line: 4,
            column: 14
        })
    );
}

#[test]
fn a_value_valid_in_every_posture_is_not_recorded() {
    let (result, found) = load("database:\n  transport: tls\nissuer:\n  allow: false\n");
    assert_eq!(result, Ok(()));
    assert!(found.is_empty());
}

#[test]
fn a_decode_that_fails_part_way_still_reports_what_it_found() {
    let (result, found) = load("database:\n  transport: plaintext\nunknown: 1\n");
    assert!(result.is_err());
    assert_eq!(found.len(), 1);
}

#[test]
fn a_value_decoded_without_the_reader_is_recorded_without_a_pointer() {
    let (value, found) = collect_development_settings(|| {
        serde_json::from_str::<Gated<Transport>>("\"plaintext\"").unwrap()
    });
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].pointer, None);
    assert_eq!(found[0].position, None);
    assert!(value.get(None).is_err());
}

#[test]
fn a_decode_with_no_collector_records_nothing_and_still_gates_the_value() {
    let value = serde_json::from_str::<Gated<Transport>>("\"plaintext\"").unwrap();
    assert!(value.get(None).is_err());
    let (_, found) = collect_development_settings(|| ());
    assert!(found.is_empty());
}

#[test]
fn a_nested_collector_keeps_its_own_findings_and_restores_the_outer() {
    let ((inner, after), outer) = collect_development_settings(|| {
        let _ = serde_json::from_str::<Gated<Transport>>("\"plaintext\"").unwrap();
        let (_, inner) = collect_development_settings(|| {
            let _ = serde_json::from_str::<Gated<Insecure>>("true").unwrap();
        });
        let _ = serde_json::from_str::<Gated<Transport>>("\"plaintext\"").unwrap();
        let (_, after) = collect_development_settings(|| ());
        (inner, after)
    });
    assert_eq!(
        inner.iter().map(|f| f.setting.code).collect::<Vec<_>>(),
        ["platform.posture.example-insecure"]
    );
    assert!(after.is_empty());
    assert_eq!(
        outer.iter().map(|f| f.setting.code).collect::<Vec<_>>(),
        [
            "platform.posture.example-plaintext",
            "platform.posture.example-plaintext"
        ]
    );
}

#[test]
fn a_panic_inside_a_collector_restores_the_outer_collector() {
    let (_, outer) = collect_development_settings(|| {
        let panicked =
            std::panic::catch_unwind(|| collect_development_settings(|| panic!("decode failed")));
        assert!(panicked.is_err());
        let _ = serde_json::from_str::<Gated<Transport>>("\"plaintext\"").unwrap();
    });
    assert_eq!(outer.len(), 1);
    let (_, none) = collect_development_settings(|| ());
    assert!(none.is_empty());
}

// F1

#[test]
fn production_refuses_each_setting_with_an_error_and_development_warns_under_the_same_code() {
    let mut production = PostureReport::new(declared(Posture::Production));
    let mut development = PostureReport::new(declared(Posture::Development));
    for report in [&mut production, &mut development] {
        report.record(found(&PLAINTEXT, Some("/database/transport")));
        report.record(found(&COMBINATION, None));
    }
    let file = Path::new("/etc/example/runtime.yaml");
    let refused = production.diagnostics(file);
    let accepted = development.diagnostics(file);
    assert_eq!(
        refused.iter().map(|d| d.code.as_str()).collect::<Vec<_>>(),
        accepted.iter().map(|d| d.code.as_str()).collect::<Vec<_>>()
    );
    assert!(refused.iter().all(|d| d.severity == Severity::Error));
    assert!(accepted.iter().all(|d| d.severity == Severity::Warning));

    assert_eq!(refused[0].code, "platform.posture.example-plaintext");
    assert_eq!(refused[0].path, "/database/transport");
    assert_eq!(
        refused[0].message,
        "The database connection is not encrypted; it is accepted only when the process declares development"
    );
    assert_eq!(
        refused[0].suggested_action,
        "Write transport: tls. For a laptop or test run, start it with `rstack dev`, or declare development with REGISTRY_STACK_POSTURE=development or --posture development."
    );
    let source = refused[0].source.as_ref().unwrap();
    assert_eq!(source.file, "/etc/example/runtime.yaml");
    assert_eq!((source.line, source.column), (Some(7), Some(5)));

    assert_eq!(
        accepted[0].message,
        "The database connection is not encrypted; production refuses it"
    );
    assert_eq!(accepted[0].suggested_action, "Write transport: tls.");
}

#[test]
fn a_combination_has_no_pointer() {
    let mut report = PostureReport::new(declared(Posture::Production));
    report.record(FoundSetting {
        setting: &COMBINATION,
        pointer: None,
        position: None,
        origin: SettingOrigin::Combination,
    });
    let diagnostics = report.diagnostics(Path::new("/etc/example/runtime.yaml"));
    assert_eq!(diagnostics[0].path, "");
}

#[test]
fn decide_refuses_in_production_with_every_setting_and_accepts_in_development() {
    let file = Path::new("/etc/example/runtime.yaml");
    let mut production = PostureReport::new(declared(Posture::Production));
    let mut development = PostureReport::new(declared(Posture::Development));
    for report in [&mut production, &mut development] {
        report.record(found(&PLAINTEXT, Some("/database/transport")));
        report.record(found(&INSECURE, Some("/issuer/allow")));
    }
    let error = production.decide(file).unwrap_err();
    assert_eq!(
        error
            .diagnostics()
            .iter()
            .map(|d| d.code.as_str())
            .collect::<Vec<_>>(),
        [
            "platform.posture.example-plaintext",
            "platform.posture.example-insecure"
        ]
    );
    assert_eq!(error.file(), Some(file));
    assert_eq!(development.decide(file), Ok(()));
}

#[test]
fn a_report_with_no_settings_decides_ok_in_both_postures() {
    let file = Path::new("/etc/example/runtime.yaml");
    for posture in [Posture::Production, Posture::Development] {
        let report = PostureReport::new(declared(posture));
        assert!(report.diagnostics(file).is_empty());
        assert_eq!(report.decide(file), Ok(()));
    }
}

#[test]
fn ready_member_shape() {
    let mut development = PostureReport::new(declared(Posture::Development));
    development.record(found(&PLAINTEXT, Some("/database/transport")));
    development.record(FoundSetting {
        setting: &COMBINATION,
        pointer: None,
        position: None,
        origin: SettingOrigin::Combination,
    });
    assert_eq!(
        Value::Object(development.ready_member()),
        serde_json::json!({
            "posture": "development",
            "developmentSettings": [
                {"code": "platform.posture.example-plaintext", "pointer": "/database/transport"},
                {"code": "evidence.posture.example-combination"}
            ]
        })
    );
    let production = PostureReport::new(declared(Posture::Production));
    assert_eq!(
        Value::Object(production.ready_member()),
        serde_json::json!({
            "posture": "production",
            "developmentSettings": []
        })
    );
}

// Explicit production settings

fn explicit(pointer: Option<&str>) -> FoundExplicitSetting {
    FoundExplicitSetting {
        setting: &UNRESTRICTED,
        pointer: pointer.map(str::to_owned),
        position: Some(Position { line: 9, column: 3 }),
        origin: SettingOrigin::RuntimeFile,
    }
}

#[test]
fn an_explicit_setting_decides_ok_in_production_and_adds_no_diagnostic() {
    let file = Path::new("/etc/example/runtime.yaml");
    let mut report = PostureReport::new(declared(Posture::Production));
    report.record_explicit(explicit(Some("/serve/allowedClients")));
    assert_eq!(report.explicit_settings().len(), 1);
    assert!(report.settings().is_empty());
    assert!(report.diagnostics(file).is_empty());
    assert_eq!(report.decide(file), Ok(()));
}

#[test]
fn an_explicit_setting_appears_in_no_ready_member() {
    for (posture, name) in [
        (Posture::Production, "production"),
        (Posture::Development, "development"),
    ] {
        let mut report = PostureReport::new(declared(posture));
        report.record_explicit(explicit(Some("/serve/allowedClients")));
        assert_eq!(
            Value::Object(report.ready_member()),
            serde_json::json!({"posture": name, "developmentSettings": []})
        );
    }
}

#[test]
fn explicit_settings_do_not_change_the_development_diagnostics() {
    let file = Path::new("/etc/example/runtime.yaml");
    let mut report = PostureReport::new(declared(Posture::Development));
    report.record_explicit(explicit(Some("/serve/allowedClients")));
    report.record(found(&PLAINTEXT, Some("/database/transport")));
    assert_eq!(report.diagnostics(file).len(), 1);
}

// Startup log

#[derive(Clone, Debug)]
struct Logged {
    level: tracing::Level,
    fields: BTreeMap<String, String>,
}

struct Collect(Arc<Mutex<Vec<Logged>>>);

struct Fields<'a>(&'a mut BTreeMap<String, String>);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }
}

impl tracing::Subscriber for Collect {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = BTreeMap::new();
        event.record(&mut Fields(&mut fields));
        self.0.lock().unwrap().push(Logged {
            level: *event.metadata().level(),
            fields,
        });
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

fn logged(report: &PostureReport) -> Vec<Logged> {
    let events = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::with_default(Collect(events.clone()), || report.log_startup());
    let events = events.lock().unwrap().clone();
    events
}

#[test]
fn startup_logs_the_posture_a_warning_per_development_setting_and_each_explicit_setting() {
    let mut report = PostureReport::new(DeclaredPosture {
        posture: Posture::Development,
        source: PostureSource::Environment,
    });
    report.record(found(&PLAINTEXT, Some("/database/transport")));
    report.record_explicit(explicit(Some("/serve/allowedClients")));
    let events = logged(&report);
    assert_eq!(events.len(), 3);

    assert_eq!(events[0].level, tracing::Level::INFO);
    assert_eq!(events[0].fields["message"], "posture declared");
    assert_eq!(events[0].fields["posture"], "development");
    assert_eq!(events[0].fields["posture_source"], "environment");
    assert_eq!(events[0].fields["development_settings"], "1");
    assert_eq!(events[0].fields["explicit_production_settings"], "1");

    assert_eq!(events[1].level, tracing::Level::WARN);
    assert_eq!(
        events[1].fields["message"],
        "development-only setting in use; production refuses it"
    );
    assert_eq!(
        events[1].fields["error_code"],
        "platform.posture.example-plaintext"
    );
    assert_eq!(events[1].fields["pointer"], "/database/transport");

    assert_eq!(events[2].level, tracing::Level::INFO);
    assert_eq!(
        events[2].fields["message"],
        "explicit production setting in use"
    );
    assert_eq!(
        events[2].fields["setting_code"],
        "adapter.posture.example-unrestricted"
    );
    assert_eq!(events[2].fields["pointer"], "/serve/allowedClients");
}

#[test]
fn startup_in_production_logs_one_line_for_a_clean_report() {
    let report = PostureReport::new(declared(Posture::Production));
    let events = logged(&report);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].fields["posture"], "production");
    assert_eq!(events[0].fields["posture_source"], "flag");
    assert_eq!(events[0].fields["development_settings"], "0");
}

#[test]
fn posture_codes_are_recognised_by_their_second_segment() {
    assert!(is_posture_code("platform.posture.insecure-issuer-http"));
    assert!(is_posture_code("breg.posture.placeholder-identity"));
    assert!(!is_posture_code("platform.database.test-only-plaintext"));
    assert!(!is_posture_code("platform.activation.posture-mismatch"));
    assert!(!is_posture_code("config.unknown-key"));
    assert!(!is_posture_code("posture"));
}

#[cfg(feature = "schema")]
#[test]
fn the_schema_is_the_inner_schema_with_the_development_codes() {
    let mut generator = schemars::generate::SchemaSettings::draft2020_12().into_generator();
    let schema = generator.subschema_for::<Gated<Transport>>();
    let schema = serde_json::to_value(&schema).unwrap();
    assert_eq!(
        schema["x-registry-development-only"],
        serde_json::json!(["platform.posture.example-plaintext"])
    );
}

// Stated

static LENIENT: ExplicitProductionSetting = ExplicitProductionSetting {
    code: "platform.posture.example-lenient",
    key: "format",
    summary: "The format is lenient, which the operator states deliberately",
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
    #[serde(default)]
    allow: Option<Gated<Insecure>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FlatTokens {
    #[serde(flatten)]
    tokens: Tokens,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StatedExample {
    direct: Tokens,
    #[serde(default)]
    flat: Option<FlatTokens>,
}

fn load_stated(body: &str) -> (Result<StatedExample, String>, CollectedSettings) {
    let text = format!("{HEAD}{body}");
    let (result, collected) = collect_posture_settings(|| {
        RuntimeConfigLoader::new_without_posture(ENVELOPE)
            .parse_str::<StatedExample>(&text, |_| None)
    });
    (
        result
            .map(|loaded| loaded.config)
            .map_err(|e| e.to_string()),
        collected,
    )
}

#[test]
fn stated_records_an_explicit_value_with_its_pointer_and_position_and_never_refuses() {
    let (result, collected) = load_stated("direct:\n  format: lenient\n");
    let config = result.expect("an explicit setting never refuses");
    assert_eq!(config.direct.format.get(), &Format::Lenient);
    assert_eq!(collected.explicit.len(), 1);
    let found = &collected.explicit[0];
    assert_eq!(found.setting.code, "platform.posture.example-lenient");
    assert_eq!(found.pointer.as_deref(), Some("/direct/format"));
    assert_eq!(found.position.map(|position| position.line), Some(4));
    assert_eq!(found.origin, SettingOrigin::RuntimeFile);
    assert!(collected.development.is_empty());
}

#[test]
fn an_explicit_setting_becomes_the_report_line_for_its_file() {
    let (_, collected) = load_stated("direct:\n  format: lenient\n");
    let found = &collected.explicit[0];
    let line = found.report_line(Some("runtime.yaml"));
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
    let line = unplaced.report_line(None);
    assert_eq!(
        (line.file, line.pointer, line.line, line.column),
        (None, None, None, None)
    );
}

#[test]
fn stated_records_nothing_for_the_value_every_posture_treats_as_the_default() {
    let (result, collected) = load_stated("direct:\n  format: strict\n");
    assert!(result.is_ok());
    assert!(collected.explicit.is_empty());
}

#[test]
fn stated_in_a_flattened_member_points_at_the_holding_mapping_key() {
    let (result, collected) = load_stated("direct:\n  format: strict\nflat:\n  format: lenient\n");
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(collected.explicit.len(), 1);
    assert_eq!(
        collected.explicit[0].pointer.as_deref(),
        Some("/flat/format")
    );
}

#[test]
fn the_two_collectors_record_a_gated_and_a_stated_value_of_one_decode_apart() {
    let (result, collected) = load_stated("direct:\n  format: lenient\n  allow: true\n");
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(collected.explicit.len(), 1);
    assert_eq!(collected.development.len(), 1);
    assert_eq!(
        collected.development[0].setting.code,
        "platform.posture.example-insecure"
    );
}

#[test]
fn collect_development_settings_still_returns_the_development_findings_of_a_decode_with_stated_values(
) {
    let text = format!("{HEAD}direct:\n  format: lenient\n  allow: true\n");
    let (result, found) = collect_development_settings(|| {
        RuntimeConfigLoader::new_without_posture(ENVELOPE)
            .parse_str::<StatedExample>(&text, |_| None)
    });
    assert!(result.is_ok());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].setting.code, "platform.posture.example-insecure");
}

#[test]
fn nested_posture_collectors_keep_their_own_explicit_findings() {
    let ((inner, after), outer) = collect_posture_settings(|| {
        let (_, inner) = collect_posture_settings(|| {
            let text = format!("{HEAD}direct:\n  format: lenient\n");
            let _ = RuntimeConfigLoader::new_without_posture(ENVELOPE)
                .parse_str::<StatedExample>(&text, |_| None);
        });
        let (_, after) = collect_posture_settings(|| ());
        (inner.explicit.len(), after.explicit.len())
    });
    assert_eq!((inner, after, outer.explicit.len()), (1, 0, 0));
}

#[test]
fn the_loader_hands_every_explicit_setting_to_the_posture_report() {
    let text = format!("{HEAD}direct:\n  format: lenient\n");
    for posture in [Posture::Production, Posture::Development] {
        let loader = RuntimeConfigLoader::new(ENVELOPE, declared(posture));
        let loaded = loader
            .parse_str::<StatedExample>(&text, |_| None)
            .expect("an explicit setting is valid in every posture");
        let listed = loaded.posture.explicit_settings();
        assert_eq!(listed.len(), 1, "{posture:?}");
        assert_eq!(listed[0].setting.code, "platform.posture.example-lenient");
        assert_eq!(listed[0].pointer.as_deref(), Some("/direct/format"));
        assert_eq!(listed[0].position.map(|position| position.line), Some(4));
        assert!(loaded.posture.settings().is_empty());
        assert!(loaded
            .posture
            .diagnostics(Path::new("runtime.yaml"))
            .is_empty());
    }
}

#[cfg(feature = "schema")]
#[test]
fn the_stated_schema_is_the_inner_schema_with_the_explicit_codes() {
    let mut generator = schemars::generate::SchemaSettings::draft2020_12().into_generator();
    let schema = generator.subschema_for::<Stated<Format>>();
    let schema = serde_json::to_value(&schema).unwrap();
    assert_eq!(
        schema["x-registry-explicit-production"],
        serde_json::json!(["platform.posture.example-lenient"])
    );
    assert!(schema.get("x-registry-development-only").is_none());
}

// SPDX-License-Identifier: Apache-2.0

//! Privacy canary: distinctive values go in through every ledger API,
//! then every row of every table in the ledger schema is dumped as text and
//! searched for them. The one value allowed to persist is the extract
//! `publishedAt` in the staleness clock column. Every error and key type is
//! also formatted with `Display` and `Debug` and searched for the canaries
//! and for key bytes.

mod status_support;

use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::{DateTime, TimeDelta, TimeZone, Utc};
use registry_evidence::status::{
    check_observation_retention, validate_key_separation, AllocationFields, CredentialMembers,
    EntryStatus, HolderKeyThumbprint, KeyRing, KeyVersion, LedgerConfig, ListPolicy, Observation,
    Provenance, ReasonCategory, SchemaName, StatusError, StatusKey, StatusLedger, StatusListId,
    StatusSubject, TransitionRequest, DEFAULT_CLOCK_SKEW,
};
use serde_json::{Map, Value};
use status_support::{
    allocate_for, dump_schema, extract_read, holder_digest_keys, inspector, key, ledger,
    mapping_version, now, pseudonym_keys, reason, revision, selector_profile, subject, text,
    HOLDER_DIGEST_KEY_BYTE, PSEUDONYM_KEY_BYTE, PUBLIC_ORIGIN, REQUIREMENT_ID, SELECTOR_PROFILE_ID,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const SELECTOR_CANARY: &str = "canary-selector-4b7e91d2";
const RECORD_CANARY: &str = "canary-record-c83f05a6";
const PUBLISHER_CANARY: &str = "canary-publisher-0e5d17";
const EXTRACT_ID_CANARY: &str = "canary-extract-9a71f3";

fn published_at_canary() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 19, 3, 17, 29).unwrap()
}

fn thumbprint_canary_bytes() -> [u8; 32] {
    std::array::from_fn(|position| 0xc0 + u8::try_from(position).unwrap())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decimal_run(byte: u8) -> String {
    vec![byte.to_string(); 4].join(", ")
}

/// Every form a canary could take in a dump or a formatted value.
fn canary_forms() -> Vec<(String, String)> {
    let mut forms = Vec::new();
    for (name, value) in [
        ("selector value", SELECTOR_CANARY),
        ("record id", RECORD_CANARY),
        ("extract publisher", PUBLISHER_CANARY),
        ("extract id", EXTRACT_ID_CANARY),
    ] {
        forms.push((name.to_owned(), value.to_owned()));
        forms.push((format!("{name} (hex)"), hex(value.as_bytes())));
        forms.push((format!("{name} (base64url)"), URL_SAFE_NO_PAD.encode(value)));
    }
    let thumbprint = thumbprint_canary_bytes();
    forms.push((
        "thumbprint (base64url)".to_owned(),
        URL_SAFE_NO_PAD.encode(thumbprint),
    ));
    forms.push((
        "thumbprint (base64url prefix)".to_owned(),
        URL_SAFE_NO_PAD.encode(thumbprint)[..16].to_owned(),
    ));
    forms.push(("thumbprint (hex)".to_owned(), hex(&thumbprint[..8])));
    forms.push((
        "thumbprint (base64)".to_owned(),
        STANDARD.encode(&thumbprint[..12]),
    ));
    forms.push((
        "thumbprint (decimal)".to_owned(),
        "192, 193, 194, 195".to_owned(),
    ));
    forms.extend(published_at_forms());
    forms
}

fn published_at_forms() -> Vec<(String, String)> {
    let published = published_at_canary();
    vec![
        (
            "publishedAt (ISO)".to_owned(),
            "2026-10-19T03:17:29".to_owned(),
        ),
        (
            "publishedAt (SQL)".to_owned(),
            "2026-10-19 03:17:29".to_owned(),
        ),
        (
            "publishedAt (epoch)".to_owned(),
            published.timestamp().to_string(),
        ),
    ]
}

fn key_byte_forms() -> Vec<(String, String)> {
    let mut forms = Vec::new();
    for (name, byte) in [
        ("pseudonym key", PSEUDONYM_KEY_BYTE),
        ("holder digest key", HOLDER_DIGEST_KEY_BYTE),
    ] {
        forms.push((format!("{name} (hex)"), hex(&[byte; 8])));
        forms.push((format!("{name} (base64)"), STANDARD.encode([byte; 9])));
        forms.push((format!("{name} (decimal)"), decimal_run(byte)));
    }
    forms
}

fn assert_free_of(haystack: &str, forms: &[(String, String)], context: &str) {
    for (name, form) in forms {
        assert!(
            !haystack.contains(form.as_str()),
            "{context} carries the {name} canary"
        );
    }
}

fn canary_subject(value: &str) -> StatusSubject {
    subject(value)
}

#[tokio::test]
async fn no_canary_reaches_any_ledger_table() {
    let ledger = ledger().await;
    let published = published_at_canary();
    let run_instant = now();
    let thumbprints =
        [
            HolderKeyThumbprint::from_base64url(&URL_SAFE_NO_PAD.encode(thumbprint_canary_bytes()))
                .unwrap(),
        ];
    let person = canary_subject(SELECTOR_CANARY);
    let record = canary_subject(RECORD_CANARY);

    ledger
        .ledger
        .register_mapping_version(&ledger.reserved, mapping_version(1))
        .await
        .unwrap();
    for subject in [&person, &record] {
        ledger
            .ledger
            .record_observation(
                &ledger.reserved,
                subject,
                &Observation {
                    status: EntryStatus::Suspended,
                    revision: revision(2),
                    captured_at: run_instant - TimeDelta::minutes(1),
                    mapping_version: mapping_version(1),
                },
            )
            .await
            .unwrap();
    }
    let bound = allocate_for(
        &ledger,
        &person,
        extract_read(published, run_instant),
        CredentialMembers::HolderBound(&thumbprints),
    )
    .await;
    let unbound = allocate_for(
        &ledger,
        &record,
        extract_read(published, run_instant),
        CredentialMembers::Unbound { count: 2 },
    )
    .await;
    // Inherited from the observations above.
    assert_eq!(
        ledger
            .ledger
            .entry_status(&ledger.reserved, bound[0].entry())
            .await
            .unwrap(),
        EntryStatus::Suspended
    );

    let requests = [
        TransitionRequest {
            entry: bound[0].entry().clone(),
            to: EntryStatus::Invalid,
            reason: reason("withdrawn-at-source"),
            provenance: Provenance::Hook {
                mapping_version: mapping_version(1),
                event_id: text(&Uuid::new_v4().to_string()),
                revision: revision(3),
                package_revision: text("sha256:5e1f"),
                source: text("urn:example:registry"),
            },
        },
        TransitionRequest {
            entry: unbound[0].entry().clone(),
            to: EntryStatus::Valid,
            reason: reason("reinstated"),
            provenance: Provenance::Operator {
                principals: vec![text("operator-a"), text("operator-b")],
                case_reference: text("case-17"),
            },
        },
        TransitionRequest {
            entry: unbound[1].entry().clone(),
            to: EntryStatus::Invalid,
            reason: reason("absent-from-extract"),
            provenance: Provenance::Reconciliation {
                mapping_version: mapping_version(1),
                run_id: Uuid::new_v4(),
                extract_digest: [0x3c; 32],
                revision: None,
            },
        },
    ];
    for request in &requests {
        ledger
            .ledger
            .apply_transition(&ledger.reserved, request)
            .await
            .unwrap();
    }
    ledger
        .ledger
        .advance_staleness_clock(&ledger.reserved, published, run_instant)
        .await
        .unwrap();
    ledger
        .ledger
        .purge_observations(&ledger.reserved, Duration::from_secs(30 * 24 * 60 * 60))
        .await
        .unwrap();
    let clock = ledger
        .ledger
        .staleness_clock(&ledger.reserved)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(clock.instant(), published);

    let mut forms = canary_forms();
    forms.extend(key_byte_forms());
    let dump = dump_schema(&inspector().await, &ledger.schema).await;
    let tables: std::collections::BTreeSet<&str> =
        dump.iter().map(|row| row.table.as_str()).collect();
    for table in [
        "allocations",
        "lists",
        "mapping_versions",
        "observations",
        "schema_migrations",
        "staleness_clock",
        "transitions",
    ] {
        assert!(tables.contains(table), "the dump has no {table} row");
    }
    let mut published_at_seen = false;
    for row in &dump {
        if row.table == "staleness_clock" {
            let mut json = row.json.clone();
            let observed = json
                .as_object_mut()
                .unwrap()
                .remove("last_observed_at")
                .unwrap();
            let observed: DateTime<Utc> = serde_json::from_value(observed).unwrap();
            assert_eq!(observed, published);
            published_at_seen = true;
            assert_free_of(&json.to_string(), &forms, "the staleness clock row");
            continue;
        }
        let context = format!("a {} row", row.table);
        assert_free_of(&row.text, &forms, &context);
        assert_free_of(&row.json.to_string(), &forms, &context);
    }
    assert!(published_at_seen);
}

#[tokio::test]
async fn no_error_or_key_type_formats_a_canary_or_key_bytes() {
    let mut formatted: Vec<String> = Vec::new();
    let mut push = |display: Option<String>, debug: String| {
        formatted.extend(display);
        formatted.push(debug);
    };

    // Errors raised by canary inputs.
    let long_selector = SELECTOR_CANARY.repeat(4);
    let mut projection = Map::new();
    projection.insert("person_ref".to_owned(), Value::String(long_selector));
    let error =
        StatusSubject::from_json_projection(SELECTOR_PROFILE_ID, &selector_profile(), &projection)
            .unwrap_err();
    push(Some(error.to_string()), format!("{error:?}"));
    let error = StatusError::from(error);
    push(Some(error.to_string()), format!("{error:?}"));
    let error = HolderKeyThumbprint::from_base64url(&format!("{SELECTOR_CANARY}!")).unwrap_err();
    push(Some(error.to_string()), format!("{error:?}"));
    let error =
        registry_evidence::status::ProvenanceText::new(&format!("{RECORD_CANARY}\n")).unwrap_err();
    push(Some(error.to_string()), format!("{error:?}"));
    let error = ReasonCategory::new(&format!("{SELECTOR_CANARY}!")).unwrap_err();
    push(Some(error.to_string()), format!("{error:?}"));
    let error = StatusListId::parse(SELECTOR_CANARY).unwrap_err();
    push(Some(error.to_string()), format!("{error:?}"));
    let error = SchemaName::new(SELECTOR_CANARY).unwrap_err();
    push(Some(error.to_string()), format!("{error:?}"));
    let error = StatusLedger::new(LedgerConfig {
        schema: SchemaName::default(),
        public_origin: format!("https://{SELECTOR_CANARY}.example/{RECORD_CANARY}"),
        list_policy: ListPolicy::new(Duration::from_secs(60)).unwrap(),
        pseudonym_keys: pseudonym_keys(),
        holder_digest_keys: holder_digest_keys(),
        clock_skew: DEFAULT_CLOCK_SKEW,
    })
    .unwrap_err();
    push(Some(error.to_string()), format!("{error:?}"));
    let error = StatusKey::new(
        KeyVersion::new(1).unwrap(),
        Zeroizing::new(vec![PSEUDONYM_KEY_BYTE; 16]),
    )
    .unwrap_err();
    push(Some(error.to_string()), format!("{error:?}"));
    let error = KeyRing::new(
        key(1, PSEUDONYM_KEY_BYTE),
        vec![key(1, HOLDER_DIGEST_KEY_BYTE)],
    )
    .unwrap_err();
    push(Some(error.to_string()), format!("{error:?}"));
    let error = validate_key_separation(
        &pseudonym_keys(),
        &holder_digest_keys(),
        &[PSEUDONYM_KEY_BYTE; 32],
        &[0x77; 32],
    )
    .unwrap_err();
    push(Some(error.to_string()), format!("{error:?}"));
    let error =
        check_observation_retention(Duration::from_secs(60), Duration::from_secs(600)).unwrap_err();
    push(Some(error.to_string()), format!("{error:?}"));

    // Errors from the database paths, including PostgreSQL failures.
    let ledger = ledger().await;
    let published = published_at_canary();
    let error = ledger
        .ledger
        .advance_staleness_clock(&ledger.reserved, published, published - TimeDelta::days(1))
        .await
        .unwrap_err();
    push(Some(error.to_string()), format!("{error:?}"));
    let unmigrated = StatusLedger::new(LedgerConfig {
        schema: SchemaName::new(&format!("evidence_status_{}", Uuid::new_v4().simple())).unwrap(),
        public_origin: PUBLIC_ORIGIN.to_owned(),
        list_policy: ListPolicy::new(Duration::from_secs(60)).unwrap(),
        pseudonym_keys: pseudonym_keys(),
        holder_digest_keys: holder_digest_keys(),
        clock_skew: DEFAULT_CLOCK_SKEW,
    })
    .unwrap();
    let error = unmigrated
        .record_observation(
            &ledger.reserved,
            &canary_subject(SELECTOR_CANARY),
            &Observation {
                status: EntryStatus::Invalid,
                revision: revision(1),
                captured_at: published,
                mapping_version: mapping_version(1),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(error, StatusError::Database(_)), "{error:?}");
    push(Some(error.to_string()), format!("{error:?}"));
    let error = ledger
        .ledger
        .record_observation(
            &ledger.reserved,
            &canary_subject(SELECTOR_CANARY),
            &Observation {
                status: EntryStatus::Invalid,
                revision: revision(1),
                captured_at: published,
                mapping_version: mapping_version(1),
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, StatusError::MappingVersionNotCurrent { .. }),
        "{error:?}"
    );
    push(Some(error.to_string()), format!("{error:?}"));

    // Key types, subjects, digests and the values that carry canaries.
    let person = canary_subject(SELECTOR_CANARY);
    let thumbprint =
        HolderKeyThumbprint::from_base64url(&URL_SAFE_NO_PAD.encode(thumbprint_canary_bytes()))
            .unwrap();
    let thumbprints = [thumbprint];
    let pseudonyms = pseudonym_keys();
    let digests = holder_digest_keys();
    push(None, format!("{:?}", key(1, PSEUDONYM_KEY_BYTE)));
    push(
        None,
        format!(
            "{:?}",
            KeyRing::new(key(2, PSEUDONYM_KEY_BYTE), vec![key(1, 0x61)]).unwrap()
        ),
    );
    push(None, format!("{pseudonyms:?}"));
    push(None, format!("{digests:?}"));
    push(
        None,
        format!("{:?}", pseudonyms.pseudonym(&person).unwrap()),
    );
    push(
        None,
        format!("{:?}", pseudonyms.lookup_pseudonyms(&person).unwrap()),
    );
    push(None, format!("{:?}", digests.digest(&thumbprints[0])));
    push(None, format!("{:?}", thumbprints[0]));
    push(None, format!("{person:?}"));
    let read = extract_read(published, now());
    push(None, format!("{read:?}"));
    let fields = AllocationFields {
        requirement_id: REQUIREMENT_ID,
        subject: &person,
        issued_at: now(),
        not_after: now() + TimeDelta::days(1),
        source_read: read,
    };
    push(None, format!("{fields:?}"));
    push(
        None,
        format!("{:?}", CredentialMembers::HolderBound(&thumbprints)),
    );
    push(None, format!("{:?}", ledger.ledger));
    push(None, format!("{:?}", ledger.issuance));
    push(None, format!("{:?}", ledger.reserved));
    ledger
        .ledger
        .register_mapping_version(&ledger.reserved, mapping_version(1))
        .await
        .unwrap();
    ledger
        .ledger
        .advance_staleness_clock(&ledger.reserved, published, now())
        .await
        .unwrap();
    let clock = ledger
        .ledger
        .staleness_clock(&ledger.reserved)
        .await
        .unwrap()
        .unwrap();
    push(None, format!("{clock:?}"));
    let mut transaction = ledger
        .ledger
        .begin(&ledger.issuance, Duration::from_secs(20))
        .await
        .unwrap();
    let references = transaction
        .allocate(&fields, CredentialMembers::HolderBound(&thumbprints))
        .await
        .unwrap();
    push(None, format!("{references:?}"));
    transaction.commit().await.unwrap();

    let mut forms = canary_forms();
    forms.extend(key_byte_forms());
    for (position, output) in formatted.iter().enumerate() {
        assert_free_of(output, &forms, &format!("formatted value {position}"));
    }
}

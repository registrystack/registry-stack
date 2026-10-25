// SPDX-License-Identifier: Apache-2.0

//! One generic reader projects three differently shaped occurrence record
//! types served by a real PostgreSQL-backed registry: the descriptor comes
//! from the served metadata, the record from an ordinary read and the recorded
//! time from the creation revision. The projection code never branches on a
//! record type.

#![cfg(feature = "postgres-test")]

#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};

use registry_breg::api::VerifiedRequestClaims;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_yaml;
use registry_breg_client::{
    occurrence_view, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey, BRegMetadata,
    BRegOccurrenceDescriptor, BRegOccurrenceError, BRegOccurrenceEvidence, BRegRecordFormat,
    BRegRecordOptions, BaseRegistryClient,
};
use serde_json::{json, Value};

const SHAPES: &str = include_str!("fixtures/occurrence/shapes.yaml");

/// Every record type the reader needs, with the fields the profile may read
/// and write. Reference fields that no journey fills are left out.
const PERMITTED: &[(&str, &[&str])] = &[
    ("entry", &["entry-number", "name"]),
    (
        "entry-registration",
        &[
            "entry",
            "source-reference",
            "effective-at",
            "occurred-on",
            "summary",
            "corrects",
        ],
    ),
    ("grant", &["grant-number", "status"]),
    (
        "grant-pause-decision",
        &[
            "grant",
            "decided-on",
            "effective-from",
            "effective-until",
            "basis-reference",
            "summary",
            "corrects",
        ],
    ),
    ("item", &["item-number"]),
    ("custody-record", &["item", "holder-reference", "status"]),
    (
        "custody-handover",
        &[
            "item",
            "previous-custody",
            "new-custody",
            "agreed-not-before",
            "agreed-before",
            "effective-at",
            "deed-reference",
        ],
    ),
];

/// The shared shapes fixture with record permissions in place of its Action
/// permissions, so the reader can create and read every record type.
fn registry() -> registry_breg::CompiledRegistry {
    let record_types = SHAPES
        .split("\nactions:\n")
        .next()
        .expect("shapes fixture declares record types before its actions");
    let permissions: String = PERMITTED
        .iter()
        .map(|(record_type, fields)| {
            let fields = fields.join(", ");
            format!(
                "        - {{recordType: {record_type}, operations: [create, get, revisions], \
                 revisionAccess: true, readableFields: [{fields}], writableFields: [{fields}], \
                 rowBoundaries: unrestricted}}\n"
            )
        })
        .collect();
    let project = format!(
        "{record_types}\naccessProfiles:\n  - id: reader\n    default: true\n    \
         principalClaim: registry_principal\n    requiredScopes: unrestricted\n    \
         permissions:\n      records:\n{permissions}"
    );
    let project = parse_project_yaml(project.as_bytes()).expect("reader registry parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("reader registry compiles")
}

fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "occurrence-reader-fixture",
        BTreeSet::new(),
        None,
        BTreeMap::new(),
    )
    .expect("claims are verified")
}

struct Journey<'a> {
    client: &'a BaseRegistryClient,
    contract: &'a BRegMetadata,
    sequence: usize,
}

impl Journey<'_> {
    /// Create one record through the served create binding and return its
    /// identifier.
    async fn create(&mut self, record_type: &str, data: Value) -> String {
        self.sequence += 1;
        let BRegDirectWrite::Create(binding) = self
            .contract
            .select_direct_write(&format!("records.{record_type}.create"), "reader")
            .expect("the profile may create this record type")
        else {
            panic!("{record_type} create binding")
        };
        let request =
            BRegCreateRequest::new(data.as_object().expect("create data is an object").clone())
                .expect("create request is bounded");
        let key = BRegIdempotencyKey::parse(format!("reader-{}", self.sequence))
            .expect("idempotency key");
        self.client
            .create_record(&binding, &request, &key, BRegRecordFormat::Json)
            .await
            .unwrap_or_else(|error| panic!("{record_type} create succeeds: {error:?}"))
            .value
            .data
            .record_identifier
    }

    /// The one generic projection: descriptor from metadata, record from a
    /// read, recorded time from the creation revision.
    async fn project(&self, record_type: &str, route: &str, id: &str) -> Value {
        let descriptor = self
            .contract
            .occurrence(record_type)
            .expect("the served metadata carries the descriptor");
        let record = self
            .client
            .get_record(route, id, &BRegRecordOptions::default())
            .await
            .expect("record read")
            .value
            .data;
        let creation = self
            .client
            .occurrence_creation_revision(route, id, None)
            .await
            .expect("creation revision read")
            .expect("the profile may read the creation revision");
        let view = occurrence_view(
            self.contract.registry_revision(),
            record_type,
            &descriptor,
            &record,
            &BRegOccurrenceEvidence {
                creation_revision: Some(&creation),
                ..Default::default()
            },
        )
        .expect("the view projects");
        serde_json::to_value(view).expect("view serializes")
    }
}

fn available(type_name: &str, value: Value) -> Value {
    json!({"status": "available", "type": type_name, "value": value})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_reader_projects_three_schemas() {
    let fixture = client_http::ClientFixture::start(registry(), claims()).await;
    let client = &fixture.http.client;
    let contract = client
        .registry_contract(Some("reader"))
        .await
        .expect("metadata is served and parses");
    let contract = contract.value;
    let mut journey = Journey {
        client,
        contract: &contract,
        sequence: 0,
    };

    let entry = journey
        .create("entry", json!({"entryNumber": "E-1", "name": "Entry one"}))
        .await;
    let grant = journey
        .create("grant", json!({"grantNumber": "G-1", "status": "active"}))
        .await;
    let item = journey.create("item", json!({"itemNumber": "I-1"})).await;
    let previous = journey
        .create(
            "custody-record",
            json!({"item": item, "holderReference": "holder-a", "status": "released"}),
        )
        .await;
    let current = journey
        .create(
            "custody-record",
            json!({"item": item, "holderReference": "holder-b", "status": "held"}),
        )
        .await;

    let registration = journey
        .create(
            "entry-registration",
            json!({
                "entry": entry,
                "sourceReference": "SRC-1",
                "effectiveAt": "2026-10-20T09:30:00+02:00",
                "occurredOn": "2026-10-19",
                "summary": "Registered from the source",
            }),
        )
        .await;
    let decision = journey
        .create(
            "grant-pause-decision",
            json!({
                "grant": grant,
                "decidedOn": "2026-10-21",
                "effectiveFrom": "2026-11-01",
                "basisReference": "NOTICE-1",
            }),
        )
        .await;
    let handover = journey
        .create(
            "custody-handover",
            json!({
                "item": item,
                "previousCustody": previous,
                "newCustody": current,
                "agreedNotBefore": "2026-09-01",
                "effectiveAt": "2026-10-22T12:00:00Z",
                "deedReference": "DEED-1",
            }),
        )
        .await;

    // One loop, no per-type branches: the table only supplies what to read
    // and what the view must contain.
    let cases = [
        (
            "entry-registration",
            "entry-registrations",
            registration.clone(),
            "Entry registered",
            json!({
                "occurredAt": {"kind": "point", "at": available("date", json!("2026-10-19"))},
                "effective": {"kind": "point",
                    "at": available("instant", json!("2026-10-20T07:30:00+00:00"))},
            }),
            vec![("entry", entry.clone())],
            vec![("source", "SRC-1")],
        ),
        (
            "grant-pause-decision",
            "grant-pause-decisions",
            decision.clone(),
            "Grant pause decided",
            json!({
                "occurredAt": {"kind": "point", "at": available("date", json!("2026-10-21"))},
                "effective": {"kind": "interval", "meaning": "span",
                    "start": available("date", json!("2026-11-01")),
                    "end": {"status": "declaredUnknown"}},
            }),
            vec![("grant", grant.clone())],
            vec![("basis", "NOTICE-1")],
        ),
        (
            "custody-handover",
            "custody-handovers",
            handover,
            "Custody handed over",
            json!({
                "occurredAt": {"kind": "interval", "meaning": "within",
                    "start": available("date", json!("2026-09-01")),
                    "end": {"status": "declaredUnknown"}},
                "effective": {"kind": "point",
                    "at": available("instant", json!("2026-10-22T12:00:00+00:00"))},
            }),
            vec![
                ("item", item.clone()),
                ("previous-custody", previous.clone()),
                ("new-custody", current.clone()),
            ],
            vec![("deed", "DEED-1")],
        ),
    ];
    for (record_type, route, id, label, times, subjects, sources) in cases {
        let view = journey.project(record_type, route, &id).await;
        assert_eq!(view["label"], label, "{record_type} label");
        assert_eq!(view["occurredAt"], times["occurredAt"], "{record_type}");
        assert_eq!(view["effective"], times["effective"], "{record_type}");
        assert_eq!(
            view["source"],
            json!({"recordType": record_type, "recordId": id, "revision": "1"})
        );
        assert_eq!(view["registryRevision"], contract.registry_revision());
        assert_eq!(view["recordedAtSource"], "creation-revision");
        assert_eq!(
            view["recordedAt"]["status"], "available",
            "{record_type} recorded time comes from the creation revision"
        );
        let recorded = view["recordedAt"]["value"]
            .as_str()
            .expect("recorded time is text");
        assert!(
            recorded.ends_with('Z') && recorded.contains('T'),
            "{record_type} recorded time is RFC 3339 with a Z zone: {recorded}"
        );
        assert_eq!(
            view["subjects"]
                .as_array()
                .expect("subjects")
                .iter()
                .map(|subject| (
                    subject["role"].as_str().expect("role").to_owned(),
                    subject["value"]["value"].as_str().expect("id").to_owned()
                ))
                .collect::<Vec<_>>(),
            subjects
                .into_iter()
                .map(|(role, id)| (role.to_owned(), id))
                .collect::<Vec<_>>(),
            "{record_type} subjects"
        );
        assert_eq!(
            view["sources"]
                .as_array()
                .expect("sources")
                .iter()
                .map(|source| (
                    source["role"].as_str().expect("role").to_owned(),
                    source["value"]["value"].as_str().expect("text").to_owned()
                ))
                .collect::<Vec<_>>(),
            sources
                .into_iter()
                .map(|(role, value)| (role.to_owned(), value.to_owned()))
                .collect::<Vec<_>>(),
            "{record_type} sources"
        );
    }

    // A record type without a descriptor is not an occurrence.
    assert!(matches!(
        contract.occurrence("entry"),
        Err(BRegOccurrenceError::NotAnOccurrence)
    ));
    assert!(matches!(
        contract.occurrence("no-such-record-type"),
        Err(BRegOccurrenceError::NotAnOccurrence)
    ));

    // The served descriptor is the reader's contract: a malformed member and
    // an unsupported version are refused rather than guessed.
    let served = contract
        .occurrence("grant-pause-decision")
        .expect("served descriptor")
        .to_value();
    let mut malformed = served.clone();
    malformed["subjects"] = json!("not-a-list");
    let error = BRegOccurrenceDescriptor::from_value(&malformed)
        .expect_err("a descriptor with non-list subjects is malformed");
    assert!(
        matches!(error, BRegOccurrenceError::MalformedDescriptor { .. }),
        "{error:?}"
    );
    let mut unsupported = served;
    unsupported["descriptorVersion"] = json!("2");
    assert!(matches!(
        BRegOccurrenceDescriptor::from_value(&unsupported),
        Err(BRegOccurrenceError::UnsupportedVersion { .. })
    ));

    // Evidence read for a different record is refused, never merged.
    let descriptor = contract
        .occurrence("grant-pause-decision")
        .expect("served descriptor");
    let record = client
        .get_record(
            "grant-pause-decisions",
            &decision,
            &BRegRecordOptions::default(),
        )
        .await
        .expect("record read")
        .value
        .data;
    let other = client
        .occurrence_creation_revision("entry-registrations", &registration, None)
        .await
        .expect("creation revision read")
        .expect("the profile may read the creation revision");
    let refused = occurrence_view(
        contract.registry_revision(),
        "grant-pause-decision",
        &descriptor,
        &record,
        &BRegOccurrenceEvidence {
            creation_revision: Some(&other),
            ..Default::default()
        },
    )
    .expect_err("another record's creation revision is not evidence");
    assert!(
        matches!(refused, BRegOccurrenceError::WrongRecordEvidence { .. }),
        "{refused:?}"
    );

    // A creation revision for an unreadable or absent history is None, and the
    // view then reports the recorded time as unavailable.
    let absent = client
        .occurrence_creation_revision(
            "grant-pause-decisions",
            "00000000-0000-4000-8000-0000000000ff",
            None,
        )
        .await
        .expect("an absent history is not a failure");
    assert!(absent.is_none());
    let view = occurrence_view(
        contract.registry_revision(),
        "grant-pause-decision",
        &descriptor,
        &record,
        &BRegOccurrenceEvidence::default(),
    )
    .expect("the view projects without creation evidence");
    let view = serde_json::to_value(view).expect("view serializes");
    assert_eq!(view["recordedAt"], json!({"status": "unavailable"}));
    fixture.finish().await;
}

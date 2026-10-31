// SPDX-License-Identifier: Apache-2.0

//! Generated cross-layer properties for the facade boundary in
//! `products/adapter/CONCEPT.md` section 13.5.

use super::*;

use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};
use registry_adapter_core::{
    binding_record_schema, check_profile, AccessProfile, Binding, EnvelopeTemplate, PinnedRef,
    Problem, ProfileOperation, ProjectIdentity, RecordField, RecordFieldType, RecordType,
};
use registry_platform_yaml::{
    BoundedU32, BoundedU64, Digest, ExternalId, LocalId, UniqueIdList, UniqueList,
};

const DUPLICATE_CODE: &str = "adapter.profile.problem-class-duplicate";
const UNRESOLVED_CODE: &str = "adapter.profile.problem-class-unresolved";

fn local(value: &str) -> LocalId {
    LocalId::new(value).expect("a generated local identifier")
}

fn external(value: &str) -> ExternalId {
    ExternalId::new(value).expect("a generated external identifier")
}

fn digest() -> Digest {
    Digest::new("sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9")
        .expect("a digest")
}

fn pin(id: &str) -> PinnedRef {
    PinnedRef {
        id: local(id),
        version: "1".to_owned(),
        digest: digest(),
    }
}

#[derive(Clone, Debug)]
struct GeneratedField {
    kind: RecordFieldType,
    required: bool,
    present: bool,
}

#[derive(Clone, Debug)]
struct GeneratedModel {
    fields: Vec<GeneratedField>,
    wrapped: bool,
    paginated: bool,
}

fn generated_model() -> impl Strategy<Value = GeneratedModel> {
    (
        prop::collection::vec((0_u8..6, any::<bool>(), any::<bool>()), 1..=8),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(raw_fields, wrapped, paginated)| {
            let mut fields: Vec<_> = raw_fields
                .into_iter()
                .map(|(kind, required, present)| GeneratedField {
                    kind: match kind {
                        0 => RecordFieldType::String,
                        1 => RecordFieldType::Integer,
                        2 => RecordFieldType::Decimal,
                        3 => RecordFieldType::Boolean,
                        4 => RecordFieldType::Date,
                        _ => RecordFieldType::DateTime,
                    },
                    required,
                    present,
                })
                .collect();
            // Every generated case carries a required member, so the same
            // case proves the missing-required negative as well as the
            // admitted value.
            fields[0].required = true;
            fields[0].present = true;
            GeneratedModel {
                fields,
                wrapped,
                paginated,
            }
        })
}

fn field_name(index: usize) -> String {
    format!("field{index}")
}

fn field_value(kind: RecordFieldType, index: usize) -> Value {
    match kind {
        RecordFieldType::String => Value::String(format!("value-{index}")),
        RecordFieldType::Integer => json!(i64::try_from(index).expect("small generated index")),
        RecordFieldType::Decimal => json!(index as f64 + 0.25),
        RecordFieldType::Boolean => Value::Bool(index.is_multiple_of(2)),
        RecordFieldType::Date => Value::String("2024-02-29".to_owned()),
        RecordFieldType::DateTime => Value::String("2024-02-29T12:34:56Z".to_owned()),
    }
}

fn project_for(model: &GeneratedModel) -> (AdapterProject, Binding) {
    let fields = model
        .fields
        .iter()
        .enumerate()
        .map(|(index, field)| RecordField {
            name: local(&field_name(index)),
            r#type: field.kind,
            required: field.required,
        })
        .collect();
    let binding = Binding {
        id: local("find-records"),
        operation: external("records-find"),
        record_type: local("generated-record"),
        route: external("generated-route"),
        filters: UniqueList::new(Vec::new()).expect("empty filters"),
        maximum_upstream_calls: BoundedU64::new(1).expect("one upstream call"),
    };
    let project = AdapterProject {
        project: ProjectIdentity {
            id: local("generated-project"),
            version: "1".to_owned(),
        },
        profile: pin("generated-profile"),
        pack: pin("generated-pack"),
        record_types: UniqueIdList::new(vec![RecordType {
            name: local("generated-record"),
            fields: UniqueList::new(fields).expect("generated field names are unique"),
        }])
        .expect("one record type"),
        templated_routes: UniqueIdList::new(Vec::new()).expect("no route templates"),
        bindings: UniqueIdList::new(vec![binding.clone()]).expect("one binding"),
        access_profiles: UniqueIdList::<AccessProfile>::new(Vec::new())
            .expect("no access profiles needed for schema derivation"),
        parameterized_parts: BTreeMap::new(),
    };
    (project, binding)
}

fn domain_record(model: &GeneratedModel) -> Value {
    let members = model
        .fields
        .iter()
        .enumerate()
        .filter(|(_, field)| field.required || field.present)
        .map(|(index, field)| (field_name(index), field_value(field.kind, index)))
        .collect();
    Value::Object(members)
}

fn route_record(domain: &Value, wrapped: bool) -> Value {
    if wrapped {
        json!({
            "recordIdentifier": "generated-id",
            "revisionIdentifier": "generated-revision",
            "domainData": domain,
        })
    } else {
        domain.clone()
    }
}

fn served_operation(record_schema: Value, paginated: bool) -> ServedOperation {
    ServedOperation {
        operation: "records-find".to_owned(),
        method: HttpMethod::Get,
        method_path: "/records/generated-record".to_owned(),
        request_template: None,
        request_maximum_bytes: crate::load::DEFAULT_REQUEST_MAXIMUM_BYTES,
        filters: Vec::new(),
        record_type_parameter: "type".to_owned(),
        record_id_parameter: None,
        binding: "find-records".to_owned(),
        record_type: "generated-record".to_owned(),
        route_id: "generated-route".to_owned(),
        steps: Arc::new(Vec::new()),
        resilience: crate::resilience::ResilienceRuntime::empty(),
        maximum_upstream_calls: 1,
        response_envelope: crate::envelope::CompiledEnvelope::compile("{}", &BTreeMap::new())
            .expect("an empty envelope compiles for slot testing"),
        item_envelope: None,
        record_schema,
        pagination: paginated.then_some(ServedPagination {
            cursor_parameter: "cursor".to_owned(),
            page_size_parameter: "page-size".to_owned(),
            page_size_minimum: 1,
            page_size_maximum: 100,
            page_size_default: Some(20),
        }),
    }
}

fn slots_body(record: Value, paginated: bool) -> Value {
    if paginated {
        Value::Array(vec![record])
    } else {
        record
    }
}

fn disclosed_value<'a>(slots: &'a BTreeMap<&str, Value>, paginated: bool) -> &'a Value {
    if paginated {
        &slots["records"][0]
    } else {
        &slots["record"]
    }
}

const PROBLEM_ROOTS: &[ErrorClass] = &[
    ErrorClass::AggregationDuplicate,
    ErrorClass::BreakerOpen,
    ErrorClass::BudgetExhausted,
    ErrorClass::ConversionUnmapped,
    ErrorClass::CredentialRejected,
    ErrorClass::DisclosureViolation,
    ErrorClass::EgressRefused,
    ErrorClass::LoopMaximumIterationsReached,
    ErrorClass::Script,
    ErrorClass::ThrottleRejected,
    ErrorClass::Upstream,
    ErrorClass::Validation,
    ErrorClass::Outcome,
    ErrorClass::Facade,
];

fn problem_code(prefix: &str, class: ErrorClass) -> String {
    format!("generated.{prefix}-{}", class.class().replace('.', "-"))
}

fn problem(prefix: &str, class: ErrorClass) -> Problem {
    Problem {
        code: external(&problem_code(prefix, class)),
        status: BoundedU32::new(500).expect("problem status"),
        title: "generated problem".to_owned(),
        classes: UniqueList::new(vec![class]).expect("one class"),
    }
}

fn profile_with_problem_mapping(
    override_mask: u64,
    omitted_root: Option<ErrorClass>,
    duplicated_class: Option<ErrorClass>,
) -> AdapterProfile {
    let mut problems: Vec<_> = PROBLEM_ROOTS
        .iter()
        .copied()
        .filter(|root| Some(*root) != omitted_root)
        .map(|root| problem("root", root))
        .collect();
    for (index, class) in ErrorClass::ALL.iter().copied().enumerate() {
        if !PROBLEM_ROOTS.contains(&class) && override_mask & (1_u64 << index) != 0 {
            problems.push(problem("override", class));
        }
    }
    if let Some(class) = duplicated_class {
        problems.push(problem("duplicate", class));
    }
    AdapterProfile {
        id: local("generated-profile"),
        version: "1".to_owned(),
        operations: UniqueIdList::new(vec![ProfileOperation {
            id: local("records-find"),
            method: HttpMethod::Get,
            path: "/records/{type}".to_owned(),
            path_parameters: UniqueList::new(vec![local("type")]).expect("one path parameter"),
            record_type_parameter: local("type"),
            record_id_parameter: None,
            success_status: BoundedU32::new(200).expect("success status"),
            request_envelope: None,
            read_only: false,
            request_maximum_bytes: None,
            response_envelope: EnvelopeTemplate(r#"{"records": {{records}}}"#.to_owned()),
            item_envelope: None,
            pagination: None,
        }])
        .expect("one operation"),
        problems: UniqueIdList::new(problems).expect("problem codes are unique"),
        problem_envelope: EnvelopeTemplate(r#"{"code": "{{problemCode}}"}"#.to_owned()),
        parameterized_parts: UniqueList::new(Vec::new()).expect("no parameterized parts"),
    }
}

fn has_finding(profile: &AdapterProfile, code: &str) -> bool {
    check_profile(profile)
        .iter()
        .any(|finding| finding.code.as_str() == code)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        rng_seed: RngSeed::Fixed(0x1305_d15c_105e),
        failure_persistence: Some(Box::new(FileFailurePersistence::SourceParallel(
            "proptest-regressions",
        ))),
        .. ProptestConfig::default()
    })]

    /// The core derives a closed schema from each generated declaration,
    /// and the real facade release point admits exactly valid domain data.
    /// Undeclared, missing, mistyped, and wrapper-only canaries are explicit
    /// negative counterexamples in every generated case.
    #[test]
    fn generated_route_outputs_never_escape_the_declared_model(model in generated_model()) {
        let (project, binding) = project_for(&model);
        let schema = binding_record_schema(&project, &binding)
            .expect("the generated binding derives a record schema");
        let operation = served_operation(schema, model.paginated);
        let domain = domain_record(&model);
        let admitted = route_record(&domain, model.wrapped);
        let body = slots_body(admitted, model.paginated);
        let slots = disclosed_slots(
            &operation,
            &body,
            model.paginated.then_some(1),
            "generated-record",
            "generated-request",
        )
        .expect("the declared output is disclosed");
        prop_assert_eq!(disclosed_value(&slots, model.paginated), &domain);

        let mut undeclared = domain.clone();
        undeclared
            .as_object_mut()
            .expect("a generated record is an object")
            .insert("undeclared-canary".to_owned(), Value::String("must-not-escape".to_owned()));
        let leaked = slots_body(route_record(&undeclared, model.wrapped), model.paginated);
        prop_assert!(disclosed_slots(
            &operation,
            &leaked,
            model.paginated.then_some(1),
            "generated-record",
            "generated-request",
        ).is_err());

        let mut missing = domain.clone();
        missing
            .as_object_mut()
            .expect("a generated record is an object")
            .remove(&field_name(0));
        let missing = slots_body(route_record(&missing, model.wrapped), model.paginated);
        prop_assert!(disclosed_slots(
            &operation,
            &missing,
            model.paginated.then_some(1),
            "generated-record",
            "generated-request",
        ).is_err());

        let mut mistyped = domain.clone();
        mistyped
            .as_object_mut()
            .expect("a generated record is an object")
            .insert(field_name(0), Value::Null);
        let mistyped = slots_body(route_record(&mistyped, model.wrapped), model.paginated);
        prop_assert!(disclosed_slots(
            &operation,
            &mistyped,
            model.paginated.then_some(1),
            "generated-record",
            "generated-request",
        ).is_err());

        let invalid_wrapper = json!({
            "recordIdentifier": "generated-id",
            "domainData": domain,
            "internal-canary": "must-not-escape",
        });
        let invalid_wrapper = slots_body(invalid_wrapper, model.paginated);
        prop_assert!(disclosed_slots(
            &operation,
            &invalid_wrapper,
            model.paginated.then_some(1),
            "generated-record",
            "generated-request",
        ).is_err());
    }

    /// The authoring checker admits generated root mappings with arbitrary
    /// narrower overrides, and the facade resolves every class. Removing a
    /// generated root or repeating a declared class exercises the two
    /// concrete authoring counterexamples required by totality.
    #[test]
    fn generated_problem_mappings_are_total_and_checker_enforced(
        override_mask in any::<u64>(),
        missing_root_index in 0_usize..PROBLEM_ROOTS.len(),
        duplicate_index in 0_usize..PROBLEM_ROOTS.len(),
    ) {
        let profile = profile_with_problem_mapping(override_mask, None, None);
        let findings = check_profile(&profile);
        prop_assert!(findings.is_empty(), "generated total mapping was refused: {findings:?}");
        for class in ErrorClass::ALL.iter().copied() {
            prop_assert!(select_problem(&profile, class).is_some(), "{} did not resolve", class.class());
        }

        // Source failures the closed hierarchy distinguishes still fall
        // back to the profile's upstream root unless this generated profile
        // explicitly overrides that leaf.
        for class in [
            ErrorClass::UpstreamHttp,
            ErrorClass::UpstreamTimeout,
            ErrorClass::UpstreamConnection,
            ErrorClass::UpstreamMalformed,
            ErrorClass::UpstreamTooLarge,
            ErrorClass::UpstreamRedirect,
        ] {
            let selected = select_problem(&profile, class).expect("an upstream problem");
            let class_index = ErrorClass::ALL
                .iter()
                .position(|candidate| *candidate == class)
                .expect("the class is inventoried");
            let expected = if override_mask & (1_u64 << class_index) != 0 {
                problem_code("override", class)
            } else {
                problem_code("root", ErrorClass::Upstream)
            };
            prop_assert_eq!(selected.code.as_str(), expected);
        }

        let missing = profile_with_problem_mapping(
            override_mask,
            Some(PROBLEM_ROOTS[missing_root_index]),
            None,
        );
        prop_assert!(has_finding(&missing, UNRESOLVED_CODE));

        let duplicated = profile_with_problem_mapping(
            override_mask,
            None,
            Some(PROBLEM_ROOTS[duplicate_index]),
        );
        prop_assert!(has_finding(&duplicated, DUPLICATE_CODE));
    }
}

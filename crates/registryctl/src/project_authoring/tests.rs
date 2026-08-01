// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_starter_provenance_matches_authored_content() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let starters = [
            (
                "http",
                manifest_dir.join("assets/project-starters/bounded-http"),
            ),
            (
                "spreadsheet",
                manifest_dir.join("assets/project-starters/spreadsheet"),
            ),
            (
                "dhis2-tracker",
                manifest_dir.join("tests/fixtures/project-authoring/dhis2-tracker"),
            ),
            (
                "opencrvs-dci",
                manifest_dir.join("tests/fixtures/project-authoring/opencrvs"),
            ),
            (
                "fhir-r4",
                manifest_dir.join("tests/fixtures/project-authoring/fhir-r4-coverage-active"),
            ),
            (
                "snapshot",
                manifest_dir.join("tests/fixtures/project-authoring/snapshot-exact"),
            ),
        ];
        let mut mismatches = Vec::new();
        for (expected_id, path) in starters {
            let loaded = load_registry_project(&path, None).expect("starter loads");
            let provenance = loaded.project.starter.as_ref().expect("starter provenance");
            assert_eq!(provenance.id, expected_id);
            if provenance.content_digest != loaded.project_content_digest {
                mismatches.push(format!(
                    "{expected_id}: expected {}, calculated {}",
                    provenance.content_digest, loaded.project_content_digest
                ));
            }
        }
        for (expected_id, directory) in [
            ("http", "bounded-http"),
            ("spreadsheet", "spreadsheet"),
        ] {
            let temporary = tempfile::tempdir().expect("temporary embedded starter");
            copy_embedded_dir(
                PROJECT_STARTERS
                    .get_dir(directory)
                    .expect("embedded starter exists"),
                temporary.path(),
            )
            .expect("embedded starter copies");
            let loaded =
                load_registry_project(temporary.path(), None).expect("embedded starter loads");
            let provenance = loaded
                .project
                .starter
                .as_ref()
                .expect("embedded starter provenance");
            assert_eq!(provenance.id, expected_id);
            if provenance.content_digest != loaded.project_content_digest {
                mismatches.push(format!(
                    "{expected_id} embedded: expected {}, calculated {}",
                    provenance.content_digest, loaded.project_content_digest
                ));
            }
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    #[test]
    fn evidence_subject_type_is_closed_and_omission_normalizes_to_person() {
        let bytes = PROJECT_STARTERS
            .get_file("bounded-http/registry-stack.yaml")
            .expect("bounded HTTP project is embedded")
            .contents();
        let omitted =
            parse_current_authoring_document::<RegistryProject>(bytes).expect("project parses");
        let service = &omitted.services["person-verification"];
        assert_eq!(service.subject_type, None);
        assert_eq!(
            service.effective_subject_type(),
            EvidenceSubjectType::Person
        );
        assert!(
            serde_json::to_value(&omitted)
                .expect("project serializes")
                .pointer("/services/person-verification/subject_type")
                .is_none(),
            "normalized omission must preserve authored-content serialization"
        );

        let mut invalid: Value = serde_norway::from_slice(bytes).expect("project YAML parses");
        invalid["services"]["person-verification"]["subject_type"] = json!("organisation");
        let invalid_bytes =
            serde_norway::to_string(&invalid).expect("invalid subject project serializes");
        parse_current_authoring_document::<RegistryProject>(invalid_bytes.as_bytes())
            .expect_err("unknown evidence subject type must fail closed");

        invalid["services"]["person-verification"]["subject_type"] = json!("project");
        let project_bytes =
            serde_norway::to_string(&invalid).expect("project subject project serializes");
        let explicit =
            parse_current_authoring_document::<RegistryProject>(project_bytes.as_bytes())
                .expect("project is an allowed subject type");
        assert_eq!(
            explicit.services["person-verification"].subject_type,
            Some(EvidenceSubjectType::Project)
        );
    }

    #[test]
    fn records_service_rejects_an_explicit_evidence_subject_type() {
        let bytes = PROJECT_STARTERS
            .get_file("spreadsheet/registry-stack.yaml")
            .expect("spreadsheet project is embedded")
            .contents();
        let mut value: Value = serde_norway::from_slice(bytes).expect("project YAML parses");
        value["services"]["projects-records"]["subject_type"] = json!("person");
        let invalid = serde_norway::to_string(&value).expect("records subject project serializes");
        parse_current_authoring_document::<RegistryProject>(invalid.as_bytes())
            .expect_err("public schema rejects evidence fields on records services");

        let typed: RegistryProject =
            serde_norway::from_str(&invalid).expect("presence-aware typed model retains the field");
        let error = validate_project_shape(&typed)
            .expect_err("typed validation also rejects evidence fields on records services");
        assert!(error
            .to_string()
            .contains("records_api service cannot declare evidence-service fields"));
    }

    #[test]
    fn corrected_http_authoring_lowers_to_one_product_neutral_request() {
        let authored: AuthoredIntegrationDocument = serde_norway::from_str(
            r#"
version: 1
id: person-status
revision: 1
source:
  product: previously-unknown-registry
  versions: { unverified: [deployment-api-7] }
  auth: { type: none }
input:
  person_id:
    role: selector
    type: string
    maxLength: 64
capability:
  http:
    request:
      method: GET
      path: /people/{input.person_id}
    response:
      no_match: [404]
outputs:
  active:
    type: boolean
    x-registry-source: /active
"#,
        )
        .expect("corrected http authoring parses");
        let lowered =
            lower_authored_integration(&authored).expect("corrected http authoring lowers");
        let CapabilityDeclaration::Http { http } = lowered.capability else {
            panic!("http capability remains http");
        };
        assert_eq!(http.operations.len(), 1);
        let operation = &http.operations["request"];
        let request = &operation.request;
        assert_eq!(request.path, "/people/{person_id}");
        assert_eq!(operation.response.max_bytes, 512 * 1024);
        assert!(matches!(
            operation.response.schema,
            SchemaNode::Object {
                additional_fields: AdditionalFields::Ignore,
                ..
            }
        ));
        assert_eq!(
            lowered.source.product.as_deref(),
            Some("previously-unknown-registry")
        );
        assert_eq!(lowered.outputs.len(), 1);
    }

    #[test]
    fn date_outputs_keep_the_typed_contract_without_a_string_bound() {
        let entity_field: EntityFieldSchema = serde_norway::from_str(
            r#"type: string
format: date
maxLength: 10
"#,
        )
        .expect("date entity field parses");
        let (output_type, nullable, max_bytes) =
            entity_output_contract("birth_date", &entity_field).expect("date field lowers");
        assert_eq!(output_type, OutputType::Date);
        assert!(!nullable);
        assert_eq!(max_bytes, None);
        validate_snapshot_output(
            "birth_date",
            &OutputDeclaration {
                output_type,
                nullable,
                max_bytes,
                minimum: None,
                maximum: None,
                structured_schema: None,
                from: Some("snapshot.record.birth_date".to_string()),
                source_pointer: None,
            },
        )
        .expect("typed snapshot date validates");

        let authored: AuthoredIntegrationDocument = serde_norway::from_str(
            r#"
version: 1
id: person-birth-date
revision: 1
source: { auth: { type: none } }
input:
  person_id: { role: selector, type: string, maxLength: 64 }
capability:
  http:
    request: { method: GET, path: '/people/{input.person_id}' }
outputs:
  birth_date:
    type: string
    format: date
    maxLength: 10
    x-registry-source: /birth_date
"#,
        )
        .expect("date HTTP authoring parses");
        let lowered = lower_authored_integration(&authored).expect("date HTTP authoring lowers");
        let output = &lowered.outputs["birth_date"];
        assert_eq!(output.output_type, OutputType::Date);
        assert_eq!(output.max_bytes, None);
        validate_output(output, integration_operations(&lowered))
            .expect("typed HTTP date validates");
    }

    #[test]
    fn integer_entity_fields_enforce_json_safe_bounds() {
        let safe: EntityFieldSchema = serde_norway::from_str(
            r#"type: integer
minimum: -9007199254740991
maximum: 9007199254740991
"#,
        )
        .expect("JSON-safe entity field parses");
        let (output_type, nullable, max_bytes) =
            entity_output_contract("sequence", &safe).expect("JSON-safe entity field lowers");
        assert_eq!(output_type, OutputType::Integer);
        assert!(!nullable);
        assert_eq!(max_bytes, None);

        for (name, source) in [
            (
                "below",
                "type: integer\nminimum: -9007199254740992\nmaximum: 1\n",
            ),
            (
                "above",
                "type: integer\nminimum: 0\nmaximum: 9007199254740992\n",
            ),
        ] {
            let field: EntityFieldSchema =
                serde_norway::from_str(source).expect("adjacent unsafe entity field parses");
            assert!(
                entity_output_contract(name, &field)
                    .expect_err("adjacent unsafe entity field rejects")
                    .to_string()
                    .contains("incompatible constraints"),
                "{name} must fail at the runtime authority"
            );
        }
    }

    #[test]
    fn integer_integration_outputs_enforce_json_safe_bounds_recursively() {
        let safe: AuthoredOutputDeclaration = serde_norway::from_str(
            r#"type: object
max_bytes: 1024
fields:
  direct:
    required: true
    schema:
      type: integer
      minimum: -9007199254740991
      maximum: 9007199254740991
  nested:
    required: true
    schema:
      type: array
      max_bytes: 512
      max_items: 2
      items:
        type: integer
        minimum: -9007199254740991
        maximum: 9007199254740991
"#,
        )
        .expect("nested JSON-safe output contract parses");
        let mut nodes = OUTPUT_SCHEMA_ENVELOPE_NODES_V1;
        validate_authored_output("sequence", &safe, &mut nodes)
            .expect("nested JSON-safe integer boundaries validate");

        for (name, source) in [
            (
                "nested object lower bound",
                r#"type: object
max_bytes: 256
fields:
  sequence:
    required: true
    schema:
      type: integer
      minimum: -9007199254740992
      maximum: 0
"#,
            ),
            (
                "nested array upper bound",
                r#"type: array
max_bytes: 256
max_items: 2
items:
  type: integer
  minimum: 0
  maximum: 9007199254740992
"#,
            ),
        ] {
            let output: AuthoredOutputDeclaration =
                serde_norway::from_str(source).expect("adjacent unsafe output contract parses");
            let mut nodes = OUTPUT_SCHEMA_ENVELOPE_NODES_V1;
            assert!(
                validate_authored_output("sequence", &output, &mut nodes)
                    .expect_err("adjacent unsafe nested integer bound rejects")
                    .to_string()
                    .contains("Integer schema has invalid constraints"),
                "{name} must fail during recursive authoring validation"
            );
        }
    }

    #[test]
    fn structured_script_output_lowers_recursively_with_closed_bounded_fields() {
        let authored = r#"type: array
max_bytes: 1024
max_items: 2
items:
  type: object
  max_bytes: 384
  fields:
    type:
      required: true
      schema: { type: string, maxLength: 16 }
    name:
      required: true
      schema: { type: string, maxLength: 160 }
    identifier:
      required: false
      schema: { type: [string, "null"], maxLength: 64 }
"#;
        let output: AuthoredOutputDeclaration =
            serde_norway::from_str(authored).expect("structured output parses");
        let mut nodes = OUTPUT_SCHEMA_ENVELOPE_NODES_V1;
        let expanded = validate_authored_output("parents", &output, &mut nodes)
            .expect("structured output validates");
        assert_eq!(nodes, OUTPUT_SCHEMA_ENVELOPE_NODES_V1 + 5);
        assert_eq!(expanded, 9);

        let lowered = lower_output_map(
            &BTreeMap::from([("parents".to_string(), output)]),
            "birth",
            false,
        )
        .expect("structured script output lowers");
        let parents = &lowered["parents"];
        assert_eq!(parents.output_type, OutputType::Array);
        assert_eq!(parents.max_bytes, Some(1024));
        assert!(parents.from.is_none());
        let Some(StructuredOutputSchema::Array {
            nullable,
            max_bytes,
            max_items,
            items,
        }) = &parents.structured_schema
        else {
            panic!("parents must retain its recursive schema");
        };
        assert!(!nullable);
        assert_eq!(*max_bytes, 1024);
        assert_eq!(*max_items, 2);
        let StructuredOutputSchema::Object { fields, .. } = items.as_ref() else {
            panic!("parents items must be objects");
        };
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            ["identifier", "name", "type"]
        );
        assert!(!fields["identifier"].required);
        assert!(matches!(
            fields["identifier"].schema.as_ref(),
            StructuredOutputSchema::String {
                nullable: true,
                max_bytes: 256
            }
        ));

        assert!(lower_output_map(
            &BTreeMap::from([(
                "parents".to_string(),
                serde_norway::from_str(authored).expect("structured output parses again"),
            )]),
            "birth",
            true,
        )
        .expect_err("HTTP cannot author structured output projection")
        .to_string()
        .contains("require capability.script"));
    }

    #[test]
    fn structured_output_nullability_uses_the_one_scalar_type_union_idiom() {
        fn parse(source: &str) -> AuthoredOutputDeclaration {
            serde_norway::from_str(source).expect("structured output parses")
        }

        fn lower(name: &str, output: AuthoredOutputDeclaration) -> OutputDeclaration {
            let mut nodes = OUTPUT_SCHEMA_ENVELOPE_NODES_V1;
            validate_authored_output(name, &output, &mut nodes)
                .expect("union-typed structured output validates");
            lower_output_map(
                &BTreeMap::from([(name.to_string(), output)]),
                "birth",
                false,
            )
            .expect("union-typed structured output lowers")
            .remove(name)
            .expect("the lowered output is present")
        }

        let nullable_object = lower(
            "record",
            parse(
                r#"type: [object, "null"]
max_bytes: 64
fields:
  active:
    required: true
    schema: { type: boolean }
"#,
            ),
        );
        assert_eq!(nullable_object.output_type, OutputType::Object);
        assert!(nullable_object.nullable);
        assert!(matches!(
            nullable_object.structured_schema,
            Some(StructuredOutputSchema::Object {
                nullable: true,
                ..
            })
        ));

        let required_object = lower(
            "record",
            parse(
                r#"type: object
max_bytes: 64
fields:
  active:
    required: true
    schema: { type: boolean }
"#,
            ),
        );
        assert!(!required_object.nullable);
        assert!(matches!(
            required_object.structured_schema,
            Some(StructuredOutputSchema::Object {
                nullable: false,
                ..
            })
        ));

        let nullable_array = lower(
            "records",
            parse(
                r#"type: [array, "null"]
max_bytes: 64
max_items: 2
items: { type: boolean }
"#,
            ),
        );
        assert_eq!(nullable_array.output_type, OutputType::Array);
        assert!(nullable_array.nullable);
        assert!(matches!(
            nullable_array.structured_schema,
            Some(StructuredOutputSchema::Array {
                nullable: true,
                ..
            })
        ));

        let required_array = lower(
            "records",
            parse(
                r#"type: array
max_bytes: 64
max_items: 2
items: { type: boolean }
"#,
            ),
        );
        assert!(!required_array.nullable);

        let nested = parse(
            r#"type: [array, "null"]
max_bytes: 512
max_items: 2
items:
  type: [object, "null"]
  max_bytes: 128
  fields:
    identifier:
      required: false
      schema: { type: [string, "null"], maxLength: 16 }
"#,
        );
        let mut nodes = OUTPUT_SCHEMA_ENVELOPE_NODES_V1;
        validate_authored_output("parents", &nested, &mut nodes)
            .expect("a nested union-typed structured output validates");

        for retired in [
            concat!(
                "type: object\n",
                "nullable: true\n",
                "max_bytes: 64\n",
                "fields:\n",
                "  active:\n",
                "    required: true\n",
                "    schema: { type: boolean }\n"
            ),
            concat!(
                "type: array\n",
                "nullable: false\n",
                "max_bytes: 64\n",
                "max_items: 2\n",
                "items: { type: boolean }\n"
            ),
        ] {
            assert!(
                serde_norway::from_str::<AuthoredOutputDeclaration>(retired).is_err(),
                "the retired composite `nullable` key must not parse: {retired}"
            );
        }

        for null_only in [
            r#"type: ["null"]
max_bytes: 64
fields:
  active:
    required: true
    schema: { type: boolean }
"#,
            r#"type: ["null", object]
max_bytes: 64
fields:
  active:
    required: true
    schema: { type: boolean }
"#,
            r#"type: [array, "null"]
max_bytes: 64
fields:
  active:
    required: true
    schema: { type: boolean }
"#,
        ] {
            assert!(
                serde_norway::from_str::<AuthoredOutputDeclaration>(null_only).is_err(),
                "only `[<composite>, \"null\"]` is an authored union: {null_only}"
            );
        }
    }

    #[test]
    fn authored_output_count_preserves_the_generic_non_notary_limit() {
        fn boolean_output() -> AuthoredOutputDeclaration {
            AuthoredOutputDeclaration::Scalar(AuthoredScalarOutputDeclaration {
                output_type: AuthoredSchemaType::Single(AuthoredScalarType::Boolean),
                format: None,
                max_length: None,
                minimum: None,
                maximum: None,
                source: None,
            })
        }

        const {
            assert!(MAX_OUTPUTS > registry_notary_core::MAX_RELAY_OUTPUT_OBJECT_FIELDS_V1);
        }
        let outputs = |count| {
            (0..count)
                .map(|index| (format!("field_{index}"), boolean_output()))
                .collect::<BTreeMap<_, _>>()
        };
        validate_authored_outputs(&outputs(
            registry_notary_core::MAX_RELAY_OUTPUT_OBJECT_FIELDS_V1 + 1,
        ))
        .expect("generic authoring retains more outputs than a Notary consultation");
        validate_authored_outputs(&outputs(MAX_OUTPUTS))
            .expect("the generic integration output limit validates");
        assert!(validate_authored_outputs(&outputs(MAX_OUTPUTS + 1))
            .expect_err("one output beyond the generic integration limit rejects")
            .to_string()
            .contains(&format!("between one and {MAX_OUTPUTS} fields")));
    }

    #[test]
    fn notary_output_count_applies_only_to_evidence_consultations() {
        let mut evidence =
            load_registry_project(&project_golden("opencrvs"), None).expect("OpenCRVS project loads");
        let birth = evidence
            .integrations
            .get_mut("birth-record")
            .expect("birth integration exists");
        let template = serde_json::to_value(&birth.document.outputs["sex"])
            .expect("scalar output serializes");
        while birth.document.outputs.len()
            <= registry_notary_core::MAX_RELAY_OUTPUT_OBJECT_FIELDS_V1
        {
            let index = birth.document.outputs.len();
            birth.document.outputs.insert(
                format!("extra_{index}"),
                serde_json::from_value(template.clone()).expect("scalar output clones"),
            );
        }
        validate_integration("birth-record", &birth.document)
            .expect("the generic integration contract still accepts 33 outputs");
        let error = validate_service_integration_links(&evidence.project, &evidence.integrations)
            .expect_err("an Evidence consultation cannot exceed the Notary output limit");
        assert!(error.to_string().contains(&format!(
            "integration outputs must contain no more than {} entries",
            registry_notary_core::MAX_RELAY_OUTPUT_OBJECT_FIELDS_V1
        )));

        let records_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("assets/project-starters/spreadsheet");
        let mut records =
            load_registry_project(&records_root, None).expect("Records API project loads");
        records.project.integrations.insert(
            "wide".to_string(),
            IntegrationReference {
                file: PathBuf::from("integrations/wide/integration.yaml"),
            },
        );
        records.integrations.insert(
            "wide".to_string(),
            evidence
                .integrations
                .remove("birth-record")
                .expect("wide integration remains available"),
        );
        validate_project_shape(&records.project)
            .expect("a Records API-only project may retain the generic integration limit");
        validate_service_integration_links(&records.project, &records.integrations)
            .expect("Records API-only integrations are not narrowed to the Notary limit");
    }

    #[test]
    fn structured_output_byte_caps_must_encode_a_non_null_value() {
        fn validate(source: &str) -> Result<()> {
            let output: AuthoredOutputDeclaration =
                serde_norway::from_str(source).expect("structured output parses");
            let mut nodes = OUTPUT_SCHEMA_ENVELOPE_NODES_V1;
            validate_authored_output("record", &output, &mut nodes).map(|_| ())
        }

        let required_boolean = |max_bytes| {
            format!(
                r#"type: object
max_bytes: {max_bytes}
fields:
  active:
    required: true
    schema: {{ type: boolean }}
"#
            )
        };
        assert!(validate(&required_boolean(14))
            .expect_err("a cap below the required-member encoding rejects")
            .to_string()
            .contains("must be at least 15"));
        validate(&required_boolean(15))
            .expect("the exact compact encoding bound for the required member validates");

        let array = |max_bytes| {
            format!(
                r#"type: array
max_bytes: {max_bytes}
max_items: 1
items: {{ type: boolean }}
"#
            )
        };
        assert!(validate(&array(1))
            .expect_err("a cap below the empty-array encoding rejects")
            .to_string()
            .contains("must be at least 2"));
        validate(&array(2)).expect("the empty-array encoding bound validates");

        let nested = r#"type: object
max_bytes: 64
fields:
  child:
    required: true
    schema:
      type: object
      max_bytes: 1
      fields:
        active:
          required: false
          schema: { type: boolean }
"#;
        assert!(validate(nested)
            .expect_err("an impossible nested object cap rejects")
            .to_string()
            .contains("outputs.record.fields.child.schema.max_bytes must be at least 2"));
    }

    #[test]
    fn structured_output_limits_reserve_the_notary_result_envelope() {
        fn boolean_schema() -> AuthoredOutputSchema {
            AuthoredOutputSchema::Scalar(AuthoredScalarOutputSchema {
                output_type: AuthoredSchemaType::Single(AuthoredScalarType::Boolean),
                format: None,
                max_length: None,
                minimum: None,
                maximum: None,
            })
        }

        fn boolean_output() -> AuthoredOutputDeclaration {
            AuthoredOutputDeclaration::Scalar(AuthoredScalarOutputDeclaration {
                output_type: AuthoredSchemaType::Single(AuthoredScalarType::Boolean),
                format: None,
                max_length: None,
                minimum: None,
                maximum: None,
                source: None,
            })
        }

        fn object_declaration(field_count: usize) -> AuthoredOutputObjectDeclaration {
            AuthoredOutputObjectDeclaration {
                output_type: AuthoredObjectSchemaType::Single(
                    AuthoredOutputObjectType::Object,
                ),
                max_bytes: 65_536,
                fields: (0..field_count)
                    .map(|index| {
                        (
                            format!("field_{index}"),
                            AuthoredOutputObjectField {
                                required: true,
                                schema: Box::new(boolean_schema()),
                            },
                        )
                    })
                    .collect(),
            }
        }

        fn object_output(field_count: usize) -> AuthoredOutputDeclaration {
            AuthoredOutputDeclaration::Object(object_declaration(field_count))
        }

        fn array_output(array_nodes: usize) -> AuthoredOutputDeclaration {
            assert!(array_nodes > 0);
            let mut items = boolean_schema();
            for _ in 1..array_nodes {
                items = AuthoredOutputSchema::Array(AuthoredOutputArrayDeclaration {
                    output_type: AuthoredArraySchemaType::Single(
                        AuthoredOutputArrayType::Array,
                    ),
                    max_bytes: 65_536,
                    max_items: 1,
                    items: Box::new(items),
                });
            }
            AuthoredOutputDeclaration::Array(AuthoredOutputArrayDeclaration {
                output_type: AuthoredArraySchemaType::Single(
                    AuthoredOutputArrayType::Array,
                ),
                max_bytes: 65_536,
                max_items: 1,
                items: Box::new(items),
            })
        }

        let maximum_depth = BTreeMap::from([("nested".to_string(), array_output(5))]);
        validate_authored_outputs(&maximum_depth)
            .expect("five array nodes plus one leaf fit downstream depth eight");
        let excessive_depth = BTreeMap::from([("nested".to_string(), array_output(6))]);
        assert_eq!(
            validate_authored_outputs(&excessive_depth)
                .expect_err("one more nested node exceeds downstream depth eight")
                .to_string(),
            "outputs.nested.items.items.items.items.items.items schema exceeds the maximum depth of 8",
            "a recursive depth rejection must name the nested authored path, not just the output"
        );

        let node_budget = |extra_scalars| {
            let mut outputs = (0..7)
                .map(|index| (format!("wide_{index}"), object_output(32)))
                .collect::<BTreeMap<_, _>>();
            for index in 0..(5 + extra_scalars) {
                outputs.insert(format!("scalar_{index}"), boolean_output());
            }
            outputs
        };
        validate_authored_outputs(&node_budget(0))
            .expect("236 authored nodes plus the 20-node envelope fit exactly");
        assert!(validate_authored_outputs(&node_budget(1))
            .expect_err("237 authored nodes exceed the downstream node budget")
            .to_string()
            .contains("more than 256 nodes"));

        let expanded_output = |field_count| {
            BTreeMap::from([(
                "expanded".to_string(),
                AuthoredOutputDeclaration::Array(AuthoredOutputArrayDeclaration {
                    output_type: AuthoredArraySchemaType::Single(
                        AuthoredOutputArrayType::Array,
                    ),
                    max_bytes: 65_536,
                    max_items: 255,
                    items: Box::new(AuthoredOutputSchema::Object(object_declaration(field_count))),
                }),
            )])
        };
        validate_authored_outputs(&expanded_output(14))
            .expect("expanded schema remains below the downstream envelope-adjusted bound");
        assert!(validate_authored_outputs(&expanded_output(15))
            .expect_err("the result envelope pushes expanded nodes beyond 4096")
            .to_string()
            .contains("recursive expansion exceeds 4096 nodes"));
    }

    #[test]
    fn corrected_authoring_rejects_the_superseded_operation_graph() {
        serde_norway::from_str::<AuthoredIntegrationDocument>(
            r#"
version: 1
id: obsolete-flow
revision: 1
source:
  auth: { type: none }
input:
  person_id: { role: selector, type: string, maxLength: 64 }
capability:
  http:
    operations: {}
outputs:
  active: { type: boolean, x-registry-source: /active }
"#,
        )
        .expect_err("operation graph has no authoring alias");
    }

    #[test]
    fn typed_authoring_preserves_roles_scalar_contracts_and_conservative_bounds() {
        let authored: AuthoredIntegrationDocument = serde_norway::from_str(
            r#"
version: 1
id: typed-person-status
revision: 3
source:
  product: generic-registry
  versions: { unverified: [api-1] }
  auth: { type: none }
input:
  person_id:
    role: selector
    type: string
    minLength: 4
    maxLength: 64
    pattern: '^[A-Z0-9]+$'
    enum: [ABCD, ABCD1234]
    const: ABCD1234
  as_of:
    role: selector
    type: string
    format: date
    minLength: 10
    maxLength: 10
  include_archived:
    role: parameter
    type: [boolean, "null"]
    enum: [true, false, null]
  page:
    role: parameter
    type: integer
    minimum: 1
    maximum: 9007199254740991
capability:
  http:
    request: { method: GET, path: '/people/{input.person_id}' }
outputs:
  active: { type: boolean, x-registry-source: /active }
"#,
        )
        .expect("typed authoring parses");
        let lowered = lower_authored_integration(&authored).expect("typed authoring lowers");
        let person_id = &lowered.input["person_id"];
        assert_eq!(person_id.role, AuthoredInputRole::Selector);
        assert_eq!(person_id.input_type, InputType::String);
        assert!(!person_id.nullable);
        assert_eq!(person_id.min_length, Some(4));
        assert_eq!(person_id.max_length, Some(64));
        assert_eq!(person_id.bytes, 256);
        assert_eq!(person_id.enum_values.as_ref().map(Vec::len), Some(2));
        assert_eq!(person_id.const_value, Some(json!("ABCD1234")));

        let as_of = &lowered.input["as_of"];
        assert_eq!(as_of.input_type, InputType::FullDate);
        assert_eq!(
            as_of.bytes, 10,
            "date uses its encoded bound, not maxLength * 4"
        );

        let boolean = &lowered.input["include_archived"];
        assert_eq!(boolean.role, AuthoredInputRole::Parameter);
        assert_eq!(boolean.input_type, InputType::Boolean);
        assert!(boolean.nullable);
        assert_eq!(boolean.bytes, 5);

        let integer = &lowered.input["page"];
        assert_eq!(integer.input_type, InputType::Integer);
        assert_eq!(integer.minimum, Some(1));
        assert_eq!(integer.maximum, Some(9_007_199_254_740_991));
        assert_eq!(integer.bytes, 16);
    }

    #[test]
    fn generated_input_slots_use_the_relay_closed_typed_shape() {
        let parameter = InputDeclaration {
            role: AuthoredInputRole::Parameter,
            input_type: InputType::Integer,
            nullable: true,
            max_length: None,
            min_length: None,
            bytes: 4,
            pattern: None,
            enum_values: None,
            const_value: None,
            canonicalization: Canonicalization::Identity,
            minimum: Some(-10),
            maximum: Some(20),
        };
        assert_eq!(
            relay_input_slot(&parameter).expect("typed Relay input slot lowers"),
            json!({
                "role": "parameter",
                "type": ["integer", "null"],
                "x-registry-canonicalization": "identity",
                "minimum": -10,
                "maximum": 20,
            })
        );
    }

    #[test]
    fn typed_input_limits_fail_closed() {
        let base = r#"
version: 1
id: bounded-inputs
revision: 1
source: { auth: { type: none } }
input:
  subject: { role: selector, type: string, maxLength: 64 }
capability:
  http:
    request: { method: GET, path: '/people/{input.subject}' }
outputs:
  active: { type: boolean, x-registry-source: /active }
"#;
        let nullable_selector = base.replace(
            "type: string, maxLength: 64",
            "type: [string, \"null\"], maxLength: 64",
        );
        let authored: AuthoredIntegrationDocument =
            serde_norway::from_str(&nullable_selector).expect("nullable selector parses");
        assert!(lower_authored_integration(&authored)
            .expect_err("nullable selector rejects")
            .to_string()
            .contains("selector inputs cannot be nullable"));

        let safe_integer = base.replace(
            "type: string, maxLength: 64",
            "type: integer, minimum: -9007199254740991, maximum: 9007199254740991",
        );
        let authored: AuthoredIntegrationDocument =
            serde_norway::from_str(&safe_integer).expect("JSON-safe integer parses");
        lower_authored_integration(&authored).expect("JSON-safe integer lowers");

        let unsafe_lower_integer = base.replace(
            "type: string, maxLength: 64",
            "type: integer, minimum: -9007199254740992, maximum: 1",
        );
        let authored: AuthoredIntegrationDocument =
            serde_norway::from_str(&unsafe_lower_integer).expect("unsafe lower integer parses");
        assert!(lower_authored_integration(&authored)
            .expect_err("unsafe lower integer rejects")
            .to_string()
            .contains("Integer schema has incompatible constraints"));

        let unsafe_upper_integer = base.replace(
            "type: string, maxLength: 64",
            "type: integer, minimum: 0, maximum: 9007199254740992",
        );
        let authored: AuthoredIntegrationDocument =
            serde_norway::from_str(&unsafe_upper_integer).expect("unsafe upper integer parses");
        assert!(lower_authored_integration(&authored)
            .expect_err("unsafe upper integer rejects")
            .to_string()
            .contains("Integer schema has incompatible constraints"));

        let boundary_selector = base.replace("maxLength: 64", "maxLength: 1024");
        let authored: AuthoredIntegrationDocument =
            serde_norway::from_str(&boundary_selector).expect("boundary selector parses");
        lower_authored_integration(&authored).expect("4096-byte selector lowers");

        let oversized_selector = base.replace("maxLength: 64", "maxLength: 1025");
        let authored: AuthoredIntegrationDocument =
            serde_norway::from_str(&oversized_selector).expect("oversized selector parses");
        assert!(lower_authored_integration(&authored)
            .expect_err("aggregate selector bytes reject")
            .to_string()
            .contains("exceeds 4096 bytes"));
    }

    #[test]
    fn typed_input_cardinality_accepts_sixteen_total_and_eight_selectors() {
        fn authored_with_inputs(selectors: usize, parameters: usize) -> String {
            let mut input = String::new();
            for index in 0..selectors {
                input.push_str(&format!(
                    "  selector_{index}: {{ role: selector, type: string, maxLength: 8 }}\n"
                ));
            }
            for index in 0..parameters {
                input.push_str(&format!(
                    "  parameter_{index}: {{ role: parameter, type: [boolean, \"null\"] }}\n"
                ));
            }
            format!(
                r#"
version: 1
id: composite-selector
revision: 1
source: {{ auth: {{ type: none }} }}
input:
{input}capability:
  http:
    request: {{ method: GET, path: /people }}
outputs:
  active: {{ type: boolean, x-registry-source: /active }}
"#
            )
        }

        let authored: AuthoredIntegrationDocument =
            serde_norway::from_str(&authored_with_inputs(8, 8))
                .expect("maximum typed input map parses");
        assert_eq!(
            lower_authored_integration(&authored)
                .expect("eight selectors plus eight parameters lower")
                .input
                .len(),
            16
        );

        let authored: AuthoredIntegrationDocument =
            serde_norway::from_str(&authored_with_inputs(9, 0)).expect("nine-selector map parses");
        assert!(lower_authored_integration(&authored)
            .expect_err("nine selectors reject")
            .to_string()
            .contains("between one and eight selectors"));

        let authored: AuthoredIntegrationDocument =
            serde_norway::from_str(&authored_with_inputs(8, 9))
                .expect("seventeen-input map parses");
        assert!(lower_authored_integration(&authored)
            .expect_err("seventeen inputs reject")
            .to_string()
            .contains("between one and sixteen entries"));
    }

    fn project_golden(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/project-authoring")
            .join(name)
    }

    #[test]
    fn nia_userinfo_release_is_minimized_hash_covered_and_relay_valid() {
        let project = project_golden("nia-attribute-release");
        let loaded =
            load_registry_project(&project, Some("local")).expect("NIA release project loads");
        let compiled = compile_project(&loaded, None).expect("NIA release project compiles");
        validate_generated_product_configs(&compiled)
            .expect("generated NIA Relay config passes the product validator");
        let relay: Value = serde_norway::from_slice(
            compiled
                .relay_private
                .get(Path::new("config/relay.yaml"))
                .expect("generated Relay config exists"),
        )
        .expect("generated Relay config parses");
        let table_fields = relay["datasets"][0]["tables"][0]["schema"]["fields"]
            .as_array()
            .expect("generated PostgreSQL table fields are a list");
        assert!(
            table_fields
                .iter()
                .all(|field| field["sensitive"] == json!(true)),
            "provider changes must not make stored fields non-sensitive"
        );
        let public_fields = relay["datasets"][0]["entities"][0]["fields"]
            .as_array()
            .expect("generated public fields are a list");
        assert!(
            public_fields
                .iter()
                .all(|field| field["sensitive"] == json!(true)),
            "provider changes must not make projected fields non-sensitive"
        );
        let profile = &relay["datasets"][0]["entities"][0]["attribute_release_profiles"][0];
        assert_eq!(profile["id"], "solmara-nia-userinfo");
        assert_eq!(profile["version"], "v1");
        assert_eq!(profile["release_scope"], "population:identity_release");
        assert_eq!(profile["subject"]["source_field"], "legacy_nid");
        assert!(profile["subject"].get("input").is_none());
        assert!(profile["subject"].get("cardinality").is_none());
        assert_eq!(
            profile["release_conditions"]["expression"]["cel"],
            "source.identity_status == 'active' && source.alive == true"
        );
        assert!(profile.get("response").is_none());
        let claims = profile["claims"]
            .as_array()
            .expect("release claims are a closed list")
            .iter()
            .map(|claim| claim["name"].as_str().expect("claim name is a string"))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            claims,
            BTreeSet::from([
                "birthdate",
                "family_name",
                "gender",
                "given_name",
                "individual_id",
                "name",
            ])
        );

        let mut changed =
            load_registry_project(&project, Some("local")).expect("comparison project loads");
        changed
            .project
            .services
            .get_mut("nia-population-records")
            .and_then(|service| service.api.as_mut())
            .and_then(|api| {
                api.attribute_release_profiles
                    .get_mut("solmara-nia-userinfo")
            })
            .and_then(|profile| profile.claims.get_mut("gender"))
            .expect("gender release claim exists")
            .required = true;
        let changed_digests = semantic_digests(
            &changed.project,
            &changed.integrations,
            &changed.entities,
            changed.environment.as_ref(),
        )
        .expect("changed semantic digests compile");
        assert_ne!(
            loaded.semantic_digests.service_policy, changed_digests.service_policy,
            "release claim policy changes must alter the signed semantic digest"
        );
        let changed_compiled =
            compile_project(&changed, None).expect("changed NIA release project compiles");
        assert_ne!(
            compiled.approval_state["generated_closure_digests"]["relay"],
            changed_compiled.approval_state["generated_closure_digests"]["relay"],
            "release claim changes must alter the signed Relay closure digest"
        );
    }

    #[test]
    fn normalized_subject_type_changes_claim_semantics_and_notary_compilation() {
        let mut loaded = load_registry_project(&project_golden("custom-system"), Some("local"))
            .expect("golden project loads");
        let baseline = loaded.semantic_digests.claim.clone();
        let service = loaded
            .project
            .services
            .get_mut("household-eligibility")
            .expect("evidence service exists");
        assert_eq!(service.subject_type, None);
        service.subject_type = Some(EvidenceSubjectType::Person);
        let explicit_person = semantic_digests(
            &loaded.project,
            &loaded.integrations,
            &loaded.entities,
            loaded.environment.as_ref(),
        )
        .expect("explicit person digest compiles");
        assert_eq!(
            explicit_person.claim, baseline,
            "omitted and explicit person must share normalized Claim semantics"
        );

        loaded
            .project
            .services
            .get_mut("household-eligibility")
            .expect("evidence service exists")
            .subject_type = Some(EvidenceSubjectType::Project);
        let project_subject = semantic_digests(
            &loaded.project,
            &loaded.integrations,
            &loaded.entities,
            loaded.environment.as_ref(),
        )
        .expect("project subject digest compiles");
        assert_ne!(
            project_subject.claim, baseline,
            "subject category changes must alter the Claim semantic digest"
        );

        let compiled = compile_project(&loaded, None).expect("project subject compiles");
        let notary: Value = serde_norway::from_slice(
            compiled
                .notary_private
                .get(Path::new("config/notary.yaml"))
                .expect("Notary config exists"),
        )
        .expect("Notary config parses");
        assert!(notary["evidence"]["claims"]
            .as_array()
            .expect("generated claims are an array")
            .iter()
            .all(|claim| claim["subject_type"] == "project"));
        assert_eq!(
            fixture_subject_type(&loaded, "eligibility")
                .expect("offline fixture derives the project subject"),
            EvidenceSubjectType::Project
        );
    }

    #[test]
    fn attribute_release_purpose_must_be_header_safe_during_authoring() {
        let mut loaded =
            load_registry_project(&project_golden("nia-attribute-release"), Some("local"))
                .expect("NIA release project loads");
        let api = loaded
            .project
            .services
            .get_mut("nia-population-records")
            .and_then(|service| service.api.as_mut())
            .expect("records API exists");
        let purpose = "identité_verification".to_string();
        api.purposes[0] = purpose.clone();
        api.attribute_release_profiles
            .get_mut("solmara-nia-userinfo")
            .expect("release profile exists")
            .purpose = purpose;

        let error =
            validate_project_entity_links(&loaded.project, &loaded.integrations, &loaded.entities)
                .expect_err("header-bound release purpose must use visible ASCII");
        assert!(
            error.to_string().contains("purpose must use visible ASCII"),
            "unexpected diagnostic: {error:#}"
        );
    }

    #[test]
    fn attribute_release_version_must_be_a_portable_path_segment() {
        let mut loaded =
            load_registry_project(&project_golden("nia-attribute-release"), Some("local"))
                .expect("NIA release project loads");
        loaded
            .project
            .services
            .get_mut("nia-population-records")
            .and_then(|service| service.api.as_mut())
            .and_then(|api| {
                api.attribute_release_profiles
                    .get_mut("solmara-nia-userinfo")
            })
            .expect("release profile exists")
            .version = "v1/preview".to_string();

        let error =
            validate_project_entity_links(&loaded.project, &loaded.integrations, &loaded.entities)
                .expect_err("path-reserved profile version must fail during authoring");
        assert!(
            error
                .to_string()
                .contains("version must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}"),
            "unexpected diagnostic: {error:#}"
        );
    }

    #[test]
    fn attribute_release_prerequisites_fail_during_authoring() {
        for case in ["required principal filters", "pagination max_limit"] {
            let mut loaded =
                load_registry_project(&project_golden("nia-attribute-release"), Some("local"))
                    .expect("NIA release project loads");
            let api = loaded
                .project
                .services
                .get_mut("nia-population-records")
                .and_then(|service| service.api.as_mut())
                .expect("records API exists");
            let expected = match case {
                "required principal filters" => {
                    api.required_principal_filters
                        .push("legacy_nid".to_string());
                    "attribute release profiles cannot use required principal filters"
                }
                "pagination max_limit" => {
                    api.pagination.default_limit = 1;
                    api.pagination.max_limit = 1;
                    "attribute release profiles require records pagination max_limit of at least 2"
                }
                _ => unreachable!("unknown prerequisite case"),
            };

            let error = validate_project_entity_links(
                &loaded.project,
                &loaded.integrations,
                &loaded.entities,
            )
            .expect_err("invalid release prerequisite must fail during authoring");
            assert!(
                error.to_string().contains(expected),
                "unexpected {case} diagnostic: {error:#}"
            );
        }
    }

    #[test]
    fn interval_materialization_refresh_uses_an_operational_bound() {
        let project = project_golden("nia-attribute-release");
        let mut loaded =
            load_registry_project(&project, Some("local")).expect("NIA release project loads");
        loaded
            .entities
            .get_mut("population")
            .expect("population entity exists")
            .document
            .materialization
            .refresh = "1m".to_string();
        validate_entity_definition(&loaded.entities["population"].document)
            .expect("one-minute materialization refresh is supported");
        let compiled = compile_project(&loaded, None).expect("interval project compiles");
        let relay: Value = serde_norway::from_slice(
            compiled
                .relay_private
                .get(Path::new("config/relay.yaml"))
                .expect("generated Relay config exists"),
        )
        .expect("generated Relay config parses");
        assert_eq!(
            relay["datasets"][0]["tables"][0]["refresh"]["mode"],
            "interval"
        );
        assert_eq!(
            relay["datasets"][0]["tables"][0]["refresh"]["interval"],
            "1m"
        );

        loaded
            .entities
            .get_mut("population")
            .expect("population entity exists")
            .document
            .materialization
            .refresh = "31d".to_string();
        let error = validate_entity_definition(&loaded.entities["population"].document)
            .expect_err("refresh beyond 30 days must fail closed");
        assert!(error
            .to_string()
            .contains("entity materialization refresh is invalid"));
    }

    #[test]
    fn attribute_release_claims_cannot_read_unprojected_entity_fields() {
        let mut loaded =
            load_registry_project(&project_golden("nia-attribute-release"), Some("local"))
                .expect("NIA release project loads");
        loaded
            .project
            .services
            .get_mut("nia-population-records")
            .and_then(|service| service.api.as_mut())
            .expect("records API exists")
            .projection
            .retain(|field| field != "birth_date");
        let error =
            validate_project_entity_links(&loaded.project, &loaded.integrations, &loaded.entities)
                .expect_err("unprojected release input must fail closed");
        assert!(error
            .to_string()
            .contains("claim source_field must be an explicitly projected entity field"));
    }

    #[test]
    fn effective_records_api_scopes_must_be_unique() {
        for (name, change, expected_fields) in [
            (
                "effective aggregate default",
                "aggregate_default",
                (
                    "services.nia-population-records.api.scopes.aggregate",
                    "services.nia-population-records.api.scopes.metadata",
                ),
            ),
            (
                "evidence verification",
                "evidence_verification",
                (
                    "services.nia-population-records.api.scopes.evidence_verification",
                    "services.nia-population-records.api.scopes.rows",
                ),
            ),
        ] {
            let mut loaded =
                load_registry_project(&project_golden("nia-attribute-release"), Some("local"))
                    .expect("NIA release project loads");
            let api = loaded
                .project
                .services
                .get_mut("nia-population-records")
                .and_then(|service| service.api.as_mut())
                .expect("records API exists");
            match change {
                "aggregate_default" => {
                    api.scopes.metadata = "population:aggregate".to_string();
                    api.scopes.aggregate = None;
                }
                "evidence_verification" => {
                    api.scopes.evidence_verification = Some(api.scopes.rows.clone());
                }
                _ => unreachable!("unknown scope collision case"),
            }

            let error = validate_project_entity_links(
                &loaded.project,
                &loaded.integrations,
                &loaded.entities,
            )
            .expect_err("colliding effective records scopes must fail closed");
            let diagnostic = error.to_string();
            assert!(
                diagnostic.contains(expected_fields.0) && diagnostic.contains(expected_fields.1),
                "unexpected {name} diagnostic: {diagnostic}"
            );
        }
    }

    #[test]
    fn attribute_release_scope_must_differ_from_every_effective_records_scope() {
        for record_scope_field in ["metadata", "rows", "aggregate", "evidence_verification"] {
            let mut loaded =
                load_registry_project(&project_golden("nia-attribute-release"), Some("local"))
                    .expect("NIA release project loads");
            let api = loaded
                .project
                .services
                .get_mut("nia-population-records")
                .and_then(|service| service.api.as_mut())
                .expect("records API exists");
            let release_scope = "population:identity_release".to_string();
            match record_scope_field {
                "metadata" => api.scopes.metadata = release_scope,
                "rows" => api.scopes.rows = release_scope,
                "aggregate" => api.scopes.aggregate = Some(release_scope),
                "evidence_verification" => api.scopes.evidence_verification = Some(release_scope),
                _ => unreachable!("unknown records scope field"),
            }

            let error = validate_project_entity_links(
                &loaded.project,
                &loaded.integrations,
                &loaded.entities,
            )
            .expect_err("attribute release scope collision must fail closed");
            let diagnostic = error.to_string();
            assert!(
                diagnostic.contains(
                    "services.nia-population-records.api.attribute_release_profiles.solmara-nia-userinfo.release_scope"
                ) && diagnostic.contains(&format!(
                    "services.nia-population-records.api.scopes.{record_scope_field}"
                )),
                "unexpected {record_scope_field} collision diagnostic: {diagnostic}"
            );
        }
    }

    #[test]
    fn generated_relay_rejects_independent_raw_and_typed_binding_tampering() {
        let project = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/project-authoring/custom-system");
        let loaded = load_registry_project(&project, Some("local")).expect("golden project loads");
        let compiled = compile_project(&loaded, None).expect("golden project compiles");
        let relay = compiled
            .relay_consultation_private
            .get(Path::new("config/relay.yaml"))
            .expect("consultation Relay config exists");
        let original: Value = serde_norway::from_slice(relay).expect("Relay config parses");

        for field in ["sha256", "hash"] {
            let mut tampered = original.clone();
            tampered["consultation"]["artifacts"]["private_bindings"][0][field] =
                Value::String(format!("sha256:{}", "0".repeat(64)));
            let bytes = serde_norway::to_string(&tampered).expect("tampered config serializes");
            let error = validate_generated_relay(
                bytes.as_bytes(),
                &compiled.relay_consultation_private,
                "config/relay.yaml",
            )
            .expect_err("tampered binding pin must fail closed");
            let diagnostic = format!("{error:#}");
            assert!(
                diagnostic.contains("binding")
                    || diagnostic.contains("generated Relay config failed production loading"),
                "unexpected {field} diagnostic: {diagnostic}"
            );
        }
    }

    #[test]
    fn generated_public_and_consultation_relays_are_separate_and_production_validated() {
        let loaded = load_registry_project(&project_golden("custom-system"), Some("local"))
            .expect("golden project loads");
        let compiled = compile_project(&loaded, None).expect("golden project compiles");
        let public_path = Path::new("config/relay.yaml");
        let consultation_path = Path::new("config/relay.yaml");
        let public_bytes = compiled
            .relay_private
            .get(public_path)
            .expect("public Relay config exists");
        let consultation_bytes = compiled
            .relay_consultation_private
            .get(consultation_path)
            .expect("consultation Relay config exists");
        let public: Value =
            serde_norway::from_slice(public_bytes).expect("public Relay config parses");
        let consultation: Value =
            serde_norway::from_slice(consultation_bytes).expect("consultation Relay config parses");

        assert_eq!(
            compiled
                .relay_private
                .keys()
                .map(PathBuf::as_path)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                Path::new("config/relay.yaml"),
                Path::new("descriptors/operations.json"),
                Path::new("descriptors/secret-consumers.json"),
            ]),
            "the public Relay input contains only instance-applicable generated members"
        );
        let referenced_artifacts = consultation["consultation"]["artifacts"]
            .as_object()
            .expect("consultation artifact closure exists")
            .values()
            .flat_map(|entries| {
                entries
                    .as_array()
                    .expect("consultation artifact class is a list")
            })
            .map(|entry| {
                entry["path"]
                    .as_str()
                    .expect("consultation artifact has a path")
            })
            .collect::<BTreeSet<_>>();
        let vendored_artifacts = compiled
            .relay_consultation_private
            .keys()
            .filter_map(|path| path.strip_prefix("config").ok())
            .filter_map(|path| path.to_str())
            .filter(|path| path.starts_with("artifacts/"))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            vendored_artifacts, referenced_artifacts,
            "the consultation Relay input vendors exactly its selected artifacts"
        );

        assert!(public.get("consultation").is_none());
        assert!(consultation.get("consultation").is_some());
        assert_eq!(public["instance"]["id"], "household-relay");
        assert_eq!(
            consultation["instance"]["id"],
            "household-relay-consultation"
        );
        assert_eq!(
            public["auth"]["oidc"]["allowed_clients"],
            json!(["household-relay-client"])
        );
        assert_eq!(
            consultation["auth"]["oidc"]["allowed_clients"],
            json!(["household-notary"])
        );
        assert_eq!(
            consultation["auth"]["oidc"]["allow_dev_insecure_fetch_urls"],
            false
        );
        let public_operations: Value = serde_json::from_slice(
            compiled
                .relay_private
                .get(Path::new("descriptors/operations.json"))
                .expect("public Relay operations descriptor exists"),
        )
        .expect("public Relay operations descriptor parses");
        let consultation_operations: Value = serde_json::from_slice(
            compiled
                .relay_consultation_private
                .get(Path::new("descriptors/operations.json"))
                .expect("consultation Relay operations descriptor exists"),
        )
        .expect("consultation Relay operations descriptor parses");
        assert_eq!(public_operations["service"], "household-relay");
        assert_eq!(public_operations["consultation_profiles"], 0);
        assert_eq!(
            consultation_operations["service"],
            "household-relay-consultation"
        );
        assert_eq!(consultation_operations["consultation_profiles"], 1);

        for (files, config) in [
            (&compiled.relay_private, &public),
            (&compiled.relay_consultation_private, &consultation),
        ] {
            let descriptor: Value = serde_json::from_slice(
                files
                    .get(Path::new("descriptors/secret-consumers.json"))
                    .expect("Relay secret-consumer descriptor exists"),
            )
            .expect("Relay secret-consumer descriptor parses");
            assert_eq!(
                descriptor,
                secret_consumer_descriptor("registry-relay", config),
                "each Relay instance describes only the secrets selected by its primary config"
            );
        }
        assert_eq!(
            compiled.approval_state["generated_closure_digests"]["relay"],
            json!(closure_digest(&compiled.relay_private).expect("public Relay closure digests"))
        );
        assert_eq!(
            compiled.approval_state["generated_closure_digests"]["relay_consultation"],
            json!(closure_digest(&compiled.relay_consultation_private)
                .expect("consultation Relay closure digests"))
        );
        assert_ne!(
            compiled.approval_state["generated_closure_digests"]["relay"],
            compiled.approval_state["generated_closure_digests"]["relay_consultation"],
            "the approval state independently binds both Relay instances"
        );
        validate_generated_relay(public_bytes, &compiled.relay_private, "config/relay.yaml")
            .expect("public Relay passes production loading");
        validate_generated_relay(
            consultation_bytes,
            &compiled.relay_consultation_private,
            "config/relay.yaml",
        )
        .expect("consultation Relay passes production loading and activation");
    }

    #[test]
    fn local_notary_add_on_uses_stable_issuer_and_mounted_jwks_file() {
        let mut loaded = load_registry_project(&project_golden("custom-system"), Some("local"))
            .expect("golden project loads");
        let environment = loaded.environment.as_mut().expect("environment exists");
        environment
            .relay
            .as_mut()
            .expect("Relay binding exists")
            .local_api_keys = Some(RelayLocalApiKeyBinding {
            match_principal: "local_match".to_string(),
            no_match_principal: "local_no_match".to_string(),
            scopes: vec!["registry_relay:ops_read".to_string()],
        });
        environment
            .deployment
            .notary
            .as_mut()
            .expect("Notary deployment exists")
            .service = "registryctl-local-notary".to_string();

        let unrelated =
            compile_project(&loaded, None).expect("non-canonical local project compiles");
        let unrelated_consultation: Value = serde_norway::from_slice(
            unrelated
                .relay_consultation_private
                .get(Path::new("config/relay.yaml"))
                .expect("consultation Relay config exists"),
        )
        .expect("consultation Relay config parses");
        assert_eq!(
            unrelated_consultation["auth"]["oidc"]["issuer"],
            "https://workload-issuer.internal.invalid"
        );
        assert_eq!(
            unrelated_consultation["auth"]["oidc"]["jwks_url"],
            "https://workload-issuer.internal.invalid/.well-known/jwks.json"
        );
        assert_eq!(
            unrelated_consultation["auth"]["oidc"]["allow_dev_insecure_fetch_urls"],
            false
        );

        let binding = loaded
            .environment
            .as_mut()
            .expect("environment exists")
            .notary_relay
            .as_mut()
            .expect("Notary-to-Relay binding exists");
        binding.base_url = "http://10.89.0.4:8080".to_string();
        binding.workload_client_id = "registryctl-local-notary".to_string();
        binding.token_file = PathBuf::from("/run/secrets/relay-workload-token");
        loaded
            .environment
            .as_mut()
            .expect("environment exists")
            .relay
            .as_mut()
            .expect("Relay binding exists")
            .issuer = "https://registryctl-local-notary.invalid".to_string();

        let compiled = compile_project(&loaded, None).expect("local add-on project compiles");
        let public: Value = serde_norway::from_slice(
            compiled
                .relay_private
                .get(Path::new("config/relay.yaml"))
                .expect("public Relay config exists"),
        )
        .expect("public Relay config parses");
        let consultation_bytes = compiled
            .relay_consultation_private
            .get(Path::new("config/relay.yaml"))
            .expect("consultation Relay config exists");
        let consultation: Value =
            serde_norway::from_slice(consultation_bytes).expect("consultation Relay config parses");

        assert_eq!(public["auth"]["mode"], "api_key");
        assert_eq!(consultation["auth"]["mode"], "oidc");
        assert_eq!(
            consultation["auth"]["oidc"]["issuer"],
            "https://registryctl-local-notary.invalid"
        );
        assert_eq!(
            consultation["auth"]["oidc"]["development_jwks_file"],
            "/run/registry/dev-public/notary-workload-jwks.json"
        );
        assert!(consultation["auth"]["oidc"].get("jwks_url").is_none());
        assert!(consultation["auth"]["oidc"]
            .get("discovery_url")
            .is_none());
        assert_eq!(
            consultation["auth"]["oidc"]["allow_dev_insecure_fetch_urls"],
            false
        );
        validate_generated_product_configs(&compiled)
            .expect("local add-on product configs pass production validation");
    }

    #[test]
    fn generated_local_api_key_validation_preserves_refs_and_rejects_malformed_or_duplicate_keys() {
        let project =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/project-starters/spreadsheet");
        let loaded =
            load_registry_project(&project, Some("local")).expect("spreadsheet starter loads");
        let compiled = compile_project(&loaded, None).expect("spreadsheet starter compiles");
        let relay = compiled
            .relay_private
            .get(Path::new("config/relay.yaml"))
            .expect("Relay config exists");
        let original: Value = serde_norway::from_slice(relay).expect("Relay config parses");

        validate_generated_relay(relay, &compiled.relay_private, "config/relay.yaml")
            .expect("temporary validation credentials satisfy production loading");
        let after: Value = serde_norway::from_slice(relay).expect("Relay config still parses");
        assert_eq!(after, original, "validation must not mutate emitted config");
        assert_eq!(
            after["auth"]["api_keys"][0]["fingerprint"],
            json!({
                "provider": "env",
                "name": "REGISTRYCTL_LOCAL_RELAY_MATCH_KEY_HASH",
            })
        );
        assert_eq!(
            after["auth"]["api_keys"][1]["fingerprint"],
            json!({
                "provider": "env",
                "name": "REGISTRYCTL_LOCAL_RELAY_NO_MATCH_KEY_HASH",
            })
        );

        let mut malformed = original.clone();
        malformed["auth"]["api_keys"][0]["fingerprint"]["name"] = Value::String(String::new());
        let mut duplicate = original.clone();
        let first_fingerprint = duplicate["auth"]["api_keys"][0]["fingerprint"].clone();
        duplicate["auth"]["api_keys"][1]["fingerprint"] = first_fingerprint;
        for (label, invalid) in [("malformed", malformed), ("duplicate", duplicate)] {
            let bytes = serde_norway::to_string(&invalid).expect("invalid config serializes");
            let error = validate_generated_relay(
                bytes.as_bytes(),
                &compiled.relay_private,
                "config/relay.yaml",
            )
            .expect_err("invalid API-key config must fail production validation");
            let diagnostic = format!("{error:#}");
            assert!(
                diagnostic.contains("failed production loading"),
                "unexpected {label} diagnostic: {diagnostic}"
            );
            assert!(
                !diagnostic.contains("REGISTRYCTL_LOCAL_RELAY")
                    && !diagnostic.contains("registryctl-project-validation"),
                "{label} diagnostic disclosed validation material: {diagnostic}"
            );
        }
    }

    #[test]
    fn generated_local_api_key_validation_material_is_private_distinct_and_disposable() {
        let validation_root =
            GeneratedValidationDirectory::create().expect("validation root creates");
        let root_path = validation_root.path.clone();
        let mut config = json!({
            "auth": {
                "api_keys": [
                    {
                        "fingerprint": {
                            "provider": "env",
                            "name": "FIRST_FINGERPRINT",
                        },
                    },
                    {
                        "fingerprint": {
                            "provider": "env",
                            "name": "SECOND_FINGERPRINT",
                        },
                    },
                ],
            },
        });
        materialize_generated_relay_validation_fingerprints(&mut config, &root_path)
            .expect("validation fingerprints materialize");
        let first = PathBuf::from(
            config["auth"]["api_keys"][0]["fingerprint"]["path"]
                .as_str()
                .expect("first validation path"),
        );
        let second = PathBuf::from(
            config["auth"]["api_keys"][1]["fingerprint"]["path"]
                .as_str()
                .expect("second validation path"),
        );
        assert_ne!(first, second);
        assert_ne!(
            fs::read_to_string(&first).expect("first fingerprint reads"),
            fs::read_to_string(&second).expect("second fingerprint reads")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&root_path).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for path in [&first, &second] {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        drop(validation_root);
        assert!(
            !root_path.exists(),
            "temporary validation material must be removed"
        );
    }

    #[test]
    fn cel_consultation_roots_ignore_strings_and_comments() {
        assert_eq!(
            cel_member_roots("'decoy.exists' == 'x' && person.exists").expect("CEL roots parse"),
            BTreeSet::from(["person".to_string()])
        );
        assert_eq!(
            cel_member_roots(
                "person.details.name == 'Ada' && person.name.startsWith('A') \
                 && person['details'].active"
            )
            .expect("nested CEL roots parse"),
            BTreeSet::from(["person".to_string()])
        );
        assert_eq!(
            cel_member_roots(
                r#"person.exists // decoy.value ' "unterminated
&& another.exists"#
            )
            .expect("commented CEL roots parse"),
            BTreeSet::from(["another".to_string(), "person".to_string()])
        );
        assert_eq!(
            cel_member_roots("person.items.exists(item, item.active)")
                .expect("macro-local CEL roots parse"),
            BTreeSet::from(["person".to_string()])
        );
        assert_eq!(
            cel_references("person.items.exists(item, item.active)")
                .expect("macro-local CEL members parse"),
            CelReferences {
                roots: BTreeSet::from(["person".to_string()]),
                first_level_members: BTreeMap::from([(
                "person".to_string(),
                BTreeSet::from(["items".to_string()])
                )]),
                uses_index: false,
            }
        );
        assert_eq!(
            cel_member_roots("person.items.exists(item, item.active) && item.secret == 'outside'")
                .expect("out-of-scope CEL roots parse"),
            BTreeSet::from(["item".to_string(), "person".to_string()])
        );
        assert!(cel_member_roots("person.exists && 'unterminated").is_err());
    }

    #[test]
    fn registry_cel_claims_reject_structured_members_and_constant_only_rules() {
        let mut loaded =
            load_registry_project(&project_golden("opencrvs"), None).expect("OpenCRVS project loads");
        let set_claim_expression = |loaded: &mut LoadedRegistryProject, expression: &str| {
            let claim = loaded
                .project
                .services
                .get_mut("birth-verification")
                .and_then(|service| service.claims.get_mut("parents"))
                .expect("structured parents claim exists");
            claim.output = None;
            claim.cel = Some(expression.to_string());
        };
        set_claim_expression(
            &mut loaded,
            "birth.parents.exists(parent, parent.name != '')",
        );

        let error = validate_service_integration_links(&loaded.project, &loaded.integrations)
            .expect_err("structured consultation members must not enter authored CEL claims");
        assert!(error.to_string().contains(
            "service birth-verification claim parents CEL cannot reference structured consultation output birth.parents"
        ));

        set_claim_expression(&mut loaded, r#"birth["parents"] != null"#);
        let error = validate_service_integration_links(&loaded.project, &loaded.integrations)
            .expect_err("registry-backed CEL index access must fail before generation");
        assert!(error
            .to_string()
            .contains("registry-backed CEL cannot use index access"));

        set_claim_expression(&mut loaded, "['literal-value'][0] == 'literal-value'");
        let error = validate_service_integration_links(&loaded.project, &loaded.integrations)
            .expect_err("constant-only CEL cannot replace Registry evidence");
        assert!(error
            .to_string()
            .contains("every claim must derive from one declared Relay consultation"));
    }

    #[test]
    fn secret_descriptor_includes_named_environment_providers() {
        let descriptor = secret_consumer_descriptor(
            "registry-notary",
            &json!({
                "authentication": {
                    "fingerprint": { "provider": "env", "name": "CALLER_TOKEN_HASH" },
                },
                "audit": {
                    "source": {
                        "provider": "environment",
                        "name": "AUDIT_PSEUDONYM_EPOCH_1",
                    },
                },
            }),
        );
        let consumers = descriptor["consumers"]
            .as_array()
            .expect("descriptor consumers are present");
        assert!(consumers.iter().any(|consumer| {
            consumer["locator"] == "CALLER_TOKEN_HASH"
                && consumer["config_pointer"] == "/authentication/fingerprint/name"
        }));
        assert!(consumers.iter().any(|consumer| {
            consumer["locator"] == "AUDIT_PSEUDONYM_EPOCH_1"
                && consumer["config_pointer"] == "/audit/source/name"
        }));
    }

    #[test]
    fn released_rhai_capability_identity_is_not_a_source_product() {
        assert!(is_script_runtime_released(ReleasedScriptRuntime::RhaiV1));
        assert!(!is_script_runtime_released_in(
            ReleasedScriptRuntime::RhaiV1,
            &[]
        ));
    }

    #[test]
    fn duplicate_project_claim_ids_fail_before_generation() {
        let project = project_golden("custom-system");
        let mut loaded = load_registry_project(&project, None).expect("golden project loads");
        let duplicate: ServiceDeclaration = serde_json::from_value(
            serde_json::to_value(&loaded.project.services["household-eligibility"])
                .expect("service serializes"),
        )
        .expect("service clones through its strict model");
        loaded
            .project
            .services
            .insert("duplicate-service".to_string(), duplicate);
        let error = validate_project_shape(&loaded.project)
            .expect_err("duplicate project claim ids must fail closed");
        assert!(error
            .to_string()
            .contains("claim ids must be unique across project services"));
    }

    #[test]
    fn generated_notary_validation_rejects_empty_claim_formats() {
        let loaded = load_registry_project(&project_golden("custom-system"), Some("local"))
            .expect("golden project loads");
        let mut compiled = compile_project(&loaded, None).expect("golden project compiles");
        let config_path = Path::new("config/notary.yaml").to_path_buf();
        let mut notary: Value = serde_norway::from_slice(
            compiled
                .notary_private
                .get(&config_path)
                .expect("Notary config exists"),
        )
        .expect("generated Notary config parses");
        notary["evidence"]["claims"][0]["formats"] = Value::Array(Vec::new());
        compiled.notary_private.insert(
            config_path,
            serde_norway::to_string(&notary)
                .expect("tampered Notary config serializes")
                .into_bytes()
                .into_boxed_slice(),
        );

        let error = validate_generated_notary(&compiled)
            .expect_err("generated validation must reject an empty formats list");
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("formats must not be empty"));
        assert!(diagnostic.contains("omit formats"));
    }

    #[test]
    fn generated_products_persist_audit_records_to_the_managed_volume() {
        let loaded = load_registry_project(&project_golden("custom-system"), Some("local"))
            .expect("golden project loads");
        let compiled = compile_project(&loaded, None).expect("golden project compiles");
        let product_configs = [
            (
                "Relay",
                compiled
                    .relay_private
                    .get(Path::new("config/relay.yaml"))
                    .expect("Relay config exists"),
            ),
            (
                "consultation Relay",
                compiled
                    .relay_consultation_private
                    .get(Path::new("config/relay.yaml"))
                    .expect("consultation Relay config exists"),
            ),
            (
                "Notary",
                compiled
                    .notary_private
                    .get(Path::new("config/notary.yaml"))
                    .expect("Notary config exists"),
            ),
        ];

        for (product, bytes) in product_configs {
            let config: Value =
                serde_norway::from_slice(bytes).expect("generated product config parses");
            assert_eq!(
                config.pointer("/audit/sink"),
                Some(&json!("file")),
                "{product} must use a durable audit sink"
            );
            assert_eq!(
                config.pointer("/audit/path"),
                Some(&json!("/var/lib/registry/audit/audit.jsonl")),
                "{product} must write to the managed audit volume"
            );
        }
    }

    #[test]
    fn disclosure_review_classes_are_directional() {
        let loaded = load_registry_project(&project_golden("custom-system"), None)
            .expect("golden project loads");
        let original = disclosure_review_profiles(&loaded.project);
        let baseline = json!({ "disclosure_profiles": original });

        let mut narrowed = disclosure_review_profiles(&loaded.project);
        narrowed
            .get_mut("household-eligibility")
            .expect("service profile exists")
            .insert(
                "household-category".to_string(),
                DisclosureReviewProfile {
                    default: DisclosureMode::Redacted,
                    allowed: BTreeSet::from([DisclosureMode::Redacted]),
                },
            );
        assert_eq!(
            disclosure_change_classes(&narrowed, Some(&baseline)),
            (true, false)
        );

        let mut widened = disclosure_review_profiles(&loaded.project);
        widened
            .get_mut("household-eligibility")
            .expect("service profile exists")
            .insert(
                "household-record-exists".to_string(),
                DisclosureReviewProfile {
                    default: DisclosureMode::Value,
                    allowed: BTreeSet::from([DisclosureMode::Value, DisclosureMode::Redacted]),
                },
            );
        assert_eq!(
            disclosure_change_classes(&widened, Some(&baseline)),
            (false, true)
        );

        let mut mixed = narrowed;
        mixed
            .get_mut("household-eligibility")
            .expect("service profile exists")
            .insert(
                "household-record-exists".to_string(),
                DisclosureReviewProfile {
                    default: DisclosureMode::Value,
                    allowed: BTreeSet::from([DisclosureMode::Value, DisclosureMode::Redacted]),
                },
            );
        assert_eq!(
            disclosure_change_classes(&mixed, Some(&baseline)),
            (true, true)
        );
    }

    #[test]
    fn compiler_upgrade_is_reported_independently_of_authored_semantic_changes() {
        let loaded = load_registry_project(&project_golden("custom-system"), None)
            .expect("golden project loads");
        let disclosure_digest = format!("sha256:{}", "a".repeat(64));
        let baseline = json!({
            "compiler_version": "0.0.0",
            "semantic_digests": {
                "claim": format!("sha256:{}", "0".repeat(64)),
                "integration": loaded.semantic_digests.integration.as_str(),
                "service_policy": loaded.semantic_digests.service_policy.as_str(),
                "operator_security": loaded.semantic_digests.operator_security.as_str(),
            },
            "disclosure_digest": disclosure_digest,
        });
        assert_eq!(
            semantic_change_records(&loaded, Some(&baseline), &disclosure_digest)
                .into_iter()
                .map(|change| change.dimension)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["claim", "compiler"]),
        );
    }

    #[test]
    fn signed_review_and_approval_state_validation_are_closed_and_separate() {
        let loaded = load_registry_project(&project_golden("custom-system"), Some("local"))
            .expect("golden project loads");
        let compiled = compile_project(&loaded, None).expect("golden project compiles");
        let review = compiled.review;
        let approval_state = compiled.approval_state;
        validate_signed_review_record(&review).expect("current review record is valid");
        validate_signed_approval_state(&approval_state).expect("current approval state is valid");

        for unsupported_schema in [
            "registry.project.approval-state.v1",
            "registry.project.approval-state.v2",
            "registry.project.approval-state.v3",
        ] {
            let mut unsupported_state = approval_state.clone();
            unsupported_state["schema"] = json!(unsupported_schema);
            let error = validate_signed_approval_state(&unsupported_state)
                .expect_err("pre-1.0 approval state must not enter semantic validation");
            let message = error.to_string();
            assert_eq!(
                message,
                "baseline approval state uses an unsupported schema; recreate pre-1.0 generated \
                 artifacts before rebuilding"
            );
            assert!(!message.contains(unsupported_schema));
            assert!(!message.contains("fictional-citizen-registry"));
        }

        let mut leaked_digest = review.clone();
        leaked_digest
            .as_object_mut()
            .expect("review is an object")
            .insert(
                "semantic_digest".to_string(),
                Value::String(format!("sha256:{}", "0".repeat(64))),
            );
        assert!(validate_signed_review_record(&leaked_digest)
            .expect_err("public review with a lower-level digest must fail")
            .to_string()
            .contains("missing or unknown fields"));

        let mut nested_leak = review.clone();
        nested_leak["entity_materializations"]["leak"] = json!({
            "provider_hash": format!("sha256:{}", "0".repeat(64)),
        });
        assert!(validate_signed_review_record(&nested_leak)
            .expect_err("nested lower-level public hash must fail")
            .to_string()
            .contains("exposes lower-level hash or digest"));

        let mut missing_state = approval_state.clone();
        missing_state
            .as_object_mut()
            .expect("approval state is an object")
            .remove("semantic_digests");
        assert!(validate_signed_approval_state(&missing_state)
            .expect_err("approval state without semantic digests must fail")
            .to_string()
            .contains("missing or unknown fields"));

        let mut inconsistent_products = approval_state.clone();
        inconsistent_products["promotion_projection"]["products"] = json!(["relay"]);
        assert!(validate_signed_approval_state(&inconsistent_products)
            .expect_err("projection products must match signed generated closures")
            .to_string()
            .contains("product inventory disagrees"));

        let mut missing_projection = approval_state.clone();
        missing_projection
            .as_object_mut()
            .expect("approval state is an object")
            .remove("promotion_projection");
        assert!(validate_signed_approval_state(&missing_projection)
            .expect_err("approval state without promotion projection must fail")
            .to_string()
            .contains("missing or unknown fields"));

        let mut malformed_projection = approval_state.clone();
        malformed_projection["promotion_projection"]["fields"][0]["address"]["path"] =
            json!("/not/a/closed/promotion/address");
        assert!(validate_signed_approval_state(&malformed_projection)
            .expect_err("approval state promotion projection must remain closed")
            .to_string()
            .contains("promotion_projection is invalid"));

        let mut malformed_state = approval_state.clone();
        malformed_state["report_digest"] = Value::String("sha256:not-a-digest".to_string());
        assert!(validate_signed_approval_state(&malformed_state)
            .expect_err("malformed internal digest must fail")
            .to_string()
            .contains("must be a SHA-256 digest"));

        let mut malformed_nested_baseline = approval_state;
        malformed_nested_baseline["baseline"] = json!({});
        assert!(validate_signed_approval_state(&malformed_nested_baseline)
            .expect_err("nested baseline summary must remain closed")
            .to_string()
            .contains("missing or unknown fields"));
    }
}

#[test]
fn fixture_input_validation_uses_typed_values_and_explicit_null() {
    let boolean = InputDeclaration {
        role: AuthoredInputRole::Parameter,
        input_type: InputType::Boolean,
        nullable: true,
        max_length: None,
        min_length: None,
        bytes: 5,
        pattern: None,
        enum_values: Some(vec![json!(true), Value::Null]),
        const_value: None,
        canonicalization: Canonicalization::Identity,
        minimum: None,
        maximum: None,
    };
    validate_fixture_input_value("include_archived", &boolean, &json!(true))
        .expect("Boolean fixture value validates");
    validate_fixture_input_value("include_archived", &boolean, &Value::Null)
        .expect("explicit nullable parameter validates");
    assert!(validate_fixture_input_value("include_archived", &boolean, &json!(false)).is_err());
    assert!(validate_fixture_input_value("include_archived", &boolean, &json!("true")).is_err());

    let integer = InputDeclaration {
        role: AuthoredInputRole::Selector,
        input_type: InputType::Integer,
        nullable: false,
        max_length: None,
        min_length: None,
        bytes: 2,
        pattern: None,
        enum_values: None,
        const_value: None,
        canonicalization: Canonicalization::Identity,
        minimum: Some(-5),
        maximum: Some(10),
    };
    validate_fixture_input_value("sequence", &integer, &json!(10))
        .expect("bounded Integer fixture value validates");
    assert!(validate_fixture_input_value("sequence", &integer, &json!(11)).is_err());
    assert!(validate_fixture_input_value("sequence", &integer, &Value::Null).is_err());
}

#[test]
fn oauth_authoring_lowers_host_owned_form_exchange_with_expiry_cache() {
    let authored: AuthoredIntegrationDocument = serde_norway::from_str(
        r#"
version: 1
id: generic-status
revision: 1
source:
  auth:
    type: oauth2_client_credentials
    request: form
    response_profile: oauth2_bearer
    scope: records.read registry.read
    audience: https://registry.invalid
    refresh_skew: 20s
input:
  person_id: { role: selector, type: string, maxLength: 64 }
capability:
  http:
    request: { method: GET, path: '/people/{input.person_id}' }
outputs:
  active: { type: boolean, x-registry-source: /active }
"#,
    )
    .expect("OAuth integration parses");
    let lowered = lower_authored_integration(&authored).expect("OAuth integration lowers");
    let operations = integration_operations(&lowered);
    let oauth = operations.get("oauth").expect("host-owned OAuth operation");
    assert_eq!(oauth.role, OperationRole::Credential);
    assert_eq!(oauth.request.path, "/");
    assert_eq!(
        oauth.request.codec.as_deref(),
        Some("oauth2_client_credentials_form_v1")
    );
    assert_eq!(operations["request"].depends_on, vec!["oauth".to_string()]);
}

#[test]
fn oauth_authoring_lowers_strict_no_expiry_exchange_without_refresh_controls() {
    let authored: AuthoredIntegrationDocument = serde_norway::from_str(
        r#"
version: 1
id: generic-status
revision: 1
source:
  auth:
    type: oauth2_client_credentials
    request: form
    response_profile: oauth2_bearer_no_expiry
input:
  person_id: { role: selector, type: string, maxLength: 64 }
capability:
  http:
    request: { method: GET, path: '/people/{input.person_id}' }
outputs:
  active: { type: boolean, x-registry-source: /active }
"#,
    )
    .expect("no-expiry OAuth integration parses");
    let lowered =
        lower_authored_integration(&authored).expect("no-expiry OAuth integration lowers");
    let operations = integration_operations(&lowered);
    let oauth = operations
        .get("oauth")
        .expect("host-owned OAuth operation");
    let SchemaNode::Object {
        additional_fields,
        fields,
    } = &oauth.response.schema
    else {
        panic!("OAuth response uses the closed object schema");
    };
    assert_eq!(additional_fields, &AdditionalFields::Reject);
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["access_token", "token_type"]
    );

    let mut invalid = authored;
    invalid
        .source
        .as_mut()
        .expect("source")
        .auth
        .refresh_skew = Some("20s".to_string());
    let error = lower_authored_integration(&invalid)
        .expect_err("no-expiry response profile rejects cache refresh controls");
    assert!(error
        .to_string()
        .contains("refresh_skew requires the oauth2_bearer response profile"));
}

#[test]
fn environment_source_binding_has_no_legacy_destination_or_credential_type_aliases() {
    let source: EnvironmentIntegration = serde_norway::from_str(
        r#"
source:
  origin: https://registry.invalid
  allowed_private_cidrs: [10.42.0.0/16]
  credential:
    client_id: { secret: REGISTRY_CLIENT_ID }
    client_secret: { secret: REGISTRY_CLIENT_SECRET }
    generation: 7
  oauth:
    origin: https://identity.invalid
    path: /oauth/token
    generation: 3
  jwks:
    origin: https://trust.invalid
    path: /.well-known/jwks.json
    generation: 4
  concurrency: 4
  timeout: 10s
"#,
    )
    .expect("simple source binding parses");
    assert_eq!(
        source
            .source
            .oauth
            .as_ref()
            .map(|endpoint| endpoint.generation),
        Some(3)
    );
    assert_eq!(
        source
            .source
            .jwks
            .as_ref()
            .map(|endpoint| endpoint.generation),
        Some(4)
    );

    for legacy in [
        "data_destination: { origin: https://registry.invalid }",
        "source: { origin: https://registry.invalid, advanced_capabilities: {} }",
        "source: { origin: https://registry.invalid, credential: { type: basic, generation: 1 } }",
    ] {
        assert!(serde_norway::from_str::<EnvironmentIntegration>(legacy).is_err());
    }
}

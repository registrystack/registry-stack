use registry_evidence_authoring::openapi::{
    openapi::Spec,
    types::{OpenApiDialect, OperationKey, ParameterLocation},
};
use serde_json::{json, Value};

fn operation(method: &str, path: &str) -> OperationKey {
    OperationKey {
        method: method.to_owned(),
        path: path.to_owned(),
    }
}

fn document(version: &str, schema: Value) -> Spec {
    Spec::from_value(
        json!({
            "openapi": version,
            "info": {"title": "Source", "version": "1"},
            "paths": {
                "/records": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "record",
                                "content": {"application/json": {"schema": schema}}
                            }
                        }
                    }
                }
            }
        }),
        "test document",
    )
    .expect("valid OpenAPI document")
}

#[test]
fn dialect_is_retained_and_nullable_is_normalized_only_for_openapi_30() {
    let openapi30 = document("3.0.4", json!({"type": "string", "nullable": true}));
    assert_eq!(openapi30.dialect(), OpenApiDialect::OpenApi30);
    assert_eq!(openapi30.openapi_version(), "3.0.4");
    let schema30 = openapi30
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("3.0 schema resolves")
        .schema
        .0;
    assert_eq!(schema30["type"], json!(["string", "null"]));
    assert!(schema30.get("nullable").is_none());

    let openapi31 = document("3.1.1", json!({"type": "string", "nullable": true}));
    assert_eq!(openapi31.dialect(), OpenApiDialect::OpenApi31);
    assert_eq!(openapi31.openapi_version(), "3.1.1");
    let schema31 = openapi31
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("3.1 schema resolves")
        .schema
        .0;
    assert_eq!(schema31["type"], "string");
    assert_eq!(schema31["nullable"], true);
}

#[test]
fn declared_operations_are_complete_and_exact_operation_lookup_resolves_path_refs() {
    let spec = Spec::from_value(
        json!({
            "openapi": "3.1.0",
            "info": {"title": "Source", "version": "1"},
            "paths": {
                "/records": {"$ref": "#/components/pathItems/Records"},
                "/health": {"trace": {"responses": {}}}
            },
            "components": {
                "pathItems": {
                    "Records": {
                        "get": {"operationId": "listRecords"},
                        "delete": {"operationId": "deleteRecord"}
                    }
                }
            }
        }),
        "operations",
    )
    .expect("valid OpenAPI document");

    assert_eq!(
        spec.declared_operations().expect("operations resolve"),
        vec![
            operation("TRACE", "/health"),
            operation("GET", "/records"),
            operation("DELETE", "/records"),
        ]
    );
    assert_eq!(
        spec.operation(&operation("DELETE", "/records"))
            .expect("exact operation")
            .get("operationId")
            .and_then(Value::as_str),
        Some("deleteRecord")
    );
}

#[test]
fn declared_operations_report_broken_paths_and_malformed_operations() {
    let broken_ref = Spec::from_value(
        json!({
            "openapi": "3.1.0",
            "info": {"title": "Source", "version": "1"},
            "paths": {"/records": {"$ref": "#/components/pathItems/Missing"}}
        }),
        "broken ref",
    )
    .expect("version is valid");
    let error = broken_ref.declared_operations().unwrap_err().to_string();
    assert!(error.contains("/records"), "message was: {error}");

    let malformed = Spec::from_value(
        json!({
            "openapi": "3.1.0",
            "info": {"title": "Source", "version": "1"},
            "paths": {"/records": {"get": "not an operation"}}
        }),
        "malformed operation",
    )
    .expect("version is valid");
    let error = malformed.declared_operations().unwrap_err().to_string();
    assert!(error.contains("GET /records"), "message was: {error}");

    let unknown_method = Spec::from_value(
        json!({
            "openapi": "3.1.0",
            "info": {"title": "Source", "version": "1"},
            "paths": {"/records": {"connect": {"responses": {}}}}
        }),
        "unknown method",
    )
    .expect("version is valid");
    let error = unknown_method
        .declared_operations()
        .unwrap_err()
        .to_string();
    assert!(error.contains("connect"), "message was: {error}");
}

#[test]
fn operation_parameters_resolve_refs_and_apply_operation_overrides() {
    let spec = Spec::from_value(
        json!({
            "openapi": "3.1.0",
            "info": {"title": "Source", "version": "1"},
            "paths": {
                "/records/{record_id}": {
                    "parameters": [
                        {"$ref": "#/components/parameters/RecordId"},
                        {"$ref": "#/components/parameters/PageSize"}
                    ],
                    "get": {
                        "parameters": [
                            {"$ref": "#/components/parameters/SmallPageSize"},
                            {
                                "name": "X-Trace",
                                "in": "header",
                                "schema": {"type": "string", "example": "from-schema"}
                            }
                        ]
                    }
                }
            },
            "components": {
                "schemas": {
                    "RecordId": {"type": "string", "minLength": 1}
                },
                "parameters": {
                    "RecordId": {
                        "name": "record_id",
                        "in": "path",
                        "required": true,
                        "example": "record-123",
                        "schema": {"$ref": "#/components/schemas/RecordId"}
                    },
                    "PageSize": {
                        "name": "page_size",
                        "in": "query",
                        "example": 20,
                        "schema": {"type": "integer", "default": 25}
                    },
                    "SmallPageSize": {
                        "name": "page_size",
                        "in": "query",
                        "example": 4,
                        "schema": {"type": "integer", "default": 5}
                    }
                }
            }
        }),
        "parameters",
    )
    .expect("valid OpenAPI document");

    let parameters = spec
        .operation_parameters(&operation("GET", "/records/{record_id}"))
        .expect("parameters resolve");
    assert_eq!(parameters.len(), 3);

    assert_eq!(parameters[0].name, "record_id");
    assert_eq!(parameters[0].location, ParameterLocation::Path);
    assert!(parameters[0].required);
    assert_eq!(parameters[0].schema.0["type"], "string");
    assert_eq!(parameters[0].example, Some(json!("record-123")));

    assert_eq!(parameters[1].name, "page_size");
    assert_eq!(parameters[1].location, ParameterLocation::Query);
    assert!(!parameters[1].required);
    assert_eq!(parameters[1].example, Some(json!(4)));
    assert_eq!(parameters[1].default, Some(json!(5)));

    assert_eq!(parameters[2].name, "X-Trace");
    assert_eq!(parameters[2].location, ParameterLocation::Header);
    assert_eq!(parameters[2].example, Some(json!("from-schema")));
}

#[test]
fn openapi31_ref_annotations_are_retained_and_constraint_siblings_are_refused() {
    let annotated = Spec::from_value(
        json!({
            "openapi": "3.1.0",
            "info": {"title": "Source", "version": "1"},
            "paths": {
                "/records": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "record",
                                "content": {"application/json": {"schema": {
                                    "$ref": "#/components/schemas/RecordId",
                                    "description": "Identifier returned here"
                                }}}
                            }
                        }
                    }
                }
            },
            "components": {"schemas": {"RecordId": {"type": "string"}}}
        }),
        "annotated ref",
    )
    .expect("valid OpenAPI document");
    let schema = annotated
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("annotation sibling resolves")
        .schema
        .0;
    assert_eq!(schema["description"], "Identifier returned here");
    assert_eq!(schema["allOf"][0]["type"], "string");

    let constrained = Spec::from_value(
        json!({
            "openapi": "3.1.0",
            "info": {"title": "Source", "version": "1"},
            "paths": {
                "/records": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "record",
                                "content": {"application/json": {"schema": {
                                    "$ref": "#/components/schemas/RecordId",
                                    "minLength": 4
                                }}}
                            }
                        }
                    }
                }
            },
            "components": {"schemas": {"RecordId": {"type": "string"}}}
        }),
        "constrained ref",
    )
    .expect("valid OpenAPI document");
    let error = constrained
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("minLength"), "message was: {message}");
    assert!(message.contains("OpenAPI 3.1"), "message was: {message}");
}

#[test]
fn openapi30_ref_siblings_are_ignored_before_nullable_normalization() {
    let spec = Spec::from_value(
        json!({
            "openapi": "3.0.3",
            "info": {"title": "Source", "version": "1"},
            "paths": {
                "/records": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "record",
                                "content": {"application/json": {"schema": {
                                    "$ref": "#/components/schemas/RecordId",
                                    "nullable": true,
                                    "minLength": 12
                                }}}
                            }
                        }
                    }
                }
            },
            "components": {"schemas": {"RecordId": {
                "type": "string",
                "nullable": true,
                "minLength": 1
            }}}
        }),
        "3.0 ref siblings",
    )
    .expect("valid OpenAPI document");

    let schema = spec
        .response_schema(&operation("GET", "/records"), "200", "application/json")
        .expect("3.0 ref resolves")
        .schema
        .0;
    assert_eq!(schema["type"], json!(["string", "null"]));
    assert_eq!(schema["minLength"], 1);
    assert!(schema.get("nullable").is_none());
}

#[test]
fn root_mock_hint_does_not_search_nested_extensions() {
    let hint = json!({"generator": "canonical"});
    let spec = Spec::from_value(
        json!({
            "openapi": "3.1.0",
            "info": {"title": "Source", "version": "1"},
            "x-evidencectl-mock": hint,
            "paths": {
                "/records": {
                    "get": {"x-evidencectl-mock": {"ignored": true}}
                }
            }
        }),
        "mock hint",
    )
    .expect("valid OpenAPI document");

    assert_eq!(spec.mock_hint(), Some(&json!({"generator": "canonical"})));
}

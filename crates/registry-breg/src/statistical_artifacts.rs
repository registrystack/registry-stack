// SPDX-License-Identifier: Apache-2.0
//! Shared statistical-dataset metadata and OpenAPI projections.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use crate::model::{CompiledStatisticalDataset, CompiledStatisticalPeriod};
use crate::statistics::{TOTAL_CODE, UNKNOWN_CODE};

pub(crate) fn statistical_dataset_metadata_entry(
    dataset: &CompiledStatisticalDataset,
    profile: &str,
) -> Option<Value> {
    let operations = statistical_dataset_operations(dataset, profile);
    if operations.is_empty() {
        return None;
    }
    let (period_kind, granularity, first_period) = period_metadata(&dataset.period);
    Some(json!({
        "id": dataset.id,
        "unit": dataset.unit_entity_id,
        "periodKind": period_kind,
        "granularity": granularity,
        "firstPeriod": first_period,
        "dimensions": dataset.dimensions.iter().map(|dimension| {
            let mut codes = dimension.codes.clone();
            if dimension.include_unknown {
                codes.push(UNKNOWN_CODE.to_owned());
            }
            codes.push(TOTAL_CODE.to_owned());
            json!({
                "field": dimension.field,
                "vocabulary": dimension_vocabulary(dimension),
                "codes": codes,
            })
        }).collect::<Vec<_>>(),
        "definitionDigest": dataset.definition_digest,
        "operations": operations,
    }))
}

pub(crate) fn all_statistical_dataset_metadata(
    datasets: &BTreeMap<String, CompiledStatisticalDataset>,
) -> Value {
    Value::Array(
        datasets
            .values()
            .map(|dataset| {
                let mut profiles = Map::new();
                for profile in dataset.access_profiles.keys() {
                    if let Some(entry) = statistical_dataset_metadata_entry(dataset, profile) {
                        profiles.insert(profile.clone(), entry["operations"].clone());
                    }
                }
                let (period_kind, granularity, first_period) = period_metadata(&dataset.period);
                json!({
                    "id": dataset.id,
                    "unit": dataset.unit_entity_id,
                    "periodKind": period_kind,
                    "granularity": granularity,
                    "firstPeriod": first_period,
                    "dimensions": dataset.dimensions.iter().map(|dimension| {
                        let mut codes = dimension.codes.clone();
                        if dimension.include_unknown { codes.push(UNKNOWN_CODE.to_owned()); }
                        codes.push(TOTAL_CODE.to_owned());
                        json!({"field":dimension.field,"vocabulary":dimension_vocabulary(dimension),"codes":codes})
                    }).collect::<Vec<_>>(),
                    "definitionDigest": dataset.definition_digest,
                    "accessProfiles": profiles,
                })
            })
            .collect(),
    )
}

fn dimension_vocabulary(dimension: &crate::model::CompiledStatisticalDimension) -> &str {
    match &dimension.domain {
        crate::model::CompiledStatisticalDimensionDomain::Boolean => "boolean",
        crate::model::CompiledStatisticalDimensionDomain::Vocabulary { vocabulary } => vocabulary,
    }
}

pub(crate) fn statistical_dataset_operations(
    dataset: &CompiledStatisticalDataset,
    profile: &str,
) -> BTreeSet<&'static str> {
    let mut operations = BTreeSet::new();
    if dataset.live_profiles.contains(profile) {
        operations.insert("read_live");
    }
    if let Some(releases) = &dataset.releases {
        let can_read = dataset.live_profiles.contains(profile)
            || releases.publisher == profile
            || releases.readers.contains(profile);
        if can_read {
            operations.extend([
                "list_releases",
                "read_released_series",
                "read_latest_release",
                "read_release_version",
            ]);
        }
        if releases.publisher == profile {
            operations.extend(["publish_release", "withdraw_release"]);
        }
    }
    operations
}

fn period_metadata(
    period: &CompiledStatisticalPeriod,
) -> (&'static str, crate::statistics::PeriodGranularity, &str) {
    match period {
        CompiledStatisticalPeriod::Flow {
            granularity,
            first_period,
            ..
        } => ("flow", *granularity, first_period),
        CompiledStatisticalPeriod::Stock {
            granularity,
            first_period,
            ..
        } => ("stock", *granularity, first_period),
    }
}

pub(crate) fn append_statistics_openapi(
    paths: &mut Map<String, Value>,
    component_schemas: &mut Map<String, Value>,
    datasets: &BTreeMap<String, CompiledStatisticalDataset>,
    admission_datasets: &BTreeMap<String, CompiledStatisticalDataset>,
    selected: bool,
) {
    if datasets.is_empty() {
        return;
    }
    component_schemas.insert("StatisticalDatasetDocument".to_owned(), document_schema());
    component_schemas.insert(
        "StatisticalReleaseHeader".to_owned(),
        release_header_schema(),
    );
    component_schemas.insert(
        "StatisticalReleasePage".to_owned(),
        json!({
            "type":"object","additionalProperties":false,
            "required":["items","pageInfo"],
            "properties":{
                "items":{"type":"array","items":{"$ref":"#/components/schemas/StatisticalReleaseHeader"}},
                "pageInfo":{
                    "type":"object","additionalProperties":false,
                    "required":["hasMore","nextCursor"],
                    "properties":{
                        "hasMore":{"type":"boolean"},
                        "nextCursor":{"type":["string","null"]}
                    }
                }
            }
        }),
    );
    component_schemas.insert(
        "StatisticalReleaseRequest".to_owned(),
        json!({
            "type":"object","additionalProperties":false,"required":["status"],
            "properties":{"status":{"type":"string","enum":["provisional","final"]}}
        }),
    );
    component_schemas.insert(
        "StatisticalWithdrawalRequest".to_owned(),
        json!({
            "type":"object","additionalProperties":false,"required":["reason"],
            "properties":{"reason":{"type":"string","enum":["computation-error","source-data-error","disclosure-risk"]}}
        }),
    );
    for dataset in datasets.values() {
        let admission_dataset = admission_datasets.get(&dataset.id).unwrap_or(dataset);
        let base = format!("/v1/statistics/{}", dataset.id);
        if !dataset.live_profiles.is_empty() {
            insert_operation(
                paths,
                &format!("{base}:live"),
                "get",
                operation(
                    dataset,
                    selected,
                    "read_live",
                    &dataset.live_profiles,
                    &admission_dataset.live_profiles,
                    read_parameters(RangeParameters::Optional, false, false, false),
                    success_document_response(),
                    None,
                ),
            );
        }
        let Some(releases) = &dataset.releases else {
            continue;
        };
        let readers = release_read_profiles(dataset);
        let admission_readers = release_read_profiles(admission_dataset);
        if !readers.is_empty() {
            insert_operation(
                paths,
                &format!("{base}/releases"),
                "get",
                operation(
                    dataset,
                    selected,
                    "list_releases",
                    &readers,
                    &admission_readers,
                    release_list_parameters(),
                    json!({"200": json_response("StatisticalReleasePage", false), "400": problem_response(), "401": problem_response(), "404": problem_response(), "503": problem_response(), "504":problem_response()}),
                    None,
                ),
            );
            insert_operation(
                paths,
                &format!("{base}/releases:series"),
                "get",
                operation(
                    dataset,
                    selected,
                    "read_released_series",
                    &readers,
                    &admission_readers,
                    read_parameters(RangeParameters::Required, true, false, false),
                    success_document_response(),
                    None,
                ),
            );
            insert_operation(
                paths,
                &format!("{base}/releases/{{period}}"),
                "get",
                operation(
                    dataset,
                    selected,
                    "read_latest_release",
                    &readers,
                    &admission_readers,
                    read_parameters(RangeParameters::None, true, true, false),
                    success_document_response(),
                    None,
                ),
            );
            insert_operation(
                paths,
                &format!("{base}/releases/{{period}}/versions/{{version}}"),
                "get",
                operation(
                    dataset,
                    selected,
                    "read_release_version",
                    &readers,
                    &admission_readers,
                    read_parameters(RangeParameters::None, false, true, true),
                    success_document_response(),
                    None,
                ),
            );
        }
        if !releases.publisher.is_empty() {
            let publisher = BTreeSet::from([releases.publisher.clone()]);
            let admission_publisher = admission_dataset
                .releases
                .as_ref()
                .filter(|releases| !releases.publisher.is_empty())
                .map(|releases| BTreeSet::from([releases.publisher.clone()]))
                .unwrap_or_default();
            insert_operation(
                paths,
                &format!("{base}/releases/{{period}}/versions"),
                "post",
                operation(
                    dataset,
                    selected,
                    "publish_release",
                    &publisher,
                    &admission_publisher,
                    publish_parameters(false),
                    json!({"201": json_response("StatisticalReleaseHeader", true), "400":problem_response(), "401":problem_response(), "404":problem_response(), "409":problem_response(), "410":problem_response(), "415":problem_response(), "422":problem_response(), "500":problem_response(), "503":problem_response(), "504":problem_response()}),
                    Some("StatisticalReleaseRequest"),
                ),
            );
            insert_operation(
                paths,
                &format!("{base}/releases/{{period}}/versions/{{version}}/withdrawal"),
                "post",
                operation(
                    dataset,
                    selected,
                    "withdraw_release",
                    &publisher,
                    &admission_publisher,
                    publish_parameters(true),
                    json!({"200": json_response("StatisticalReleaseHeader", true), "400":problem_response(), "401":problem_response(), "404":problem_response(), "409":problem_response(), "410":problem_response(), "415":problem_response(), "422":problem_response(), "500":problem_response(), "503":problem_response(), "504":problem_response()}),
                    Some("StatisticalWithdrawalRequest"),
                ),
            );
        }
    }
}

fn release_read_profiles(dataset: &CompiledStatisticalDataset) -> BTreeSet<String> {
    let mut profiles = dataset.live_profiles.clone();
    if let Some(releases) = &dataset.releases {
        if !releases.publisher.is_empty() {
            profiles.insert(releases.publisher.clone());
        }
        profiles.extend(
            releases
                .readers
                .iter()
                .filter(|profile| !profile.is_empty())
                .cloned(),
        );
    }
    profiles
}

fn insert_operation(paths: &mut Map<String, Value>, path: &str, method: &str, operation: Value) {
    paths.entry(path.to_owned()).or_insert_with(|| json!({}))[method] = operation;
}

#[allow(clippy::too_many_arguments)] // Each route supplies its generated request and response contract.
fn operation(
    dataset: &CompiledStatisticalDataset,
    selected: bool,
    operation: &str,
    profiles: &BTreeSet<String>,
    admission_profiles: &BTreeSet<String>,
    mut parameters: Vec<Value>,
    responses: Value,
    request_schema: Option<&str>,
) -> Value {
    let default_profile = admission_profiles
        .iter()
        .find(|id| {
            dataset
                .access_profiles
                .get(*id)
                .is_some_and(|profile| profile.default)
        })
        .or_else(|| {
            (admission_profiles.len() == 1)
                .then(|| admission_profiles.first())
                .flatten()
        });
    if let Some(parameter) = parameters
        .iter_mut()
        .find(|parameter| parameter["in"] == "query" && parameter["name"] == "accessProfile")
    {
        parameter["required"] = json!(default_profile.is_none());
        if let Some(default_profile) = default_profile {
            parameter["schema"]["default"] = json!(default_profile);
        }
    }
    let mut value = json!({
        "operationId": format!("statistics.{}.{}", dataset.id, operation),
        "security":[{"bearerAuth":[]}],
        "parameters": parameters,
        "responses": responses,
        "x-registry-statisticalDataset": dataset.id,
        "x-registry-statisticalOperation": operation,
    });
    if selected {
        let profile = profiles
            .first()
            .expect("selected statistical operation has a profile");
        value["x-registry-accessProfile"] = json!(profile);
        if let Some(parameter) = value["parameters"].as_array_mut().and_then(|parameters| {
            parameters.iter_mut().find(|parameter| {
                parameter["in"] == "query" && parameter["name"] == "accessProfile"
            })
        }) {
            parameter["schema"]["const"] = json!(profile);
            parameter["description"] = json!("Select this caller-visible access profile explicitly unless it is the configured default.");
        }
    } else {
        value["x-registry-accessProfiles"] = json!(profiles);
        value["x-registry-defaultAccessProfile"] = json!(default_profile);
    }
    if let Some(schema) = request_schema {
        value["requestBody"] = json!({
            "required":true,
            "content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{schema}")}}}
        });
    }
    value
}

fn access_profile_parameter() -> Value {
    json!({"in":"query","name":"accessProfile","required":false,"schema":{"type":"string","maxLength":128}})
}

fn trace_parameter() -> Value {
    json!({"in":"header","name":"traceparent","required":false,"schema":{"type":"string","maxLength":55}})
}

fn period_parameter() -> Value {
    json!({"in":"path","name":"period","required":true,"schema":{"type":"string","maxLength":10}})
}

fn version_parameter() -> Value {
    json!({"in":"path","name":"version","required":true,"schema":{"type":"integer","format":"int64","minimum":1}})
}

#[derive(Clone, Copy)]
enum RangeParameters {
    None,
    Optional,
    Required,
}

fn read_parameters(
    range: RangeParameters,
    status: bool,
    period: bool,
    version: bool,
) -> Vec<Value> {
    let mut parameters = vec![access_profile_parameter(), trace_parameter()];
    if period {
        parameters.push(period_parameter());
    }
    if version {
        parameters.push(version_parameter());
    }
    if !matches!(range, RangeParameters::None) {
        let required = matches!(range, RangeParameters::Required);
        parameters.extend([
            json!({"in":"query","name":"from","required":required,"schema":{"type":"string","maxLength":10}}),
            json!({"in":"query","name":"to","required":required,"schema":{"type":"string","maxLength":10}}),
        ]);
    }
    if status {
        parameters.push(json!({"in":"query","name":"status","required":false,"schema":{"type":"string","enum":["final"]}}));
    }
    parameters.push(json!({"in":"header","name":"Accept","required":false,"schema":{"type":"string","enum":["application/json","text/csv"]}}));
    parameters
}

fn release_list_parameters() -> Vec<Value> {
    vec![
        access_profile_parameter(),
        trace_parameter(),
        json!({"in":"query","name":"$top","required":false,"schema":{"type":"integer","minimum":1,"maximum":100,"default":50}}),
        json!({"in":"query","name":"$skiptoken","required":false,"schema":{"type":"string"}}),
    ]
}

fn publish_parameters(version: bool) -> Vec<Value> {
    let mut parameters = vec![
        access_profile_parameter(),
        trace_parameter(),
        period_parameter(),
    ];
    if version {
        parameters.push(version_parameter());
    }
    parameters.push(json!({
        "in":"header","name":"Idempotency-Key","required":true,
        "schema":{
            "type":"string","minLength":1,"maxLength":256,
            "pattern":"^[\\x21-\\x2B\\x2D-\\x3A\\x3C-\\x7E]+$"
        }
    }));
    parameters
}

fn success_document_response() -> Value {
    json!({
        "200": {
            "description":"Statistical dataset document returned.",
            "headers": read_headers(true),
            "content":{
                "application/json":{"schema":{"$ref":"#/components/schemas/StatisticalDatasetDocument"}},
                "text/csv":{"schema":{"type":"string"}}
            }
        },
        "400":problem_response(), "401":problem_response(), "404":problem_response(),
        "410":problem_response(), "500":problem_response(), "503":problem_response(), "504":problem_response()
    })
}

fn json_response(schema: &str, digest: bool) -> Value {
    json!({
        "description":"Request completed.",
        "headers":read_headers(digest),
        "content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{schema}")}}}
    })
}

fn problem_response() -> Value {
    json!({
        "description":"Problem response.",
        "headers":{"Cache-Control":{"schema":{"const":"no-store"}}},
        "content":{"application/problem+json":{"schema":{"$ref":"#/components/schemas/Problem"}}}
    })
}

fn read_headers(digest: bool) -> Value {
    let mut headers = Map::from_iter([
        (
            "Cache-Control".to_owned(),
            json!({"schema":{"const":"no-store"}}),
        ),
        ("Vary".to_owned(), json!({"schema":{"type":"string"}})),
        (
            "traceparent".to_owned(),
            json!({"schema":{"type":"string","maxLength":55}}),
        ),
    ]);
    if digest {
        headers.insert(
            "Repr-Digest".to_owned(),
            json!({"schema":{"type":"string","pattern":"^sha-256=:[A-Za-z0-9+/]+=*:$"}}),
        );
    }
    Value::Object(headers)
}

fn document_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["dataset","periods","dimensions","cells"],
        "properties":{
            "dataset":{
                "type":"object","additionalProperties":false,
                "required":["id","unit","measure","periodKind","granularity","population","definitionDigest"],
                "properties":{
                    "id":{"type":"string"},"unit":{"type":"string"},
                    "measure":{"const":"count"},
                    "periodKind":{"type":"string","enum":["flow","stock"]},
                    "granularity":{"type":"string","enum":["day","month","quarter","year"]},
                    "population":{"type":"string"},
                    "definitionDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"}
                }
            },
            "periods":{
                "type":"array","items":{
                    "type":"object","additionalProperties":false,
                    "required":["code","start","end","referenceDate","ended"],
                    "properties":{
                        "code":{"type":"string"},"start":{"type":"string","format":"date"},
                        "end":{"type":"string","format":"date"},
                        "referenceDate":{"type":"string","format":"date"},"ended":{"type":"boolean"},
                        "version":{
                            "type":"object","additionalProperties":false,
                            "required":["version","status","contentDigest","snapshot"],
                            "properties":{
                                "version":{"type":"integer","format":"int64","minimum":1},
                                "status":{"type":"string","enum":["provisional","final"]},
                                "contentDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
                                "snapshot":{"type":["string","null"]}
                            }
                        }
                    }
                }
            },
            "dimensions":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["field","vocabulary","codes"],"properties":{"field":{"type":"string"},"vocabulary":{"type":"string"},"codes":{"type":"array","items":{"type":"string"}}}}},
            "cells":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["period","dimensions","value","status"],"properties":{"period":{"type":"string"},"dimensions":{"type":"object","additionalProperties":{"type":"string"}},"value":{"type":["integer","null"],"minimum":0},"status":{"type":"string","enum":["exact","suppressed","rounded"]}}}},
            "release":{
                "type":"object","additionalProperties":false,
                "required":["period","version","status","snapshot","computedAt","packageDigest"],
                "properties":{
                    "period":{"type":"string"},"version":{"type":"integer","format":"int64","minimum":1},
                    "status":{"type":"string","enum":["provisional","final"]},"snapshot":{"type":["string","null"]},
                    "computedAt":{"type":"string","format":"date-time"},
                    "packageDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"}
                }
            },
            "live":{
                "type":"object","additionalProperties":false,"required":["evaluatedAt","accessProfile"],
                "properties":{"evaluatedAt":{"type":"string","format":"date"},"accessProfile":{"type":"string"}}
            },
            "disclosure":{
                "type":"object","additionalProperties":false,
                "required":["method","minimumCount","roundingBase","roundingRule","totals"],
                "properties":{
                    "method":{"const":"minimum-count-and-rounding"},
                    "minimumCount":{"type":"integer","minimum":2},"roundingBase":{"type":"integer","minimum":2},
                    "roundingRule":{"const":"nearest-multiple-halves-up"},
                    "totals":{"const":"rounded-independently"}
                }
            }
        }
    })
}

fn release_header_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["dataset","period","version","status","definitionDigest","snapshot","computedAt","packageDigest"],
        "oneOf":[{"required":["contentDigest"]},{"required":["withdrawal"]}],
        "properties":{
            "dataset":{"type":"string"},"period":{"type":"string"},
            "version":{"type":"integer","format":"int64","minimum":1},
            "status":{"type":"string","enum":["provisional","final"]},
            "definitionDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "contentDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "snapshot":{"type":["string","null"]},"computedAt":{"type":"string","format":"date-time"},
            "packageDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "withdrawal":{
                "type":"object","additionalProperties":false,"required":["withdrawnAt","reason"],
                "properties":{
                    "withdrawnAt":{"type":"string","format":"date-time"},
                    "reason":{"type":"string","enum":["computation-error","source-data-error","disclosure-risk"]}
                }
            }
        }
    })
}

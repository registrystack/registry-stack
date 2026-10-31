// SPDX-License-Identifier: Apache-2.0

//! The facade profile: the contract artifact a deployment serves
//! (`products/adapter/CONCEPT.md` sections 6 and 7).
//!
//! Nothing about any one target API is compiled in: a profile declares its
//! operation set by id, its request and response envelope templates over
//! the closed slot vocabulary, its pagination parameters, and its problem
//! codes and problem envelope. The engine owns the mechanism (filling
//! slots, encoding cursors, setting the status); the profile owns every
//! name and shape a caller sees.

use registry_platform_yaml::{BoundedU64, ExternalId, LocalId, UniqueIdList, UniqueList};
use serde::{Deserialize, Serialize};

use crate::project::RecordField;

/// One facade response whose status is fixed by the engine rather than the
/// profile's authored default. The class remains profile-mapped, so the code,
/// title, and optional data contract still come from the closest declared
/// problem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedFacadeProblemResponse {
    pub class: crate::model::ErrorClass,
    pub status: u16,
}

/// The closed facade class/status pairs emitted by fixed engine paths. Keep
/// this source-neutral list aligned with the runtime's controlled
/// `facade_problem` call sites.
pub const FIXED_FACADE_PROBLEM_RESPONSES: &[FixedFacadeProblemResponse] = &[
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::Facade,
        status: 500,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::Facade,
        status: 503,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::FacadeUnauthenticated,
        status: 401,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::FacadeForbidden,
        status: 403,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::FacadeInvalidRequest,
        status: 400,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::FacadeInvalidField,
        status: 422,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::FacadeInvalidCursor,
        status: 400,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::FacadeNotFound,
        status: 404,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::FacadeMethodNotAllowed,
        status: 405,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::FacadePayloadTooLarge,
        status: 413,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::FacadeUnsupportedMediaType,
        status: 415,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::FacadeNotAcceptable,
        status: 406,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::FacadeConflict,
        status: 409,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::FacadeIdempotencyMismatch,
        status: 422,
    },
    FixedFacadeProblemResponse {
        class: crate::model::ErrorClass::OutcomeNotFound,
        status: 404,
    },
];

/// Look up one controlled facade class/status pair. The runtime uses the
/// typed pair at its fixed facade boundary; derived problem schemas use the
/// same closed descriptor.
#[must_use]
pub fn fixed_facade_problem_response(
    class: crate::model::ErrorClass,
    status: u16,
) -> Option<&'static FixedFacadeProblemResponse> {
    FIXED_FACADE_PROBLEM_RESPONSES
        .iter()
        .find(|response| response.class == class && response.status == status)
}

/// The most scalar fields one problem may disclose in its optional data
/// object. The bound keeps the reviewed problem contract small.
pub const MAX_PROBLEM_DATA_FIELDS: usize = 16;

/// The largest serialized problem data object the runtime may release.
pub const MAX_PROBLEM_DATA_BYTES: usize = 2 * 1024;

/// The closed envelope slot vocabulary the engine fills
/// (`products/adapter/CONCEPT.md` section 7). A slot outside this set is
/// refused by the authoring checks.
pub const ENVELOPE_SLOTS: &[&str] = &[
    "cursor",
    "filters",
    "nextCursor",
    "problemCode",
    "problemData",
    "problemDetail",
    "problemTitle",
    "record",
    "recordId",
    "recordType",
    "pageSize",
    "records",
    "requestId",
    "status",
];

/// The slots only a read operation's request envelope fills, from the
/// caller's JSON body; every response, item, and problem envelope refuses
/// them.
pub const READ_REQUEST_SLOTS: &[&str] = &["cursor", "filters", "pageSize", "recordId"];

/// The slot holding one validated route result.
pub const SLOT_RECORD: &str = "record";
/// The slot holding the validated result list.
pub const SLOT_RECORDS: &str = "records";
/// The problem envelope's code slot; a problem envelope without it is
/// refused.
pub const SLOT_PROBLEM_CODE: &str = "problemCode";
/// The optional, closed data object declared by the selected problem.
pub const SLOT_PROBLEM_DATA: &str = "problemData";

/// An envelope template: a JSON template whose string members carry
/// `{{slot}}` placeholders from the closed vocabulary
/// (`products/adapter/CONCEPT.md` section 7). The template is data; the
/// engine fills it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeTemplate(pub String);

impl EnvelopeTemplate {
    /// The template text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }

    /// Whether the template mentions a slot, in required (`{{slot}}`) or
    /// optional (`{{?slot}}`), or null (`{{??slot}}`) form.
    #[must_use]
    pub fn mentions(&self, slot: &str) -> bool {
        crate::checks::envelope_placeholders(self.text())
            .into_iter()
            .any(|(name, _)| name == slot)
    }
}

/// One facade operation, declared by id
/// (`products/adapter/CONCEPT.md` sections 6 and 7). The id is a
/// profile-declared bounded string (CFG-ID-5), never an engine enum.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileOperation {
    /// The profile-declared operation id a binding names.
    pub id: LocalId,
    /// The facade method.
    pub method: crate::model::HttpMethod,
    /// The facade path template, e.g. `/v2/cases/{type}`. Placeholders
    /// are single-brace `{name}` templates, Camel REST DSL / OpenAPI path
    /// templating; `{{name}}` is the pack layer's substitution syntax and
    /// refuses here.
    pub path: String,
    /// The path parameters the template names: every `{name}` in `path`
    /// must resolve here, every entry must appear in the path, and the
    /// list is unique (CFG-ID-6).
    #[serde(default, skip_serializing_if = "path_parameters_empty")]
    pub path_parameters: UniqueList<LocalId>,
    /// The path parameter the bound record type substitutes into
    /// (`products/adapter/CONCEPT.md` section 7): one of `pathParameters`,
    /// checked at the profile checks. No rule reads meaning from the
    /// parameter's position.
    pub record_type_parameter: LocalId,
    /// The path parameter the caller's `recordId` header fills on get,
    /// update, and patch; one of `pathParameters` when declared. A search
    /// or create operation fills none; the profile checks require the
    /// parameter exactly where the facade reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id_parameter: Option<LocalId>,
    /// The status the facade answers a success with; two hundreds only
    /// (CFG-QTY-4). Every non-2xx answer is a problem body.
    #[serde(default = "default_success_status")]
    pub success_status: registry_platform_yaml::BoundedU32<200, 299>,
    /// Where a writable record sits in an incoming body. A write
    /// operation's request envelope must name the `record` slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_envelope: Option<EnvelopeTemplate>,
    /// Whether a POST operation only reads: it is served like a read
    /// (never the write path), its request envelope is a closed template
    /// over the caller's JSON body, and its route reaches only safe sends.
    /// A GET operation is a read without declaring it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub read_only: bool,
    /// The largest request body, in bytes, a read operation with a body
    /// accepts; a larger one answers `facade.payload-too-large`. Sixteen
    /// kibibytes when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_maximum_bytes: Option<BoundedU64<1, 1_048_576>>,
    /// The response envelope; must name its result slot.
    pub response_envelope: EnvelopeTemplate,
    /// The per-record template: when declared, every record the response
    /// envelope's `record` or `records` slot carries is rendered through
    /// it first. It may name `record`, `recordId` (the identifier the
    /// route's record carries beside its domain data), `recordType`, and
    /// `requestId`. A call whose route yields no identifier for a template
    /// that names `recordId` is a disclosure violation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_envelope: Option<EnvelopeTemplate>,
    /// The pagination parameters of a search operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pagination: Option<PaginationParameters>,
}

impl ProfileOperation {
    /// Whether the operation only reads: a GET, or a POST declaring
    /// `readOnly`.
    #[must_use]
    pub fn is_read(&self) -> bool {
        self.method.is_safe() || self.read_only
    }
}

impl registry_platform_yaml::Identified for ProfileOperation {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

/// The pagination parameters of a search operation: the cursor and
/// page-size query parameter names and their bounds
/// (`products/adapter/CONCEPT.md` section 7). The engine owns encoding the
/// cursor; the profile owns the names.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaginationParameters {
    /// The cursor query parameter name.
    pub cursor_parameter: ExternalId,
    /// The page-size query parameter name.
    pub page_size_parameter: ExternalId,
    /// The smallest page size a caller may ask for.
    pub page_size_minimum: BoundedU64<1, 10_000>,
    /// The largest page size a caller may ask for.
    pub page_size_maximum: BoundedU64<1, 100_000>,
    /// The page size a call that names none gets; within the bounds. A
    /// cursor carries the page size of the call that minted it: a later
    /// call may omit the size, and one that names a different size is
    /// refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size_default: Option<BoundedU64<1, 100_000>>,
}

/// One parameterized part: a part of the profile a deployment declares at
/// bind time (`products/adapter/CONCEPT.md` sections 6 and 7).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParameterizedPart {
    /// The part name.
    pub name: ExternalId,
    /// What the part means, for review.
    pub description: String,
}

/// One problem a caller can receive: the profile's own answer shape for
/// the error classes it maps (`products/adapter/CONCEPT.md` sections 7
/// and 8.11.6). A pack raises error classes and never names a problem
/// code or builds a problem body; the profile decides what the caller
/// sees.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Problem {
    /// The profile's own problem code a caller receives.
    pub code: ExternalId,
    /// The default HTTP status for profile-governed route failures. Fixed
    /// facade admission failures retain their engine-defined status; the
    /// effective problem schema includes those resolved class/status pairs.
    pub status: registry_platform_yaml::BoundedU32<400, 599>,
    /// The problem title the envelope's `problemTitle` slot fills from.
    pub title: String,
    /// The error classes this problem answers: a class resolves to the
    /// entry whose declared class is closest to it, by the rule of
    /// `products/adapter/CONCEPT.md` section 8.7.
    pub classes: UniqueList<crate::model::ErrorClass>,
    /// The optional closed scalar object this problem may disclose. Every
    /// declared field is required when the object is present; authoring
    /// checks enforce the field-count and required-field bounds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = MAX_PROBLEM_DATA_FIELDS))
    )]
    pub data_fields: Option<UniqueList<RecordField>>,
}

impl registry_platform_yaml::Identified for Problem {
    fn id(&self) -> &str {
        self.code.as_str()
    }
}

/// Resolve the problem whose declared class is the closest ancestor of the
/// raised class. Authoring checks guarantee one result for every class.
#[must_use]
pub fn resolve_problem(
    profile: &AdapterProfile,
    class: crate::model::ErrorClass,
) -> Option<&Problem> {
    let mut best: Option<(usize, &Problem)> = None;
    for problem in profile.problems.iter() {
        for declared in problem.classes.iter() {
            if class.is_within(*declared) {
                let depth = declared.class().split('.').count();
                if best.is_none_or(|(held, _)| depth > held) {
                    best = Some((depth, problem));
                }
            }
        }
    }
    best.map(|(_, problem)| problem)
}

/// The facade profile artifact (`AdapterProfile`): the operation set, the
/// envelope templates, the pagination parameters, and the problems and
/// problem envelope.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterProfile {
    /// The profile identifier a project pins.
    pub id: LocalId,
    /// The profile's own version; a project pin names it next to the
    /// digest (CFG-ID-4).
    pub version: String,
    /// The operations the profile serves.
    pub operations: UniqueIdList<ProfileOperation>,
    /// The problems a caller can receive, each mapping error classes to a
    /// code, status, and title. The totality check requires every class of
    /// the closed hierarchy, uncatchable and facade classes included, to
    /// resolve to exactly one entry
    /// (`products/adapter/CONCEPT.md` sections 7 and 8.11.6).
    pub problems: UniqueIdList<Problem>,
    /// The problem envelope template; must carry the `problemCode` slot.
    pub problem_envelope: EnvelopeTemplate,
    /// The parts of the profile a deployment declares at bind time.
    #[serde(default)]
    pub parameterized_parts: registry_platform_yaml::UniqueList<ParameterizedPart>,
}

/// A path-parameter list is omitted from the wire when empty, the shape
/// `Vec`'s `skip_serializing_if = "Vec::is_empty"` gave.
fn path_parameters_empty(parameters: &UniqueList<LocalId>) -> bool {
    parameters.is_empty()
}

/// The success status an operation that declares none answers with.
fn is_false(value: &bool) -> bool {
    !*value
}

fn default_success_status() -> registry_platform_yaml::BoundedU32<200, 299> {
    registry_platform_yaml::BoundedU32::new(200).expect("the default status is in range")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_facade_problem_response_lookup_is_closed_to_emitted_pairs() {
        for response in FIXED_FACADE_PROBLEM_RESPONSES {
            assert_eq!(
                fixed_facade_problem_response(response.class, response.status),
                Some(response)
            );
        }
        assert!(
            fixed_facade_problem_response(crate::model::ErrorClass::FacadeInvalidField, 418)
                .is_none()
        );
        assert!(
            fixed_facade_problem_response(crate::model::ErrorClass::OutcomeRejected, 422).is_none()
        );
        let unique: std::collections::HashSet<_> = FIXED_FACADE_PROBLEM_RESPONSES
            .iter()
            .map(|response| (response.class, response.status))
            .collect();
        assert_eq!(unique.len(), FIXED_FACADE_PROBLEM_RESPONSES.len());
    }

    fn operation(id: &str, method: crate::model::HttpMethod) -> ProfileOperation {
        ProfileOperation {
            id: LocalId::new(id).expect("id"),
            method,
            path: "/v2/cases/{type}".to_string(),
            path_parameters: UniqueList::new(vec![LocalId::new("type").expect("id")])
                .expect("unique"),
            record_type_parameter: LocalId::new("type").expect("id"),
            record_id_parameter: Some(LocalId::new("type").expect("id")),
            success_status: default_success_status(),
            request_envelope: None,
            response_envelope: EnvelopeTemplate(r#"{"cases": {{records}}}"#.to_string()),
            item_envelope: None,
            read_only: false,
            request_maximum_bytes: None,
            pagination: None,
        }
    }

    /// One problem entry covering the named classes with the code and
    /// status under test.
    fn problem(code: &str, status: u32, classes: &[crate::model::ErrorClass]) -> Problem {
        Problem {
            code: ExternalId::new(code).expect("code"),
            status: registry_platform_yaml::BoundedU32::<400, 599>::new(status).expect("status"),
            title: "the record could not be read".to_string(),
            classes: UniqueList::new(classes.to_vec()).expect("unique"),
            data_fields: None,
        }
    }

    /// The profile declares its own version (the artifact table:
    /// authored, versioned); the reader refuses a profile without one,
    /// since a project pin compares against it (CFG-ID-4).
    /// The version is text, compared exactly, never a number: an
    /// unquoted numeric version is refused with the reader's usual type
    /// diagnostic, never coerced.
    #[test]
    fn profile_refuses_a_numeric_version() {
        for json in [
            r#"{"id":"case-api","version":1,"operations":[],"problems":[],"problemEnvelope":"{}"}"#,
            r#"{"id":"case-api","version":1.0,"operations":[],"problems":[],"problemEnvelope":"{}"}"#,
        ] {
            assert!(
                serde_json::from_str::<AdapterProfile>(json).is_err(),
                "a numeric version is refused, never coerced"
            );
        }
    }

    #[test]
    fn profile_reader_requires_a_version() {
        let json = r#"{"id":"case-api","operations":[],"problems":[],"problemEnvelope":"{}"}"#;
        assert!(
            serde_json::from_str::<AdapterProfile>(json).is_err(),
            "a profile without a version is refused"
        );
        let declared = r#"{"id":"case-api","version":"1.0.0","operations":[],"problems":[],"problemEnvelope":"{}"}"#;
        let profile = serde_json::from_str::<AdapterProfile>(declared).expect("parse");
        assert_eq!(profile.version, "1.0.0");
    }

    /// The retired flat `problemCodes` member is gone: the problems list
    /// replaced it (`products/adapter/CONCEPT.md` sections 7 and
    /// 8.11.6), and the reader refuses the old member outright rather
    /// than reading half a contract.
    #[test]
    fn profile_refuses_the_retired_problem_codes_member() {
        let json = r#"{"id":"case-api","version":"1.0.0","operations":[],"problemCodes":["cases.conflict"],"problemEnvelope":"{}"}"#;
        assert!(
            serde_json::from_str::<AdapterProfile>(json).is_err(),
            "the retired problemCodes member is refused"
        );
    }

    /// A facade path-parameter list is unique (CFG-ID-6): a repeated
    /// parameter name refuses at the reader.
    #[test]
    fn profile_refuses_duplicate_path_parameters() {
        let operation = r#"{"id":"records-get","method":"GET","path":"/v1/records/{type}","pathParameters":["type","type"],"recordTypeParameter":"type","responseEnvelope":"{\"cases\": {{records}}}"}"#;
        let json = format!(
            r#"{{"id":"case-api","version":"1.0.0","operations":[{operation}],"problems":[],"problemEnvelope":"{{}}"}}"#
        );
        assert!(
            serde_json::from_str::<AdapterProfile>(&json).is_err(),
            "a repeated path parameter refuses"
        );
        let unique = r#"{"id":"records-get","method":"GET","path":"/v1/records/{type}","pathParameters":["type"],"recordTypeParameter":"type","responseEnvelope":"{\"cases\": {{records}}}"}"#;
        let json = format!(
            r#"{{"id":"case-api","version":"1.0.0","operations":[{unique}],"problems":[],"problemEnvelope":"{{}}"}}"#
        );
        let profile = serde_json::from_str::<AdapterProfile>(&json).expect("parse");
        assert_eq!(profile.operations[0].path_parameters.len(), 1);
    }

    /// An operation names the path parameter the bound record type
    /// substitutes into: the member is required at the reader
    /// (`products/adapter/CONCEPT.md` section 7), an operation without
    /// one refuses, and a declared member round-trips.
    #[test]
    fn an_operation_requires_its_record_type_parameter() {
        let without = r#"{"id":"records-get","method":"GET","path":"/v1/records/{type}","pathParameters":["type"],"responseEnvelope":"{\"cases\": {{records}}}"}"#;
        let json = format!(
            r#"{{"id":"case-api","version":"1.0.0","operations":[{without}],"problems":[],"problemEnvelope":"{{}}"}}"#
        );
        assert!(
            serde_json::from_str::<AdapterProfile>(&json).is_err(),
            "an operation without a record type parameter is refused"
        );
        let declared = r#"{"id":"records-get","method":"GET","path":"/v1/records/{type}","pathParameters":["type"],"recordTypeParameter":"type","responseEnvelope":"{\"cases\": {{records}}}"}"#;
        let json = format!(
            r#"{{"id":"case-api","version":"1.0.0","operations":[{declared}],"problems":[],"problemEnvelope":"{{}}"}}"#
        );
        let profile = serde_json::from_str::<AdapterProfile>(&json).expect("parse");
        assert_eq!(profile.operations[0].record_type_parameter.as_str(), "type");
    }

    /// `successStatus` defaults to 200 and admits two hundreds only
    /// (CFG-QTY-4): the typed bound refuses anything else at the reader,
    /// and a declared status reads back.
    #[test]
    fn success_status_defaults_to_200_and_stays_two_hundreds_only() {
        let base = r#"{"id":"records-get","method":"GET","path":"/v1/records/{type}","pathParameters":["type"],"recordTypeParameter":"type""#;
        let tail = r#","responseEnvelope":"{\"cases\": {{records}}}"}"#;
        let profile_json = |operation: String| {
            format!(
                r#"{{"id":"case-api","version":"1.0.0","operations":[{operation}],"problems":[],"problemEnvelope":"{{}}"}}"#
            )
        };
        let parsed = serde_json::from_str::<AdapterProfile>(&profile_json(format!("{base}{tail}")))
            .expect("parse");
        assert_eq!(parsed.operations[0].success_status.get(), 200);
        let parsed = serde_json::from_str::<AdapterProfile>(&profile_json(format!(
            "{base},\"successStatus\":201{tail}"
        )))
        .expect("parse");
        assert_eq!(parsed.operations[0].success_status.get(), 201);
        for refused in [199, 300] {
            let json = format!("{base},\"successStatus\":{refused}{tail}");
            assert!(
                serde_json::from_str::<AdapterProfile>(&profile_json(json)).is_err(),
                "a success status outside 200 to 299 is refused"
            );
        }
    }

    /// The profile artifact round-trips with profile-declared operation
    /// ids and the problems list (`products/adapter/CONCEPT.md` sections
    /// 7 and 8.11.6).
    #[test]
    fn profile_round_trips_with_declared_operation_ids() {
        let profile = AdapterProfile {
            id: LocalId::new("case-api").expect("id"),
            version: "1.0.0".to_string(),
            operations: UniqueIdList::new(vec![
                operation("cases-find", crate::model::HttpMethod::Post),
                operation("cases-get", crate::model::HttpMethod::Get),
            ])
            .expect("unique"),
            problems: UniqueIdList::new(vec![problem(
                "cases.conflict",
                409,
                &[crate::model::ErrorClass::OutcomeConflict],
            )])
            .expect("unique"),
            problem_envelope: EnvelopeTemplate(
                r#"{"code": "{{problemCode}}", "title": "{{problemTitle}}"}"#.to_string(),
            ),
            parameterized_parts: Default::default(),
        };
        let json = serde_json::to_string(&profile).expect("serialize");
        assert!(json.contains("\"problems\""));
        assert_eq!(
            serde_json::from_str::<AdapterProfile>(&json).ok(),
            Some(profile)
        );
    }

    /// A problem entry names only classes of the closed hierarchy: an
    /// unknown class string refuses at the reader with the shared error
    /// class text.
    #[test]
    fn a_problem_entry_refuses_an_unknown_class() {
        let json = r#"{"id":"case-api","version":"1.0.0","operations":[],"problems":[{"code":"cases.gone","status":404,"title":"gone","classes":["upstream.exploded"]}],"problemEnvelope":"{}"}"#;
        let error = serde_json::from_str::<AdapterProfile>(json)
            .expect_err("an unknown error class is refused");
        assert!(
            error
                .to_string()
                .contains("an error class from the closed Adapter hierarchy"),
            "the refusal names the closed hierarchy: {error}"
        );
    }

    /// A problem status sits inside 400 to 599 (CFG-QTY-4): the typed
    /// bound refuses anything else at the reader.
    #[test]
    fn a_problem_status_outside_the_bound_refuses() {
        for status in [399, 600] {
            let json = format!(
                r#"{{"id":"case-api","version":"1.0.0","operations":[],"problems":[{{"code":"cases.gone","status":{status},"title":"gone","classes":["outcome.not-found"]}}],"problemEnvelope":"{{}}"}}"#
            );
            assert!(
                serde_json::from_str::<AdapterProfile>(&json).is_err(),
                "status {status} sits outside 400 to 599"
            );
        }
        let inside = r#"{"id":"case-api","version":"1.0.0","operations":[],"problems":[{"code":"cases.gone","status":404,"title":"gone","classes":["outcome.not-found"]}],"problemEnvelope":"{}"}"#;
        let profile = serde_json::from_str::<AdapterProfile>(inside).expect("parse");
        assert_eq!(profile.problems[0].status.get(), 404);
    }

    #[test]
    fn problem_data_fields_round_trip_without_changing_older_profiles() {
        let without = r#"{"id":"case-api","version":"1.0.0","operations":[],"problems":[{"code":"cases.gone","status":404,"title":"gone","classes":["outcome.not-found"]}],"problemEnvelope":"{}"}"#;
        let profile = serde_json::from_str::<AdapterProfile>(without).expect("parse");
        assert!(profile.problems[0].data_fields.is_none());
        assert!(!serde_json::to_string(&profile)
            .expect("serialize")
            .contains("dataFields"));

        let with = r#"{"id":"case-api","version":"1.0.0","operations":[],"problems":[{"code":"cases.partial","status":409,"title":"partial","classes":["outcome.conflict"],"dataFields":[{"name":"accepted","type":"integer","required":true}]}],"problemEnvelope":"{\"data\": {{?problemData}}}"}"#;
        let profile = serde_json::from_str::<AdapterProfile>(with).expect("parse");
        let fields = profile.problems[0]
            .data_fields
            .as_ref()
            .expect("declared fields");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name.as_str(), "accepted");
        assert_eq!(
            serde_json::from_str::<AdapterProfile>(
                &serde_json::to_string(&profile).expect("serialize")
            )
            .ok(),
            Some(profile)
        );
    }

    #[test]
    fn problem_resolution_uses_the_closest_declared_class() {
        let root = problem("cases.outcome", 422, &[crate::model::ErrorClass::Outcome]);
        let exact = problem(
            "cases.conflict",
            409,
            &[crate::model::ErrorClass::OutcomeConflict],
        );
        let profile = AdapterProfile {
            id: LocalId::new("case-api").expect("id"),
            version: "1.0.0".to_string(),
            operations: UniqueIdList::new(Vec::new()).expect("empty"),
            problems: UniqueIdList::new(vec![root, exact]).expect("unique"),
            problem_envelope: EnvelopeTemplate(r#"{"code":"{{problemCode}}"}"#.to_string()),
            parameterized_parts: UniqueList::new(Vec::new()).expect("empty"),
        };
        assert_eq!(
            resolve_problem(&profile, crate::model::ErrorClass::OutcomeConflict)
                .map(|problem| problem.code.as_str()),
            Some("cases.conflict")
        );
        assert_eq!(
            resolve_problem(&profile, crate::model::ErrorClass::OutcomeRejected)
                .map(|problem| problem.code.as_str()),
            Some("cases.outcome")
        );
    }

    #[cfg(feature = "schema")]
    #[test]
    fn generated_profile_schema_bounds_problem_data_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(AdapterProfile)).expect("schema");
        assert_eq!(
            schema["$defs"]["Problem"]["properties"]["dataFields"]["maxItems"],
            serde_json::json!(MAX_PROBLEM_DATA_FIELDS)
        );
        assert_eq!(
            schema["$defs"]["Problem"]["properties"]["dataFields"]["minItems"],
            serde_json::json!(1)
        );
    }

    /// Problem codes are unique at the reader (CFG-ID-5): two entries
    /// with one code refuse.
    #[test]
    fn duplicate_problem_codes_refuse_at_the_reader() {
        let entries = r#""problems":[{"code":"cases.gone","status":404,"title":"gone","classes":["outcome.not-found"]},{"code":"cases.gone","status":409,"title":"again","classes":["outcome.conflict"]}]"#;
        let json = format!(
            r#"{{"id":"case-api","version":"1.0.0","operations":[],{entries},"problemEnvelope":"{{}}"}}"#
        );
        assert!(
            serde_json::from_str::<AdapterProfile>(&json).is_err(),
            "a repeated problem code refuses"
        );
    }

    /// Repeated operation ids are refused at the reader (CFG-ID-5).
    #[test]
    fn duplicate_operation_ids_are_refused() {
        assert!(
            UniqueIdList::new(vec![
                operation("cases-find", crate::model::HttpMethod::Post),
                operation("cases-find", crate::model::HttpMethod::Get),
            ])
            .is_err(),
            "duplicate operation id refused"
        );
    }

    /// The slot vocabulary is closed: the known slots resolve, and an
    /// unknown one does not. The refusal itself is an authoring check in
    /// `crate::checks`.
    #[test]
    fn slot_vocabulary_is_closed() {
        for slot in [
            "record",
            "records",
            "recordType",
            "recordId",
            "nextCursor",
            "requestId",
            "problemCode",
            "problemTitle",
            "problemDetail",
            "problemData",
            "status",
            "filters",
            "pageSize",
            "cursor",
        ] {
            assert!(
                ENVELOPE_SLOTS.contains(&slot),
                "{slot} must stay in the closed vocabulary"
            );
        }
        assert_eq!(ENVELOPE_SLOTS.len(), 14);
    }

    /// Envelope templates answer slot-mention queries in both placeholder
    /// forms (`{{name}}` and `{{?name}}`).
    #[test]
    fn envelope_templates_mention_slots() {
        let template = EnvelopeTemplate(
            r#"{"cursor": "{{?nextCursor}}", "record": {{record}}, "req": "{{requestId}}"}"#
                .to_string(),
        );
        assert!(template.mentions(SLOT_RECORD));
        assert!(template.mentions("nextCursor"));
        assert!(template.mentions("requestId"));
        assert!(!template.mentions(SLOT_RECORDS));
        assert!(!template.mentions("unknownSlot"));
    }

    /// Pagination parameters round-trip with their bounds.
    #[test]
    fn pagination_parameters_round_trip() {
        let pagination = PaginationParameters {
            cursor_parameter: ExternalId::new("cursor").expect("name"),
            page_size_parameter: ExternalId::new("limit").expect("name"),
            page_size_minimum: BoundedU64::<1, 10_000>::new(1).expect("min"),
            page_size_maximum: BoundedU64::<1, 100_000>::new(500).expect("max"),
            page_size_default: None,
        };
        let json = serde_json::to_string(&pagination).expect("serialize");
        assert!(json.contains("cursorParameter"));
        assert_eq!(
            serde_json::from_str::<PaginationParameters>(&json).ok(),
            Some(pagination)
        );
    }
}

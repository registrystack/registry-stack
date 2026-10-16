//! Authoritative serde wire schemas for the Casework contract generator.
use registry_casework_core::*;
use schemars::{
    generate::{Contract, SchemaSettings},
    JsonSchema,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, env, fs, path::PathBuf};

fn add<T: JsonSchema>(schemas: &mut BTreeMap<String, Value>, name: &str, contract: Contract) {
    let mut settings = SchemaSettings::draft2020_12();
    settings.contract = contract;
    let schema = settings.into_generator().into_root_schema_for::<T>();
    schemas.insert(
        name.to_owned(),
        serde_json::to_value(schema).expect("wire schema"),
    );
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|arg| arg == "--validate-openapi")
    {
        if arguments.len() != 4 || arguments[2] != "--examples" {
            return Err("expected --validate-openapi PATH --examples PATH".into());
        }
        let document: Value = serde_json::from_slice(&fs::read(&arguments[1])?)?;
        let examples: BTreeMap<String, Vec<Value>> =
            serde_json::from_slice(&fs::read(&arguments[3])?)?;
        for (name, values) in examples {
            if document["components"]["schemas"].get(&name).is_none() {
                return Err(format!("wire example has no schema: {name}").into());
            }
            let schema = json!({"$ref":format!("#/components/schemas/{name}"),"components":document["components"]});
            let compiled = jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .compile(&schema)
                .map_err(|_| format!("cannot compile generated schema: {name}"))?;
            for value in values {
                if !compiled.is_valid(&value) {
                    return Err(format!(
                        "Rust wire example disagrees with generated schema: {name}"
                    )
                    .into());
                }
            }
        }
        return Ok(());
    }

    let mut schemas = BTreeMap::new();
    let mut input_roots = Vec::<String>::new();
    macro_rules! input {($($ty:ty),* $(,)?)=>{$(add::<$ty>(&mut schemas,stringify!($ty),Contract::Deserialize);input_roots.push(stringify!($ty).to_owned());)*};}
    macro_rules! output {($($ty:ty),* $(,)?)=>{$(add::<$ty>(&mut schemas,stringify!($ty),Contract::Serialize);)*};}
    input!(
        ReviewCreateRequest,
        ReviewCancelRequest,
        ReviewTaskDecisionRequest,
        ReviewTaskDraftInput,
        AssignmentRequest,
        DelegateRequest,
        ReviewNoteRequest,
        TaskApprovalRequest,
        BootstrapDirectoryRequest,
        DirectoryTeamUpdateRequest,
        AbsenceInput,
        HolidaySetRevisionInput,
        ReviewCaseloadMoveRequest,
        ReviewCaseloadApplyRequest,
        ReviewClockRecomputeRequest,
        ReviewClockRecomputeApplyRequest,
        ReviewStaffingQuery,
        DirectoryTargetsQuery,
        AbsencesQuery
    );
    output!(
        ReviewRequestAccepted,
        ReviewRequestView,
        ReviewResult,
        ReviewResultFeedPage,
        ReviewCancelResponse,
        ReviewTask,
        ReviewTaskPage,
        ReviewTaskContext,
        ReviewPolicyClosure,
        OwnReviewDecisionPage,
        SupervisoryReviewTaskPage,
        ReviewTaskDraft,
        ReviewHistoryPage,
        ReviewHistoryEntry,
        ReviewAccountabilityRecord,
        Description,
        DirectoryResponse,
        DirectoryTargetPage,
        AbsenceList,
        AbsenceRecord,
        HolidaySetDocument,
        ReviewCaseloadPreview,
        ReviewCaseloadResult,
        ReviewClockRecomputePreview,
        ReviewClockRecomputeResult,
        TaskTemplatePreviews,
        TaskGrantView,
        TaskGrantList,
        TaskGrantRevocation,
        TaskAssertionResponse,
        TaskGrantStatus,
        ReviewCompletion,
        Decision,
        ReviewValidationReason
    );
    add::<Vec<ReviewPolicyClosure>>(&mut schemas, "ReviewPolicyClosureList", Contract::Serialize);
    add::<Vec<ReviewClockOccurrence>>(
        &mut schemas,
        "ReviewClockOccurrenceList",
        Contract::Serialize,
    );
    add::<Option<ReviewTask>>(&mut schemas, "OptionalReviewTask", Contract::Serialize);
    let document = json!({"schemas":schemas,"inputRoots":input_roots,"projectDocuments":schema::project_documents()?,"offlineDocuments":schema::offline_documents()?});
    let rendered = serde_json::to_string_pretty(&document)? + "\n";
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("--output") => {
            let path = PathBuf::from(arguments.next().ok_or("--output requires a path")?);
            fs::write(path, rendered)?;
        }
        None => print!("{rendered}"),
        Some(_) => return Err("expected --output PATH".into()),
    }
    Ok(())
}

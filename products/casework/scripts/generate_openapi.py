#!/usr/bin/env python3
"""Generate Casework HTTP contracts from serde schemas and runtime operations."""
from __future__ import annotations
import argparse
import copy
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / "products/casework/generated/registry-casework.openapi.json"
PROFILE = "registry-casework-profile"
REVIEW_PROFILE = "registry-review-profile"
SOURCE_PROFILE = "registry-source-profile"

@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    operation_id: str
    response: str | None = None
    body: str | None = None
    query: str | None = None
    source: bool = False
    revision: str | None = None
    idempotency: bool = False
    public: bool = False
    service: bool = False
    review: bool = False

# Transport metadata only. DTO shapes and all statuses/problems come from Rust.
ENDPOINTS = [
    Endpoint("GET","/health","health",public=True),
    Endpoint("GET","/ready","readiness",public=True),
    Endpoint("GET","/.well-known/jwks.json","getTaskAuthorityKeys","TaskAuthorityJwks",public=True),
    Endpoint("GET","/v1/casework","describeCasework","Description"),
    Endpoint("GET","/v1/review-policies","listReviewPolicies","ReviewPolicyClosureList"),
    Endpoint("GET","/v1/review-policies/{policy_id}","getReviewPolicy","ReviewPolicyClosure"),
    Endpoint("POST","/v1/review-requests","createOrRecoverReviewRequest","ReviewRequestAccepted","ReviewCreateRequest",idempotency=True,review=True),
    Endpoint("GET","/v1/review-requests/{request_id}","getReviewRequest","ReviewRequestView",review=True),
    Endpoint("GET","/v1/review-requests/{request_id}/result","getReviewResult","ReviewResult",review=True),
    Endpoint("POST","/v1/review-requests/{request_id}/cancel","cancelReviewRequest","ReviewCancelResponse","ReviewCancelRequest",idempotency=True,review=True),
    Endpoint("GET","/v1/review-requests/{request_id}/history","getReviewHistory","ReviewHistoryPage",query="page",source=True),
    Endpoint("GET","/v1/review-requests/{request_id}/clocks","getReviewClocks","ReviewClockOccurrenceList",source=True),
    Endpoint("POST","/v1/review-requests/{request_id}/notes","addReviewNote","ReviewHistoryEntry","ReviewNoteRequest",source=True,idempotency=True),
    Endpoint("GET","/v1/review-results","listReviewResults","ReviewResultFeedPage",query="page",review=True),
    Endpoint("GET","/v1/review-tasks","listReviewTasks","ReviewTaskPage",query="ReviewStaffingQuery",source=True),
    Endpoint("GET","/v1/review-tasks/next","getNextReviewTask","OptionalReviewTask",query="ReviewStaffingQuery",source=True),
    Endpoint("GET","/v1/review-tasks/holdings","getReviewTaskHoldings","ReviewTaskPage",query="ReviewStaffingQuery",source=True),
    Endpoint("GET","/v1/review-tasks/supervision","listSupervisoryReviewTasks","SupervisoryReviewTaskPage",query="supervision",source=True),
    Endpoint("GET","/v1/review-tasks/own-decisions","listOwnReviewDecisions","OwnReviewDecisionPage",query="own-decisions",source=True),
    Endpoint("GET","/v1/review-tasks/{task_id}","getReviewTask","ReviewTask",source=True),
    Endpoint("GET","/v1/review-tasks/{task_id}/context","getReviewTaskContext","ReviewTaskContext",source=True),
    Endpoint("POST","/v1/review-tasks/{task_id}/claim","claimReviewTask","ReviewTask",source=True,revision="positive",idempotency=True),
    Endpoint("POST","/v1/review-tasks/{task_id}/assign","assignReviewTask","ReviewTask","AssignmentRequest",source=True,revision="positive",idempotency=True),
    Endpoint("POST","/v1/review-tasks/{task_id}/delegate","delegateReviewTask","ReviewTask","DelegateRequest",source=True,revision="positive",idempotency=True),
    Endpoint("POST","/v1/review-tasks/{task_id}/release","releaseReviewTask","ReviewTask",source=True,revision="positive",idempotency=True),
    Endpoint("GET","/v1/review-tasks/{task_id}/draft","getReviewDecisionDraft","ReviewTaskDraft",source=True),
    Endpoint("PUT","/v1/review-tasks/{task_id}/draft","saveReviewDecisionDraft","ReviewTaskDraft","ReviewTaskDraftInput",source=True,revision="positive",idempotency=True),
    Endpoint("DELETE","/v1/review-tasks/{task_id}/draft","deleteReviewDecisionDraft",source=True,revision="positive",idempotency=True),
    Endpoint("POST","/v1/review-tasks/{task_id}/decisions","decideReviewTask",body="ReviewTaskDecisionRequest",source=True,revision="positive",idempotency=True),
    Endpoint("GET","/v1/review-tasks/{task_id}/task-templates","previewReviewTaskTemplates","TaskTemplatePreviews",source=True),
    Endpoint("GET","/v1/review-tasks/{task_id}/task-grants","listReviewTaskGrants","TaskGrantList",source=True),
    Endpoint("POST","/v1/review-tasks/{task_id}/task-grants","approveReviewTaskGrant","TaskGrantView","TaskApprovalRequest",source=True,revision="positive",idempotency=True),
    Endpoint("POST","/v1/review-tasks/{task_id}/task-grants/{grant_id}/revoke","revokeReviewTaskGrant","TaskGrantRevocation"),
    Endpoint("POST","/v1/task-grants/{grant_id}/assertion","getTaskAssertion","TaskAssertionResponse",service=True),
    Endpoint("GET","/v1/task-grants/{grant_id}/status","getTaskGrantStatus","TaskGrantStatus",service=True),
    Endpoint("GET","/v1/review-accountability/{event_id}","getReviewAccountability","ReviewAccountabilityRecord",source=True),
    Endpoint("GET","/v1/directory","getDirectory","DirectoryResponse"),
    Endpoint("GET","/v1/directory/targets","listDirectoryTargets","DirectoryTargetPage",query="DirectoryTargetsQuery"),
    Endpoint("PUT","/v1/directory/teams/{team_id}","updateDirectoryTeam","DirectoryResponse","DirectoryTeamUpdateRequest",revision="nonnegative",idempotency=True),
    Endpoint("POST","/v1/directory/bootstrap","bootstrapDirectory","DirectoryResponse","BootstrapDirectoryRequest",revision="nonnegative",idempotency=True),
    Endpoint("GET","/v1/directory/absences","listAbsences","AbsenceList",query="AbsencesQuery"),
    Endpoint("POST","/v1/directory/absences","createAbsence","AbsenceRecord","AbsenceInput",revision="nonnegative",idempotency=True),
    Endpoint("PUT","/v1/directory/absences/{absence_id}","updateAbsence","AbsenceRecord","AbsenceInput",revision="positive",idempotency=True),
    Endpoint("DELETE","/v1/directory/absences/{absence_id}","deleteAbsence",revision="positive",idempotency=True),
    Endpoint("POST","/v1/directory/caseload/preview","previewReviewCaseload","ReviewCaseloadPreview","ReviewCaseloadMoveRequest",source=True),
    Endpoint("POST","/v1/directory/caseload/apply","applyReviewCaseload","ReviewCaseloadResult","ReviewCaseloadApplyRequest",source=True),
    Endpoint("POST","/v1/directory/clocks/recompute/preview","previewReviewClockRecompute","ReviewClockRecomputePreview","ReviewClockRecomputeRequest",source=True),
    Endpoint("POST","/v1/directory/clocks/recompute/apply","applyReviewClockRecompute","ReviewClockRecomputeResult","ReviewClockRecomputeApplyRequest",source=True),
    Endpoint("POST","/v1/directory/holidays","createHolidayRevision","HolidaySetDocument","HolidaySetRevisionInput",idempotency=True),
    Endpoint("GET","/v1/directory/holidays/{id}/revisions/{revision}","getHolidayRevision","HolidaySetDocument"),
]
ROUTES = {endpoint.path for endpoint in ENDPOINTS}

def ref(name: str) -> dict:
    return {"$ref": f"#/components/schemas/{name}"}

def object_schema(properties: dict, required: list[str]) -> dict:
    return {"type":"object","additionalProperties":False,"properties":properties,"required":required}

def merge_wire_schemas(wire: dict) -> dict:
    """Keep input omission rules separate from output presence rules."""
    result = {}
    inputs = set(wire["inputRoots"])
    def put(name, value):
        if name in result and result[name] != value:
            raise ValueError(f"conflicting Rust schema definition: {name}")
        result[name] = value
    for root_name, raw_schema in wire["schemas"].items():
        schema = copy.deepcopy(raw_schema)
        definitions = schema.pop("$defs", {})
        schema.pop("$schema", None)
        schema.pop("title", None)
        def component(name):
            return name if root_name not in inputs or name in inputs else "Input" + name
        def rewrite(value):
            if isinstance(value, dict):
                return {key: (f"#/components/schemas/{component(item.removeprefix('#/$defs/'))}" if key == "$ref" and item.startswith("#/$defs/") else f"#/components/schemas/{root_name}" if key=="$ref" and item=="#" else rewrite(item)) for key,item in value.items()}
            if isinstance(value, list): return [rewrite(item) for item in value]
            return value
        for name, definition in definitions.items():
            definition.pop("title", None)
            put(component(name), rewrite(definition))
        put(root_name, rewrite(schema))
    result["TaskAuthorityJwks"] = {"type":"object","description":"JSON Web Key Set of the configured task authority's public verification keys.","required":["keys"],"properties":{"keys":{"type":"array","items":{"type":"object"}}}}
    return result

def parameter(name: str, where: str, schema: dict, required: bool = False, description: str = "") -> dict:
    return {"name":name,"in":where,"required":required,"description":description,"schema":schema}

def bounded_identifier(maximum=128):
    return {"type":"string","minLength":1,"maxLength":maximum,"x-maximum-utf8-bytes":maximum,"pattern":"^[A-Za-z0-9._:-]+$"}

def query_parameters(kind: str, schemas: dict) -> list[dict]:
    if kind in schemas:
        schema=schemas[kind]
        return [parameter(name,"query",value,name in schema.get("required",[])) for name,value in schema["properties"].items()]
    properties={"cursor":{"type":"string","format":"uuid"},"limit":{"type":"integer","minimum":1,"maximum":100}}
    if kind in ("supervision","own-decisions"): properties["queue"]=bounded_identifier()
    if kind=="supervision":properties["requestId"]={"type":"string","format":"uuid"}
    return [parameter(name,"query",schema) for name,schema in properties.items()]

def response(schema_name: str | None = None, description="Success") -> dict:
    value={"description":description,"headers":{"traceparent":{"$ref":"#/components/headers/TraceparentHeader"}}}
    if schema_name: value["content"]={"application/json":{"schema":ref(schema_name)}}
    return value

def problem_component_name(code: str) -> str:
    return "Problem" + "".join(part.title() for part in re.split(r"[.-]",code))

def problem_schemas(entries: list[dict]) -> dict:
    text={"type":"string"}
    base=object_schema({"type":text,"title":text,"status":{"type":"integer"},"detail":text,"code":text,"traceId":text},["type","title","status","detail","code","traceId"])
    result={"Problem":base}
    for entry in entries:
        uri=entry["uri"]
        result[problem_component_name(entry["code"])]={"allOf":[ref("Problem"),{"properties":{"type":{"const":uri},"title":{"const":entry["title"]},"status":{"const":entry["httpStatuses"][0]},"detail":{"const":entry["description"]},"code":{"const":entry["code"]}}}]}
    return result

def problem_responses(codes: set[str], catalog: dict) -> dict:
    by_status={}
    for code in sorted(codes):
        entry=catalog[code];by_status.setdefault(entry["httpStatuses"][0],[]).append(entry)
    result={}
    for status,entries in sorted(by_status.items()):
        variants=[ref(problem_component_name(entry["code"])) for entry in entries]
        value=response(description="Problem: "+", ".join(entry["code"] for entry in entries))
        value["content"]={"application/problem+json":{"schema":variants[0] if len(variants)==1 else {"oneOf":variants}}}
        if status==401:value["headers"]["WWW-Authenticate"]={"schema":{"const":"Bearer"}}
        if status==503:value["headers"]["Retry-After"]={"schema":{"type":"integer","minimum":0}}
        result[str(status)]=value
    return result

def schema_problem_codes(openapi: dict, schema: dict) -> set[str]:
    return {openapi["components"]["schemas"][variant["$ref"].rsplit("/",1)[1]]["allOf"][1]["properties"]["code"]["const"] for variant in schema.get("oneOf",[schema])}

def verify_operation_responses(openapi: dict, contract: dict) -> None:
    catalog={entry["code"]:entry for entry in contract["entries"]}
    actual={(method.upper(),path) for path,item in openapi["paths"].items() for method in item}
    expected={(op["method"],op["path"]) for op in contract["operations"]}
    if actual!=expected:raise ValueError("Rust/OpenAPI operation inventory drifted")
    for op in contract["operations"]:
        responses=openapi["paths"][op["path"]][op["method"].lower()]["responses"]
        for status in op["successStatuses"]:
            if str(status) not in responses:raise ValueError("Rust/OpenAPI success status drifted")
        codes=set(op["problems"])|set(contract["frameworkProblems"])
        expected_by_status={}
        for code in codes:
            status=catalog[code]["httpStatuses"][0]
            if status not in op["successStatuses"]:expected_by_status.setdefault(status,set()).add(code)
        actual_by_status={int(status):schema_problem_codes(openapi,value["content"]["application/problem+json"]["schema"]) for status,value in responses.items() if int(status)>=400 and int(status) not in op["successStatuses"]}
        if actual_by_status!=expected_by_status:raise ValueError(f"Rust/OpenAPI problem response drifted for {op['method']} {op['path']}")

def document(contract: dict, wire: dict) -> dict:
    schemas=merge_wire_schemas(wire)
    schemas.update(problem_schemas(contract["entries"]))
    catalog={entry["code"]:entry for entry in contract["entries"]}
    rust={(op["method"],op["path"]):op for op in contract["operations"]}
    endpoints={(endpoint.method,endpoint.path):endpoint for endpoint in ENDPOINTS}
    if endpoints.keys()!=rust.keys():raise ValueError(f"Rust/OpenAPI operation inventory drifted: {sorted(endpoints.keys() ^ rust.keys())}")
    paths={}
    for key,endpoint in endpoints.items():
        op=rust[key]
        if bool(endpoint.body)!=op["acceptsJson"] or bool(endpoint.query)!=op["extractsQuery"] or bool(re.search(r"\{",endpoint.path))!=op["extractsPath"]:raise ValueError(f"Rust/OpenAPI extraction drifted for {key}")
        parameters=[parameter("traceparent","header",{"type":"string"})]
        if not endpoint.public and not endpoint.service:parameters.append(parameter(REVIEW_PROFILE if endpoint.review else PROFILE,"header",bounded_identifier(),True,"The caller's exact governed access profile for this protocol."))
        if endpoint.source:parameters.append(parameter(SOURCE_PROFILE,"header",bounded_identifier(),False,"Current-source lists, open work, source context, task mutations and new notes require the human caller's source-valid profile and credential. Retained terminal task and history reads use Casework authority. Submitted context requires no provider."))
        for name in re.findall(r"\{([^}]+)\}",endpoint.path):
            schema={"type":"string","format":"uuid"}
            if name in ("policy_id","team_id","id"):schema=bounded_identifier()
            if name=="revision":schema={"type":"integer","minimum":1}
            parameters.append(parameter(name,"path",schema,True))
        if endpoint.query:parameters+=query_parameters(endpoint.query,schemas)
        if endpoint.revision:parameters.append(parameter("If-Match","header",{"type":"string","pattern":'^"[1-9][0-9]*"$' if endpoint.revision=="positive" else '^"(?:0|[1-9][0-9]*)"$'},True,"Quoted current revision."))
        if endpoint.idempotency:parameters.append(parameter("Idempotency-Key","header",{"type":"string","minLength":1,"maxLength":128,"pattern":"^[!-~]+$"},True,"Retain this exact key and request bytes for explicit recovery."))
        responses={str(status):response(endpoint.response if status in (200,201) else None) for status in op["successStatuses"]}
        if endpoint.body == "ReviewCreateRequest":
            for status in ("200", "201"):
                if status in responses:
                    responses[status]["headers"]["Registry-Review-Producer"] = {"description":"Authenticated trusted producer identity for this acceptance or exact recovery. Optional for compatibility with older providers; never a substitute for the submission digest.","schema":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.:-]+$"}}
        codes=set(op["problems"])|set(contract["frameworkProblems"])
        for status,value in problem_responses(codes,catalog).items():
            if status not in responses:responses[status]=value
        operation={"operationId":endpoint.operation_id,"summary":re.sub(r"([a-z])([A-Z])",r"\1 \2",endpoint.operation_id).capitalize(),"security":[] if endpoint.public else [{"bearerAuth":[]}],"parameters":parameters,"responses":responses}
        if endpoint.body:
            if endpoint.body not in schemas:raise ValueError(f"missing Rust body DTO {endpoint.body}")
            operation["requestBody"]={"required":True,"content":{"application/json":{"schema":ref(endpoint.body)}}}
        if endpoint.response and endpoint.response not in schemas:raise ValueError(f"missing Rust success DTO {endpoint.response}")
        if endpoint.idempotency:operation["description"]="Recovery repeats the exact request and caller-supplied idempotency key. Clients do not retry mutations implicitly."
        if endpoint.body in ("ReviewCreateRequest","ReviewTaskDecisionRequest"):
            headers=responses.get("400",{}).get("headers",{})
            prefix="Registry-Review" if endpoint.review else "Registry-Casework"
            headers[prefix+"-Validation-Path"]={"description":"Bounded value-free JSON path; present together with the validation reason.","schema":{"type":"string","maxLength":256}}
            headers[prefix+"-Validation-Reason"]={"description":"Closed value-free validation category; present together with the validation path.","schema":ref("ReviewValidationReason")}
            if endpoint.body=="ReviewTaskDecisionRequest":headers["Registry-Casework-Validation-Allowed"]={"description":"Comma-separated outcome identifiers the review policy declares for the requested settlement; present only with the outcome-not-declared reason.","schema":{"type":"string","maxLength":1039,"pattern":"^[a-z][a-z0-9_-]{0,63}(,[a-z][a-z0-9_-]{0,63}){0,15}$"}}
        paths.setdefault(endpoint.path,{})[endpoint.method.lower()]=operation
    result={"openapi":"3.1.0","info":{"title":"Registry Casework API","version":"v1alpha1","description":"Source-neutral review policies, requests, human decisions, and immutable results. Context providers and downstream grant authority remain independent trust boundaries.","license":{"name":"Apache-2.0","identifier":"Apache-2.0"}},"paths":paths,"components":{"schemas":schemas,"headers":{"TraceparentHeader":{"description":"W3C trace context.","schema":{"type":"string"}}},"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer","bearerFormat":"JWT","description":"Exact trusted-issuer identity and governed scopes. A producer token grants no human review authority."}}},"x-registry-casework-framework-problems":contract["frameworkProblems"]}
    verify_operation_responses(result,contract)
    verify_refs(result)
    return result

def verify_refs(document: dict) -> None:
    def walk(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if key=="$ref" and item.startswith("#/"):
                    current=document
                    for part in item[2:].split("/"):
                        part=part.replace("~1","/").replace("~0","~")
                        if not isinstance(current,dict) or part not in current:raise ValueError(f"unresolved generated schema reference: {item}")
                        current=current[part]
                else:walk(item)
        elif isinstance(value,list):
            for item in value:walk(item)
    walk(document)

def verify_source(repository_root: Path, openapi: dict) -> None:
    source=(repository_root/"crates/registry-casework/src/http.rs").read_text().split("#[cfg(test)]",1)[0]
    routes=set(re.findall(r'\.route\(\s*"([^"]+)"',source))
    if routes!=set(openapi["paths"]):raise ValueError(f"runtime route inventory drifted: {sorted(routes ^ set(openapi['paths']))}")
    if "SourceBinding" in openapi["components"]["schemas"]:raise ValueError("retired SourceBinding remains")
    rendered=json.dumps(openapi)
    for retired in ("/v1/work-items","/events/sources","ReviewerTask","ReviewKindPolicy","TaskProposalIdentity"):
        if retired in rendered:raise ValueError(f"retired Casework contract remains: {retired}")

def cargo_example(repository_root: Path, package: str, example: str, output: Path, features: str | None = None, extra: list[str] | None = None) -> None:
    command=["cargo","run","--locked","--offline","-q","-j","2","-p",package]
    if features:command += ["--features",features]
    command += ["--example",example,"--",*(extra or ["--output",str(output)])]
    subprocess.run(command,cwd=repository_root,check=True)

def load_wire_schemas(repository_root: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="casework-wire-") as directory:
        output=Path(directory)/"wire.json";cargo_example(repository_root,"registry-casework-core","wire-schemas",output,"schema")
        return json.loads(output.read_text())

def load_rust_contract(repository_root: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="casework-contract-") as directory:
        output=Path(directory)/"contract.json";cargo_example(repository_root,"registry-casework","problem-catalog",output)
        contract=json.loads(output.read_text())
    if set(contract)!={"entries","frameworkProblems","operations","reviewWireExamples"}:raise ValueError("runtime contract envelope drifted")
    codes=[entry["code"] for entry in contract["entries"]]
    if codes!=sorted(set(codes)):raise ValueError("runtime problem codes must be sorted and unique")
    return contract

def validate_wire_examples(repository_root: Path, openapi: dict, examples: dict) -> None:
    with tempfile.TemporaryDirectory(prefix="casework-wire-validation-") as directory:
        document_path=Path(directory)/"openapi.json";examples_path=Path(directory)/"examples.json"
        document_path.write_text(json.dumps(openapi));examples_path.write_text(json.dumps(examples))
        cargo_example(repository_root,"registry-casework-core","wire-schemas",document_path,"schema",["--validate-openapi",str(document_path),"--examples",str(examples_path)])

def problem_table(existing: str, contract: dict) -> str:
    """Replace only the published problem-code table from its runtime owner."""
    table=re.search(r"(?ms)^- id: problem-codes\n.*?(?=^- id: |\Z)",existing)
    if table is None:raise ValueError("published Casework problem-code table is absent")
    def scalar(value):return "'"+str(value).replace("'","''")+"'"
    lines=["- id: problem-codes","  title: Problem codes","  columns: [Code, Status, When]","  rows:"]
    for entry in contract["entries"]:
        statuses=", ".join(str(status) for status in entry["httpStatuses"])
        lines.append("    - ["+", ".join(map(scalar,["`"+entry["code"]+"`",statuses,entry["description"]]))+"]")
    return existing[:table.start()]+"\n".join(lines)+"\n"+existing[table.end():]

def main() -> int:
    parser=argparse.ArgumentParser();parser.add_argument("--check",action="store_true");args=parser.parse_args()
    try:
        wire=load_wire_schemas(ROOT);contract=load_rust_contract(ROOT);openapi=document(contract,wire)
        verify_source(ROOT,openapi);validate_wire_examples(ROOT,openapi,contract["reviewWireExamples"])
        files={OUTPUT:json.dumps(openapi,indent=2,sort_keys=True)+"\n"}
        for name,content in wire["projectDocuments"].items():files[ROOT/"products/casework/generated/project"/name]=content
        for name,content in wire["offlineDocuments"].items():files[ROOT/"products/casework/generated"/name]=content
        retired=[ROOT/"products/casework/generated/simulation/simulation.schema.json"]
        published=ROOT/"docs/site/src/data/casework-api.yaml"
        files[published]=problem_table(published.read_text(),contract)
        stale=[]
        for path in retired:
            if path.exists():
                if args.check:stale.append(path)
                else:path.unlink()

        for path,content in files.items():
            if args.check:
                if not path.is_file() or path.read_text()!=content:stale.append(path)
            else:path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content)
        for path in stale:print(f"stale Casework contract: {path.relative_to(ROOT)}",file=sys.stderr)
        return 1 if stale else 0
    except (OSError,ValueError,subprocess.CalledProcessError) as error:
        print(f"Casework contract generation failed: {error}",file=sys.stderr);return 1

if __name__=="__main__":raise SystemExit(main())

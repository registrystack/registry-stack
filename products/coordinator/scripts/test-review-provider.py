#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native BReg -> Coordinator Review -> optional Casework -> BReg proof.

Uses already built public executables and owned disposable dev sessions. The
Coordinator database URL must identify an owned loopback PostgreSQL database.
"""
import argparse
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import uuid

REPO = Path(__file__).resolve().parents[3]
EXAMPLE = REPO / "products/coordinator/examples/review-provider"
# Give source observation a short fixed window; the expiry proof waits against
# the original availableUntil without changing any result timestamp.
EXPIRING_RETENTION_SECONDS = 45
VARIANTS = {
    "correct-amount": ("review-provider", "applications", "external-review"),
    "correct-amount-manual": ("review-provider-manual", "applications-manual", "external-manual-review"),
    "correct-amount-expiring": ("review-provider-expiring", "applications-expiring", "external-expiring-review"),
}


def native_fixture():
    spec = importlib.util.spec_from_file_location("review_provider_native", Path(__file__).with_name("test-real-services.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load(path):
    return json.loads(Path(path).read_text())


def write_source(native, root, urls, bindings=None, *, borrower=False):
    root = native.write_breg(root, urls, borrower=borrower)
    registry = load(root / "registry.yaml")
    record = registry["recordTypes"][0]
    record["fields"].append({"id": "active", "type": "boolean", "required": True, "classification": "internal"})
    base = next(action for action in registry["actions"] if action["id"] == "correct-amount")
    base["execution"]["proposal"]["reviewContext"] = {"id": "application-amount-context", "fields": {
        "applicationId": {"type": "input", "input": "application"},
        "recordActive": {"type": "record", "input": "application", "field": "active"},
        "currentAmount": {"type": "record", "input": "application", "field": "requested-amount"},
        "proposedAmount": {"type": "input", "input": "proposed-amount"},
    }}
    for action_id in list(VARIANTS)[1:]:
        action = copy.deepcopy(base)
        action["id"] = action_id
        action["execution"]["proposal"]["application"] = {"mode": "manual"}
        registry["actions"].append(action)
    active_action = copy.deepcopy(next(action for action in registry["actions"] if action["id"] == "correct-notice-permission"))
    active_action["id"] = "correct-active"
    next(field for field in active_action["inputs"] if field["id"] == "proposed-notice-allowed")["id"] = "proposed-active"
    active_action["plan"]["effects"][0]["set"] = {"active": {"fromInput": "proposed-active"}}
    registry["actions"].append(active_action)
    profiles = {profile["id"]: profile for profile in registry["accessProfiles"]}
    target = copy.deepcopy(profiles["seeder"]["permissions"]["actions"][0]["targets"])
    seeder = profiles["seeder"]["permissions"]
    for permission in seeder["records"]:
        permission["readableFields"].append("active")
        permission["writableFields"].append("active")
    for action_id in list(VARIANTS)[1:]:
        seeder["actions"].append({"action": action_id, "operations": ["start"], "targets": target})
        seeder["proposals"].append({"action": action_id, "operations": ["get", "submit", "cancel"], "ownership": "caller", "targets": target})
    seeder["actions"].append({"action": "correct-active", "operations": ["start"], "targets": target})
    seeder["proposals"].append({"action": "correct-active", "operations": ["get", "submit", "cancel"], "ownership": "caller", "targets": target})
    for permission in seeder["proposals"]:
        if permission["action"] in VARIANTS:
            permission["operations"] += ["rebase", "revise", "get-review-status"]
            if permission["action"] != "correct-amount":
                permission["operations"] += ["apply", "retry"]
    fields = ["applicationId", "recordActive", "currentAmount", "proposedAmount"]
    assessment = profiles["follow-up-reader"]
    assessment["id"] = "assessment"
    assessment["permissions"]["records"][0]["readableFields"] = ["tenant", "active", "requested-amount"]
    assessment["permissions"]["proposals"] = [{"action": action, "operations": ["get-review-context"], "targets": target, "readableContextFields": fields} for action in VARIANTS]
    profiles["reviewer"]["permissions"]["records"][0]["readableFields"] = ["tenant", "active", "requested-amount"]
    profiles["reviewer"]["permissions"]["proposals"] = [{"action": action, "operations": ["get", "get-review-context"], "targets": target, "readableContextFields": fields} for action in VARIANTS]
    profiles["reader"]["permissions"]["proposals"] = [{"action": action, "operations": ["get-review-status"], **({"reviewAuthority": "coordinator"} if bindings else {"targets": target})} for action in VARIANTS]
    if bindings:
        registry["reviewAuthorities"] = [{"id": "coordinator", "protocol": "id.registrystack.org/protocols/review/v1"}]
        for action in registry["actions"]:
            if action["id"] in VARIANTS:
                binding = bindings[action["id"]]
                # Automatic application uses the provider's current policy at
                # acceptance. Manual and expiry fixtures exercise strict pins.
                policy = {"id": binding["id"]} if action["id"] == "correct-amount" else binding
                action["execution"]["proposal"]["review"] = {"type": "required", "authority": "coordinator", "source": native.SOURCE, "policy": policy}
    native.private(root / "registry.yaml", registry)
    clients = load(root / "dev-clients.yaml")
    reader = next(client for client in clients["clients"] if client["id"] == "application-reader")
    reader["accessProfiles"] = ["assessment"]
    reader["claims"]["registry_actor_kind"] = "service"
    if bindings:
        clients["reviewAuthorities"] = {"coordinator": {"endpoint": urls["coordinator"], "profile": "breg-producer", "producerId": "breg", "recoveryDays": 7, "client": "producer"}}
    native.private(root / "dev-clients.yaml", clients)
    journeys = load(root / "tests/journeys.yaml")
    for step in journeys["journeys"][0]["steps"]:
        if "data" in step["request"]:
            step["request"]["data"]["active"] = True
        if "fields" in step["expect"]:
            step["expect"]["fields"]["active"] = True
    native.private(root / "tests/journeys.yaml", journeys)
    return root


def write_human(native, root, urls, resource, agent, contexts):
    root = native.write_casework(root, urls, resource, agent, contexts["correct-amount"])
    policy = load(root / "casework.yaml")
    template = copy.deepcopy(policy["reviewPolicies"][0])
    provider = copy.deepcopy(policy["contextProviders"][0])
    policy["reviewPolicies"] = []
    policy["contextProviders"] = []
    policy.pop("taskTemplates", None)
    for action, (_, provider_id, policy_id) in VARIANTS.items():
        context = contexts[action]
        path = root / "schemas" / (action + ".schema.json")
        native.private(path, context["bytes"])
        item = copy.deepcopy(template)
        item["id"] = policy_id
        item["context"] = {"mode": "current-source", "provider": provider_id, "contract": context["contract"]}
        item["displaySchema"] = {"$ref": "schemas/" + path.name}
        policy["reviewPolicies"].append(item)
        policy["contextProviders"].append({**provider, "id": provider_id, "deploymentRef": provider_id})
    requester = next(profile for profile in policy["accessProfiles"] if profile["id"] == "producer")
    requester.update(id="coordinator-producer", requiredScopes=["casework:review"])
    policy["trustedProducers"] = [{"id": "coordinator", "profile": "coordinator-producer", "issuer": urls["issuer"], "subject": native.CASEWORK_PRINCIPALS["review-producer"], "sourceNamespaces": [native.SOURCE], "reviewPolicies": [value[2] for value in VARIANTS.values()], "recoveryDays": 7}]
    native.private(root / "casework.yaml", policy)
    clients = load(root / "dev-clients.yaml")
    requester = next(client for client in clients["clients"] if client["id"] == "producer")
    requester.update(id="review-producer", accessProfile="coordinator-producer", scopes=["casework:review"], claims={"casework_principal": native.CASEWORK_PRINCIPALS["review-producer"]})
    provider = clients["integrations"]["contextProviders"]["applications"]
    clients["integrations"]["contextProviders"] = {value[1]: copy.deepcopy(provider) for value in VARIANTS.values()}
    native.private(root / "dev-clients.yaml", clients)
    return root


def bound_project(native, root, action, context, human_policy):
    shutil.copytree(EXAMPLE, root)
    flow, _, _ = VARIANTS[action]
    workflow = (root / "workflow.yaml").read_text().replace("id: review-provider,", "id: " + flow + ",")
    if action.endswith("-expiring"):
        workflow = workflow.replace("resultRetentionSeconds: 86400", f"resultRetentionSeconds: {EXPIRING_RETENTION_SECONDS}")
    native.private(root / "workflow.yaml", workflow)
    source = (root / "functions.rhai").read_text().replace('"correct-amount"', json.dumps(action))
    old_context = "urn:registry:breg:review-context:coordinator-source:correct-amount:application-amount-context"
    source = source.replace(old_context, context["contract"]["id"]).replace("sha256:" + "a" * 64, context["contract"]["revision"]).replace("sha256:" + "b" * 64, context["contract"]["schemaDigest"])
    source = source.replace('"external-review"', json.dumps(human_policy["id"])).replace("sha256:" + "c" * 64, human_policy["digest"])
    native.private(root / "functions.rhai", source)
    scenarios = json.loads((root / "scenarios.yaml").read_text().split("\n", 1)[1])
    for case in scenarios["cases"]:
        case["input"]["policy"]["id"] = flow
        case["input"]["context"]["binding"]["reference"] = case["input"]["context"]["binding"]["reference"].replace(":correct-amount:", ":" + action + ":")
        if case["replies"]["assess"][0]["type"] == "success":
            case["replies"]["assess"][0]["value"]["contract"] = context["contract"]
        for reply in case["replies"].get("submit-human", []):
            reply["value"]["policy"] = human_policy
        for reply in case["replies"].get("withdraw-human", []):
            reply["value"]["result"]["policy"] = human_policy
        if case.get("waits", {}).get("await-human", {}).get("type") == "event":
            case["waits"]["await-human"]["value"]["policy"] = human_policy
    native.private(root / "scenarios.yaml", scenarios)
    return root


def wait_until(work, predicate, label, seconds=90):
    until = time.monotonic() + seconds
    while True:
        value = work()
        if predicate(value):
            return value
        assert time.monotonic() < until, label
        time.sleep(0.2)


def run(args):
    native = native_fixture()
    database = os.environ.get("COORDINATOR_TEST_DATABASE_URL", "")
    parsed = urllib.parse.urlsplit(database)
    assert parsed.scheme in ("postgres", "postgresql") and parsed.hostname in ("127.0.0.1", "localhost", "::1") and parsed.path.strip("/"), "set an owned disposable loopback COORDINATOR_TEST_DATABASE_URL"
    root = args.work_dir or Path(tempfile.mkdtemp(prefix="coordinator-review-provider-", dir=Path(tempfile.gettempdir()).resolve()))
    if args.work_dir:
        root.mkdir(mode=0o700)
    root = root.resolve()
    print(f"Private Review journey state: {root}", flush=True)
    journey = native.Journey(root, args.bin_dir.resolve(), 1, build_manifest=args.build_manifest, required_binaries=("breg", "bregctl", "casework", "caseworkctl", "coordinator", "coordinatorctl"), require_reviewed_notice_starter=False)
    success = False
    runtime = None
    try:
        coordinator_port = native.free_ports(1)[0]
        coordinator_url = f"http://127.0.0.1:{coordinator_port}"
        upstream = native.LostResponseProxy(coordinator_url, "/v1/review-requests")
        journey.proxies.append(upstream)
        urls = {**journey.urls, "coordinator": upstream.url}
        bootstrap = write_source(native, root / "issuer-owner", urls)
        journey.sessions.append(("bregctl", bootstrap))
        bootstrap_port, bootstrap_database = native.free_ports(2)
        bootstrap_report = journey.ctl("bregctl", "dev", "start", bootstrap, "--breg-port", bootstrap_port, "--issuer-port", journey.ports["issuer"], "--database-port", bootstrap_database, "--breg-bin", journey.bin / "breg")
        resource = bootstrap_report["resource"]
        export = root / "context-export"
        journey.ctl("bregctl", "generate", "schemas", bootstrap, "--output", export)
        contexts = {action: native.exported_context_schema(export, action) for action in VARIANTS}
        agent = native.subject(journey.token("bregctl", bootstrap, "task-agent"))
        casework = write_human(native, root / "human-review", urls, resource, agent, contexts)
        def pair(package):
            for action, (_, provider, _) in VARIANTS.items():
                journey.ctl("caseworkctl", "provider", "pair", casework, "--provider-id", provider, "--breg-package", package, "--action-id", action, "--bregctl-bin", journey.bin / "bregctl", "--apply")
        pair(Path(bootstrap_report["stateFile"]).parent / "build/package")
        checked = journey.ctl("caseworkctl", "check", casework)
        human_bindings = {binding["id"]: binding for binding in checked["policyBindings"]}
        projects = {}
        provider_bindings = {}
        for action, (flow, _, policy_id) in VARIANTS.items():
            project = bound_project(native, root / flow, action, contexts[action], human_bindings[policy_id])
            checked = journey.ctl("coordinatorctl", "check", "--project", project)
            journey.ctl("coordinatorctl", "test", "--project", project)
            provider_bindings[action] = {"id": flow, "version": "1", "digest": checked["workflowRevision"]}
            projects[flow] = project
        owner = write_source(native, root / "source", urls, provider_bindings, borrower=True)
        journey.sessions.append(("bregctl", owner))
        report = journey.ctl("bregctl", "dev", "start", owner, "--breg-port", journey.ports["breg"], "--database-port", journey.ports["bregdb"], "--issuer-project", bootstrap, "--breg-bin", journey.bin / "breg")
        assert report["resource"] == resource and report["issuer"] == bootstrap_report["issuer"], "the isolated source must borrow the exact owner issuer and resource"
        pair(Path(report["stateFile"]).parent / "build/package")
        rebound = journey.ctl("caseworkctl", "check", casework)
        assert {binding["id"]: binding for binding in rebound["policyBindings"]} == human_bindings, "source policy pinning cannot alter its independent exported context contract"
        journey.sessions.append(("caseworkctl", casework))
        journey.casework_start(casework, bootstrap)
        downstream = native.LostResponseProxy(journey.urls["casework"], "/v1/review-requests")
        journey.proxies.append(downstream)
        keys = root / "coordinator-secrets"
        assessor = journey.export(bootstrap, "application-reader", keys)
        human = journey.export(bootstrap, "review-producer", keys)
        producer = journey.export(bootstrap, "producer", keys)
        operator = journey.export(bootstrap, "seed-client", keys)
        runtime, _, worker = journey.coordinator_service("review-provider", keys, {
            "registry": {"type": "breg", "baseUrl": journey.urls["breg"], "profile": "assessment", "authorization": journey.authorization(assessor, resource, ["records:get"])},
            "review": {"type": "casework-review-producer", "baseUrl": downstream.url, "profile": "coordinator-producer", "producer": "coordinator", "resultCheckSeconds": 60, "authorization": journey.authorization(human, resource, ["casework:review"])},
        }, coordinator_port, "review-provider-initial", additional_projects=[(flow, project) for flow, project in projects.items() if flow != "review-provider"], primary_project=projects["review-provider"])
        journey.stop(worker)
        config = load(runtime)
        config["deployment"]["authentication"]["audience"] = resource
        config["deployment"]["authentication"]["policies"] = {
            Path(producer["clientIdFile"]).read_text().strip(): {"requiredScopes": ["casework:reviews:request"], "workflows": list(projects), "actions": ["review-create", "review-read", "review-cancel"], "reviewProducer": {"id": "breg", "sourceNamespace": native.SOURCE, "profile": "breg-producer", "sources": [native.SOURCE]}},
            Path(operator["clientIdFile"]).read_text().strip(): {"requiredScopes": ["records:get"], "workflows": list(projects), "actions": ["status", "inspect", "retry-same", "cancel", "reconcile"], "operator": True},
        }
        native.private(runtime, config)
        worker = journey.spawn("coordinator", runtime, "review-provider-serving")
        journey.ready(worker, coordinator_url)
        operator_token = lambda: journey.token("bregctl", bootstrap, "seed-client")
        review_token = lambda: journey.token("bregctl", bootstrap, "producer")
        review_headers = {"Registry-Review-Profile": "breg-producer"}
        def inspect(run):
            return native.http("GET", coordinator_url + f"/v1/runs/{run}/inspect", operator_token())
        def request_for(proposal):
            def current():
                runs = native.http("GET", coordinator_url + "/v1/runs?limit=100", operator_token())
                for run in runs["runs"]:
                    view = native.http("GET", coordinator_url + "/v1/review-requests/" + run["runId"], review_token(), headers=review_headers)
                    if view["subject"]["id"] == proposal["id"] and view["subject"]["version"] == str(proposal["submissionVersion"]):
                        return view
                return None
            return wait_until(current, lambda value: value is not None, "source request did not become one durable Review Run")
        def terminal(proposal, expected):
            view = request_for(proposal)
            result = wait_until(lambda: native.http("GET", coordinator_url + "/v1/review-requests/" + view["requestId"] + "/result", review_token(), headers=review_headers, expected=(200, 202)), lambda value: value is not None, "Review did not settle")
            assert result["status"] == expected and result["subject"] == view["subject"] and result["policy"] == view["policy"] and result["submissionDigest"] == view["submissionDigest"]
            assert result["subject"]["version"] == str(proposal["submissionVersion"]) and result["subject"]["digest"] == proposal["effectDigest"]
            return view, result
        intended_inputs = {}
        def create(label, *, active=True, action="correct-amount", amount=None):
            seed = journey.token("bregctl", owner, "seed-client")
            record = native.http("POST", journey.urls["breg"] + "/v1/records/applications?accessProfile=seeder", seed, {"data": {"tenant": "tenant-a", "applicantName": label, "benefitProgram": "housing-support", "requestedAmount": 1200, "email": label + "@example.invalid", "noticeAllowed": True, "appointmentAllowed": True, "active": active}}, {"Idempotency-Key": str(uuid.uuid4())}, (201,))["data"]["recordIdentifier"]
            inputs = {"applicationId": record, "proposedAmount": 1250 if amount is None else amount, "reason": "Synthetic Review provider journey"}
            draft = journey.start_proposal(owner, action, inputs)
            intended_inputs[draft["id"]] = inputs
            return record, journey.proposal_transition(owner, draft, "submit")
        def apply_body(proposal):
            return {key: proposal[key] for key in ("submissionVersion", "effectDigest")}
        def ready_to_apply(proposal, label):
            binding = {key: proposal[key] for key in ("id", "actionId", "actionRevision", "submissionVersion", "effectDigest")}
            def current():
                value = journey.read_proposal(owner, proposal)
                assert {key: value[key] for key in binding} == binding, "source readiness must name the exact frozen Proposal"
                return value
            return wait_until(current, lambda value: value["links"]["apply"]["availability"]["available"], label)
        def readiness(proposal):
            return {"binding": {key: proposal[key] for key in ("id", "actionId", "actionRevision", "submissionVersion", "effectDigest")}, "proposalRevision": proposal["revision"], "availability": proposal["links"]["apply"]["availability"]}
        def applied(proposal):
            current = wait_until(lambda: journey.read_proposal(owner, proposal), lambda value: value["state"] == "applied", "source did not independently apply the exact approved Proposal")
            assert {key: current[key] for key in ("id", "actionId", "actionRevision", "submissionVersion", "effectDigest")} == {key: proposal[key] for key in ("id", "actionId", "actionRevision", "submissionVersion", "effectDigest")}
            assert current["application"]["submissionVersion"] == proposal["submissionVersion"] and current["application"]["effectDigest"] == proposal["effectDigest"]
            return current
        def change_active(record, active):
            draft = journey.start_proposal(owner, "correct-active", {"applicationId": record, "proposedActive": active, "reason": "Independently change the condition assessed by the Review policy"})
            submitted = journey.proposal_transition(owner, draft, "submit")
            return applied(submitted)
        proof = {"boundary": "native_breg_coordinator_review_casework", "sourceApplyAuthority": "independent BReg grants and current commit guards", "binarySha256": journey.binary_digests}
        record, proposal = create("automatic")
        view, result = terminal(proposal, "approved")
        assert view["policy"] == provider_bindings["correct-amount"], "ID-only selection must accept and retain the concrete provider policy"
        effect = applied(proposal)
        assert effect["application"]["effectDigest"] == proposal["effectDigest"]
        wait_until(lambda: upstream.commands, lambda commands: len(commands) >= 2, "source did not recover the lost Review acceptance")
        assert upstream.commands[0]["key"] == upstream.commands[1]["key"] and upstream.commands[0]["bodyHash"] == upstream.commands[1]["bodyHash"]
        proof["automatic"] = {"policySelector": {"id": provider_bindings["correct-amount"]["id"]}, "acceptedPolicy": view["policy"], "subject": view["subject"], "resultId": result["resultId"], "application": effect["application"], "sameKeyAcceptanceRecovery": True}
        # A dedicated service assessment profile cannot borrow source apply.
        native.http("POST", journey.urls["breg"] + f"/v1/proposals/{proposal['id']}/apply?accessProfile=assessment", journey.token("bregctl", bootstrap, "application-reader"), apply_body(proposal), {"Idempotency-Key": str(uuid.uuid4()), "If-Match": f'"{effect["revision"]}"'}, (403, 404))
        human_record, human_proposal = create("human", amount=1500)
        human_view = request_for(human_proposal)
        held = wait_until(lambda: inspect(human_view["requestId"]), lambda value: value["run"]["state"] == "attention" and value["run"]["uncertain"], "lost downstream acceptance did not hold the exact prepared call")
        assert held["run"]["step"] == "submit-human"
        journey.stop(worker)
        worker = journey.spawn("coordinator", runtime, "review-provider-restarted-unknown")
        journey.ready(worker, coordinator_url)
        assert inspect(human_view["requestId"])["run"]["uncertain"]
        native.http("POST", coordinator_url + f"/v1/runs/{human_view['requestId']}/retry-same", operator_token(), {"reason": "Recover the exact original downstream Review acceptance"})
        wait_until(lambda: inspect(human_view["requestId"]), lambda value: bool(value["waits"]), "same-command recovery did not persist the accepted downstream binding")
        assert len(downstream.commands) >= 2 and downstream.commands[0]["key"] == downstream.commands[1]["key"] and downstream.commands[0]["bodyHash"] == downstream.commands[1]["bodyHash"]
        staff = journey.token("caseworkctl", casework, "staff")
        staff_headers = {"Registry-Casework-Profile": "staff", "Registry-Source-Profile": "reviewer"}
        task = wait_until(lambda: native.http("GET", journey.urls["casework"] + "/v1/review-tasks?queue=review&limit=25", staff, headers=staff_headers), lambda page: any(item["subject"]["id"] == human_proposal["id"] for item in page["items"]), "human route did not reach Casework")
        task = next(item for item in task["items"] if item["subject"]["id"] == human_proposal["id"])
        downstream_view = native.http("GET", journey.urls["casework"] + "/v1/review-requests/" + task["requestId"], journey.token("bregctl", bootstrap, "review-producer"), headers={"Registry-Review-Profile": "coordinator-producer"})
        assert downstream_view["subject"] == human_view["subject"] and downstream_view["policy"] == human_bindings["external-review"]
        assert downstream_view["requestId"] != human_view["requestId"] and downstream_view["submissionDigest"] != human_view["submissionDigest"]
        task_url = journey.urls["casework"] + "/v1/review-tasks/" + task["taskId"]
        display = native.http("GET", task_url + "/context", staff, headers=staff_headers)
        assert display["context"]["projection"]["display"] == {"applicationId": human_record, "recordActive": True, "currentAmount": 1200, "proposedAmount": 1500}
        native.http("POST", task_url + "/claim", staff, headers={**staff_headers, "If-Match": f'"{task["revision"]}"', "Idempotency-Key": str(uuid.uuid4())})
        current = native.http("GET", task_url, staff, headers=staff_headers)
        native.http("POST", task_url + "/decisions", staff, {"decision": {"type": "approve"}}, {**staff_headers, "If-Match": f'"{current["revision"]}"', "Idempotency-Key": str(uuid.uuid4())}, (204,))
        journey.stop(worker)
        journey.advance_completion_fixture(runtime, [human_view["requestId"]])
        worker = journey.spawn("coordinator", runtime, "review-provider-restarted-wait")
        journey.ready(worker, coordinator_url)
        _, human_result = terminal(human_proposal, "approved")
        applied(human_proposal)
        downstream_result = native.http("GET", journey.urls["casework"] + "/v1/review-requests/" + task["requestId"] + "/result", journey.token("bregctl", bootstrap, "review-producer"), headers={"Registry-Review-Profile": "coordinator-producer"})
        assert human_result["policy"] != downstream_result["policy"] and human_result["resultId"] != downstream_result["resultId"]
        assert human_result["submissionDigest"] == human_view["submissionDigest"] and downstream_result["submissionDigest"] == downstream_view["submissionDigest"]
        proof["human"] = {"upstreamPolicy": human_result["policy"], "downstreamPolicy": downstream_result["policy"], "upstreamSubmissionDigest": human_result["submissionDigest"], "downstreamSubmissionDigest": downstream_result["submissionDigest"], "restartedUnknownAndWaiting": True, "sameCommandRecovery": True}
        _, cancellable = create("cancelled-human", amount=1500)
        cancel_view = request_for(cancellable)
        cancel_tasks = wait_until(lambda: native.http("GET", journey.urls["casework"] + "/v1/review-tasks?queue=review&limit=25", staff, headers=staff_headers), lambda page: any(item["subject"]["id"] == cancellable["id"] for item in page["items"]), "cancellable human route did not reach Casework")
        cancel_task = next(item for item in cancel_tasks["items"] if item["subject"]["id"] == cancellable["id"])
        wait_until(lambda: inspect(cancel_view["requestId"]), lambda value: bool(value["waits"]), "cancellable human acceptance did not become a durable wait")
        cancelled_source = journey.proposal_transition(owner, journey.read_proposal(owner, cancellable), "cancel")
        assert cancelled_source["state"] == "cancelled" and "application" not in cancelled_source
        _, cancelled_result = terminal(cancellable, "cancelled")
        downstream_cancel_result = lambda: native.http("GET", journey.urls["casework"] + "/v1/review-requests/" + cancel_task["requestId"] + "/result", journey.token("bregctl", bootstrap, "review-producer"), headers={"Registry-Review-Profile": "coordinator-producer"}, expected=(200, 202))
        cancelled_downstream = wait_until(downstream_cancel_result, lambda value: value is not None, "authored human withdrawal did not settle")
        assert cancelled_downstream["status"] == "cancelled" and cancelled_downstream["subject"] == cancelled_result["subject"]
        journey.stop(worker)
        worker = journey.spawn("coordinator", runtime, "review-provider-restarted-cancel")
        journey.ready(worker, coordinator_url)
        assert downstream_cancel_result() == cancelled_downstream
        assert terminal(cancellable, "cancelled")[1] == cancelled_result
        assert "application" not in journey.read_proposal(owner, cancellable)
        proof["cancellation"] = {"upstreamResultId": cancelled_result["resultId"], "downstreamResultId": cancelled_downstream["resultId"], "immutableAcrossRestart": True, "durableHumanWithdrawal": True, "noSourceApplication": True}
        _, refused = create("inactive", active=False)
        _, refused_result = terminal(refused, "rejected")
        assert refused_result["outcome"] == "record-inactive"
        refused_source = wait_until(lambda: journey.read_proposal(owner, refused), lambda value: value.get("applicationStatus", {}).get("state") == "blocked", "source did not refuse the rejected review")
        assert "application" not in refused_source
        stale_record, stale = create("stale", action="correct-amount-manual")
        stale_view, stale_result = terminal(stale, "approved")
        stale_ready = ready_to_apply(stale, "source did not accept the exact approval before changing its assessed condition")
        change_active(stale_record, False)
        current = journey.read_proposal(owner, stale)
        link = current["links"]["apply"]
        stale_refusal = native.http("POST", urllib.parse.urljoin(journey.urls["breg"], link["path"]) + "?accessProfile=seeder", journey.token("bregctl", owner, "seed-client"), apply_body(stale), {"Idempotency-Key": str(uuid.uuid4()), "If-Match": link["ifMatch"]}, (412,))
        assert stale_refusal["code"] == "precondition.failed"
        current = journey.read_proposal(owner, stale)
        assert "application" not in current and terminal(stale, "approved")[1] == stale_result
        rebased = journey.proposal_transition(owner, current, "rebase", {"input": intended_inputs[stale["id"]]})
        resubmitted = journey.proposal_transition(owner, rebased, "submit")
        inactive_view, inactive_result = terminal(resubmitted, "rejected")
        assert inactive_result["outcome"] == "record-inactive" and inactive_view["requestId"] != stale_view["requestId"]
        assert "application" not in journey.read_proposal(owner, resubmitted)
        change_active(stale_record, True)
        current = journey.read_proposal(owner, resubmitted)
        rebased = journey.proposal_transition(owner, current, "rebase", {"input": intended_inputs[stale["id"]]})
        resubmitted = journey.proposal_transition(owner, rebased, "submit")
        fresh_view, fresh_result = terminal(resubmitted, "approved")
        assert fresh_view["requestId"] != stale_view["requestId"] and fresh_result["subject"]["version"] != stale_result["subject"]["version"]
        current = ready_to_apply(resubmitted, "fresh exact review did not authorize independently permitted apply")
        recovered = journey.proposal_transition(owner, current, "apply", apply_body(resubmitted))
        assert recovered["state"] == "applied" and recovered["application"]["effectDigest"] == resubmitted["effectDigest"]
        proof["staleConditionRecovery"] = {"assessedCondition": "recordActive", "oldSubject": stale_result["subject"], "sourceReadyBeforeConditionChange": readiness(stale_ready), "inactiveSubject": inactive_result["subject"], "inactiveReassessment": inactive_result["status"], "freshSubject": fresh_result["subject"], "oldApprovalDidNotOverrideGuard": True, "oldApplyProblem": stale_refusal["code"], "freshApplication": recovered["application"]}
        _, expiring = create("expiring", action="correct-amount-expiring")
        expiring_view, expiring_result = terminal(expiring, "approved")
        expiring_ready = ready_to_apply(expiring, "source did not accept the exact short-lived approval before expiry")
        available_until = dt.datetime.fromisoformat(expiring_result["availableUntil"].replace("Z", "+00:00"))
        remaining = (available_until - dt.datetime.now(dt.timezone.utc)).total_seconds()
        assert remaining > 0, "source readiness must precede the original result expiry"
        time.sleep(remaining + 0.2)
        native.http("GET", coordinator_url + f"/v1/review-requests/{expiring_view['requestId']}/result", review_token(), headers=review_headers, expected=(410,))
        native.http("POST", coordinator_url + f"/v1/review-requests/{expiring_view['requestId']}/cancel", review_token(), {"subject": expiring_view["subject"], "reason": "Expired custody cannot be renewed"}, {**review_headers, "Idempotency-Key": str(uuid.uuid4())}, (410,))
        current = journey.read_proposal(owner, expiring)
        expiry_refusal = native.http("POST", journey.urls["breg"] + f"/v1/proposals/{expiring['id']}/apply?accessProfile=seeder", journey.token("bregctl", owner, "seed-client"), apply_body(expiring), {"Idempotency-Key": str(uuid.uuid4()), "If-Match": current["links"]["apply"]["ifMatch"]}, (412,))
        assert expiry_refusal["code"] == "precondition.failed"
        assert "application" not in journey.read_proposal(owner, expiring)
        proof["refusalAndExpiry"] = {"inactiveResult": refused_result["status"], "sourceReadyBeforeExpiry": readiness(expiring_ready), "resultRetentionSeconds": EXPIRING_RETENTION_SECONDS, "availableUntil": expiring_result["availableUntil"], "expiredResultAndCancel": 410, "expiredApplyProblem": expiry_refusal["code"], "noSourceApplication": True}
        native.private(root / "native-review-provider-proof.json", proof)
        success = True
    finally:
        journey.cleanup(success)
        if success and runtime:
            config = load(runtime)
            schema = config["namespace"]
            role = config["deployment"]["runtimeRole"]
            assert re.fullmatch(r"coordinator_[0-9a-f]{32}", schema) and re.fullmatch(r"coordinator_native_[0-9a-f]{16}", role)
            result = subprocess.run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-q"], input=f"DROP SCHEMA {schema} CASCADE; DROP ROLE {role};\n".encode(), env=native.database_environment(database, journey.env), capture_output=True, timeout=30)
            assert result.returncode == 0, "owned Coordinator schema/role cleanup failed"
    print("Native Review provider journey passed: automatic and human approval, exact recovery, cancellation and withdrawal, stale guard and fresh rebase, refusal and expiry.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True, type=Path, help="Directory containing the six already built public executables")
    parser.add_argument("--build-manifest", type=Path, help="Private source, executable and FIPS library evidence from native preparation")
    parser.add_argument("--work-dir", type=Path, help="New private directory for retained synthetic diagnostics")
    args = parser.parse_args()
    os.umask(0o077)
    run(args)


if __name__ == "__main__":
    main()

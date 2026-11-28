"""Value-free acceptance failures for exact correlation, disclosure and cleanup."""

import json
from datetime import datetime
from urllib.parse import parse_qs, urlsplit


def check_ask_loop(observed, text, content):
    """Check served milestones, returning a content-free proof receipt."""
    submitted, asked = observed["submitted"], observed["asked"]
    proposal, version = submitted["id"], submitted["submissionVersion"]
    request, task, ask = observed["accepted"]["requestId"], asked["task"]["taskId"], asked["ask"]["askId"]
    file = observed["additionId"]
    question = asked["ask"]
    assert question["state"] == "open" and question["wants"] == [{"kind": "document"}], "ask differs"
    assert question.get("dueAt") and datetime.fromisoformat(question["dueAt"]) > datetime.fromisoformat(
        question["askedAt"]
    ), "ask has no future due date"
    assert asked["task"]["requestId"] == request and asked["task"]["marker"] == "waiting", "ask task differs"
    for name in ("party", "answered"):
        document = observed[name]
        assert all(document[key] == submitted[key] for key in ("id", "submissionVersion", "effectDigest")), (
            "answer changed the frozen submission"
        )
        assert document["state"] == "submitted", "submission left review"
    party = observed["party"]
    assert (party["status"], party["turn"]) == ("awaiting-party", "party"), "party turn missing"
    assert any(item["id"] == proposal for item in observed["partyPage"]["items"]), "party list omits proposal"
    assert any(
        item["id"] == ask
        and item["state"] == "open"
        and datetime.fromisoformat(item["dueAt"]) == datetime.fromisoformat(question["dueAt"])
        for item in party["asks"]
    ), "mirror differs"
    event = observed["hook"]
    assert event["type"] == "proposal.asked" and event["data"]["transition"] == "asked", "asked hook missing"
    assert event["data"]["proposalId"] == proposal and event["data"]["submissionVersion"] == version, (
        "asked hook names another submission"
    )
    assert observed["answered"]["status"] == "in-review", "local answer did not return to review"
    answers = [item for item in observed["answered"]["asks"] if item["id"] == ask]
    assert len(answers) == 1 and answers[0]["state"] == "answered", "local answer missing"
    assert answers[0]["answer"]["text"] == text and answers[0]["answer"]["additions"] == [file], (
        "local answer differs"
    )
    assert observed["task"]["taskId"] == task and observed["task"]["marker"] == "answered", (
        "delivery marker missing"
    )
    context = observed["context"]
    assert context["taskId"] == task and context["requestId"] == request, "reviewer binding changed"
    asks = [item for item in context["asks"] if item["askId"] == ask]
    assert len(asks) == 1 and asks[0]["taskId"] == task and asks[0]["state"] == "answered", (
        "reviewer ask differs"
    )
    answer = asks[0]["answer"]
    assert answer["text"] == text and len(answer["documents"]) == 1, "reviewer answer differs"
    document = answer["documents"][0]
    assert document["id"] == file and document["verificationStatus"] in ("approved", "notRequired"), (
        "citation differs"
    )
    download = document["download"]
    parsed = urlsplit(download["path"])
    assert download["method"] == "GET" and download["operation"] == "get-review-context", (
        "download authority differs"
    )
    assert parsed.path == f"/v1/proposals/{proposal}/additions/{file}", "download file differs"
    assert parse_qs(parsed.query).get("reviewAskId") == [ask], "download ask differs"
    assert observed["download"] == content, "cited download bytes differ"
    assert set(observed["createdRequestIds"]) == {request}, "more than one review request created"
    assert len(observed["correlations"]) >= 3 and all(
        item["requestId"] == request for item in observed["correlations"]
    ), "accepted request changed during the loop"
    decided = observed["decidedTask"]
    assert decided["taskId"] == task and decided["requestId"] == request, "decision changed task or request"
    assert decided["state"] == "decided" and decided["decidedByCaller"] is True, "holder decision missing"
    assert (
        decided["decisionReceipt"]["decision"] == "approve"
        and decided["decisionReceipt"]["outcome"] == "approved"
    ), "holder did not approve"
    assert observed["requests"] and all(item["actor"] != "applicant" for item in observed["requests"]), (
        "Casework received the applicant token"
    )
    return {
        "proposalId": proposal,
        "submissionVersion": version,
        "requestId": request,
        "taskId": task,
        "askId": ask,
        "additionId": file,
        "hookEventId": event["id"],
        "status": "in-review",
        "marker": "answered",
        "decision": "approved",
        "applicantToken": "not-sent",
    }


def check_correlation(proposal, accepted, result):
    assert all(
        result[key] == accepted[key] for key in ("requestId", "policy", "subject", "submissionDigest")
    ), "review result correlation mismatch"
    assert accepted["subject"] == {
        "source": "registry",
        "type": "proposal",
        "id": proposal["id"],
        "version": str(proposal["submissionVersion"]),
        "digest": proposal["effectDigest"],
    }, "review subject does not match frozen submission"
    assert result["status"] == "approved" and result["outcome"] == "approved", "review did not approve"


def check_minimized(payload, expected):
    assert payload["supportedValues"] == [
        {"providesValueFor": "urn:example:concept:record-active:active", "value": expected}
    ], "assertion output differs"
    assert type(payload["supportedValues"][0]["value"]) is bool, "assertion output is not Boolean"
    encoded = json.dumps(payload)
    assert not any(
        value in encoded
        for value in (
            "PRIVATE-CANARY",
            "SYNTHETIC-LIVE",
            '"label"',
            '"status"',
            '"active"',
            '"retired"',
            '"registrationNumber"',
        )
    ), "private source values disclosed"


def check_cleanup(receipt):
    assert receipt == {"processesStopped": True, "databasesRemaining": 0, "rolesRemaining": 0}, (
        "owned resources remain"
    )


def check_observations(before, after):
    check_minimized(before, False)
    check_minimized(after, True)
    keys = (
        "configurationRevision",
        "subjects",
        "issuedBy",
        "providedBy",
        "supportsRequirement",
        "isConformantTo",
        "purpose",
        "audience",
    )
    assert all(before[key] == after[key] for key in keys), "observation identity or contract drifted"
    assert before["requestNonce"] != after["requestNonce"], "observations reused a prepared request"

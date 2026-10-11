"""Live citizen self-registration journey over the public BReg and Casework APIs.

The caller owns process startup, native ThunderID sign-in, directory bootstrap,
and BReg restart. This module neither mints credentials nor reaches into either
service's database. Checkpoints deliberately contain only states and counts.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

APPLICANT_PROFILE = "registration-applicant"
MEMBER_PROFILE = "registration-member"
OPERATOR_PROFILE = "registration-operator"
CASEWORK_PROFILE = "registration-reviewer"
SOURCE_PROFILE = "registration-reviewer"
QUEUE = "registration-review"
PROGRAM_CODE = "synthetic-citizen-program"


class JourneyError(RuntimeError):
    """A public contract in the live journey did not hold."""


@dataclass(frozen=True)
class _Response:
    status: int
    body: Any
    headers: Mapping[str, str]


def _actor(value: Mapping[str, Any], label: str) -> dict[str, str]:
    token = value.get("access_token")
    subject = value.get("sub")
    if not isinstance(token, str) or not token or not isinstance(subject, str) or not subject:
        raise JourneyError(f"{label} must contain non-empty access_token and sub strings")
    return {"access_token": token, "sub": subject}


def _same_origin_url(origin: str, path: str) -> str:
    base = origin.rstrip("/") + "/"
    url = urllib.parse.urljoin(base, path.lstrip("/"))
    expected = urllib.parse.urlsplit(base)
    actual = urllib.parse.urlsplit(url)
    if (actual.scheme, actual.netloc) != (expected.scheme, expected.netloc):
        raise JourneyError("a server-supplied action link changed origin")
    return url


def _request(
    origin: str,
    method: str,
    path: str,
    token: str,
    *,
    body: Any | None = None,
    headers: Mapping[str, str] | None = None,
    content_type: str = "application/json",
) -> _Response:
    request_headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        **(dict(headers) if headers else {}),
    }
    encoded = None
    if body is not None:
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request_headers["Content-Type"] = content_type
    call = urllib.request.Request(
        _same_origin_url(origin, path),
        data=encoded,
        headers=request_headers,
        method=method,
    )
    try:
        response = urllib.request.urlopen(call, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    except (urllib.error.URLError, TimeoutError) as error:
        raise JourneyError(f"{method} request could not reach the configured service") from error
    with response:
        raw = response.read()
        status = response.status
        if not isinstance(status, int):
            raise JourneyError(f"{method} request omitted its HTTP status")
        response_headers = {name.lower(): value for name, value in response.headers.items()}
        try:
            document = json.loads(raw) if raw else {}
        except json.JSONDecodeError as error:
            raise JourneyError(f"{method} request returned non-JSON HTTP {status}") from error
        return _Response(status, document, response_headers)


def _expect(response: _Response, status: int, step: str) -> Any:
    if response.status != status:
        code = response.body.get("code") if isinstance(response.body, dict) else None
        suffix = f" ({code})" if isinstance(code, str) else ""
        raise JourneyError(f"{step} returned HTTP {response.status}{suffix}, expected {status}")
    return response.body


def _expect_problem(response: _Response, status: int, code: str, step: str) -> None:
    _expect(response, status, step)
    if not isinstance(response.body, dict) or response.body.get("code") != code:
        raise JourneyError(f"{step} did not return {code}")


def _record_id(response: _Response, step: str) -> str:
    body = _expect(response, response.status, step)
    try:
        value = body["data"]["recordIdentifier"]
    except (KeyError, TypeError) as error:
        raise JourneyError(f"{step} omitted data.recordIdentifier") from error
    if not isinstance(value, str) or not value:
        raise JourneyError(f"{step} returned an invalid record identifier")
    return value


def _etag(response: _Response, step: str) -> str:
    value = response.headers.get("etag")
    if not isinstance(value, str) or not value:
        raise JourneyError(f"{step} omitted the strong ETag")
    return value


def _profile_path(path: str, profile: str) -> str:
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}accessProfile={urllib.parse.quote(profile, safe='')}"


def _breg_get(origin: str, path: str, token: str, profile: str) -> _Response:
    return _request(origin, "GET", _profile_path(path, profile), token)


def _list_all(origin: str, route: str, token: str, profile: str) -> list[dict[str, Any]]:
    path = _profile_path(f"/v1/records/{route}", profile)
    items: list[dict[str, Any]] = []
    seen_cursors: set[str] = set()
    while True:
        response = _request(origin, "GET", path, token)
        body = _expect(response, 200, f"list {route} as {profile}")
        if not isinstance(body, dict) or not isinstance(body.get("items"), list):
            raise JourneyError(f"list {route} returned an invalid collection envelope")
        if not all(isinstance(item, dict) for item in body["items"]):
            raise JourneyError(f"list {route} returned an invalid collection member")
        items.extend(body["items"])
        page = body.get("pageInfo")
        cursor = page.get("nextCursor") if isinstance(page, dict) else None
        if cursor is None:
            return items
        if not isinstance(cursor, str) or not cursor or cursor in seen_cursors:
            raise JourneyError(f"list {route} returned an invalid continuation cursor")
        seen_cursors.add(cursor)
        path = (
            f"/v1/records/{route}?accessProfile={urllib.parse.quote(profile, safe='')}"
            f"&$skiptoken={urllib.parse.quote(cursor, safe='')}"
        )


def _counts(breg_url: str, reviewer_token: str) -> dict[str, int]:
    return {
        "person": len(_list_all(breg_url, "persons", reviewer_token, OPERATOR_PROFILE)),
        "link": len(_list_all(breg_url, "self-service-links", reviewer_token, OPERATOR_PROFILE)),
        "enrollment": len(_list_all(breg_url, "program-enrollments", reviewer_token, OPERATOR_PROFILE)),
    }


def _require_counts(actual: Mapping[str, int], expected: Mapping[str, int], step: str) -> None:
    if dict(actual) != dict(expected):
        raise JourneyError(f"{step} returned unexpected governed-record counts")


def _application_body(owner: str, given: str, family: str, date_of_birth: str) -> dict[str, Any]:
    return {
        "data": {
            "owner": owner,
            "givenName": given,
            "familyName": family,
            "dateOfBirth": date_of_birth,
            "programCode": PROGRAM_CODE,
        }
    }


def _create_application(
    breg_url: str,
    actor: Mapping[str, str],
    body: Mapping[str, Any],
    key: str,
    *,
    replay: bool = False,
) -> tuple[str, _Response]:
    path = _profile_path("/v1/records/registration-applications", APPLICANT_PROFILE)
    headers = {"Idempotency-Key": key}
    response = _request(breg_url, "POST", path, actor["access_token"], body=body, headers=headers)
    _expect(response, 201, "create registration application")
    if replay:
        repeated = _request(breg_url, "POST", path, actor["access_token"], body=body, headers=headers)
        _expect(repeated, 201, "replay registration application create")
        if repeated.body != response.body or repeated.headers.get("etag") != response.headers.get("etag"):
            raise JourneyError("application create replay changed its committed response")
    return _record_id(response, "create registration application"), response


def _get_application(breg_url: str, application_id: str, actor: Mapping[str, str]) -> _Response:
    return _breg_get(
        breg_url,
        f"/v1/records/registration-applications/{urllib.parse.quote(application_id, safe='')}",
        actor["access_token"],
        APPLICANT_PROFILE,
    )


def _request_view(response: _Response, step: str) -> dict[str, Any]:
    body = _expect(response, 200, step)
    try:
        request = body["data"]["request"]
    except (KeyError, TypeError) as error:
        raise JourneyError(f"{step} omitted data.request") from error
    if not isinstance(request, dict):
        raise JourneyError(f"{step} returned an invalid data.request")
    return request


def _action(request: Mapping[str, Any], operation: str, step: str) -> dict[str, Any]:
    actions = request.get("actions")
    if not isinstance(actions, list):
        raise JourneyError(f"{step} omitted request actions")
    matches = [item for item in actions if isinstance(item, dict) and item.get("operation") == operation]
    if len(matches) != 1:
        raise JourneyError(f"{step} did not offer exactly one {operation} action")
    candidate = matches[0]
    if not isinstance(candidate.get("href"), str) or not isinstance(candidate.get("ifMatch"), str):
        raise JourneyError(f"{step} returned an incomplete {operation} action")
    return candidate


def _post_action(
    breg_url: str,
    actor: Mapping[str, str],
    action: Mapping[str, Any],
    body: Mapping[str, Any],
    key: str,
    step: str,
    *,
    replay: bool = False,
) -> _Response:
    headers = {"If-Match": action["ifMatch"], "Idempotency-Key": key}
    response = _request(
        breg_url,
        "POST",
        action["href"],
        actor["access_token"],
        body=body,
        headers=headers,
    )
    _expect(response, 200, step)
    if replay:
        repeated = _request(
            breg_url,
            "POST",
            action["href"],
            actor["access_token"],
            body=body,
            headers=headers,
        )
        _expect(repeated, 200, f"replay {step}")
        if repeated.body != response.body:
            raise JourneyError(f"{step} replay changed its committed response")
    return response


def _poll(deadline: float, step: str, probe: Callable[[], Any | None]) -> Any:
    while True:
        value = probe()
        if value is not None:
            return value
        if time.monotonic() >= deadline:
            raise JourneyError(f"{step} did not complete within the live journey deadline")
        time.sleep(0.25)


def _poll_application(
    deadline: float,
    breg_url: str,
    application_id: str,
    actor: Mapping[str, str],
    predicate: Callable[[dict[str, Any]], bool],
    step: str,
) -> tuple[_Response, dict[str, Any]]:
    def probe() -> tuple[_Response, dict[str, Any]] | None:
        response = _get_application(breg_url, application_id, actor)
        if response.status in (502, 503):
            return None
        request = _request_view(response, step)
        return (response, request) if predicate(request) else None

    return _poll(deadline, step, probe)


def _submission_request_id(
    deadline: float, breg_url: str, application_id: str, actor: Mapping[str, str]
) -> str:
    def accepted(request: dict[str, Any]) -> bool:
        review = request.get("review")
        submission = review.get("submission") if isinstance(review, dict) else None
        return isinstance(submission, dict) and submission.get("state") == "accepted" and isinstance(
            submission.get("requestId"), str
        )

    _, request = _poll_application(
        deadline,
        breg_url,
        application_id,
        actor,
        accepted,
        "review submission acceptance",
    )
    return request["review"]["submission"]["requestId"]


def _casework_headers() -> dict[str, str]:
    return {
        "Registry-Casework-Profile": CASEWORK_PROFILE,
        "Registry-Source-Profile": SOURCE_PROFILE,
    }


def replace_directory(
    casework_url: str,
    issuer: str,
    reviewer_token: str,
    principal: str,
) -> dict[str, Any]:
    """Replace the disposable registration review team with one native reviewer."""

    if not all(isinstance(value, str) and value for value in (issuer, reviewer_token, principal)):
        raise JourneyError("issuer, reviewer_token, and principal must be non-empty strings")
    admin_headers = {"Registry-Casework-Profile": "registration-administrator"}
    current = _request(
        casework_url,
        "GET",
        "/v1/directory",
        reviewer_token,
        headers=admin_headers,
    )
    document = _expect(current, 200, "read Casework directory")
    revision = document.get("revision") if isinstance(document, dict) else None
    if not isinstance(revision, int) or revision < 0:
        raise JourneyError("Casework directory returned an invalid revision")
    updated = _request(
        casework_url,
        "PUT",
        "/v1/directory/teams/registration-team",
        reviewer_token,
        body={
            "staff": [{"issuer": issuer, "subject": principal}],
            "supervisors": [],
            "servedQueues": [QUEUE],
        },
        headers={
            **admin_headers,
            "If-Match": f'"{revision}"',
            "Idempotency-Key": f"registration-team-{uuid.uuid4().hex}",
        },
    )
    result = _expect(updated, 200, "replace Casework registration team")
    if not isinstance(result, dict):
        raise JourneyError("Casework directory replacement returned an invalid response")
    teams = result.get("teams")
    matching = [
        team
        for team in teams if isinstance(team, dict) and team.get("id") == "registration-team"
    ] if isinstance(teams, list) else []
    members = matching[0].get("members") if len(matching) == 1 else None
    if (
        len(matching) != 1
        or not isinstance(members, list)
        or len(members) != 1
        or not isinstance(members[0], dict)
        or members[0].get("issuer") != issuer
        or members[0].get("subject") != principal
        or matching[0].get("supervisors") != []
        or matching[0].get("servedQueues") != [QUEUE]
    ):
        raise JourneyError("Casework did not persist the exact registration review team")
    return result


def _casework_tasks(casework_url: str, reviewer_token: str) -> _Response:
    query = urllib.parse.urlencode({"queue": QUEUE, "ownership": "unclaimed", "limit": 100})
    return _request(
        casework_url,
        "GET",
        f"/v1/review-tasks?{query}",
        reviewer_token,
        headers=_casework_headers(),
    )


def _wait_for_task(
    deadline: float, casework_url: str, reviewer_token: str, review_request_id: str
) -> dict[str, Any]:
    def probe() -> dict[str, Any] | None:
        response = _casework_tasks(casework_url, reviewer_token)
        if response.status in (502, 503):
            return None
        body = _expect(response, 200, "list registration review tasks")
        items = body.get("items") if isinstance(body, dict) else None
        if not isinstance(items, list):
            raise JourneyError("Casework returned an invalid review task page")
        for item in items:
            if isinstance(item, dict) and item.get("requestId") == review_request_id:
                if not isinstance(item.get("taskId"), str) or not isinstance(item.get("revision"), int):
                    raise JourneyError("Casework returned an invalid matching review task")
                return item
        return None

    return _poll(deadline, "registration review task discovery", probe)


def _assert_source_context(
    casework_url: str,
    reviewer_token: str,
    task: Mapping[str, Any],
    application_id: str,
    expected_data: Mapping[str, Any],
) -> None:
    response = _request(
        casework_url,
        "GET",
        f"/v1/review-tasks/{urllib.parse.quote(task['taskId'], safe='')}/context",
        reviewer_token,
        headers=_casework_headers(),
    )
    body = _expect(response, 200, "read registration review source context")
    context = body.get("context") if isinstance(body, dict) else None
    projection = context.get("projection") if isinstance(context, dict) else None
    display = projection.get("display") if isinstance(projection, dict) else None
    reference = context.get("reference") if isinstance(context, dict) else None
    subject = body.get("subject") if isinstance(body, dict) else None
    binding = projection.get("binding") if isinstance(projection, dict) else None
    if (
        not isinstance(subject, dict)
        or subject.get("source") != "citizen-self-registration"
        or subject.get("type") != "registration-application"
        or subject.get("id") != application_id
        or not isinstance(subject.get("version"), str)
        or not subject["version"]
        or not isinstance(binding, dict)
        or binding.get("version") != subject["version"]
        or binding.get("integrity") != subject.get("digest")
    ):
        raise JourneyError("Casework source context did not bind the current application proposal")
    expected_reference = (
        f"breg:citizen-self-registration:registration-application:{application_id}:{subject['version']}"
    )
    if (
        not isinstance(context, dict)
        or context.get("strategy") != "source"
        or context.get("bindingStatus") != "current"
        or reference != expected_reference
        or display != expected_data
    ):
        raise JourneyError("Casework did not return the exact current BReg source projection")


def _claim_task(
    casework_url: str, reviewer_token: str, task: Mapping[str, Any], key: str
) -> dict[str, Any]:
    response = _request(
        casework_url,
        "POST",
        f"/v1/review-tasks/{urllib.parse.quote(task['taskId'], safe='')}/claim",
        reviewer_token,
        headers={
            **_casework_headers(),
            "If-Match": f'"{task["revision"]}"',
            "Idempotency-Key": key,
        },
    )
    body = _expect(response, 200, "claim registration review task")
    if not isinstance(body, dict) or not isinstance(body.get("revision"), int):
        raise JourneyError("Casework claim returned an invalid task revision")
    return body


def _decide_task(
    casework_url: str,
    reviewer_token: str,
    task_id: str,
    revision: int,
    decision: Mapping[str, Any],
    key: str,
    *,
    replay: bool = False,
) -> None:
    path = f"/v1/review-tasks/{urllib.parse.quote(task_id, safe='')}/decisions"
    headers = {
        **_casework_headers(),
        "If-Match": f'"{revision}"',
        "Idempotency-Key": key,
    }
    body = {"decision": dict(decision)}
    response = _request(casework_url, "POST", path, reviewer_token, body=body, headers=headers)
    _expect(response, 204, "record registration review decision")
    if replay:
        repeated = _request(casework_url, "POST", path, reviewer_token, body=body, headers=headers)
        _expect(repeated, 204, "replay registration review decision")


def _review(
    deadline: float,
    breg_url: str,
    casework_url: str,
    application_id: str,
    actor: Mapping[str, str],
    reviewer_token: str,
    expected_data: Mapping[str, Any],
    decision: Mapping[str, Any],
    key_prefix: str,
    *,
    replay_decision: bool = False,
) -> str:
    review_request_id = _submission_request_id(deadline, breg_url, application_id, actor)
    task = _wait_for_task(deadline, casework_url, reviewer_token, review_request_id)
    _assert_source_context(casework_url, reviewer_token, task, application_id, expected_data)
    claimed = _claim_task(casework_url, reviewer_token, task, f"{key_prefix}-claim")
    _decide_task(
        casework_url,
        reviewer_token,
        task["taskId"],
        claimed["revision"],
        decision,
        f"{key_prefix}-decision",
        replay=replay_decision,
    )
    return review_request_id


def _wait_review_state(
    deadline: float,
    breg_url: str,
    application_id: str,
    actor: Mapping[str, str],
    state: str,
) -> tuple[_Response, dict[str, Any]]:
    def matches(request: dict[str, Any]) -> bool:
        review = request.get("review")
        result = review.get("result") if isinstance(review, dict) else None
        return isinstance(result, dict) and result.get("state") == state

    return _poll_application(
        deadline, breg_url, application_id, actor, matches, f"review state {state}"
    )


def _wait_task_absent(
    deadline: float, casework_url: str, reviewer_token: str, review_request_id: str
) -> None:
    def probe() -> bool | None:
        response = _casework_tasks(casework_url, reviewer_token)
        if response.status in (502, 503):
            return None
        body = _expect(response, 200, "list registration review tasks after withdrawal")
        items = body.get("items") if isinstance(body, dict) else None
        if not isinstance(items, list):
            raise JourneyError("Casework returned an invalid review task page")
        return True if not any(
            isinstance(item, dict) and item.get("requestId") == review_request_id for item in items
        ) else None

    _poll(deadline, "withdrawn task removal", probe)


def run_journey(
    breg_url: str,
    casework_url: str,
    applicant_a: Mapping[str, Any],
    applicant_b: Mapping[str, Any],
    reviewer_token: str,
    login: Callable[[str], Mapping[str, Any]],
    phone_a: str,
    phone_b: str,
    checkpoint: Callable[[str, dict[str, Any]], None],
    restart_breg: Callable[[], None],
) -> None:
    """Exercise native account ownership, review, application, and revocation."""

    if not isinstance(reviewer_token, str) or not reviewer_token:
        raise JourneyError("reviewer_token must be a non-empty native access token")
    if not callable(login) or not callable(checkpoint) or not callable(restart_breg):
        raise JourneyError("login, checkpoint, and restart_breg must be callable")
    a = _actor(applicant_a, "applicant_a")
    b = _actor(applicant_b, "applicant_b")
    if a["sub"] == b["sub"]:
        raise JourneyError("the two applicant accounts must have distinct subjects")
    deadline = time.monotonic() + 285
    run_key = f"citizen-live-{uuid.uuid4().hex}"

    zero = {"person": 0, "link": 0, "enrollment": 0}
    initial_counts = _counts(breg_url, reviewer_token)
    _require_counts(initial_counts, zero, "initial operator reads")
    checkpoint("baseline-counts", initial_counts)

    # The account claim, not caller input, is the immutable owner boundary.
    wrong_owner = _request(
        breg_url,
        "POST",
        _profile_path("/v1/records/registration-applications", APPLICANT_PROFILE),
        a["access_token"],
        body=_application_body(b["sub"], "Spoofed", "Owner", "1992-02-02"),
        headers={"Idempotency-Key": f"{run_key}-spoof-create"},
    )
    _expect_problem(wrong_owner, 412, "precondition.failed", "create with a spoofed owner")

    arbitrary_person = _application_body(a["sub"], "Ada", "Okafor", "1990-04-12")
    arbitrary_person["data"]["person"] = str(uuid.uuid4())
    extra = _request(
        breg_url,
        "POST",
        _profile_path("/v1/records/registration-applications", APPLICANT_PROFILE),
        a["access_token"],
        body=arbitrary_person,
        headers={"Idempotency-Key": f"{run_key}-person-target"},
    )
    _expect_problem(extra, 400, "request.invalid", "create with an arbitrary person target")

    direct_create_bodies = {
        "persons": {"data": {"givenName": "Direct", "familyName": "Person", "dateOfBirth": "1990-01-01"}},
        "self-service-links": {
            "data": {"person": str(uuid.uuid4()), "principal": a["sub"], "active": True}
        },
        "program-enrollments": {
            "data": {"person": str(uuid.uuid4()), "programCode": PROGRAM_CODE}
        },
    }
    for route, body in direct_create_bodies.items():
        denied = _request(
            breg_url,
            "POST",
            _profile_path(f"/v1/records/{route}", APPLICANT_PROFILE),
            a["access_token"],
            body=body,
            headers={"Idempotency-Key": f"{run_key}-direct-{route}"},
        )
        _expect_problem(denied, 404, "resource.not_found", f"direct create on {route}")

    a_body = _application_body(a["sub"], "Ada", "Okafor", "1990-04-12")
    b_body = _application_body(b["sub"], "Binta", "Mensah", "1988-08-23")
    a_id, a_create = _create_application(
        breg_url, a, a_body, f"{run_key}-create-a", replay=True
    )
    b_id, _ = _create_application(breg_url, b, b_body, f"{run_key}-create-b")

    spoof_patch = _request(
        breg_url,
        "PATCH",
        _profile_path(
            f"/v1/records/registration-applications/{urllib.parse.quote(a_id, safe='')}",
            APPLICANT_PROFILE,
        ),
        a["access_token"],
        body=[{"op": "replace", "path": "/data/owner", "value": b["sub"]}],
        headers={"If-Match": _etag(a_create, "created application"), "Idempotency-Key": f"{run_key}-spoof-patch"},
        content_type="application/json-patch+json",
    )
    _expect_problem(spoof_patch, 412, "precondition.failed", "patch to a spoofed owner")

    a_view = _get_application(breg_url, a_id, a)
    extra_patch = _request(
        breg_url,
        "PATCH",
        _profile_path(
            f"/v1/records/registration-applications/{urllib.parse.quote(a_id, safe='')}",
            APPLICANT_PROFILE,
        ),
        a["access_token"],
        body=[{"op": "add", "path": "/data/person", "value": str(uuid.uuid4())}],
        headers={"If-Match": _etag(a_view, "owned draft"), "Idempotency-Key": f"{run_key}-person-patch"},
        content_type="application/json-patch+json",
    )
    _expect_problem(extra_patch, 400, "request.invalid", "patch with an arbitrary person target")

    cross_get = _get_application(breg_url, a_id, b)
    _expect_problem(cross_get, 404, "resource.not_found", "second account get")
    cross_patch = _request(
        breg_url,
        "PATCH",
        _profile_path(
            f"/v1/records/registration-applications/{urllib.parse.quote(a_id, safe='')}",
            APPLICANT_PROFILE,
        ),
        b["access_token"],
        body=[{"op": "replace", "path": "/data/familyName", "value": "Cross-account"}],
        headers={"If-Match": _etag(a_view, "owned draft"), "Idempotency-Key": f"{run_key}-cross-patch"},
        content_type="application/json-patch+json",
    )
    # Mutation row-boundary refusals use the same 412 as an unmet precondition.
    _expect_problem(cross_patch, 412, "precondition.failed", "second account patch")
    a_request = _request_view(a_view, "read owned draft")
    a_submit = _action(a_request, "submit-request", "read owned draft")
    cross_submit = _request(
        breg_url,
        "POST",
        a_submit["href"],
        b["access_token"],
        body={},
        headers={"If-Match": a_submit["ifMatch"], "Idempotency-Key": f"{run_key}-cross-submit"},
    )
    _expect_problem(cross_submit, 412, "precondition.failed", "second account submit")
    b_visible = _list_all(breg_url, "registration-applications", b["access_token"], APPLICANT_PROFILE)
    if {item.get("recordIdentifier") for item in b_visible} != {b_id}:
        raise JourneyError("the second account's application list was not owner-filtered")
    unchanged = _get_application(breg_url, a_id, a)
    unchanged_body = _expect(unchanged, 200, "owner read after refused mutations")
    if (
        unchanged_body.get("data", {}).get("domainData") != a_body["data"]
        or _etag(unchanged, "owner read after refused mutations") != _etag(a_view, "owned draft")
    ):
        raise JourneyError("a refused mutation changed the owner's application or revision")

    # A fresh native login must resolve to the same immutable account and draft.
    refreshed_a = _actor(login(phone_a), "login(phone_a)")
    refreshed_b = _actor(login(phone_b), "login(phone_b)")
    if refreshed_a["sub"] != a["sub"] or refreshed_b["sub"] != b["sub"]:
        raise JourneyError("native re-login changed an applicant subject")
    a, b = refreshed_a, refreshed_b
    if _request_view(_get_application(breg_url, a_id, a), "read saved A draft").get("bregState") != "draft":
        raise JourneyError("applicant A did not recover the saved draft after login")
    if _request_view(_get_application(breg_url, b_id, b), "read saved B draft").get("bregState") != "draft":
        raise JourneyError("applicant B did not recover the saved draft after login")
    checkpoint("drafts-saved", {"status": "draft", "count": 2})

    # Simulate losing the first submit response, then recover it with the same key.
    a_view = _get_application(breg_url, a_id, a)
    a_submit = _action(_request_view(a_view, "read A before submit"), "submit-request", "read A before submit")
    _post_action(
        breg_url, a, a_submit, {}, f"{run_key}-submit-a-v1", "submit A proposal", replay=True
    )
    submitted_a = _request_view(_get_application(breg_url, a_id, a), "read submitted A")
    if any(
        isinstance(item, dict) and item.get("operation") == "apply-request"
        for item in submitted_a.get("actions", [])
    ):
        raise JourneyError("the applicant was offered application authority")
    parsed_submit = urllib.parse.urlsplit(a_submit["href"])
    apply_path = parsed_submit.path.rsplit("/", 1)[0] + "/apply"
    applicant_apply = _request(
        breg_url,
        "POST",
        _profile_path(apply_path, APPLICANT_PROFILE),
        a["access_token"],
        body={
            "proposalVersion": submitted_a.get("proposalVersion"),
            "effectDigest": submitted_a.get("effectDigest"),
        },
        headers={"If-Match": _etag(_get_application(breg_url, a_id, a), "submitted A"), "Idempotency-Key": f"{run_key}-owner-apply"},
    )
    if applicant_apply.status not in (404, 412):
        raise JourneyError("the applicant apply attempt was not refused")

    a_expected = dict(a_body["data"])
    _review(
        deadline,
        breg_url,
        casework_url,
        a_id,
        a,
        reviewer_token,
        a_expected,
        {
            "type": "changes-requested",
            "outcome": "changes-requested",
            "reason": "Correct the synthetic family name.",
        },
        f"{run_key}-a-v1",
    )
    _, changed = _wait_review_state(deadline, breg_url, a_id, a, "changesRequested")
    checkpoint("changes-requested", {"status": changed["review"]["result"]["state"]})
    _require_counts(_counts(breg_url, reviewer_token), zero, "changes-requested target reads")

    revise = _action(changed, "revise-request", "changes-requested application")
    if revise.get("rebase") is not False:
        raise JourneyError("changes-requested revision did not require rebase false")
    _post_action(
        breg_url, a, revise, {"rebase": False}, f"{run_key}-revise-a", "revise A proposal"
    )
    revised_view = _get_application(breg_url, a_id, a)
    revised = _request_view(revised_view, "read revised A draft")
    if revised.get("bregState") != "draft":
        raise JourneyError("revision did not return A's application to draft")
    patch = _request(
        breg_url,
        "PATCH",
        _profile_path(
            f"/v1/records/registration-applications/{urllib.parse.quote(a_id, safe='')}",
            APPLICANT_PROFILE,
        ),
        a["access_token"],
        body=[{"op": "replace", "path": "/data/familyName", "value": "Okafor-Synthetic"}],
        headers={"If-Match": _etag(revised_view, "revised A draft"), "Idempotency-Key": f"{run_key}-edit-a"},
        content_type="application/json-patch+json",
    )
    _expect(patch, 200, "edit revised A draft")
    a_expected["familyName"] = "Okafor-Synthetic"
    resubmit_view = _get_application(breg_url, a_id, a)
    resubmit = _action(
        _request_view(resubmit_view, "read edited A draft"), "submit-request", "read edited A draft"
    )
    _post_action(breg_url, a, resubmit, {}, f"{run_key}-submit-a-v2", "resubmit A proposal")
    _require_counts(_counts(breg_url, reviewer_token), zero, "pre-approval target reads")
    checkpoint("before-approval", zero)
    _review(
        deadline,
        breg_url,
        casework_url,
        a_id,
        a,
        reviewer_token,
        a_expected,
        {"type": "approve"},
        f"{run_key}-a-v2",
        replay_decision=True,
    )

    def applied(request: dict[str, Any]) -> bool:
        review = request.get("review")
        application = review.get("application") if isinstance(review, dict) else None
        return request.get("bregState") == "applied" and isinstance(application, dict) and application.get("state") == "applied"

    _, applied_request = _poll_application(
        deadline, breg_url, a_id, a, applied, "automatic registration application"
    )
    one_each = {"person": 1, "link": 1, "enrollment": 1}
    applied_counts = _counts(breg_url, reviewer_token)
    _require_counts(applied_counts, one_each, "approved target reads")
    approved_people = _list_all(breg_url, "persons", reviewer_token, OPERATOR_PROFILE)
    approved_person_data = {
        "givenName": a_expected["givenName"],
        "familyName": a_expected["familyName"],
        "dateOfBirth": a_expected["dateOfBirth"],
    }
    if (
        len(approved_people) != 1
        or not isinstance(approved_people[0].get("recordIdentifier"), str)
        or approved_people[0].get("domainData") != approved_person_data
    ):
        raise JourneyError("the applied Person did not contain the exact approved identity fields")
    approved_person_id = approved_people[0]["recordIdentifier"]
    checkpoint("approval-applied", {"status": applied_request["bregState"], **applied_counts})

    # The second account receives a terminal rejection and no governed records.
    b_submit_view = _get_application(breg_url, b_id, b)
    b_submit = _action(
        _request_view(b_submit_view, "read B before submit"), "submit-request", "read B before submit"
    )
    _post_action(breg_url, b, b_submit, {}, f"{run_key}-submit-b", "submit B proposal", replay=True)
    _review(
        deadline,
        breg_url,
        casework_url,
        b_id,
        b,
        reviewer_token,
        dict(b_body["data"]),
        {"type": "reject", "outcome": "rejected", "reason": "Synthetic rejection."},
        f"{run_key}-b",
    )
    _, rejected = _wait_review_state(deadline, breg_url, b_id, b, "rejected")
    _require_counts(_counts(breg_url, reviewer_token), one_each, "rejected target reads")
    b_member_rows = _list_all(breg_url, "program-enrollments", b["access_token"], MEMBER_PROFILE)
    if b_member_rows:
        raise JourneyError("the rejected account received a program enrollment")
    checkpoint("rejected", {"status": rejected["review"]["result"]["state"], **one_each})

    # A pending source-backed request may be withdrawn only by its owner.
    c_body = _application_body(b["sub"], "Binta", "Mensah-Withdrawn", "1988-08-23")
    c_id, _ = _create_application(breg_url, b, c_body, f"{run_key}-create-withdrawn")
    c_view = _get_application(breg_url, c_id, b)
    c_submit = _action(
        _request_view(c_view, "read pending-withdrawal draft"),
        "submit-request",
        "read pending-withdrawal draft",
    )
    _post_action(breg_url, b, c_submit, {}, f"{run_key}-submit-withdrawn", "submit pending withdrawal")
    c_review_id = _submission_request_id(deadline, breg_url, c_id, b)
    c_task = _wait_for_task(deadline, casework_url, reviewer_token, c_review_id)
    _assert_source_context(casework_url, reviewer_token, c_task, c_id, c_body["data"])
    c_pending = _request_view(_get_application(breg_url, c_id, b), "read pending withdrawal")
    c_cancel = _action(c_pending, "cancel-request", "read pending withdrawal")
    _post_action(breg_url, b, c_cancel, {}, f"{run_key}-cancel-withdrawn", "cancel pending request")
    _, cancelled = _poll_application(
        deadline,
        breg_url,
        c_id,
        b,
        lambda request: request.get("bregState") == "cancelled",
        "pending request cancellation",
    )
    _wait_task_absent(deadline, casework_url, reviewer_token, c_review_id)
    _require_counts(_counts(breg_url, reviewer_token), one_each, "withdrawn target reads")
    checkpoint("withdrawn", {"status": cancelled["bregState"], **one_each})

    # A second approval for the same account must roll back all three effects.
    duplicate_body = _application_body(a["sub"], "Ada", "Duplicate", "1990-04-12")
    duplicate_id, _ = _create_application(
        breg_url, a, duplicate_body, f"{run_key}-create-duplicate"
    )
    duplicate_view = _get_application(breg_url, duplicate_id, a)
    duplicate_submit = _action(
        _request_view(duplicate_view, "read duplicate draft"),
        "submit-request",
        "read duplicate draft",
    )
    _post_action(
        breg_url,
        a,
        duplicate_submit,
        {},
        f"{run_key}-submit-duplicate",
        "submit duplicate proposal",
        replay=True,
    )
    _review(
        deadline,
        breg_url,
        casework_url,
        duplicate_id,
        a,
        reviewer_token,
        duplicate_body["data"],
        {"type": "approve"},
        f"{run_key}-duplicate",
        replay_decision=True,
    )

    def duplicate_retry(request: dict[str, Any]) -> bool:
        review = request.get("review")
        result = review.get("result") if isinstance(review, dict) else None
        application = review.get("application") if isinstance(review, dict) else None
        return (
            request.get("bregState") == "submitted"
            and isinstance(result, dict)
            and result.get("state") == "approved"
            and isinstance(application, dict)
            and application.get("state") == "queued"
            and isinstance(application.get("attempts"), int)
            and application["attempts"] >= 2
            and isinstance(application.get("nextAttemptAt"), str)
        )

    # Generic precondition refusals are retried with backoff. Observe returned
    # attempts and unchanged effects rather than waiting for retry exhaustion.
    _, duplicate_request = _poll_application(
        deadline, breg_url, duplicate_id, a, duplicate_retry, "duplicate application retries"
    )
    previous_attempts = duplicate_request["review"]["application"]["attempts"]
    _require_counts(_counts(breg_url, reviewer_token), one_each, "duplicate retry target reads")
    restart_breg()
    _, recovered_duplicate = _poll_application(
        deadline, breg_url, duplicate_id, a, duplicate_retry, "duplicate retry recovery after restart"
    )
    recovered_application = recovered_duplicate["review"]["application"]
    if recovered_application["attempts"] < previous_attempts:
        raise JourneyError("retained restart lost the duplicate's recorded application attempts")
    for field in ("proposalVersion", "effectDigest"):
        if recovered_duplicate.get(field) != duplicate_request.get(field):
            raise JourneyError("retained restart changed the duplicate's frozen proposal")
    if recovered_duplicate["review"]["result"] != duplicate_request["review"]["result"]:
        raise JourneyError("retained restart changed the duplicate's accepted approval")
    _, recovered_original = _poll_application(
        deadline, breg_url, a_id, a, applied, "applied registration after restart"
    )
    application_id = applied_request["review"]["application"].get("applicationId")
    if (
        not isinstance(application_id, str)
        or not application_id
        or recovered_original["review"]["application"].get("applicationId") != application_id
    ):
        raise JourneyError("retained restart changed the original application receipt")
    recovered_counts = _counts(breg_url, reviewer_token)
    _require_counts(recovered_counts, one_each, "post-restart duplicate target reads")
    checkpoint(
        "duplicate-retrying",
        {"status": recovered_application["state"], "attempts": recovered_application["attempts"], **recovered_counts},
    )

    # Enrollment is the supported citizen read path to the approved Person reference.
    enrollments = _list_all(
        breg_url, "program-enrollments", a["access_token"], MEMBER_PROFILE
    )
    if len(enrollments) != 1:
        raise JourneyError("the approved account did not see exactly one enrollment")
    enrollment_id = enrollments[0].get("recordIdentifier")
    enrollment_data = enrollments[0].get("domainData")
    if (
        not isinstance(enrollment_id, str)
        or not isinstance(enrollment_data, dict)
        or enrollment_data.get("person") != approved_person_id
        or enrollment_data.get("programCode") != PROGRAM_CODE
    ):
        raise JourneyError("the member enrollment did not reference the exact approved Person")
    enrollment_get = _breg_get(
        breg_url,
        f"/v1/records/program-enrollments/{urllib.parse.quote(enrollment_id, safe='')}",
        a["access_token"],
        MEMBER_PROFILE,
    )
    _expect(enrollment_get, 200, "member enrollment get")
    other_get = _breg_get(
        breg_url,
        f"/v1/records/program-enrollments/{urllib.parse.quote(enrollment_id, safe='')}",
        b["access_token"],
        MEMBER_PROFILE,
    )
    _expect_problem(other_get, 404, "resource.not_found", "other account enrollment get")
    person_direct = _breg_get(
        breg_url,
        f"/v1/records/persons/{urllib.parse.quote(enrollment_data['person'], safe='')}",
        a["access_token"],
        MEMBER_PROFILE,
    )
    _expect_problem(person_direct, 404, "resource.not_found", "member direct Person get")
    checkpoint("membership-active", {"status": "active", "enrollment": 1})
    checkpoint("membership-pagination", {"status": "not-exercised-single-record", "count": 1})

    links = _list_all(breg_url, "self-service-links", reviewer_token, OPERATOR_PROFILE)
    if len(links) != 1:
        raise JourneyError("operator did not find exactly one account link")
    link_id = links[0].get("recordIdentifier")
    link_data = links[0].get("domainData")
    if (
        not isinstance(link_id, str)
        or not isinstance(link_data, dict)
        or link_data.get("principal") != a["sub"]
        or link_data.get("person") != enrollment_data["person"]
        or link_data.get("active") is not True
    ):
        raise JourneyError("the applied account link was not derived from its owner and Person")
    link_get = _breg_get(
        breg_url,
        f"/v1/records/self-service-links/{urllib.parse.quote(link_id, safe='')}",
        reviewer_token,
        OPERATOR_PROFILE,
    )
    _expect(link_get, 200, "operator account-link get")
    deactivate = _request(
        breg_url,
        "PATCH",
        _profile_path(
            f"/v1/records/self-service-links/{urllib.parse.quote(link_id, safe='')}",
            OPERATOR_PROFILE,
        ),
        reviewer_token,
        body=[{"op": "replace", "path": "/data/active", "value": False}],
        headers={"If-Match": _etag(link_get, "operator account-link get"), "Idempotency-Key": f"{run_key}-deactivate-link"},
        content_type="application/json-patch+json",
    )
    _expect(deactivate, 200, "deactivate account link")
    old_token_get = _breg_get(
        breg_url,
        f"/v1/records/program-enrollments/{urllib.parse.quote(enrollment_id, safe='')}",
        a["access_token"],
        MEMBER_PROFILE,
    )
    _expect_problem(old_token_get, 404, "resource.not_found", "revoked-token enrollment get")
    if _list_all(breg_url, "program-enrollments", a["access_token"], MEMBER_PROFILE):
        raise JourneyError("the pre-revocation token still listed an enrollment")
    checkpoint("link-revoked", {"status": "inactive", "enrollment": 0})
    checkpoint("complete", {"status": "passed", **_counts(breg_url, reviewer_token)})


__all__ = ["JourneyError", "replace_directory", "run_journey"]

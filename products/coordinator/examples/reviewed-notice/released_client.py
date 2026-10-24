# SPDX-License-Identifier: Apache-2.0
"""Prepare and admit the tutorial run through the unified Python client."""

import hashlib
from pathlib import Path

import rfc8785


def input_from_record(response, application):
    try:
        record = response["data"]
        if (
            record["recordIdentifier"] != application
            or response["meta"]["entityTypeIdentifier"] != "application"
        ):
            raise ValueError("BReg returned a different application identity")
        revision = record["revisionIdentifier"]
        fields = record["domainData"]
        projection = {
            name: fields[name]
            for name in ("applicantName", "benefitProgram", "requestedAmount")
        }
        if not isinstance(revision, str) or not revision:
            raise ValueError("application revision is invalid")
        for name in ("applicantName", "benefitProgram"):
            value = projection[name]
            if not isinstance(value, str) or not 0 < len(value.encode("utf-8")) <= 256:
                raise ValueError("an application reviewed field has an invalid value")
        amount = projection["requestedAmount"]
        if type(amount) is not int or not 0 <= amount < 2**64:
            raise ValueError("an application reviewed field has an invalid value")
        canonical = rfc8785.dumps(projection)
    except (KeyError, TypeError, rfc8785.CanonicalizationError):
        raise ValueError("application projection cannot be prepared") from None
    return {
        "applicationId": application,
        "applicationRevision": revision,
        "applicationDigest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
    }


def prepare_input(url, header_file, application):
    from registry_client import breg

    lines = Path(header_file).read_text().splitlines()
    tokens = [
        line.removeprefix("Authorization: Bearer ")
        for line in lines
        if line.startswith("Authorization: Bearer ")
    ]
    if len(tokens) != 1 or not tokens[0] or any(c.isspace() for c in tokens[0]):
        raise ValueError("application reader credential file was refused")
    client = breg.BaseRegistryClient(url, authorization={"static": tokens[0]})
    result = client.get_record(
        "applications", application, access_profile="follow-up-reader"
    )
    return input_from_record(result["value"], application)


def start_run(url, token, flow, key, data):
    from registry_client import coordinator

    client = coordinator.CoordinatorClient(url, maximum_mutation_retries=0)
    contract = client.workflow(token, flow)["value"]
    if contract["workflow"] != flow:
        raise ValueError("Coordinator returned a different workflow identity")
    request = {
        "workflow": flow,
        "workflowRevision": contract["workflowRevision"],
        "input": data,
    }
    first = client.start(token, key, request)["value"]
    repeat = client.start(token, key, request)["value"]
    if repeat["runId"] != first["runId"]:
        raise ValueError("Coordinator repeated start did not retain its run identity")
    return first["runId"]

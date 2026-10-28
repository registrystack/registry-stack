"""Value-free acceptance failures for exact correlation, disclosure and cleanup."""

import json


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
        for value in ("PRIVATE-CANARY", "SYNTHETIC-LIVE", '"label"', '"status"', '"registrationNumber"')
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

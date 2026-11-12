"""Read licensing records, then submit and recover one message receipt."""

import argparse
import json
from time import sleep

from registry_client import connect, messaging


MESSAGE_KEY = "python-script-application-received"
MESSAGE = {
    "senderProfile": "licensing-email",
    "to": {"email": "applicant@example.test"},
    "template": {"id": "application-received", "version": "1"},
    "locale": "en",
    "data": {"reference": "application-001"},
    "correlationId": "python-script-application-001",
}


def _applications(stack):
    return stack.breg.list_records(
        "applications",
        top=1,
        select=["reference", "profession"],
        access_profile="applicant",
    )


def run(*, wait_for_rotation: bool = False) -> dict[str, object]:
    stack = connect()
    applications = _applications(stack)
    if wait_for_rotation:
        sleep(65)
        applications = _applications(stack)
    try:
        submitted = stack.messaging.submit(MESSAGE_KEY, MESSAGE)
    except messaging.MessagingClientError as error:
        if not error.outcome_unknown:
            raise
        submitted = None
    receipt = stack.messaging.message_receipt(MESSAGE_KEY, MESSAGE)
    if applications.get("kind") != "complete":
        raise RuntimeError("the BReg read did not complete")
    records = applications.get("value")
    if not isinstance(records, dict) or not isinstance(records.get("items"), list):
        raise RuntimeError("the BReg read returned an invalid page")
    if receipt.get("kind") != "complete" or (
        submitted is not None and submitted.get("kind") != "complete"
    ):
        raise RuntimeError("the Messaging request did not complete")
    if submitted is not None and submitted["value"]["id"] != receipt["value"]["id"]:
        raise RuntimeError("the Messaging receipt did not match the submission")
    return {
        "applications": len(records["items"]),
        "message": receipt["value"]["id"],
        "status": receipt["value"]["status"],
    }


def main(arguments: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--wait-for-rotation",
        action="store_true",
        help="repeat the BReg read after one local runner token rotation",
    )
    options = parser.parse_args(arguments)
    print(
        json.dumps(
            run(wait_for_rotation=options.wait_for_rotation),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

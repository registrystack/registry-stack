#!/usr/bin/env python3
"""Release roster decisions shared by the release scripts and workflows.

``BREG_SERVICES_FIRST_RELEASE`` is the single place that decides which release
first ships the two Base Registry Engine supporting services, the citizen MCP
gateway ``breg-mcp`` and the citizen review page ``breg-review``. It is
``None`` because both services are merged to main but have not joined a
release: no version selects their binaries, images, or security evidence.

The pull request that admits them to a release sets this constant to the
first release version, for example ``(0, 37, 0)``, and every release script
and workflow follows from it. No script or workflow carries its own version
literal for these services.

``MESSAGING_FIRST_RELEASE`` is the single place that decides which release
first ships Registry Messaging. It is ``None`` because Messaging is merged to
main but has not joined a release: no version selects its binaries, image,
clients, rehearsal leg, or security evidence.

Messaging joins a release in the pull request that adopts the shared platform
activation crate (issue #1731) in place of ``messaging migrate``. That pull
request sets this constant to the first release version, for example
``(0, 37, 0)``, and every release script and workflow follows from it. No
script or workflow carries its own Messaging version literal.
"""

from __future__ import annotations

import argparse
import re
import sys


BREG_SERVICES_FIRST_RELEASE: tuple[int, int, int] | None = None

MESSAGING_FIRST_RELEASE: tuple[int, int, int] | None = None

VERSION_PATTERN = re.compile(r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def parse_version(version: str) -> tuple[int, int, int]:
    match = VERSION_PATTERN.fullmatch(version)
    if match is None:
        raise ValueError(f"release version must be X.Y.Z: {version!r}")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def breg_services_in_release(version: tuple[int, int, int]) -> bool:
    """Return whether the release at ``version`` ships breg-mcp and breg-review.

    The constant is read at call time so tests can patch it.
    """
    first_release = BREG_SERVICES_FIRST_RELEASE
    return first_release is not None and tuple(version) >= first_release


def messaging_in_release(version: tuple[int, int, int]) -> bool:
    """Return whether the release at ``version`` ships Registry Messaging.

    The constant is read at call time so tests can patch it.
    """
    first_release = MESSAGING_FIRST_RELEASE
    return first_release is not None and tuple(version) >= first_release


def version_argument(value: str) -> tuple[int, int, int]:
    try:
        return parse_version(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    breg_services = commands.add_parser(
        "breg-services-in-release",
        help="print true when the release version ships breg-mcp and breg-review, else false",
    )
    breg_services.add_argument("version", type=version_argument, help="release version as X.Y.Z")
    breg_services.set_defaults(in_release=breg_services_in_release)
    messaging = commands.add_parser(
        "messaging-in-release",
        help="print true when the release version ships Registry Messaging, else false",
    )
    messaging.add_argument("version", type=version_argument, help="release version as X.Y.Z")
    messaging.set_defaults(in_release=messaging_in_release)
    args = parser.parse_args(argv)
    print("true" if args.in_release(args.version) else "false")
    return 0


if __name__ == "__main__":
    sys.exit(main())

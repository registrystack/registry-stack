#!/usr/bin/env python3
"""Release roster decisions shared by the release scripts and workflows.

``RENDER_FIRST_RELEASE`` and ``EVIDENCE_OID4VCI_IMAGE_FIRST_RELEASE`` name the
first release that ships the Registry Render binary and image and the
Evidence OID4VCI adapter image, respectively. The adapter binary predates its
image and remains in every historical payload that already shipped it.

``DISCOVERYCTL_FIRST_RELEASE`` names the first release that publishes the
Discovery packaging CLI beside the existing Discovery runtime binary.
``SCHEDULING_BINARY_FIRST_RELEASE`` adds the Scheduling runtime binary beside
its existing image and operator CLI. Both additions start in v0.38.0.

``RELAY_RETIREMENT_RELEASE`` is the first numbered release that omits Relay.
Historical numbered releases keep their original Relay inventory; current and
future release plans use the retained-product roster.

``BREG_SERVICES_FIRST_RELEASE`` is the single place that decides which release
first ships the two Base Registry Engine supporting services, the citizen MCP
gateway ``breg-mcp`` and the citizen review page ``breg-review``. Both join
the binary, image, and security-evidence rosters in v0.38.0.

``MESSAGING_FIRST_RELEASE`` is the single place that decides which release
first ships the Registry Messaging binaries, image, rehearsal leg, and
security evidence. The unified Node and Python client facades add Messaging in
the same release. Those packaging surfaces join in v0.38.0, together with
Messaging's shared package activation contract.

``SCHEDULING_CLIENT_FIRST_RELEASE`` is the single place that decides which
release first adds the Registry Scheduling namespace and native bindings to the
unified Node and Python client packages. The Scheduling runtime, image, and
operator CLI already ship; only the client facades join, in v0.40.0.
"""

from __future__ import annotations

import argparse
import re
import sys


BREG_SERVICES_FIRST_RELEASE: tuple[int, int, int] | None = (0, 38, 0)

MESSAGING_FIRST_RELEASE: tuple[int, int, int] | None = (0, 38, 0)

DISCOVERYCTL_FIRST_RELEASE: tuple[int, int, int] | None = (0, 38, 0)

SCHEDULING_BINARY_FIRST_RELEASE: tuple[int, int, int] | None = (0, 38, 0)

SCHEDULING_CLIENT_FIRST_RELEASE: tuple[int, int, int] | None = (0, 40, 0)

RENDER_FIRST_RELEASE: tuple[int, int, int] | None = (0, 38, 0)

EVIDENCE_OID4VCI_IMAGE_FIRST_RELEASE: tuple[int, int, int] | None = (0, 38, 0)

RELAY_RETIREMENT_RELEASE: tuple[int, int, int] = (0, 39, 0)

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


def discoveryctl_in_release(version: tuple[int, int, int]) -> bool:
    """Return whether the release at ``version`` ships discoveryctl."""

    first_release = DISCOVERYCTL_FIRST_RELEASE
    return first_release is not None and tuple(version) >= first_release


def scheduling_binary_in_release(version: tuple[int, int, int]) -> bool:
    """Return whether Scheduling also ships as a standalone runtime binary."""

    first_release = SCHEDULING_BINARY_FIRST_RELEASE
    return first_release is not None and tuple(version) >= first_release


def scheduling_client_in_release(version: tuple[int, int, int]) -> bool:
    """Return whether the unified client packages carry Registry Scheduling.

    The constant is read at call time so tests can patch it.
    """
    first_release = SCHEDULING_CLIENT_FIRST_RELEASE
    return first_release is not None and tuple(version) >= first_release


def render_in_release(version: tuple[int, int, int]) -> bool:
    """Return whether the release at ``version`` ships Registry Render."""

    first_release = RENDER_FIRST_RELEASE
    return first_release is not None and tuple(version) >= first_release


def evidence_oid4vci_image_in_release(version: tuple[int, int, int]) -> bool:
    """Return whether the release at ``version`` ships the OID4VCI image."""

    first_release = EVIDENCE_OID4VCI_IMAGE_FIRST_RELEASE
    return first_release is not None and tuple(version) >= first_release


def relay_in_release(version: tuple[int, int, int]) -> bool:
    """Return whether a numbered release retains the historical Relay roster."""

    return tuple(version) < RELAY_RETIREMENT_RELEASE


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
    discoveryctl = commands.add_parser(
        "discoveryctl-in-release",
        help="print true when the release version ships discoveryctl, else false",
    )
    discoveryctl.add_argument(
        "version", type=version_argument, help="release version as X.Y.Z"
    )
    discoveryctl.set_defaults(in_release=discoveryctl_in_release)
    scheduling_binary = commands.add_parser(
        "scheduling-binary-in-release",
        help="print true when the release publishes the Scheduling runtime binary",
    )
    scheduling_binary.add_argument("version", type=version_argument, help="release version as X.Y.Z")
    scheduling_binary.set_defaults(in_release=scheduling_binary_in_release)
    scheduling_client = commands.add_parser(
        "scheduling-client-in-release",
        help="print true when the unified client packages carry Registry Scheduling, else false",
    )
    scheduling_client.add_argument("version", type=version_argument, help="release version as X.Y.Z")
    scheduling_client.set_defaults(in_release=scheduling_client_in_release)
    render = commands.add_parser(
        "render-in-release",
        help="print true when the release version ships Registry Render, else false",
    )
    render.add_argument("version", type=version_argument, help="release version as X.Y.Z")
    render.set_defaults(in_release=render_in_release)
    evidence_oid4vci_image = commands.add_parser(
        "evidence-oid4vci-image-in-release",
        help="print true when the release version ships the Evidence OID4VCI image, else false",
    )
    evidence_oid4vci_image.add_argument(
        "version", type=version_argument, help="release version as X.Y.Z"
    )
    evidence_oid4vci_image.set_defaults(
        in_release=evidence_oid4vci_image_in_release
    )
    relay = commands.add_parser(
        "relay-in-release",
        help="print true when the numbered release retains Relay, else false",
    )
    relay.add_argument("version", type=version_argument, help="release version as X.Y.Z")
    relay.set_defaults(in_release=relay_in_release)
    args = parser.parse_args(argv)
    print("true" if args.in_release(args.version) else "false")
    return 0


if __name__ == "__main__":
    sys.exit(main())

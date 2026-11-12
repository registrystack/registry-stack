"""Construct request-local product clients from one complete person context."""

from __future__ import annotations

from .portal import PortalContext, ReauthenticationRequired
from .workload_breg import BRegWorkload
from .workload_casework import CaseworkWorkload, HolderCaseworkWorkload


class PersonProducts:
    """Product clients and non-secret identity facts for this one request."""

    __slots__ = ("breg", "casework", "subject", "principal", "persona", "csrf_token")

    def __init__(
        self,
        breg: BRegWorkload,
        casework: CaseworkWorkload | HolderCaseworkWorkload,
        subject: str,
        principal: str,
        persona: str,
        csrf_token: str,
    ):
        self.breg = breg
        self.casework = casework
        self.subject = subject
        self.principal = principal
        self.persona = persona
        self.csrf_token = csrf_token


def bind_person(
    context: PortalContext,
    *,
    persona: str,
    breg_url: str,
    casework_url: str,
    casework_profile: str,
) -> PersonProducts:
    """Make new native clients; no credential or caller state is retained globally."""
    if context.persona != persona:
        raise ReauthenticationRequired()
    breg_token = context._token_for("breg")
    casework_token = context._token_for("casework")
    from . import breg, casework

    return PersonProducts(
        BRegWorkload(
            breg.BaseRegistryClient(  # pyright: ignore[reportAttributeAccessIssue]
                breg_url, authorization={"static": breg_token}
            )
        ),
        (HolderCaseworkWorkload if persona == "holder" else CaseworkWorkload)(
            casework.CaseworkClient(casework_url),  # pyright: ignore[reportAttributeAccessIssue]
            casework_token,
            casework_profile,
        ),
        context.subject,
        context.principal,
        context.persona,
        context.csrf_token,
    )

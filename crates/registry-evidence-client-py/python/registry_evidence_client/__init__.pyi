"""Type stubs for the compiled `registry_evidence_client` extension module.

Hand-written, not generated: PyO3 does not emit a `.pyi` on its own. Kept
honest by `tests/python/test_drift.py`, which introspects the compiled
module's real classes and asserts this file names exactly the same methods
and attributes, in both directions.

Every "JSON-shaped" parameter and return value below crosses the FFI boundary
as a plain Python object graph built from `dict`/`list`/`str`/`int`/`float`/
`bool`/`None`, mirroring the wire JSON it stands for. The request specification
is typed because the binding constrains its complete top-level shape and its
explicit response format. Other JSON documents remain `Any` where the binding
does not narrow their structure beyond the wrapped Rust contract.

Every method on `EvidenceClient` is an ordinary, blocking call: the client
owns a private tokio runtime and blocks on it for every network call,
releasing the GIL for the duration so other Python threads keep running.
None of this crosses into `asyncio`; there is no `async def` anywhere here.
"""

from typing import Any, Literal, Mapping, Optional, Sequence, TypedDict, Union

EvidenceResponseFormat = Literal["signed-jws", "sd-jwt-vc"]

SubjectRequest = TypedDict(
    "SubjectRequest", {"role": str, "selector_profile": str}
)
SubjectRequestWithValues = TypedDict(
    "SubjectRequestWithValues",
    {
        "role": str,
        "selector_profile": str,
        "selector_values": Mapping[str, Union[str, int, bool]],
    },
)
ExpectedSubject = TypedDict("ExpectedSubject", {"role": str, "binding": str})
EvidenceRequestSpec = TypedDict(
    "EvidenceRequestSpec",
    {
        "response_format": EvidenceResponseFormat,
        "requirement": str,
        "purpose": str,
        "audience": str,
        "evidence_type": str,
        "issued_by": str,
        "provided_by": str,
        "configuration_revision": str,
        "expected_assurance_profile": Any,
        "subjects": Sequence[Union[SubjectRequest, SubjectRequestWithValues]],
        "expected_outputs": Sequence[Mapping[str, Any]],
        "maximum_assertion_lifetime_seconds": int,
        "clock_skew_seconds": int,
        "subject_expectations": Union[
            Literal["accept_first_use"], Sequence[ExpectedSubject]
        ],
    },
)

class EvidenceClientError(Exception):
    """Base exception for every mapped failure this client reports.

    `kind` is always present, one of "configuration", "nonce", "token",
    "transport", "denied", "not_available", "protocol", or "verification".
    Branch on `kind`, never on the rendered message, which this crate does
    not freeze. `status`, `code`, `operation`, `retry_after_seconds`,
    `transport_kind`, and `token_kind` are present only when the underlying
    failure carries them; every other case leaves them `None`.

    No attribute here ever carries response bytes, a credential, a header
    value, a selector value, or a subject binding.

    Two failures escape this hierarchy entirely, since neither is a mapped
    failure with a `kind`: the client's internal runtime failing to start,
    which raises `RuntimeError`, and a serialization failure on a value this
    crate itself constructed, which raises `ValueError`.
    """

    kind: str
    status: Optional[int]
    code: Optional[str]
    operation: Optional[str]
    retry_after_seconds: Optional[int]
    transport_kind: Optional[str]
    token_kind: Optional[str]

class ConfigurationError(EvidenceClientError):
    """The client cannot be used as configured, or a prepared request already
    spent the single send it allows."""

    ...

class NonceError(EvidenceClientError):
    """The request nonce could not be generated."""

    ...

class TokenError(EvidenceClientError):
    """The credential presented to the deployment could not be obtained. See
    the `token_kind` attribute for the specific cause."""

    ...

class TransportError(EvidenceClientError):
    """The exchange with the deployment failed below the HTTP layer. See the
    `transport_kind` attribute for the specific cause."""

    ...

class DeniedError(EvidenceClientError):
    """The deployment refused the request with a contract-coded problem
    response. See the `status`, `code`, and `retry_after_seconds`
    attributes."""

    ...

class NotAvailableError(EvidenceClientError):
    """The deployment answered that no evidence is available for this
    request."""

    ...

class ProtocolError(EvidenceClientError):
    """The deployment answered outside its contract: an uncoded refusal, or a
    response this client could not parse. See the `status` attribute."""

    ...

class VerificationError(EvidenceClientError):
    """A signed response failed offline verification against the closed
    policy. See the `code` attribute for the verifier's own kind."""

    ...

class PreparedEvidenceRequest:
    """One request, closed and nonce-bearing, before any byte has left the
    process. No public constructor: obtain one only from
    `EvidenceClient.prepare`. Good for exactly one `send` or
    `request_and_verify` call."""

    request_nonce: str
    policy_document: Any
    subject_expectations: Union[str, Sequence[Any]]

class RawEvidenceResponse:
    """A signed response, read but not yet judged. No public constructor:
    obtain one only from `EvidenceClient.send`. Reading either attribute
    judges nothing; `verify` is what decides whether these bytes are
    trustworthy."""

    body: bytes
    operation: Optional[str]

class VerifiedEvidence:
    """A response that satisfied every expectation."""

    evidence: Any
    operation: Optional[str]
    pinned_subject_expectations: Any

class EvidenceClient:
    """A relying party's connection to one Evidence deployment."""

    def __init__(
        self,
        base_url: str,
        trusted_jwks: Any,
        revoked_key_ids: Sequence[str],
        token: Any,
        request_timeout_seconds: Optional[float] = ...,
        connect_timeout_seconds: Optional[float] = ...,
        user_agent: Optional[str] = ...,
        trusted_root_certificates: Optional[bytes] = ...,
        max_response_bytes: Optional[int] = ...,
        max_metadata_bytes: Optional[int] = ...,
    ) -> None: ...
    def prepare(self, spec: EvidenceRequestSpec) -> PreparedEvidenceRequest: ...
    def discover(self) -> Any: ...
    def fetch_jwks(self) -> Any: ...
    def send(self, prepared: PreparedEvidenceRequest) -> RawEvidenceResponse: ...
    def verify(
        self,
        prepared: PreparedEvidenceRequest,
        response: RawEvidenceResponse,
    ) -> VerifiedEvidence: ...
    def request_and_verify(
        self, prepared: PreparedEvidenceRequest
    ) -> VerifiedEvidence: ...
    def verify_as_of(
        self,
        prepared: PreparedEvidenceRequest,
        response: RawEvidenceResponse,
        as_of_unix_seconds: float,
    ) -> VerifiedEvidence: ...

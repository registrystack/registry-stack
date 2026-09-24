from typing import Generic, Literal, TypeAlias, TypedDict, TypeVar

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]
# Message identifiers are lowercase hyphenated UUIDs, checked by the native
# binding before any request is sent.
MessageId: TypeAlias = str
# RFC 3339 instants, parsed by the runtime.
Instant: TypeAlias = str

Channel: TypeAlias = Literal["email", "sms"]
MessageStatus: TypeAlias = Literal[
    "queued", "sending", "submitted", "delivered", "failed", "expired", "cancelled", "unknown",
]
MessageDispatch: TypeAlias = Literal[
    "queued", "sending", "submitted", "failed", "unknown", "cancelled", "expired",
]
MessageReport: TypeAlias = Literal["none", "sent", "delivered", "undelivered", "unavailable"]
AttemptOutcome: TypeAlias = Literal[
    "in-progress", "accepted", "transient", "permanent", "maybe-sent", "interrupted",
]

class EmailRecipient(TypedDict):
    email: str

class PhoneRecipient(TypedDict):
    phone: str

Recipient: TypeAlias = EmailRecipient | PhoneRecipient

class TemplateReference(TypedDict):
    id: str
    version: str

class _DirectContentOptional(TypedDict, total=False):
    subject: str

class DirectContent(_DirectContentOptional):
    text: str

class _SubmitMessageRequestOptional(TypedDict, total=False):
    template: TemplateReference
    locale: str
    data: JsonValue
    content: DirectContent
    notBefore: Instant
    expiresAt: Instant
    correlationId: str

class SubmitMessageRequest(_SubmitMessageRequestOptional):
    """Exactly one of `template` or `content`; `locale` and `data` accompany a template."""

    senderProfile: str
    to: Recipient

MessageLinks = TypedDict("MessageLinks", {"self": str, "cancel": str})

class MessageReceipt(TypedDict):
    id: MessageId
    status: MessageStatus
    links: MessageLinks

class _AttemptSummaryOptional(TypedDict, total=False):
    finishedAt: Instant

class AttemptSummary(_AttemptSummaryOptional):
    generation: int
    attempt: int
    outcome: AttemptOutcome
    startedAt: Instant
    providerReference: bool

class _MessageViewOptional(TypedDict, total=False):
    reportedAt: Instant
    template: TemplateReference
    correlationId: str
    notBefore: Instant

class MessageView(_MessageViewOptional):
    id: MessageId
    status: MessageStatus
    dispatch: MessageDispatch
    report: MessageReport
    channel: Channel
    senderProfile: str
    to: Recipient
    acceptedAt: Instant
    expiresAt: Instant
    updatedAt: Instant
    attempts: list[AttemptSummary]
    links: MessageLinks

T = TypeVar("T")

class Complete(TypedDict, Generic[T]):
    kind: Literal["complete"]
    value: T
    trace_id: str

MessagingErrorKind: TypeAlias = Literal[
    "configuration", "invalid_request", "transport", "problem", "protocol",
]
# The Rust client answers a code outside this catalogue as a protocol
# failure, so the catalogue is closed.
MessagingProblemCode: TypeAlias = Literal[
    "authentication.refused",
    "callback.unreadable",
    "callback.unverified",
    "content.invalid",
    "content.too-large",
    "content.too-many-segments",
    "idempotency.expired",
    "idempotency.key-reused",
    "message.dispatch-started",
    "message.not-visible",
    "message.terminal",
    "operation.not-authorized",
    "profile.not-authorized",
    "request.body-too-large",
    "request.invalid",
    "request.method-not-allowed",
    "request.not-found",
    "request.unprocessable",
    "request.unsupported-media-type",
    "service.unavailable",
    "template.data-invalid",
    "template.locale-unavailable",
    "template.not-found",
    "template.render-refused",
]
MessagingProtocolFailure: TypeAlias = Literal[
    "header_bounds", "trace_context", "media_type", "body", "problem", "status", "protocol",
]

class MessagingClientError(Exception):
    kind: MessagingErrorKind
    code: MessagingProblemCode | None
    title: str | None
    detail: str | None
    status: int | None
    trace_id: str | None
    transport_kind: str | None
    protocol_failure: MessagingProtocolFailure | None

class MessagingClient:
    def __init__(self, base_url: str, request_timeout_seconds: float | None = None, connect_timeout_seconds: float | None = None, max_response_bytes: int | None = None, user_agent: str | None = None, trusted_root_certificates: bytes | None = None) -> None: ...
    def health(self) -> Complete[None]: ...
    def ready(self) -> Complete[None]: ...
    def submit(self, token: str, idempotency_key: str, request: SubmitMessageRequest) -> Complete[MessageReceipt]: ...
    def message(self, token: str, message_id: MessageId) -> Complete[MessageView]: ...

PROBLEM_CODES: list[str]
__version__: str

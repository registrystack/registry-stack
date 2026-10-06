from typing import Generic, Literal, TypeAlias, TypedDict, TypeVar

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
# RFC 3339 instants. Instants the binding sends are parsed and normalized to
# UTC before any request; instants it answers are UTC.
Instant: TypeAlias = str

class ExternalReference(TypedDict):
    """An opaque record link Scheduling retains with a hold or appointment."""

    product: str
    recordType: str
    identifier: str

class PartyCounts(TypedDict):
    recipients: int
    attendees: int

class _AdmissionRequestOptional(TypedDict, total=False):
    channel: str | None
    duplicateKey: str | None
    windowRevision: int | None
    externalReferences: list[ExternalReference]

class AdmissionRequest(_AdmissionRequestOptional):
    """One admission: the offering, start, and party a hold or booking asks capacity for."""

    offering: str
    start: Instant
    party: PartyCounts
    policyRevision: int
    capabilities: list[str]
    prerequisites: list[str]

class _HoldConfirmationOptional(TypedDict, total=False):
    admission: None

class HoldConfirmation(_HoldConfirmationOptional):
    hold: str

class _DirectBookingOptional(TypedDict, total=False):
    hold: None

class DirectBooking(_DirectBookingOptional):
    admission: AdmissionRequest

# Exactly one of `hold` (confirm a held claim) or `admission` (book directly).
CreateAppointmentRequest: TypeAlias = HoldConfirmation | DirectBooking

class RescheduleAppointmentRequest(TypedDict):
    observedRevision: int
    admission: AdmissionRequest

class _CancelAppointmentRequestOptional(TypedDict, total=False):
    reason: str | None

class CancelAppointmentRequest(_CancelAppointmentRequestOptional):
    observedRevision: int

class SchedulingServiceDocument(TypedDict):
    schedulingId: str
    policyRevision: int
    policyDigest: str

class ServiceDocument(TypedDict):
    id: str
    label: str

SchedulingMode: TypeAlias = Literal["exact-time", "arrival-window"]

class ReminderDocument(TypedDict):
    minutesBefore: int

class WindowDocument(TypedDict):
    id: str
    revision: int
    start: Instant
    end: Instant
    units: int

class OfferingDocument(TypedDict):
    id: str
    service: str
    label: str
    mode: SchedulingMode
    location: str
    leadTimeMinutes: int
    horizonDays: int
    cancellationCutoffMinutes: int
    durationMinutes: int | None
    bufferBeforeMinutes: int | None
    bufferAfterMinutes: int | None
    startIncrementMinutes: int | None
    maxRecipients: int | None
    window: WindowDocument | None
    reminders: list[ReminderDocument]
    requiresCapabilities: list[str]
    prerequisites: list[str]

class ResourceDocument(TypedDict):
    resourceId: str
    pool: str
    capabilities: list[str]
    available: bool

class LocationDocument(TypedDict):
    locationId: str
    timezone: str

class SlotEntry(TypedDict):
    kind: Literal["slot"]
    start: Instant
    end: Instant
    free: int

class WindowEntry(TypedDict):
    kind: Literal["window"]
    window: str
    start: Instant
    end: Instant
    remaining: int
    channelRemaining: int | None

# Exact-time offerings answer grid slots; arrival-window offerings answer windows.
AvailabilityEntry: TypeAlias = SlotEntry | WindowEntry

T = TypeVar("T")

class PageDocument(TypedDict, Generic[T]):
    items: list[T]
    nextCursor: str | None

class HoldDocument(TypedDict):
    holdId: str
    offering: str
    start: Instant
    end: Instant
    resource: str | None
    units: int
    expiresAt: Instant
    policyRevision: int
    externalReferences: list[ExternalReference]

AppointmentState: TypeAlias = Literal["confirmed", "cancelled"]

class AppointmentDocument(TypedDict):
    appointmentId: str
    offering: str
    start: Instant
    end: Instant
    resource: str | None
    units: int
    channel: str | None
    revision: int
    state: AppointmentState
    policyRevision: int
    createdAt: Instant
    cancelledAt: Instant | None
    externalReferences: list[ExternalReference]

class AppointmentHistoryEntryDocument(TypedDict):
    eventId: str
    kind: str
    revision: int
    occurredAt: Instant
    actor: str | None
    detail: JsonValue

class _ExplainDocumentOptional(TypedDict, total=False):
    publicCode: str
    detailedCode: str
    explanation: str

class ExplainDocument(_ExplainDocumentOptional):
    offering: str
    start: Instant

class Complete(TypedDict, Generic[T]):
    kind: Literal["complete"]
    value: T
    trace_id: str

SchedulingErrorKind: TypeAlias = Literal[
    "configuration", "invalid_request", "transport", "problem", "protocol",
]
# The Rust client answers a code outside this catalogue as a protocol
# failure, so the catalogue is closed.
SchedulingProblemCode: TypeAlias = Literal[
    "authentication.refused",
    "booking.duplicate-active",
    "cancellation.cutoff-passed",
    "capability.unmatched",
    "capacity.exhausted",
    "cursor.expired",
    "cursor.invalid",
    "eligibility.unavailable",
    "hold.expired",
    "hold.released",
    "hook.unavailable",
    "horizon.outside",
    "idempotency.expired",
    "idempotency.key-reused",
    "location.closed",
    "operation.not-authorized",
    "party.capacity-inadequate",
    "policy.changed",
    "precondition.failed",
    "precondition.required",
    "prerequisite.missing",
    "profile.not-authorized",
    "request.body-too-large",
    "request.invalid",
    "request.method-not-allowed",
    "request.not-found",
    "request.unprocessable",
    "request.unsupported-media-type",
    "resource.unavailable",
    "revision.mismatch",
    "schedule.unpublished",
    "service.unavailable",
]
SchedulingProtocolFailure: TypeAlias = Literal[
    "header_bounds", "trace_context", "media_type", "body", "problem", "status", "protocol",
]

class SchedulingClientError(Exception):
    kind: SchedulingErrorKind
    code: SchedulingProblemCode | None
    title: str | None
    detail: str | None
    status: int | None
    trace_id: str | None
    transport_kind: str | None
    protocol_failure: SchedulingProtocolFailure | None
    # Whether the request may have taken effect although this error was
    # raised: a timeout or broken exchange after sending, an unusable answer,
    # or a 5xx. When True, recover a keyed request by sending it again under
    # the same idempotency key; a new key could apply it twice. False for a
    # configuration or request defect, a connection never established, and
    # every 4xx refusal. It is False for 410 idempotency.expired too, but
    # there an earlier attempt under the key was answered and may have
    # committed: read an appointment by its external reference or identifier
    # before choosing a new key. A hold cannot be read and expires on its own,
    # so start a new request.
    outcome_unknown: bool

class SchedulingClient:
    def __init__(self, base_url: str, request_timeout_seconds: float | None = None, connect_timeout_seconds: float | None = None, max_response_bytes: int | None = None, user_agent: str | None = None, trusted_root_certificates: bytes | None = None, max_mutation_retries: int | None = None) -> None: ...
    def get_scheduling(self, token: str) -> Complete[SchedulingServiceDocument]: ...
    def list_services(self, token: str, cursor: str | None = None) -> Complete[PageDocument[ServiceDocument]]: ...
    def list_offerings(self, token: str, cursor: str | None = None) -> Complete[PageDocument[OfferingDocument]]: ...
    def availability(self, token: str, offering: str, *, start: Instant | None = None, end: Instant | None = None, cursor: str | None = None, limit: int | None = None) -> Complete[PageDocument[AvailabilityEntry]]: ...
    def explain(self, token: str, offering: str, start: Instant) -> Complete[ExplainDocument]: ...
    def create_hold(self, token: str, idempotency_key: str, request: AdmissionRequest) -> Complete[HoldDocument]: ...
    def release_hold(self, token: str, hold_id: str) -> Complete[None]: ...
    def create_appointment(self, token: str, idempotency_key: str, request: CreateAppointmentRequest) -> Complete[AppointmentDocument]: ...
    def get_appointment(self, token: str, appointment_id: str) -> Complete[AppointmentDocument]: ...
    def list_appointments(self, token: str, reference: ExternalReference, *, cursor: str | None = None, limit: int | None = None) -> Complete[PageDocument[AppointmentDocument]]: ...
    def reschedule_appointment(self, token: str, appointment_id: str, idempotency_key: str, request: RescheduleAppointmentRequest) -> Complete[AppointmentDocument]: ...
    def cancel_appointment(self, token: str, appointment_id: str, idempotency_key: str, request: CancelAppointmentRequest) -> Complete[AppointmentDocument]: ...
    def appointment_history(self, token: str, appointment_id: str, cursor: str | None = None) -> Complete[PageDocument[AppointmentHistoryEntryDocument]]: ...
    def list_resources(self, token: str, cursor: str | None = None) -> Complete[PageDocument[ResourceDocument]]: ...
    def list_locations(self, token: str, cursor: str | None = None) -> Complete[PageDocument[LocationDocument]]: ...

PROBLEM_CODES: list[str]
__version__: str

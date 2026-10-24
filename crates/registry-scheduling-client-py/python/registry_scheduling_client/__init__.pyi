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

class _AdditionalAllocationRequestOptional(TypedDict, total=False):
    resource: str
    units: int

class AdditionalAllocationRequest(_AdditionalAllocationRequestOptional):
    offering: str

class PrimaryAllocationRequirement(TypedDict):
    kind: Literal["primary"]

class AdditionalAllocationRequirement(TypedDict):
    kind: Literal["additional"]
    index: int

AllocationRequirementDocument: TypeAlias = PrimaryAllocationRequirement | AdditionalAllocationRequirement

class AllocationDocument(TypedDict):
    requirement: AllocationRequirementDocument
    offering: str
    resource: str
    units: int
    occupiedStart: Instant
    occupiedEnd: Instant

class _OperationalAllocationOptional(TypedDict, total=False):
    resource: str

class OperationalAllocationDocument(_OperationalAllocationOptional):
    requirement: AllocationRequirementDocument
    offering: str
    units: int
    occupiedStart: Instant
    occupiedEnd: Instant

class _AvailabilityPreviewOptional(TypedDict, total=False):
    durationMinutes: int
    resource: str
    resourceUnits: int
    additionalAllocations: list[AdditionalAllocationRequest]
    party: PartyCounts

class AvailabilityPreviewRequest(_AvailabilityPreviewOptional):
    offering: str
    start: Instant

class _AvailabilityPreviewDocumentOptional(TypedDict, total=False):
    publicCode: str

class AvailabilityPreviewDocument(_AvailabilityPreviewDocumentOptional):
    offering: str
    start: Instant
    end: Instant
    capacityAvailable: bool

ManagerSelection: TypeAlias = Literal["schedulingManager"]

class BusyCoverage(TypedDict):
    start: Instant
    end: Instant
    resources: list[str]

class BusyIntervalInput(TypedDict):
    externalUid: str
    externalRevision: str
    resource: str
    start: Instant
    end: Instant

class _BusyRequestOptional(TypedDict, total=False):
    freshUntil: Instant | None

class BusyReconciliationRequest(_BusyRequestOptional):
    expectedRevision: int
    observedAt: Instant
    coverage: BusyCoverage
    status: Literal["fresh", "unavailable"]
    records: list[BusyIntervalInput]

class BusyCommitmentImpact(TypedDict):
    kind: str
    resource: str
    occupiedStart: Instant
    occupiedEnd: Instant

class _BusyImpactOptional(TypedDict, total=False):
    items: list[BusyCommitmentImpact]

class BusyImpactSummary(_BusyImpactOptional):
    total: int
    detailsAvailable: bool
    truncated: bool

class BusyReconciliationCounts(TypedDict):
    sourceId: str
    requestDigest: str
    added: int
    changed: int
    deleted: int
    retainedOutsideAuthority: int
    retainedAcrossCoverageBoundary: int
    impacts: BusyImpactSummary

class BusyReconciliationPreview(BusyReconciliationCounts):
    expectedRevision: int
    currentRevision: int

class BusyApplyOutcome(BusyReconciliationCounts):
    kind: Literal["applied", "already-applied"]
    revision: int

class PartyReference(TypedDict):
    """Source-owned booking data, not authority or proof of a relationship."""

    role: Literal["beneficiary", "organization"]
    reference: ExternalReference

class _AdmissionRequestOptional(TypedDict, total=False):
    party: PartyCounts
    manager: ManagerSelection
    partyReferences: list[PartyReference]
    durationMinutes: int
    resource: str
    resourceUnits: int
    additionalAllocations: list[AdditionalAllocationRequest]
    channel: str | None
    duplicateKey: str | None
    windowRevision: int | None
    externalReferences: list[ExternalReference]

class AdmissionRequest(_AdmissionRequestOptional):
    """One admission: the offering, start, and party a hold or booking asks capacity for."""

    offering: str
    start: Instant
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

AttendanceState: TypeAlias = Literal["arrived", "completed", "no-show"]

class RecordAttendanceRequest(TypedDict):
    observedAppointmentRevision: int
    observedRevision: int
    state: AttendanceState
    observedAt: Instant

class AttendanceDocument(TypedDict):
    appointmentId: str
    appointmentRevision: int
    revision: int
    state: AttendanceState
    observedAt: Instant
    recordedAt: Instant

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
OpeningCoverage: TypeAlias = Literal["service-interval", "occupied-interval"]

class ReminderDocument(TypedDict):
    minutesBefore: int

class WindowDocument(TypedDict):
    id: str
    revision: int
    start: Instant
    end: Instant
    units: int

class DurationSelectionDocument(TypedDict):
    minimumMinutes: int
    maximumMinutes: int
    incrementMinutes: int

class _OfferingDocumentOptional(TypedDict, total=False):
    windows: list[WindowDocument]
    pool: str
    durationSelection: DurationSelectionDocument
    openingCoverage: OpeningCoverage
    allowResourceSelection: bool
    partyCounts: Literal["required", "optional"]

class OfferingDocument(_OfferingDocumentOptional):
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

class _ResourceDocumentOptional(TypedDict, total=False):
    capacityUnits: int

class ResourceDocument(_ResourceDocumentOptional):
    resourceId: str
    pool: str
    capabilities: list[str]
    available: bool

class LocationDocument(TypedDict):
    locationId: str
    timezone: str

class _SlotEntryOptional(TypedDict, total=False):
    availableUnits: int

class SlotEntry(_SlotEntryOptional):
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

class _BookingPartyOptional(TypedDict, total=False):
    allocations: list[AllocationDocument]
    party: PartyCounts
    manager: ManagerSelection
    partyReferences: list[PartyReference]

class HoldDocument(_BookingPartyOptional):
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

class _AppointmentDocumentOptional(_BookingPartyOptional, total=False):
    attendance: AttendanceDocument

class AppointmentDocument(_AppointmentDocumentOptional):
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

OperationalTimeBasis: TypeAlias = Literal["displayed", "occupied"]

class _OperationalAppointmentQueryOptional(TypedDict, total=False):
    offering: str
    state: AppointmentState
    resource: str
    externalReference: ExternalReference
    profile: str
    cursor: str
    limit: int

class OperationalAppointmentQuery(_OperationalAppointmentQueryOptional):
    service: str
    location: str
    start: Instant
    end: Instant
    timeBasis: OperationalTimeBasis

class _OperationalAppointmentDocumentOptional(TypedDict, total=False):
    attendance: AttendanceDocument
    allocations: list[OperationalAllocationDocument]
    occupiedStart: Instant
    occupiedEnd: Instant
    resource: str
    units: int
    party: PartyCounts
    externalReferences: list[ExternalReference]

class OperationalAppointmentDocument(_OperationalAppointmentDocumentOptional):
    appointmentId: str
    revision: int
    service: str
    location: str
    offering: str
    state: AppointmentState
    displayedStart: Instant
    displayedEnd: Instant

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
    "configuration", "invalid-request", "transport", "problem", "protocol",
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
    "receipt.unresolved",
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
    "header-bounds", "trace-context", "media-type", "body", "problem", "status", "protocol",
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
    def __init__(self, base_url: str, attempt_timeout_seconds: float | None = None, connect_timeout_seconds: float | None = None, maximum_response_bytes: int | None = None, user_agent: str | None = None, trusted_root_certificates: bytes | None = None, maximum_mutation_retries: int | None = None) -> None: ...
    def get_scheduling(self, token: str) -> Complete[SchedulingServiceDocument]: ...
    def list_services(self, token: str, cursor: str | None = None) -> Complete[PageDocument[ServiceDocument]]: ...
    def list_offerings(self, token: str, cursor: str | None = None) -> Complete[PageDocument[OfferingDocument]]: ...
    def availability(self, token: str, offering: str, *, start: Instant | None = None, end: Instant | None = None, cursor: str | None = None, limit: int | None = None, duration_minutes: int | None = None, resource: str | None = None) -> Complete[PageDocument[AvailabilityEntry]]: ...
    def preview_availability(self, token: str, request: AvailabilityPreviewRequest) -> Complete[AvailabilityPreviewDocument]: ...
    def preview_source_busy(self, token: str, profile: str, request: BusyReconciliationRequest) -> Complete[BusyReconciliationPreview]: ...
    def apply_source_busy(self, token: str, profile: str, request: BusyReconciliationRequest) -> Complete[BusyApplyOutcome]: ...
    def explain(self, token: str, offering: str, start: Instant, *, duration_minutes: int | None = None, resource: str | None = None) -> Complete[ExplainDocument]: ...
    def create_hold(self, token: str, idempotency_key: str, request: AdmissionRequest) -> Complete[HoldDocument]: ...
    def release_hold(self, token: str, hold_id: str) -> Complete[None]: ...
    def create_appointment(self, token: str, idempotency_key: str, request: CreateAppointmentRequest) -> Complete[AppointmentDocument]: ...
    # Observe the original success using the same body/key and current token; never resend or mutate.
    def appointment_receipt(self, token: str, idempotency_key: str, request: CreateAppointmentRequest) -> Complete[AppointmentDocument]: ...
    def get_appointment(self, token: str, appointment_id: str) -> Complete[AppointmentDocument]: ...
    def list_appointments(self, token: str, reference: ExternalReference, *, cursor: str | None = None, limit: int | None = None) -> Complete[PageDocument[AppointmentDocument]]: ...
    def list_operational_appointments(self, token: str, query: OperationalAppointmentQuery) -> Complete[PageDocument[OperationalAppointmentDocument]]: ...
    def reschedule_appointment(self, token: str, appointment_id: str, idempotency_key: str, request: RescheduleAppointmentRequest) -> Complete[AppointmentDocument]: ...
    def cancel_appointment(self, token: str, appointment_id: str, idempotency_key: str, request: CancelAppointmentRequest) -> Complete[AppointmentDocument]: ...
    def record_attendance(self, token: str, appointment_id: str, idempotency_key: str, request: RecordAttendanceRequest) -> Complete[AttendanceDocument]: ...
    def appointment_history(self, token: str, appointment_id: str, cursor: str | None = None) -> Complete[PageDocument[AppointmentHistoryEntryDocument]]: ...
    def list_resources(self, token: str, cursor: str | None = None) -> Complete[PageDocument[ResourceDocument]]: ...
    def list_locations(self, token: str, cursor: str | None = None) -> Complete[PageDocument[LocationDocument]]: ...

PROBLEM_CODES: list[str]
__version__: str

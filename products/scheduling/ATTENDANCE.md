# Attendance observations

Scheduling can retain one current attendance observation for a logical
appointment. The observation is separate from the capacity lifecycle.
Recording `arrived`, `completed`, or `no-show` does not
confirm, cancel, move, release, or consume a hold or appointment, and changing
the booking later does not rewrite the attendance history.

An observation describes the appointment as a whole. It does not identify an
individual participant and is never expanded to one row per party member.
Optional party counts do not decide whether an authorized observation may be
recorded. A resource-only reservation can therefore carry
an explicit appointment-level observation, but Scheduling does not infer a
person, a headcount, equipment return, condition, damage, or any source-system
outcome from it.

## Write authority

Every write requires a current task grant whose exact service and location
permission contains `attendance.record`. Catalogue access, ordinary owner
reads, source-manager appointment detail, operational appointment profiles,
and other commitment actions do not imply this action. The task grant is
checked before the transaction opens and its deadline is checked again at
commit. The source that approved the grant remains independent of the booking
record and any institutional decision that follows from attendance.

The write is:

```http
PUT /v1/appointments/{appointment_id}/attendance
Authorization: Bearer TASK_TOKEN
Idempotency-Key: caller-chosen-key
Content-Type: application/json

{
  "observedAppointmentRevision": 3,
  "observedRevision": 0,
  "state": "arrived",
  "observedAt": "2026-10-23T08:15:00Z"
}
```

`observedAt` is when staff say the attendance fact became effective.
`recordedAt` is when Scheduling made the recording decision after acquiring
the appointment lock. The observation row, history detail, receipt, and
after-event use that same time. It does not claim the exact database commit
instant. An effective time after this decision time is refused. A late or
backfilled observation is permitted, including for a past or cancelled
appointment, because the observation is a corrigible fact rather than a
capacity transition.

`observedAppointmentRevision` must equal the booking revision under the
transaction lock. This prevents a staff client that read an earlier visit
from attaching a no-show or arrival after another caller rescheduled it.
`observedRevision: 0` records the first fact for the current visit. A
correction supplies that visit's exact current attendance revision. Each
accepted correction appends a new revision; a stale concurrent correction is
refused with `revision.mismatch`. A no-show may therefore be corrected to
arrived or completed without changing the appointment revision or state. The
caller supplies an idempotency key: an exact retry returns its original
answer, while reusing the key for changed bytes is refused.

The visit binding is the revision of the latest `confirmed` or `rescheduled`
appointment history event. Cancellation advances the appointment revision but
does not mint a new visit, so it does not hide an observation. A reschedule
does mint a new visit and its exact detail initially has no current attendance.
Rescheduling away and later back still produces a new visit revision, avoiding
accidental revival of the older visit's observation even when its displayed
times happen to match.

The current response keeps the two revision streams explicit:

```json
{
  "appointmentId": "25b91ea4-75ca-48de-b9ef-4326fec81f28",
  "appointmentRevision": 3,
  "revision": 2,
  "state": "completed",
  "observedAt": "2026-10-23T08:45:00Z",
  "recordedAt": "2026-10-23T09:00:00Z"
}
```

The exact appointment detail may include this minimized current document for
the current owner, retained source manager, or exact appointment-detail task
grant. Attendance corrections also appear in the authorized exact appointment
history, using its existing pseudonymized actor envelope. The current detail
does not expose the attendance writer, and neither surface exposes the grant
or task subjects. Operational reads omit attendance unless their selected
profile explicitly projects `attendance`; that projection returns only the
permitted current observation and never the correction history.

## After event

The write appends its correction, idempotency receipt, history entry, and
`appointment.attendance-observed` after-event in the same database
transaction. Existing Scheduling hook delivery signs the event and delivers
it after commit. The event carries appointment identity, booking and
attendance revisions, state, effective time, and recorded time through a
closed projection. It carries no writer, grant, party identity, participant
list, resource condition, or institutional decision.

A Coordinator workflow can follow the event only through its own configured,
authorized trigger. Event admission grants no authority for the workflow's
later product calls, and a receiver response cannot change the appointment or
attendance observation.

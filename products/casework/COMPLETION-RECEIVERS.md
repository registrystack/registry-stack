# Receive completion wakes

A Casework completion wakes your producer so it can read the immutable result
under its own authority. Authenticate and durably enqueue the wake before you
acknowledge it. A wake never authorizes a source mutation.

## Wire and delivery contract

Casework POSTs JSON with exactly these business fields:

```json
{"type":"review.completed","eventId":"11111111-1111-4111-8111-111111111111","requestId":"22222222-2222-4222-8222-222222222222","resultId":"33333333-3333-4333-8333-333333333333","completedAt":"2026-09-19T12:34:56Z"}
```

`Idempotency-Key` is the string form of `eventId`.
`Registry-Recipient-Binding` is the producer's configured recipient binding.
The destination presents either `Authorization: Bearer <secret>` or the
configured named secret header. Compare the expected secret and recipient
before accepting a wake; HTTP framework logs must redact credential headers.
The body contains event/request/result identifiers and a completion time, with
no review decision or source record payload.

Any 2xx response acknowledges delivery. Casework decides from the status and
drops the response without reading its body, including an unfinished stream.
Use an empty 204 for compatibility with releases through 0.43.0, which required
that response. Redirects are not followed.

Delivery is **at-least-once**: after a lost acknowledgement Casework can send
again. The same eventId, payload, recipient binding and idempotency key survive
retries. Receivers must durably deduplicate by eventId before acknowledging;
this does not provide exactly-once delivery or exactly-once business effects.

`attemptTimeoutMilliseconds` defaults to 5000 (100-30000),
`retryDelaySeconds` to 30 (1-86400), and `maximumAttempts` to 12 (1-100).
A failed attempt returns to pending until the configured attempt bound or
retention deadline exhausts it. Exhausted work is terminal for this dispatcher;
recover missed work through the producer's authenticated result feed. The
outbox has one value-free failure diagnostic per settled failed attempt and
one terminal diagnostic at exhaustion. Only destination identifier, attempt
and fixed failure/terminal labels are emitted; URLs, credentials, payloads
and subject identifiers stay absent. A stale lease owner cannot settle or
log another owner's attempt as exhausted.

## Durable receiver examples

Create an adopter-owned inbox in the receiver database:

```sql
CREATE TABLE completion_inbox (
  event_id uuid PRIMARY KEY,
  payload text NOT NULL
);
```

These framework-neutral handlers assume the HTTP adapter has bounded the JSON
body, rejected duplicate members, checked the five fields and UUID/time types,
and normalized header names to lowercase. Pass an operator-resolved secret and
recipient; never use event fields to select credentials or authority.
Return 503 when the database cannot commit. Keep inbox entries until your own
reconciliation is complete and replay policy permits erasure.

Python with a psycopg connection:

```python
import hmac
import json


def receive_completion(headers, event, db, secret, recipient):
    if not hmac.compare_digest(headers.get("authorization", ""), "Bearer " + secret):
        return 401
    if headers.get("registry-recipient-binding") != recipient:
        return 403
    if event["type"] != "review.completed" or headers.get("idempotency-key") != event["eventId"]:
        return 400
    payload = json.dumps(event, sort_keys=True, separators=(",", ":"))
    with db.transaction():
        db.execute("INSERT INTO completion_inbox VALUES (%s,%s) ON CONFLICT DO NOTHING",
                   (event["eventId"], payload))
        stored = db.execute("SELECT payload FROM completion_inbox WHERE event_id=%s",
                            (event["eventId"],)).fetchone()[0]
        if stored != payload:
            return 409
    return 204  # The commit completed before acknowledgement.
```

Node with a `pg` pool (the SQL statement autocommits before its promise resolves):

```javascript
const { timingSafeEqual } = require('node:crypto');

async function receiveCompletion(headers, event, pool, secret, recipient) {
  const got = Buffer.from(headers.authorization ?? '');
  const expected = Buffer.from(`Bearer ${secret}`);
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) return 401;
  if (headers['registry-recipient-binding'] !== recipient) return 403;
  if (event.type !== 'review.completed' || headers['idempotency-key'] !== event.eventId) return 400;
  const payload = JSON.stringify({ type: event.type, eventId: event.eventId,
    requestId: event.requestId, resultId: event.resultId, completedAt: event.completedAt });
  await pool.query('INSERT INTO completion_inbox VALUES ($1,$2) ON CONFLICT DO NOTHING',
    [event.eventId, payload]);
  const stored = await pool.query('SELECT payload FROM completion_inbox WHERE event_id=$1',
    [event.eventId]);
  return stored.rows[0].payload === payload ? 204 : 409;
}
```

A database error must reach your HTTP adapter as a safe 503; do not acknowledge
an uncertain insert. For named-header authentication compare the configured
header's raw value with the secret instead of constructing a bearer value.

A worker reads the persisted inbox and your application's previously accepted
binding. For Python, call
`client.review_result(resource_token, requester_profile, persisted_accepted)`;
Node uses `client.reviewResult(resourceToken, requesterProfile, persistedAccepted)`.
Persisted acceptance has `requestId`, `policy`, `subject` and `submissionDigest`.
Validate that the event belongs to a known accepted request, then let the
maintained client correlate the fetched result to that binding. You may retain
an unmatched authenticated wake until your request acceptance is durably recorded.
Neither the notification's resultId nor an approved result replaces the source's
current authorization, revision guards or transaction checks.

The PostgreSQL regression
`at_least_once_completion_durably_deduplicates_after_lost_ack_and_exhausts_bounded_retries`
drives a real completed review, lost acknowledgement, receiver restart,
stable resend and bounded exhaustion through the dispatcher.

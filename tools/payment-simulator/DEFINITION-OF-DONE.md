# Payment simulator: initial definition of done

Build a useful local development mock, with G2P as its first payment profile.
This delivery scope takes precedence over the broader implementation roadmap
and test catalogue. The HTTP behavior must be trustworthy enough to develop
against; production operations and assurance are outside this delivery.

## Required to finish

1. **Independent local tool.** `uv sync --locked` installs the Python package,
   and a documented command starts it on loopback with an explicit SQLite
   state file. No Rust build, live provider, or external database is needed.
2. **Five working APIs.** Register, update, lookup, batch submission, and batch
   detail implement the G2P profile's request/response shapes and useful errors.
   The generated OpenAPI describes the implemented routes and can be reproduced.
3. **Realistic state.** Exact amounts, immutable accepted instructions and
   destinations, stable pagination, and pending/processing/credited/rejected
   results work. SQLite persists acceptance, replay responses, and simulated
   credits. Exact replay returns the same batch; conflicting reuse is refused.
4. **Three demonstrated scenarios.** Live HTTP tests cover all-success,
   partial failure, and a response lost after acceptance followed by process
   restart and exact replay. The last scenario proves one batch and at most
   one simulated credit per original instruction.
5. **Portable contract assertions.** A test suite accepts a target URL and
   credentials. Its public assertions use HTTP, without importing simulator
   code or reading SQLite. Target-specific setup, process controls, and ledger
   evidence stay in fixture drivers and are reported separately.
6. **Small development boundary.** Synthetic data, loopback default, a simple
   bearer credential from a file, explicit producer/tenant scope, no outbound
   payment calls, and no public reset or fault-control routes. Scenario controls
   are local CLI commands. This does not claim production authentication.
7. **Evidence and handoff.** Focused formatting/lint and Python tests pass;
   the documented quickstart and restart journey are executed; a focused code
   review has no unresolved issue that defeats these criteria. README and
   scope notes match what runs, with omissions stated plainly.

## Deliberately outside this delivery

The P2G increment below shares these exclusions unless explicitly stated.

- Coordinator mutation operations or programme integration. Those live separately in the
  [Coordinator product](../../products/coordinator/README.md#configured-http-operations);
  they do not add runtime imports or payment-specific behavior to this simulator.
- Real payment rails or a real-provider compatibility claim.
- Callback delivery, receiver credentials, and the callback test matrix.
  Callback URL fields remain accepted for wire compatibility; polling is used.
- Production identity providers, signatures, audit systems, high availability,
  performance targets, disaster recovery, and exhaustive crash injection.
- Receipt pruning, retention administration, and general schema migration
  tooling. Initialize a versioned local database automatically; apply the
  single additive P2G v1-to-v2 upgrade and refuse other unsupported versions
  without deleting state.
- Container/release publishing and new CI machinery. Local locked commands
  are sufficient for this iteration.

Keep the implementation small: ordinary Python modules, SQLite transactions,
one process, and targeted tests. Add machinery only to satisfy a required
behavior or resolve a demonstrated defect. Do not weaken replay or correlation
semantics to make a test pass.

## P2G collections increment

Add only `POST /rtpRequest` and `GET /transferRequests/{transferRequestId}`
from the reviewed [P2G profile](P2G-SPEC.md), preserving the original five G2P
operations. The increment is complete when:

- The spec identifies upstream mislinks, the synchronous polling adaptation,
  and the distinction between RTP completion and confirmed payment.
- Paid, failed and expired fixtures work, with `COM/PENDING` visible before
  confirmed `COM/PAID` and a payment reference present only for the paid case.
- Exact amounts, accepted intent, command receipts and payment references
  survive replay and restart. Current biller authority precedes disclosure.
- Live HTTP tests reuse the target harness and prove recovery after a lost
  acknowledgement; a local witness counts one payment for the accepted request.
- The additive SQLite v1-to-v2 upgrade preserves existing G2P receipts/credits.
- Generated OpenAPI, focused tests, a runnable collection example and a bounded
  review agree with the implementation.

Programme funding, real checkout, bank notification ingress, callbacks,
refunds, cancellation, reissue and a real-time expiry scheduler remain outside
this increment. No new dependency or general migration framework is needed.

## Completion evidence

Record the exact commands and results in the final handoff. Distinguish public
HTTP behavior, local ledger/restart evidence, and unverified provider behavior.
Finish when the seven criteria above are met. If an external prerequisite
blocks progress, retain the implementation and report the failing command,
what remains unverified, and what would unblock it.

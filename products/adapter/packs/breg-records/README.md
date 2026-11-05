# BReg Records Adapter pack

This maintained pack maps one configured Base Registry Engine Record type to
the Adapter's generic exact-read and direct-write contracts. A project supplies
the BReg route segment and one access profile. The deployment supplies a
dedicated BReg bearer credential.

Create and conditional Update each use one native `:batch` POST. BReg assigns
the UUID, applies `ifMatch` atomically inside its Record transaction, and holds
the exact keyed response for its configured receipt-retention window. The pack
declares seven days because that is BReg's default; a deployment that lowers
`retention.receiptRetentionDays` cannot use this pack unchanged.

The companion GET and batch result must run as the same BReg principal, access
profile, and readable-field projection. The GET response ETag becomes the
source-item revision, while the batch result's `etag` becomes the write receipt
validator. The real-process Adapter test checks that BReg returns the same
native validator through both paths.

Pending-write recovery must also retain the same BReg origin, access profile,
provider idempotency namespace, and source principal. Rotating a credential is
safe only when BReg still recognizes the same principal and key namespace.
Before changing a binding to another principal, an operator must finish or
reconcile every pending write; the Adapter cannot prove principal continuity
from secret-reference strings.

The Update mapper converts a flat JSON Merge Patch object to BReg JSON Patch:
non-null members use `add` and null members use `remove`. The facade refuses
a member whose value is an object with 422 before this mapper runs, so a
widened input schema cannot turn a nested change into a whole-member
replacement. An array value replaces the whole member, as RFC 7396 specifies.

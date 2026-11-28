# Registry Stack TypeScript clients

Use these clients from Node 24, Deno, browsers, or edge functions with Fetch
and WebCrypto. The source modules use erasable TypeScript and have no runtime
dependencies. The package and source generator require Node 24 or later. The browser build emits standard ES modules and declarations in
`dist/`.

## Call a product

One generated file per service holds the two entry points. A service is one Base
Registry Engine (BReg) register and the products installed beside it. The
examples in `generated/services/` are a facility register with Documents,
Casework and Evidence, and one with every product.

In a page, call `createRegistryClient`. It takes no token. The page's session
part signs each call:

```ts
import { createRegistryClient } from './generated/services/breg-facility-documents-casework-evidence.ts'

const registry = createRegistryClient({ baseUrl: '/registry' })

const answer = await registry.list('facility', { accessProfile: 'facility-reader', top: 25 })
console.log(answer.items)
await registry.casework.call('describeCasework')
```

In a function, a script or a back end, call `createRegistryServerClient`. It
requires a token:

```ts
import { createRegistryServerClient } from './generated/services/breg-facility-documents-casework-evidence.ts'

const registry = createRegistryServerClient({
  baseUrl: 'https://registry.example.org',
  token: () => session.currentAccessToken(),
  timeoutMs: 10_000,
})
```

The object has the register's methods at the top level and each installed
product's typed operation client at `registry.<product>`, such as
`registry.casework.call(...)`. Every module of one service shares one transport,
so they share one base URL, one token call per request, and the same deadlines.
A product module exports its `Client` class and types, and no factory. A
`Client` is built from a `Transport`.

Both entry points accept `profile` as a default for routes with an
`accessProfile` query parameter. An explicit `accessProfile` on a call takes
precedence. Routes without that parameter receive no default. A route whose
`accessProfile` parameter is required, whether called with `call()`, `invoke`,
`targetConditions`, `list` or `read`, refuses with a `TypeError` before anything
is sent when neither the call nor the client names a profile. See
[the service tests](tests/service.test.ts).

The server entry refuses to construct where `globalThis.document` exists, with a
`TypeError`. The page entry refuses a `token` member with a `TypeError`, and
keeps Coordinator, Messaging and OID4VCI server-only, in the type and at run time.

`createRegistryClient` and `createRegistryServerClient` have no audience
parameter yet.

Task helpers attach at one marked place, the `withTaskHelpers` function in the
generated file. They are `proposalCommands` and `documentCommands`, and the
comment there shows the two lines that attach them. The service description
takes an optional `authorProfile` for the proposals helper. Until they exist `registry.documents` is the Document Store's
typed operation client, and `registry.proposals` is absent.

## Create a credential offer

Install `evidence-oid4vci` in your service description to get `registry.oid4vci`
in the server entry. The example with every product includes it.
Configure the server token function with a bearer credential authorized to
create offers.

```ts
import { createRegistryServerClient } from './generated/services/breg-facility-all-products.ts'

const registry = createRegistryServerClient({
  baseUrl: 'https://registry.example.org',
  token: () => offerBearer(),
})
const { data } = await registry.oid4vci.call('createCredentialOffer', {
  body: { credentialConfigurationId: 'licence', subjects: [{ role: 'holder' }] },
})
const offerUri = data.credentialOfferUri
```

The module also types `createDraft13CredentialOffer`, `health` and `readiness`.
Wallet exchanges and discovery metadata use the OID4VCI protocol directly.

## Generate a service

```sh
node generate-service.ts --register breg-facility --products documents,casework,evidence \
  generated/services/my-service.ts
```

The register is a BReg module in `generated/`. The products are any subset of
`casework`, `coordinator`, `documents`, `evidence`, `evidence-oid4vci`, `messaging` and `scheduling`.
Pass `--check` to compare the output with the file on disk. `npm run generate`
rewrites every committed example, and `npm run check:generated` fails when one
drifts.

Successful calls return an object
with `data`, HTTP `status` and `headers`, and the request's `idempotencyKey`
when applicable. Supported representations are typed through `accept` where
the operation declares a response media type. Empty success has
`data: undefined`. Declared binary responses have `data.bytes` and
`data.mediaType`. A declared 304 has `status: 304` and `data: undefined`. JSON responses
tolerate fields added by newer servers while checking the declared members.
The TypeScript types expose the declared fields. JSON integers outside
−9,007,199,254,740,991 to 9,007,199,254,740,991 are rejected on decode.
Compact Evidence credentials have `data.text` and
`data.mediaType`. Verify signed Evidence against your relying-party trust
policy before using its assertion.

Use HTTPS for a remote registry. HTTP is accepted for `localhost`, IPv4
loopback, and IPv6 loopback. `localhost` resolves through the operating system.
With `allowInsecureHttp: true`, HTTP is also accepted for a host that cannot be
on the public internet. That is a private or link-local IP address in
`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `fc00::/7` or
`fe80::/10`. It is also a host name without a dot, such as a container name on
a compose network. HTTP to any other host is refused when the client is built,
before any token is asked for, with or without the option.
Supply a base without credentials, query, fragment, or `.` and `..` segments
(plain or percent-encoded). A path prefix is preserved. In a browser the base
can be a path such as `/registry`. It resolves against
`globalThis.location.origin` and then follows the same rule. Where there is no
page origin, a path is refused. A refused base throws
`TypeError('Invalid registry base URL')`. The server entry's token function runs on each call. It may return a
string or a promise of one. Fetch omits ambient credentials. Every call handles redirects manually. Every
call, including page methods, Actions and byte transfers, accepts an
`AbortSignal` in `signal`. For a JSON or text call, the 10-second default
deadline covers the exchange including token acquisition and reading the
response. The default response cap is 8 MiB and can be set with
`maxResponseBytes` on the client or on one call.

## Byte transfers

A byte transfer is an operation whose request body is not JSON or form fields,
such as a document upload. An operation whose success answer is read as bytes,
such as a download, is one too.

- An upload body is a `Uint8Array`, a string, or a `Blob` such as a `File` from
  a file input. A `Blob` is sent as given.
- `timeoutMs` is an idle deadline. It restarts when the answer's headers arrive
  and each time a chunk of the body arrives. A slow download that keeps moving
  finishes, and one that stops fails with reason `timeout`.
- While an upload is sent, the deadline is `timeoutMs` plus one second for
  each 16 KiB of body. That allows an upload rate as low as 128 kbit/s.
- Pass `onProgress(loaded, total)` to track bytes. In page mode, an upload
  with this callback uses `XMLHttpRequest` when available. It reports upload
  events and uses `timeoutMs` again once the upload finishes. This path uses
  `XMLHttpRequest`, not a `fetch` you supply in the client's options. Fetch
  uploads report the full size once response headers arrive.
- Fetch uses manual redirects. `XMLHttpRequest` can follow redirects, so the
  client refuses an answer whose final URL differs from the request URL. A
  redirected write has an unknown outcome. On a 307 or 308 from the page's own
  origin, the body, `Registry-Client` and `Idempotency-Key` may already have
  reached the redirect target before the client can refuse. Cookies do not. Keep
  the page's own origin from redirecting a registry route.
- Downloads report bytes as they arrive. The total comes from a plausible
  `Content-Length` when available and is otherwise `undefined`.
- Progress callbacks must not throw. The client logs a fixed message once
  per call if a callback throws, and the transfer continues.
- Set a per-call `maxResponseBytes` to bound a transfer answer, for example
  `{ maxResponseBytes: 50 * 1024 * 1024 }`. Larger answers fail with
  `too-large`. Page-mode 401 and 503 answers are read up to the client's cap, or
  the call's cap if that is larger.

See [the transfer tests](tests/transfer.test.ts) for the transport behaviour.

## Page mode

A page whose session part signs its calls uses `createRegistryClient`, which takes no token:

```ts
const registry = createRegistryClient({ baseUrl: '/registry' })
```

Page mode works only on the page's own origin. The page calls its own origin's
session part, which forwards the call to the registry with the bearer token. No
registry answers a cross-origin page call, and the browser refuses one. A page
client whose base is an absolute URL on another origin refuses the call with a
`TypeError` before anything is sent. The page's own origin must not redirect a
registry route to another place. A redirect would carry the request, its body and
its `Idempotency-Key` along with it. The client refuses a redirected answer, and a
request's idempotency key makes a replay to the same URL harmless.

- The client sends no `Authorization` header.
- Fetch sends cookies with `credentials: 'same-origin'`, so they go to the
  page's own origin only. The server entry sends `'omit'`.
- The page client sends `Registry-Client: page` on every call. The session part
  requires it on every route. The exported `registryClientHeader` constant holds
  the name and value, and a header of that name in a call's options is
  replaced. The server entry does not send it.
- A 401 is the session service's own answer when it carries all three of the
  header `Registry-Session-Answer: 1`, an `application/problem+json` body with
  `code: 'session.expired'` and `status: 401`, and the body's `type`
  `https://id.registrystack.org/problems/registry-platform/session/expired`.
  It reports `sign-in-expired`. Keep the person's unsent values and offer to
  sign in again. The gateway removes the header from every product answer, so a
  product answer that carries the code alone is a product answer.
- Other 401 answers report `configuration` or a body size error. Keep the
  person's unsent values and route a configuration refusal to the service
  operator using the module named in `error.message` and `error.product`. The
  sentence a person reads names no module.
- A 503 is the session service's own answer when it carries the same header, an
  `application/problem+json` body with `code: 'session.unavailable'` and
  `status: 503`, and the `type`
  `https://id.registrystack.org/problems/registry-platform/session/unavailable`.
  It reports `unreachable`. The session part forwarded nothing, so you can offer
  a retry. Any other 503 is a product failure, and a write it answers has an
  unknown outcome.
- A page 401 or 503 is read up to the client's `maxResponseBytes` even when a
  call sets a smaller cap, so a small cap does not hide an expiry.
- These session and configuration failures have `outcomeUnknown: false`.
  A bare 403 still means the person is not allowed.

- In a page and on a server a 412 has `reason: 'stale'`. Reload and try again. The Base
  Registry Engine (BReg) also answers a refused guard with 412, so it is
  `stale` too, and `describeError` still shows that guard's label.

Operations authenticated by a signature never send cookies. See
[the page-mode tests](tests/page.test.ts) for these answers.

## Errors and writes

`describeError(error)` always shows a fixed sentence and never repeats the
response detail. An error the client raised itself with a `client.` code shows
that code's sentence from `clientSentences`, the one table a programme replaces
through `describeError(error, { clientSentences })`, or a generic sentence for
a code the table lacks. Its `detail` stays on the error for developers. A
`client.` code that arrived in an answer is a product failure and gets the
usual sentence. When `outcomeUnknown` is true, the sentence asks you to check whether
the change was made before trying again. For a refused BReg guard, pass the labels your project declares
for its guards, keyed by `guardReason`, as
`describeError(error, { guardLabels })`. The sentence is then that label, and
otherwise a fixed sentence. The OpenAPI document does not carry guard labels.
Read `traceId` from the error.

`RegistryError.kind` distinguishes a validated product refusal, an unreachable
exchange, and an unexpected response. `reason` adds a value-free classification
such as `token`, `timeout`, `media`, `schema`, or `unsafe-integer`. Inspect the
HTTP status and the validated, correlated `problem`, `code`, `detail`, or
`traceId` when available. The explicit, non-enumerable `raw` accessor returns
a copy of a complete response body within the cap. It can contain reflected
request data. Messaging exposes `retryAfterSeconds` only for a validated 429
with a single delta-seconds value from 1 through 86,400. Calls make one
exchange.

Operations declaring `Idempotency-Key` send your `idempotencyKey` or a generated
UUID. The receipt lookups, Messaging `readMessageReceipt` and Scheduling
`readAppointmentReceipt`, are the only calls that require the original key.
The generator lists them by contract and route, and stops when a keyed
operation that looks like a read is not listed. Other operations send no
idempotency header. The answer
and error include the key the call used or would have sent. `outcomeUnknown`
marks a dispatched mutation whose outcome could not be established, including
a transport failure, 5xx, or unreadable success. Failures before dispatch and
4xx responses leave it false.

A call that cannot be built throws `TypeError` before anything is sent. Examples
are a missing path value, an undeclared media type, or a receipt lookup without
its key. Every other failure is a `RegistryError`.

Operations that a Standard Webhooks signature authenticates, such as
Coordinator `admitEvent` and the `receiveReviewCompletion` routes, take the
exact signed body as a `Uint8Array` and send those bytes unchanged. The client
asks for no token and sends no bearer credential on them.

Persist the original body, target, profile, preconditions and key for BReg
replay. An exact replay returns the retained receipt. A changed request under
the same key receives 409 `idempotency.key-reused`. Use a new key if you
recompute the input and start a new write. Scheduling and Messaging receipt
lookups require the original key and request.

For unkeyed operations, use the route's recovery behavior.

- Coordinator `retrySame` schedules a held step with the same command. Read the
  run before resubmitting an uncertain scheduling request. For a parked review
  wait, repeating `cancelRun` preserves authored cleanup. Read run status to
  see whether cancellation was recorded. Cancellation never reverses an
  accepted product effect.
- Document Store erasure is repeat-safe and retains the original due time.
- Scheduling source-busy reconciliation can repeat the original body and
  expected revision. A later conflict leaves the earlier outcome unresolved.
  Hold release uses the hold ID as its server-side replay key.

## Pagination and BReg Actions

```ts
import { allPages } from './core.ts'

const contacts = await allPages(cursor => client.records_contact_listPage({
  query: { accessProfile: 'directory-editor', $top: 25 },
}, cursor))
```

Page methods are generated only for read operations. They normalise product
responses to `Page<T> { items, nextCursor }`. Use `pages(load, cap)` to iterate or
`allPages(load, cap)` to collect the items. Both default to 100 pages
and throw `RangeError` if a cursor repeats or a continuation remains at the
cap. A null or empty cursor ends iteration. Cursor values are opaque. BReg Record list follow-up requests carry only the
selected access profile and `$skiptoken` on the same route. The first
request carries filters and page size. Other cursor routes retain their
query options.

`pages` returns an iterator you can step with `next()`. A page that fails to
load rejects that call and leaves the walk where it was, so the next call loads
the same cursor again. A failed load does not count toward the cap. A "Next"
control can keep one walk and retry after a failure. `pages` never retries by
itself, so each attempt is one the caller asked for. The `load` function you
pass must only read a page, because a retry runs it again.

```ts
const walk = pages(cursor => client.records_contact_listPage({}, cursor))
const first = await walk.next()
```

Use `list(recordType, options)` for the register's top-level list of a record
type. The query profiles published for the route determine the options.

```ts
const page = await client.list('licence', {
  accessProfile: 'licence-officer',
  where: { status: ['active', 'suspended'], holderName: { startsWith: 'Dep' } },
  orderBy: 'expiresOn',
  top: 20,
  count: true,
})
if (page.nextCursor !== null) {
  const next = await client.list('licence', { accessProfile: 'licence-officer', after: page.nextCursor })
}
```

- `where` keys are the profile's filterable properties. A value is an
  equality (`'active'`), a list for `in`, `{ startsWith }`, `{ contains }`,
  `{ isNull }`, or a range with `gt`, `ge`, `lt` and `le`. Each form needs the
  matching operator in the profile. All filters hold together.
- `orderBy` is one sortable property, or `'property desc'` where allowed.
  `select` lists selectable properties. `count` is allowed only with
  `allowCount`. `top` runs from 1 to the profile's `maximumPageSize`.
- A list with several query profiles or a route that requires a profile needs
  either the service default or an explicit `accessProfile`. The explicit
  profile takes precedence. The client checks filters against the resolved profile.
- A profile with `requiredFilters` lists only when `where` holds an equality
  filter on every property of one alternative. An `in` list does not count.
- The types enforce these rules, and the client checks them again before it
  sends anything. A refusal is a `TypeError` naming the property and profile,
  never a filter value.
- The answer is `{ items, nextCursor }`, plus `count` when the answer carries
  it. A null cursor ends the list. With `after`, keep the same access profile.
  If the first page used the default, omit `accessProfile` again. If it named
  a profile, repeat that profile.
  The client refuses `where`, `orderBy`, `select` and `count` alongside `after`.
  The continuation sends only the access profile and the cursor.
- Sub-collection lists use `call` by operation ID or their generated page method.

Each item is `{ id, revision, data }`. The fields come from the record's
`recordIdentifier`, `revisionIdentifier` and `domainData`. Pass the row ID to
`read` to load the detail page in the same shape.

```ts
const row = await registry.read('facility', id, { accessProfile: 'facility-reader' })
console.log(row.data.name)
```

The type of `data` describes the record's declared fields. A profile or
selection can return only a subset. A read that takes a profile uses the
service default unless the call names its own. If the route requires a profile
and neither is set, the client refuses before sending. A valid 404 problem
remains a refusal.

`invoke` takes Actions that apply at once. Use `call` with the start operation
ID to start a reviewed Action. If an untyped caller passes a reviewed Action
to `invoke`, it gets a fixed message pointing to proposals before dispatch.

```ts
const input = { contactId, email: 'alice@example.org' }
const preconditions = await client.targetConditions('update-contact-email', {
  contactId: input.contactId,
})
const receipt = await client.invoke('update-contact-email', input, { preconditions })
```

Action IDs, input members, access profiles, and Record fields come from the
project contract. Use target condition inputs for the named Action and the same
target in the invocation. Each returned condition carries that target's
`ifMatch`. The `invoke` signature requires conditions for Actions that declare
them and disallows them for Actions with no required conditions. `invoke` never
reads target conditions by itself. The `ifMatch` it sends is the one the person
saw, so a change made since then is refused rather than overwritten.

An Action with an availability route is a typed call. Its answer reports
`available`, `observedRevision`, an optional `guardReason` with its optional
`guardLabel`, and `missingInputs` as the document declares them.

```ts
const { data } = await client.call('actions.register-facility.availability', {
  body: { input: { operatorId }, targetInput: 'operatorId' },
})
```

Each BReg module exports `actionInputs`, keyed by Action ID. It is empty for a
project without Actions that declare inputs. An entry holds the
Action's `display`, `inputMode`, and `inputs` exactly as the OpenAPI document's
`x-registry-action` declares them, so a form can be built from it.

## Verify a delivery

```ts
import { verifyDelivery } from './webhook.ts'

const event = await verifyDelivery(rawHeaderPairs, rawBodyBytes, {
  currentKey,
  previousKey,
  eventIdMember: 'id',
})
```

Pass the original bytes and the original header pairs, preserving duplicate
header instances. Capture the pairs before an HTTP framework combines repeated
fields. The pairs must hold exactly one each of `webhook-id`,
`webhook-timestamp`, `webhook-signature`, and `content-type`, and the content
type must be exactly `application/json`. A body over 1 MiB (1,048,576 bytes,
the bound every Registry Stack verifier shares) is refused with
`body-too-large`. Keys are 32 to 64 exact bytes and may not start with `whsec_`.
The signature header accepts up to four entries. The verifier checks the
Standard Webhooks `v1` HMAC through WebCrypto and a five-minute timestamp
window. Rotation accepts a signature under either key.

Registry Stack additionally restricts `webhook-id` to 1–256 visible ASCII
characters without a period and binds it to the signed JSON member. The
default member is `id`. Use `eventIdMember: 'eventId'` for review completions
or `eventIdMember: null` when only the signature, timestamp, and JSON object
are required. Use `DeliveryError.code` to distinguish failures. Keep keys in
trusted execution environments. Replay tracking belongs to the receiving
application.

## Receive a delivery in a function

`verifyRequest` takes the incoming `Request` and the key. It checks the headers
and the content type first, so a refused delivery is never read. It then reads
the body stream once, up to 1 MiB, so the function does not clone the request.
A body that cannot be read is refused with `invalid-body` and nothing from the
read error. This Deno function runs the same way on Supabase Edge Functions.

```ts
import { DeliveryError, verifyRequest } from './webhook.ts'

const keyText = Deno.env.get('REGISTRY_WEBHOOK_KEY')
const currentKey = new TextEncoder().encode(keyText ?? '')
if (currentKey.length < 32 || currentKey.length > 64) {
  throw new Error('Set REGISTRY_WEBHOOK_KEY to the 32 to 64 byte delivery key.')
}

Deno.serve(async request => {
  let event: Record<string, unknown>
  try {
    event = await verifyRequest(request, { currentKey })
  } catch (error) {
    if (error instanceof DeliveryError) return new Response(null, { status: 400 })
    throw error
  }
  // Do the work only here, after verification. Log the delivery ID and event type, nothing else.
  console.log('verified delivery', request.headers.get('webhook-id'), event.type)
  return new Response(null, { status: 204 })
})
```

How it behaves:

- The key is the secret's bytes exactly as the sending product reads them from
  its file. A key written as 43 base64url characters is used as those 43
  characters' bytes. It is not decoded.
- The function stops at startup when the key is unset or outside 32 to 64
  bytes. A 64-character key with a trailing newline is 65 bytes, so it stops
  there too. The sending product refuses that key file at startup as well.
- The signature covers the webhook ID, the timestamp and the body. It does not
  cover the URL.
- A delivery more than 300 seconds from the function's clock is refused.
- A `webhook-signature` header sent twice is refused.
- Deliveries can repeat. Store `webhook-id` with a digest of the body before
  acting, and refuse a different body under a stored ID. See the Duplicates
  section of the delivery signing reference.
- The default `eventIdMember` is `id`. Pass `eventIdMember: null` or
  `'eventId'` as described above.

## Generate, build, and test

From the repository root:

```sh
npm --prefix clients/typescript ci
npm --prefix clients/typescript run generate
npm --prefix clients/typescript run check:generated
npm --prefix clients/typescript run check:types
npm --prefix clients/typescript test
npm --prefix clients/typescript run test:deno
npm --prefix clients/typescript run build
```

`test` runs the Node tests. `test:deno` runs the transport and delivery tests
under Deno and needs Deno installed.

Use Node 24 to generate a module from the OpenAPI document produced by
`bregctl` for your own project. The generated module imports the shared runtime
using paths relative to its output location.

```sh
node clients/typescript/generate.ts --breg \
  /path/to/project/generated/openapi.json clients/typescript/generated/my-registry.ts
```

Pass `--check` to verify a single output without writing it. Unsupported schema
constructs report a JSON pointer. For a deliberately unconstrained schema in
your own project, review the pointed schema and pass
`--allow-unconstrained=/pointer` for that exact site. The output records the
source SHA-256 and the sites mapped to `JsonValue`.

The included clients cover Casework, Coordinator, Document Store, Evidence,
Messaging, Scheduling, and the two BReg examples. OID4VCI and OID4VP use
wallet-specific authorization, protocol exchanges, and credential lifecycles
that call for dedicated wallet clients.

For a browser smoke test, serve the built package directory on loopback over HTTP and open
`browser-test.html`. The page uses a fake transport and reports its result in
the page.

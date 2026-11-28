# Task helpers: Proposals and files

Two helpers sit on the generated clients. The generated service file attaches them, so a page reads
`registry.proposals` (under the service's `authorProfile`) and `registry.documents` (when the Document
Store is installed). They take the generated client for the module and
add no transport of their own: deadlines, caps, page mode and errors are the core's.

```ts
import { documentCommands, proposalCommands } from './tasks/index.ts'

const proposals = proposalCommands(bregClient, { accessProfile: 'licence-applicant', clientSentences })
const documents = documentCommands(documentsClient)
```

Every failure throws a `RegistryError`. A refusal the helper makes before sending carries a
`problem.code` that starts with `client.` and a `problem.detail` in plain English. The detail is
for developers and may name served values, such as a policy, a slot or a link operation. It never
reaches the screen. `describeError(error)` shows the fixed sentence for that code from
`clientSentences` in `core.ts`, the one table a programme replaces with its own words through
`describeError(error, { clientSentences })`. A code the table lacks gets a generic sentence, which a
programme replaces under the key `client.fallback`. A `client.` code that arrived from the register is
not one of these and gets the usual sentence. When a step is refused because the register no longer
offers it (`client.command-unavailable`), the sentence is the one for the served reason, such as
`package-changed`, because the person has a next step. A call the generated client cannot build is a
configuration refusal (`client.unknown-operation`) in both helpers.

## Proposals

A Proposal is plain data. It survives `structuredClone` and a JSON round trip. Commands are on
`proposals` and take the Proposal.

```ts
let p = await proposals.start('apply-for-licence', input)
p = await proposals.edit(p, { phone })                  // merges into the answers already given
p = await proposals.edit(p, { secondPhone: undefined }) // undefined removes an answer
p = await proposals.attach(p, 'diploma', file, { onProgress, signal })
p = await proposals.submit(p)

p.status              // draft, awaiting-party, in-review, approved, processing, applied, rejected, cancelled
p.sentBack            // submitted and the review asked for changes
p.decision?.publicReason
p.attachments.diploma // { status, required, mediaType, size, canUpload, canDownload, accepts }
p.can.submit          // { available, reason, recovery, message } for every command
p.application?.resultLinks // the records an applied Proposal changed

p = await proposals.resubmit(p, { changes: { phone }, files: { diploma: newFile }, signal })
p = await proposals.rebase(p)   // the form changed: update, then submit
p = await proposals.cancel(p)
const blob = await proposals.download(p, 'diploma')
const { items, nextCursor } = await proposals.list({ owner: 'caller' }) // the caller's own
const { items: waiting } = await proposals.list({ turn: 'party' })    // waiting on the person
const fromTypedCall = proposalFromServed(answer.data)
```

- **Commands follow the served links.** The link gives the operation, the access profile and the
  `If-Match` value. A link that is missing or unavailable is refused before sending, with the
  register's reason. A link whose `operation` does not match its name is refused, so a served
  document cannot steer a command.
- **Which copy a command acts on.** The Proposal the page passes, unless this helper's own last
  write produced a newer revision of it. A background `get` or `list` never changes which answers
  a command sends. A second tab gets a `stale` refusal and the page reads the Proposal again.
- **`status`.** The register's value is used when it serves one. Until then the helper derives it
  from `state`, `turn`, `decision` and `applicationStatus`, following the register's status rule.
  The values are not screen text: a programme maps them to its own words.
- **Offering "correct and send again".** Show the control when `p.can.resubmit.available` is true:
  that is the register's answer. `p.sentBack` and `p.decision?.publicReason` say why, for the
  wording. Pass `files` only for the slots that get a new file.
- **`can` is total** over edit, attach, submit, resubmit, rebase and cancel. A command the
  register did not offer reads `{ available: false, reason: 'not-offered' }`. The sentences live in
  `availabilityMessages`, written for applicant and staff pages alike. It is the `can.*` part of
  the one words table in `core.ts` (`clientSentences`), re-exported here, together with `available`
  and `unavailable` for a step with no reason of its own. `message` is chosen when the Proposal is
  made, so a programme that replaces the table passes the same `clientSentences` to `proposalCommands`
  (and to `proposalFromServed` for a document it holds) and to `describeError`. Both then speak in
  the programme's words. The generated file attaches `proposals` with the default table, so a programme
  that replaces the table builds `proposalCommands(registry, { accessProfile, clientSentences })` itself.
- **`edit` and `rebase` merge** the changes into the answers the caller can read, and an
  `undefined` member removes an answer. They refuse before sending when the caller cannot read the
  inputs. Known limit until the product's configuration check lands: the register serves only the
  inputs the caller's profile may read, so a merge would clear an input the caller may write but
  not read.
- **`resubmit`** is one call for "correct and send again": revise, attach, edit, submit. It is
  available only while the Proposal waits on the person (submitted, turn `party`), so it never
  withdraws a pending review or discards an approval. Called again after a failure, it continues
  only from the register's next version, and only when that version carries this call's own
  changes and, for each given file, either that file or the one the page's copy held. Anything else is refused with `client.stale-copy`, and the page reloads.
- **After a Revise lands** the Proposal is a draft again: `decision` and `sentBack` are gone. Keep
  the reviewer's reason in the page if the screen still needs it.
- **`rebase`** is available only when the Proposal needs it: the Action's package changed, or a
  manual Apply was refused and the answers must be corrected. It leaves a draft. The page then
  calls `submit`.
- **`attach` checks first.** An unknown slot, a type the slot does not list exactly, or a file
  larger than the slot allows is refused before any bytes go.
- **A retry replays.** Each command's idempotency key is derived from the command, the Proposal,
  its `If-Match` value and the body, so the same command on the same copy sends the same key,
  after a reload and in a second tab. `start` sends a random key, or the one passed in
  `idempotencyKey`. After a failure whose outcome is unknown, calling `start` again with the same
  input reuses the key, so a draft is not created twice.
- **Writes on one Proposal run one at a time.** Two quick clicks do not fail as stale.
- **After a command the helper reads the Proposal again,** because a command's answer omits the
  decision and the input. If the write landed and that read fails, the error is
  `client.read-after-write` with the Proposal id and the write's key, and the next queued write
  reads the Proposal first.
- **`download`** is capped at the slot's maximum size and checked against the stored size and
  digest. The Blob is typed with the served type only for PDF, PNG and JPEG, and as plain binary
  otherwise.

Known limits until the register changes:

- **Downloads of a Proposal attachment fail today** with `unexpected`/`media` for any file not
  served as plain binary: BReg's API description declares only `application/octet-stream` for
  that route, and the register answers with the stored type. The fix is in BReg, and a test pins
  today's failure so it flips when the fix lands.
- **Submit with an empty required slot reads as `stale` today.** The register answers a bare 412
  and keeps offering Submit. The register is adding the link reason `attachment-required` (which
  the helper shows in `can.submit` once the client is regenerated from the register's updated API
  description) and the code `attachment.required`. Until then a page can
  check `p.attachments` (`required` and `status === 'empty'`) before offering Submit.
- **Register refusals on Proposal commands carry no code yet.** BReg's API description declares no
  problem body on the lifecycle routes, so a refusal reaches the page without `code`, `detail` or
  the field it names. The fix is in BReg.

## Files in the Document Store

```ts
const doc = await documents.upload(file, { policy: 'named-share', label: 'Diploma', onProgress, signal })
await documents.waitUntilReady(doc.id, { timeoutMs: 60_000 })
const blob = await documents.download(doc.id)
saveBlob(blob, 'diploma.pdf')
const grant = await documents.share(doc.id, { with: officeSubject })
const { items: shares } = await documents.shares(doc.id)
await documents.revoke(shares[0].id)
await documents.requestErasure(doc.id)
const { items: sharedWithMe } = await documents.received()
await documents.call('listDocumentPolicies')   // every other operation stays reachable
```

- **`upload`** checks the policy's types and size before sending, computes the digest, reserves
  the document and sends the bytes. Only the upload id is taken from the reserved upload path: the
  bytes and the token never go to a host or path from the answer. A person may leave out the
  custodian: the Document Store then holds the document for the person.
- **Keys.** `upload` and `share` use one key per request, or the one passed in `idempotencyKey`.
  After a failure whose outcome is unknown, the same request again reuses the key, so a
  reservation or a grant is not made twice. After a success, or a definite refusal, the next call
  is a new intent with a new key: sharing again after a revoke issues a new grant. A key that has
  expired is never reused.
- **`waitUntilReady`** polls until the version is `ready`, within one time budget that also bounds
  a read in progress. A rejected, suspended or erased version throws at once. A passing network
  failure or server error is retried until the budget ends. Polling is never faster than every 250 ms.
- **`download`** needs a `ready` version, is capped at its length and checked against its digest.
  A rejected, suspended, erasure-pending or erased version is refused with the same code as
  `waitUntilReady` (`client.document-<status>`), because it will never be ready. The Blob type
  follows the same safe list as Proposal downloads.
- **`saveBlob`** saves a Blob through a download link. It never opens the file in the page.

## Progress

`attach`, `resubmit` (its files), Proposal `download`, and document `upload` and `download`
accept `onProgress(loaded, total)` and pass it to the core's byte transfer, which reports the
bytes moved. The client README says how a page upload and a fetch upload report.

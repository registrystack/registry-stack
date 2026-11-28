import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { RegistryError, Transport, clientFallbackSentence, clientSentences, describeError } from '../core.ts'
import { Client as Facility } from '../generated/breg-facility.ts'
import { Client as Minimal } from '../generated/breg-minimal.ts'
import { availabilityMessages, proposalCommands, proposalFromServed, proposalStatus, type JsonObject, type Proposal, type ProposalCallValues, type ServedProposal } from '../tasks/proposals.ts'

const baseUrl = 'https://registry.example.org'
const accessProfile = 'facility-correction-author'
const fixture = (name: string): ServedProposal =>
  JSON.parse(readFileSync(new URL(`./fixtures/tasks/${name}.json`, import.meta.url), 'utf8'))
const pdf = (size = 4) => new Blob([new Uint8Array(size).fill(37)], { type: 'application/pdf' })
const hex = async (blob: Blob) =>
  [...new Uint8Array(await crypto.subtle.digest('SHA-256', await blob.arrayBuffer()))].map(b => b.toString(16).padStart(2, '0')).join('')

interface Seen { method: string; path: string; query: URLSearchParams; headers: Headers; body: BodyInit | null | undefined; credentials?: RequestCredentials }
type Handler = (seen: Seen, count: number) => Response | Promise<Response>

// A register stand-in: `routes` maps "METHOD /path-after-the-proposal" or the full path to a handler.
function register(routes: Record<string, Handler>, extra: { token?: boolean } = {}) {
  const seen: Seen[] = []
  const counts = new Map<string, number>()
  const fetch: typeof globalThis.fetch = async (url, init) => {
    const parsed = new URL(String(url))
    const entry: Seen = {
      method: init?.method ?? 'GET', path: parsed.pathname, query: parsed.searchParams,
      headers: new Headers(init?.headers), body: init?.body, credentials: init?.credentials,
    }
    seen.push(entry)
    const key = `${entry.method} ${parsed.pathname}`
    const handler = routes[key]
    assert.ok(handler, `unscripted request ${key}`)
    const count = (counts.get(key) ?? 0) + 1
    counts.set(key, count)
    return handler(entry, count)
  }
  const options = extra.token === false ? { baseUrl, fetch } : { baseUrl, token: () => 'fixture', fetch }
  const client = new Facility(new Transport(options))
  return { seen, client, commands: proposalCommands(client, { accessProfile }) }
}

const ok = (doc: unknown, status = 200) => Response.json(doc, { status })
const P = '/v1/proposals/prop-1'
const calls = (seen: Seen[]) => seen.map(s => `${s.method} ${s.path.replace(P, '')}`)
const keyOf = (s: Seen) => s.headers.get('idempotency-key') ?? ''

// The screen shows the table's sentence for the code, never the detail or a served value.
function onScreen(error: RegistryError): void {
  assert.equal(error.raisedByClient, true)
  // A step the register offers no more shows the sentence for the served reason.
  const reason = error.code === 'client.command-unavailable' ? error.problem?.['reason'] : undefined
  const key = typeof reason === 'string' && Object.hasOwn(availabilityMessages, reason) ? reason : error.code!
  assert.equal(describeError(error), clientSentences[key] ?? clientFallbackSentence)
  assert.ok(Object.hasOwn(clientSentences, error.code!), `${error.code} has a sentence`)
  assert.ok(!describeError(error).includes(error.detail!))
}

async function refusal(promise: Promise<unknown>, code: string, reason?: string): Promise<RegistryError> {
  const error = await promise.then(() => assert.fail('expected a refusal'), (e: unknown) => e)
  assert.ok(error instanceof RegistryError, String(error))
  assert.equal(error.kind, 'refused')
  assert.equal(error.reason, 'input')
  assert.equal(error.code, code)
  assert.ok(error.detail && error.detail.length > 10, 'plain English detail')
  onScreen(error)
  if (reason) assert.equal(error.problem?.['reason'], reason)
  return error
}

// 1 and 14: commands follow served links, only start/get/list use the options profile.
test('get reads the proposal with the options profile and no mutation headers', async () => {
  const { seen, commands } = register({ [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')) })
  const proposal = await commands.get('prop-1')
  assert.equal(proposal.id, 'prop-1')
  assert.equal(seen[0]?.query.get('accessProfile'), accessProfile)
  assert.equal(seen[0]?.headers.has('if-match'), false)
  assert.equal(seen[0]?.headers.get('authorization'), 'Bearer fixture')
})

test('start posts the action input, passes a given key, then reads the proposal again', async () => {
  const { seen, commands } = register({
    'POST /v1/actions/correct-address/proposals': () => ok(fixture('proposal-draft-optional'), 201),
    [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')),
  })
  const proposal = await commands.start('correct-address', { city: 'Springfield' }, { idempotencyKey: 'key-from-caller' })
  assert.deepEqual(calls(seen).map(c => c.split(' ')[0]), ['POST', 'GET'])
  assert.deepEqual(JSON.parse(String(seen[0]?.body)), { input: { city: 'Springfield' } })
  assert.equal(seen[0]?.query.get('accessProfile'), accessProfile)
  assert.equal(keyOf(seen[0]!), 'key-from-caller')
  assert.equal(proposal.state, 'draft')
})

test('start without a key leaves the key to the core, and refuses an action id that is not a plain id', async () => {
  const { seen, commands } = register({
    'POST /v1/actions/correct-address/proposals': () => ok(fixture('proposal-draft-optional'), 201),
    [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')),
  })
  await commands.start('correct-address')
  assert.ok(keyOf(seen[0]!).length > 0)
  assert.ok(!keyOf(seen[0]!).startsWith('rc1-'))
  assert.deepEqual(JSON.parse(String(seen[0]?.body)), { input: {} })
  const before = seen.length
  await refusal(commands.start('../x'), 'client.action-id')
  assert.equal(seen.length, before)
})

// 14: list.
test('list sends the filter and returns plain Proposals with a null cursor on the last page', async () => {
  const { seen, commands } = register({
    'GET /v1/proposals': (_s, n) => ok(fixture(n === 1 ? 'proposal-list' : 'proposal-list-last')),
  })
  const first = await commands.list({ turn: 'party', state: 'draft', action: 'correct-address', limit: 5 })
  assert.deepEqual(Object.fromEntries(seen[0]!.query), { accessProfile, turn: 'party', state: 'draft', action: 'correct-address', limit: '5' })
  assert.equal(first.items.length, 2)
  assert.equal(first.nextCursor, 'cursor-2')
  assert.equal(first.items[1]?.sentBack, true)
  const last = await commands.list({ cursor: first.nextCursor ?? undefined })
  assert.equal(seen[1]?.query.get('cursor'), 'cursor-2')
  assert.equal(last.nextCursor, null)
})

// 4: status, row by row (rule: records/2026/2026-11-27-proposal-review-loop/status-rule.md).
test('proposalStatus follows the derivation row by row', () => {
  const submitted = fixture('proposal-submitted')
  const rows: [string, ServedProposal, string][] = [
    ['cancelled', fixture('proposal-cancelled'), 'cancelled'],
    ['rejected', fixture('proposal-rejected'), 'rejected'],
    ['applied', fixture('proposal-applied'), 'applied'],
    ['draft', fixture('proposal-draft-optional'), 'draft'],
    ['party turn', fixture('proposal-sent-back'), 'awaiting-party'],
    ['approved decision', fixture('proposal-approved'), 'approved'],
    ['official, no application status', submitted, 'in-review'],
    ['official, awaiting review', { ...submitted, applicationStatus: { mode: 'manual', state: 'awaiting-review' } }, 'in-review'],
    ['official, application pending', { ...submitted, applicationStatus: { mode: 'manual', state: 'pending' } }, 'processing'],
    ['nobody, no decision', { ...submitted, turn: 'nobody' }, 'processing'],
    ['nobody, application applying', { ...submitted, turn: 'nobody', applicationStatus: { mode: 'automatic', state: 'applying' } }, 'processing'],
  ]
  for (const [name, served, status] of rows) assert.equal(proposalStatus(served), status, name)
})

test('proposalStatus: the party turn wins over an approved decision', () => {
  assert.equal(proposalStatus({ ...fixture('proposal-approved'), turn: 'party' }), 'awaiting-party')
})

test('proposalStatus uses a served status of the eight, and derives when the value is unknown', () => {
  for (const status of ['draft', 'awaiting-party', 'in-review', 'approved', 'processing', 'applied', 'rejected', 'cancelled']) {
    assert.equal(proposalStatus({ ...fixture('proposal-draft-optional'), status }), status)
  }
  assert.equal(proposalStatus({ ...fixture('proposal-draft-optional'), status: 'completed' }), 'draft')
  assert.equal(proposalStatus({ ...fixture('proposal-sent-back'), status: 'action-needed' }), 'awaiting-party')
})

// 3, 5, 6: the derived view.
test('can is total, maps links, and gives a reason and a sentence when a command is not offered', async () => {
  const { commands } = register({ [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')) })
  const draft = await commands.get('prop-1')
  assert.deepEqual(Object.keys(draft.can).sort(), ['attach', 'cancel', 'edit', 'rebase', 'resubmit', 'submit'])
  for (const name of ['attach', 'cancel', 'edit', 'submit'] as const) {
    assert.equal(draft.can[name].available, true, name)
    assert.ok(draft.can[name].message.length > 0)
  }
  assert.equal(draft.can.resubmit.available, false)
  assert.equal(draft.can.resubmit.reason, 'stale-revision')
  assert.equal(draft.can.resubmit.recovery, 'receipt-only')
  assert.ok(draft.can.resubmit.message.length > 5)
  assert.match(draft.can.resubmit.message, /no longer possible for this application/i)
})

test('can.resubmit follows the revise link and carries the served reason and recovery', async () => {
  const docs = { open: fixture('proposal-sent-back'), stale: fixture('proposal-submitted-stale') }
  const { commands } = register({ [`GET ${P}`]: (_s, n) => ok(n === 1 ? docs.open : docs.stale) })
  const open = await commands.get('prop-1')
  assert.equal(open.can.resubmit.available, true)
  assert.equal(open.can.attach.available, false)
  assert.equal(open.can.attach.reason, 'not-offered')
  const waiting = await commands.get('prop-1')
  assert.deepEqual(
    { available: waiting.can.resubmit.available, reason: waiting.can.resubmit.reason, recovery: waiting.can.resubmit.recovery },
    { available: false, reason: 'pending-review', recovery: 'refresh' },
  )
  assert.ok(waiting.can.resubmit.message.length > 5)
})

test('sentBack is true only for a submitted proposal whose decision asks for changes', async () => {
  const docs = ['proposal-sent-back', 'proposal-submitted', 'proposal-approved']
  const { commands } = register({ [`GET ${P}`]: (_s, n) => ok(fixture(docs[n - 1]!)) })
  assert.equal((await commands.get('prop-1')).sentBack, true)
  assert.equal((await commands.get('prop-1')).sentBack, false)
  assert.equal((await commands.get('prop-1')).sentBack, false)
  const draftWithDecision = { ...fixture('proposal-draft-optional'), decision: { status: 'changes-requested', decidedAt: '2026-11-27T11:00:00Z' } }
  const { commands: other } = register({ [`GET ${P}`]: () => ok(draftWithDecision) })
  assert.equal((await other.get('prop-1')).sentBack, false)
})

test('the attachments view maps value and verification status and carries what the slot accepts', async () => {
  const states = [undefined, 'notRequired', 'pending', 'approved', 'rejected'] as const
  const expected = ['empty', 'attached', 'pending', 'approved', 'rejected']
  const { commands } = register({
    [`GET ${P}`]: (_s, n) => {
      const doc = fixture(n === 1 ? 'proposal-draft' : 'proposal-draft-attached')
      const slot = doc.attachments!['supporting-document']!
      const status = states[n - 1]
      if (status && slot.value) slot.value = { ...slot.value, verificationStatus: status }
      return ok(doc)
    },
  })
  for (const [index, status] of expected.entries()) {
    const view = (await commands.get('prop-1')).attachments['supporting-document']!
    assert.equal(view.status, status, `row ${index}`)
    assert.equal(view.required, true)
    assert.deepEqual(view.accepts, { contentTypes: ['application/pdf'], maximumBytes: 1048576 })
    if (status === 'empty') assert.equal('mediaType' in view, false)
    else assert.deepEqual([view.mediaType, view.size], ['application/pdf', 4096])
  }
})

test('a Proposal is plain data: it survives structuredClone and a JSON round trip', async () => {
  const { commands } = register({ [`GET ${P}`]: () => ok(fixture('proposal-draft-attached')) })
  const proposal = await commands.get('prop-1')
  assert.deepEqual(structuredClone(proposal), proposal)
  assert.deepEqual(JSON.parse(JSON.stringify(proposal)), proposal)
  const minimal = await register({ [`GET ${P}`]: () => ok(fixture('proposal-draft-no-input')) }).commands.get('prop-1')
  assert.deepEqual(JSON.parse(JSON.stringify(minimal)), minimal)
  assert.equal('input' in minimal, false)
})

// 1, 2, 7, 8, 11: edit.
test('edit merges into the readable input, sends the link condition and a derived key, then reads again', async () => {
  const draft = fixture('proposal-draft-optional')
  const scripted = register({
    [`GET ${P}`]: () => ok(fixture('proposal-draft-attached')),
    [`POST ${P}/edit`]: () => ok(fixture('proposal-draft-attached')),
  })
  const p = (await register({ [`GET ${P}`]: () => ok(draft) }).commands.get('prop-1'))
  const view = await scripted.commands.edit(p, { city: 'Shelbyville' })
  assert.deepEqual(calls(scripted.seen), ['POST /edit', 'GET '])
  const [edit] = scripted.seen
  assert.equal(edit?.headers.get('if-match'), '"etag-3"')
  assert.equal(edit?.query.get('accessProfile'), accessProfile)
  assert.deepEqual(JSON.parse(String(edit?.body)), { input: { facilityId: 'f-1', city: 'Shelbyville' } })
  assert.match(keyOf(edit!), /^rc1-[0-9a-f]{64}$/)
  assert.ok(new TextEncoder().encode(keyOf(edit!)).length < 128)
  assert.equal(view.revision, 4)
})

test('the derived key repeats for the same command and differs for another body', async () => {
  const p = await register({ [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')) }).commands.get('prop-1')
  const keys: string[] = []
  for (const city of ['A', 'A', 'B']) {
    const { seen, commands } = register({
      [`POST ${P}/edit`]: () => ok(fixture('proposal-draft-optional')),
      [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')),
    })
    await commands.edit(p, { city })
    keys.push(keyOf(seen[0]!))
  }
  assert.equal(keys[0], keys[1])
  assert.notEqual(keys[0], keys[2])
})

test('edit refuses before sending when the grant cannot read the input', async () => {
  const { seen, commands } = register({ [`GET ${P}`]: () => ok(fixture('proposal-draft-no-input')) })
  const p = await commands.get('prop-1')
  await refusal(commands.edit(p, { city: 'X' }), 'client.inputs-not-readable')
  assert.equal(seen.length, 1, 'only the get was sent')
})

// 2: unavailable links refuse before sending.
test('a missing link refuses with client.command-unavailable and not-offered, without a request', async () => {
  const doc = fixture('proposal-draft-optional')
  delete doc.links['submit']
  const { seen, commands } = register({ [`GET ${P}`]: () => ok(doc) })
  const p = await commands.get('prop-1')
  seen.length = 0
  const error = await refusal(commands.submit(p), 'client.command-unavailable', 'not-offered')
  assert.match(error.detail ?? '', /not offered/i)
  assert.equal(seen.length, 0)
})

test('a command the state does not allow refuses with the served reason, without a request', async () => {
  const { seen, commands } = register({ [`GET ${P}`]: () => ok(fixture('proposal-submitted')) })
  const p = await commands.get('prop-1')
  seen.length = 0
  await refusal(commands.submit(p), 'client.command-unavailable', 'stale-revision')
  await refusal(commands.edit(p, {}), 'client.command-unavailable', 'stale-revision')
  await refusal(commands.attach(p, 'supporting-document', pdf()), 'client.command-unavailable', 'not-offered')
  assert.equal(seen.length, 0)
})

test('a link the register marks unavailable refuses with its reason and recovery', async () => {
  const { seen, commands } = register({ [`GET ${P}`]: () => ok(fixture('proposal-submitted-stale')) })
  const p = await commands.get('prop-1')
  seen.length = 0
  const error = await refusal(commands.resubmit(p), 'client.command-unavailable', 'pending-review')
  assert.equal(error.problem?.['recovery'], 'refresh')
  assert.equal(writesOf(seen).length, 0)
})

test('a command link that carries a different operation than its name is refused', async () => {
  const doc = fixture('proposal-draft-optional')
  doc.links['submit']!.operation = 'apply'
  const { seen, commands } = register({ [`GET ${P}`]: () => ok(doc) })
  const p = await commands.get('prop-1')
  seen.length = 0
  await refusal(commands.submit(p), 'client.link-operation')
  assert.equal(seen.length, 0)
})

// 9: attach.
test('attach checks the slot, the type and the size before sending', async () => {
  const { seen, commands } = register({ [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')) })
  const p = await commands.get('prop-1')
  seen.length = 0
  await refusal(commands.attach(p, 'nope', pdf()), 'client.unknown-slot')
  const type = await refusal(commands.attach(p, 'supporting-document', new Blob(['x'], { type: 'image/png' })), 'client.file-type')
  assert.match(type.detail ?? '', /application\/pdf/)
  const params = await refusal(commands.attach(p, 'supporting-document', new Blob(['x'], { type: 'application/pdf;version=1.7' })), 'client.file-type')
  assert.match(params.detail ?? '', /application\/pdf/)
  const none = await refusal(commands.attach(p, 'supporting-document', new Blob(['x'])), 'client.file-type')
  assert.match(none.detail ?? '', /application\/pdf/)
  const big = await refusal(commands.attach(p, 'supporting-document', pdf(1048577)), 'client.file-too-large')
  assert.match(big.detail ?? '', /1048576/)
  assert.equal(seen.length, 0)
})

test('attach sends the bytes with the slot link condition, the file type and a derived key', async () => {
  let doc = fixture('proposal-draft-optional')
  const { seen, commands } = register({
    [`GET ${P}`]: () => ok(doc),
    [`PATCH ${P}/attachments/supporting-document`]: () => { doc = fixture('proposal-draft-attached'); return ok(doc) },
  })
  const p = await commands.get('prop-1')
  const file = pdf(6)
  const view = await commands.attach(p, 'supporting-document', file)
  const patch = seen.find(s => s.method === 'PATCH')!
  assert.equal(patch.headers.get('if-match'), '"etag-3"')
  assert.equal(patch.headers.get('content-type'), 'application/pdf')
  assert.equal(patch.query.get('accessProfile'), accessProfile)
  assert.deepEqual(new Uint8Array(await (patch.body as Blob).arrayBuffer()), new Uint8Array(6).fill(37))
  assert.match(keyOf(patch), /^rc1-[0-9a-f]{64}$/)
  assert.equal(calls(seen).at(-1), 'GET ')
  assert.equal(view.attachments['supporting-document']?.status, 'attached')
})

test('attach infers PDF from an untyped filename and sends the resolved content type', async () => {
  const { seen, commands } = register({
    [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')),
    [`PATCH ${P}/attachments/supporting-document`]: () => ok(fixture('proposal-draft-attached')),
  })
  const draft = await commands.get('prop-1')
  const file = new File(['bytes'], 'support.PDF')
  assert.equal(file.type, '')
  await commands.attach(draft, 'supporting-document', file)
  assert.equal(seen.find(request => request.method === 'PATCH')?.headers.get('content-type'), 'application/pdf')
  const error = await refusal(commands.attach(draft, 'supporting-document', new File(['x'], 'support.unknown')), 'client.file-type')
  assert.match(error.detail!, /accepts application\/pdf/u)
  assert.equal(seen.filter(request => request.method === 'PATCH').length, 1)
})

test('attach normalises JPEG aliases and refuses a PDF filename on a PNG-only slot', async () => {
  const doc = fixture('proposal-draft-optional')
  const slot = doc.attachments!['supporting-document']!
  const contentTypes: string[] = []
  const commands = proposalCommands({
    call: async (operation: string, input: ProposalCallValues) => {
      if (operation.endsWith('.patch')) contentTypes.push(input.contentType!)
      return { data: doc }
    },
  }, { accessProfile })
  slot.contentTypes = ['image/jpeg']
  const jpeg = await commands.get('prop-1')
  for (const alias of ['image/jpg', 'image/pjpeg']) {
    await commands.attach(jpeg, 'supporting-document', new File(['x'], 'photo.unknown', { type: alias }))
  }
  assert.deepEqual(contentTypes, ['image/jpeg', 'image/jpeg'])
  slot.contentTypes = ['image/png']
  const png = await commands.get('prop-1')
  const error = await refusal(commands.attach(png, 'supporting-document', new File(['x'], 'support.pdf')), 'client.file-type')
  assert.match(error.detail!, /accepts image\/png/u)
  assert.equal(contentTypes.length, 2)
})

test('the attach key follows the file bytes', async () => {
  const keys: string[] = []
  for (const fill of [1, 1, 2]) {
    const { seen, commands } = register({
      [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')),
      [`PATCH ${P}/attachments/supporting-document`]: () => ok(fixture('proposal-draft-attached')),
    })
    const p = await commands.get('prop-1')
    await commands.attach(p, 'supporting-document', new Blob([new Uint8Array(4).fill(fill)], { type: 'application/pdf' }))
    keys.push(keyOf(seen.find(s => s.method === 'PATCH')!))
  }
  assert.equal(keys[0], keys[1])
  assert.notEqual(keys[0], keys[2])
})

// submit, cancel.
test('submit and cancel send an empty body with their own link condition', async () => {
  const { seen, commands } = register({
    [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')),
    [`POST ${P}/submit`]: () => ok(fixture('proposal-submitted')),
    [`POST ${P}/cancel`]: () => ok(fixture('proposal-cancelled')),
  })
  const p = await commands.get('prop-1')
  await commands.submit(p)
  const submit = seen.find(s => s.path.endsWith('/submit'))!
  assert.equal(submit.headers.get('if-match'), '"etag-3"')
  assert.deepEqual(JSON.parse(String(submit.body)), {})
  const { seen: seenCancel, commands: other } = register({
    [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')),
    [`POST ${P}/cancel`]: () => ok(fixture('proposal-cancelled')),
  })
  const view = await other.cancel(await other.get('prop-1'))
  assert.equal(seenCancel.find(s => s.path.endsWith('/cancel'))?.headers.get('if-match'), '"etag-3"')
  assert.equal(view.status, 'draft', 'the view is the document read again, not the command answer')
})

// 10: resubmit.
const nextVersion = (d: ServedProposal): ServedProposal => ({ ...d, submissionVersion: d.submissionVersion + 1 })

interface ResubmitOptions { failAttachOnce?: boolean; failSubmitOnce?: boolean; loseSubmitAnswerOnce?: boolean; ignoreRevisedInput?: boolean; sha256?: string }

// A register that moves a sent-back proposal through revise, attach, edit and submit, one
// submission version higher after the revise. Revise and edit take the input they are sent,
// unless `ignoreRevisedInput` makes revise drop it.
function resubmitServer(options: ResubmitOptions = {}) {
  let doc = fixture('proposal-sent-back')
  const count = { revise: 0, patch: 0, edit: 0, submit: 0 }
  const failed = { attach: false, submit: false, lost: false }
  const sentInput = (s: Seen): JsonObject | undefined => (JSON.parse(String(s.body)) as { input?: JsonObject }).input
  const server = register({
    [`GET ${P}`]: () => ok(doc),
    [`POST ${P}/revise`]: s => {
      count.revise++
      // Revise carries the previous round's attachments forward.
      const revised = { ...nextVersion(fixture('proposal-draft-optional')), input: options.ignoreRevisedInput ? doc.input : sentInput(s) ?? doc.input }
      const carried = doc.attachments?.['supporting-document']?.value
      if (carried) revised.attachments!['supporting-document']!.value = carried
      doc = revised
      return ok(doc)
    },
    [`PATCH ${P}/attachments/supporting-document`]: () => {
      count.patch++
      if (options.failAttachOnce && !failed.attach) { failed.attach = true; return new Response(null, { status: 503 }) }
      const attached = { ...nextVersion(fixture('proposal-draft-attached')), input: doc.input }
      if (options.sha256) attached.attachments!['supporting-document']!.value!.sha256 = options.sha256
      doc = attached
      return ok(doc)
    },
    [`POST ${P}/edit`]: s => { count.edit++; doc = { ...doc, input: sentInput(s) }; return ok(doc) },
    [`POST ${P}/cancel`]: () => ok(fixture('proposal-cancelled')),
    [`POST ${P}/submit`]: () => {
      count.submit++
      if (options.failSubmitOnce && !failed.submit) { failed.submit = true; return new Response(null, { status: 503 }) }
      doc = { ...nextVersion(fixture('proposal-submitted')), input: doc.input }
      if (options.loseSubmitAnswerOnce && !failed.lost) { failed.lost = true; return new Response(null, { status: 503 }) }
      return ok(doc)
    },
  })
  return { ...server, count, setDoc: (next: ServedProposal) => { doc = next } }
}

const writesOf = (seen: Seen[]) => seen.filter(s => s.method !== 'GET')
const staleCopy = async (promise: Promise<unknown>) => {
  const error = await promise.then(() => assert.fail('expected a refusal'), (e: unknown) => e)
  assert.ok(error instanceof RegistryError)
  assert.deepEqual([error.kind, error.reason, error.code], ['refused', 'stale', 'client.stale-copy'])
  assert.match(error.detail ?? '', /reload/i)
  onScreen(error)
}
const changed = { city: 'Shelbyville' }

test('resubmit reads the register, revises, attaches, edits only when needed, then submits', async () => {
  const server = resubmitServer({ ignoreRevisedInput: true })
  const p = await server.commands.get('prop-1')
  server.seen.length = 0
  const view = await server.commands.resubmit(p, { changes: changed, files: { 'supporting-document': pdf() } })
  assert.deepEqual(calls(server.seen), [
    'GET ', 'POST /revise', 'GET ', 'PATCH /attachments/supporting-document', 'GET ', 'POST /edit', 'GET ', 'POST /submit', 'GET ',
  ])
  const writes = writesOf(server.seen)
  assert.deepEqual(writes.map(s => s.headers.get('if-match')), ['"etag-6"', '"etag-3"', '"etag-4"', '"etag-4"'])
  assert.deepEqual(JSON.parse(String(writes[0]?.body)), { input: { facilityId: 'f-1', city: 'Shelbyville' } })
  assert.equal(new Set(writes.map(keyOf)).size, 4, 'each step has its own key')
  for (const write of writes) assert.match(keyOf(write), /^rc1-/)
  assert.equal(view.status, 'in-review')
})

test('resubmit skips the edit when the revised document already holds the changes, and sends {} without changes', async () => {
  const withChanges = resubmitServer()
  const p = await withChanges.commands.get('prop-1')
  withChanges.seen.length = 0
  await withChanges.commands.resubmit(p, { changes: changed })
  assert.deepEqual(calls(withChanges.seen).filter(c => !c.startsWith('GET')), ['POST /revise', 'POST /submit'])
  const plain = resubmitServer()
  const q = await plain.commands.get('prop-1')
  plain.seen.length = 0
  await plain.commands.resubmit(q)
  assert.deepEqual(JSON.parse(String(writesOf(plain.seen)[0]?.body)), {})
})

test('resubmit removes an input that a change sets to undefined', async () => {
  const server = resubmitServer()
  const p = await server.commands.get('prop-1')
  server.seen.length = 0
  await server.commands.resubmit(p, { changes: { city: undefined } })
  assert.deepEqual(JSON.parse(String(writesOf(server.seen)[0]?.body)), { input: { facilityId: 'f-1' } })
  const again = await server.commands.resubmit(p, { changes: { city: undefined } })
  assert.equal(again.state, 'submitted', 'a retry finds the removal done')
  assert.equal(server.count.revise, 1)
})

test('resubmit refuses a bad file before the first write', async () => {
  const server = resubmitServer()
  const p = await server.commands.get('prop-1')
  server.seen.length = 0
  await refusal(server.commands.resubmit(p, { files: { 'supporting-document': new Blob(['x'], { type: 'image/png' }) } }), 'client.file-type')
  await refusal(server.commands.resubmit(p, { files: { nope: pdf() } }), 'client.unknown-slot')
  assert.equal(writesOf(server.seen).length, 0)
})

test('resubmit is available only while the party is to act, and says so', async () => {
  const { seen, commands } = register({ [`GET ${P}`]: () => ok(fixture('proposal-submitted')) })
  const p = await commands.get('prop-1')
  assert.equal(p.served.links['revise']?.availability?.available, true, 'the register offers revise in review')
  assert.deepEqual([p.can.resubmit.available, p.can.resubmit.reason], [false, 'not-awaiting-party'])
  assert.ok(p.can.resubmit.message.length > 5)
  seen.length = 0
  await refusal(commands.resubmit(p), 'client.command-unavailable', 'not-awaiting-party')
  assert.equal(writesOf(seen).length, 0)
  const approved = await register({ [`GET ${P}`]: () => ok(fixture('proposal-approved')) }).commands.get('prop-1')
  assert.equal(approved.can.resubmit.reason, 'not-awaiting-party')
  const sentBack = await register({ [`GET ${P}`]: () => ok(fixture('proposal-sent-back')) }).commands.get('prop-1')
  assert.equal(sentBack.can.resubmit.available, true)
})

test('two concurrent resubmit calls with the same correction make one revise and one submit', async () => {
  const server = resubmitServer()
  const p = await server.commands.get('prop-1')
  const [a, b] = await Promise.all([server.commands.resubmit(p, { changes: changed }), server.commands.resubmit(p, { changes: changed })])
  assert.deepEqual([server.count.revise, server.count.submit], [1, 1])
  assert.equal(a.status, 'in-review')
  assert.equal(b.status, 'in-review')
})

test('two different concurrent corrections: the second is refused, not reported as done', async () => {
  const server = resubmitServer()
  const p = await server.commands.get('prop-1')
  const [a, b] = await Promise.allSettled([server.commands.resubmit(p, { changes: { city: 'A' } }), server.commands.resubmit(p, { changes: { city: 'B' } })])
  assert.equal(a.status, 'fulfilled')
  assert.equal(b.status, 'rejected')
  await staleCopy(Promise.reject((b as PromiseRejectedResult).reason))
  assert.deepEqual([server.count.revise, server.count.submit], [1, 1])
})

test('a copy older than a later round is refused', async () => {
  const server = resubmitServer()
  const p = await server.commands.get('prop-1')
  server.setDoc({ ...fixture('proposal-submitted'), submissionVersion: 3 })
  server.seen.length = 0
  await staleCopy(server.commands.resubmit(p, { changes: changed }))
  assert.equal(writesOf(server.seen).length, 0)
})

test("another tab's different correction is refused, not overwritten", async () => {
  const server = resubmitServer()
  const p = await server.commands.get('prop-1')
  server.setDoc({ ...nextVersion(fixture('proposal-draft-optional')), input: { facilityId: 'f-1', city: 'Other' } })
  server.seen.length = 0
  await staleCopy(server.commands.resubmit(p, { changes: changed }))
  assert.equal(writesOf(server.seen).length, 0)
})

test('a refused stale resubmit does not make the register copy this instance\'s own', async () => {
  const server = resubmitServer()
  const p = await server.commands.get('prop-1')
  const later = { ...nextVersion(fixture('proposal-submitted')), revision: 9, input: { facilityId: 'f-1', city: 'Other' } }
  for (const link of Object.values(later.links)) if (link.ifMatch) link.ifMatch = '"etag-9"'
  server.setDoc(later)
  await staleCopy(server.commands.resubmit(p, { changes: changed }))
  server.seen.length = 0
  await server.commands.cancel(p)
  assert.equal(server.seen.find(s => s.method === 'POST')?.headers.get('if-match'), '"etag-6"', 'the old copy keeps its own condition')
})

test('without changes, a draft is resumed only when nothing else was edited and given files are held', async () => {
  const server = resubmitServer()
  const p = await server.commands.get('prop-1')
  server.setDoc({ ...nextVersion(fixture('proposal-draft-optional')), input: { facilityId: 'f-1', city: 'Half-edited' } })
  server.seen.length = 0
  await staleCopy(server.commands.resubmit(p))
  server.setDoc({ ...nextVersion(fixture('proposal-draft-optional')), input: { ...p.input } })
  await staleCopy(server.commands.resubmit(p, { files: { 'supporting-document': pdf() } }))
  assert.equal(writesOf(server.seen).length, 0)
  const resumed = await server.commands.resubmit(p)
  assert.equal(resumed.state, 'submitted')
  assert.deepEqual([server.count.revise, server.count.submit], [0, 1])
})

test('a plain retry with the same file resumes after a revise landed and the attach failed', async () => {
  const server = resubmitServer({ failAttachOnce: true })
  const p = await server.commands.get('prop-1')
  const options = { files: { 'supporting-document': pdf() } }
  await assert.rejects(server.commands.resubmit(p, options), { status: 503 })
  const view = await server.commands.resubmit(p, options)
  assert.equal(view.state, 'submitted')
  assert.deepEqual([server.count.revise, server.count.patch, server.count.submit], [1, 2, 1], 'one revise, one attach landed, one submit')
})

test('a draft whose slot holds a third file is refused as another tab\'s upload', async () => {
  const server = resubmitServer()
  const p = await server.commands.get('prop-1')
  const draft = { ...nextVersion(fixture('proposal-draft-attached')), input: { ...p.input } }
  draft.attachments!['supporting-document']!.value!.sha256 = 'c'.repeat(64)
  server.setDoc(draft)
  server.seen.length = 0
  await staleCopy(server.commands.resubmit(p, { files: { 'supporting-document': pdf() } }))
  await staleCopy(server.commands.resubmit(p, { changes: { city: 'Springfield' }, files: { 'supporting-document': pdf() } }))
  assert.equal(writesOf(server.seen).length, 0)
})

test('resuming from a draft whose input cannot be read is refused', async () => {
  const server = resubmitServer()
  const p = await server.commands.get('prop-1')
  const hidden = nextVersion(fixture('proposal-draft-optional'))
  delete hidden.input
  server.setDoc(hidden)
  server.seen.length = 0
  await refusal(server.commands.resubmit(p, { changes: changed }), 'client.inputs-not-readable')
  assert.equal(writesOf(server.seen).length, 0)
})

test('a retry after a submit that landed but lost its answer returns the submitted document', async () => {
  const server = resubmitServer({ loseSubmitAnswerOnce: true })
  const p = await server.commands.get('prop-1')
  await assert.rejects(server.commands.resubmit(p, { changes: changed }), { status: 503 })
  const view = await server.commands.resubmit(p, { changes: changed })
  assert.equal(view.state, 'submitted')
  assert.equal(view.submissionVersion, 2)
  assert.deepEqual([server.count.revise, server.count.submit], [1, 1])
})

test('a retry after a failure between revise and submit matches the resolved type on the draft', async () => {
  const file = new File([pdf()], 'support.pdf')
  const server = resubmitServer({ failSubmitOnce: true, sha256: await hex(file) })
  const p = await server.commands.get('prop-1')
  const options = { changes: changed, files: { 'supporting-document': file } }
  await assert.rejects(server.commands.resubmit(p, options), { status: 503 })
  const view = await server.commands.resubmit(p, options)
  assert.equal(view.status, 'in-review')
  assert.deepEqual([server.count.revise, server.count.patch, server.count.submit], [1, 1, 2])
  assert.equal(server.seen.find(request => request.method === 'PATCH')?.headers.get('content-type'), 'application/pdf')
})

test('a fresh instance after a failure in the middle continues from the draft', async () => {
  const server = resubmitServer({ failAttachOnce: true })
  const p = await server.commands.get('prop-1')
  const options = { changes: changed, files: { 'supporting-document': pdf() } }
  await assert.rejects(server.commands.resubmit(p, options), { status: 503 })
  const reloaded = proposalCommands(server.client, { accessProfile })
  const view = await reloaded.resubmit(p, options)
  assert.equal(view.status, 'in-review')
  assert.deepEqual([server.count.revise, server.count.patch, server.count.submit], [1, 2, 1])
})

// 12: one write at a time per proposal.
test('two quick submits make one submit and one clean refusal, never a stale error', async () => {
  let doc = fixture('proposal-draft-optional')
  const events: string[] = []
  const { seen, commands } = register({
    [`GET ${P}`]: () => { events.push('get'); return ok(doc) },
    [`POST ${P}/submit`]: async () => {
      events.push('submit:start')
      await new Promise(resolve => setTimeout(resolve, 20))
      doc = fixture('proposal-submitted')
      events.push('submit:end')
      return ok(doc)
    },
  })
  const p = await commands.get('prop-1')
  events.length = 0
  const [a, b] = await Promise.allSettled([commands.submit(p), commands.submit(p)])
  assert.equal(a.status, 'fulfilled')
  assert.equal(b.status, 'rejected')
  assert.equal((b as PromiseRejectedResult).reason.code, 'client.command-unavailable')
  assert.equal(seen.filter(s => s.path.endsWith('/submit')).length, 1)
  assert.deepEqual(events, ['submit:start', 'submit:end', 'get'])
})

test('a queued write uses the newest document this instance has seen, not the stale one passed in', async () => {
  // The read after the first edit serves revision 4, whose edit link carries a new condition.
  let served = fixture('proposal-draft-optional')
  const { seen, commands } = register({
    [`GET ${P}`]: () => ok(served),
    [`POST ${P}/edit`]: () => { served = fixture('proposal-draft-attached'); return ok(served) },
  })
  const p = await commands.get('prop-1')
  seen.length = 0
  await Promise.all([commands.edit(p, { city: 'A' }), commands.edit(p, { city: 'B' })])
  const edits = seen.filter(s => s.path.endsWith('/edit'))
  assert.deepEqual(edits.map(s => s.headers.get('if-match')), ['"etag-3"', '"etag-4"'])
  assert.deepEqual(JSON.parse(String(edits[1]?.body)), { input: { facilityId: 'f-1', city: 'B' } })
})

test('writes on different proposals do not wait for each other', async () => {
  let release: () => void = () => {}
  const gate = new Promise<void>(resolve => { release = resolve })
  const second = fixture('proposal-draft-optional')
  second.id = 'prop-2'
  for (const link of Object.values(second.links)) link.path = link.path.replace('prop-1', 'prop-2')
  const { commands } = register({
    [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')),
    'GET /v1/proposals/prop-2': () => ok(second),
    [`POST ${P}/submit`]: async () => { await gate; return ok(fixture('proposal-submitted')) },
    'POST /v1/proposals/prop-2/submit': () => ok(fixture('proposal-submitted')),
  })
  const one = await commands.get('prop-1')
  const two = await commands.get('prop-2')
  const slow = commands.submit(one)
  const fast = await commands.submit(two)
  assert.equal(fast.id, 'prop-2', 'the second proposal finished while the first was still held')
  release()
  await slow
})

// 13: download.
async function holding(bytes: Uint8Array): Promise<ServedProposal> {
  const doc = fixture('proposal-draft-attached')
  const value = doc.attachments!['supporting-document']!.value!
  value.sha256 = await hex(new Blob([bytes as Uint8Array<ArrayBuffer>]))
  value.byteSize = bytes.length
  return doc
}

test('download returns a Blob with the stored type when the register answers with a safe media type', async () => {
  const bytes = new Uint8Array(4)
  const doc = await holding(bytes)
  const { seen, commands } = register({
    [`GET ${P}`]: () => ok(doc),
    [`GET ${P}/attachments/supporting-document`]: () => new Response(bytes, { headers: { 'Content-Type': 'application/pdf' } }),
  })
  const p = await commands.get('prop-1')
  const blob = await commands.download(p, 'supporting-document')
  assert.equal(blob.type, 'application/pdf')
  assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), bytes)
  const get = seen.find(s => s.path.endsWith('/attachments/supporting-document'))!
  assert.equal(get.query.get('submissionVersion'), '1')
  assert.equal(get.query.get('accessProfile'), accessProfile)
})

test('download returns a Blob when the register answers with octet-stream', async () => {
  const doc = await holding(new Uint8Array([1, 2, 3]))
  const { commands } = register({
    [`GET ${P}`]: () => ok(doc),
    [`GET ${P}/attachments/supporting-document`]: () => new Response(new Uint8Array([1, 2, 3]), { headers: { 'Content-Type': 'application/octet-stream' } }),
  })
  const blob = await commands.download(await commands.get('prop-1'), 'supporting-document')
  assert.equal(blob.type, 'application/octet-stream')
  assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), new Uint8Array([1, 2, 3]))
})

test('download keeps only a short list of safe served types', async () => {
  const doc = await holding(new Uint8Array([1]))
  const types: string[] = []
  const stub = {
    call: async (operation: string) => {
      if (operation === 'proposals.get') return { data: doc }
      return { data: { bytes: new Uint8Array([1]), mediaType: types.shift() } }
    },
  }
  const commands = proposalCommands(stub, { accessProfile })
  const p = await commands.get('prop-1')
  const seen: string[] = []
  for (const served of ['application/pdf', 'image/png', 'image/jpeg', 'text/html', 'image/svg+xml']) {
    types.push(served)
    seen.push((await commands.download(p, 'supporting-document')).type)
  }
  assert.deepEqual(seen, ['application/pdf', 'image/png', 'image/jpeg', 'application/octet-stream', 'application/octet-stream'])
})

test('download caps the answer at the slot size and checks size and digest before returning', async () => {
  const calls: { operation: string; maxResponseBytes?: number }[] = []
  const doc = await holding(new Uint8Array([1, 2, 3]))
  const stub = {
    call: async (operation: string, values: { maxResponseBytes?: number }) => {
      calls.push({ operation, maxResponseBytes: values.maxResponseBytes })
      if (operation === 'proposals.get') return { data: doc }
      return { data: { bytes: new Uint8Array([1, 2, 3]), mediaType: 'application/octet-stream' } }
    },
  }
  const commands = proposalCommands(stub, { accessProfile })
  await commands.download(await commands.get('prop-1'), 'supporting-document')
  assert.equal(calls.at(-1)?.maxResponseBytes, 1048576)
})

test('download throws too-large for a body over the slot size', async () => {
  const doc = await holding(new Uint8Array([1]))
  const { commands } = register({
    [`GET ${P}`]: () => ok(doc),
    [`GET ${P}/attachments/supporting-document`]: () => new Response(new Uint8Array(1048577), { headers: { 'Content-Type': 'application/octet-stream' } }),
  })
  await assert.rejects(commands.download(await commands.get('prop-1'), 'supporting-document'), { reason: 'too-large' })
})

test('download throws client.content-digest when the bytes do not match the served digest or size', async () => {
  const doc = await holding(new Uint8Array([1, 2, 3]))
  for (const body of [new Uint8Array([9, 9, 9]), new Uint8Array([1, 2, 3, 4])]) {
    const { commands } = register({
      [`GET ${P}`]: () => ok(doc),
      [`GET ${P}/attachments/supporting-document`]: () => new Response(body, { headers: { 'Content-Type': 'application/octet-stream' } }),
    })
    await assert.rejects(commands.download(await commands.get('prop-1'), 'supporting-document'),
      (error: unknown) => error instanceof RegistryError && error.code === 'client.content-digest'
        && error.kind === 'unexpected' && error.reason === 'schema' && (onScreen(error), true))
  }
})

test('download refuses a link that names no submission version as an unexpected answer', async () => {
  const doc = fixture('proposal-draft-attached')
  const slot = doc.attachments!['supporting-document']!
  delete slot.value
  slot.links['download']!.path = '/v1/proposals/prop-1/attachments/supporting-document'
  const { seen, commands } = register({ [`GET ${P}`]: () => ok(doc) })
  const p = await commands.get('prop-1')
  seen.length = 0
  const error = await refusal(commands.download(p, 'supporting-document'), 'client.link-operation')
  assert.equal(describeError(error), clientSentences['client.link-operation'])
  assert.equal(seen.length, 0)
})

test('download refuses an unknown slot and a slot without a download link', async () => {
  const { seen, commands } = register({ [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')) })
  const p = await commands.get('prop-1')
  seen.length = 0
  await refusal(commands.download(p, 'nope'), 'client.unknown-slot')
  await refusal(commands.download(p, 'supporting-document'), 'client.command-unavailable', 'not-offered')
  assert.equal(seen.length, 0)
})

// signal and page mode.
test('an aborted signal reaches the call', async () => {
  const { commands } = register({ [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')) })
  const p = await commands.get('prop-1')
  const controller = new AbortController()
  controller.abort()
  await assert.rejects(commands.submit(p, { signal: controller.signal }), { reason: 'aborted' })
  await assert.rejects(commands.get('prop-1', { signal: controller.signal }), { reason: 'aborted' })
})

test('page mode sends no bearer credential and cookies to the same origin only', async () => {
  const { seen, commands } = register({
    [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')),
    [`POST ${P}/submit`]: () => ok(fixture('proposal-submitted')),
  }, { token: false })
  const p = await commands.get('prop-1')
  await commands.submit(p)
  for (const s of seen) {
    assert.equal(s.headers.has('authorization'), false)
    assert.equal(s.credentials, 'same-origin')
  }
  assert.equal(seen.find(s => s.method === 'POST')?.headers.get('if-match'), '"etag-3"')
})

// Compile-time: the helper accepts the facility and the minimal generated Clients.
export function acceptsGeneratedClients(facility: Facility, minimal: Minimal): Proposal | void {
  proposalCommands(facility, { accessProfile: 'facility-correction-author' })
  proposalCommands(minimal, { accessProfile: 'directory-editor' })
}

test('the helper accepts the facility and the minimal generated clients', async () => {
  const minimal = new Minimal(new Transport({ baseUrl, token: () => 'fixture', fetch: async () => ok(fixture('proposal-draft-optional')) }))
  const commands = proposalCommands(minimal, { accessProfile: 'directory-editor' })
  assert.equal(typeof acceptsGeneratedClients, 'function')
  await assert.doesNotReject(commands.get('prop-1'))
})

test('onProgress goes unchanged to the byte transfer calls only', async () => {
  const recorded: { operation: string; onProgress: unknown }[] = []
  let doc = fixture('proposal-sent-back')
  const stub = {
    call: async (operation: string, input: { onProgress?: unknown }) => {
      recorded.push({ operation, onProgress: input.onProgress })
      if (operation === 'proposals.revise') doc = nextVersion(fixture('proposal-draft-optional'))
      if (operation.endsWith('.patch')) doc = nextVersion(fixture('proposal-draft-attached'))
      if (operation === 'proposals.submit') doc = nextVersion(fixture('proposal-submitted'))
      if (operation.startsWith('proposals.attachments.') && operation.endsWith('.get')) return { data: { bytes: new Uint8Array([1]), mediaType: 'application/pdf' } }
      return { data: doc }
    },
  }
  const commands = proposalCommands(stub, { accessProfile })
  const onProgress = () => {}
  await commands.resubmit(await commands.get('prop-1'), { files: { 'supporting-document': pdf() }, onProgress })
  const byOperation = Object.fromEntries(recorded.map(r => [r.operation, r.onProgress]))
  assert.equal(byOperation['proposals.attachments.supporting-document.patch'], onProgress)
  assert.equal(byOperation['proposals.revise'], undefined)
  assert.equal(byOperation['proposals.submit'], undefined)
  recorded.length = 0
  const later = proposalCommands(stub, { accessProfile })
  doc = await holding(new Uint8Array([1]))
  await later.download(await later.get('prop-1'), 'supporting-document', { onProgress })
  assert.equal(recorded.find(r => r.operation.startsWith('proposals.attachments.') && r.operation.endsWith('.get'))?.onProgress, onProgress)
  doc = fixture('proposal-draft-optional')
  recorded.length = 0
  await later.attach(await later.get('prop-1'), 'supporting-document', pdf(), { onProgress })
  assert.equal(recorded.find(r => r.operation.endsWith('.patch'))?.onProgress, onProgress)
})

// E: a write that lands but whose follow-up read fails.
test('start keeps its own key and reports a saved change when the read after it fails', async () => {
  const { seen, commands } = register({
    'POST /v1/actions/correct-address/proposals': () => ok(fixture('proposal-draft-optional'), 201),
    [`GET ${P}`]: () => new Response(null, { status: 503 }),
  })
  const error = await commands.start('correct-address', {}).then(() => assert.fail('expected an error'), (e: unknown) => e)
  assert.ok(error instanceof RegistryError)
  assert.equal(error.problem?.['code'], 'client.read-after-write')
  assert.equal(error.problem?.['proposalId'], 'prop-1')
  assert.equal(error.kind, 'unreachable')
  assert.equal(error.status, 503)
  assert.equal(error.outcomeUnknown, false)
  assert.equal(error.idempotencyKey, keyOf(seen[0]!))
  assert.ok(keyOf(seen[0]!).length > 0)
  assert.match(error.detail ?? '', /saved/i)
  onScreen(error)
  assert.ok(error.cause instanceof RegistryError)
})

test('a command whose write landed but whose read fails reports it with the write key', async () => {
  let reads = 0
  const { seen, commands } = register({
    [`GET ${P}`]: () => ++reads === 1 ? ok(fixture('proposal-draft-optional')) : new Response(null, { status: 503 }),
    [`POST ${P}/submit`]: () => ok(fixture('proposal-submitted')),
  })
  const p = await commands.get('prop-1')
  const error = await commands.submit(p).then(() => assert.fail('expected an error'), (e: unknown) => e)
  assert.ok(error instanceof RegistryError)
  assert.equal(error.code, 'client.read-after-write')
  onScreen(error)
  assert.equal(error.problem?.['proposalId'], 'prop-1')
  assert.equal(error.idempotencyKey, keyOf(seen.find(s => s.method === 'POST')!))
  assert.equal(error.outcomeUnknown, false)
  assert.match(error.detail ?? '', /saved/i)
})

// H: list whitelist.
test('list sends only the eight filter members and never the access profile', async () => {
  const { seen, commands } = register({ 'GET /v1/proposals': () => ok(fixture('proposal-list-last')) })
  await commands.list({
    turn: 'party', state: 'draft', action: 'a', owner: 'caller', target: 't', pendingManualApplication: true, cursor: 'c', limit: 3,
    accessProfile: 'proposal-reviewer', extra: 'x',
  } as never)
  assert.deepEqual(Object.fromEntries(seen[0]!.query), {
    accessProfile, turn: 'party', state: 'draft', action: 'a', owner: 'caller', target: 't', pendingManualApplication: 'true', cursor: 'c', limit: '3',
  })
})

// F: one typed wrapper checks the field names.
export function misspeltField(): ProposalCallValues {
  // @ts-expect-error a misspelt field is not accepted
  return { idempotencykey: 'x' }
}
test('the call values type names its fields', () => {
  assert.deepEqual(misspeltField(), { idempotencykey: 'x' })
})

// Rebase.
test('can.rebase is available only when the register offers it and the proposal needs it', async () => {
  const recovery = fixture('proposal-draft-optional')
  recovery.links['submit']!.availability = { available: false, observedRevision: 3, reason: 'invalid-input', recovery: 'rebase' }
  const docs = ['proposal-package-changed', 'proposal-draft', 'proposal-sent-back', 'proposal-applied']
  const { commands } = register({ [`GET ${P}`]: (_s, n) => ok(n <= 4 ? fixture(docs[n - 1]!) : recovery) })
  const changed = await commands.get('prop-1')
  assert.equal(changed.can.rebase.available, true)
  assert.match(changed.can.rebase.message, /form for this application has changed/i)
  assert.deepEqual(changed.can.resubmit, { available: false, reason: 'package-changed', recovery: 'rebase', message: changed.can.resubmit.message })
  for (const name of ['proposal-draft', 'proposal-sent-back']) {
    const view = await commands.get('prop-1')
    assert.deepEqual([view.can.rebase.available, view.can.rebase.reason], [false, 'not-needed'], name)
  }
  assert.equal((await commands.get('prop-1')).can.rebase.reason, 'already-applied')
  assert.equal((await commands.get('prop-1')).can.rebase.available, true, 'a link that recovers by rebase is enough')
  const missing = fixture('proposal-package-changed')
  delete missing.links['rebase']
  const view = await register({ [`GET ${P}`]: () => ok(missing) }).commands.get('prop-1')
  assert.equal(view.can.rebase.reason, 'not-offered')
})

test('a package-changed proposal can be rebased and then submitted', async () => {
  let doc = fixture('proposal-package-changed')
  const { seen, commands } = register({
    [`GET ${P}`]: () => ok(doc),
    [`POST ${P}/rebase`]: () => { doc = { ...fixture('proposal-draft-optional'), submissionVersion: 2, revision: 6 }; return ok(doc) },
    [`POST ${P}/submit`]: () => { doc = fixture('proposal-submitted'); return ok(doc) },
  })
  const p = await commands.get('prop-1')
  seen.length = 0
  const draft = await commands.rebase(p, { city: 'Shelbyville' })
  assert.deepEqual(calls(seen), ['POST /rebase', 'GET '])
  const [rebase] = seen
  assert.equal(rebase?.headers.get('if-match'), '"etag-5"')
  assert.equal(rebase?.query.get('accessProfile'), accessProfile)
  assert.deepEqual(JSON.parse(String(rebase?.body)), { input: { facilityId: 'f-1', city: 'Shelbyville' } })
  assert.match(keyOf(rebase!), /^rc1-[0-9a-f]{64}$/)
  assert.equal(draft.state, 'draft', 'rebase does not submit')
  assert.equal((await commands.submit(draft)).state, 'submitted')
})

test('rebase without changes sends the readable input unchanged', async () => {
  let doc = fixture('proposal-package-changed')
  const { seen, commands } = register({
    [`GET ${P}`]: () => ok(doc),
    [`POST ${P}/rebase`]: () => { doc = fixture('proposal-draft-optional'); return ok(doc) },
  })
  const p = await commands.get('prop-1')
  await commands.rebase(p)
  assert.deepEqual(JSON.parse(String(seen.find(s => s.method === 'POST')?.body)), { input: { facilityId: 'f-1', city: 'Springfield' } })
})

test('rebase refuses with not-needed, and when the input cannot be read, without a write', async () => {
  const { seen, commands } = register({ [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')) })
  const p = await commands.get('prop-1')
  seen.length = 0
  await refusal(commands.rebase(p), 'client.command-unavailable', 'not-needed')
  const hidden = fixture('proposal-package-changed')
  delete hidden.input
  const other = register({ [`GET ${P}`]: () => ok(hidden) })
  await refusal(other.commands.rebase(await other.commands.get('prop-1')), 'client.inputs-not-readable')
  assert.equal(writesOf(seen).length + writesOf(other.seen).length, 0)
})

// Item 2: a write that landed with a failed read leaves the cache untrusted.
test('after a write whose read failed, the next write reads the proposal first and builds from it', async () => {
  let doc = fixture('proposal-draft-optional')
  let reads = 0
  const sent = (s: Seen) => (JSON.parse(String(s.body)) as { input: JsonObject }).input
  const { seen, commands } = register({
    [`GET ${P}`]: () => ++reads === 2 ? new Response(null, { status: 503 }) : ok(doc),
    [`POST ${P}/edit`]: s => { doc = { ...fixture('proposal-draft-attached'), input: sent(s) }; return ok(doc) },
  })
  const p = await commands.get('prop-1')
  await assert.rejects(commands.edit(p, { city: 'A' }), { code: 'client.read-after-write' })
  seen.length = 0
  await commands.edit(p, { facilityId: 'f-9' })
  const edit = seen.find(s => s.method === 'POST')!
  assert.deepEqual(calls(seen).slice(0, 2), ['GET ', 'POST /edit'], 'the proposal is read before the write')
  assert.equal(edit.headers.get('if-match'), '"etag-4"')
  assert.deepEqual(sent(edit), { facilityId: 'f-9', city: 'A' })
})

// Item 3: only this instance's own writes update what a command acts on.
test('a list that learns a newer revision does not change the condition a command sends', async () => {
  const newer = fixture('proposal-draft-optional')
  newer.revision = 9
  for (const link of Object.values(newer.links)) if (link.ifMatch) link.ifMatch = '"etag-9"'
  const { seen, commands } = register({
    [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')),
    'GET /v1/proposals': () => ok({ items: [newer] }),
    [`POST ${P}/submit`]: () => ok(fixture('proposal-submitted')),
  })
  const p = await commands.get('prop-1')
  await commands.list()
  await commands.get('prop-1')
  await commands.submit(p)
  assert.equal(seen.find(s => s.method === 'POST')?.headers.get('if-match'), '"etag-3"')
})

// The register marks Submit unavailable while a required slot is empty. The helper follows the link.
test('submit follows the register: unavailable with attachment-required refuses before sending', async () => {
  const doc = fixture('proposal-draft')
  doc.links['submit']!.availability = { available: false, observedRevision: 3, reason: 'attachment-required', recovery: 'refresh' }
  // A stub client: the generated response schema does not list this reason until the register declares it.
  const seen: string[] = []
  const commands = proposalCommands({ call: async (operation: string) => { seen.push(operation); return { data: doc } } }, { accessProfile })
  const p = await commands.get('prop-1')
  assert.deepEqual([p.can.submit.available, p.can.submit.reason], [false, 'attachment-required'])
  assert.equal(p.can.submit.message, 'A required document is missing. Add it before sending.')
  seen.length = 0
  await refusal(commands.submit(p), 'client.command-unavailable', 'attachment-required')
  assert.equal(seen.length, 0)
})

test('the helper does not compute a missing required slot: an available submit link is sent', async () => {
  const { seen, commands } = register({
    [`GET ${P}`]: () => ok(fixture('proposal-draft')),
    [`POST ${P}/submit`]: () => ok(fixture('proposal-submitted')),
  })
  const p = await commands.get('prop-1')
  assert.equal(p.attachments['supporting-document']?.status, 'empty')
  assert.equal(p.attachments['supporting-document']?.required, true)
  assert.equal(p.can.submit.available, true)
  await commands.submit(p)
  assert.equal(seen.filter(s => s.method === 'POST').length, 1)
})

// Item 5 and 6: rebase for a refused application, and the package-changed sentence.
test('a manual Apply the register refused counts as needing a rebase, with its own sentence', async () => {
  let doc = fixture('proposal-application-refused')
  const { seen, commands } = register({
    [`GET ${P}`]: () => ok(doc),
    [`POST ${P}/rebase`]: () => { doc = { ...fixture('proposal-draft-optional'), submissionVersion: 2, revision: 6 }; return ok(doc) },
  })
  const p = await commands.get('prop-1')
  assert.equal(p.can.rebase.available, true)
  assert.match(p.can.rebase.message, /could not be applied/i)
  assert.notEqual(p.can.rebase.message, availabilityMessages['rebase'])
  assert.equal(p.can.resubmit.available, false)
  assert.equal((await commands.rebase(p)).state, 'draft')
  assert.equal(seen.filter(s => s.method === 'POST').length, 1)
})

test('the package-changed sentence tells the reader to update the form first', () => {
  assert.equal(availabilityMessages['package-changed'], 'The form for this application has changed. Update it to the current form first.')
})

// Item 9: one sentence set for applicant and staff pages.
test('no sentence addresses the reader as you', () => {
  for (const [reason, sentence] of Object.entries(availabilityMessages)) assert.doesNotMatch(sentence, /\byou(r|rs)?\b/i, reason)
})

// Item 7: a call the generated client cannot build throws a RegistryError.
test('an unknown action throws a RegistryError, not the generated client TypeError', async () => {
  const { seen, commands } = register({})
  const error = await commands.start('unknown-action').then(() => assert.fail('expected an error'), (e: unknown) => e)
  assert.ok(error instanceof RegistryError, String(error))
  assert.deepEqual([error.kind, error.reason, error.code], ['refused', 'input', 'client.unknown-operation'])
  assert.match(error.detail ?? '', /actions\.unknown-action\.start/)
  assert.equal(seen.length, 0)
})

// Item 8: a plain retry of start keeps its key while the last attempt's outcome is open.
const problem = () => new Response(JSON.stringify({
  title: 'Conflict', type: 'https://id.registrystack.org/problems/registry-breg/idempotency/key-reused',
  code: 'idempotency.key-reused', status: 409, detail: 'The key is already in use.', traceId: '1'.repeat(32),
}), { status: 409, headers: { 'Content-Type': 'application/problem+json' } })
const startPath = 'POST /v1/actions/correct-address/proposals'
const startKeys = (seen: Seen[]) => seen.filter(s => s.method === 'POST').map(keyOf)

test('start reuses its key for the same request after a failure with an open outcome, then drops it', async () => {
  const { seen, commands } = register({
    [startPath]: (_s, n) => { if (n === 1) throw new TypeError('offline'); return ok(fixture('proposal-draft-optional'), 201) },
    [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')),
  })
  await assert.rejects(commands.start('correct-address', { city: 'A' }), { kind: 'unreachable' })
  await commands.start('correct-address', { city: 'A' })
  await commands.start('correct-address', { city: 'A' })
  const keys = startKeys(seen)
  assert.equal(keys[0], keys[1], 'the retry reuses the key')
  assert.notEqual(keys[2], keys[1], 'a success clears it')
})

test('start keeps the key after a read-after-write failure and uses another for different input', async () => {
  let reads = 0
  const { seen, commands } = register({
    [startPath]: () => ok(fixture('proposal-draft-optional'), 201),
    [`GET ${P}`]: () => ++reads === 1 ? new Response(null, { status: 503 }) : ok(fixture('proposal-draft-optional')),
  })
  await assert.rejects(commands.start('correct-address', { city: 'A' }), { code: 'client.read-after-write' })
  await commands.start('correct-address', { city: 'B' })
  await commands.start('correct-address', { city: 'A' })
  const keys = startKeys(seen)
  assert.notEqual(keys[1], keys[0])
  assert.equal(keys[2], keys[0])
})

test('start drops the key after a definite refusal, and a given key wins and is not kept', async () => {
  const { seen, commands } = register({
    [startPath]: (_s, n) => n === 1 || n === 3 ? problem() : ok(fixture('proposal-draft-optional'), 201),
    [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')),
  })
  await assert.rejects(commands.start('correct-address', { city: 'A' }), { kind: 'refused' })
  await commands.start('correct-address', { city: 'A' })
  await assert.rejects(commands.start('correct-address', { city: 'A' }, { idempotencyKey: 'mine' }), { kind: 'refused' })
  await commands.start('correct-address', { city: 'A' })
  const keys = startKeys(seen)
  assert.notEqual(keys[1], keys[0], 'a refusal clears the key')
  assert.equal(keys[2], 'mine')
  assert.notEqual(keys[3], 'mine')
})

// Item 11: an undefined change removes the input.
test('edit removes an input whose change is undefined', async () => {
  const { seen, commands } = register({
    [`GET ${P}`]: () => ok(fixture('proposal-draft-optional')),
    [`POST ${P}/edit`]: () => ok(fixture('proposal-draft-attached')),
  })
  const p = await commands.get('prop-1')
  await commands.edit(p, { city: undefined, postalCode: '12345' })
  assert.deepEqual(JSON.parse(String(seen.find(s => s.method === 'POST')?.body)), { input: { facilityId: 'f-1', postalCode: '12345' } })
})

// Item 12 and 14: the Proposal carries what the register serves, and can be made from a served document.
test('a Proposal carries the served action revision, digest, handoff refusal, application and statuses', async () => {
  const doc = fixture('proposal-package-changed')
  const digest = 'sha256:' + 'b'.repeat(64)
  doc.effectDigest = digest
  doc.handoffRefusal = { code: 'review.refused' }
  doc.application = { applicationId: 'app-1', effectDigest: digest, resultLinks: [{ recordId: 'r', recordType: 'facility', revision: 2 }], submissionVersion: 1 }
  doc.applicationStatus = { mode: 'manual', state: 'blocked', reason: 'package-changed', recovery: 'rebase' }
  const { commands } = register({ [`GET ${P}`]: () => ok(doc) })
  const p = await commands.get('prop-1')
  assert.equal(p.actionRevision, 'rev-a')
  assert.equal(p.effectDigest, digest)
  assert.deepEqual(p.handoffRefusal, { code: 'review.refused' })
  assert.deepEqual(p.application, doc.application)
  assert.deepEqual(p.applicationStatus, doc.applicationStatus)
  assert.equal(p.blockedReason, 'package-changed')
  assert.deepEqual(JSON.parse(JSON.stringify(p)), p)
  const plain = await register({ [`GET ${P}`]: () => ok(fixture('proposal-draft')) }).commands.get('prop-1')
  for (const member of ['effectDigest', 'handoffRefusal', 'application', 'applicationStatus', 'blockedReason']) assert.equal(member in plain, false, member)
})

test('the attachments view says whether a slot can be uploaded to and downloaded from', async () => {
  const docs = ['proposal-draft', 'proposal-draft-attached', 'proposal-sent-back']
  const { commands } = register({ [`GET ${P}`]: (_s, n) => ok(fixture(docs[n - 1]!)) })
  const flags = []
  for (const _ of docs) {
    const view = (await commands.get('prop-1')).attachments['supporting-document']!
    flags.push([view.canUpload, view.canDownload])
  }
  assert.deepEqual(flags, [[true, false], [true, true], [false, true]])
})

test('proposalFromServed gives the same Proposal the commands do', async () => {
  const doc = fixture('proposal-sent-back')
  const { commands } = register({ [`GET ${P}`]: () => ok(doc) })
  assert.deepEqual(proposalFromServed(doc), await commands.get('prop-1'))
})

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { RegistryError, availabilityMessages, clientFallbackSentence, clientSentences, describeError } from '../core.ts'
import { proposalCommands, proposalFromServed, type ServedProposal } from '../tasks/proposals.ts'
import { refusal } from '../tasks/shared.ts'

const fixture = (name: string): ServedProposal =>
  JSON.parse(readFileSync(new URL(`./fixtures/tasks/${name}.json`, import.meta.url), 'utf8'))
// A draft whose Submit link is offered with the given availability.
const draftWithSubmit = (availability: { available: boolean; reason?: string; recovery?: string }): ServedProposal => {
  const served = fixture('proposal-draft')
  return { ...served, links: { ...served.links, submit: { ...served.links['submit']!, availability: { observedRevision: served.revision, ...availability } } } }
}

// Every code the helpers raise. `client.document-<status>` is one code for each unusable status.
const helperCodes = [
  'client.action-id', 'client.action-unavailable', 'client.browser-only', 'client.command-unavailable',
  'client.content-digest', 'client.document-erased', 'client.document-erasure-pending', 'client.document-not-ready',
  'client.document-rejected', 'client.document-suspended', 'client.file-too-large', 'client.file-type',
  'client.inputs-not-readable', 'client.invalid-interval', 'client.invalid-timeout', 'client.link-operation',
  'client.read-after-write', 'client.stale-copy', 'client.unknown-operation', 'client.unknown-policy',
  'client.unknown-slot', 'client.upload-path', 'client.wait-timeout',
]

const sourceOf = (name: string) => readFileSync(new URL(`../tasks/${name}.ts`, import.meta.url), 'utf8')

test('the table has a sentence for every code the helpers raise', () => {
  for (const code of helperCodes) {
    assert.ok(Object.hasOwn(clientSentences, code), `${code} has no sentence`)
    assert.notEqual(clientSentences[code], '')
  }
})

test('the code list matches the codes written in the helper sources', () => {
  const found = new Set<string>()
  for (const name of ['files', 'proposals']) {
    for (const [code] of sourceOf(name).matchAll(/client\.[a-z]+(?:-[a-z]+)*/gu)) found.add(code)
  }
  // `client.call` and `client.list` are method calls on the generated client, and `client.document` is the
  // start of the status-built codes.
  const codes = [...found].filter(code => !/^client\.(call|list\w*)$/u.test(code) && code !== 'client.document')
  const statuses = /UNUSABLE_STATUSES: string\[\] = \[([^\]]*)\]/u.exec(sourceOf('files'))![1]!
    .split(',').map(item => `client.document-${item.trim().replaceAll("'", '')}`)
  assert.deepEqual([...new Set([...codes, ...statuses])].sort(), [...helperCodes].sort())
})

test('each sentence in the table is plain words: no product name, quoted value, digit or developer instruction', () => {
  for (const [key, sentence] of Object.entries(clientSentences)) {
    assert.match(sentence, /^[A-Z][^"`'\d]*\.$/u, `${key}: ${sentence}`)
    assert.doesNotMatch(sentence, /\b(register|registry|BReg|Document Store|Proposal|API|client|policy|slot|SHA|digest|option|timeout)\b/iu, `${key}: ${sentence}`)
  }
})

test('the table holds no problem code that arrives on the wire', () => {
  assert.ok(!Object.hasOwn(clientSentences, 'attachment.required'))
  for (const key of Object.keys(clientSentences)) {
    assert.match(key, /^(?:[^.]+$|(?:client|availability|proposal\.status)\.[^.]+$)/u)
  }
})

for (const code of helperCodes) {
  test(`describeError shows the table sentence for ${code} and never its detail`, () => {
    const detail = 'Unknown document policy "licence-evidence". Known policies: a, b. Pass timeoutMs 12 ms.'
    const error = refusal(code, detail, { slot: 'diploma', operation: 'revise' })
    assert.equal(error.raisedByClient, true)
    assert.equal(error.detail, detail)
    const sentence = describeError(error)
    assert.equal(sentence, clientSentences[code])
    assert.ok(!sentence.includes('licence-evidence') && !sentence.includes('diploma'))
  })

  test(`a replaced table changes the sentence for ${code}`, () => {
    const error = refusal(code, 'Developer detail.')
    assert.equal(describeError(error, { clientSentences: { [code]: 'Dans votre langue.' } }), 'Dans votre langue.')
  })
}

test('an unknown helper code falls back to the generic sentence', () => {
  assert.equal(describeError(refusal('client.something-new', 'Detail.')), clientFallbackSentence)
})

test('the wait timeout does not claim the document was not ready, since every read may have failed in transit', () => {
  assert.doesNotMatch(clientSentences['client.wait-timeout']!, /not ready/u)
  assert.match(clientSentences['client.wait-timeout']!, /Try again/u)
})

test('a replaced fallback changes the sentence for a code the table lacks', () => {
  const error = refusal('client.something-new', 'Detail.')
  assert.equal(describeError(error, { clientSentences: { 'client.fallback': 'Autre chose.' } }), 'Autre chose.')
  assert.equal(describeError(error, { clientSentences: { 'client.fallback': '' } }), clientFallbackSentence)
})

test('the generic sentence names no module and no value', () => {
  assert.match(clientFallbackSentence, /^[A-Z][^"`'\d]*\.$/u)
})

test('the helpers re-export the can.* reason sentences', async () => {
  const { availabilityMessages: reexported } = await import('../tasks/proposals.ts')
  assert.equal(reexported, availabilityMessages)
})

// One words table: the same `clientSentences` reaches the `can.*` messages and describeError.
test('a replaced table reaches every can.* message, as the same table reaches describeError', () => {
  const clientSentences = Object.fromEntries([...Object.keys(availabilityMessages), 'available', 'unavailable'].map(key => [key, `Replaced ${key}.`]))
  const p = proposalFromServed(fixture('proposal-submitted'), { clientSentences })
  assert.equal(p.can.edit.available, false)
  for (const [name, view] of Object.entries(p.can)) assert.match(view.message, /^Replaced /u, `${name}: ${view.message}`)
  const served = fixture('proposal-draft')
  assert.equal(proposalFromServed(served, { clientSentences }).can.submit.message, 'Replaced available.')
  const changed = { ...served, blockedReason: 'package-changed' as const }
  assert.equal(proposalFromServed(changed, { clientSentences }).can.rebase.message, 'Replaced rebase.')
  assert.notEqual(proposalFromServed(changed).can.rebase.message, 'Replaced rebase.')
  const reasonless = draftWithSubmit({ available: false })
  assert.equal(proposalFromServed(reasonless, { clientSentences }).can.submit.message, 'Replaced unavailable.')
  const unknown = draftWithSubmit({ available: false, reason: 'something-new' })
  assert.equal(proposalFromServed(unknown, { clientSentences }).can.submit.message, 'Replaced unavailable.')
})

test('proposalCommands takes the table, so what it reads and what describeError shows agree', async () => {
  const doc = fixture('proposal-draft')
  const commands = proposalCommands({ call: async () => ({ data: doc }) }, { accessProfile: 'facility-correction-author', clientSentences: { available: 'Oui.' } })
  const p = await commands.get('prop-1')
  assert.equal(p.can.submit.message, 'Oui.')
  const { items } = await proposalCommands({ call: async () => ({ data: { items: [doc] } }) }, { accessProfile: 'x', clientSentences: { available: 'Oui.' } }).list()
  assert.equal(items[0]!.can.submit.message, 'Oui.')
})

test('a prototype key as a served reason gets the unavailable sentence, not a function', () => {
  const p = proposalFromServed(draftWithSubmit({ available: false, reason: 'constructor' }))
  assert.equal(p.can.submit.message, clientSentences['unavailable'])
})

// client.command-unavailable names the step the person can take, from the served reason.
test('client.command-unavailable shows the sentence for the served reason, and the generic one otherwise', async () => {
  const commandFailure = async (served: ServedProposal) => {
    const commands = proposalCommands({ call: async () => ({ data: served }) }, { accessProfile: 'facility-correction-author' })
    return commands.submit(proposalFromServed(served)).then(() => assert.fail('expected a refusal'), (e: unknown) => e)
  }
  const stale = await commandFailure(draftWithSubmit({ available: false, reason: 'package-changed', recovery: 'rebase' }))
  assert.equal((stale as RegistryError).code, 'client.command-unavailable')
  assert.equal(describeError(stale), availabilityMessages['package-changed'])
  assert.equal(describeError(stale, { clientSentences: { 'package-changed': 'Mettez a jour.' } }), 'Mettez a jour.')
  const unknown = await commandFailure(draftWithSubmit({ available: false, reason: 'something-new' }))
  assert.equal(describeError(unknown), clientSentences['client.command-unavailable'])
  const missing = fixture('proposal-draft')
  delete missing.links['submit']
  assert.equal(describeError(await commandFailure(missing)), availabilityMessages['not-offered'])
})

test('client.command-unavailable never takes a client. key or a prototype key from the reason', () => {
  for (const reason of ['client.stale-copy', 'constructor', '__proto__', 'client.fallback']) {
    const error = refusal('client.command-unavailable', 'Detail.', { reason })
    assert.equal(describeError(error), clientSentences['client.command-unavailable'], reason)
  }
})

test('a reason sentence is shown only for an error the client raised', () => {
  const wire = new RegistryError({ kind: 'refused', reason: 'status', status: 409, outcomeUnknown: false, problem: { code: 'client.command-unavailable', reason: 'package-changed' } })
  assert.notEqual(describeError(wire), availabilityMessages['package-changed'])
})

test('a helper cannot let extra members replace the code or detail', () => {
  const error = refusal('client.file-type', 'Real detail.', { code: 'client.stale-copy', detail: 'Other.' })
  assert.equal(error.code, 'client.file-type')
  assert.equal(error.detail, 'Real detail.')
})

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { clientSentences, pages, type Page } from '../core.ts'
import {
  createRegistryClient as facility, type FacilityProposal, type ProposalListRow, type ProposalSlot, type ProposalStatus,
} from '../generated/services/breg-facility-documents-casework-evidence.ts'
import { createRegistryClient as minimal, createRegistryServerClient } from '../generated/services/breg-minimal-casework.ts'
import * as minimalContract from '../generated/breg-minimal.ts'
import type { Client as Licence } from './fixtures/breg-list.ts'

const baseUrl = 'https://registry.example.org'
const contactId = '00000000-0000-4000-8000-000000000001'
const input = { contactId, email: 'alice@example.org' }
const preconditions = { contactId: { ifMatch: '"record-1"' } }

test('generated invoke fills an undefined profile and preserves an explicit profile', async () => {
  const profiles: (string | null)[] = []
  const client = minimal({ baseUrl, profile: 'directory-editor', fetch: async url => {
    profiles.push(new URL(String(url)).searchParams.get('accessProfile'))
    return Response.json({})
  } })
  await assert.rejects(client.directory.invoke('update-contact-email', input, { preconditions }))
  await assert.rejects(client.directory.invoke('update-contact-email', input, { preconditions, accessProfile: 'explicit-profile' as never }))
  assert.deepEqual(profiles, ['directory-editor', 'explicit-profile'])
})

test('the register module exports its published profiles and availability reasons', () => {
  assert.deepEqual(minimalContract.profiles, ['directory-editor'])
  assert.deepEqual(Object.keys(minimalContract.reasons).sort(), ['guard-not-satisfied', 'input-required', 'not-disclosed'])
  assert.equal(minimalContract.reasons['not-disclosed'], 'It is unclear whether this action is available.')
})

for (const { answer, reason, requestInput, options, extra } of [
  { answer: { available: true, observedRevision: 1 }, reason: 'Available.', requestInput: input },
  { answer: { available: false, observedRevision: 1, reason: 'guard-not-satisfied', recovery: 'none', guardLabel: 'Untrusted text' },
    reason: 'The action is not possible in the current state.', requestInput: input },
  { answer: { available: false, observedRevision: 1, reason: 'guard-not-satisfied', recovery: 'none',
      guardLabel: 'Untrusted text', guardReason: 'contact-inactive' },
    reason: 'Only active contacts can be edited.', requestInput: input,
    options: { guardLabels: { 'contact-inactive': 'Only active contacts can be edited.' },
      clientSentences: { 'availability.guard-not-satisfied': 'Generic refusal.' } },
    extra: { guardReason: 'contact-inactive' } },
  { answer: { available: null, observedRevision: 1, reason: 'input-required', recovery: 'correct-input', missingInputs: ['email'] },
    reason: 'Complete the required fields to check whether this action is available.',
    requestInput: { contactId }, extra: { missingInputs: ['email'] } },
  { answer: { available: null, observedRevision: null, reason: 'not-disclosed', recovery: 'none' },
    reason: 'Ask your supervisor.', requestInput: { contactId },
    options: { clientSentences: { 'availability.not-disclosed': 'Ask your supervisor.' } } },
]) {
  test('generated availability presents the register answer: ' + reason, async () => {
    let sent = false
    const client = minimal({ baseUrl, profile: 'directory-editor', fetch: async (url, init) => {
      assert.equal(String(url), baseUrl + '/v1/actions/update-contact-email/availability?accessProfile=directory-editor')
      assert.equal(init?.method, 'POST')
      assert.deepEqual(JSON.parse(String(init?.body)), { targetInput: 'contactId', input: requestInput })
      assert.equal(new Headers(init?.headers).get('Idempotency-Key'), null)
      sent = true
      return Response.json({ availability: answer })
    } })
    assert.deepEqual(await client.directory.available('update-contact-email', requestInput, options), { available: answer.available, reason, ...extra })
    assert.ok(sent)
  })
}

test('service Proposal start and attach keep the existing HTTP exchange', async () => {
  const draft = JSON.parse(readFileSync(new URL('./fixtures/tasks/proposal-draft-optional.json', import.meta.url), 'utf8'))
  const attached = JSON.parse(readFileSync(new URL('./fixtures/tasks/proposal-draft-attached.json', import.meta.url), 'utf8'))
  const requests: Array<{ method: string; path: string; query: string; headers: Headers; body: RequestInit['body'] }> = []
  let view = draft
  const client = facility({ baseUrl, fetch: async (url, init) => {
    const address = new URL(String(url))
    const method = init?.method ?? 'GET'
    requests.push({ method, path: address.pathname, query: address.search, headers: new Headers(init?.headers), body: init?.body })
    if (method === 'PATCH') view = attached
    return Response.json(view, { status: method === 'POST' ? 201 : 200 })
  } })
  const proposal = await client.facility.proposals.start('correct-address', { city: 'Springfield' }, { idempotencyKey: 'start-key' })
  const file = new Blob(['fixture'], { type: 'application/pdf' })
  await client.facility.proposals.attach(proposal, 'supporting-document', file)
  assert.deepEqual(requests.map(({ method, path }) => [method, path]), [
    ['POST', '/v1/actions/correct-address/proposals'],
    ['GET', '/v1/proposals/prop-1'],
    ['PATCH', '/v1/proposals/prop-1/attachments/supporting-document'],
    ['GET', '/v1/proposals/prop-1'],
  ])
  assert.ok(requests.every(({ query }) => query === '?accessProfile=facility-correction-author'))
  assert.deepEqual(JSON.parse(String(requests[0]?.body)), { input: { city: 'Springfield' } })
  assert.equal(requests[0]?.headers.get('Idempotency-Key'), 'start-key')
  assert.equal(requests[2]?.headers.get('If-Match'), '"etag-3"')
  assert.equal(requests[2]?.body, file)
})

test('the words table covers every Proposal status', () => {
  const statuses = {
    draft: true, 'awaiting-party': true, 'in-review': true, approved: true,
    processing: true, applied: true, rejected: true, cancelled: true,
  } satisfies Record<ProposalStatus, true>
  for (const status of Object.keys(statuses)) assert.ok(clientSentences['proposal.status.' + status], status)
})

test('page mode resolves paths on its origin and a server without an origin requires an absolute base', async () => {
  const urls: string[] = []
  const fetch: typeof globalThis.fetch = async url => {
    urls.push(String(url))
    return Response.json({})
  }
  const location = Object.getOwnPropertyDescriptor(globalThis, 'location')
  Object.defineProperty(globalThis, 'location', { value: { origin: baseUrl }, configurable: true })
  try {
    for (const address of ['/registry', baseUrl + '/registry']) {
      await assert.rejects(minimal({ baseUrl: address, fetch }).directory.call('records.contact.list'))
    }
  } finally {
    if (location) Object.defineProperty(globalThis, 'location', location)
    else Reflect.deleteProperty(globalThis, 'location')
  }
  assert.throws(() => createRegistryServerClient({ baseUrl: '/registry', token: () => 'fixture' }), TypeError)
  await assert.rejects(createRegistryServerClient({ baseUrl: baseUrl + '/registry', token: () => 'fixture', fetch }).directory.call('records.contact.list'))
  assert.deepEqual(urls, Array(3).fill(baseUrl + '/registry/v1/records/contacts'))
})

type IsAny<T> = 0 extends (1 & T) ? true : false

export async function strictPageTypes(licence: Licence, proposal: FacilityProposal, listRow: ProposalListRow, slot: ProposalSlot) {
  const client = minimal({ baseUrl })
  const { available, reason, missingInputs } = await client.directory.available('update-contact-email', { contactId })
  const missing: ('contactId' | 'email')[] | undefined = missingInputs
  // @ts-expect-error the default must be a published register profile
  minimal({ baseUrl, profile: 'alternate-default' })
  // @ts-expect-error the server default must be a published register profile
  createRegistryServerClient({ baseUrl, profile: 'alternate-default', token: () => 'fixture' })
  const offered: boolean | null = available
  const words: string = reason
  // @ts-expect-error the availability input requires contactId
  await client.directory.available('update-contact-email', { email: input.email })
  // @ts-expect-error only actions with an availability operation are accepted
  await client.directory.available('register-contact', {})
  const facilities = facility({ baseUrl })
  // @ts-expect-error a reviewed Action has no availability operation
  await facilities.facility.available('correct-address', { city: 'Springfield' })
  const draft = await facilities.facility.proposals.start('correct-address', { city: 'Springfield' })
  const file = new Blob()
  await facilities.facility.proposals.attach(draft, 'supporting-document', file)
  const existing = await facilities.facility.proposals.get('prop-1')
  // @ts-expect-error narrow the Action before attaching to its slot
  await facilities.facility.proposals.attach(existing, 'supporting-document', file)
  // @ts-expect-error narrow the Action before downloading from its slot
  await facilities.facility.proposals.download(existing, 'supporting-document')
  const files = { 'supporting-document': file }
  // @ts-expect-error narrow the Action before resubmitting files for its slot
  await facilities.facility.proposals.resubmit(existing, { files })
  await facilities.facility.proposals.resubmit(existing, { changes: { city: 'Springfield' } })
  if (existing.actionId === 'correct-address') {
    await facilities.facility.proposals.attach(existing, 'supporting-document', file)
    const edited = await facilities.facility.proposals.edit(existing, { city: 'Springfield' })
    await facilities.facility.proposals.download(edited, 'supporting-document')
    // @ts-expect-error download accepts the slots declared for this Action
    await facilities.facility.proposals.download(existing, 'other-document')
    await facilities.facility.proposals.resubmit(existing, { files: { 'supporting-document': file } })
    // @ts-expect-error resubmit accepts the slots declared for this Action
    await facilities.facility.proposals.resubmit(existing, { files: { 'other-document': file } })
  }
  for (const row of (await facilities.facility.proposals.list()).items) {
    if (row.actionId === 'correct-address') {
      await facilities.facility.proposals.attach(row, 'supporting-document', file)
    }
  }
  // @ts-expect-error only the declared slot is accepted
  await facilities.facility.proposals.attach(draft, 'other-document', file)
  const deactivate = await facilities.facility.proposals.start('deactivate-facility')
  // @ts-expect-error this Action has no supporting-document slot
  await facilities.facility.proposals.attach(deactivate, 'supporting-document', file)
  // @ts-expect-error this Action has no slot to download from
  await facilities.facility.proposals.download(deactivate, 'supporting-document')
  // @ts-expect-error this Action accepts no resubmission files
  await facilities.facility.proposals.resubmit(deactivate, { files: { 'supporting-document': file } })
  // @ts-expect-error the Action input does not have an email field
  await facilities.facility.proposals.start('correct-address', { email: 'alice@example.org' })
  // @ts-expect-error an immediate Action does not start a Proposal
  await facilities.facility.proposals.start('register-facility', {})

  const walk = pages(async (): Promise<Page<string>> => ({ items: ['row'], nextCursor: null }))
  const { value } = await walk.next()
  const typed: IsAny<typeof value> = false
  const item: string | undefined = value?.items[0]

  const row = (await licence.list('licence', { accessProfile: 'licence-officer' })).items[0]!
  const read = await licence.read('licence', 'L-1')
  const listNumber: string = row.data.licenceNumber
  const readNumber: string = read.data.licenceNumber
  // @ts-expect-error optional fields may be omitted from list rows
  const listName: string = row.data.holderName
  // @ts-expect-error optional fields may be omitted from reads
  const readName: string = read.data.holderName
  return { offered, words, missing, typed, item, listNumber, readNumber, listName, readName, proposal, listRow, slot }
}

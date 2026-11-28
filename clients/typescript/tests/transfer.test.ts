import test from 'node:test'
import assert from 'node:assert/strict'
import { Transport, type Operation } from '../core.ts'
import { Client as Documents } from '../generated/documents.ts'
import { Client as Facility } from '../generated/breg-facility.ts'

const baseUrl = 'https://registry.example.org'
const download = { path: { documentId: 'd', versionId: 'v' } }
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

// Sends `count` chunks, waiting `gap` milliseconds before each, then ends. With `stallAfter`
// it stops sending after that many chunks and never ends.
function trickle(count: number, gap: number, size = 1024, stallAfter = Infinity) {
  let sent = 0
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (sent >= stallAfter) return new Promise<void>(() => {})
      await delay(gap)
      if (sent === count) { controller.close(); return }
      sent++
      controller.enqueue(new Uint8Array(size).fill(sent))
    },
  })
}

test('a slow but moving download is not cut by the deadline, which resets while bytes move', async () => {
  const documents = new Documents({ baseUrl, token: () => 'fixture', timeoutMs: 200,
    fetch: async () => new Response(trickle(15, 20), { headers: { 'Content-Type': 'application/pdf' } }) })
  const started = Date.now()
  const { data } = await documents.call('downloadDocumentVersion', download)
  assert.ok(Date.now() - started > 200, 'the transfer outlasted one deadline')
  assert.equal(data.bytes.length, 15 * 1024)
  assert.equal(data.mediaType, 'application/pdf')
})

test('a download that stops moving times out after the idle deadline', async () => {
  const documents = new Documents({ baseUrl, token: () => 'fixture', timeoutMs: 100,
    fetch: async () => new Response(trickle(15, 5, 1024, 3), { headers: { 'Content-Type': 'application/pdf' } }) })
  await assert.rejects(documents.call('downloadDocumentVersion', download), { reason: 'timeout', status: 200 })
})

test('a JSON call keeps its whole-call deadline even while bytes move', async () => {
  const json: Operation = { method: 'GET', path: '/v1/items', responses: { 200: [{ mediaType: 'application/json', mode: 'json' }] } }
  const transport = new Transport({ baseUrl, token: () => 'fixture', timeoutMs: 100,
    fetch: async () => new Response(trickle(15, 20, 1), { headers: { 'Content-Type': 'application/json' } }) })
  await assert.rejects(transport.call(json), { reason: 'timeout' })
})

test('a download is not cut by the client response cap and takes a per-call cap', async () => {
  const large = new Uint8Array(9 * 1024 * 1024).fill(7)
  const documents = new Documents({ baseUrl, token: () => 'fixture', maxResponseBytes: 128,
    fetch: async (url) => String(url).endsWith('/content')
      ? new Response(large, { headers: { 'Content-Type': 'application/octet-stream' } })
      : Response.json({ items: [], nextCursor: null, padding: 'x'.repeat(256) }) })
  const { data } = await documents.call('downloadDocumentVersion', download)
  assert.equal(data.bytes.length, large.length)
  await assert.rejects(documents.call('downloadDocumentVersion', { ...download, maxResponseBytes: 1024 }),
    { reason: 'too-large', kind: 'unexpected', status: 200 })
  await assert.rejects(documents.call('listDocuments', {} as never), { reason: 'too-large' })
  for (const maxResponseBytes of [0, 1.5, -1, Number.NaN]) {
    await assert.rejects(documents.call('downloadDocumentVersion', { ...download, maxResponseBytes }),
      { name: 'TypeError', message: 'Invalid response cap' })
  }
})

test('an upload accepts a Blob or a File and sends it as given', async () => {
  const bodies: unknown[] = []
  const documents = new Documents({ baseUrl, token: () => 'fixture', fetch: async (_url, init) => {
    bodies.push(init?.body)
    return new Response(null, { status: 503 })
  } })
  const blob = new Blob([Uint8Array.of(1, 2, 3)], { type: 'application/pdf' })
  const file = new File([Uint8Array.of(4, 5)], 'diploma.pdf', { type: 'application/pdf' })
  for (const body of [blob, file]) {
    await assert.rejects(documents.call('uploadDocumentContent', { path: { uploadId: 'u' }, body, contentType: 'application/pdf' }),
      { status: 503 })
  }
  assert.equal(bodies[0], blob)
  assert.equal(bodies[1], file)
  const attachments: unknown[] = []
  const facility = new Facility({ baseUrl, token: () => 'fixture', fetch: async (_url, init) => {
    attachments.push(init?.body)
    assert.equal(new Headers(init?.headers).get('content-type'), 'application/pdf')
    return new Response(null, { status: 503 })
  } })
  await assert.rejects(facility.call('proposals.attachments.supporting-document.patch', {
    path: { proposal_id: 'p' }, query: { accessProfile: 'facility-correction-author' }, headers: { 'If-Match': '"1"' }, body: file,
  }), { status: 503 })
  assert.equal(attachments[0], file)
  await assert.rejects(documents.call('uploadDocumentContent', { path: { uploadId: 'u' }, body: {} as never,
    contentType: 'application/pdf' }), { name: 'TypeError', message: 'Binary request body must be a Uint8Array, Blob or string' })
})

test('while an upload is sent, the wait for the answer grows with the body size', async () => {
  const slowAnswer = async () => { await delay(300); return new Response(null, { status: 503 }) }
  const documents = new Documents({ baseUrl, token: () => 'fixture', timeoutMs: 100, fetch: slowAnswer })
  const options = { path: { uploadId: 'u' }, contentType: 'application/pdf' }
  await assert.rejects(documents.call('uploadDocumentContent', { ...options, body: new Blob([Uint8Array.of(1)]) }),
    { status: 503 })
  await assert.rejects(documents.call('uploadDocumentContent', { ...options, body: new Uint8Array() }), { reason: 'timeout' })
})

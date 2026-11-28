import test, { type TestContext } from 'node:test'
import { make } from './helpers.ts'
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
  const documents = make(Documents, { baseUrl, token: () => 'fixture', timeoutMs: 200,
    fetch: async () => new Response(trickle(15, 20), { headers: { 'Content-Type': 'application/pdf' } }) })
  const started = Date.now()
  const { data } = await documents.call('downloadDocumentVersion', download)
  assert.ok(Date.now() - started > 200, 'the transfer outlasted one deadline')
  assert.equal(data.bytes.length, 15 * 1024)
  assert.equal(data.mediaType, 'application/pdf')
})

test('a download that stops moving times out after the idle deadline', async () => {
  const documents = make(Documents, { baseUrl, token: () => 'fixture', timeoutMs: 100,
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
  const documents = make(Documents, { baseUrl, token: () => 'fixture', maxResponseBytes: 128,
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
  const documents = make(Documents, { baseUrl, token: () => 'fixture', fetch: async (_url, init) => {
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
  const facility = make(Facility, { baseUrl, token: () => 'fixture', fetch: async (_url, init) => {
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
  const documents = make(Documents, { baseUrl, token: () => 'fixture', timeoutMs: 100, fetch: slowAnswer })
  const options = { path: { uploadId: 'u' }, contentType: 'application/pdf' }
  await assert.rejects(documents.call('uploadDocumentContent', { ...options, body: new Blob([Uint8Array.of(1)]) }),
    { status: 503 })
  await assert.rejects(documents.call('uploadDocumentContent', { ...options, body: new Uint8Array() }), { reason: 'timeout' })
})

const upload: Operation = {
  method: 'PUT', path: '/v1/upload', keyed: true, mutating: true, requestMediaType: 'application/octet-stream',
  responses: { 200: [{ mediaType: 'application/json', mode: 'json', validate: value => value === true }] },
}
const uploadBody = Uint8Array.of(1, 2, 3)
type Progress = [number, number | undefined]

class UploadRequest extends EventTarget {
  static requests: UploadRequest[] = []
  upload = new EventTarget()
  headers = new Headers()
  responseType = ''
  // Starts on, so a client that forgets to turn it off fails the assertion.
  withCredentials = true
  responseURL = ''
  responseHeaders = 'content-type: application/json\r\n'
  response = new ArrayBuffer(0)
  readyState = 0
  status = 0
  aborted = false
  method = ''
  url = ''
  body: unknown

  constructor() {
    super()
    UploadRequest.requests.push(this)
  }

  open(method: string, url: string) { this.method = method; this.url = url }
  setRequestHeader(name: string, value: string) { this.headers.set(name, value) }
  getAllResponseHeaders() { return this.responseHeaders }
  send(body: unknown) { this.body = body }
  abort() { this.aborted = true; this.dispatchEvent(new Event('abort')) }

  progress(target: EventTarget, loaded: number, total?: number) {
    target.dispatchEvent(Object.assign(new Event('progress'), { loaded, total, lengthComputable: total !== undefined }))
  }

  startAnswer(url = this.url, status = 200) {
    this.responseURL = url
    this.status = status
    this.readyState = 2
    this.dispatchEvent(new Event('readystatechange'))
  }

  finishAnswer(body = 'true') {
    this.response = new TextEncoder().encode(body).buffer
    this.dispatchEvent(new Event('load'))
  }
}

function withUploadRequest(context: TestContext) {
  UploadRequest.requests = []
  const log = context.mock.method(globalThis.console, 'error', () => {})
  const original = Object.getOwnPropertyDescriptor(globalThis, 'XMLHttpRequest')
  Object.defineProperty(globalThis, 'XMLHttpRequest', { value: UploadRequest, configurable: true })
  context.after(() => {
    if (original) Object.defineProperty(globalThis, 'XMLHttpRequest', original)
    else Reflect.deleteProperty(globalThis, 'XMLHttpRequest')
  })
  return log
}

test('page XHR sends the same request and reports ordered upload progress', async context => {
  const log = withUploadRequest(context)
  const seen: Progress[] = []
  const client = new Transport({ baseUrl, fetch: async () => { throw new Error('unexpected Fetch') } })
  const answer = client.call(upload, { body: uploadBody, idempotencyKey: 'upload-key', onProgress: (...args) => {
    seen.push(args)
    throw new Error('private callback data')
  } })
  const request = UploadRequest.requests[0]!
  assert.ok(request)
  assert.equal(request.method, 'PUT')
  assert.equal(request.url, baseUrl + '/v1/upload')
  assert.equal(request.responseType, 'arraybuffer')
  assert.equal(request.withCredentials, false)
  assert.equal(request.headers.get('Registry-Client'), 'page')
  assert.equal(request.headers.get('Idempotency-Key'), 'upload-key')
  assert.equal(request.headers.get('Content-Type'), 'application/octet-stream')
  assert.deepEqual(request.body, uploadBody)
  request.progress(request.upload, 1, 3)
  request.progress(request.upload, 2)
  request.upload.dispatchEvent(new Event('load'))
  request.startAnswer()
  request.finishAnswer()
  assert.equal((await answer).data, true)
  assert.deepEqual(seen, [[1, 3], [2, undefined], [3, 3]])
  assert.deepEqual(log.mock.calls.map(call => call.arguments), [['Registry progress callback failed.']])
})

test('page XHR reports the final upload value once when the last progress event already reached it', async context => {
  withUploadRequest(context)
  const seen: Progress[] = []
  const pending = new Transport({ baseUrl }).call(upload, { body: uploadBody, onProgress: (...args) => seen.push(args) })
  const request = UploadRequest.requests[0]!
  request.progress(request.upload, 3, 3)
  request.upload.dispatchEvent(new Event('load'))
  request.startAnswer()
  request.finishAnswer()
  await pending
  assert.deepEqual(seen, [[3, 3]])
})

test('page XHR aborts before opening and while an upload is in flight', async context => {
  withUploadRequest(context)
  const client = new Transport({ baseUrl })
  const options = { body: uploadBody, onProgress: () => {} }
  await assert.rejects(client.call(upload, { ...options, signal: AbortSignal.abort() }),
    { reason: 'aborted', outcomeUnknown: false })
  assert.equal(UploadRequest.requests.length, 0)
  const controller = new AbortController()
  const pending = client.call(upload, { ...options, signal: controller.signal })
  controller.abort()
  await assert.rejects(pending, { reason: 'aborted', outcomeUnknown: true })
  assert.equal(UploadRequest.requests[0]?.aborted, true)
})

test('page XHR allows more time for the upload and reverts to the call deadline after it', async context => {
  withUploadRequest(context)
  const client = new Transport({ baseUrl, timeoutMs: 25 })
  const pending = client.call(upload, { body: uploadBody, onProgress: () => {} })
  const request = UploadRequest.requests[0]!
  assert.ok(request)
  await delay(50)
  assert.equal(request.aborted, false)
  request.upload.dispatchEvent(new Event('load'))
  // The 1 s allowance for the upload ends at the upload, so the call fails near its own 25 ms deadline.
  const outcome = await Promise.race([pending.then(() => 'answered', (error: unknown) => error), delay(300).then(() => 'still waiting')])
  assert.deepEqual([(outcome as { reason?: string }).reason, (outcome as { outcomeUnknown?: boolean }).outcomeUnknown], ['timeout', true])
  assert.equal(request.aborted, true)
})

test('page XHR aborts answers over the cap during progress or at completion', async context => {
  withUploadRequest(context)
  const client = new Transport({ baseUrl })
  for (const streamed of [true, false]) {
    const pending = client.call(upload, { body: uploadBody, onProgress: () => {}, maxResponseBytes: 3 })
    const request = UploadRequest.requests.at(-1)!
    assert.ok(request)
    request.startAnswer()
    if (streamed) request.progress(request, 4, 4)
    else request.finishAnswer()
    await assert.rejects(pending, { reason: 'too-large', status: 200, outcomeUnknown: true })
    assert.equal(request.aborted, true)
  }
})

test('page XHR refuses a redirected answer with the same error as an opaque Fetch redirect', async context => {
  withUploadRequest(context)
  const client = new Transport({ baseUrl })
  const pending = client.call(upload, { body: uploadBody, onProgress: () => {} })
  const request = UploadRequest.requests[0]!
  assert.ok(request)
  request.startAnswer(baseUrl + '/elsewhere')
  request.finishAnswer()
  const opaqueRedirect = { type: 'opaqueredirect', status: 0, body: null, headers: new Headers() } as Response
  const fetchClient = new Transport({ baseUrl, fetch: async () => opaqueRedirect })
  const expected = { kind: 'unreachable', reason: 'status', status: undefined, outcomeUnknown: true }
  await assert.rejects(pending, expected)
  await assert.rejects(fetchClient.call(upload, { body: uploadBody }), expected)
})

test('server upload uses Fetch even with XHR available and reports one final value', async context => {
  withUploadRequest(context)
  const seen: Progress[] = []
  const client = new Transport({ baseUrl, token: () => 'fixture', fetch: async (_url, init) => {
    assert.equal(new Headers(init?.headers).get('Authorization'), 'Bearer fixture')
    return Response.json(true)
  } })
  const result = await client.call(upload, { body: uploadBody, onProgress: (...args) => seen.push(args) })
  assert.equal(result.data, true)
  assert.equal(UploadRequest.requests.length, 0)
  assert.deepEqual(seen, [[3, 3]])
})

test('Fetch download drops the declared total once more bytes arrive than it declared', async () => {
  const headers = { 'Content-Type': 'application/pdf', 'content-length': '2' }
  const documents = make(Documents, { baseUrl, fetch: async () => new Response(trickle(3, 1, 1), { headers }) })
  const seen: Progress[] = []
  await documents.call('downloadDocumentVersion', { ...download, onProgress: (...args) => seen.push(args) })
  assert.deepEqual(seen, [[1, 2], [2, 2], [3, undefined]])
})

test('Fetch download reports no progress for an answer that is not a success', async () => {
  const documents = make(Documents, { baseUrl, fetch: async () => new Response(trickle(2, 1, 1),
    { status: 500, headers: { 'Content-Type': 'application/pdf' } }) })
  const seen: Progress[] = []
  await assert.rejects(documents.call('downloadDocumentVersion', { ...download, onProgress: (...args) => seen.push(args) }),
    { status: 500 })
  assert.deepEqual(seen, [])
})

test('Fetch download reports each chunk with a plausible length or an unknown total', async () => {
  for (const length of ['3', undefined, '9007199254740992']) {
    const headers = new Headers({ 'Content-Type': 'application/pdf' })
    if (length !== undefined) headers.set('content-length', length)
    const documents = make(Documents, { baseUrl, fetch: async () => new Response(trickle(3, 1, 1), { headers }) })
    const seen: Progress[] = []
    await documents.call('downloadDocumentVersion', { ...download, onProgress: (...args) => seen.push(args) })
    assert.deepEqual(seen, [1, 2, 3].map(loaded => [loaded, length === '3' ? 3 : undefined]))
  }
})


const sessionHeaders = 'content-type: application/problem+json\r\nregistry-session-answer: 1\r\n'
const sessionType = 'https://id.registrystack.org/problems/registry-platform/session/'
const sessionBody = (kind: string, status: number) =>
  JSON.stringify({ title: 'Session', status, code: 'session.' + kind, type: sessionType + kind })

test('page XHR reads the session answers by header and type, and a product lookalike stays a product answer', async context => {
  withUploadRequest(context)
  const client = new Transport({ baseUrl })
  const run = async (status: number, headers: string, body: string) => {
    const pending = client.call(upload, { body: uploadBody, onProgress: () => {} })
    const request = UploadRequest.requests.at(-1)!
    request.responseHeaders = headers
    request.startAnswer(undefined, status)
    request.finishAnswer(body)
    return await pending.catch((error: unknown) => error) as { reason: string; outcomeUnknown: boolean }
  }
  const expired = await run(401, sessionHeaders, sessionBody('expired', 401))
  assert.deepEqual([expired.reason, expired.outcomeUnknown], ['sign-in-expired', false])
  const unavailable = await run(503, sessionHeaders, sessionBody('unavailable', 503))
  assert.deepEqual([unavailable.reason, unavailable.outcomeUnknown], ['status', false])
  const bare = 'content-type: application/problem+json\r\n'
  const lookalike401 = await run(401, bare, sessionBody('expired', 401))
  assert.equal(lookalike401.reason, 'configuration')
  const lookalike503 = await run(503, bare, sessionBody('unavailable', 503))
  assert.deepEqual([lookalike503.reason, lookalike503.outcomeUnknown], ['status', true])
})

test('page XHR caps a 401 by the client default when no per-call cap is given', async context => {
  withUploadRequest(context)
  const client = new Transport({ baseUrl, maxResponseBytes: 32 })
  const pending = client.call(upload, { body: uploadBody, onProgress: () => {} })
  const request = UploadRequest.requests[0]!
  request.responseHeaders = sessionHeaders
  request.startAnswer(undefined, 401)
  request.finishAnswer(sessionBody('expired', 401))
  await assert.rejects(pending, { reason: 'too-large', status: 401, outcomeUnknown: false })
})

test('page XHR maps a network error to an unreachable failure with an unknown write outcome', async context => {
  withUploadRequest(context)
  const pending = new Transport({ baseUrl }).call(upload, { body: uploadBody, onProgress: () => {} })
  UploadRequest.requests[0]!.dispatchEvent(new Event('error'))
  await assert.rejects(pending, { kind: 'unreachable', reason: 'network', outcomeUnknown: true })
})

const binaryUpload: Operation = { ...upload, responses: {
  200: [{ mediaType: 'application/octet-stream', mode: 'binary' }],
} }
const binaryHeaders = (extra = '') => 'content-type: application/octet-stream\r\n' + extra

test('page XHR reports download progress with the declared length, or an unknown total', async context => {
  withUploadRequest(context)
  for (const [extra, expected] of [
    ['content-length: 4\r\n', [[2, 4], [4, 4]]],
    ['', [[2, undefined], [4, undefined]]],
    ['content-length: 4\r\ncontent-encoding: gzip\r\n', [[2, undefined], [4, undefined]]],
    // More bytes than declared: the length is no longer a total.
    ['content-length: 3\r\n', [[2, 3], [4, undefined]]],
  ] as const) {
    const seen: Progress[] = []
    const pending = new Transport({ baseUrl }).call(binaryUpload, { body: uploadBody, onProgress: (...args) => seen.push(args) })
    const request = UploadRequest.requests.at(-1)!
    request.upload.dispatchEvent(new Event('load'))
    request.responseHeaders = binaryHeaders(extra)
    request.startAnswer()
    request.progress(request, 2)
    request.response = Uint8Array.of(1, 2, 3, 4).buffer
    request.dispatchEvent(new Event('load'))
    await pending
    assert.deepEqual(seen.slice(1), expected, extra)
  }
})

test('page XHR reports no download progress for an answer that is not a success', async context => {
  withUploadRequest(context)
  const seen: Progress[] = []
  const pending = new Transport({ baseUrl }).call(binaryUpload, { body: uploadBody, onProgress: (...args) => seen.push(args) })
  const request = UploadRequest.requests[0]!
  request.upload.dispatchEvent(new Event('load'))
  request.responseHeaders = binaryHeaders()
  request.startAnswer(undefined, 500)
  request.progress(request, 2)
  request.response = Uint8Array.of(1, 2).buffer
  request.dispatchEvent(new Event('load'))
  await assert.rejects(pending, { status: 500 })
  assert.deepEqual(seen, [[3, 3]])
})

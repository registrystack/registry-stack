import assert from 'node:assert/strict'
import { DeliveryError, verifyRequest } from '../../webhook.ts'

interface SharedVector {
  name: string
  keyHex: string
  previousKeyHex: string | null
  id: string
  timestamp: string
  body: string
  signature: string
  now: number
  expected: string
  keyPolicy: 'accepted' | 'below-minimum'
}

const shared: SharedVector[] = JSON.parse(Deno.readTextFileSync(new URL(
  '../../../../crates/registry-platform-crypto/tests/fixtures/standard-webhooks.json', import.meta.url,
)))
const fromHex = (value: string) => Uint8Array.from(value.match(/../gu) ?? [], pair => Number.parseInt(pair, 16))

const requestFor = (vector: SharedVector, extra: [string, string][] = [], body: BodyInit = vector.body) => {
  const headers = new Headers([
    ['webhook-id', vector.id], ['webhook-timestamp', vector.timestamp], ['webhook-signature', vector.signature],
    ['content-type', 'application/json'],
  ])
  for (const [name, value] of extra) headers.append(name, value)
  return new Request('https://function.example/hook', { method: 'POST', headers, body })
}
const optionsFor = (vector: SharedVector) => ({
  currentKey: fromHex(vector.keyHex),
  previousKey: vector.previousKeyHex === null ? undefined : fromHex(vector.previousKeyHex),
  eventIdMember: null,
  now: () => vector.now,
})

for (const vector of shared.filter(entry => entry.keyPolicy === 'accepted')) {
  Deno.test('verifyRequest on shared vector ' + vector.name, async () => {
    const verified = verifyRequest(requestFor(vector), optionsFor(vector))
    if (vector.expected === 'accepted') {
      assert.deepEqual(await verified, JSON.parse(vector.body))
    } else {
      await assert.rejects(verified, { name: 'DeliveryError', code: vector.expected })
    }
  })
}

const accepting = shared.find(entry => entry.expected === 'accepted' && entry.keyPolicy === 'accepted')!

Deno.test('verifyRequest refuses a stale delivery before it reads the body', async () => {
  const request = requestFor(accepting)
  await assert.rejects(
    verifyRequest(request, { ...optionsFor(accepting), now: () => accepting.now + 301 }),
    { code: 'stale-delivery' })
  assert.equal(request.bodyUsed, false)
})

Deno.test('verifyRequest refuses a signature header appended twice', async () => {
  await assert.rejects(
    verifyRequest(requestFor(accepting, [['webhook-signature', accepting.signature]]), optionsFor(accepting)),
    (error: unknown) => error instanceof DeliveryError && error.code === 'duplicate-header')
})

Deno.test('verifyRequest refuses a body that is not application/json', async () => {
  const request = new Request('https://function.example/hook', { method: 'POST', body: accepting.body, headers: {
    'webhook-id': accepting.id, 'webhook-timestamp': accepting.timestamp, 'webhook-signature': accepting.signature,
  } })
  await assert.rejects(verifyRequest(request, optionsFor(accepting)), { code: 'invalid-content-type' })
  assert.equal(request.bodyUsed, false)
})

Deno.test('verifyRequest refuses a body over 1 MiB while reading', async () => {
  const chunk = new Uint8Array(64 * 1024).fill(0x20)
  const endless = new ReadableStream<Uint8Array>({ pull(controller) { controller.enqueue(chunk) } })
  await assert.rejects(verifyRequest(requestFor(accepting, [], endless), optionsFor(accepting)),
    { name: 'DeliveryError', code: 'body-too-large' })
})

Deno.test('verifyRequest turns a failed body read into a fixed invalid-body error', async () => {
  const secret = 'contact alice@example.org'
  const failing = new ReadableStream<Uint8Array>({ pull(controller) { controller.error(new Error(secret)) } })
  await assert.rejects(verifyRequest(requestFor(accepting, [], failing), optionsFor(accepting)), (error: unknown) =>
    error instanceof DeliveryError && error.code === 'invalid-body' && error.cause === undefined
      && !String(error.stack).includes(secret))
})

Deno.test('verifyRequest reads the body stream once without a clone', async () => {
  const request = requestFor(accepting)
  const calls = { clone: 0, arrayBuffer: 0, text: 0, json: 0, blob: 0, body: 0 }
  for (const name of ['clone', 'arrayBuffer', 'text', 'json', 'blob'] as const) {
    const original = request[name].bind(request) as () => unknown
    Object.defineProperty(request, name, { value: () => { calls[name]++; return original() } })
  }
  const stream = request.body
  Object.defineProperty(request, 'body', { get: () => { calls.body++; return stream } })
  assert.deepEqual(await verifyRequest(request, optionsFor(accepting)), JSON.parse(accepting.body))
  assert.deepEqual(calls, { clone: 0, arrayBuffer: 0, text: 0, json: 0, blob: 0, body: 1 })
  assert.equal(request.bodyUsed, true)
})

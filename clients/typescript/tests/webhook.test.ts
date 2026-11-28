import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { DeliveryError, verifyDelivery, verifyRequest } from '../webhook.ts'
import { verifyMac } from '../webhook-mac.ts'

const vectors = JSON.parse(readFileSync(new URL('./webhook-vectors.json', import.meta.url), 'utf8'))
const key = (offset: number) => Uint8Array.from({ length: 32 }, (_, i) => i + offset)
const bytes = (text: string) => new TextEncoder().encode(text)
const headers = (signature: string): [string, string][] => [
  ['webhook-id', 'msg_fixture'], ['webhook-timestamp', '1614265330'],
  ['webhook-signature', signature], ['content-type', 'application/json'],
]
const maximumBodyBytes = 1_048_576

async function sign(key: Uint8Array, id: string, timestamp: string, body: Uint8Array): Promise<string> {
  const imported = await crypto.subtle.importKey('raw', Uint8Array.from(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const prefix = bytes(id + '.' + timestamp + '.')
  const content = new Uint8Array(prefix.length + body.length)
  content.set(prefix)
  content.set(body, prefix.length)
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', imported, content))
  return 'v1,' + btoa(String.fromCharCode(...mac))
}
const paddedBody = (size: number) => {
  const prefix = '{"id":"msg_fixture","pad":"'
  return bytes(prefix + 'a'.repeat(size - prefix.length - 2) + '"}')
}

test('published known answer through internal MAC', async () => {
  const raw = Uint8Array.from(atob('MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'), char => char.charCodeAt(0))
  const sig = Uint8Array.from(atob('g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE='), char => char.charCodeAt(0))
  assert.equal(await verifyMac(raw, sig, 'msg_p5jXN8AQM9LWM0D4loKWxJek', '1614265330',
    bytes('{"test": 2432232314}')), true)
})

test('official library vectors, time window, tampering and rotation', async () => {
  const delivery = headers(vectors.previous + ' ' + vectors.current)
  for (const delta of [-300, 300]) {
    const options = { currentKey: key(32), previousKey: key(0), now: () => 1614265330 + delta }
    assert.deepEqual(await verifyDelivery(delivery, bytes(vectors.body), options), { id: 'msg_fixture' })
    assert.deepEqual(await verifyDelivery(headers(vectors.previous), bytes(vectors.body), options), { id: 'msg_fixture' })
    await assert.rejects(verifyDelivery(delivery, bytes(vectors.body + ' '), options), { code: 'signature-mismatch' })
    await assert.rejects(verifyDelivery(delivery, bytes(vectors.body), { ...options, currentKey: key(64), previousKey: undefined }), { code: 'signature-mismatch' })
  }
  for (const delta of [-301, 301]) {
    await assert.rejects(verifyDelivery(delivery, bytes(vectors.body), {
      currentKey: key(32), now: () => 1614265330 + delta,
    }), { code: 'stale-delivery' })
  }
})

test('rejects malformed headers and invalid signed envelopes', async () => {
  const options = { currentKey: key(32), now: () => 1614265330 }
  for (const [signature, code] of [
    ['', 'malformed-signature'], ['v1', 'malformed-signature'],
    ['v1,AA==', 'malformed-signature'], [vectors.current + '\n', 'malformed-signature'], ['v2,skip', 'unsupported-version'],
    [Array(5).fill(vectors.current).join(' '), 'malformed-signature'],
  ]) {
    await assert.rejects(verifyDelivery(headers(signature!), bytes(vectors.body), options), { code })
  }
  const valid = headers(vectors.current)
  for (const invalid of ['01', '+1', '1\n', '9'.repeat(21)]) {
    const entries = headers(vectors.current)
    entries[1]![1] = invalid
    await assert.rejects(verifyDelivery(entries, bytes(vectors.body), options), { code: 'invalid-timestamp' })
  }
  for (const invalid of ['', 'contains.dot', 'with space', 'x'.repeat(257)]) {
    const entries = headers(vectors.current)
    entries[0]![1] = invalid
    await assert.rejects(verifyDelivery(entries, bytes(vectors.body), options), { code: 'invalid-id' })
  }
  await assert.rejects(verifyDelivery(valid.slice(1), bytes(vectors.body), options), { code: 'missing-header' })
  await assert.rejects(verifyDelivery([...valid, valid[0]!], bytes(vectors.body), options), { code: 'duplicate-header' })
  await assert.rejects(verifyDelivery(valid, bytes(vectors.body), { ...options, eventIdMember: 'eventId' }), { code: 'id-mismatch' })
  await assert.rejects(verifyDelivery(headers(vectors.array), bytes('[]'), options), { code: 'invalid-envelope' })
  await assert.rejects(verifyDelivery(valid, bytes(vectors.body), { ...options, currentKey: bytes('whsec_' + 'a'.repeat(32)) }), { code: 'invalid-key' })
})

test('mixed case and combined duplicates are handled by header name', async () => {
  const options = { currentKey: key(32), now: () => 1614265330 }
  const mixed = headers(vectors.current).map(([name, value]) =>
    [name.replace(/^webhook/u, 'WebHook'), value] as const)
  await verifyDelivery(mixed, bytes(vectors.body), options)
  for (const [index] of mixed.entries()) {
    const folded = mixed.map(([name, value], position) =>
      [name, position === index ? value + ', ' + value : value] as const)
    await assert.rejects(verifyDelivery(folded, bytes(vectors.body), options), { code: 'duplicate-header' })
  }
})

test('requires exactly one application/json content type', async () => {
  const options = { currentKey: key(32), now: () => 1614265330 }
  const valid = headers(vectors.current)
  await assert.rejects(verifyDelivery(valid.slice(0, 3), bytes(vectors.body), options), { code: 'missing-header' })
  for (const media of ['text/plain', 'application/json; charset=utf-8', 'Application/JSON', '']) {
    await assert.rejects(verifyDelivery([...valid.slice(0, 3), ['Content-Type', media]], bytes(vectors.body), options),
      { code: 'invalid-content-type' })
  }
  await assert.rejects(verifyDelivery([...valid, ['content-type', 'application/json']], bytes(vectors.body), options),
    { code: 'duplicate-header' })
})

test('refuses a correctly signed body over the shared 1 MiB bound', async () => {
  const options = { currentKey: key(32), now: () => 1614265330 }
  const atLimit = paddedBody(maximumBodyBytes)
  assert.equal(atLimit.length, maximumBodyBytes)
  const signed = async (body: Uint8Array) => [...headers(await sign(key(32), 'msg_fixture', '1614265330', body))]
  assert.equal((await verifyDelivery(await signed(atLimit), atLimit, options)).id, 'msg_fixture')
  const over = paddedBody(maximumBodyBytes + 1)
  await assert.rejects(verifyDelivery(await signed(over), over, options), { name: 'DeliveryError', code: 'body-too-large' })
})

test('rejects a malformed unknown entry even alongside a correct v1', async () => {
  const options = { currentKey: key(32), now: () => 1614265330 }
  for (const entry of ['v2,', ',opaque', 'v2']) {
    await assert.rejects(verifyDelivery(headers(vectors.current + ' ' + entry), bytes(vectors.body), options),
      { code: 'malformed-signature' })
  }
  await assert.rejects(verifyDelivery(headers(vectors.current), bytes(vectors.body),
    { ...options, currentKey: 'fixture' as never }), { code: 'invalid-key' })
  await assert.rejects(verifyDelivery(headers(vectors.current), 'fixture' as never, options), { code: 'invalid-body' })
  const unsafe = headers(vectors.current)
  unsafe[1]![1] = '9007199254740993'
  await assert.rejects(verifyDelivery(unsafe, bytes(vectors.body), { ...options, now: () => 9007199254740992 }),
    { code: 'invalid-timestamp' })
})

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

const shared: SharedVector[] = JSON.parse(readFileSync(new URL(
  '../../../crates/registry-platform-crypto/tests/fixtures/standard-webhooks.json', import.meta.url,
), 'utf8'))
const fromHex = (value: string) => Uint8Array.from(value.match(/../gu) ?? [], pair => Number.parseInt(pair, 16))

for (const vector of shared) {
  test('shared webhook vector ' + vector.name, async () => {
    const body = bytes(vector.body)
    const currentKey = fromHex(vector.keyHex)
    const verified = verifyDelivery([
      ['webhook-id', vector.id], ['webhook-timestamp', vector.timestamp], ['webhook-signature', vector.signature],
      ['content-type', 'application/json'],
    ], body, {
      currentKey, previousKey: vector.previousKeyHex === null ? undefined : fromHex(vector.previousKeyHex),
      eventIdMember: null, now: () => vector.now,
    })
    if (vector.keyPolicy === 'below-minimum') {
      await assert.rejects(verified, { code: 'invalid-key' })
      const mac = Uint8Array.from(atob(vector.signature.slice(3)), char => char.charCodeAt(0))
      assert.equal(await verifyMac(currentKey, mac, vector.id, vector.timestamp, body), vector.expected === 'accepted')
    } else if (vector.expected === 'accepted') {
      assert.deepEqual(await verified, JSON.parse(vector.body))
    } else {
      await assert.rejects(verified, { code: vector.expected })
    }
  })
}

const requestFor = (vector: SharedVector, extra: [string, string][] = [], body: BodyInit = vector.body) => {
  const init = new Headers([
    ['webhook-id', vector.id], ['webhook-timestamp', vector.timestamp], ['webhook-signature', vector.signature],
    ['content-type', 'application/json'],
  ])
  for (const [name, value] of extra) init.append(name, value)
  return new Request('https://function.example/hook', { method: 'POST', headers: init, body, duplex: 'half' } as RequestInit)
}
const requestOptions = (vector: SharedVector) => ({
  currentKey: fromHex(vector.keyHex),
  previousKey: vector.previousKeyHex === null ? undefined : fromHex(vector.previousKeyHex),
  eventIdMember: null,
  now: () => vector.now,
})

for (const vector of shared.filter(entry => entry.keyPolicy === 'accepted')) {
  test('verifyRequest on shared vector ' + vector.name, async () => {
    const verified = verifyRequest(requestFor(vector), requestOptions(vector))
    if (vector.expected === 'accepted') {
      assert.deepEqual(await verified, JSON.parse(vector.body))
    } else {
      await assert.rejects(verified, { name: 'DeliveryError', code: vector.expected })
    }
  })
}

test('verifyRequest refuses a stale delivery', async () => {
  const vector = shared.find(entry => entry.expected === 'accepted' && entry.keyPolicy === 'accepted')!
  await assert.rejects(verifyRequest(requestFor(vector), { ...requestOptions(vector), now: () => vector.now + 301 }),
    { code: 'stale-delivery' })
})

test('verifyRequest refuses a signature header appended twice', async () => {
  const vector = shared.find(entry => entry.expected === 'accepted' && entry.keyPolicy === 'accepted')!
  const request = requestFor(vector, [['webhook-signature', vector.signature]])
  await assert.rejects(verifyRequest(request, requestOptions(vector)), { code: 'duplicate-header' })
})

function instrument(request: Request) {
  const calls = { clone: 0, arrayBuffer: 0, text: 0, json: 0, blob: 0, body: 0 }
  for (const name of ['clone', 'arrayBuffer', 'text', 'json', 'blob'] as const) {
    const original = request[name].bind(request) as () => unknown
    Object.defineProperty(request, name, { value: () => { calls[name]++; return original() } })
  }
  const stream = request.body
  Object.defineProperty(request, 'body', { get: () => { calls.body++; return stream } })
  return calls
}

test('verifyRequest reads the body stream once without a clone', async () => {
  const vector = shared.find(entry => entry.expected === 'accepted' && entry.keyPolicy === 'accepted')!
  const request = requestFor(vector)
  const calls = instrument(request)
  assert.deepEqual(await verifyRequest(request, requestOptions(vector)), JSON.parse(vector.body))
  assert.deepEqual(calls, { clone: 0, arrayBuffer: 0, text: 0, json: 0, blob: 0, body: 1 })
  assert.equal(request.bodyUsed, true)
})

test('verifyRequest checks the headers and content type before it reads the body', async () => {
  const vector = shared.find(entry => entry.expected === 'accepted' && entry.keyPolicy === 'accepted')!
  const unsigned = new Request('https://function.example/hook', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: vector.body })
  await assert.rejects(verifyRequest(unsigned, requestOptions(vector)), { code: 'missing-header' })
  assert.equal(unsigned.bodyUsed, false)
  const text = new Request('https://function.example/hook', { method: 'POST', body: vector.body,
    headers: { 'webhook-id': vector.id, 'webhook-timestamp': vector.timestamp, 'webhook-signature': vector.signature } })
  assert.equal(text.headers.get('content-type'), 'text/plain;charset=UTF-8')
  await assert.rejects(verifyRequest(text, requestOptions(vector)), { code: 'invalid-content-type' })
  assert.equal(text.bodyUsed, false)
  const stale = requestFor(vector)
  await assert.rejects(verifyRequest(stale, { ...requestOptions(vector), now: () => vector.now + 301 }), { code: 'stale-delivery' })
  assert.equal(stale.bodyUsed, false)
})

test('verifyRequest refuses a body over 1 MiB by its length and while reading', async () => {
  const vector = shared.find(entry => entry.expected === 'accepted' && entry.keyPolicy === 'accepted')!
  const declared = requestFor(vector, [['content-length', String(maximumBodyBytes + 1)]])
  await assert.rejects(verifyRequest(declared, requestOptions(vector)), { name: 'DeliveryError', code: 'body-too-large' })
  assert.equal(declared.bodyUsed, false)
  let pulled = 0
  let cancelled = false
  const chunk = new Uint8Array(64 * 1024).fill(0x20)
  const endless = new ReadableStream<Uint8Array>({
    pull(controller) { pulled += chunk.length; controller.enqueue(chunk) },
    cancel() { cancelled = true },
  })
  await assert.rejects(verifyRequest(requestFor(vector, [], endless), requestOptions(vector)),
    { name: 'DeliveryError', code: 'body-too-large' })
  assert.ok(pulled <= maximumBodyBytes + 2 * chunk.length, String(pulled))
  assert.equal(cancelled, true)
})

test('verifyRequest turns a failed body read into a fixed invalid-body error', async () => {
  const vector = shared.find(entry => entry.expected === 'accepted' && entry.keyPolicy === 'accepted')!
  const secret = 'contact alice@example.org'
  const failing = new ReadableStream<Uint8Array>({ pull(controller) { controller.error(new Error(secret)) } })
  await assert.rejects(verifyRequest(requestFor(vector, [], failing), requestOptions(vector)), (error: unknown) => {
    assert.ok(error instanceof DeliveryError)
    assert.equal(error.code, 'invalid-body')
    assert.equal(error.message, 'invalid-body')
    assert.equal(error.cause, undefined)
    assert.ok(!JSON.stringify(error).includes(secret) && !String(error.stack).includes(secret))
    return true
  })
})

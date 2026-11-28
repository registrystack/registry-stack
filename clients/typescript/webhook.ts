import { verifyMac } from './webhook-mac.ts'

export type DeliveryErrorCode =
  | 'missing-header' | 'duplicate-header' | 'invalid-content-type' | 'invalid-id' | 'invalid-timestamp'
  | 'stale-delivery' | 'invalid-key' | 'unsupported-version' | 'malformed-signature'
  | 'signature-mismatch' | 'id-mismatch' | 'invalid-envelope' | 'invalid-body' | 'body-too-large'

export class DeliveryError extends Error {
  readonly code: DeliveryErrorCode
  constructor(code: DeliveryErrorCode) {
    super(code)
    this.name = 'DeliveryError'
    this.code = code
  }
}

export interface DeliveryOptions {
  currentKey: Uint8Array
  previousKey?: Uint8Array
  now?: () => number
  eventIdMember?: string | null
}

// The bound every Registry Stack verifier shares: MAX_BODY_BYTES in
// crates/registry-platform-crypto/src/delivery_signature.rs.
const maximumBodyBytes = 1_048_576
const base64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const headerNames = ['webhook-id', 'webhook-timestamp', 'webhook-signature', 'content-type'] as const

function readHeaders(headers: Iterable<readonly [string, string]>): [string, string, string] {
  const values = new Map<string, string>()
  for (const [name, value] of headers) {
    const lower = name.toLowerCase()
    if (!headerNames.some(header => header === lower)) continue
    if (values.has(lower) || value.includes(', ')) throw new DeliveryError('duplicate-header')
    values.set(lower, value)
  }
  const [id, timestamp, signature, contentType] = headerNames.map(name => values.get(name))
  if (id === undefined || timestamp === undefined || signature === undefined || contentType === undefined) {
    throw new DeliveryError('missing-header')
  }
  if (contentType !== 'application/json') throw new DeliveryError('invalid-content-type')
  return [id, timestamp, signature]
}

function decodeSignatures(header: string): Uint8Array<ArrayBuffer>[] {
  const entries = header.split(' ')
  if (entries.length > 4) throw new DeliveryError('malformed-signature')
  const signatures: Uint8Array<ArrayBuffer>[] = []
  for (const entry of entries) {
    const comma = entry.indexOf(',')
    if (comma < 1 || comma === entry.length - 1) throw new DeliveryError('malformed-signature')
    if (entry.slice(0, comma) !== 'v1') continue
    const value = entry.slice(comma + 1)
    if (value.length !== 44 || !/^[A-Za-z0-9+/]{43}=$/u.test(value)) throw new DeliveryError('malformed-signature')
    if ((base64.indexOf(value[42]!) & 3) !== 0) throw new DeliveryError('malformed-signature')
    const decoded = new Uint8Array(32)
    for (let index = 0; index < decoded.length; index++) {
      const bit = index * 8
      const symbol = Math.floor(bit / 6)
      const left = base64.indexOf(value[symbol]!)
      const right = base64.indexOf(value[symbol + 1]!)
      decoded[index] = ((left << 6) | right) >> (4 - bit % 6)
    }
    signatures.push(decoded)
  }
  if (signatures.length === 0) throw new DeliveryError('unsupported-version')
  return signatures
}

interface CheckedHeaders {
  id: string
  timestamp: string
  keys: Uint8Array[]
  signatures: Uint8Array<ArrayBuffer>[]
}

/** Every check that needs no body, so a refusal never reads one. */
function checkHeaders(headers: Iterable<readonly [string, string]>, options: DeliveryOptions): CheckedHeaders {
  const [id, timestamp, signature] = readHeaders(headers)
  if (id.length < 1 || id.length > 256 || /[^!-~]|\./u.test(id)) throw new DeliveryError('invalid-id')
  if (!/^(0|[1-9][0-9]{0,19})$/u.test(timestamp) || /\s/u.test(timestamp) || !Number.isSafeInteger(Number(timestamp))) {
    throw new DeliveryError('invalid-timestamp')
  }
  const now = (options.now ?? (() => Math.floor(Date.now() / 1000)))()
  if (!Number.isFinite(now) || Math.abs(now - Number(timestamp)) > 300) {
    throw new DeliveryError('stale-delivery')
  }
  const keys = [options.currentKey]
  if (options.previousKey !== undefined) keys.push(options.previousKey)
  for (const key of keys) {
    if (!(key instanceof Uint8Array) || key.length < 32 || key.length > 64 || key.subarray(0, 6).every((byte, index) => byte === 'whsec_'.charCodeAt(index))) {
      throw new DeliveryError('invalid-key')
    }
  }
  return { id, timestamp, keys, signatures: decodeSignatures(signature) }
}

async function checkBody(
  checked: CheckedHeaders, body: Uint8Array, options: DeliveryOptions,
): Promise<Record<string, unknown>> {
  if (body.length > maximumBodyBytes) throw new DeliveryError('body-too-large')
  const raw = Uint8Array.from(body)
  const matches = await Promise.all(checked.keys.flatMap(key =>
    checked.signatures.map(mac => verifyMac(key, mac, checked.id, checked.timestamp, raw))))
  if (!matches.some(Boolean)) throw new DeliveryError('signature-mismatch')
  let envelope: unknown
  try {
    envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw))
  } catch {
    throw new DeliveryError('invalid-envelope')
  }
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    throw new DeliveryError('invalid-envelope')
  }
  const record = envelope as Record<string, unknown>
  if (options.eventIdMember !== null) {
    const member = options.eventIdMember ?? 'id'
    if (!Object.hasOwn(record, member) || record[member] !== checked.id) throw new DeliveryError('id-mismatch')
  }
  return record
}

export async function verifyDelivery(
  headers: Iterable<readonly [string, string]>, body: Uint8Array, options: DeliveryOptions,
): Promise<Record<string, unknown>> {
  if (!(body instanceof Uint8Array)) throw new DeliveryError('invalid-body')
  return checkBody(checkHeaders(headers, options), body, options)
}

async function readBody(request: Request): Promise<Uint8Array> {
  const stream = request.body
  if (!stream) return new Uint8Array()
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  while (true) {
    let chunk: ReadableStreamReadResult<Uint8Array>
    try {
      chunk = await reader.read()
    } catch {
      // The read error can carry request data, so only the fixed code leaves this function.
      throw new DeliveryError('invalid-body')
    }
    if (chunk.done) break
    size += chunk.value.length
    if (size > maximumBodyBytes) {
      // The refusal is the answer. A cancel that fails has nothing to add to it.
      void reader.cancel().catch(() => {})
      throw new DeliveryError('body-too-large')
    }
    chunks.push(chunk.value)
  }
  const body = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.length
  }
  return body
}

/**
 * Verifies a delivery from a Fetch Request. Checks the headers and content type first,
 * then reads the body stream once, refusing more than 1 MiB.
 */
export async function verifyRequest(
  request: Request, options: DeliveryOptions,
): Promise<Record<string, unknown>> {
  const checked = checkHeaders(request.headers, options)
  const length = request.headers.get('content-length')
  if (length !== null && /^[0-9]+$/u.test(length) && Number(length) > maximumBodyBytes) {
    throw new DeliveryError('body-too-large')
  }
  return checkBody(checked, await readBody(request), options)
}

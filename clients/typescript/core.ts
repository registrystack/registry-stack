export { assertClientVersion } from './version.ts'

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

/**
 * The fixed header a page client sends on every call. The session part in front of a page
 * requires it on every route. A client with a token provider, which runs on a server, does
 * not send it. Its name and value live only here.
 */
export const registryClientHeader = { name: 'Registry-Client', value: 'page' } as const

export interface ClientOptions {
  baseUrl: string | URL
  profile?: string
  /**
   * Runs on each call for a bearer credential. Leave it out in a page whose session part
   * signs calls: the client then sends no `Authorization` and sends cookies to its own
   * origin only.
   */
  token?: () => string | undefined | Promise<string | undefined>
  allowInsecureHttp?: boolean
  timeoutMs?: number
  maxResponseBytes?: number
  fetch?: typeof fetch
}

export interface CallOptions {
  signal?: AbortSignal
  idempotencyKey?: string
  onProgress?: (loaded: number, total: number | undefined) => void
  /**
   * Largest answer body this call reads. A JSON or text call reads up to the client's
   * `maxResponseBytes` without it. A byte transfer has no default cap. A page 401 or 503 is read up to
   * the larger of this and the client's `maxResponseBytes`.
   */
  maxResponseBytes?: number
}

export interface RequestValues extends CallOptions {
  path?: object
  query?: object
  headers?: object
  body?: unknown
  accept?: string
  contentType?: string
}

export interface ResponseVariant {
  mediaType?: string
  mode: 'json' | 'empty' | 'binary' | 'text'
  validate?: (value: unknown) => boolean
}

export interface Operation {
  method: string
  path: string
  product?: string
  accessProfileParameter?: boolean
  accessProfileRequired?: boolean
  keyed?: boolean
  mutating?: boolean
  messaging?: boolean
  requiresExistingKey?: boolean
  signed?: boolean
  requestMediaType?: string
  requestMediaTypes?: string[]
  commaQuery?: string[]
  problemValidators?: Record<string, (value: unknown) => boolean>
  responses: Record<number, readonly ResponseVariant[]>
}

export interface Answer<T> {
  data: T
  status: number
  headers: Headers
  idempotencyKey?: string
}

export interface WireBytes<Media extends string = string> { bytes: Uint8Array; mediaType: Media }
export interface WireText<Media extends string = string> { text: string; mediaType: Media }

export type ErrorKind = 'refused' | 'unreachable' | 'unexpected'
export type ErrorReason = 'token' | 'input' | 'network' | 'timeout' | 'aborted'
  | 'too-large' | 'media' | 'schema' | 'unsafe-integer' | 'status' | 'stale' | 'sign-in-expired' | 'configuration'

interface ErrorInfo {
  product?: string
  /** Set by code that raises an error itself, never by an answer that arrived on the wire. */
  raisedByClient?: boolean
  reason: ErrorReason
  kind: ErrorKind
  status?: number
  problem?: Record<string, unknown>
  raw?: Uint8Array
  idempotencyKey?: string
  outcomeUnknown: boolean
  retryAfterSeconds?: number
}

// For developers, in `message` and `product`. The sentence a person reads names no module.
function configurationMessage(product = 'registry'): string {
  return `The ${product} service refused this page's session. Check the service configuration.`
}

export class RegistryError extends Error implements ErrorInfo {
  readonly product?: string
  /** True for an error the client raised itself, whose `client.` code and `detail` are its own words. */
  readonly raisedByClient: boolean
  readonly kind: ErrorKind
  readonly reason: ErrorReason
  readonly status?: number
  readonly problem?: Record<string, unknown>
  readonly #raw?: Uint8Array
  get raw(): Uint8Array | undefined { return this.#raw?.slice() }
  readonly idempotencyKey?: string
  readonly outcomeUnknown: boolean
  readonly retryAfterSeconds?: number
  readonly code?: string
  readonly detail?: string
  readonly traceId?: string

  constructor(info: ErrorInfo) {
    super(info.reason === 'configuration' ? configurationMessage(info.product) : 'Registry request ' + info.kind)
    this.name = 'RegistryError'
    this.product = info.product
    this.raisedByClient = info.raisedByClient === true
    this.kind = info.kind
    this.reason = info.reason
    this.status = info.status
    this.problem = info.problem
    this.#raw = info.raw
    this.idempotencyKey = info.idempotencyKey
    this.outcomeUnknown = info.outcomeUnknown
    this.retryAfterSeconds = info.retryAfterSeconds
    const { code, detail, traceId } = info.problem ?? {}
    this.code = typeof code === 'string' ? code : undefined
    this.detail = typeof detail === 'string' ? detail : undefined
    this.traceId = typeof traceId === 'string' ? traceId : undefined
  }
}

const invalidBase = () => new TypeError('Invalid registry base URL')

const tokenOverHttp = () => new TypeError('A client with a token needs an https base URL, or a loopback host.')

/**
 * A host that cannot be on the public internet: a private IP literal, or a single-label name such as a
 * container name on a compose network. The client does not resolve names, so a name is judged as written.
 * Link-local addresses are not private here: they are where cloud metadata lives.
 */
function privateHost(hostname: string): boolean {
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/u.exec(hostname)
  if (ipv4) {
    const first = Number(ipv4[1])
    const second = Number(ipv4[2])
    return first === 10 || first === 172 && second >= 16 && second <= 31 || first === 192 && second === 168
  }
  if (hostname.startsWith('[')) {
    const leading = hostname.slice(1).split(':', 1)[0]!
    const hextet = leading === '' ? 0 : Number.parseInt(leading, 16)
    return (hextet & 0xfe00) === 0xfc00
  }
  return !hostname.includes('.')
}

/**
 * The IPv4 address an IPv6 literal carries in its last 32 bits: the mapped (`::ffff:`), NAT64 (`64:ff9b::`) and
 * IPv4-compatible (`::`) forms, which the URL parser writes as two hex groups. An operating system sends a mapped
 * literal to the IPv4 address.
 */
function embeddedIpv4(hostname: string): string | undefined {
  const groups = /^\[(?:::ffff:|64:ff9b::|::)([0-9a-f]{1,4}):([0-9a-f]{1,4})\]$/u.exec(hostname)
  if (!groups) return undefined
  const high = Number.parseInt(groups[1]!, 16)
  const low = Number.parseInt(groups[2]!, 16)
  return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`
}

/** A literal no base may name under any scheme: cloud metadata, the "this network" block and multicast. */
function deniedHost(hostname: string): boolean {
  const embedded = embeddedIpv4(hostname)
  if (embedded !== undefined) return deniedHost(embedded)
  if (hostname === '[::]') return true
  const ipv4 = /^(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}$/u.exec(hostname)
  if (ipv4) {
    const first = Number(ipv4[1])
    return first === 0 || first >= 224 && first <= 239 || hostname === '169.254.169.254' || hostname === '100.100.100.200'
  }
  if (hostname.startsWith('[')) {
    const leading = hostname.slice(1).split(':', 1)[0]!
    return (leading !== '' && (Number.parseInt(leading, 16) & 0xff00) === 0xff00) || hostname === '[fd00:ec2::254]'
  }
  return false
}

function baseAddress(value: string | URL, allowInsecureHttp: boolean, hasToken: boolean): string {
  let input = String(value)
  // A path such as /registry resolves against the page origin where one exists.
  if (/^\/(?!\/)/u.test(input)) {
    const origin = (globalThis as { location?: { origin?: unknown } }).location?.origin
    if (typeof origin === 'string') input = origin + input
  }
  if (!/^https?:\/\/[^/]+/iu.test(input) || /[\s\\?#]/u.test(input) || /^https?:\/\/[^/]*@/iu.test(input)) {
    throw invalidBase()
  }
  const authorityAndPath = input.slice(input.indexOf('://') + 3)
  const slash = authorityAndPath.indexOf('/')
  // Dot segments, plain or percent-encoded, would move the base to another route prefix.
  if (authorityAndPath.includes('//') || slash >= 0 && authorityAndPath.slice(slash + 1).split('/')
    .some(segment => /^(?:\.|%2e){1,2}$/iu.test(segment))) {
    throw invalidBase()
  }
  let url: URL
  try {
    url = new URL(input)
  } catch {
    // The parser's own error can carry the rejected input, so it is replaced by the fixed one.
    throw invalidBase()
  }
  const loopback = url.hostname === 'localhost' || url.hostname === '[::1]' || /^127(\.\d{1,3}){3}$/u.test(url.hostname)
  if (deniedHost(url.hostname)) throw invalidBase()
  // A token is a credential, so it never crosses plain http beyond loopback. Without one (a page, or a signed
  // operation) the option admits a private host. A mapped loopback literal is not loopback.
  if (url.protocol === 'http:' && !loopback && hasToken) throw tokenOverHttp()
  const plainHttp = url.protocol === 'http:' && (loopback || allowInsecureHttp && privateHost(url.hostname))
  if (url.protocol !== 'https:' && !plainHttp || url.username || url.password) throw invalidBase()
  return url.href.replace(/\/+$/u, '')
}

class InputError extends TypeError {}

function endpoint(base: string, operation: Operation, values: RequestValues, profile: string | undefined): URL {
  const template = operation.path
  if (!/^\/(?!\/)[a-zA-Z0-9_./{}:-]+$/u.test(template) || template.split('/').some(part => part === '.' || part === '..')) {
    throw new InputError('Invalid operation path')
  }
  const url = new URL(base + template.replace(/\{([^{}]+)\}/gu, (_, name: string) => {
    const value = (values.path as Record<string, unknown> | undefined)?.[name]
    if (typeof value !== 'string' && typeof value !== 'number') throw new InputError('Missing path value')
    if (value === '' || value === '.' || value === '..' || typeof value === 'number' && (!Number.isFinite(value) || value < 0)) throw new InputError('Invalid path value')
    return encodeURIComponent(value)
  }))
  for (const [key, value] of Object.entries(values.query ?? {})) {
    const entries = Array.isArray(value) ? operation.commaQuery?.includes(key) ? [value.join(',')] : value : [value]
    for (const entry of entries) {
      if (entry !== undefined) url.searchParams.append(key, String(entry))
    }
  }
  if (operation.accessProfileParameter && !url.searchParams.has('accessProfile')) {
    if (profile !== undefined) url.searchParams.set('accessProfile', profile)
    else if (operation.accessProfileRequired) throw new InputError('This call needs an access profile')
  }
  return url
}

function mediaType(value: string | null): string {
  return (value ?? '').split(';', 1)[0]!.trim().toLowerCase()
}

export function isJsonMedia(value: string): boolean {
  return value === 'application/json' || /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+\+json$/iu.test(value)
}

function retryAfter(value: string | null): number | undefined {
  if (!value || !/^[0-9]+$/u.test(value)) return undefined
  const seconds = Number(value)
  return seconds >= 1 && seconds <= 86_400 ? seconds : undefined
}

function matchesTrace(headers: Headers, trace: unknown): boolean {
  const match = /^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$/u.exec(headers.get('traceparent') ?? '')
  return Boolean(match && match[1] === trace && !/^0+$/u.test(match[1]!) && !/^0+$/u.test(match[2]!))
}

function matchesMessagingProblem(headers: Headers, problem: Record<string, unknown>): boolean {
  return typeof problem.code === 'string' && matchesTrace(headers, problem.traceId) &&
    problem.type === 'https://id.registrystack.org/problems/registry-messaging/' + problem.code.replaceAll('.', '/')
}

function containsCredential(value: unknown, token: string): boolean {
  const pending = [value]
  while (pending.length) {
    const item = pending.pop()
    if (typeof item === 'string' && item.includes(token)) return true
    if (item && typeof item === 'object') {
      for (const [key, member] of Object.entries(item)) {
        if (key.includes(token)) return true
        pending.push(member)
      }
    }
  }
  return false
}

class UnsafeInteger extends Error {}

function decodeJson(bytes: Uint8Array): unknown {
  return JSON.parse(decoder.decode(bytes), (_key, value: unknown) => {
    if (typeof value === 'number' &&
        (!Number.isFinite(value) || Number.isInteger(value) && !Number.isSafeInteger(value))) {
      throw new UnsafeInteger()
    }
    return value
  })
}

function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason)
    signal.addEventListener('abort', abort, { once: true })
    if (signal.aborted) abort()
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort))
  })
}

class AnswerTooLarge extends Error {}
class RedirectedAnswer extends Error {}

type ResponseHead = Pick<Response, 'headers' | 'status'>
type Progress = NonNullable<CallOptions['onProgress']>

function progressReporter(callback: Progress): Progress {
  let reported = false
  return (loaded, total) => {
    try {
      callback(loaded, total)
    } catch {
      if (!reported) {
        reported = true
        console.error('Registry progress callback failed.')
      }
    }
  }
}

function responseLength(headers: Headers): number | undefined {
  const length = headers.get('content-length')
  const encoding = headers.get('content-encoding')
  if (!length || !/^[0-9]+$/u.test(length) || encoding && encoding.toLowerCase() !== 'identity') return undefined
  const total = Number(length)
  return Number.isSafeInteger(total) ? total : undefined
}

// The members of XMLHttpRequest the upload path uses. The code reads it through this type
// so it type-checks without a DOM library.
interface ProgressEventLike { loaded: number; total: number; lengthComputable: boolean }
interface XhrTarget {
  addEventListener(type: 'progress', listener: (event: ProgressEventLike) => void): void
  addEventListener(type: 'load' | 'readystatechange' | 'error' | 'abort', listener: () => void): void
}
interface XhrRequest extends XhrTarget {
  readonly upload: XhrTarget
  readonly readyState: number
  readonly status: number
  readonly response: unknown
  readonly responseURL: string
  responseType: string
  withCredentials: boolean
  open(method: string, url: string): void
  setRequestHeader(name: string, value: string): void
  getAllResponseHeaders(): string
  send(body?: RequestBody): void
  abort(): void
}
const xhrConstructor = (): (new () => XhrRequest) | undefined => {
  const found = (globalThis as { XMLHttpRequest?: unknown }).XMLHttpRequest
  return typeof found === 'function' ? found as new () => XhrRequest : undefined
}

function xhrBytes(Request: new () => XhrRequest, url: URL, method: string, headers: Headers, body: RequestBody,
    signal: AbortSignal, answerLimit: (head: ResponseHead) => number, progress: Progress,
    receive: (head: ResponseHead) => void, moved: () => void, download: boolean): Promise<Uint8Array> {
  let abort: (() => void) | undefined
  return new Promise<Uint8Array>((resolve, reject) => {
    const request = new Request()
    request.open(method, url.href)
    request.withCredentials = false
    request.responseType = 'arraybuffer'
    headers.forEach((value, name) => request.setRequestHeader(name, value))
    const size = bodySize(body)
    let sent = false
    let lastUploaded = -1
    let limit = Infinity
    let head: ResponseHead | undefined
    let lastDownloaded = 0

    const stop = (error: unknown) => {
      reject(error)
      request.abort()
    }
    abort = () => stop(signal.reason)
    const finishUpload = () => {
      if (sent) return
      sent = true
      moved()
      if (lastUploaded !== size) progress(size, size)
    }
    const receiveHead = () => {
      if (request.responseURL && request.responseURL !== url.href) throw new RedirectedAnswer()
      if (head || request.status === 0) return
      const receivedHeaders = new Headers()
      for (const line of request.getAllResponseHeaders().split('\r\n')) {
        const separator = line.indexOf(':')
        if (separator > 0) receivedHeaders.append(line.slice(0, separator), line.slice(separator + 1).trim())
      }
      head = { status: request.status, headers: receivedHeaders }
      receive(head)
      limit = answerLimit(head)
      moved()
    }
    const reportDownload = (loaded: number) => {
      if (!download || !head || head.status < 200 || head.status >= 300 || loaded <= lastDownloaded) return
      lastDownloaded = loaded
      const total = responseLength(head.headers)
      progress(loaded, total !== undefined && total >= loaded ? total : undefined)
    }
    request.upload.addEventListener('progress', event => {
      if (sent) return
      lastUploaded = event.loaded
      progress(event.loaded, event.lengthComputable ? event.total : event.loaded === size ? size : undefined)
    })
    request.upload.addEventListener('load', finishUpload)
    request.addEventListener('readystatechange', () => {
      if (request.readyState !== 2) return
      try { receiveHead() } catch (error) { stop(error) }
    })
    request.addEventListener('progress', event => {
      if (event.loaded > limit) stop(new AnswerTooLarge())
      else {
        moved()
        reportDownload(event.loaded)
      }
    })
    request.addEventListener('load', () => {
      try {
        receiveHead()
        if (!head) throw new Error('Registry request failed')
        const bytes = new Uint8Array(request.response as ArrayBuffer)
        if (bytes.length > limit) throw new AnswerTooLarge()
        finishUpload()
        reportDownload(bytes.length)
        resolve(bytes)
      } catch (error) {
        stop(error)
      }
    })
    request.addEventListener('error', () => reject(new Error('Registry request failed')))
    request.addEventListener('abort', () => reject(signal.reason))
    signal.throwIfAborted()
    signal.addEventListener('abort', abort, { once: true })
    try {
      request.send(body)
    } catch (error) {
      reject(error)
    }
  }).finally(() => { if (abort) signal.removeEventListener('abort', abort) })
}

/**
 * A byte transfer sends or answers with bytes rather than JSON: a request body that is not
 * JSON or form fields, or a success answer read as bytes.
 */
export function isTransfer(operation: Operation): boolean {
  const media = operation.requestMediaTypes ?? (operation.requestMediaType ? [operation.requestMediaType] : [])
  return media.some(entry => !isJsonMedia(mediaType(entry)) && mediaType(entry) !== 'application/x-www-form-urlencoded')
    || Object.entries(operation.responses).some(([status, variants]) =>
      Number(status) >= 200 && Number(status) < 300 && variants.some(variant => variant.mode === 'binary'))
}

// Fetch cannot report upload progress, so while a body is sent the wait for the answer
// grows by one second for each 16 KiB, an upload rate of 128 kbit/s.
const uploadAllowanceMs = (bytes: number) => Math.ceil(bytes / 16_384) * 1000
const longestTimer = 2_147_483_647

type RequestBody = string | Blob | Uint8Array<ArrayBuffer>

function bodySize(body: RequestBody | undefined): number {
  if (body === undefined) return 0
  if (typeof body === 'string') return new TextEncoder().encode(body).length
  if (body instanceof Blob) return body.size
  return body.length
}

async function readBytes(response: Response, maxBytes: number, signal: AbortSignal,
    moved?: () => void, progress?: Progress): Promise<Uint8Array> {
  if (!response.body) return new Uint8Array()
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  let total = progress ? responseLength(response.headers) : undefined
  try {
    while (true) {
      const chunk = await abortable(reader.read(), signal)
      if (chunk.done) break
      moved?.()
      size += chunk.value.length
      if (size > maxBytes) throw new AnswerTooLarge()
      if (total !== undefined && size > total) total = undefined
      progress?.(size, total)
      chunks.push(chunk.value)
    }
  } catch (error) {
    void reader.cancel().catch(() => {})
    throw error
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.length
  }
  return bytes
}

const decoder = new TextDecoder('utf-8', { fatal: true })

function parseProblem(raw: Uint8Array, media: string): Record<string, unknown> | undefined {
  if (media !== 'application/problem+json') return undefined
  try {
    const value = decodeJson(raw)
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const problem = value as Record<string, unknown>
      if (['type', 'title', 'code', 'detail', 'traceId'].every(key =>
        !Object.hasOwn(problem, key) || typeof problem[key] === 'string') &&
        (typeof problem.title === 'string' || typeof problem.code === 'string')) return problem
    }
  } catch (error) {
    if (error instanceof UnsafeInteger) throw error
    return undefined
  }
}

// The session service sets this header on its own answers, and the gateway removes it from every
// forwarded reply, so a product cannot produce it.
const sessionAnswerHeader = 'registry-session-answer'
const sessionProblemBase = 'https://id.registrystack.org/problems/registry-platform/session/'

/**
 * The session service's own answer: the status, the marker header, and a problem whose code,
 * status and type all name the same session answer. A product answer with the code alone is not.
 */
function isSessionProblem(raw: Uint8Array, media: string, headers: Headers, answer: 'expired' | 'unavailable'): boolean {
  if (media !== 'application/problem+json' || headers.get(sessionAnswerHeader) !== '1') return false
  try {
    const value = JSON.parse(decoder.decode(raw)) as unknown
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
    const problem = value as Record<string, unknown>
    return problem.code === 'session.' + answer && problem.status === (answer === 'expired' ? 401 : 503)
      && problem.type === sessionProblemBase + answer
  } catch {
    return false
  }
}

export class Transport {
  readonly #base: string
  readonly #options: ClientOptions
  readonly #timeout: number
  readonly #limit: number

  constructor(options: ClientOptions) {
    // One read of each option, so the check and the kept copy cannot disagree.
    const copy = { ...options }
    this.#base = baseAddress(copy.baseUrl, copy.allowInsecureHttp === true, copy.token !== undefined)
    this.#timeout = copy.timeoutMs ?? 10_000
    this.#limit = copy.maxResponseBytes ?? 8 * 1024 * 1024
    if (!Number.isSafeInteger(this.#timeout) || this.#timeout < 1 || this.#timeout > 2_147_483_647
        || !Number.isSafeInteger(this.#limit) || this.#limit < 1) throw new RangeError('Invalid transport bounds')
    this.#options = copy
  }

  get profile(): string | undefined { return this.#options.profile }

  register(routePrefix: string, profile = this.profile): Pick<Transport, 'call' | 'profile'> {
    if (routePrefix !== '' && (!/^\/(?!\/)[a-zA-Z0-9_./:-]+$/u.test(routePrefix)
      || routePrefix.includes('//') || routePrefix.split('/').some(part => part === '.' || part === '..'))) {
      throw new TypeError('Invalid register route prefix')
    }
    const base = this.#base + routePrefix.replace(/\/$/u, '')
    return { profile, call: (operation, values) => this.#call(base, profile, operation, values) }
  }

  call<T>(operation: Operation, values?: RequestValues): Promise<Answer<T>> {
    return this.#call(this.#base, this.profile, operation, values)
  }

  async #call<T>(base: string, profile: string | undefined, operation: Operation, values: RequestValues = {}): Promise<Answer<T>> {
    const deadline = new AbortController()
    // A JSON call has one deadline for the whole exchange. A byte transfer restarts it
    // while bytes move, so it fails only when the transfer stalls.
    const transfer = isTransfer(operation)
    let timer: ReturnType<typeof setTimeout> | undefined
    const wait = (ms: number) => {
      clearTimeout(timer)
      timer = setTimeout(() => deadline.abort(), Math.min(ms, longestTimer))
    }
    wait(this.#timeout)
    let response: ResponseHead | undefined
    let raw: Uint8Array | undefined
    let problem: Record<string, unknown> | undefined
    let idempotencyKey: string | undefined
    let token: string | undefined
    let dispatched = false
    let stage: ErrorReason = 'input'
    let callerSignal: AbortSignal | undefined
    let ownError: RegistryError | undefined
    const pageMode = this.#options.token === undefined && !operation.signed
    const failure = (kind: ErrorKind, reason: ErrorReason, notForwarded = false) => {
      const status = response?.status
      const outcomeUnknown = !notForwarded && operation.mutating === true && dispatched && (
        status === undefined || status === 0 || status >= 500 || status >= 200 && status < 300 ||
        (reason === 'timeout' || reason === 'aborted') && (status < 400 || status >= 500)
      )
      ownError = new RegistryError({
        kind, reason, status: status === 0 ? undefined : status, raw, problem,
        // Only the two failures a developer must route to a service name it.
        product: pageMode && status === 401 && (reason === 'configuration' || reason === 'too-large')
          ? operation.product ?? 'registry' : undefined,
        idempotencyKey: token && idempotencyKey?.includes(token) ? undefined : idempotencyKey,
        retryAfterSeconds: operation.messaging && status === 429 && problem
          ? retryAfter(response?.headers.get('retry-after') ?? null) : undefined,
        outcomeUnknown,
      })
      return ownError
    }
    try {
      callerSignal = values.signal
      const signal = callerSignal ? AbortSignal.any([deadline.signal, callerSignal]) : deadline.signal
      const cap = values.maxResponseBytes
      if (cap !== undefined && (!Number.isSafeInteger(cap) || cap < 1)) throw new InputError('Invalid response cap')
      const limit = cap ?? (transfer ? Number.POSITIVE_INFINITY : this.#limit)
      if (operation.keyed) {
        idempotencyKey = values.idempotencyKey
        if (operation.requiresExistingKey && !idempotencyKey) {
          throw new InputError('Receipt lookup requires its original idempotency key')
        }
        idempotencyKey ??= crypto.randomUUID()
      }
      const url = endpoint(base, operation, values, profile)
      // The session part forwards a page's calls, so a page client stays on the page's own origin.
      const pageOrigin = (globalThis as { location?: { origin?: unknown } }).location?.origin
      if (pageMode && typeof pageOrigin === 'string' && url.origin !== pageOrigin) {
        throw new InputError('A page client calls only its own origin')
      }
      const headers = new Headers()
      for (const [key, value] of Object.entries(values.headers ?? {})) {
        if (['authorization', 'cookie', 'idempotency-key'].includes(key.toLowerCase())) continue
        if (value !== undefined) headers.set(key, String(value))
      }
      // Only a page client, which has no token, names itself. A server client does not send it.
      if (this.#options.token === undefined) headers.set(registryClientHeader.name, registryClientHeader.value)
      if (idempotencyKey !== undefined) headers.set('idempotency-key', idempotencyKey)
      if (values.accept) headers.set('accept', values.accept)
      let body: RequestBody | undefined
      if (values.body !== undefined) {
        const declared = operation.requestMediaTypes ?? [operation.requestMediaType]
        const content = values.contentType ?? operation.requestMediaType
        if (!content || mediaType(content).includes('*') ||
            !(declared.includes(content) || declared.includes('*/*') && /^[^/\s]+\/[^/\s]+$/u.test(mediaType(content)))) {
          throw new InputError('Invalid request media type')
        }
        headers.set('content-type', content)
        if (operation.signed) {
          // The signature covers these exact bytes, so they are sent as given.
          if (!(values.body instanceof Uint8Array)) throw new InputError('Signed request body must be the signed bytes')
          body = Uint8Array.from(values.body)
        } else if (!declared.includes('*/*') && isJsonMedia(mediaType(content))) body = JSON.stringify(values.body)
        else if (typeof values.body === 'string') body = values.body
        else if (values.body instanceof Uint8Array) body = Uint8Array.from(values.body)
        // A Blob, including a File, cannot change after it is made, so it is sent as given.
        else if (values.body instanceof Blob) body = values.body
        else throw new InputError('Binary request body must be a Uint8Array, Blob or string')
      }
      stage = 'token'
      signal.throwIfAborted()
      // A signed operation authenticates by its signature, so no bearer credential is asked for.
      const source = operation.signed ? undefined : this.#options.token
      token = source ? await abortable(Promise.resolve(source()), signal) : undefined
      if (token) headers.set('authorization', 'Bearer ' + token)
      signal.throwIfAborted()
      const fetcher = this.#options.fetch ?? globalThis.fetch
      stage = 'network'
      dispatched = true
      // Page mode sends cookies to the page's own origin only. A token or a signature
      // authenticates every other call, so it sends none.
      const progress = (transfer || operation.signed) && values.onProgress ? progressReporter(values.onProgress) : undefined
      const downloads = progress && Object.values(operation.responses).some(variants => variants.some(variant => variant.mode === 'binary'))
      const size = bodySize(body)
      if (transfer) wait(this.#timeout + uploadAllowanceMs(size))
      const moved = () => { if (transfer) wait(this.#timeout) }
      // A session answer is small, so a page 401 or 503 is read up to the larger of the call's cap
      // and the client default.
      const answerLimit = (head: ResponseHead) => pageMode && (head.status === 401 || head.status === 503)
        ? Math.max(cap ?? 0, this.#limit) : limit
      const Xhr = xhrConstructor()
      if (pageMode && progress && body !== undefined && Xhr !== undefined) {
        raw = await xhrBytes(Xhr, url, operation.method, headers, body, signal, answerLimit, progress,
          head => { response = head }, moved, downloads === true)
      } else {
        const fetched = await abortable(fetcher(url, {
          method: operation.method, headers, body, redirect: 'manual', credentials: pageMode ? 'same-origin' : 'omit', signal,
        }), signal)
        response = fetched
        moved()
        if (body !== undefined) progress?.(size, size)
        raw = await readBytes(fetched, answerLimit(fetched), signal, moved,
          downloads && fetched.ok ? progress : undefined)
      }
      if (!response) throw new Error('Registry request failed')
      signal.throwIfAborted()
      const media = mediaType(response.headers.get('content-type'))
      if (pageMode && response.status === 401 && isSessionProblem(raw, media, response.headers, 'expired')) {
        throw failure('refused', 'sign-in-expired', true)
      }
      if (pageMode && response.status === 503 && isSessionProblem(raw, media, response.headers, 'unavailable')) {
        throw failure('unreachable', 'status', true)
      }
      const variants = operation.responses[response.status]
      if (!variants) {
        stage = 'schema'
        const validate = operation.problemValidators?.[response.status] ?? operation.problemValidators?.default
        if (validate && (!operation.messaging || response.headers.get('content-type') === 'application/problem+json')) {
          let candidate: Record<string, unknown> | undefined
          try {
            candidate = parseProblem(raw, media)
          } catch (error) {
            if (!pageMode || response.status !== 401 || !(error instanceof UnsafeInteger)) throw error
          }
          if (candidate && candidate.status === response.status && validate(candidate)
              && (!operation.messaging || matchesMessagingProblem(response.headers, candidate))
              && (!token || !containsCredential(candidate, token))) problem = candidate
        }
        if (response.status === 401 && pageMode) throw failure('refused', 'configuration')
        const kind = response.status >= 500 || response.status === 0 ? 'unreachable'
          : response.status >= 400 && problem ? 'refused' : 'unexpected'
        throw failure(kind, response.status === 412 ? 'stale' : 'status')
      }
      const variant = variants.find(entry => entry.mediaType !== undefined &&
        (mediaType(entry.mediaType) === media || (entry.mediaType === '*/*' && media !== '')))
        ?? variants.find(entry => entry.mode === 'empty')
      if (!variant) throw failure('unexpected', 'media')
      let data: unknown
      stage = 'schema'
      switch (variant.mode) {
        case 'empty':
          if (raw.length !== 0) throw failure('unexpected', 'schema')
          break
        case 'json':
          if (!isJsonMedia(media)) throw failure('unexpected', 'media')
          data = decodeJson(raw)
          if (variant.validate && !variant.validate(data)) throw failure('unexpected', 'schema')
          break
        case 'text':
          data = { text: decoder.decode(raw), mediaType: media }
          break
        case 'binary':
          data = { bytes: raw, mediaType: media }
          break
      }
      return { data: data as T, status: response.status, headers: response.headers, idempotencyKey }
    } catch (error) {
      if (ownError && error === ownError) throw ownError
      if (stage === 'input' && error instanceof InputError) throw new TypeError(error.message)
      if (error instanceof RedirectedAnswer) {
        response = undefined
        throw failure('unreachable', 'status')
      }
      const reason = deadline.signal.aborted ? 'timeout' : callerSignal?.aborted ? 'aborted'
        : error instanceof AnswerTooLarge ? 'too-large' : error instanceof UnsafeInteger ? 'unsafe-integer' : stage
      const unreachable = ['network', 'timeout', 'aborted', 'token'].includes(reason) || (response?.status ?? 0) >= 500
      throw failure(unreachable ? 'unreachable' : 'unexpected', reason)
    } finally {
      clearTimeout(timer)
    }
  }
}

export interface Page<T> { items: T[]; nextCursor: string | null }

/** A BReg list page. `count` is there when the call asked for it and the profile allows it. */
export interface ListPage<T> extends Page<T> { count?: number }

export type FilterOperator = 'equals' | 'in' | 'range' | 'is-null' | 'is-not-null' | 'prefix' | 'contains'
type Scalar = string | number | boolean
type DomainField<Row, F extends string> = Row extends { domainData?: infer D }
  ? D extends object ? F extends keyof D ? D[F] : unknown : unknown
  : unknown
/** The value a filter compares a Record property with, from the row type where it declares one. */
export type FieldValue<Row, F extends string> = [Extract<NonNullable<DomainField<Row, F>>, Scalar>] extends [never]
  ? Scalar : Extract<NonNullable<DomainField<Row, F>>, Scalar>
export interface Range<V> { gt?: V; ge?: V; lt?: V; le?: V }
/** The filter forms a query profile allows for one property. */
export type Filter<V, Op extends FilterOperator> =
  | ('equals' extends Op ? V : never)
  | ('in' extends Op ? readonly V[] : never)
  | ('range' extends Op ? Range<V> : never)
  | ('prefix' extends Op ? { startsWith: string } : never)
  | ('contains' extends Op ? { contains: string } : never)
  | ('is-null' extends Op ? { isNull: true } : never)
  | ('is-not-null' extends Op ? { isNull: false } : never)

export interface ListProfileRules {
  maximumPageSize: number
  allowCount: boolean
  selectable: string[]
  filterable: Record<string, FilterOperator[]>
  sortable: Record<string, Array<'asc' | 'desc'>>
  requiredFilters?: string[][]
}
export interface ListRules {
  accessProfileParameter: boolean
  requiresAccessProfile?: boolean
  profiles: Record<string, ListProfileRules>
  recordProperties?: readonly string[]
}
export interface ListRequest extends CallOptions {
  accessProfile?: string
  where?: object
  orderBy?: string
  select?: readonly string[]
  count?: boolean
  top?: number
}

const rangeKeys = ['gt', 'ge', 'lt', 'le'] as const
const maximumInValues = 100

function filterLiteral(value: unknown): string {
  if (typeof value === 'string') return "'" + value.replaceAll("'", "''") + "'"
  if (typeof value === 'boolean') return String(value)
  if (typeof value === 'number' && /^-?\d+(?:\.\d+)?$/u.test(String(value))) return String(value)
  throw new TypeError('Filter values must be strings, booleans or plain decimal numbers')
}

function predicate(property: string, value: unknown): [FilterOperator, string[]] {
  if (value === null) throw new TypeError('Use isNull to filter on a missing value')
  if (Array.isArray(value)) {
    if (value.length < 1 || value.length > maximumInValues) throw new TypeError('An in filter needs 1 to 100 values')
    return ['in', [property + ' in (' + value.map(filterLiteral).join(',') + ')']]
  }
  if (typeof value !== 'object') return ['equals', [property + ' eq ' + filterLiteral(value)]]
  const entry = value as Record<string, unknown>
  const keys = Object.keys(entry).filter(key => entry[key] !== undefined)
  const only = keys.length === 1 ? keys[0] : undefined
  if (only === 'startsWith' && typeof entry.startsWith === 'string') {
    return ['prefix', ['startswith(' + property + ',' + filterLiteral(entry.startsWith) + ')']]
  }
  if (only === 'contains' && typeof entry.contains === 'string') {
    return ['contains', ['contains(' + property + ',' + filterLiteral(entry.contains) + ')']]
  }
  if (only === 'isNull' && typeof entry.isNull === 'boolean') {
    return [entry.isNull ? 'is-null' : 'is-not-null', [property + (entry.isNull ? ' eq null' : ' ne null')]]
  }
  if (keys.length && keys.every(key => (rangeKeys as readonly string[]).includes(key))) {
    return ['range', rangeKeys.filter(key => keys.includes(key)).map(key => property + ' ' + key + ' ' + filterLiteral(entry[key]))]
  }
  throw new TypeError('A filter is a value, a list of values, or one of startsWith, contains, isNull, gt, ge, lt and le')
}

/**
 * Builds a BReg list query from typed options and the operation's query profiles, and
 * refuses what the profile does not allow before anything is sent. A message names a
 * property or profile only when the contract declares it, never a filter value. With a
 * cursor, the query is the access profile and the cursor, because the cursor carries the
 * rest.
 */
export function listQuery(rules: ListRules, options: ListRequest, cursor?: string, defaultProfile?: string): Record<string, string | number | boolean> {
  const chosen = rules.accessProfileParameter && options.accessProfile === undefined
    ? defaultProfile : options.accessProfile
  const names = Object.keys(rules.profiles)
  if (chosen !== undefined && !rules.accessProfileParameter) throw new TypeError('This list takes no access profile')
  if (chosen === undefined && (rules.requiresAccessProfile || names.length !== 1)) throw new TypeError('This list needs an access profile')
  const name = chosen ?? names[0]!
  if (typeof name !== 'string' || !Object.hasOwn(rules.profiles, name)) {
    throw new TypeError(chosen !== undefined && options.accessProfile === undefined
      ? "The client's default access profile is not one this record type publishes, so name one on the call." : 'Unknown access profile')
  }
  const profile = rules.profiles[name]!
  const under = ' under profile `' + name + '`'
  const known = (property: unknown) => typeof property === 'string' && (Object.hasOwn(profile.filterable, property)
    || Object.hasOwn(profile.sortable, property) || profile.selectable.includes(property)
    || rules.recordProperties?.includes(property))
  const label = (property: unknown) => known(property) ? '`' + String(property) + '`' : 'A property'
  const query: Record<string, string | number | boolean> = {}
  if (chosen !== undefined) query.accessProfile = chosen
  if (cursor !== undefined) return { ...query, $skiptoken: cursor }

  const where = options.where ?? {}
  if (typeof where !== 'object' || where === null || Array.isArray(where)) throw new TypeError('`where` must be an object')
  const predicates: string[] = []
  const equalities = new Set<string>()
  for (const [property, value] of Object.entries(where)) {
    if (value === undefined) continue
    if (!Object.hasOwn(profile.filterable, property)) throw new TypeError(label(property) + ' cannot be filtered' + under)
    const [operator, text] = predicate(property, value)
    if (!profile.filterable[property]!.includes(operator)) {
      throw new TypeError(label(property) + ' cannot be filtered with ' + operator + under)
    }
    if (operator === 'equals') equalities.add(property)
    predicates.push(...text)
  }
  const required = profile.requiredFilters
  if (required && !required.some(alternative => alternative.every(property => equalities.has(property)))) {
    throw new TypeError('Profile `' + name + '` lists only with an equality filter on ' +
      required.map(alternative => alternative.map(property => '`' + property + '`').join(' and ')).join(', or on '))
  }
  if (predicates.length) query.$filter = predicates.join(' and ')

  if (options.orderBy !== undefined) {
    const match = typeof options.orderBy === 'string' ? /^([^ ]+)(?: (desc))?$/u.exec(options.orderBy) : null
    const property = match?.[1]
    const direction = match?.[2] ?? 'asc'
    if (!property || !Object.hasOwn(profile.sortable, property) || !profile.sortable[property]!.includes(direction as 'asc' | 'desc')) {
      throw new TypeError(label(property) + ' cannot be sorted that way' + under)
    }
    query.$orderby = options.orderBy
  }
  if (options.select !== undefined) {
    if (!Array.isArray(options.select) || !options.select.length) throw new TypeError('`select` needs at least one property')
    for (const property of options.select) {
      if (typeof property !== 'string' || !profile.selectable.includes(property)) {
        throw new TypeError(label(property) + ' cannot be selected' + under)
      }
    }
    if (new Set(options.select).size !== options.select.length) throw new TypeError('`select` names a property twice')
    query.$select = options.select.join(',')
  }
  if (options.top !== undefined) {
    if (!Number.isSafeInteger(options.top) || options.top < 1 || options.top > profile.maximumPageSize) {
      throw new TypeError('`top` must be a whole number from 1 to ' + profile.maximumPageSize + under)
    }
    query.$top = options.top
  }
  if (options.count !== undefined) {
    if (typeof options.count !== 'boolean') throw new TypeError('`count` must be true or false')
    if (options.count && !profile.allowCount) throw new TypeError('Profile `' + name + '` does not allow count')
    query.$count = options.count
  }
  return query
}

export function listPage<T>(data: { items: T[]; pageInfo: { nextCursor?: string | null }; count?: number }): ListPage<T> {
  const page: ListPage<T> = { items: data.items, nextCursor: data.pageInfo.nextCursor ?? null }
  if (typeof data.count === 'number') page.count = data.count
  return page
}

/**
 * Walks cursor pages. A failed load rejects that `next()` call and leaves the walk
 * where it was, so the next call loads the same cursor again. A repeated cursor or
 * the page cap ends the walk after a RangeError.
 */
export function pages<T>(
  load: (cursor?: string) => Promise<Page<T>>, cap = 100,
): AsyncIterableIterator<Page<T>, void, undefined> {
  if (!Number.isSafeInteger(cap) || cap < 1) throw new RangeError('Invalid page cap')
  let cursor: string | undefined
  const seen = new Set<string>()
  let index = 0
  let done = false
  let tail: Promise<unknown> = Promise.resolve()
  async function step(): Promise<IteratorResult<Page<T>, void>> {
    if (done) return { done: true, value: undefined }
    if (index >= cap) {
      done = true
      throw new RangeError('Page cap reached')
    }
    const page = await load(cursor)
    if (page.nextCursor && seen.has(page.nextCursor)) {
      done = true
      throw new RangeError('Page cursor repeated')
    }
    index++
    if (page.nextCursor) {
      cursor = page.nextCursor
      seen.add(cursor)
    } else done = true
    return { done: false, value: page }
  }
  const walk: AsyncIterableIterator<Page<T>, void, undefined> = {
    next() {
      const result = tail.then(step, step)
      tail = result.catch(() => undefined)
      return result
    },
    return() {
      done = true
      return Promise.resolve({ done: true, value: undefined })
    },
    throw(error: unknown) {
      done = true
      return Promise.reject(error)
    },
    [Symbol.asyncIterator]() { return walk },
  }
  return walk
}

export async function allPages<T>(load: (cursor?: string) => Promise<Page<T>>, cap = 100): Promise<T[]> {
  const items: T[] = []
  for await (const page of pages(load, cap)) {
    for (const item of page.items) items.push(item)
  }
  return items
}

export interface DescribeOptions {
  /**
   * The label each guard declares in the project contract, keyed by its `guardReason`.
   * Only these constants are shown for a refused guard.
   */
  guardLabels?: Readonly<Record<string, string>>
  /** Replaces a default sentence by its key in the words table. */
  clientSentences?: Readonly<Record<string, string>>
}

/** One sentence per `can.*` reason. Part of the one words table, `clientSentences`. */
export const availabilityMessages: Readonly<Record<string, string>> = {
  'not-offered': 'This is not offered for this application.',
  'not-needed': 'This application does not need to be updated to a new form.',
  rebase: 'The form for this application has changed. Update it to the current form, then send it again.',
  'not-awaiting-party': 'This can only be done while the application is waiting for the applicant.',
  'pending-review': 'This is waiting for review.',
  'review-rejected': 'The review rejected this application.',
  'review-changes-requested': 'The reviewer asked for changes first.',
  'review-ended': 'The review has ended.',
  'stale-revision': 'This is no longer possible for this application.',
  'package-changed': 'The form for this application has changed. Update it to the current form first.',
  'attachment-required': 'A required document is missing. Add it before sending.',
  'rebase-refused': 'This application could not be applied as it stands. Update it to the current form, then send it again.',
  'dependency-outage': 'A service this depends on is unavailable. Try again later.',
  'invalid-input': 'This application needs corrections first.',
  'already-applied': 'This application has already been applied.',
}

const availableSentence = 'Available.'
const configurationSentence = 'This page is not set up correctly for this request.'
const developerSentence = 'This page could not complete the request.'
const unexpectedAnswerSentence = 'The answer was not what this page expected, so this page stopped for safety.'
const documentUnusableSentence = 'This document cannot be used.'

export const clientFallbackSentence = 'The request could not be completed from this page.'

/**
 * The sentence a person reads for each `client.` code the client raises itself, with the `can.*` reasons and the two
 * sentences for an offered or an unavailable step. This is the one table a programme replaces with its own language,
 * through `DescribeOptions.clientSentences`, and passes to `proposalCommands` as well.
 */
export const clientSentences: Readonly<Record<string, string>> = {
  ...availabilityMessages,
  'client.page-access-refused': 'You are signed in, but this page is not available to your account.',
  available: availableSentence,
  'availability.available': availableSentence,
  unavailable: 'This is not available right now.',
  'availability.guard-not-satisfied': 'The action is not possible in the current state.',
  'availability.input-required': 'Complete the required fields to check whether this action is available.',
  'availability.not-disclosed': 'It is unclear whether this action is available.',
  'proposal.status.draft': 'Draft.',
  'proposal.status.awaiting-party': 'Waiting for the applicant.',
  'proposal.status.in-review': 'Under review.',
  'proposal.status.approved': 'Approved.',
  'proposal.status.processing': 'Being processed.',
  'proposal.status.applied': 'Applied.',
  'proposal.status.rejected': 'Rejected.',
  'proposal.status.cancelled': 'Cancelled.',
  'client.fallback': clientFallbackSentence,
  'client.file-type': 'This kind of file is not accepted here, so choose another file.',
  'client.file-too-large': 'This file is too large, so choose a smaller file.',
  'client.content-digest': 'The file received does not match the one stored, so it was not opened. Try again.',
  'client.command-unavailable': 'This step is not available for this application now.',
  'client.action-unavailable': 'This action is not available for this document.',
  'client.link-operation': unexpectedAnswerSentence,
  'client.upload-path': unexpectedAnswerSentence,
  'client.stale-copy': 'This application changed elsewhere. Reload it and try again.',
  'client.read-after-write': 'Your change was saved, but this page could not refresh. Reload it to see the latest version.',
  'client.inputs-not-readable': 'This page cannot change these answers.',
  'client.browser-only': developerSentence,
  'client.document-not-ready': 'This document is not ready yet. Try again shortly.',
  'client.wait-timeout': 'This document could not be checked in time. Try again shortly.',
  'client.document-rejected': documentUnusableSentence,
  'client.document-suspended': documentUnusableSentence,
  'client.document-erasure-pending': documentUnusableSentence,
  'client.document-erased': documentUnusableSentence,
  // Raised only by a page that is set up wrongly.
  'client.action-id': configurationSentence,
  'client.unknown-operation': configurationSentence,
  'client.unknown-slot': configurationSentence,
  'client.unknown-policy': configurationSentence,
  // Raised only by a bad option from the page.
  'client.invalid-interval': developerSentence,
  'client.invalid-timeout': developerSentence,
}

/**
 * The sentence for `key`: the programme's own non-empty replacement, else the default table. A key the table lacks gets
 * the fallback sentence, which the programme may replace under `client.fallback`.
 */
export function sentence(key: string, options: DescribeOptions = {}): string {
  const replacement = (name: string): string | undefined => {
    const replaced = options.clientSentences
    const own = replaced && Object.hasOwn(replaced, name) ? replaced[name] : undefined
    return typeof own === 'string' && own !== '' ? own : undefined
  }
  return replacement(key) ?? (Object.hasOwn(clientSentences, key) ? clientSentences[key]! : replacement('client.fallback') ?? clientFallbackSentence)
}

export interface ActionAvailability<Input extends string = string> {
  available: boolean | null
  reason: string
  missingInputs?: Input[]
  guardReason?: string
}

function guardLabel(reason: unknown, options: DescribeOptions): string | undefined {
  const labels = options.guardLabels
  const label = typeof reason === 'string' && labels && Object.hasOwn(labels, reason) ? labels[reason] : undefined
  return typeof label === 'string' && label !== '' ? label : undefined
}

export function actionAvailability<Input extends string>(
  answer: { available: boolean | null; reason?: string; missingInputs?: Input[]; guardReason?: string },
  options: DescribeOptions,
): ActionAvailability<Input> {
  const { available, missingInputs, guardReason } = answer
  return {
    available,
    reason: guardLabel(guardReason, options) ?? sentence('availability.' + (available ? 'available' : answer.reason), options),
    ...(missingInputs === undefined ? {} : { missingInputs }),
    ...(guardReason === undefined ? {} : { guardReason }),
  }
}

const unreadable = 'The registry sent an answer that could not be read.'
const notBuilt = 'The request could not be built from the given values.'

/**
 * One fixed sentence a person can read, chosen by the failure's reason and status, or by
 * the `client.` code of an error the client raised itself. It never repeats text from an
 * answer or from an error's `detail`, which stays on the error for developers. For a refused
 * guard it shows the label the caller supplies for that guard's reason.
 */
export function describeError(error: unknown, options: DescribeOptions = {}): string {
  if (!(error instanceof RegistryError)) {
    return error instanceof TypeError ? notBuilt : 'Something went wrong.'
  }
  if (error.raisedByClient && error.code?.startsWith('client.')) {
    // A step the register no longer offers shows the sentence for the served reason when it is one of the fixed
    // availability reasons. Any other reason, and any `client.` key, keeps the step's own sentence.
    const reason = error.code === 'client.command-unavailable' ? error.problem?.['reason'] : undefined
    return sentence(typeof reason === 'string' && Object.hasOwn(availabilityMessages, reason) ? reason : error.code, options)
  }
  if (error.outcomeUnknown) return 'The change may or may not have been made, so check before trying again.'
  if (error.kind === 'refused' && error.code === 'action.guard_failed') {
    return guardLabel(error.problem?.guardReason, options) ?? sentence('availability.guard-not-satisfied', options)
  }
  switch (error.reason) {
    case 'configuration':
      return error.status === 401 && error.code === 'authentication.refused'
        ? sentence('client.page-access-refused', options)
        : 'This service is not available from this page right now, so try again later.'
    case 'sign-in-expired': return 'Your sign-in has ended, so sign in again.'
    case 'stale': return 'The item changed since it was loaded, so reload it and try again.'
    case 'token': return 'Your credentials could not be obtained, so sign in again.'
    case 'input': return notBuilt
    case 'timeout': return 'The registry took too long to answer.'
    case 'aborted': return 'The request was cancelled.'
    case 'network': return 'The registry did not answer, so check the connection and try again.'
  }
  const status = error.status
  if (status === 401 && error.reason === 'too-large' && error.product) return unreadable
  if (status === undefined || status >= 200 && status < 300) return unreadable
  if (status >= 500) return 'The registry failed to complete the request, so try again later.'
  if (status === 401) return 'The registry refused your credentials, so sign in again.'
  if (status === 403) return 'You are not allowed to do this.'
  if (status === 404) return 'The requested item was not found.'
  if (status === 409 || status === 412 || status === 428) return 'The request conflicts with the current state, so reload and try again.'
  if (status === 429) return 'Too many requests were sent, so wait a moment and try again.'
  if (status === 400 || status === 422) return 'The registry found the request not valid.'
  return 'The registry sent an unexpected answer.'
}

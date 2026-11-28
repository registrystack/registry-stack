export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

export interface ClientOptions {
  baseUrl: string | URL
  token: () => string | undefined | Promise<string | undefined>
  allowInsecureHttp?: boolean
  timeoutMs?: number
  maxResponseBytes?: number
  fetch?: typeof fetch
}

export interface CallOptions {
  signal?: AbortSignal
  idempotencyKey?: string
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
  | 'too-large' | 'media' | 'schema' | 'unsafe-integer' | 'status'

interface ErrorInfo {
  reason: ErrorReason
  kind: ErrorKind
  status?: number
  problem?: Record<string, unknown>
  raw?: Uint8Array
  idempotencyKey?: string
  outcomeUnknown: boolean
  retryAfterSeconds?: number
}

export class RegistryError extends Error implements ErrorInfo {
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
    super('Registry request ' + info.kind)
    this.name = 'RegistryError'
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

/**
 * A host that cannot be on the public internet: a private or link-local IP literal, or a
 * single-label name such as a container name on a compose network.
 */
function privateHost(hostname: string): boolean {
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/u.exec(hostname)
  if (ipv4) {
    const first = Number(ipv4[1])
    const second = Number(ipv4[2])
    return first === 10 || first === 172 && second >= 16 && second <= 31
      || first === 192 && second === 168 || first === 169 && second === 254
  }
  if (hostname.startsWith('[')) {
    const leading = hostname.slice(1).split(':', 1)[0]!
    const hextet = leading === '' ? 0 : Number.parseInt(leading, 16)
    return (hextet & 0xfe00) === 0xfc00 || (hextet & 0xffc0) === 0xfe80
  }
  return !hostname.includes('.')
}

function baseAddress(value: string | URL, allowInsecureHttp: boolean): string {
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
  const plainHttp = url.protocol === 'http:' && (loopback || allowInsecureHttp && privateHost(url.hostname))
  if (url.protocol !== 'https:' && !plainHttp || url.username || url.password) throw invalidBase()
  return url.href.replace(/\/+$/u, '')
}

class InputError extends TypeError {}

function endpoint(base: string, operation: Operation, values: RequestValues): URL {
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

async function readBytes(response: Response, maxBytes: number, signal: AbortSignal): Promise<Uint8Array> {
  if (!response.body) return new Uint8Array()
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    while (true) {
      const chunk = await abortable(reader.read(), signal)
      if (chunk.done) break
      size += chunk.value.length
      if (size > maxBytes) throw new AnswerTooLarge()
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

export class Transport {
  readonly #base: string
  readonly #options: ClientOptions
  readonly #timeout: number
  readonly #limit: number

  constructor(options: ClientOptions) {
    this.#base = baseAddress(options.baseUrl, options.allowInsecureHttp === true)
    this.#timeout = options.timeoutMs ?? 10_000
    this.#limit = options.maxResponseBytes ?? 8 * 1024 * 1024
    if (!Number.isSafeInteger(this.#timeout) || this.#timeout < 1 || this.#timeout > 2_147_483_647
        || !Number.isSafeInteger(this.#limit) || this.#limit < 1) throw new RangeError('Invalid transport bounds')
    this.#options = { ...options }
  }

  async call<T>(operation: Operation, values: RequestValues = {}): Promise<Answer<T>> {
    const deadline = new AbortController()
    const timer = setTimeout(() => deadline.abort(), this.#timeout)
    let response: Response | undefined
    let raw: Uint8Array | undefined
    let problem: Record<string, unknown> | undefined
    let idempotencyKey: string | undefined
    let token: string | undefined
    let dispatched = false
    let stage: ErrorReason = 'input'
    let callerSignal: AbortSignal | undefined
    let ownError: RegistryError | undefined
    const failure = (kind: ErrorKind, reason: ErrorReason) => {
      const status = response?.status
      const outcomeUnknown = operation.mutating === true && dispatched && (
        status === undefined || status === 0 || status >= 500 || status >= 200 && status < 300 ||
        (reason === 'timeout' || reason === 'aborted') && (status < 400 || status >= 500)
      )
      ownError = new RegistryError({
        kind, reason, status: status === 0 ? undefined : status, raw, problem,
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
      if (operation.keyed) {
        idempotencyKey = values.idempotencyKey
        if (operation.requiresExistingKey && !idempotencyKey) {
          throw new InputError('Receipt lookup requires its original idempotency key')
        }
        idempotencyKey ??= crypto.randomUUID()
      }
      const url = endpoint(this.#base, operation, values)
      const headers = new Headers()
      for (const [key, value] of Object.entries(values.headers ?? {})) {
        if (['authorization', 'cookie', 'idempotency-key'].includes(key.toLowerCase())) continue
        if (value !== undefined) headers.set(key, String(value))
      }
      if (idempotencyKey !== undefined) headers.set('idempotency-key', idempotencyKey)
      if (values.accept) headers.set('accept', values.accept)
      let body: BodyInit | undefined
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
        else throw new InputError('Binary request body must be a Uint8Array or string')
      }
      stage = 'token'
      signal.throwIfAborted()
      // A signed operation authenticates by its signature, so no bearer credential is asked for.
      token = operation.signed ? undefined : await abortable(Promise.resolve(this.#options.token()), signal)
      if (token) headers.set('authorization', 'Bearer ' + token)
      signal.throwIfAborted()
      const fetcher = this.#options.fetch ?? globalThis.fetch
      stage = 'network'
      dispatched = true
      response = await abortable(fetcher(url, {
        method: operation.method, headers, body, redirect: 'manual', credentials: 'omit', signal,
      }), signal)
      raw = await readBytes(response, this.#limit, signal)
      signal.throwIfAborted()
      const media = mediaType(response.headers.get('content-type'))
      const variants = operation.responses[response.status]
      if (!variants) {
        stage = 'schema'
        const validate = operation.problemValidators?.[response.status] ?? operation.problemValidators?.default
        if (validate && (!operation.messaging || response.headers.get('content-type') === 'application/problem+json')) {
          const candidate = parseProblem(raw, media)
          if (candidate && candidate.status === response.status && validate(candidate)
              && (!operation.messaging || matchesMessagingProblem(response.headers, candidate))
              && (!token || !containsCredential(candidate, token))) problem = candidate
        }
        const kind = response.status >= 500 || response.status === 0 ? 'unreachable'
          : response.status >= 400 && problem ? 'refused' : 'unexpected'
        throw failure(kind, 'status')
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

/**
 * Walks cursor pages. A failed load rejects that `next()` call and leaves the walk
 * where it was, so the next call loads the same cursor again. A repeated cursor or
 * the page cap ends the walk after a RangeError.
 */
export function pages<T>(
  load: (cursor?: string) => Promise<Page<T>>, cap = 100,
): AsyncIterableIterator<Page<T>> {
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
  const walk: AsyncIterableIterator<Page<T>> = {
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
}

const unreadable = 'The registry sent an answer that could not be read.'
const notBuilt = 'The request could not be built from the given values.'

/**
 * One fixed sentence a person can read, chosen by the failure's reason and status. It
 * never repeats text from the answer. For a refused guard it shows the label the caller
 * supplies for that guard's reason.
 */
export function describeError(error: unknown, options: DescribeOptions = {}): string {
  if (!(error instanceof RegistryError)) {
    return error instanceof TypeError ? notBuilt : 'Something went wrong.'
  }
  if (error.outcomeUnknown) return 'The change may or may not have been made, so check before trying again.'
  if (error.kind === 'refused' && error.code === 'action.guard_failed') {
    const reason = error.problem?.guardReason
    const labels = options.guardLabels
    const label = typeof reason === 'string' && labels && Object.hasOwn(labels, reason) ? labels[reason] : undefined
    return typeof label === 'string' && label !== '' ? label : 'The action is not possible in the current state.'
  }
  switch (error.reason) {
    case 'token': return 'Your credentials could not be obtained, so sign in again.'
    case 'input': return notBuilt
    case 'timeout': return 'The registry took too long to answer.'
    case 'aborted': return 'The request was cancelled.'
    case 'network': return 'The registry did not answer, so check the connection and try again.'
  }
  const status = error.status
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

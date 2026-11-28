import { RegistryError, type Page } from '../core.ts'
import { clientError, downloadedBlob, refusal as refuse, resolveFileType, sha256Hex, type ProgressCallback } from './shared.ts'
import type {
  Schema_DocumentGrantView,
  Schema_DocumentPolicyView,
  Schema_DocumentView,
  Schema_IssueGrantRequest,
  Schema_ReservationView,
  Schema_ReserveDocumentRequest,
} from '../generated/documents.ts'

export type DocumentView = Schema_DocumentView
export type DocumentGrantView = Schema_DocumentGrantView
export type DocumentStatus = DocumentView['version']['status']

export type OnProgress = ProgressCallback

interface CallBase {
  signal?: AbortSignal
  idempotencyKey?: string
  maxResponseBytes?: number
}
interface TransferBase extends CallBase { onProgress?: OnProgress }

type ListOptions = { signal?: AbortSignal; query?: { limit?: number } }

/** The operations these commands call, with the input each takes and the data it answers. */
interface DocumentCalls {
  (operation: 'listDocumentPolicies', input?: CallBase): Promise<{ data: { items: Schema_DocumentPolicyView[] } }>
  (operation: 'reserveDocument', input: CallBase & { body: Schema_ReserveDocumentRequest }): Promise<{ data: Schema_ReservationView }>
  (operation: 'uploadDocumentContent', input: TransferBase & { path: { uploadId: string }; body: Blob; contentType: string }): Promise<{ data: DocumentView }>
  (operation: 'readDocument', input: CallBase & { path: { documentId: string } }): Promise<{ data: DocumentView }>
  (operation: 'downloadDocumentVersion', input: TransferBase & { path: { documentId: string; versionId: string } }): Promise<{ data: { bytes: Uint8Array; mediaType: string } }>
  (operation: 'issueDocumentGrant', input: CallBase & { path: { documentId: string }; body: Schema_IssueGrantRequest }): Promise<{ data: DocumentGrantView }>
  (operation: 'revokeDocumentGrant', input: CallBase & { path: { grantId: string } }): Promise<{ data: DocumentGrantView }>
  (operation: 'requestDocumentErasure', input: CallBase & { path: { documentId: string } }): Promise<{ data: DocumentView }>
}

/**
 * The part of a generated Document Store client these commands use. The generated `Client`
 * satisfies it, and function properties keep the comparison strict: a misspelt operation or a
 * body that the generated client would refuse does not compile.
 */
export interface DocumentClient {
  call: DocumentCalls
  listDocumentsPage: (options?: ListOptions, cursor?: string) => Promise<Page<DocumentView>>
  listDocumentGrantsPage: (options: ListOptions & { path: { documentId: string } }, cursor?: string) => Promise<Page<DocumentGrantView>>
  listReceivedGrantsPage: (options?: ListOptions, cursor?: string) => Promise<Page<DocumentGrantView>>
}

type Signal = { signal?: AbortSignal }
type Progress = { onProgress?: OnProgress }
// A caller can pass the key from a failed attempt to retry it. Without one, the commands keep
// the key of an attempt that may have reached the register and use it for the same request again.
type Keyed = { idempotencyKey?: string }

export interface DocumentCommands<C extends DocumentClient = DocumentClient> {
  /** The client's own calls and page methods, for what these commands do not cover. */
  call: C['call']
  listDocumentsPage: C['listDocumentsPage']
  listDocumentGrantsPage: C['listDocumentGrantsPage']
  listReceivedGrantsPage: C['listReceivedGrantsPage']
  list(opts?: { cursor?: string; limit?: number } & Signal): Promise<Page<DocumentView>>
  /** Grants other people issued to the caller. */
  received(opts?: { cursor?: string; limit?: number } & Signal): Promise<Page<DocumentGrantView>>
  upload(file: Blob, opts: { policy: string; label?: string; custodian?: string } & Signal & Progress & Keyed): Promise<DocumentView>
  waitUntilReady(documentId: string, opts?: { timeoutMs?: number; intervalMs?: number } & Signal): Promise<DocumentView>
  download(documentId: string, opts?: Signal & Progress): Promise<Blob>
  share(documentId: string, opts: { with: string; kind?: 'human' | 'service'; expiryHours?: number } & Signal & Keyed): Promise<DocumentGrantView>
  shares(documentId: string, opts?: { cursor?: string; limit?: number } & Signal): Promise<Page<DocumentGrantView>>
  revoke(grantId: string, opts?: Signal): Promise<DocumentGrantView>
  requestErasure(documentId: string, opts?: Signal): Promise<DocumentView>
}

const UPLOAD_PATH = /\/v1\/uploads\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/content$/u
const UNUSABLE_STATUSES: string[] = ['rejected', 'suspended', 'erasure-pending', 'erased']
// A key the register no longer accepts: the request has to start again under a new key.
const EXPIRED_CODES = ['upload.expired', 'idempotency.expired']
const MINIMUM_POLL_INTERVAL_MS = 250
const OBJECT_URL_LIFETIME_MS = 4_000

function aborted(): RegistryError {
  return new RegistryError({ kind: 'unreachable', reason: 'aborted', outcomeUnknown: false })
}

/** The same error with a different key or problem, keeping the original as `cause`. */
function rebuilt(error: RegistryError, changes: { problem?: Record<string, unknown>; idempotencyKey: string | undefined }): RegistryError {
  const copy = new RegistryError({
    kind: error.kind, reason: error.reason, status: error.status, problem: changes.problem ?? error.problem, raw: error.raw,
    idempotencyKey: changes.idempotencyKey, outcomeUnknown: error.outcomeUnknown, raisedByClient: error.raisedByClient, retryAfterSeconds: error.retryAfterSeconds,
  })
  Object.defineProperty(copy, 'cause', { value: error, configurable: true })
  return copy
}

/**
 * Runs a keyed command. `resolve(fingerprint)` picks the key once the request is known: the
 * caller's key, else the key kept from an earlier attempt of the same request that may have
 * reached the register, else a new one. The kept key is dropped on success and on a definite
 * answer. An expired key is dropped and not offered for a retry.
 */
async function keyedCommand<T>(
  given: string | undefined,
  kept: Map<string, string>,
  run: (resolve: (fingerprint: unknown[]) => string) => Promise<T>,
): Promise<T> {
  let key = given
  let fingerprint: string | undefined
  const resolve = (parts: unknown[]) => {
    fingerprint = JSON.stringify(parts)
    key = given ?? kept.get(fingerprint) ?? crypto.randomUUID()
    if (given === undefined) kept.set(fingerprint, key)
    return key
  }
  try {
    const result = await run(resolve)
    if (fingerprint !== undefined) kept.delete(fingerprint)
    return result
  } catch (error) {
    if (!(error instanceof RegistryError)) throw error
    const expired = error.code !== undefined && EXPIRED_CODES.includes(error.code)
    if (fingerprint !== undefined && (expired || !(error.outcomeUnknown || error.kind === 'unreachable'))) kept.delete(fingerprint)
    if (expired) {
      const detail = `${error.detail ?? 'The register no longer accepts this key.'} The key cannot be used again. Call again with a new key.`
      throw rebuilt(error, { problem: { ...error.problem, detail }, idempotencyKey: undefined })
    }
    throw key === undefined || error.idempotencyKey === key ? error : rebuilt(error, { idempotencyKey: key })
  }
}

/** Settles with `promise`, or rejects as aborted when `signal` fires first. */
function untilAborted<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return promise
  if (signal.aborted) return Promise.reject(aborted())
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(aborted())
    signal.addEventListener('abort', onAbort, { once: true })
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort))
  })
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) { reject(aborted()); return }
    const onAbort = () => { clearTimeout(timer); reject(aborted()) }
    const timer = setTimeout(() => { signal.removeEventListener('abort', onAbort); resolve() }, ms)
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

/**
 * Settles with `promise`. The generated client throws a TypeError for a call it cannot build, before any
 * request. That is a fault in how the page is set up, so it is raised as the same refusal the Proposals
 * helper raises.
 */
async function guarded<T>(operation: string, promise: Promise<T>): Promise<T> {
  try {
    return await promise
  } catch (error) {
    if (error instanceof TypeError) {
      throw refuse('client.unknown-operation', `The register client cannot send "${operation}": ${error.message}.`, { operation })
    }
    throw error
  }
}

/** A method of the client, callable on its own. */
function bound<F>(client: object, method: F): F {
  return ((...args: unknown[]) => Reflect.apply(method as (...args: unknown[]) => unknown, client, args)) as F
}

export function documentCommands<C extends DocumentClient>(client: C, options: { custodian?: string } = {}): DocumentCommands<C> {
  let policies: Promise<Schema_DocumentPolicyView[]> | undefined
  const keptUploadKeys = new Map<string, string>()
  const keptShareKeys = new Map<string, string>()

  const read = async (documentId: string, signal?: AbortSignal) =>
    (await guarded('readDocument', client.call('readDocument', { path: { documentId }, signal }))).data

  // Read once per instance and shared by every caller. The shared read carries no caller's
  // signal, each caller races its own signal against it. A failed read is not kept.
  const policyList = (signal?: AbortSignal): Promise<Schema_DocumentPolicyView[]> => {
    if (signal?.aborted) return Promise.reject(aborted())
    policies ??= guarded('listDocumentPolicies', client.call('listDocumentPolicies'))
      .then(answer => answer.data.items)
      .catch((error: unknown) => { policies = undefined; throw error })
    return untilAborted(policies, signal)
  }

  const page = (cursor: string | undefined, limit: number | undefined, signal: AbortSignal | undefined) =>
    [{ signal, ...(limit === undefined ? {} : { query: { limit } }) }, cursor] as const

  return {
    call: bound(client, client.call),
    listDocumentsPage: bound(client, client.listDocumentsPage),
    listDocumentGrantsPage: bound(client, client.listDocumentGrantsPage),
    listReceivedGrantsPage: bound(client, client.listReceivedGrantsPage),

    list: ({ cursor, limit, signal } = {}) => guarded('listDocumentsPage', client.listDocumentsPage(...page(cursor, limit, signal))),

    received: ({ cursor, limit, signal } = {}) => guarded('listReceivedGrantsPage', client.listReceivedGrantsPage(...page(cursor, limit, signal))),

    upload(file, { policy, label, custodian, signal, onProgress, idempotencyKey }) {
      return keyedCommand(idempotencyKey, keptUploadKeys, async resolve => {
        const known = await policyList(signal)
        const chosen = known.find(item => item.id === policy)
        if (!chosen) throw refuse('client.unknown-policy', `Unknown document policy "${policy}". Known policies: ${known.map(item => item.id).join(', ') || 'none'}.`)
        const contentType = resolveFileType(file, chosen.allowedContentTypes)
        if (contentType === undefined) {
          throw refuse('client.file-type', `This policy accepts only: ${chosen.allowedContentTypes.join(', ')}.`)
        }
        if (file.size > chosen.maximumDocumentBytes) {
          throw refuse('client.file-too-large', `This policy accepts files up to ${chosen.maximumDocumentBytes} bytes.`)
        }

        // With no custodian the request leaves it out and the register takes the caller's own subject.
        const subject = custodian ?? options.custodian
        const digest = `sha256:${await sha256Hex(await file.arrayBuffer())}`
        const key = resolve([digest, file.size, contentType, policy, label ?? null, subject ?? null])
        const { data: reserved } = await guarded('reserveDocument', client.call('reserveDocument', {
          signal,
          idempotencyKey: key,
          body: {
            ...(subject === undefined ? {} : { custodian: { subject } }),
            expectedDigest: digest,
            length: file.size,
            mediaType: contentType,
            policyId: policy,
            ...(label === undefined ? {} : { label }),
          },
        }))
        // Only the id is taken from the response. The request goes to the client's own base URL.
        const uploadId = UPLOAD_PATH.exec(reserved.uploadPath)?.[1]
        if (uploadId === undefined) {
          throw clientError({
            kind: 'unexpected', reason: 'schema', outcomeUnknown: false,
            problem: { code: 'client.upload-path', detail: 'The register returned an upload path in an unexpected shape, so nothing was uploaded.' },
          })
        }
        const uploaded = await guarded('uploadDocumentContent', client.call('uploadDocumentContent', {
          signal, path: { uploadId }, body: file, contentType: reserved.document.version.mediaType,
          ...(onProgress && { onProgress }),
        }))
        return uploaded.data
      })
    },

    async waitUntilReady(documentId, { timeoutMs = 60_000, intervalMs = 2_000, signal } = {}) {
      if (!Number.isFinite(timeoutMs) || timeoutMs < 0) throw refuse('client.invalid-timeout', 'timeoutMs must be a finite number of milliseconds, 0 or more.')
      if (!Number.isFinite(intervalMs)) throw refuse('client.invalid-interval', 'intervalMs must be a finite number of milliseconds.')
      const interval = Math.max(intervalMs, MINIMUM_POLL_INTERVAL_MS)
      // One budget for the whole wait. Every read and every sleep carries it with the caller's signal.
      const budget = new AbortController()
      const timer = setTimeout(() => budget.abort(), timeoutMs)
      const deadline = Date.now() + timeoutMs
      const waitSignal = signal ? AbortSignal.any([signal, budget.signal]) : budget.signal
      let lastFailure: RegistryError | undefined
      const timedOut = () => clientError({
        kind: 'unreachable', reason: 'timeout', outcomeUnknown: false,
        problem: { code: 'client.wait-timeout', detail: `The document was not ready after ${timeoutMs} ms.${lastFailure ? ` The last read failed: ${lastFailure.code ?? lastFailure.reason}.` : ''}` },
      })
      try {
        for (;;) {
          if (Date.now() >= deadline) throw timedOut()
          try {
            const view = await read(documentId, waitSignal)
            const { status } = view.version
            if (status === 'ready') return view
            if (UNUSABLE_STATUSES.includes(status)) throw refuse(`client.document-${status}`, `The document is ${status} and will not become ready.`, {}, 'status')
          } catch (error) {
            // A read that failed in transit is tried again until the budget is spent. A refusal is final.
            if (!(error instanceof RegistryError) || error.kind !== 'unreachable' || error.reason === 'aborted' || error.reason === 'token') throw error
            lastFailure = error
          }
          await sleep(Math.min(interval, Math.max(deadline - Date.now(), 0)), waitSignal)
        }
      } catch (error) {
        if (budget.signal.aborted && !signal?.aborted) throw timedOut()
        throw error
      } finally {
        clearTimeout(timer)
      }
    },

    async download(documentId, { signal, onProgress } = {}) {
      const view = await read(documentId, signal)
      const { status } = view.version
      if (UNUSABLE_STATUSES.includes(status)) throw refuse(`client.document-${status}`, `The document is ${status} and cannot be downloaded.`, {}, 'status')
      if (status !== 'ready') throw refuse('client.document-not-ready', `The document is ${status}, not ready to download.`, {}, 'status')
      if (!view.actions.includes('download')) throw refuse('client.action-unavailable', 'The register does not offer download of this document to this caller.')
      const { data } = await guarded('downloadDocumentVersion', client.call('downloadDocumentVersion', {
        signal, path: { documentId, versionId: view.version.id },
        maxResponseBytes: view.version.length,
        ...(onProgress && { onProgress }),
      }))
      const actual = `sha256:${await sha256Hex(data.bytes as BufferSource)}`
      if (actual !== view.version.expectedDigest.toLowerCase()) {
        throw clientError({
          kind: 'unexpected', reason: 'schema', outcomeUnknown: false,
          problem: { code: 'client.content-digest', detail: 'The downloaded bytes do not match the stored SHA-256 digest, so they were not returned.' },
        })
      }
      return downloadedBlob(data.bytes as Uint8Array<ArrayBuffer>, data.mediaType)
    },

    share(documentId, { with: subject, kind = 'human', expiryHours, signal, idempotencyKey }) {
      return keyedCommand(idempotencyKey, keptShareKeys, async resolve => {
        const view = await read(documentId, signal)
        if (!view.actions.includes('share')) throw refuse('client.action-unavailable', 'The register does not offer sharing of this document to this caller.')
        const key = resolve([documentId, view.version.id, kind, subject, expiryHours ?? null])
        const { data } = await guarded('issueDocumentGrant', client.call('issueDocumentGrant', {
          signal,
          path: { documentId },
          idempotencyKey: key,
          body: { grantee: { kind, subject }, versionId: view.version.id, ...(expiryHours === undefined ? {} : { expiryHours }) },
        }))
        return data
      })
    },

    shares: (documentId, { cursor, limit, signal } = {}) =>
      guarded('listDocumentGrantsPage', client.listDocumentGrantsPage({ path: { documentId }, ...page(cursor, limit, signal)[0] }, cursor)),

    async revoke(grantId, { signal } = {}) {
      return (await guarded('revokeDocumentGrant', client.call('revokeDocumentGrant', { signal, path: { grantId } }))).data
    },

    async requestErasure(documentId, { signal } = {}) {
      return (await guarded('requestDocumentErasure', client.call('requestDocumentErasure', { signal, path: { documentId } }))).data
    },
  }
}

/**
 * Browser only. Saves through a download link, so the file is never opened in the page. The
 * object URL is revoked after a delay, because some browsers start the save after the click.
 */
export function saveBlob(blob: Blob, filename: string): void {
  if (typeof document === 'undefined' || document.body === null) throw refuse('client.browser-only', 'saveBlob works only in a browser page.')
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.rel = 'noopener'
  document.body.append(link)
  try {
    link.click()
  } finally {
    link.remove()
    setTimeout(() => URL.revokeObjectURL(url), OBJECT_URL_LIFETIME_MS)
  }
}

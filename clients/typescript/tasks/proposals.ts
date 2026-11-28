import { RegistryError, availabilityMessages, sentence, type DescribeOptions, type JsonValue } from '../core.ts'
import { clientError, downloadedBlob, refusal as refuse, sha256Hex, type ProgressCallback } from './shared.ts'

export type JsonObject = Record<string, JsonValue>
export type ProposalState = 'draft' | 'submitted' | 'applied' | 'cancelled' | 'rejected'
export type ProposalStatus = 'draft' | 'awaiting-party' | 'in-review' | 'approved' | 'processing' | 'applied' | 'rejected' | 'cancelled'
export type CommandName = 'edit' | 'attach' | 'submit' | 'resubmit' | 'rebase' | 'cancel'
export type Turn = 'party' | 'official' | 'nobody'

export type { ProgressCallback }

/** Input changes: a member set to undefined removes that input. */
export type JsonChanges = Record<string, JsonValue | undefined>

/** The values every call of these commands sends. One type, so a misspelt field fails to compile. */
export interface ProposalCallValues {
  path?: { proposal_id: string }
  query?: Record<string, string | number | boolean>
  headers?: { 'If-Match': string }
  body?: unknown
  contentType?: string
  signal?: AbortSignal
  idempotencyKey?: string
  maxResponseBytes?: number
  onProgress?: ProgressCallback
}

/** The part of a generated Client these commands use. Every generated module satisfies it. */
export interface ProposalClient {
  // The operation id and its input are checked by the generated Client, not here.
  call(operation: any, ...args: any[]): Promise<{ data: any }>
}

export interface ServedLink {
  accessProfile: string
  availability?: { available: boolean; observedRevision: number; reason?: string; recovery?: string }
  ifMatch?: string
  method: string
  operation: string
  path: string
}

export interface ServedSlot {
  id: string
  required: boolean
  maximumBytes: number
  contentTypes: string[]
  classification: string
  links: Record<string, ServedLink>
  value?: {
    submissionVersion: number
    sha256: string
    byteSize: number
    contentType: string
    uploadedAt?: string
    verificationStatus: 'notRequired' | 'pending' | 'approved' | 'rejected'
  }
}

export interface ServedApplication {
  applicationId: string
  appliedAt?: string
  appliedBy?: string
  effectDigest: string
  resultLinks: { recordId: string; recordType: string; revision: number }[]
  submissionVersion: number
}

export interface ServedApplicationStatus {
  automaticRetry?: { attempts: number; maximumAttempts: number; scheduled: boolean }
  mode: 'automatic' | 'manual'
  reason?: 'package-changed' | 'dependency-outage' | 'lease-expired' | 'application-refused' | 'attempts-exhausted'
  recovery?: 'retry' | 'rebase' | 'correct-input'
  state: 'awaiting-review' | 'pending' | 'applying' | 'blocked' | 'applied' | 'cancelled' | 'rejected'
}

/** The Proposal document exactly as the register serves it. */
export interface ServedProposal {
  id: string
  actionId: string
  state: ProposalState
  turn: Turn
  submissionVersion: number
  revision: number
  links: Record<string, ServedLink>
  attachments?: Record<string, ServedSlot>
  blockedReason?: 'package-changed'
  actionRevision: string
  application?: ServedApplication
  applicationStatus?: ServedApplicationStatus
  effectDigest?: string
  handoffRefusal?: { code: 'review.initiator-required' | 'review.initiator-excluded' | 'review.policy-mismatch' | 'review.refused' }
  decision?: { status: 'approved' | 'rejected' | 'changes-requested' | 'answered'; decidedAt: string; publicReason?: string }
  input?: JsonObject
  title?: string
  createdAt?: string
  status?: string
}

export interface Availability { available: boolean; reason?: string; recovery?: string; message: string }

export interface AttachmentView {
  status: 'empty' | 'attached' | 'pending' | 'approved' | 'rejected'
  required: boolean
  canUpload: boolean
  canDownload: boolean
  mediaType?: string
  size?: number
  accepts: { contentTypes: string[]; maximumBytes: number }
}

/** Plain JSON-safe data. `served` keeps the links, with their conditions, for the next command. */
export interface Proposal {
  id: string
  actionId: string
  actionRevision: string
  state: ProposalState
  turn: Turn
  status: ProposalStatus
  sentBack: boolean
  submissionVersion: number
  revision: number
  title?: string
  createdAt?: string
  decision?: { status: string; decidedAt: string; publicReason?: string }
  effectDigest?: string
  handoffRefusal?: ServedProposal['handoffRefusal']
  applicationStatus?: ServedApplicationStatus
  application?: ServedApplication
  blockedReason?: 'package-changed'
  input?: JsonObject
  attachments: Record<string, AttachmentView>
  can: Record<CommandName, Availability>
  served: ServedProposal
}

export interface ProposalListFilter {
  turn?: Turn
  state?: ProposalState
  action?: string
  owner?: 'caller'
  target?: string
  pendingManualApplication?: boolean
  cursor?: string
  limit?: number
}

interface Options { signal?: AbortSignal }
interface TransferOptions extends Options { onProgress?: ProgressCallback }

export interface ProposalCommands {
  start(actionId: string, input?: JsonObject, opts?: Options & { idempotencyKey?: string }): Promise<Proposal>
  get(id: string, opts?: Options): Promise<Proposal>
  list(filter?: ProposalListFilter, opts?: Options): Promise<{ items: Proposal[]; nextCursor: string | null }>
  edit(p: Proposal, changes: JsonChanges, opts?: Options): Promise<Proposal>
  rebase(p: Proposal, changes?: JsonChanges, opts?: Options): Promise<Proposal>
  attach(p: Proposal, slot: string, file: Blob, opts?: TransferOptions): Promise<Proposal>
  submit(p: Proposal, opts?: Options): Promise<Proposal>
  resubmit(p: Proposal, opts?: TransferOptions & { changes?: JsonChanges; files?: Record<string, Blob> }): Promise<Proposal>
  cancel(p: Proposal, opts?: Options): Promise<Proposal>
  download(p: Proposal, slot: string, opts?: TransferOptions): Promise<Blob>
}

// The `can.*` sentences live in the one words table in core, and are re-exported here. A programme's
// replacement table is passed to `proposalFromServed` and `proposalCommands`, and to `describeError`.
export { availabilityMessages }
type Words = Pick<DescribeOptions, 'clientSentences'>

const statuses: readonly string[] = ['draft', 'awaiting-party', 'in-review', 'approved', 'processing', 'applied', 'rejected', 'cancelled']
const listFilterMembers = ['turn', 'state', 'action', 'owner', 'target', 'pendingManualApplication', 'cursor', 'limit'] as const
const cacheLimit = 100

/**
 * The served `status` when it is one of the eight. Otherwise derived from state, turn,
 * decision and application status, since the client cannot see review progress.
 */
export function proposalStatus(served: ServedProposal): ProposalStatus {
  if (typeof served.status === 'string' && statuses.includes(served.status)) return served.status as ProposalStatus
  switch (served.state) {
    case 'draft': case 'cancelled': case 'applied': case 'rejected': return served.state
    case 'submitted': {
      if (served.turn === 'party') return 'awaiting-party'
      if (served.decision?.status === 'approved') return 'approved'
      const application = served.applicationStatus?.state
      return served.turn === 'official' && (application === undefined || application === 'awaiting-review') ? 'in-review' : 'processing'
    }
  }
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value).filter(([, v]) => v !== undefined).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    return '{' + entries.map(([k, v]) => JSON.stringify(k) + ':' + canonical(v)).join(',') + '}'
  }
  return JSON.stringify(value) ?? 'null'
}

/** `rc1-` and the SHA-256 of the canonical JSON of the parts: 68 bytes, the same for the same request. */
async function derivedKey(parts: unknown[]): Promise<string> {
  return 'rc1-' + await sha256Hex(new TextEncoder().encode(canonical(parts)))
}

function digestOf(value: string): string {
  return value.replace(/^sha256:/u, '').toLowerCase()
}

function unavailable(words: Words, reason: string, recovery?: string): Availability {
  const key = Object.hasOwn(availabilityMessages, reason) ? reason : 'unavailable'
  return { available: false, reason, ...(recovery === undefined ? {} : { recovery }), message: sentence(key, words) }
}

function availabilityOf(words: Words, link: ServedLink | undefined, needsCondition = true): Availability {
  if (!link || needsCondition && link.ifMatch === undefined) return unavailable(words, 'not-offered')
  const served = link.availability
  if (served && !served.available) {
    if (served.reason === undefined) return { available: false, ...(served.recovery === undefined ? {} : { recovery: served.recovery }), message: sentence('unavailable', words) }
    return unavailable(words, served.reason, served.recovery)
  }
  return { available: true, message: sentence('available', words) }
}

/** The register offers revise on any submitted proposal. A resubmit is only right while the party is to act. */
function resubmitAvailability(words: Words, served: ServedProposal): Availability {
  const link = availabilityOf(words, served.links['revise'])
  if (!link.available) return link
  return served.state === 'submitted' && served.turn === 'party' ? link : unavailable(words, 'not-awaiting-party')
}

/** Rebase is offered on any draft or submitted proposal. It is only right once the Action has changed under it. */
function rebaseAvailability(words: Words, served: ServedProposal): Availability {
  const link = availabilityOf(words, served.links['rebase'])
  if (!link.available) return link
  const links = [...Object.values(served.links), ...Object.values(served.attachments ?? {}).flatMap(slot => Object.values(slot.links))]
  const changed = served.blockedReason === 'package-changed' || links.some(other => other.availability?.recovery === 'rebase')
  // A manual Apply the register refused leaves Revise pointing at corrections, which only a rebase can make.
  const refused = served.state === 'submitted' && served.links['revise']?.availability?.recovery === 'correct-input'
  if (!changed && !refused) return unavailable(words, 'not-needed')
  return { available: true, message: sentence(changed ? 'rebase' : 'rebase-refused', words) }
}

function attachAvailability(words: Words, served: ServedProposal): Availability {
  const uploads = Object.values(served.attachments ?? {}).map(slot => availabilityOf(words, slot.links['upload']))
  return uploads.find(a => a.available) ?? uploads.find(a => a.reason !== 'not-offered') ?? unavailable(words, 'not-offered')
}

function attachmentView(words: Words, slot: ServedSlot): AttachmentView {
  const { value } = slot
  const status: AttachmentView['status'] = !value ? 'empty'
    : value.verificationStatus === 'notRequired' ? 'attached' : value.verificationStatus
  return {
    status, required: slot.required,
    canUpload: availabilityOf(words, slot.links['upload']).available,
    canDownload: availabilityOf(words, slot.links['download'], false).available,
    ...(value ? { mediaType: value.contentType, size: value.byteSize } : {}),
    accepts: { contentTypes: [...slot.contentTypes], maximumBytes: slot.maximumBytes },
  }
}

/**
 * The Proposal the commands return, made from a served document a page already holds. The `can.*` messages
 * come from the one words table, with the programme's replacement from `options.clientSentences`.
 */
export function proposalFromServed(served: ServedProposal, options: Words = {}): Proposal {
  const { links } = served
  return {
    id: served.id, actionId: served.actionId, actionRevision: served.actionRevision, state: served.state, turn: served.turn,
    status: proposalStatus(served),
    sentBack: served.state === 'submitted' && served.decision?.status === 'changes-requested',
    submissionVersion: served.submissionVersion, revision: served.revision,
    ...(served.title === undefined ? {} : { title: served.title }),
    ...(served.createdAt === undefined ? {} : { createdAt: served.createdAt }),
    ...(served.decision === undefined ? {} : { decision: served.decision }),
    ...(served.effectDigest === undefined ? {} : { effectDigest: served.effectDigest }),
    ...(served.handoffRefusal === undefined ? {} : { handoffRefusal: served.handoffRefusal }),
    ...(served.applicationStatus === undefined ? {} : { applicationStatus: served.applicationStatus }),
    ...(served.application === undefined ? {} : { application: served.application }),
    ...(served.blockedReason === undefined ? {} : { blockedReason: served.blockedReason }),
    ...(served.input === undefined ? {} : { input: served.input }),
    attachments: Object.fromEntries(Object.entries(served.attachments ?? {}).map(([id, slot]) => [id, attachmentView(options, slot)])),
    can: {
      edit: availabilityOf(options, links['edit']), attach: attachAvailability(options, served), submit: availabilityOf(options, links['submit']),
      resubmit: resubmitAvailability(options, served), rebase: rebaseAvailability(options, served), cancel: availabilityOf(options, links['cancel']),
    },
    served,
  }
}

type SentLink = ServedLink & { ifMatch: string }

function requireLink(words: Words, link: ServedLink | undefined, command: string, operation: string, availability = availabilityOf(words, link)): SentLink {
  if (!link || !availability.available) {
    throw refuse('client.command-unavailable', `Cannot ${command}: ${availability.message} (${availability.reason ?? 'unavailable'}).`,
      { command, ...(availability.reason === undefined ? {} : { reason: availability.reason }), ...(availability.recovery === undefined ? {} : { recovery: availability.recovery }) })
  }
  if (link.operation !== operation) {
    throw refuse('client.link-operation', `Cannot ${command}: the register offered a link for "${link.operation}" where "${operation}" was expected.`, { command })
  }
  return link as SentLink
}

function sameValue(input: JsonObject, key: string, value: JsonValue | undefined): boolean {
  return value === undefined ? !Object.hasOwn(input, key) : Object.hasOwn(input, key) && canonical(input[key]) === canonical(value)
}

function merge(input: JsonObject, changes: JsonChanges): JsonObject {
  const merged = { ...input }
  for (const [key, value] of Object.entries(changes)) {
    if (value === undefined) delete merged[key]
    else merged[key] = value
  }
  return merged
}

function staleCopy(): RegistryError {
  return clientError({
    kind: 'refused', reason: 'stale', outcomeUnknown: false,
    problem: { code: 'client.stale-copy', detail: 'The application changed since it was loaded. Reload it and try again.' },
  })
}

function readableInput(served: ServedProposal): JsonObject {
  if (served.input === undefined) {
    throw refuse('client.inputs-not-readable', 'This caller may not read the inputs of the request, so a change cannot be merged into them.')
  }
  return served.input
}

function slotOf(served: ServedProposal, slot: string): ServedSlot {
  const found = Object.hasOwn(served.attachments ?? {}, slot) ? served.attachments?.[slot] : undefined
  if (!found) {
    const known = Object.keys(served.attachments ?? {})
    throw refuse('client.unknown-slot', `This request has no attachment slot "${slot}". Known slots: ${known.length ? known.join(', ') : 'none'}.`)
  }
  return found
}

function checkFile(served: ServedProposal, slot: string, file: Blob): ServedSlot {
  const descriptor = slotOf(served, slot)
  // The register compares the content type exactly and allows no wildcards, so this does too.
  if (!descriptor.contentTypes.includes(file.type)) {
    throw refuse('client.file-type', `The slot "${slot}" accepts ${descriptor.contentTypes.join(', ')}. This file is ${file.type || 'of no known type'}.`)
  }
  if (file.size > descriptor.maximumBytes) {
    throw refuse('client.file-too-large', `The slot "${slot}" accepts files up to ${descriptor.maximumBytes} bytes. This file is ${file.size} bytes.`)
  }
  return descriptor
}

function downloadVersion(link: ServedLink, slot: ServedSlot): number {
  const fromPath = Number(new URL(link.path, 'https://registry.invalid').searchParams.get('submissionVersion'))
  const version = Number.isInteger(fromPath) && fromPath > 0 ? fromPath : slot.value?.submissionVersion
  if (version === undefined) throw refuse('client.link-operation', 'Cannot download: the register did not say which submission holds the file.', { command: 'download' })
  return version
}

/** A file and its digest, read once. */
interface Prepared { file: Blob; sha256: string }

async function prepare(file: Blob): Promise<Prepared> {
  return { file, sha256: await sha256Hex(await file.arrayBuffer()) }
}

/** Both documents hold the same file in the slot, or none. */
function slotUnchanged(a: ServedProposal, b: ServedProposal, slot: string): boolean {
  const x = a.attachments?.[slot]?.value
  const y = b.attachments?.[slot]?.value
  return x === undefined || y === undefined ? x === y : digestOf(x.sha256) === digestOf(y.sha256)
}

/** Sets `key`, newest last, and drops the oldest entry past the cache limit. */
function keep<V>(map: Map<string, V>, key: string, value: V): void {
  map.delete(key)
  map.set(key, value)
  if (map.size > cacheLimit) map.delete(map.keys().next().value!)
}

/** `clientSentences` is the same table passed to `describeError`, so every `can.*` message reads in the programme's words. */
export function proposalCommands(client: ProposalClient, options: { accessProfile: string } & Words): ProposalCommands {
  const { accessProfile } = options
  const words: Words = { clientSentences: options.clientSentences }
  const viewOf = (served: ServedProposal) => proposalFromServed(served, words)
  // The read after each of this instance's own writes, per Proposal. Reads a page makes for other
  // reasons never change what a command acts on.
  const own = new Map<string, ServedProposal>()
  // Proposals whose write landed but whose read failed: their cached state is not trusted.
  const untrusted = new Set<string>()
  // The start key per request, kept while the last attempt's outcome is open.
  const startKeys = new Map<string, string>()
  const tails = new Map<string, Promise<void>>()

  async function send(operation: `proposals.${string}` | `actions.${string}.start`, values: ProposalCallValues) {
    try {
      return await client.call(operation, values)
    } catch (error) {
      // The generated client throws a TypeError for a call it cannot build, before any request.
      if (error instanceof TypeError) {
        throw refuse('client.unknown-operation', `The register client cannot send "${operation}": ${error.message}.`, { operation })
      }
      throw error
    }
  }

  function serial<T>(id: string, task: () => Promise<T>): Promise<T> {
    const run = (tails.get(id) ?? Promise.resolve()).then(task)
    const tail = run.then(() => {}, () => {})
    tails.set(id, tail)
    void tail.then(() => { if (tails.get(id) === tail) tails.delete(id) })
    return run
  }

  async function read(id: string, signal?: AbortSignal): Promise<Proposal> {
    const { data } = await send('proposals.get', { path: { proposal_id: id }, query: { accessProfile }, signal })
    return viewOf(data as ServedProposal)
  }

  /** A read the register answered with the proposal's state now: later writes build from it. */
  function adopt(view: Proposal): Proposal {
    keep(own, view.id, view.served)
    untrusted.delete(view.id)
    return view
  }

  /** The read that follows a write. If it fails the write stands, and the error says so and keeps the write's key. */
  async function readAfterWrite(id: string, idempotencyKey: string, signal?: AbortSignal): Promise<Proposal> {
    try {
      return adopt(await read(id, signal))
    } catch (cause) {
      if (!(cause instanceof RegistryError)) throw cause
      untrusted.add(id)
      const error = clientError({
        kind: 'unreachable', reason: cause.reason, status: cause.status, idempotencyKey, outcomeUnknown: false,
        problem: { code: 'client.read-after-write', proposalId: id, detail: 'The change was saved, but the latest copy could not be read. Read the application again.' },
      })
      error.cause = cause
      throw error
    }
  }

  /** The document a command acts on: the page's copy, unless this instance's own write produced a newer one. */
  function copyOf(p: Proposal): ServedProposal {
    const mine = own.get(p.id)
    return mine && mine.revision > p.served.revision ? mine : p.served
  }

  /** As `copyOf`, but after a write whose read failed the register is read first. */
  async function target(p: Proposal, signal?: AbortSignal): Promise<ServedProposal> {
    return untrusted.has(p.id) ? adopt(await read(p.id, signal)).served : copyOf(p)
  }

  async function transition(name: 'edit' | 'submit' | 'revise' | 'rebase' | 'cancel', served: ServedProposal, body: JsonObject, signal?: AbortSignal): Promise<Proposal> {
    const availability = name === 'revise' ? resubmitAvailability(words, served) : name === 'rebase' ? rebaseAvailability(words, served) : undefined
    const link = requireLink(words, served.links[name], name, name, availability)
    const idempotencyKey = await derivedKey([name, served.id, link.ifMatch, body])
    await send(`proposals.${link.operation}`, {
      path: { proposal_id: served.id }, query: { accessProfile: link.accessProfile },
      headers: { 'If-Match': link.ifMatch }, body, idempotencyKey, signal,
    })
    return readAfterWrite(served.id, idempotencyKey, signal)
  }

  async function sendFile(served: ServedProposal, slot: string, prepared: Prepared, signal?: AbortSignal, onProgress?: ProgressCallback): Promise<Proposal> {
    const { file, sha256 } = prepared
    const descriptor = checkFile(served, slot, file)
    const link = requireLink(words, descriptor.links['upload'], 'attach', 'upload')
    const idempotencyKey = await derivedKey(['attach', served.id, link.ifMatch, { slot, sha256, contentType: file.type }])
    await send(`proposals.attachments.${slot}.patch`, {
      path: { proposal_id: served.id }, query: { accessProfile: link.accessProfile },
      headers: { 'If-Match': link.ifMatch }, body: file, contentType: file.type, idempotencyKey, signal, onProgress,
    })
    return readAfterWrite(served.id, idempotencyKey, signal)
  }

  function holdsFile(served: ServedProposal, slot: string, { file, sha256 }: Prepared): boolean {
    const value = served.attachments?.[slot]?.value
    return value !== undefined && digestOf(value.sha256) === sha256 && value.contentType === file.type
  }

  async function start(actionId: string, input: JsonObject, opts: Options & { idempotencyKey?: string }): Promise<Proposal> {
    const fingerprint = canonical([actionId, input])
    const idempotencyKey = opts.idempotencyKey ?? startKeys.get(fingerprint) ?? crypto.randomUUID()
    if (opts.idempotencyKey === undefined) keep(startKeys, fingerprint, idempotencyKey)
    try {
      const { data } = await send(`actions.${actionId}.start`, { query: { accessProfile }, body: { input }, idempotencyKey, signal: opts.signal })
      const view = await readAfterWrite((data as ServedProposal).id, idempotencyKey, opts.signal)
      startKeys.delete(fingerprint)
      return view
    } catch (error) {
      // An open outcome keeps the key, so the same request replays instead of starting a second proposal.
      const open = error instanceof RegistryError && (error.outcomeUnknown || error.kind === 'unreachable' || error.code === 'client.read-after-write')
      if (!open) startKeys.delete(fingerprint)
      throw error
    }
  }

  return {
    async start(actionId, input = {}, opts = {}) {
      if (!/^[a-z0-9][a-z0-9-]*$/u.test(actionId)) {
        throw refuse('client.action-id', `"${actionId}" is not an action id. An action id is lowercase letters, digits and hyphens.`)
      }
      return start(actionId, input, opts)
    },

    get: (id, opts = {}) => read(id, opts.signal),

    async list(filter = {}, opts = {}) {
      const query: Record<string, string | number | boolean> = { accessProfile }
      for (const member of listFilterMembers) {
        const value = filter[member]
        if (value !== undefined) query[member] = value
      }
      const { data } = await send('proposals.list', { query, signal: opts.signal })
      const page = data as { items: ServedProposal[]; nextCursor?: string }
      return { items: page.items.map(viewOf), nextCursor: page.nextCursor ?? null }
    },

    edit: (p, changes, opts = {}) => serial(p.id, async () => {
      const served = await target(p, opts.signal)
      // The merge keeps every input this caller can read. Merging into a projected input can
      // erase writable inputs the caller cannot read. The product is adding a compiler check
      // for that.
      return transition('edit', served, { input: merge(readableInput(served), changes) }, opts.signal)
    }),

    rebase: (p, changes = {}, opts = {}) => serial(p.id, async () => {
      const served = await target(p, opts.signal)
      // The generated rebase body always carries `input`, so the readable input is sent even without changes.
      // The same projected-input caveat as edit applies.
      requireLink(words, served.links['rebase'], 'rebase', 'rebase', rebaseAvailability(words, served))
      return transition('rebase', served, { input: merge(readableInput(served), changes) }, opts.signal)
    }),

    attach: (p, slot, file, opts = {}) => serial(p.id, async () => {
      const served = await target(p, opts.signal)
      checkFile(served, slot, file)
      return sendFile(served, slot, await prepare(file), opts.signal, opts.onProgress)
    }),

    submit: (p, opts = {}) => serial(p.id, async () => transition('submit', await target(p, opts.signal), {}, opts.signal)),

    cancel: (p, opts = {}) => serial(p.id, async () => transition('cancel', await target(p, opts.signal), {}, opts.signal)),

    resubmit: (p, { changes, files = {}, signal, onProgress } = {}) => serial(p.id, async () => {
      // The page's copy may be old, or another call or tab may have moved the application, so the
      // register's current document is read and tied to what this call asked for. It is this call's
      // own result, or a draft this call can finish, only when its version is exactly one past the
      // page's copy and it carries these changes. Anything else is a different round: refuse.
      // A plain read: the register's document becomes this instance's own copy only once it is this call's result.
      let view = await read(p.id, signal)
      const fresh = view.served
      const expected = p.served.submissionVersion + 1
      const entries = Object.entries(files)
      for (const [slot, file] of entries) checkFile(fresh, slot, file)
      const prepared = await Promise.all(entries.map(async ([slot, file]) => [slot, await prepare(file)] as const))
      const holdsChanges = (input: JsonObject | undefined) =>
        changes === undefined || input !== undefined && Object.entries(changes).every(([key, value]) => sameValue(input, key, value))
      let resuming = false
      if (fresh.submissionVersion === expected && fresh.state === 'submitted') {
        if (fresh.turn !== 'party' && holdsChanges(fresh.input) && prepared.every(([slot, item]) => holdsFile(fresh, slot, item))) return adopt(view)
        throw staleCopy()
      } else if (fresh.submissionVersion === expected && fresh.state === 'draft') {
        if (changes !== undefined) {
          if (!holdsChanges(readableInput(fresh))) throw staleCopy()
        } else if (canonical(fresh.input) !== canonical(p.served.input)) {
          // Nothing was asked to change, so the draft's input must be the page's copy.
          throw staleCopy()
        }
        // Revise carries the earlier round's attachments forward, so a slot may hold the new file or
        // what the page's copy held. Anything else is another tab's upload.
        if (!prepared.every(([slot, item]) => holdsFile(fresh, slot, item) || slotUnchanged(fresh, p.served, slot))) throw staleCopy()
        resuming = true
        view = adopt(view)
      } else if (fresh.submissionVersion !== p.served.submissionVersion) {
        throw staleCopy()
      }
      if (!resuming) {
        requireLink(words, fresh.links['revise'], 'resubmit', 'revise', resubmitAvailability(words, fresh))
        const body: JsonObject = changes === undefined ? {} : { input: merge(readableInput(fresh), changes) }
        view = await transition('revise', fresh, body, signal)
      }
      for (const [slot, item] of prepared) {
        if (!holdsFile(view.served, slot, item)) view = await sendFile(view.served, slot, item, signal, onProgress)
      }
      const input = view.served.input
      if (changes !== undefined && input !== undefined && !holdsChanges(input)) {
        view = await transition('edit', view.served, { input: merge(input, changes) }, signal)
      }
      return transition('submit', view.served, {}, signal)
    }),

    async download(p, slot, opts = {}) {
      const served = copyOf(p)
      const descriptor = slotOf(served, slot)
      const link = requireLink(words, descriptor.links['download'], 'download', 'download', availabilityOf(words, descriptor.links['download'], false))
      const { data } = await send(`proposals.attachments.${slot}.get`, {
        path: { proposal_id: served.id },
        query: { accessProfile: link.accessProfile, submissionVersion: downloadVersion(link, descriptor) },
        maxResponseBytes: descriptor.maximumBytes, signal: opts.signal, onProgress: opts.onProgress,
      })
      const { bytes, mediaType } = data as { bytes: Uint8Array<ArrayBuffer>; mediaType: string }
      const { value } = descriptor
      if (value && (bytes.length !== value.byteSize || await sha256Hex(bytes) !== digestOf(value.sha256))) {
        throw clientError({
          kind: 'unexpected', reason: 'schema', outcomeUnknown: false,
          problem: { code: 'client.content-digest', detail: 'The downloaded file does not match the size and digest the register served for it.' },
        })
      }
      return downloadedBlob(bytes, mediaType)
    },
  }
}

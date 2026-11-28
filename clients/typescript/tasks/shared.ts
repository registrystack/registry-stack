import { RegistryError } from '../core.ts'

/** Called as bytes move. `total` is undefined when the size is not known. */
export type ProgressCallback = (loaded: number, total: number | undefined) => void

// Types a downloaded file may keep. Anything else is handed back as opaque bytes.
const safeDownloadTypes = new Set(['application/pdf', 'image/png', 'image/jpeg'])

type ClientErrorInfo = ConstructorParameters<typeof RegistryError>[0]

/** An error a helper raises itself, marked so `describeError` shows the sentence for its `client.` code. */
export function clientError(info: ClientErrorInfo): RegistryError {
  return new RegistryError({ ...info, raisedByClient: true })
}

/** A refusal made by a helper before sending, in the same shape as a register refusal. */
export function refusal(code: string, detail: string, extra: Record<string, unknown> = {}, reason: 'input' | 'status' = 'input'): RegistryError {
  return clientError({ kind: 'refused', reason, outcomeUnknown: false, problem: { ...extra, code, detail } })
}

export async function sha256Hex(data: BufferSource): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data))
  return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('')
}

/** The bytes as a Blob typed with the served type only when it is on the safe list. */
export function downloadedBlob(bytes: Uint8Array<ArrayBuffer>, mediaType: string): Blob {
  const type = (mediaType.split(';', 1)[0] ?? '').trim().toLowerCase()
  return new Blob([bytes], { type: safeDownloadTypes.has(type) ? type : 'application/octet-stream' })
}

/** Internal primitive. The delivery verifier enforces the public key policy. */
export async function verifyMac(
  key: Uint8Array, signature: Uint8Array<ArrayBuffer>, id: string, timestamp: string, body: Uint8Array,
): Promise<boolean> {
  const prefix = id + '.' + timestamp + '.'
  const content = new Uint8Array(prefix.length + body.length)
  for (let index = 0; index < prefix.length; index++) content[index] = prefix.charCodeAt(index)
  content.set(body, prefix.length)
  const imported = await crypto.subtle.importKey('raw', Uint8Array.from(key), {
    name: 'HMAC', hash: 'SHA-256',
  }, false, ['verify'])
  return crypto.subtle.verify('HMAC', imported, signature, content)
}

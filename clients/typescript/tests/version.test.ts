import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import test from 'node:test'
import { Transport } from '../core.ts'

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
const patch = version.replace(/\.\d+$/u, '.999')

async function generated(directory: string, path: string, targetVersion: string) {
  const source = new URL(path, import.meta.url)
  const text = readFileSync(source, 'utf8')
    .replace(/(from ["'])(\.{1,2}\/[^"']+)/gu, (_, prefix, specifier) => prefix + new URL(specifier, source).href)
    .replaceAll('assertClientVersion(' + JSON.stringify(version) + ')', 'assertClientVersion(' + JSON.stringify(targetVersion) + ')')
  const output = join(directory, targetVersion + '-' + path.split('/').at(-1))
  writeFileSync(output, text)
  return import(pathToFileURL(output).href)
}

test('generated clients refuse incompatible runtimes and accept a patch difference at construction', async t => {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'registry-version-')))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const register = '../tests/fixtures/breg-list.ts'
  const service = '../generated/services/breg-minimal-casework.ts'
  const options = { baseUrl: 'https://example.test' }
  const transport = new Transport(options)
  const message = new RegExp('Generated client version 999\\.0\\.0.* runtime version .* regenerate .* install ', 'iu')

  const registerMismatch = await generated(directory, register, '999.0.0')
  assert.throws(() => new registerMismatch.Client(transport), message)
  const serviceMismatch = await generated(directory, service, '999.0.0')
  assert.throws(() => serviceMismatch.createRegistryClient(options), message)
  assert.throws(() => serviceMismatch.createRegistryServerClient({ ...options, token: () => '' }), message)

  const registerPatch = await generated(directory, register, patch)
  assert.doesNotThrow(() => new registerPatch.Client(transport))
  const servicePatch = await generated(directory, service, patch)
  assert.doesNotThrow(() => servicePatch.createRegistryClient(options))
})

test('client versions match by minor before 1.0 and by major from 1.0', async () => {
  const { compatibleClientVersions } = await import('../version.ts')
  assert.equal(compatibleClientVersions('0.48.1', '0.48.4'), true)
  assert.equal(compatibleClientVersions('0.48.1', '0.49.0'), false)
  assert.equal(compatibleClientVersions('0.48.1', '1.48.1'), false)
  assert.equal(compatibleClientVersions('1.0.1', '1.7.3'), true)
  assert.equal(compatibleClientVersions('1.7.3', '2.7.3'), false)
})

for (const [version, valid] of [
  ['0.49.0-_', false],
  ['0.49.0-..', false],
  ['0.49.0-rc.1', true],
  ['0.49.0+build.5', true],
] as const) {
  test('generated client version syntax: ' + version, async () => {
    const { compatibleClientVersions } = await import('../version.ts')
    assert.equal(compatibleClientVersions(version, '0.49.0'), valid)
  })
}

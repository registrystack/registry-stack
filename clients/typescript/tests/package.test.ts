import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

test('the browser package is publishable at the unified client release version', () => {
  const read = (path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'))
  const manifest = read('../package.json')
  const native = read('../../../crates/registry-stack-client-node/package.json')
  const lock = read('../package-lock.json')
  assert.ok(!manifest.private)
  assert.equal(manifest.version, native.version)
  assert.equal(lock.packages[''].version, manifest.version)
  assert.equal(lock.packages[''].name, manifest.name)
  assert.equal(manifest.exports['.'].types, './dist/browser.d.ts')
  assert.equal(manifest.exports['.'].default, './dist/browser.js')
  assert.equal(manifest.license, 'Apache-2.0')
  assert.deepEqual(manifest.bin, { 'registry-generate': './registry-generate.js' })
  assert.deepEqual(lock.packages[''].bin, { 'registry-generate': 'registry-generate.js' })
  assert.deepEqual(manifest.files, ['dist', 'registry-generate.js', 'LICENSE'])
})

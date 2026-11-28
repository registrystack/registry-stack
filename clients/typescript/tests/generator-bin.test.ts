import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'

test('the generator bin explains a missing build and forwards arguments after a build', t => {
  const checkout = mkdtempSync(join(tmpdir(), 'registry-generator-bin-'))
  t.after(() => rmSync(checkout, { recursive: true, force: true }))
  const manifest = new URL('../package.json', import.meta.url)
  const { bin } = JSON.parse(readFileSync(manifest, 'utf8')) as { bin: Record<string, string> }
  const entry = bin['registry-generate']!
  copyFileSync(manifest, join(checkout, 'package.json'))
  if (dirname(entry) === '.') copyFileSync(new URL('../' + entry, import.meta.url), join(checkout, entry))

  const run = () => spawnSync(process.execPath, [join(checkout, entry), '--help'], { encoding: 'utf8' })
  const withoutBuild = run()
  assert.equal(withoutBuild.status, 1)
  assert.equal(withoutBuild.stderr, 'Run npm run build first to use registry-generate from this checkout.\n')

  mkdirSync(join(checkout, 'dist'))
  writeFileSync(join(checkout, 'dist/generate-project.js'), 'console.log(process.argv[2])')
  const withBuild = run()
  assert.equal(withBuild.status, 0, withBuild.stderr)
  assert.equal(withBuild.stdout, '--help\n')
})

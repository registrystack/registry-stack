import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const cli = fileURLToPath(new URL('../generate-project.ts', import.meta.url))
const root = fileURLToPath(new URL('../', import.meta.url))
const { name, version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { name: string; version: string }
const fixture = fileURLToPath(new URL('./fixtures/breg-list.openapi.json', import.meta.url))

for (const scenario of ['success', 'two registers', 'missing bregctl', 'failed compile', 'inside package', 'duplicate', 'incompatible package', 'compatible patch'] as const) {
  test('project generator: ' + scenario, t => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'registry-project-')))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const project = join(dir, 'project')
    const second = join(dir, 'second')
    mkdirSync(project)
    mkdirSync(second)
    const stub = join(dir, 'bregctl')
    writeFileSync(stub, [
      '#!/bin/sh',
      'set -eu',
      '[ "$1" = generate ] && [ "$2" = openapi ] && [ -d "$3" ] && [ "$4" = --output ] || exit 2',
      scenario === 'failed compile' ? 'exit 14' : 'mkdir -p "$5/generated"',
      'cp "$BREG_TEST_OPENAPI" "$5/generated/openapi.json"',
    ].join('\n'), { mode: 0o755 })
    const output = scenario === 'inside package'
      ? fileURLToPath(new URL('../round5-refused.ts', import.meta.url))
      : join(dir, 'app', 'service.ts')
    if (scenario === 'incompatible package' || scenario === 'compatible patch') {
      const installed = join(dir, 'node_modules', name)
      mkdirSync(installed, { recursive: true })
      writeFileSync(join(installed, 'package.json'), JSON.stringify({
        name, version: scenario === 'incompatible package' ? '999.0.0' : version.replace(/\.\d+$/u, '.999'),
      }))
    }
    const args = ['--register', 'licences=' + project, '--products', 'casework', '--output', output]
    if (scenario === 'two registers') args.push('--register', 'other=' + second, '--route-prefix', 'other=/other')
    if (scenario === 'duplicate') args.push('--register', 'licences=' + second)
    const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', env: {
      ...process.env, RSTACK_BREGCTL_BIN: scenario === 'missing bregctl' || scenario === 'inside package' || scenario === 'incompatible package'
        ? join(dir, 'missing') : stub, BREG_TEST_OPENAPI: fixture,
    } })
    const failure = {
      'missing bregctl': /bregctl.*PATH.*RSTACK_BREGCTL_BIN/u,
      'failed compile': /bregctl.*compile.*licences.*14/u,
      'inside package': /output.*inside.*package/iu,
      'incompatible package': /Generator version .* installed .* version 999\.0\.0.* regenerate .* install /iu,
      duplicate: /duplicate.*licences/iu,
    }
    if (scenario === 'success' || scenario === 'two registers' || scenario === 'compatible patch') {
      assert.equal(result.status, 0, result.stderr)
      const service = readFileSync(output, 'utf8')
      assert.match(service, /licences: member0/u)
      assert.match(service, /casework: new CaseworkClient/u)
      assert.ok(existsSync(join(dir, 'app', 'service.licences.ts')))
      const register = readFileSync(join(dir, 'app', 'service.licences.ts'), 'utf8')
      for (const source of [service, register]) {
        assert.ok(source.includes('Stack version ' + version))
        assert.ok(source.includes('client version ' + version))
      }
      const registerImports = register.split('\n').filter(line => line.startsWith('import '))
      assert.deepEqual(new Set(registerImports.map(line => line.split(' from ')[1])),
        new Set([JSON.stringify(name + '/core'), JSON.stringify(name + '/schema')]))
      assert.ok(service.includes('from ' + JSON.stringify(name + '/products/casework')))
      if (scenario === 'success') {
        const tsc = join(root, 'node_modules/typescript/bin/tsc')
        const built = join(dir, 'built')
        const build = spawnSync(process.execPath, [tsc, '-p', join(root, 'tsconfig.browser.json'), '--outDir', built],
          { encoding: 'utf8' })
        assert.equal(build.status, 0, build.stdout + build.stderr)
        const config = join(dir, 'tsconfig.json')
        writeFileSync(config, JSON.stringify({
          compilerOptions: {
            target: 'ES2023', module: 'ESNext', moduleResolution: 'Bundler', strict: true,
            noEmit: true, allowImportingTsExtensions: true, types: [],
            paths: {
              [name + '/products/*']: ['./built/generated/*.d.ts'],
              [name + '/*']: ['./built/*.d.ts'],
            },
          },
          files: ['app/service.ts'],
        }))
        const check = spawnSync(process.execPath, [tsc, '-p', config], { encoding: 'utf8' })
        assert.equal(check.status, 0, check.stdout + check.stderr)
      }
      if (scenario === 'two registers') {
        assert.match(service, /other: member1/u)
        assert.match(service, /"\/other"/u)
        assert.ok(existsSync(join(dir, 'app', 'service.other.ts')))
      }
    } else {
      assert.equal(result.status, 1)
      assert.match(result.stderr, failure[scenario])
      assert.ok(!existsSync(output))
      assert.ok(!existsSync(join(dir, 'app', 'service.licences.ts')))
      if (scenario === 'incompatible package') {
        assert.ok(!existsSync(dirname(output)))
        const registerCli = join(root, 'generate.ts')
        const result = spawnSync(process.execPath, [registerCli, '--breg', fixture, output], { encoding: 'utf8' })
        assert.equal(result.status, 1)
        assert.match(result.stderr, failure[scenario])
        assert.ok(!existsSync(output))
      }
    }
  })
}

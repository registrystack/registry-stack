import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const cli = fileURLToPath(new URL('../generate-project.ts', import.meta.url))
const root = fileURLToPath(new URL('../', import.meta.url))
const { name, version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { name: string; version: string }
const fixture = fileURLToPath(new URL('./fixtures/breg-list.openapi.json', import.meta.url))

for (const scenario of ['success', 'two registers', 'missing bregctl', 'failed compile', 'inside package', 'duplicate', 'incompatible package', 'compatible patch',
  'old Node', 'missing package', 'invalid author profile', 'blocked register', 'different compiler patch', 'older compiler minor', 'newer compiler minor', 'browser import map'] as const) {
  test('project generator: ' + scenario, t => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), 'registry-project-')))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const project = join(dir, 'project')
    const second = join(dir, 'second')
    mkdirSync(project)
    mkdirSync(second)
    const [major, minor] = version.split('.').map(Number)
    const compilerVersion = scenario === 'different compiler patch' ? major + '.' + minor + '.1'
      : scenario === 'older compiler minor' ? major + '.' + (minor! - 1) + '.0'
      : scenario === 'newer compiler minor' ? major + '.' + (minor! + 1) + '.0'
      : version
    const stub = join(dir, 'bregctl')
    writeFileSync(stub, [
      '#!/bin/sh',
      'set -eu',
      '[ "$1" != --version ] || { printf "bregctl %s\\n" "$BREG_TEST_VERSION"; exit 0; }',
      '[ "$1" = generate ] && [ "$2" = openapi ] && [ -d "$3" ] && [ "$4" = --output ] || exit 2',
      scenario === 'failed compile' ? 'exit 14' : 'mkdir -p "$5/generated"',
      'cp "$BREG_TEST_OPENAPI" "$5/generated/openapi.json"',
    ].join('\n'), { mode: 0o755 })
    const output = scenario === 'inside package'
      ? fileURLToPath(new URL('../round5-refused.ts', import.meta.url))
      : join(dir, 'app', 'service.ts')
    if (scenario !== 'missing package') {
      const installed = join(dir, 'node_modules', name)
      mkdirSync(installed, { recursive: true })
      writeFileSync(join(installed, 'package.json'), JSON.stringify({
        name, version: scenario === 'incompatible package' ? '999.0.0' : scenario === 'compatible patch' ? version.replace(/\.\d+$/u, '.999') : version,
      }))
    }
    const products = scenario === 'browser import map' ? 'documents,casework,evidence' : 'casework'
    const args = ['--register', 'licences=' + project, '--products', products, '--output', output]
    if (scenario === 'browser import map') args.push('--author-profile', 'licences=facility-correction-author')
    const openapi = scenario === 'browser import map'
      ? fileURLToPath(new URL('../../../products/breg/generated/facility/generated/openapi.json', import.meta.url))
      : fixture
    if (scenario === 'two registers') args.push('--register', 'other=' + second, '--route-prefix', 'other=/other')
    if (scenario === 'duplicate') args.push('--register', 'licences=' + second)
    if (scenario === 'invalid author profile') args.push('--author-profile', 'licences=x')
    if (scenario === 'blocked register') {
      args.push('--register', 'other=' + second, '--route-prefix', 'other=/other')
      mkdirSync(join(dir, 'app', 'service.other.ts'), { recursive: true })
      writeFileSync(output, '// Previous service')
    }
    const preload = scenario === 'old Node'
      ? ['--import', 'data:text/javascript,Object.defineProperty(process.versions,"node",{value:"22.13.0"})']
      : []
    const result = spawnSync(process.execPath, [...preload, cli, ...args], { encoding: 'utf8', env: {
      ...process.env, RSTACK_BREGCTL_BIN: scenario === 'missing bregctl' || scenario === 'inside package' || scenario === 'incompatible package'
        ? join(dir, 'missing') : stub, BREG_TEST_OPENAPI: openapi, BREG_TEST_VERSION: compilerVersion,
    } })
    const failure = {
      'missing bregctl': /bregctl.*PATH.*RSTACK_BREGCTL_BIN/u,
      'failed compile': /bregctl.*compile.*licences.*14/u,
      'inside package': /output.*inside.*package/iu,
      'incompatible package': /Generator version .* installed .* version 999\.0\.0.* regenerate .* install /iu,
      duplicate: /duplicate.*licences/iu,
      'old Node': /^.*requires Node(?:\.js)? 24 or later\.\n$/u,
      'missing package': /install @registrystack\/client in the application/iu,
      'invalid author profile': /cannot start Proposals in licences/u,
      'older compiler minor': /bregctl version .* is incompatible with client version /u,
      'newer compiler minor': /bregctl version .* is incompatible with client version /u,
      'blocked register': /rename.*service\.other\.ts/u,
    }
    if (scenario === 'browser import map') {
      assert.equal(result.status, 0, result.stderr)
      const readme = readFileSync(join(root, 'README.md'), 'utf8')
      const importMap = /<script type="importmap">\s*([\s\S]*?)\s*<\/script>/u.exec(readme)?.[1]
      assert.ok(importMap, 'The README must document the import map')
      const tsc = join(root, 'node_modules/typescript/bin/tsc')
      const installed = join(dir, 'node_modules', name)
      const publicDir = join(dir, 'public')
      writeFileSync(join(installed, 'package.json'), readFileSync(join(root, 'package.json')))
      const built = join(installed, 'dist')
      const build = spawnSync(process.execPath, [tsc, '-p', join(root, 'tsconfig.browser.json'), '--outDir', built],
        { encoding: 'utf8' })
      assert.equal(build.status, 0, build.stdout + build.stderr)
      const compile = spawnSync(process.execPath, [tsc, '--strict', '--target', 'ES2023', '--module', 'ESNext',
        '--moduleResolution', 'Bundler', '--outDir', publicDir, output], { encoding: 'utf8' })
      assert.equal(compile.status, 0, compile.stdout + compile.stderr)
      writeFileSync(join(publicDir, 'package.json'), '{"type":"module"}')
      cpSync(built, join(publicDir, 'vendor/registry-client'), { recursive: true })
      const run = spawnSync(process.execPath, ['--input-type=module', '-', publicDir, importMap], {
        encoding: 'utf8',
        input: `
import assert from 'node:assert/strict'
import { registerHooks } from 'node:module'
import { pathToFileURL } from 'node:url'
const base = pathToFileURL(process.argv[2] + '/')
const { imports } = JSON.parse(process.argv[3])
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('@registrystack/')) {
      assert.ok(Object.hasOwn(imports, specifier), 'Missing import map entry for ' + specifier)
      specifier = new URL(imports[specifier].slice(1), base).href
    }
    return nextResolve(specifier, context)
  },
})
const { createRegistryClient } = await import(new URL('service.js', base).href)
const client = createRegistryClient({ baseUrl: 'https://registry.example' })
assert.equal(typeof client.licences.proposals.attach, 'function')
assert.equal(typeof client.documents.upload, 'function')
`,
      })
      assert.equal(run.status, 0, run.stdout + run.stderr)
      return
    }
    if (scenario === 'success' || scenario === 'two registers' || scenario === 'compatible patch' || scenario === 'different compiler patch') {
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
      if (scenario === 'success' || scenario === 'two registers') {
        const tsc = join(root, 'node_modules/typescript/bin/tsc')
        const installed = join(dir, 'node_modules', name)
        mkdirSync(installed, { recursive: true })
        writeFileSync(join(installed, 'package.json'), readFileSync(join(root, 'package.json')))
        const built = join(installed, 'dist')
        const build = spawnSync(process.execPath, [tsc, '-p', join(root, 'tsconfig.browser.json'), '--outDir', built],
          { encoding: 'utf8' })
        assert.equal(build.status, 0, build.stdout + build.stderr)
        const config = join(dir, 'tsconfig.json')
        writeFileSync(join(dir, 'package.json'), JSON.stringify({ type: 'module' }))
        for (const moduleResolution of ['NodeNext', 'Bundler']) {
          writeFileSync(config, JSON.stringify({
            compilerOptions: {
              target: 'ES2023', module: moduleResolution === 'NodeNext' ? 'NodeNext' : 'ESNext',
              moduleResolution, strict: true, types: [],
            },
            files: ['app/service.ts'],
          }))
          const check = spawnSync(process.execPath, [tsc, '--noEmit', '-p', config], { encoding: 'utf8' })
          assert.equal(check.status, 0, moduleResolution + '\n' + check.stdout + check.stderr)
        }
      }
      if (scenario === 'two registers') {
        assert.match(service, /other: member1/u)
        assert.match(service, /"\/other"/u)
        assert.ok(existsSync(join(dir, 'app', 'service.other.ts')))
      }
    } else {
      assert.equal(result.status, 1, result.stdout + result.stderr)
      assert.match(result.stderr, failure[scenario])
      if (scenario === 'older compiler minor' || scenario === 'newer compiler minor') {
        assert.ok(result.stderr.includes(compilerVersion))
        assert.ok(result.stderr.includes(version))
        const readme = readFileSync(join(root, 'README.md'), 'utf8')
        const documented = /^bregctl version (\d+\.\d+\.\d+) is incompatible with client version (\d+\.\d+\.\d+)\. .*$/mu.exec(readme)
        assert.ok(documented, 'The README must show the generator refusal')
        const expected = documented[0].replace('bregctl version ' + documented[1], 'bregctl version ' + compilerVersion)
          .replace('client version ' + documented[2], 'client version ' + version)
        assert.equal(result.stderr.trim(), expected)
      }
      if (scenario === 'blocked register') {
        assert.ok(existsSync(join(dir, 'app', 'service.licences.ts')))
        assert.equal(readFileSync(output, 'utf8'), '// Previous service')
        return
      }
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

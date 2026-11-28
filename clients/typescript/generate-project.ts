#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'
import { generate } from './generate.ts'
import { checkRegisterMember, generateService, type RegisterDescription, type ServiceSettings } from './generate-service.ts'
import { checkInstalledClient, packageFile } from './generator-package.ts'

const packageRoot = dirname(realpathSync(fileURLToPath(packageFile)))
const usage = 'Usage: registry-generate --register member=/path/to/project [--register member=/other/project] '
  + '[--products documents,casework] [--author-profile member=profile] [--route-prefix member=/prefix] --output service.ts'

function assignment(value: string): [string, string] {
  const equal = value.indexOf('=')
  if (equal < 1 || equal === value.length - 1) throw new Error('Expected member=value. ' + usage)
  return [value.slice(0, equal), value.slice(equal + 1)]
}

function physicalPath(path: string): string {
  if (lstatSync(path, { throwIfNoEntry: false })) return realpathSync(path)
  return join(physicalPath(dirname(path)), basename(path))
}

function outsidePackage(path: string): void {
  const inside = (target: string) => {
    const fromPackage = relative(packageRoot, target)
    return !isAbsolute(fromPackage) && fromPackage !== '..' && !fromPackage.startsWith('..' + sep)
  }
  if (inside(path) || inside(physicalPath(path))) throw new Error('The output is inside the package: ' + path)
}

function generateProject(): void {
  const { values } = parseArgs({ options: {
    register: { type: 'string', multiple: true },
    products: { type: 'string' },
    'author-profile': { type: 'string', multiple: true },
    'route-prefix': { type: 'string', multiple: true },
    output: { type: 'string' },
    help: { type: 'boolean' },
  } })
  if (values.help) { console.log(usage); return }
  if (!values.register?.length || !values.output?.endsWith('.ts') || values.output.endsWith('.d.ts')) {
    throw new Error(usage)
  }

  const requested = new Map<string, { project: string; authors: string[]; routePrefix?: string }>()
  for (const value of values.register) {
    const [member, project] = assignment(value)
    checkRegisterMember(member)
    if (requested.has(member)) throw new Error('Duplicate register member ' + member)
    requested.set(member, { project: resolve(project), authors: [] })
  }
  for (const value of values['author-profile'] ?? []) {
    const [member, profile] = assignment(value)
    const entry = requested.get(member)
    if (!entry) throw new Error('Unknown register member ' + member)
    entry.authors.push(profile)
  }
  for (const value of values['route-prefix'] ?? []) {
    const [member, routePrefix] = assignment(value)
    const entry = requested.get(member)
    if (!entry) throw new Error('Unknown register member ' + member)
    if (entry.routePrefix !== undefined) throw new Error('Duplicate route prefix for ' + member)
    entry.routePrefix = routePrefix
  }
  const output = resolve(values.output)
  outsidePackage(output)
  for (const member of requested.keys()) outsidePackage(output.slice(0, -3) + '.' + member + '.ts')

  checkInstalledClient(physicalPath(output))
  const workspace = mkdtempSync(join(tmpdir(), 'registry-openapi-'))
  const registers: Record<string, RegisterDescription> = Object.create(null)
  const settings: Record<string, NonNullable<ServiceSettings['registers']>[string]> = Object.create(null)
  const generated = new Map<string, string>()
  try {
    for (const [member, { project, authors, routePrefix }] of requested) {
      const artifacts = join(workspace, member)
      const result = spawnSync(process.env.RSTACK_BREGCTL_BIN || 'bregctl',
        ['generate', 'openapi', project, '--output', artifacts], { stdio: ['ignore', 'inherit', 'inherit'] })
      if (result.error) {
        if ((result.error as NodeJS.ErrnoException).code === 'ENOENT') {
          throw new Error('Cannot find bregctl on PATH or at RSTACK_BREGCTL_BIN.')
        }
        throw result.error
      }
      if (result.status !== 0) {
        throw new Error('bregctl could not compile register ' + member + ' (' + (result.status ?? result.signal) + ').')
      }
      const openapi = join(artifacts, 'generated', 'openapi.json')
      const source = join(workspace, member + '.ts')
      const module = output.slice(0, -3) + '.' + member + '.ts'
      const register = 'breg-project-' + generated.size
      const code = generate(readFileSync(openapi, 'utf8'), {
        breg: true, product: member,
      })
      writeFileSync(source, code)
      generated.set(module, code)
      registers[member] = { register, authorProfiles: authors }
      settings[member] = { source, import: './' + basename(module, '.ts') + '.js', routePrefix }
    }
    const service = generateService({ registers, products: values.products ? values.products.split(',') : [] }, {
      registers: settings,
    })
    const parent = dirname(output)
    mkdirSync(parent, { recursive: true })
    const staging = mkdtempSync(join(parent, '.registry-client-'))
    try {
      for (const [path, code] of generated) writeFileSync(join(staging, basename(path)), code)
      const stagedService = join(staging, basename(output))
      writeFileSync(stagedService, service)
      for (const path of generated.keys()) renameSync(join(staging, basename(path)), path)
      renameSync(stagedService, output)
    } finally {
      rmSync(staging, { recursive: true, force: true })
    }
  } finally {
    rmSync(workspace, { recursive: true, force: true })
  }
}

try {
  if (Number(process.versions.node.split('.')[0]) < 24) {
    throw new Error('registry-generate requires Node.js 24 or later.')
  }
  generateProject()
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error))
  process.exitCode = 1
}

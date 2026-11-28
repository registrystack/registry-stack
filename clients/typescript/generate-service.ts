import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { checkOutput } from './generate.ts'
import { generatedVersionComment, packageName, packageVersion } from './generator-package.ts'

export interface RegisterDescription {
  register: string
  /** The Proposal author profiles, with the default first. */
  authorProfiles?: readonly string[]
}

export interface ServiceDescription {
  registers: Readonly<Record<string, RegisterDescription>>
  products: readonly string[]
}

export interface ServiceSettings {
  /** Import path of core.ts from the generated file. */
  coreImport?: string
  /** Import path prefix of the generated product modules from the generated file. */
  modulesImport?: string
  /** Import path of the task helpers (`tasks/index.ts`) from the generated file. */
  tasksImport?: string
  /** File path of the register's generated module, read to see whether it has Proposal operations. */
  registers?: Readonly<Record<string, { source?: string; import?: string; routePrefix?: string }>>
  /** Suffix of generated product imports. */
  modulesExtension?: string
}

// Canonical order. The page entry offers every product except the ones listed in `serverOnly`.
const productClients = {
  casework: 'CaseworkClient',
  coordinator: 'CoordinatorClient',
  documents: 'DocumentsClient',
  evidence: 'EvidenceClient',
  'evidence-oid4vci': 'Oid4vciClient',
  messaging: 'MessagingClient',
  scheduling: 'SchedulingClient',
} as const
const serverOnly: readonly string[] = ['coordinator', 'evidence-oid4vci', 'messaging']

function registerDetails(member: string, description: RegisterDescription, source: string) {
  const { register } = description
  if (!/^breg-[a-z0-9]+(-[a-z0-9]+)*$/u.test(register)) {
    throw new Error('Invalid BReg register module ' + register)
  }
  const registerText = readFileSync(source, 'utf8')
  // The operations table declares the profiles for each start, independently of Proposal reads.
  const startRows = registerText.match(/^ {2}"actions\.[^"]+\.start": .*$/gmu) ?? []
  const hasProposals = startRows.length > 0 || /^ {2}"proposals\.get": /mu.test(registerText)
  const authors = description.authorProfiles ?? []
  if (hasProposals && authors.length === 0) {
    throw new Error('The register ' + member + ' has Proposals, so the service description needs authorProfiles.')
  }
  const granted = new Set<string>()
  for (const row of startRows) {
    const type = /"accessProfile"\??: ([^;}]+)/u.exec(row)?.[1]
    for (const literal of type?.match(/"(?:[^"\\]|\\.)*"/gu) ?? []) granted.add(JSON.parse(literal))
  }
  for (const author of authors) {
    if (!granted.has(author)) {
      throw new Error('The authorProfile ' + JSON.stringify(author) + ' cannot start Proposals in ' + member
        + '. Profiles granted Proposal start: ' + ([...granted].sort().join(', ') || 'none') + '.')
    }
  }
  if (new Set(authors).size !== authors.length) throw new Error('List each author profile for ' + member + ' only once.')
  const hasTypedProposals = registerText.includes('export interface ProposalActions {')
  return { authors, hasTypedProposals }
}

const productField = (product: string) => product === 'evidence-oid4vci' ? 'oid4vci' : product

export function checkRegisterMember(name: string): void {
  const products = Object.keys(productClients)
  const reserved = [...products, ...products.map(productField), ...Object.getOwnPropertyNames(Object.prototype), 'then']
  if (reserved.includes(name)) throw new Error('Register member name clashes with ' + name)
  if (!/^[a-zA-Z][a-zA-Z0-9_]*$/u.test(name)) throw new Error('Invalid register member name ' + name)
}

export function generateService(description: ServiceDescription, settings: ServiceSettings = {}): string {
  const { registers, products } = description
  const known = Object.keys(productClients)
  for (const product of products) {
    if (!known.includes(product)) throw new Error('Unknown product ' + product)
  }
  for (const product of products) {
    if (products.indexOf(product) !== products.lastIndexOf(product)) throw new Error('Product ' + product + ' is listed twice')
  }
  const installed = known.filter(product => products.includes(product)) as Array<keyof typeof productClients>
  const shared = installed.filter(product => !serverOnly.includes(product))
  const server = installed.filter(product => serverOnly.includes(product))
  if (Object.keys(registers).length === 0) throw new Error('Declare at least one register member.')
  const members = Object.entries(registers).map(([name, entry], index) => {
    checkRegisterMember(name)
    const setting = Object.hasOwn(settings.registers ?? {}, name) ? settings.registers?.[name] : undefined
    const source = setting?.source ?? fileURLToPath(new URL('./generated/' + entry.register + '.ts', import.meta.url))
    return { name, entry, index, setting, ...registerDetails(name, entry, source) }
  })
  const typed = members.filter(member => member.hasTypedProposals)
  const typedNames = new Set(typed.map(({ name }) => name))
  const proposalTypeName = (name: string) => {
    const capitalized = name.charAt(0).toUpperCase() + name.slice(1)
    // Keep case-distinct register members distinct in the generated exports.
    return (typedNames.has(capitalized) ? name : capitalized) + 'Proposal'
  }
  const hasAuthors = members.some(member => member.authors.length > 0)
  const core = settings.coreImport ?? packageName + '/core'
  const modules = settings.modulesImport ?? packageName + '/products/'
  const tasks = settings.tasksImport ?? packageName + '/tasks'
  const extension = settings.modulesExtension ?? ''
  const registerImports = members.map(({ entry, index, setting, hasTypedProposals }) =>
    'import { Client as Register' + index + ', type AccessProfile as Profile' + index
    + (hasTypedProposals ? ', type ProposalActions as Actions' + index : '') + ' } from '
    + JSON.stringify(setting?.import ?? modules + entry.register + extension))
  const memberFactories = members.flatMap(({ name, index, setting, authors, hasTypedProposals }) => {
    const commandType = hasTypedProposals ? ' as TypedProposalCommands<Actions' + index + '>' : ''
    return [
      'function member' + index + '(transport: Transport, options?: RegisterOptions<Profile' + index + '>) {',
      '  const register = new Register' + index + '(transport.register(options?.routePrefix ?? '
        + JSON.stringify(setting?.routePrefix ?? '') + ', options?.profile))',
      ...(authors.length === 0 ? ['  return register'] : [
        '  type AuthorProfile = ' + authors.map(author => JSON.stringify(author)).join(' | '),
        '  const allowedProfiles: readonly AuthorProfile[] = ' + JSON.stringify(authors),
        '  const commandsFor = (accessProfile: AuthorProfile) => proposalCommands(register, { accessProfile })' + commandType,
        '  const commands = new Map<AuthorProfile, ReturnType<typeof commandsFor>>()',
        '  function proposalsAs(profile: AuthorProfile) {',
        '    if (!allowedProfiles.includes(profile)) throw new TypeError("Choose a declared Proposal author profile for ' + name + '.")',
        '    let proposals = commands.get(profile)',
        '    if (proposals === undefined) {',
        '      proposals = commandsFor(profile)',
        '      commands.set(profile, proposals)',
        '    }',
        '    return proposals',
        '  }',
        '  return Object.assign(register, { proposals: proposalsAs(' + JSON.stringify(authors[0]) + '), proposalsAs })',
      ]),
      '}',
      '',
    ]
  })
  const helpers = [...(hasAuthors ? ['proposalCommands'] : []), ...(typed.length ? ['type TypedProposalCommands'] : []),
    ...(installed.includes('documents') ? ['documentCommands'] : [])]
  const construct = (product: keyof typeof productClients) =>
    product === 'documents' ? 'documentCommands(new ' + productClients[product] + '(transport))' : 'new ' + productClients[product] + '(transport)'
  const fields = (list: readonly (keyof typeof productClients)[]) =>
    list.map(product => '    ' + productField(product) + ': ' + construct(product) + ',')
  return [
    '// Generated by generate-service.ts. Do not edit.',
    generatedVersionComment,
    '// Registers: ' + members.map(member => member.name).join(', ') + '. Products: ' + (installed.length ? installed.join(', ') : 'none') + '.',
    "import { assertClientVersion, Transport, type ClientOptions } from '" + core + "'",
    ...registerImports,
    ...installed.map(product => 'import { Client as ' + productClients[product] + ' } from '
      + JSON.stringify(modules + product + extension)),
    ...(helpers.length ? ["import { " + helpers.join(', ') + " } from '" + tasks + "'"] : []),
    '',
    ...(typed.length ? [
      "export type { ProposalStatus, AttachmentView } from '" + tasks + "'",
      'export interface RegisterProposalActions {',
      ...typed.map(({ name, index }) => '  ' + name + ': Actions' + index),
      '}',
      ...typed.map(({ name, index }) =>
        'export type ' + proposalTypeName(name) + ' = Awaited<ReturnType<TypedProposalCommands<Actions'
          + index + '>["get"]>>'),
      ...(members.length === 1 ? [
        'export type ProposalActions = Actions0',
        'export type ProposalListRow = ' + proposalTypeName(members[0]!.name),
        'export type ProposalSlot<Action extends keyof ProposalActions = keyof ProposalActions> = ProposalActions[Action]["slot"]',
      ] : []),
      '',
    ] : []),
    'type RegisterOptions<Profile> = { routePrefix?: string; profile?: Profile }',
    'type ServiceClientOptions = Omit<ClientOptions, "token" | "profile"> & {',
    ...(members.length === 1 ? ['  profile?: Profile0'] : []),
    '  registers?: {',
    ...members.map(({ name, index }) => '    ' + name + '?: RegisterOptions<Profile' + index + '>'),
    '  }',
    '}',
    '',
    '/** The options a page client takes. There is no `token`: the page\'s session part signs each call. */',
    "export type PageClientOptions = ServiceClientOptions",
    '',
    '/** The options a server client takes. `token` runs on each call for a bearer credential. */',
    "export type ServerClientOptions = ServiceClientOptions & { token: () => string | Promise<string> }",
    '',
    'function pageProducts(transport: Transport) {',
    '  return {',
    ...fields(shared),
    '  }',
    '}',
    '',
    'function serverProducts(transport: Transport) {',
    '  return {',
    ...fields(shared),
    ...fields(server),
    '  }',
    '}',
    '',
    ...memberFactories,
    'function registerMembers(transport: Transport, options: ServiceClientOptions) {',
    '  return {',
    ...members.map(({ name, index }) => '    ' + name + ': member' + index + '(transport, options.registers?.' + name + '),'),
    '  }',
    '}',
    '',
    'export type RegistryClient = ReturnType<typeof registerMembers> & ReturnType<typeof pageProducts>',
    'export type RegistryServerClient = ReturnType<typeof registerMembers> & ReturnType<typeof serverProducts>',
    '',
    '/**',
    ' * The client for a page. It sends no `Authorization`, sends cookies to the page\'s own origin',
    ' * only and sends `Registry-Client: page` on every call. Coordinator, OID4VCI and Messaging',
    ' * are server-only products.',
    ' */',
    'export function createRegistryClient(options: PageClientOptions): RegistryClient {',
    "  if ('token' in options) throw new TypeError('A page client takes no token, so use createRegistryServerClient on a server.')",
    '  assertClientVersion(' + JSON.stringify(packageVersion) + ')',
    '  const transport = new Transport(options)',
    '  return { ...registerMembers(transport, options), ...pageProducts(transport) }',
    '}',
    '',
    '/**',
    ' * The client for a function, a script or a back end. It requires a token, omits cookies, does',
    ' * not send `Registry-Client` and offers every installed product. It refuses to construct in',
    ' * a page.',
    ' */',
    'export function createRegistryServerClient(options: ServerClientOptions): RegistryServerClient {',
    "  if (typeof globalThis.document !== 'undefined') {",
    "    throw new TypeError('A server client cannot run in a page, so use createRegistryClient in a page.')",
    '  }',
    "  if (typeof options.token !== 'function') throw new TypeError('A server client needs a token function.')",
    '  assertClientVersion(' + JSON.stringify(packageVersion) + ')',
    '  const transport = new Transport(options)',
    '  return { ...registerMembers(transport, options), ...serverProducts(transport) }',
    '}',
    '',
  ].join('\n')
}

export function generateServiceFile(
  description: ServiceDescription, output: string, check: boolean, settings: ServiceSettings = {},
): void {
  const result = generateService(description, settings)
  if (check) checkOutput(result, readFileSync(output, 'utf8'), output)
  else writeFileSync(output, result)
}

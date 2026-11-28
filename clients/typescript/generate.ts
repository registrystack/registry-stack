import { readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, relative, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

type Node = Record<string, any>
const quote = JSON.stringify
const escape = (key: string) => key.replaceAll('~', '~0').replaceAll('/', '~1')
const unescape = (key: string) => key.replaceAll('~1', '/').replaceAll('~0', '~')
const child = (pointer: string, key: string) => pointer + '/' + escape(key)
const fail = (pointer: string, reason: string): never => { throw new Error(pointer + ': ' + reason) }

const unconstrained: Record<string, readonly string[]> = {
  'Registry Scheduling API': ['/components/schemas/AppointmentHistoryEntryDocument/properties/detail'],
  'Registry Casework API': [
    'ReviewHistoryEntry/properties/detail', 'ReviewPolicy/properties/displaySchema',
    'ReviewPolicy/properties/resultSchema', 'ReviewPolicyClosure/properties/displaySchema',
    'ReviewPolicyClosure/properties/resultSchema', 'ReviewTaskContext/properties/resultConstraints',
    'ReviewTaskContextData/oneOf/0/properties/snapshot', 'ReviewTaskDraft/properties/body',
    'ReviewTaskDraftInput/properties/body', 'RoutingPredicate/oneOf/0/properties/equals',
    'RoutingPredicate/oneOf/1/properties/oneOf/items',
  ].map(pointer => '/components/schemas/' + pointer),
  'Registry Coordinator': ['HookEnvelope/properties/data', 'RunStatus/properties/output',
    'Start/properties/input', 'WorkflowContract/properties/input'].map(pointer => '/components/schemas/' + pointer),
  'Registry Messaging API': [
    '/components/schemas/SubmitMessageRequest/properties/data',
    '/components/schemas/TemplatePreviewRequest/properties/data',
    '/paths/~1v1~1provider-callbacks~1{provider_id}/post/requestBody/content/application~1json/schema',
    '/paths/~1v1~1provider-callbacks~1{provider_id}~1{token}/post/requestBody/content/application~1json/schema',
  ],
  'local-directory': [
    '/paths/~1v1~1records~1contacts~1{record_id}/patch/requestBody/content/application~1json-patch+json/schema/items/properties/value',
  ],
  'facility-registry': ['directory-entries', 'operators'].map(route =>
    '/paths/~1v1~1records~1' + route + '~1{record_id}/patch/requestBody/content/application~1json-patch+json/schema/items/properties/value'),
}

// Receipt lookups read a retained answer under the caller's original key. The documents
// carry no machine-readable mark for a keyed read, so they are listed by contract and route.
// A keyed operation that looks like a read and is not listed stops the generator.
const receiptLookups: Record<string, readonly string[]> = {
  'Registry Messaging API': ['post /v1/messages/receipt'],
  'Registry Scheduling API': ['post /v1/appointments/receipt'],
}
function looksLikeRead(id: string, path: string, operation: Node): boolean {
  return /^(?:read|get|list|lookup|search|find|fetch)(?![a-z])/u.test(id)
    || /\/receipts?$/u.test(path)
    || /^read\b/iu.test(String(operation.summary ?? ''))
    || operation['x-scheduling-authority'] === 'reads-scope'
}

interface QueryProfile {
  profile: string
  maximumPageSize: number
  allowCount: boolean
  selectable: string[]
  filterable: { property: string; operators: string[] }[]
  sortable: { property: string; directions: string[] }[]
  requiredFilters?: string[][]
}
const filterOperators = new Set(['equals', 'in', 'range', 'is-null', 'is-not-null', 'prefix', 'contains'])
// A property name goes into a $filter, $orderby or $select value as written, so it must be a
// plain identifier.
const queryProperty = /^[A-Za-z_][A-Za-z0-9_.-]*$/u

// Reads the query profiles a BReg list operation publishes, in either form, and refuses any
// shape this client cannot type. Undefined when the operation publishes none.
function queryProfiles(operation: Node, pointer: string): QueryProfile[] | undefined {
  const several = operation['x-registry-queryProfiles']
  const one = operation['x-registry-queryProfile']
  if (several !== undefined && one !== undefined) fail(pointer, 'both x-registry-queryProfiles and x-registry-queryProfile')
  if (several === undefined && one === undefined) return undefined
  const entries: [string | undefined, Node, string][] = one !== undefined
    ? [[undefined, one, child(pointer, 'x-registry-queryProfile')]]
    : several && typeof several === 'object' && !Array.isArray(several)
      ? members(several).map(([key, value]) => [key, value, child(child(pointer, 'x-registry-queryProfiles'), key)])
      : fail(child(pointer, 'x-registry-queryProfiles'), 'expected an object of query profiles')
  if (!entries.length) fail(pointer, 'expected at least one query profile')
  const names = (value: unknown, at: string): string[] => {
    if (!Array.isArray(value)) return fail(at, 'expected a list of property names')
    value.forEach((name, index) => {
      if (typeof name !== 'string' || !queryProperty.test(name)) fail(child(at, String(index)), 'expected a property name')
    })
    return value
  }
  return entries.map(([key, value, at]) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return fail(at, 'expected a query profile')
    if (typeof value.profile !== 'string' || (key !== undefined && value.profile !== key)) fail(at, 'profile does not match its name')
    if (value.kind !== 'list') fail(at, 'only list query profiles are supported')
    if (!Number.isSafeInteger(value.maximumPageSize) || value.maximumPageSize < 1) fail(at, 'expected a maximum page size of at least 1')
    if (typeof value.allowCount !== 'boolean') fail(at, 'expected allowCount')
    const selectable = names(value.selectableProperties, child(at, 'selectableProperties'))
    const listOf = (field: string, member: string, allowed: Set<string>) => {
      const list = value[field]
      if (!Array.isArray(list)) return fail(child(at, field), 'expected a list')
      return list.map((entry: Node, index: number) => {
        const entryAt = child(child(at, field), String(index))
        if (!entry || typeof entry.property !== 'string' || !queryProperty.test(entry.property)) fail(entryAt, 'expected a property name')
        if (!Array.isArray(entry[member]) || !entry[member].length || entry[member].some((item: unknown) => !allowed.has(item as string))) {
          fail(entryAt, 'unsupported ' + member)
        }
        return { property: entry.property as string, [member]: entry[member] as string[] }
      })
    }
    const filterable = listOf('filterableProperties', 'operators', filterOperators) as QueryProfile['filterable']
    const sortable = listOf('sortableProperties', 'directions', new Set(['asc', 'desc'])) as QueryProfile['sortable']
    const profile: QueryProfile = { profile: value.profile, maximumPageSize: value.maximumPageSize, allowCount: value.allowCount,
      selectable, filterable, sortable }
    const required = value.requiredFilters
    if (required !== undefined) {
      const requiredAt = child(at, 'requiredFilters')
      if (!Array.isArray(required) || required.some((alternative: unknown) => !Array.isArray(alternative))) {
        fail(requiredAt, 'expected a list of alternatives, each a list of property names')
      }
    }
    // BReg publishes an empty list for a profile that requires no filter.
    if (Array.isArray(required) && required.length) {
      const requiredAt = child(at, 'requiredFilters')
      profile.requiredFilters = required.map((alternative: unknown[], index: number) => {
        const alternativeAt = child(requiredAt, String(index))
        if (!alternative.length) fail(alternativeAt, 'expected at least one property')
        return names(alternative, alternativeAt).map((name, position) => {
          if (!filterable.some(entry => entry.property === name && entry.operators.includes('equals'))) {
            fail(child(alternativeAt, String(position)), 'required filter is not an equality filter')
          }
          return name
        })
      })
    }
    return profile
  })
}

const patternSites = new Set([
  '/components/schemas/TaskTemplate/properties/subjects',
  '/components/schemas/RoutingCondition/properties/fields',
])
const annotations = new Set([
  '$id', '$schema', 'default', 'description', 'example', 'examples', 'title', 'format', 'writeOnly',
  'readOnly', 'deprecated', 'discriminator', 'contentEncoding', 'contentMediaType',
])
const keywords = new Set([
  '$ref', '$defs', 'type', 'nullable', 'const', 'enum', 'properties', 'required', 'items',
  'additionalProperties', 'patternProperties', 'propertyNames', 'allOf', 'anyOf', 'oneOf', 'not',
  'if', 'then', 'else', 'dependentRequired', 'minimum', 'maximum', 'minItems', 'maxItems',
  'minLength', 'maxLength', 'minProperties', 'maxProperties', 'uniqueItems', 'pattern',
])
function unicodePattern(pattern: string, pointer: string): string {
  const normalized = pattern.replace(/(\\+)"/gu, (_, slashes: string) =>
    (slashes.length % 2 === 0 ? slashes : slashes.slice(1)) + '"')
  try { new RegExp(normalized, 'u') } catch { fail(pointer, 'unsupported regular expression') }
  return normalized
}

const methods = new Set(['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'])
const record = '[a-z0-9][a-z0-9-]*'
const bregRoutes = [
  'records/' + record + '(?::(?:lookup|batch|snapshot|current|as-of)|/ingestion-runs' +
    '(?:/\\{run_id\\}(?:/(?:cancel|chunks(?:/\\{chunk_index\\}/receipt)?))?)?|/\\{record_id\\}' +
    '(?:/(?:' + record + '|attachments/' + record + '))?)?',
  'actions/' + record + '(?:/(?:proposals|availability|target-conditions))?',
  'proposals(?:/review-context|/\\{proposal_id\\}(?:/(?:apply|cancel|edit|rebase|retry|revise|review-context|' +
    'review-status|task-grant-context|submit|submissions/\\{submission_version\\}|attachments/' + record + '))?)?',
  'statistics/' + record + '(?::(?:live|exact)|/releases(?::series|/\\{period\\}' +
    '(?:/versions(?::dry-run|/\\{version\\}(?:/withdrawal)?))?)?)',
  'review-completions',
]
const bregRoute = new RegExp('^/v1/(?:' + bregRoutes.join('|') + ')$')

const isJson = (media: string) => /(?:\/json|\+json)(?:;|$)/u.test(media)
const members = (value: Node | undefined): [string, any][] => Object.entries(value ?? {})
const identifier = (value: string) => value.replace(/[^a-zA-Z0-9_]/gu, '_')

interface Settings {
  breg?: boolean
  coreImport?: string
  schemaImport?: string
  allowUnconstrained?: readonly string[]
}

export function generate(source: string, settings: Settings = {}): string {
  const doc = JSON.parse(source) as Node
  if (!/^3\.[01]\.\d+$/u.test(doc.openapi)) fail('/openapi', 'expected OpenAPI 3.0 or 3.1')
  if (!doc.paths || typeof doc.paths !== 'object') fail('/paths', 'expected paths')
  const breg = settings.breg ?? members(doc.paths).some(([, item]) =>
    members(item).some(([, operation]) => operation?.['x-registry-recordType'] || operation?.['x-registry-action']))
  const title = doc.info?.title
  const allowed = new Set([
    ...(Object.hasOwn(unconstrained, title) ? unconstrained[title]! : []),
    ...settings.allowUnconstrained ?? [],
  ])
  const used = new Set<string>()
  const validationRoots = new Set<string>()
  const types = new Map<string, string>()
  const rules = new Map<string, Node | boolean>()
  const aliases = new Map<string, string>()
  const schemas = doc.components?.schemas ?? {}
  for (const [name] of members(schemas)) {
    const pointer = '/components/schemas/' + escape(name)
    const alias = 'Schema_' + identifier(name)
    if ([...aliases.values()].includes(alias)) fail(pointer, 'colliding component name')
    aliases.set(pointer, alias)
  }
  function lookup(pointer: string): any {
    let value: any = doc
    for (const segment of pointer.split('/').slice(1)) {
      const key = unescape(segment)
      if (!value || !Object.hasOwn(value, key)) fail(pointer, 'missing reference')
      value = value[key]
    }
    return value
  }
  function reference(value: string, pointer: string): string {
    if (typeof value !== 'string' || !value.startsWith('#/')) return fail(pointer, 'only local references are supported')
    const target = value.slice(1)
    lookup(target)
    return target
  }
  function audit(schema: Node | boolean, pointer: string): void {
    if (rules.has(pointer)) return
    if (schema === false) { rules.set(pointer, false); return }
    if (schema !== true && (!schema || Array.isArray(schema) || typeof schema !== 'object')) {
      return fail(pointer, 'expected schema object or boolean')
    }
    const keys = schema === true ? [] : Object.keys(schema)
    for (const key of keys) {
      if (!keywords.has(key) && !annotations.has(key) && !key.startsWith('x-')) {
        fail(child(pointer, key), 'unsupported schema keyword')
      }
    }
    if (!keys.some(key => keywords.has(key))) {
      if (!allowed.has(pointer)) fail(pointer, 'unconstrained schema is outside the reviewed allowlist')
      used.add(pointer)
      rules.set(pointer, true)
      return
    }
    const node = schema as Node
    const rule: Node = Object.fromEntries(members(node).filter(([key]) => keywords.has(key) && key !== '$defs'))
    rules.set(pointer, rule)
    if (node.nullable === true) {
      if (!node.type || doc.openapi.startsWith('3.1')) fail(child(pointer, 'nullable'), 'unsupported nullable schema')
      rule.type = [node.type, 'null']
    }
    delete rule.nullable
    if (node.enum && (!Array.isArray(node.enum) || !node.enum.length)) fail(child(pointer, 'enum'), 'expected a non-empty enum')
    if (node.pattern !== undefined) {
      rule.pattern = unicodePattern(node.pattern, child(pointer, 'pattern'))
    }
    if (node.type && ![node.type].flat().every(type => ['array', 'object', 'number', 'integer', 'null', 'string', 'boolean'].includes(type))) {
      fail(child(pointer, 'type'), 'unsupported schema type')
    }
    if (node.$ref) {
      const target = reference(node.$ref, child(pointer, '$ref'))
      rule.$ref = target
      validationRoots.add(target)
      audit(lookup(target), target)
    }
    if (node.patternProperties && (title !== 'Registry Casework API' || !patternSites.has(pointer)
        || node.additionalProperties !== false || node.properties || Object.keys(node.patternProperties).length !== 1)) {
      fail(child(pointer, 'patternProperties'), 'unsupported pattern map')
    }
    if (node.additionalProperties && typeof node.additionalProperties === 'object' && node.properties) {
      fail(child(pointer, 'additionalProperties'), 'typed maps with named properties are unsupported')
    }
    for (const key of ['properties', 'patternProperties', '$defs']) {
      for (const [name, nested] of members(node[key])) {
        const at = child(child(pointer, key), name)
        if (key === 'patternProperties') unicodePattern(name, at)
        audit(nested, at)
      }
    }
    for (const key of ['items', 'propertyNames', 'not', 'if', 'then', 'else', 'additionalProperties']) {
      if (node[key] === undefined || key === 'additionalProperties' && typeof node[key] === 'boolean') continue
      audit(node[key], child(pointer, key))
    }
    for (const key of ['allOf', 'anyOf', 'oneOf']) {
      if (!Object.hasOwn(node, key)) continue
      if (!Array.isArray(node[key]) || !node[key].length) fail(child(pointer, key), 'expected non-empty schema array')
      node[key].forEach((entry: Node, index: number) => audit(entry, child(child(pointer, key), String(index))))
    }
  }

  function literal(value: any): string {
    if (Array.isArray(value)) return '[' + value.map(literal).join(', ') + ']'
    if (value && typeof value === 'object') return '{ ' + members(value).map(([key, entry]) =>
      quote(key) + ': ' + literal(entry)).join('; ') + ' }'
    return quote(value)
  }

  function shape(schema: Node | boolean, pointer: string, inherited?: Node, assertion = false): string {
    audit(schema, pointer)
    if (rules.get(pointer) === true) return 'JsonValue'
    if (schema === false) return 'never'
    const node = schema as Node
    const parts: string[] = []
    const pick = (key: string, value: Node | boolean) => shape(value, child(pointer, key))
    if (node.$ref) {
      const target = reference(node.$ref, child(pointer, '$ref'))
      const name = aliases.get(target)
      parts.push(name ?? shape(lookup(target), target))
    }
    if (Object.hasOwn(node, 'const')) parts.push(literal(node.const))
    if (node.enum) parts.push('(' + node.enum.map(literal).join(' | ') + ')')
    for (const key of ['anyOf', 'oneOf', 'allOf']) {
      if (node[key]) {
        const alternatives = node[key].flatMap((entry: Node, index: number) => {
          if (entry.if !== undefined) return []
          return [shape(entry, child(child(pointer, key), String(index)), node, key === 'allOf' || assertion)]
        })
        if (alternatives.length) parts.push('(' + alternatives.join(key === 'allOf' ? ' & ' : ' | ') + ')')
      }
    }
    const oneType = (type: string): string => {
      if (type === 'array') {
        if (node.items === undefined) return fail(child(pointer, 'items'), 'untyped array')
        return 'Array<' + pick('items', node.items) + '>'
      }
      if (type !== 'object') return type === 'integer' ? 'number' : type
      const body = members(node.properties).map(([key, val]) => {
        const memberPointer = child(child(pointer, 'properties'), key)
        let rendered = shape(val, memberPointer, inherited?.properties?.[key], assertion)
        if (val.not?.const !== undefined) {
          const base = inherited?.properties?.[key]
          if (base) rendered = 'Exclude<' + rendered + ', ' + literal(val.not.const) + '>'
        }
        return quote(key) + (node.required?.includes(key) ? '' : '?') + ': ' + rendered
      })
      for (const key of node.required ?? []) {
        if (Object.hasOwn(node.properties ?? {}, key)) continue
        // A partial schema can require a member declared by its enclosing intersection.
        body.push(quote(key) + ': {} | null')
      }
      if (!body.length) {
        if (node.patternProperties) {
          const [pattern, rule] = members(node.patternProperties)[0]!
          return 'Record<string, ' + shape(rule, child(child(pointer, 'patternProperties'), pattern)) + '>'
        }
        if (node.additionalProperties && typeof node.additionalProperties === 'object') {
          return 'Record<string, ' + pick('additionalProperties', node.additionalProperties) + '>'
        }
        if (node.additionalProperties === false) return 'Record<string, never>'
        return 'Record<string, JsonValue>'
      }
      return '{ ' + body.join('; ') + ' }'
    }
    const declared = node.type ?? (node.properties || node.required || node.additionalProperties !== undefined ? 'object' : undefined)
    if (declared) {
      const variants = [declared].flat().map(oneType)
      if (node.nullable === true) variants.push('null')
      parts.push('(' + variants.join(' | ') + ')')
    }
    // A finite discriminator permits precise, correlated branches. Other assertions
    // remain in the emitted validator alongside the structural type.
    const selectors = (node.allOf ?? []).filter((entry: Node) => entry.if?.properties)
    for (const [key, property] of members(node.properties)) {
      if (!node.required?.includes(key) || !Array.isArray(property.enum)) continue
      const branches = selectors.filter((entry: Node) => Object.keys(entry.if.properties).length === 1
        && Object.hasOwn(entry.if.properties, key))
      if (!branches.length) continue
      const cases = property.enum.map((value: any) => {
        const constraints = ['{ ' + quote(key) + ': ' + literal(value) + ' }']
        for (const entry of branches) {
          const predicate = entry.if.properties[key]
          const matches = (test: Node): boolean => Object.hasOwn(test, 'const') ? test.const === value
            : test.enum ? test.enum.includes(value) : test.not ? !matches(test.not) : false
          const branch = matches(predicate) ? entry.then : entry.else
          if (!branch) continue
          const index = node.allOf.indexOf(entry)
          const branchPath = child(child(child(pointer, 'allOf'), String(index)), branch === entry.then ? 'then' : 'else')
          if (branch.not?.required && !branch.properties && !branch.required) {
            constraints.push('{ ' + branch.not.required.map((name: string) => quote(name) + '?: never').join('; ') + ' }')
          } else {
            constraints.push(shape(branch, branchPath, node, true))
          }
        }
        return '(' + constraints.join(' & ') + ')'
      })
      parts.push('(' + cases.join(' | ') + ')')
    }
    if (parts.length) return parts.join(' & ')
    if (inherited && (inherited.type || inherited.$ref)) return shape(inherited, pointer + '/@inherited')
    // Assertion-only fragments narrow their enclosing type at runtime.
    if (assertion) return '{} | null'
    return fail(pointer, 'untyped schema')
  }
  for (const [pointer, name] of aliases) types.set(name, shape(lookup(pointer), pointer))
  if (title === 'Registry Casework API') {
    const pointer = '/components/schemas/TaskTemplate'
    const template = lookup(pointer)
    const deferred = template.allOf?.find((branch: Node) =>
      branch.if?.properties?.authorizationMode?.const === 'deferred'
        && branch.then?.properties?.bounds?.properties?.type?.not?.const === 'evidence')
    if (!deferred) fail(pointer, 'expected declared deferred authorization bound')
    const type = types.get('Schema_TaskTemplate')
    types.set('Schema_TaskTemplate', '(' + type + ') & (' +
      '{ authorizationMode: "deferred"; bounds: Exclude<Schema_TaskGrantBounds, { type: "evidence" }> } | ' +
      '{ authorizationMode?: "immediate" })')
  }

  const opTypes: string[] = []
  const conditionalAnswers: string[] = []
  const definitions: Node = Object.create(null)
  const pageMethods: string[] = []
  const pageNames = new Set<string>()
  const listTypes: string[] = []
  const listRowTypes: string[] = []
  const listRules: Node = {}
  const invoke: { id: string; operation: string; body: string; keys: string[]; profile: string; profileRequired: boolean; attachments: boolean }[] = []
  const actionInputs: Record<string, Node> = {}
  const conditions: { id: string; operation: string; body: string; profile: string; result: string; profileRequired: boolean }[] = []
  const seen = new Set<string>()
  function deref(value: Node, pointer: string): Node {
    if (!value.$ref) return value
    return lookup(reference(value.$ref, child(pointer, '$ref')))
  }
  function describe(value: Node | boolean, pointer: string): string {
    return shape(value, pointer)
  }

  function assertRequestSchema(schema: Node | boolean, pointer: string, seen = new Set<string>()): void {
    if (typeof schema === 'boolean' || seen.has(pointer)) return
    seen.add(pointer)
    if (schema.$ref) {
      const target = reference(schema.$ref, child(pointer, '$ref'))
      assertRequestSchema(lookup(target), target, seen)
    }
    for (const [key, property] of members(schema.properties)) {
      const at = child(child(pointer, 'properties'), key)
      if (schema.required?.includes(key) && deref(property, at).readOnly === true) {
        fail(at, 'required readOnly property on a request')
      }
      assertRequestSchema(property, at, seen)
    }
    for (const key of ['items', 'additionalProperties', 'if', 'then', 'else', 'not']) {
      if (schema[key] !== undefined) assertRequestSchema(schema[key], child(pointer, key), seen)
    }
    for (const [key, nested] of members(schema.patternProperties)) {
      assertRequestSchema(nested, child(child(pointer, 'patternProperties'), key), seen)
    }
    for (const key of ['allOf', 'anyOf', 'oneOf']) {
      schema[key]?.forEach((entry: Node, index: number) =>
        assertRequestSchema(entry, child(child(pointer, key), String(index)), seen))
    }
  }
  function objectQuery(schema: Node | boolean, pointer: string, seen = new Set<string>()): boolean {
    if (typeof schema === 'boolean' || seen.has(pointer)) return false
    seen.add(pointer)
    if (schema.$ref) {
      const target = reference(schema.$ref, child(pointer, '$ref'))
      if (objectQuery(lookup(target), target, seen)) return true
    }
    if ([schema.type].flat().includes('object') || schema.properties || schema.additionalProperties !== undefined
        || schema.const && typeof schema.const === 'object' && !Array.isArray(schema.const)
        || schema.enum?.some((entry: unknown) => entry && typeof entry === 'object' && !Array.isArray(entry))) return true
    if (schema.items && objectQuery(schema.items, child(pointer, 'items'), seen)) return true
    return ['allOf', 'oneOf', 'anyOf'].some(key => schema[key]?.some((entry: Node, index: number) =>
      objectQuery(entry, child(child(pointer, key), String(index)), seen)))
  }

  const securitySchemes: Node = doc.components?.securitySchemes ?? {}
  // An operation every one of whose security alternatives is a Standard Webhooks signature.
  function signatureOnly(operation: Node): boolean {
    const requirements = operation.security ?? doc.security
    return Array.isArray(requirements) && requirements.length > 0 && requirements.every((requirement: Node) => {
      const names = Object.keys(requirement ?? {})
      return names.length > 0 && names.every(name => {
        const scheme = Object.hasOwn(securitySchemes, name) ? securitySchemes[name] : undefined
        return scheme?.type === 'apiKey' && scheme.in === 'header' && String(scheme.name).toLowerCase() === 'webhook-signature'
      })
    })
  }
  const listedReceipts = new Set(Object.hasOwn(receiptLookups, title) ? receiptLookups[title] : [])
  const seenReceipts = new Set<string>()

  for (const [path, item] of members(doc.paths)) {
    const pathPointer = child('/paths', path)
    if (breg && !bregRoute.test(path)) fail(pathPointer, 'outside BReg route scheme')
    if (!/^\/(?!\/)[a-zA-Z0-9_./{}:-]+$/u.test(path)) fail(pathPointer, 'unsupported path template')
    for (const [method, operation] of members(item)) {
      if (!methods.has(method)) continue
      const pointer = child(pathPointer, method)
      const id = operation.operationId
      if (typeof id !== 'string' || seen.has(id)) fail(child(pointer, 'operationId'), 'expected unique operation id')
      seen.add(id)
      const inputs: string[] = ['CallOptions']
      const profiles = operation['x-registry-accessProfiles'] as string[] | undefined
        ?? (typeof operation['x-registry-accessProfile'] === 'string' ? [operation['x-registry-accessProfile']] : undefined)
      const profile = profiles?.length ? profiles.map(value => quote(value)).join(' | ') : 'never'
      const parameterMap = new Map<string, { value: Node; pointer: string }>()
      for (const [base, list] of [[pathPointer, item.parameters ?? []], [pointer, operation.parameters ?? []]] as const) {
        list.forEach((entry: Node, index: number) => {
          const at = child(child(base, 'parameters'), String(index))
          const value = deref(entry, at)
          const name = String(value.name).toLowerCase()
          if (value.in === 'cookie') fail(at, 'cookie parameters are unsupported')
          if (value.in === 'header' && ['authorization', 'cookie'].includes(name)) fail(at, 'transport owns this header')
          if (value.in === 'header' && name === 'idempotency-key' &&
              (!['post', 'put', 'patch', 'delete'].includes(method) || value.required !== true ||
                value.schema?.type !== 'string' || value.schema.const !== undefined || value.schema.enum !== undefined)) {
            fail(at, 'unsupported Idempotency-Key declaration')
          }
          if (value.in === 'query' && value.schema && objectQuery(value.schema, child(at, 'schema'))) {
            fail(at, 'object query parameters are unsupported')
          }
          parameterMap.set(value.in + ':' + value.name, { value, pointer: at })
        })
      }
      const args: Node = {}
      let requiredOptions = false
      for (const [location, group] of [['path', 'path'], ['query', 'query'], ['header', 'headers']] as const) {
        const fields: string[] = []
        let required = false
        for (const { value, pointer: at } of parameterMap.values()) {
          if (value.in !== location) continue
          if (location === 'header' && value.name.toLowerCase() === 'idempotency-key') {
            audit(value.schema, child(at, 'schema'))
            continue
          }
          if (value.style && value.style !== (location === 'query' ? 'form' : 'simple')) {
            fail(at, 'unsupported parameter serialization')
          }
          const declaredType = describe(value.schema, child(at, 'schema'))
          const profileType = breg && value.name === 'accessProfile' && profiles?.length ? profile : undefined
          fields.push(quote(value.name) + (value.required ? '' : '?') + ': ' + (profileType ?? declaredType))
          required ||= value.required === true
        }
        if (fields.length) {
          args[group] = '{ ' + fields.join('; ') + ' }'
          inputs.push('{ ' + group + (required ? '' : '?') + ': ' + args[group] + ' }')
          requiredOptions ||= required
        }
      }
      const definition: Node = { method: method.toUpperCase(), path, responses: {} }
      const commaQuery = [...parameterMap.values()].filter(({ value }) =>
        value.in === 'query' && value.explode === false && value.schema?.type === 'array').map(({ value }) => value.name)
      if (commaQuery.length) definition.commaQuery = commaQuery
      const headerKey = [...parameterMap.values()].find(({ value }) =>
        value.in === 'header' && value.name.toLowerCase() === 'idempotency-key')
      const receiptLookup = listedReceipts.has(method + ' ' + path)
      if (receiptLookup) {
        if (!headerKey) fail(pointer, 'listed receipt lookup does not declare Idempotency-Key')
        seenReceipts.add(method + ' ' + path)
      } else if (headerKey && looksLikeRead(id, path, operation)) {
        fail(pointer, 'keyed read is not a listed receipt lookup')
      }
      definition.keyed = Boolean(headerKey)
      if (signatureOnly(operation)) definition.signed = true
      if (headerKey && receiptLookup) {
        inputs.push('{ idempotencyKey: string }')
        requiredOptions = true
        definition.requiresExistingKey = true
      }
      const safePost = /^(target-conditions|availability)$/u.test(operation['x-registry-routeKind'] ?? '')
        || breg && operation['x-registry-operation'] === 'lookup'
        || /^(checkDocument|createEvidence|createEvidenceRequestBatch|getTaskAssertion|preview\w+)$/u.test(id)
        || receiptLookup
      definition.mutating = method !== 'get' && !(method === 'post' && safePost)
      if (title === 'Registry Messaging API') definition.messaging = true
      let requestType = ''
      let hasAttachments = false
      if (operation.requestBody) {
        const bodyPointer = child(pointer, 'requestBody')
        const request = deref(operation.requestBody, bodyPointer)
        const variants: string[] = []
        definition.requestMediaTypes = Object.keys(request.content)
        for (const [media, spec] of members(request.content)) {
          const at = child(child(child(bodyPointer, 'content'), media), 'schema')
          requestType = describe(spec.schema, at)
          assertRequestSchema(spec.schema, at)
          hasAttachments ||= Boolean(deref(spec.schema, at).properties?.attachments)
          if (!isJson(media)) requestType = media === 'application/x-www-form-urlencoded' ? 'string' : 'Uint8Array | Blob | string'
          if (definition.signed) requestType = 'Uint8Array'
          if (media === '*/*') {
            variants.push('{ body: ' + requestType + '; contentType: string }')
            definition.requestMediaType = media
          } else if (Object.keys(request.content).length > 1) {
            variants.push('{ body: ' + requestType + '; contentType: ' + quote(media) + ' }')
            definition.requestMediaType ??= media
          } else {
            definition.requestMediaType = media
            variants.push('{ body' + (request.required ? '' : '?') + ': ' + requestType + ' }')
          }
        }
        if (!variants.length) fail(bodyPointer, 'request requires declared media')
        inputs.push('(' + variants.join(' | ') + ')')
        requiredOptions ||= request.required === true
      }
      const resultTypes = new Set<string>()
      const responseMedia = new Set<string>()
      const answerTypes = new Map<string, Set<string>>()
      let page: { items: string; cursor: string; itemType: string } | undefined
      for (const [status, rawResponse] of members(operation.responses)) {
        const at = child(child(pointer, 'responses'), status)
        const response = deref(rawResponse, at)
        const success = /^2[0-9]{2}$/u.test(status) || status === '304'
        const variants: Node[] = []
        const statusTypes = new Set<string>()
        const content = status === '304' ? [] : members(response.content)
        if (success && !content.length) {
          variants.push({ mode: 'empty' })
          statusTypes.add('undefined')
        }
        for (const [media, spec] of content) {
          const schemaAt = child(child(child(at, 'content'), media), 'schema')
          if (!success) {
            if (spec.schema !== undefined) {
              audit(spec.schema, schemaAt)
              if (media === 'application/problem+json') validationRoots.add(schemaAt)
            }
            continue
          }
          const type = describe(spec.schema, schemaAt)
          let mode: string
          if (isJson(media)) {
            mode = 'json'
            validationRoots.add(schemaAt)
          }
          else if (media === 'application/dc+sd-jwt' || media.endsWith('+jwt')) mode = 'text'
          else if (media === '*/*' || media === 'application/octet-stream' || media === 'application/pdf') mode = 'binary'
          else mode = fail(schemaAt, 'unsupported success media')
          responseMedia.add(media)
          variants.push({ mediaType: media, mode, rule: mode === 'json' ? schemaAt : undefined })
          statusTypes.add(mode === 'json' ? type : (mode === 'binary' ? 'WireBytes' : 'WireText') +
            (media === '*/*' ? '' : '<' + quote(media) + '>'))
          if (media !== 'application/json' || status !== '200') continue
          const schema = deref(spec.schema, schemaAt)
          const props = schema.properties ?? {}
          const items = props.items ? 'items' : props.runs ? 'runs' : undefined
          const cursor = props.pageInfo?.properties?.nextCursor ? 'pageInfo.nextCursor' : props.nextCursor ? 'nextCursor' : undefined
          if (items && cursor && props[items].items) {
            const root = spec.schema.$ref ? spec.schema.$ref.slice(1) : schemaAt
            page = { items, cursor, itemType: describe(props[items].items, child(child(child(root, 'properties'), items), 'items')) }
          }
        }
        if (success) {
          definition.responses[status] = variants
          answerTypes.set(status, statusTypes)
          for (const type of statusTypes) resultTypes.add(type)
        }
        if ((Number(status) >= 400 || status === 'default') && content.some(([media, spec]) => media === 'application/problem+json' && spec.schema !== undefined)) {
          definition.problems ??= {}
          definition.problems[status] = child(child(child(at, 'content'), 'application/problem+json'), 'schema')
        }
      }
      if (answerTypes.has('304')) {
        const union = [...answerTypes].map(([status, types]) =>
          '(Answer<' + [...types].join(' | ') + '> & { status: ' + status + ' })')
        conditionalAnswers.push('  ' + quote(id) + ': ' + union.join(' | '))
      }
      if (!resultTypes.size) fail(child(pointer, 'responses'), 'missing success response')
      if (responseMedia.size) inputs.push('{ accept?: ' + [...new Set([...responseMedia, '*/*'])].map(value => quote(value)).join(' | ') + ' }')
      definitions[id] = definition
      const result = [...resultTypes].join(' | ')
      opTypes.push('  ' + quote(id) + ': { input: ' + inputs.join(' & ') + '; required: ' +
        String(requiredOptions) + '; output: ' + result + ' }')
      const cursorName = parameterMap.has('query:$skiptoken') ? '$skiptoken' : parameterMap.has('query:cursor') ? 'cursor' : undefined
      if (page && cursorName && !definition.mutating) {
        const name = identifier(id) + 'Page'
        if (pageNames.has(name)) fail(child(pointer, 'operationId'), 'colliding page method')
        pageNames.add(name)
        const rest = requiredOptions ? 'options: Operations[' + quote(id) + ']["input"], cursor?: string'
          : 'options: Operations[' + quote(id) + ']["input"] = {}, cursor?: string'
        // A BReg cursor carries the query, so a continuation sends only the access profile,
        // where the route takes one, and the cursor.
        const query = cursorName !== '$skiptoken' ? '{ ...options.query, cursor }'
          : parameterMap.has('query:accessProfile') ? '{ accessProfile: options.query?.accessProfile, "$skiptoken": cursor }'
            : '{ "$skiptoken": cursor }'
        pageMethods.push('  async ' + name + '(' + rest + '): Promise<Page<' + page.itemType + '>> {\n' +
          '    const { data } = await this.call(' + quote(id) + ', { ...options, query: cursor === undefined ? options.query : ' + query + ' })\n' +
          '    return { items: data.' + page.items + ', nextCursor: data.' + page.cursor + ' ?? null }\n  }')
      }
      const listProfiles = breg && operation['x-registry-operation'] === 'list'
        && (operation['x-registry-queryKind'] ?? 'list') === 'list' ? queryProfiles(operation, pointer) : undefined
      if (listProfiles) {
        const listShape = page && page.items === 'items' && page.cursor === 'pageInfo.nextCursor'
          && cursorName === '$skiptoken' && !definition.mutating
          ? page : fail(pointer, 'query profiles on an operation without a BReg list page')
        const profileParameter = parameterMap.get('query:accessProfile')?.value
        if (!profileParameter && listProfiles.length > 1) fail(pointer, 'several query profiles need an accessProfile parameter')
        const profileRequired = listProfiles.length > 1 || profileParameter?.required === true
        const row = 'ListRows[' + quote(id) + ']'
        const value = (property: string) => 'FieldValue<' + row + ', ' + quote(property) + '>'
        const alternatives = listProfiles.map(entry => {
          const filters = entry.filterable.map(filter => quote(filter.property) + '?: Filter<' + value(filter.property) + ', ' +
            filter.operators.map(operator => quote(operator)).join(' | ') + '>')
          const optional = filters.length ? '{ ' + filters.join('; ') + ' }' : 'never'
          const where = entry.requiredFilters
            ? 'where: (' + entry.requiredFilters.map(alternative => '{ ' + alternative.map(property =>
              quote(property) + ': ' + value(property)).join('; ') + ' }').join(' | ') + ') & ' + optional
            : 'where?: ' + optional
          const order = entry.sortable.flatMap(sort => sort.directions.map(direction =>
            quote(direction === 'asc' ? sort.property : sort.property + ' desc')))
          const fields = [
            profileParameter ? 'accessProfile' + (profileRequired ? '' : '?') + ': ' + quote(entry.profile) : 'accessProfile?: never',
            where,
            'orderBy?: ' + (order.length ? order.join(' | ') : 'never'),
            'select?: ' + (entry.selectable.length ? 'ReadonlyArray<' + entry.selectable.map(name => quote(name)).join(' | ') + '>' : 'never'),
            'count?: ' + (entry.allowCount ? 'boolean' : 'never'),
            'top?: number',
          ]
          return '(CallOptions & { ' + fields.join('; ') + ' })'
        })
        listTypes.push('  ' + quote(id) + ': ' + alternatives.join(' | '))
        listRowTypes.push('  ' + quote(id) + ': ' + listShape.itemType)
        listRules[id] = {
          accessProfileParameter: Boolean(profileParameter),
          profiles: Object.fromEntries(listProfiles.map(entry => [entry.profile, {
            maximumPageSize: entry.maximumPageSize, allowCount: entry.allowCount, selectable: entry.selectable,
            filterable: Object.fromEntries(entry.filterable.map(filter => [filter.property, filter.operators])),
            sortable: Object.fromEntries(entry.sortable.map(sort => [sort.property, sort.directions])),
            ...(entry.requiredFilters ? { requiredFilters: entry.requiredFilters } : {}),
          }])),
        }
      }
      const action = operation['x-registry-action']
      const routeKind = operation['x-registry-routeKind']
      if (breg && action && typeof action === 'object') {
        if (typeof action.id === 'string' && Array.isArray(action.inputs)) {
          actionInputs[action.id] = { display: action.display, inputMode: action.inputMode, inputs: action.inputs }
        }
        const profileRequired = parameterMap.get('query:accessProfile')?.value.required === true
        if (routeKind === 'invoke') {
          invoke.push({ id: action.id, operation: id, body: requestType, keys: action.requiredConditionKeys, profile, profileRequired, attachments: hasAttachments })
        }
        if (routeKind === 'target-conditions') {
          conditions.push({ id: action.id, operation: id, body: requestType, profile, result, profileRequired })
        }
      }
    }
  }
  for (const route of listedReceipts) {
    if (!seenReceipts.has(route)) fail('/paths', 'listed receipt lookup ' + route + ' is missing')
  }
  const actionMethods: string[] = []
  if (breg) {
    for (const action of invoke) {
      const body = '(' + action.body + ')'
      const fields = ['accessProfile' + (action.profileRequired ? '' : '?') + ': ' + action.profile,
        action.keys?.length ? 'preconditions: NonNullable<' + body + '["preconditions"]>' : 'preconditions?: never']
      if (action.attachments) fields.push('attachments: ' + body + '["attachments"]')
      const options = ['CallOptions', '{ ' + fields.join('; ') + ' }']
      const required = Boolean(action.keys?.length || action.profileRequired || action.attachments)
      actionMethods.push('  invoke(action: ' + quote(action.id) + ', input: ' + body + '["input"], options' +
        (required ? '' : '?') + ': ' + options.join(' & ') + '): Promise<Answer<Operations[' + quote(action.operation) + ']["output"]>>')
    }
    if (invoke.length) {
      actionMethods.push('  async invoke(action: string, input: object, options: CallOptions & { accessProfile?: string; preconditions?: object; attachments?: object } = {}): Promise<Answer<unknown>> {\n' +
        '    switch (action) {\n' + invoke.map(action => '      case ' + quote(action.id) + ': return this.#call(' + quote(action.operation) +
          ', { ...options, query: { accessProfile: options.accessProfile }, body: { input, preconditions: options.preconditions, attachments: options.attachments } })').join('\n') +
        '\n      default: throw new TypeError("Unknown Action")\n    }\n  }')
    }
    for (const action of conditions) {
      actionMethods.push('  targetConditions(action: ' + quote(action.id) + ', input: (' + action.body + ')["input"], options' +
        (action.profileRequired ? '' : '?') + ': CallOptions & { accessProfile' + (action.profileRequired ? '' : '?') + ': ' + action.profile + ' }): Promise<(' + action.result + ')["preconditions"]>')
    }
    if (conditions.length) {
      actionMethods.push('  async targetConditions(action: string, input: object, options: CallOptions & { accessProfile?: string } = {}): Promise<unknown> {\n' +
        '    switch (action) {\n' + conditions.map(action => '      case ' + quote(action.id) +
          ': return (await this.#call<' + action.result + '>(' + quote(action.operation) +
          ', { ...options, query: { accessProfile: options.accessProfile }, body: { input } })).data.preconditions').join('\n') +
        '\n      default: throw new TypeError("Unknown Action")\n    }\n  }')
    }
  }
  function compileRule(pointer: string): Node | boolean {
    const rule = rules.get(pointer)
    if (rule === undefined) return fail(pointer, 'missing audited rule')
    if (typeof rule === 'boolean') return rule
    const compiled = { ...rule }
    for (const key of ['properties', 'patternProperties']) {
      if (rule[key]) compiled[key] = Object.fromEntries(members(rule[key]).map(([name]) =>
        [key === 'patternProperties' ? unicodePattern(name, child(child(pointer, key), name)) : name,
          compileRule(child(child(pointer, key), name))]))
    }
    for (const key of ['items', 'propertyNames', 'not', 'if', 'then', 'else', 'additionalProperties']) {
      const next = child(pointer, key)
      if (rules.has(next)) compiled[key] = compileRule(next)
    }
    for (const key of ['allOf', 'oneOf', 'anyOf']) {
      if (rule[key]) compiled[key] = rule[key].map((_: unknown, index: number) =>
        compileRule(child(child(pointer, key), String(index))))
    }
    return compiled
  }
  const compiledRules = [...validationRoots].sort().map(pointer => [pointer, compileRule(pointer)] as const)
  const sourceHash = createHash('sha256').update(source).digest('hex')
  return [
    '// Source SHA-256 ' + sourceHash,
    ...[...used].sort().map(pointer => '// Unconstrained JSON ' + pointer),
    'import { Transport, type Answer, type CallOptions, type ClientOptions, type JsonValue, type Operation, type Page, type RequestValues, type ResponseVariant, type WireBytes, type WireText } from ' + quote(settings.coreImport ?? '../core.ts'),
    'import { validator } from ' + quote(settings.schemaImport ?? '../schema.ts'),
    ...(listTypes.length ? [
      'import { listPage, listQuery, type FieldValue, type Filter, type ListPage, type ListRequest, type ListRules } from ' +
        quote(settings.coreImport ?? '../core.ts'),
    ] : []),
    '',
    ...[...types].map(([name, type]) => 'export type ' + name + ' = ' + type),
    '',
    'export interface Operations {', ...opTypes, '}',
    ...(listTypes.length ? [
      '',
      '// The row each list returns, and the list options its query profiles allow.',
      'export interface ListRows {', ...listRowTypes, '}',
      'export interface ListOptions {', ...listTypes, '}',
      'const listRules: Record<string, ListRules> = JSON.parse(' + quote(quote(listRules)) + ')',
    ] : []),
    ...(conditionalAnswers.length ? [
      'interface ConditionalAnswers {', ...conditionalAnswers, '}',
      'type OperationAnswer<K extends keyof Operations> = K extends keyof ConditionalAnswers ? ConditionalAnswers[K] : Answer<Operations[K]["output"]>',
    ] : []),
    '',
    'const rules: Record<string, unknown> = Object.fromEntries([',
    ...compiledRules.map(([pointer, rule]) => '  [' + quote(pointer) + ', JSON.parse(' + quote(quote(rule)) + ')],'),
    '])',
    'const routes: Record<string, Operation> = Object.create(null)',
    'type Definition = Omit<Operation, "responses"> & { problems?: Record<string, string>; responses: Record<number, Array<ResponseVariant & { rule?: string }>> }',
    'const definitions: Record<string, Definition> = Object.fromEntries([',
    ...members(definitions).map(([id, definition]) => '  [' + quote(id) + ', JSON.parse(' + quote(quote(definition)) + ')],'),
    '])',
    'for (const [id, definition] of Object.entries(definitions)) {',
    '  const responses: Operation["responses"] = {}',
    '  for (const [status, variants] of Object.entries(definition.responses)) {',
    '    responses[Number(status)] = variants.map(variant => ({ ...variant, validate: variant.rule === undefined ? undefined : validator(rules, rules[variant.rule]) }))',
    '  }',
    '  routes[id] = { ...definition, responses, problemValidators: Object.fromEntries(Object.entries(definition.problems ?? {}).map(([status, rule]) => [status, validator(rules, rules[rule])])) }',
    '}',
    '',
    'export class Client {',
    '  readonly #transport: Transport',
    '  constructor(options: ClientOptions) { this.#transport = new Transport(options) }',
    '  async call<K extends keyof Operations>(operation: K, ...args: Operations[K]["required"] extends true ? [Operations[K]["input"]] : [Operations[K]["input"]?]): Promise<' +
      (conditionalAnswers.length ? 'OperationAnswer<K>' : 'Answer<Operations[K]["output"]>') + '> {',
    '    return this.#call(operation, args[0])' + (conditionalAnswers.length ? ' as Promise<OperationAnswer<K>>' : ''),
    '  }',
    '  #call<T>(operation: string, options: RequestValues = {}): Promise<Answer<T>> {',
    '    const route = routes[operation]',
    '    if (!route) throw new TypeError("Unknown operation")',
    '    return this.#transport.call(route, options)',
    '  }',
    ...pageMethods,
    ...(listTypes.length ? [
      '  list<K extends keyof ListOptions>(operation: K, ...args: {} extends ListOptions[K] ? [options?: ListOptions[K], cursor?: string] : [options: ListOptions[K], cursor?: string]): Promise<ListPage<ListRows[K]>>',
      '  async list(operation: string, options: ListRequest = {}, cursor?: string): Promise<ListPage<unknown>> {',
      '    const rules = Object.hasOwn(listRules, operation) ? listRules[operation] : undefined',
      '    if (!rules) throw new TypeError("Unknown list operation")',
      '    const query = listQuery(rules, options, cursor)',
      '    const { accessProfile, where, orderBy, select, count, top, ...call } = options',
      '    const { data } = await this.#call<{ items: unknown[]; pageInfo: { nextCursor?: string | null }; count?: number }>(operation, { ...call, query })',
      '    return listPage(data)',
      '  }',
    ] : []),
    ...actionMethods, '}',
    '',
    '// Every generated module exports this one factory name. The client it returns is typed to this',
    '// registry\'s operations.',
    'export function createRegistryClient(options: ClientOptions): Client {',
    '  return new Client(options)',
    '}',
    '',
    ...(breg ? [
      '// Each Action\'s display text and inputs exactly as the source document declares them.',
      'export const actionInputs = ' + JSON.stringify(Object.fromEntries(Object.entries(actionInputs).sort(([a], [b]) => a < b ? -1 : 1)), null, 2) + ' as const',
      '',
    ] : []),
  ].join('\n')
}

export function checkOutput(expected: string, actual: string, path: string): void {
  if (expected !== actual) throw new Error('Generated client drift: ' + path)
}

export function generateFile(
  input: string, output: string, check: boolean, breg?: boolean, allowUnconstrained: readonly string[] = [],
): void {
  const local = (name: string) => {
    const path = relative(dirname(resolve(output)), fileURLToPath(new URL(name, import.meta.url))).split('\\').join('/')
    return path.startsWith('.') ? path : './' + path
  }
  const result = generate(readFileSync(input, 'utf8'), { breg, coreImport: local('core.ts'), schemaImport: local('schema.ts'), allowUnconstrained })
  if (check) checkOutput(result, readFileSync(output, 'utf8'), output)
  else writeFileSync(output, result)
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const flags = process.argv.slice(2)
  const files = flags.filter(arg => !arg.startsWith('--'))
  try {
    const prefix = '--allow-unconstrained='
    const allowed = flags.filter(arg => arg.startsWith(prefix)).map(arg => arg.slice(prefix.length))
    if (files.length !== 2 || flags.some(arg => arg.startsWith('--') && arg !== '--check' && arg !== '--breg' && !arg.startsWith(prefix))) {
      throw new Error('Usage: node generate.ts [--check] [--breg] [--allow-unconstrained=/pointer] source.json client.ts')
    }
    generateFile(files[0]!, files[1]!, flags.includes('--check'), flags.includes('--breg') || undefined, allowed)
  } catch (error) {
    console.error(error instanceof Error ? error.message : error)
    process.exitCode = 1
  }
}

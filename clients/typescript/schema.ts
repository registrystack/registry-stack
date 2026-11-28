type Rule = boolean | {
  $ref?: string
  type?: string | string[]
  const?: unknown
  enum?: unknown[]
  properties?: Record<string, Rule>
  additionalProperties?: Rule
  patternProperties?: Record<string, Rule>
  propertyNames?: Rule
  required?: string[]
  dependentRequired?: Record<string, string[]>
  items?: Rule
  allOf?: Rule[]
  anyOf?: Rule[]
  oneOf?: Rule[]
  not?: Rule
  if?: Rule
  then?: Rule
  else?: Rule
  minimum?: number
  maximum?: number
  minItems?: number
  maxItems?: number
  minLength?: number
  maxLength?: number
  minProperties?: number
  maxProperties?: number
  uniqueItems?: boolean
  pattern?: string
}

function same(left: unknown, right: unknown): boolean {
  if (left === right) return true
  if (!left || !right || typeof left !== 'object' || typeof right !== 'object'
      || Array.isArray(left) !== Array.isArray(right)) return false
  if (Array.isArray(left) && Array.isArray(right) && left.length !== right.length) return false
  const entries = Object.entries(left)
  const record = right as Record<string, unknown>
  return entries.length === Object.keys(right).length &&
    entries.every(([key, value]) => Object.hasOwn(record, key) && same(value, record[key]))
}

function isType(type: string, value: unknown): boolean {
  switch (type) {
    case 'null': return value === null
    case 'integer': return Number.isInteger(value)
    case 'number': return typeof value === 'number' && Number.isFinite(value)
    case 'array': return Array.isArray(value)
    case 'object': return typeof value === 'object' && value !== null && !Array.isArray(value)
    default: return typeof value === type
  }
}

function bounded(value: number, min = -Infinity, max = Infinity): boolean {
  return value >= min && value <= max
}

export function validator(schemas: unknown, schema: unknown): (value: unknown) => boolean {
  const root = schemas as Record<string, Rule>
  const compiled = new WeakMap<object, { pattern?: RegExp; properties: [RegExp, Rule][] }>()
  function patternsFor(rule: Exclude<Rule, boolean>) {
    let entry = compiled.get(rule)
    if (!entry) {
      entry = {
        pattern: rule.pattern === undefined ? undefined : new RegExp(rule.pattern, 'u'),
        properties: Object.entries(rule.patternProperties ?? {}).map(([pattern, child]) => [new RegExp(pattern, 'u'), child]),
      }
      compiled.set(rule, entry)
    }
    return entry
  }
  function valid(value: unknown, rule: Rule, depth: number): boolean {
    if (depth > 256) return false
    if (typeof rule === 'boolean') return rule
    const check = (child: Rule, member: unknown = value) => valid(member, child, depth + 1)
    if (rule.$ref && (!Object.hasOwn(root, rule.$ref) || !check(root[rule.$ref]!))) return false
    if (rule.type && ![rule.type].flat().some(type => isType(type, value))) return false
    if (Object.hasOwn(rule, 'const') && !same(value, rule.const)) return false
    if (rule.enum && !rule.enum.some(item => same(value, item))) return false
    if (rule.allOf && !rule.allOf.every(item => check(item))) return false
    if (rule.anyOf && !rule.anyOf.some(item => check(item))) return false
    if (rule.oneOf && rule.oneOf.filter(item => check(item)).length !== 1) return false
    if (rule.not !== undefined && check(rule.not)) return false
    if (rule.if !== undefined) {
      const branch = check(rule.if) ? rule.then : rule.else
      if (branch !== undefined && !check(branch)) return false
    }
    if (typeof value === 'number' && !bounded(value, rule.minimum, rule.maximum)) return false
    if (typeof value === 'string') {
      if (!bounded([...value].length, rule.minLength, rule.maxLength)) return false
      if (patternsFor(rule).pattern?.test(value) === false) return false
    }
    if (Array.isArray(value)) {
      if (!bounded(value.length, rule.minItems, rule.maxItems)) return false
      const items = rule.items
      if (items !== undefined && !value.every(item => check(items, item))) return false
      if (rule.uniqueItems && value.some((item, i) => value.slice(0, i).some(other => same(item, other)))) return false
    }
    if (isType('object', value)) {
      const record = value as Record<string, unknown>
      const keys = Object.keys(record)
      if (!bounded(keys.length, rule.minProperties, rule.maxProperties)) return false
      if (rule.required?.some(key => !Object.hasOwn(record, key))) return false
      for (const [key, required] of Object.entries(rule.dependentRequired ?? {})) {
        if (Object.hasOwn(record, key) && required.some(name => !Object.hasOwn(record, name))) return false
      }
      const patterns = patternsFor(rule).properties
      for (const key of keys) {
        if (rule.propertyNames !== undefined && !check(rule.propertyNames, key)) return false
        const property = Object.hasOwn(rule.properties ?? {}, key) ? rule.properties![key] : undefined
        const matched = patterns.filter(([pattern]) => pattern.test(key))
        if (property !== undefined && !check(property, record[key])) return false
        if (matched.some(([, child]) => !check(child, record[key]))) return false
        if (property === undefined && matched.length === 0 && typeof rule.additionalProperties === 'object'
            && !check(rule.additionalProperties, record[key])) return false
      }
    }
    return true
  }
  return value => valid(value, schema as Rule, 0)
}

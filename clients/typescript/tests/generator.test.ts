import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { generate, checkOutput } from '../generate.ts'

function document(schema: object) {
  return { openapi: '3.1.0', info: { title: 'fixture' }, components: { schemas: { Thing: schema } }, paths: {} }
}
for (const [schema, pointer] of [
  [{ type: 'object', patternProperties: { '^x': { type: 'string' } } }, 'patternProperties'],
  [{ type: 'object', properties: { value: {} } }, 'properties/value'],
  [{ type: 'object', properties: { value: { mystery: true } } }, 'properties/value/mystery'],
  [{ $ref: 'https://example.org/schema' }, '\\$ref'],
  [{ type: 'object', properties: { name: { type: 'string' } }, additionalProperties: { type: 'number' } }, 'additionalProperties'],
] as const) {
  test('refuses unsupported ' + pointer, () => {
    assert.throws(() => generate(JSON.stringify(document(schema))), new RegExp('/components/schemas/Thing/' + pointer))
  })
}
test('BReg refuses paths outside the route scheme', () => {
  const input = { ...document({ type: 'string' }), paths: { '/v1/foreign': {} } }
  assert.throws(() => generate(JSON.stringify(input), { breg: true }), /\/paths\/~1v1~1foreign/)
})
test('every generated module exports the same factory name, typed to its own client', () => {
  const factory = /^export function createRegistryClient\(options: ClientOptions\): Client \{$/mu
  for (const title of ['licence-registry', 'facility-registry']) {
    const output = generate(JSON.stringify({ ...document({ type: 'string' }), info: { title } }))
    assert.match(output, factory)
    assert.doesNotMatch(output, /export function create(?!RegistryClient\b)\w*Client\b/u)
  }
})
test('determinism and drift', () => {
  const source = JSON.stringify(document({ type: 'string' }))
  const output = generate(source)
  assert.match(output, /SHA-256 [a-f0-9]{64}/)
  assert.equal(generate(source), output)
  checkOutput(output, output, 'fixture')
  assert.throws(() => checkOutput(output, output + ' ', 'fixture'), /drift/i)
})

const success = { 200: { description: 'ok', content: { 'application/json': { schema: { type: 'string' } } } } }
function endpoint(operation: object, method = 'get') {
  return { ...document({ type: 'string' }), paths: { '/v1/example': { [method]: { operationId: 'example', responses: success, ...operation } } } }
}

for (const [name, location, schema] of [
  ['filter', 'query', { type: 'object', properties: { value: { type: 'string' } } }],
  ['session', 'cookie', { type: 'string' }],
  ['Authorization', 'header', { type: 'string' }],
  ['Cookie', 'header', { type: 'string' }],
  ['Idempotency-Key', 'header', { type: 'string' }],
] as const) {
  test('refuses unsupported parameter ' + name, () => {
    const value = endpoint({ parameters: [{ name, in: location, required: true, schema }] })
    assert.throws(() => generate(JSON.stringify(value)), /\/paths\/~1v1~1example\/get\/parameters\/0/u)
  })
}

test('refuses a required readOnly property through a request reference', () => {
  const value = endpoint({ requestBody: { required: true, content: { 'application/json': {
    schema: { $ref: '#/components/schemas/Thing' },
  } } } }, 'post')
  value.components.schemas.Thing = { type: 'object', required: ['id'], properties: { id: { type: 'string', readOnly: true } } }
  assert.throws(() => generate(JSON.stringify(value)), /\/components\/schemas\/Thing\/properties\/id/u)
})

test('refuses colliding page methods', () => {
  const page = {
    parameters: [{ name: 'cursor', in: 'query', schema: { type: 'string' } }],
    responses: { 200: { content: { 'application/json': { schema: { type: 'object', properties: {
      items: { type: 'array', items: { type: 'string' } }, nextCursor: { type: 'string' },
    } } } } } },
  }
  const value = { ...document({ type: 'string' }), paths: {
    '/v1/first': { get: { operationId: 'list-first', ...page } },
    '/v1/second': { get: { operationId: 'list_first', ...page } },
  } }
  assert.throws(() => generate(JSON.stringify(value)), /\/paths\/~1v1~1second\/get\/operationId/u)
})

function definitionsOf(output: string): Record<string, Record<string, unknown>> {
  const start = output.indexOf('const definitions')
  const block = output.slice(start, output.indexOf('\n])', start))
  return Object.fromEntries([...block.matchAll(/^ {2}\[("[^"]+"), JSON\.parse\((".*")\)\],$/gmu)]
    .map(([, id, json]) => [JSON.parse(id!), JSON.parse(JSON.parse(json!))]))
}
const keyHeader = { name: 'Idempotency-Key', in: 'header', required: true, schema: { type: 'string' } }

test('signed operations take the exact body bytes and are selected by their security scheme', () => {
  const body = { required: true, content: { 'application/json': { schema: { type: 'object' } } } }
  const empty = { 204: { description: 'done' } }
  const value = { ...document({ type: 'string' }),
    components: { schemas: { Thing: { type: 'string' } }, securitySchemes: {
      bearer: { type: 'http', scheme: 'bearer' },
      signature: { type: 'apiKey', in: 'header', name: 'webhook-signature' },
      other: { type: 'apiKey', in: 'header', name: 'x-api-key' },
    } },
    paths: {
      '/v1/events': { post: { operationId: 'receive', security: [{ signature: [] }], requestBody: body, responses: empty } },
      '/v1/either': { post: { operationId: 'either', security: [{ signature: [] }, { bearer: [] }], requestBody: body, responses: empty } },
      '/v1/key': { post: { operationId: 'keyed', security: [{ other: [] }], requestBody: body, responses: empty } },
      '/v1/plain': { post: { operationId: 'plain', requestBody: body, responses: empty } },
    } }
  const output = generate(JSON.stringify(value))
  const definitions = definitionsOf(output)
  assert.equal(definitions.receive!.signed, true)
  for (const id of ['either', 'keyed', 'plain']) assert.equal(definitions[id]!.signed, undefined, id)
  assert.match(output, /"receive": \{ input: CallOptions & \(\{ body: Uint8Array \}\)/u)
  assert.match(output, /"plain": \{ input: CallOptions & \(\{ body: \(Record<string, JsonValue>\) \}\)/u)
})

test('a receipt lookup keeps its classification when its operation is renamed', () => {
  const receipt = { parameters: [keyHeader], requestBody: { required: true, content: { 'application/json': { schema: { type: 'object' } } } },
    responses: { 200: { content: { 'application/json': { schema: { type: 'object' } } } } } }
  const messaging = (paths: object) => ({ ...document({ type: 'string' }), info: { title: 'Registry Messaging API' }, paths })
  const renamed = definitionsOf(generate(JSON.stringify(messaging({
    '/v1/messages/receipt': { post: { ...receipt, operationId: 'fetchOriginalAcceptance' } },
    '/v1/messages': { post: { ...receipt, operationId: 'submitMessage' } },
  }))))
  assert.deepEqual([renamed.fetchOriginalAcceptance!.requiresExistingKey, renamed.fetchOriginalAcceptance!.mutating], [true, false])
  assert.deepEqual([renamed.submitMessage!.requiresExistingKey, renamed.submitMessage!.mutating], [undefined, true])
  // The same operation spelling in another contract is not a receipt lookup there, and a keyed
  // read that is not listed stops the generator.
  assert.throws(() => generate(JSON.stringify({ ...document({ type: 'string' }), paths: {
    '/v1/messages/receipt': { post: { ...receipt, operationId: 'readMessageReceipt' } },
  } })), /\/paths\/~1v1~1messages~1receipt\/post: keyed read is not a listed receipt lookup/u)
  assert.throws(() => generate(JSON.stringify({ ...document({ type: 'string' }), paths: {
    '/v1/holds/lookup': { post: { ...receipt, operationId: 'readHoldReceipt' } },
  } })), /\/paths\/~1v1~1holds~1lookup\/post: keyed read is not a listed receipt lookup/u)
  assert.throws(() => generate(JSON.stringify(messaging({
    '/v1/messages': { post: { ...receipt, operationId: 'submitMessage' } },
  }))), /listed receipt lookup post \/v1\/messages\/receipt is missing/u)
})

test('the committed clients require an original key for exactly the two receipt lookups', () => {
  const found: string[] = []
  for (const name of ['breg-facility', 'breg-minimal', 'casework', 'coordinator', 'documents', 'evidence', 'messaging', 'scheduling']) {
    const output = readFileSync(new URL('../generated/' + name + '.ts', import.meta.url), 'utf8')
    for (const [id, definition] of Object.entries(definitionsOf(output))) {
      if (definition.requiresExistingKey) found.push(name + ':' + id)
    }
  }
  assert.deepEqual(found.sort(), ['messaging:readMessageReceipt', 'scheduling:readAppointmentReceipt'])
})

test('page helpers are generated only for read operations', () => {
  const page = {
    parameters: [{ name: 'cursor', in: 'query', schema: { type: 'string' } }],
    responses: { 200: { content: { 'application/json': { schema: { type: 'object', properties: {
      items: { type: 'array', items: { type: 'string' } }, nextCursor: { type: 'string' },
    } } } } } },
  }
  const output = generate(JSON.stringify({ ...document({ type: 'string' }), paths: {
    '/v1/things': { get: { operationId: 'listThings', ...page }, post: { operationId: 'sweepThings', ...page } },
  } }))
  assert.match(output, /async listThingsPage\(/u)
  assert.doesNotMatch(output, /sweepThingsPage/u)
})

test('a BReg module always exports actionInputs, and generated comments hold no semicolon', () => {
  const output = generate(JSON.stringify(document({ type: 'string' })), { breg: true })
  assert.match(output, /^export const actionInputs = \{\} as const$/mu)
  for (const line of output.split('\n').filter(entry => entry.startsWith('//'))) assert.doesNotMatch(line, /;/u)
})

test('rejects patterns invalid under Unicode mode at the pattern pointer', () => {
  assert.throws(() => generate(JSON.stringify(document({ type: 'string', pattern: '\\q' }))),
    /\/components\/schemas\/Thing\/pattern/u)
})

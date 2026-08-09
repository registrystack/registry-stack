import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import {
  CONTRACTS,
  CONTRACT_STATUSES,
  FORMAT_VERSION,
  buildEvidenceConfiguration,
  collectFields,
  generateEvidenceConfiguration,
  validateEvidenceConfiguration,
} from './generate-evidence-configuration.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '../../..');
const docsRoot = resolve(scriptDir, '..');

const pathsOf = (fields) => fields.map((field) => field.key_path);

test('nested properties become dotted key paths carrying their required flag', () => {
  const fields = collectFields({
    type: 'object',
    required: ['listener'],
    properties: {
      listener: {
        type: 'object',
        required: ['port'],
        properties: { port: { type: 'integer' }, label: { type: 'string' } },
      },
    },
  });
  assert.deepEqual(pathsOf(fields), ['listener', 'listener.label', 'listener.port']);
  assert.deepEqual(
    fields.map((field) => [field.key_path, field.required]),
    [
      ['listener', 'yes'],
      ['listener.label', 'no'],
      ['listener.port', 'yes'],
    ],
  );
});

test('array items and map values use the bracket and star notation', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      requirements: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' } } } },
      sources: {
        type: 'object',
        additionalProperties: { type: 'object', properties: { origin: { type: 'string' } } },
      },
    },
  });
  assert.deepEqual(pathsOf(fields), [
    'requirements',
    'requirements[]',
    'requirements[].id',
    'sources',
    'sources.*',
    'sources.*.origin',
  ]);
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  assert.equal(byPath.get('requirements[]').kind, 'array_item');
  assert.equal(byPath.get('sources.*').kind, 'map_value');
  assert.equal(byPath.get('sources.*.origin').kind, 'property');
});

test('a closed object contributes no map-value entry', () => {
  const fields = collectFields({
    type: 'object',
    additionalProperties: false,
    properties: { version: { const: 1 } },
  });
  assert.deepEqual(pathsOf(fields), ['version']);
});

test('local references are resolved in place', () => {
  const fields = collectFields({
    type: 'object',
    properties: { path: { $ref: '#/$defs/absolute-path' } },
    $defs: { 'absolute-path': { type: 'string', minLength: 1 } },
  });
  assert.deepEqual(pathsOf(fields), ['path']);
  assert.equal(fields[0].type, 'string');
});

test('a recursive definition is recorded once, at the point it re-enters itself', () => {
  const fields = collectFields({
    type: 'object',
    properties: { node: { $ref: '#/$defs/node' } },
    $defs: {
      node: {
        type: 'object',
        properties: { name: { type: 'string' }, child: { $ref: '#/$defs/node' } },
      },
    },
  });
  assert.deepEqual(pathsOf(fields), ['node', 'node.child', 'node.name']);
});

test('an unresolvable reference is an error rather than a silently missing field', () => {
  assert.throws(
    () => collectFields({ type: 'object', properties: { a: { $ref: '#/$defs/missing' } } }),
    /unresolved schema reference/,
  );
});

test('combinator branches merge into one entry per key path', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      signer: {
        oneOf: [
          { type: 'object', required: ['kind'], properties: { kind: { const: 'file' }, ref: { type: 'string' } } },
          { type: 'object', required: ['kind'], properties: { kind: { const: 'env' } } },
        ],
      },
    },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  assert.deepEqual(pathsOf(fields), ['signer', 'signer.kind', 'signer.ref']);
  assert.deepEqual(byPath.get('signer.kind').values, ['env', 'file']);
  // `kind` is required in both branches; `ref` exists in only one, so it can
  // be neither required nor freely written beside the other branch's keys.
  assert.equal(byPath.get('signer.kind').required, 'yes');
  assert.equal(byPath.get('signer.ref').required, 'conditional');
});

test('alternative descriptions retain their discriminator semantics', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      source: {
        oneOf: [
          {
            type: 'object',
            properties: {
              transport: { const: 'http-json' },
              timeout: { type: 'integer', description: 'Bounds the HTTP exchange.' },
            },
          },
          {
            type: 'object',
            properties: {
              transport: { const: 'sqlite-extract' },
              timeout: { type: 'integer', description: 'Bounds statement execution.' },
            },
          },
        ],
      },
    },
  });
  const timeout = fields.find((field) => field.key_path === 'source.timeout');
  assert.equal(
    timeout.description,
    'For `http-json`: Bounds the HTTP exchange. For `sqlite-extract`: Bounds statement execution.',
  );
});

test('nested alternative descriptions omit their shared outer discriminator', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      source: {
        oneOf: [
          {
            type: 'object',
            properties: {
              transport: { const: 'sqlite-extract' },
              binding: {
                oneOf: [
                  {
                    type: 'object',
                    properties: {
                      kind: { const: 'selector', description: 'Uses a selector field.' },
                    },
                  },
                  {
                    type: 'object',
                    properties: {
                      kind: { const: 'prepared', description: 'Uses preparation output.' },
                    },
                  },
                ],
              },
            },
          },
          {
            type: 'object',
            properties: { transport: { const: 'http-json' } },
          },
        ],
      },
    },
  });
  const kind = fields.find((field) => field.key_path === 'source.binding.kind');
  assert.equal(
    kind.description,
    'For `selector`: Uses a selector field. For `prepared`: Uses preparation output.',
  );
});

test('a key only one alternative declares is conditional, not required', () => {
  const fields = collectFields({
    type: 'object',
    required: ['signer'],
    properties: {
      signer: {
        oneOf: [
          {
            type: 'object',
            required: ['kind', 'privateKeyRef'],
            properties: { kind: { const: 'local-jwk' }, privateKeyRef: { type: 'string' } },
          },
          {
            type: 'object',
            required: ['kind', 'mount'],
            properties: { kind: { const: 'transit' }, mount: { type: 'string' } },
          },
        ],
      },
    },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  // Reporting both as required describes a document both alternatives reject.
  assert.equal(byPath.get('signer').required, 'yes');
  assert.equal(byPath.get('signer.kind').required, 'yes');
  assert.equal(byPath.get('signer.privateKeyRef').required, 'conditional');
  assert.equal(byPath.get('signer.mount').required, 'conditional');
});

test('alternative branches report alternative constraint sets, not their union', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      baseUrl: {
        type: 'string',
        minLength: 1,
        oneOf: [{ pattern: '^https://' }, { pattern: '^http://127\\.0\\.0\\.1' }],
      },
      port: { type: 'integer', minimum: 1, maximum: 65535 },
    },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  // Each alternative carries the shared bound as well, because within one
  // alternative the two do apply together.
  assert.deepEqual(byPath.get('baseUrl').constraints, [
    ['minLength: 1', 'pattern: ^https://'],
    ['minLength: 1', 'pattern: ^http://127\\.0\\.0\\.1'],
  ]);
  // A key with no alternatives keeps a single group.
  assert.deepEqual(byPath.get('port').constraints, [['maximum: 65535', 'minimum: 1']]);
});

test('requiredness is read where a node states it, not only where the key is declared', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      concepts: {
        type: 'array',
        items: {
          type: 'object',
          required: ['form'],
          properties: { note: { type: 'string' } },
          oneOf: [
            { properties: { form: { const: 'presence' } } },
            { properties: { form: { const: 'value' } } },
          ],
        },
      },
    },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  // The `required` list sits on the item, and `properties.form` inside each
  // alternative. Reading requiredness only where a key is declared reports a
  // key every valid document must carry as one a deployment may leave out.
  assert.equal(byPath.get('concepts[].form').required, 'yes');
  assert.equal(byPath.get('concepts[].note').required, 'no');
});

test('a name required only inside `not` is not reported as required', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      request: {
        type: 'object',
        properties: { path: { type: 'string' }, pathTemplate: { type: 'string' } },
        oneOf: [
          { required: ['path'], not: { required: ['pathTemplate'] } },
          { required: ['pathTemplate'], not: { required: ['path'] } },
        ],
      },
    },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  // Each name is required by one alternative and forbidden by the other.
  // Counting the `not` would report both as required under every alternative.
  assert.equal(byPath.get('request.path').required, 'conditional');
  assert.equal(byPath.get('request.pathTemplate').required, 'conditional');
});

test('a required name that nothing declares does not become an entry of its own', () => {
  const fields = collectFields({
    type: 'object',
    required: ['listener', 'absent'],
    properties: { listener: { type: 'string' } },
  });
  // `absent` is a name the contract requires but never declares. Publishing a
  // row for it would invent a key, and would put this walk out of parity with
  // the check that owns the key-path notation.
  assert.deepEqual(pathsOf(fields), ['listener']);
});

test('an `if`/`then` rule binds a key conditionally without binding what it reaches through', () => {
  const fields = collectFields({
    type: 'object',
    required: ['service'],
    properties: {
      assuranceProfile: { enum: ['local', 'production'] },
      service: {
        type: 'object',
        required: ['providerId'],
        properties: { providerId: { type: 'string', maxLength: 512 } },
      },
      fixtures: { type: 'array', items: { type: 'string' } },
    },
    if: { required: ['assuranceProfile'], properties: { assuranceProfile: { const: 'production' } } },
    then: {
      required: ['fixtures'],
      properties: { service: { properties: { providerId: { pattern: '^https://' } } } },
    },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  // The rule requires `fixtures` only where the condition holds.
  assert.equal(byPath.get('fixtures').required, 'conditional');
  // `service` is required whatever the condition. The clause only reaches
  // through it to bound a key below, so its presence is not conditional.
  assert.equal(byPath.get('service').required, 'yes');
  assert.equal(byPath.get('service.providerId').required, 'yes');
  // The pattern binds in one case only, so it is reported as a further
  // tightening rather than as an alternative to the bound that always applies.
  assert.deepEqual(byPath.get('service.providerId').constraints, [['maxLength: 512']]);
  assert.deepEqual(byPath.get('service.providerId').conditional_constraints, [
    ['pattern: ^https://'],
  ]);
});

test('a condition tightens the alternatives rather than standing beside them', () => {
  // Two independent axes bound one key: the alternatives it always chooses
  // between, and a rule that narrows whichever one was chosen. Listing them
  // side by side would offer the unbounded case as a third choice, so a reader
  // would think any value passes.
  const fields = collectFields({
    type: 'object',
    required: ['baseUrl'],
    properties: {
      kind: { enum: ['none', 'token'] },
      baseUrl: {
        oneOf: [
          { type: 'string', pattern: '^https://' },
          { type: 'string', pattern: '^http://127' },
        ],
      },
    },
    if: { required: ['kind'], properties: { kind: { const: 'none' } } },
    then: { properties: { baseUrl: { pattern: '^http://127\\.0\\.0\\.1:[0-9]+$' } } },
  });
  const field = fields.find((entry) => entry.key_path === 'baseUrl');
  assert.deepEqual(field.constraints, [['pattern: ^https://'], ['pattern: ^http://127']]);
  assert.deepEqual(field.conditional_constraints, [
    ['pattern: ^http://127\\.0\\.0\\.1:[0-9]+$'],
  ]);
  // The silent side of the condition adds no bound, and saying so beside the
  // alternatives is what made the key read as unbounded.
  assert.ok(!field.constraints.some((group) => group.length === 0));
});

test('an array whose contents the grammar fixes reports that bound', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      formats: {
        type: 'array',
        minItems: 1,
        contains: { const: 'signed-jws' },
        items: { enum: ['signed-jws', 'unsigned', 'sd-jwt-vc'] },
      },
      capabilities: { type: 'array', items: { enum: ['search-then-fetch-set'] } },
      either: { type: 'array', contains: { enum: ['a', 'b'] } },
    },
    if: { required: ['formats'], properties: { formats: { minItems: 2 } } },
    then: { properties: { capabilities: { contains: { const: 'search-then-fetch-set' } } } },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  // Without this, the entry says `minItems: 1` and the reader concludes any one
  // format will do, when the grammar rejects a list without the signed form.
  assert.deepEqual(byPath.get('formats').constraints, [
    ['contains: signed-jws', 'minItems: 1'],
  ]);
  assert.deepEqual(byPath.get('either').constraints, [['contains: a | b']]);
  // The same keyword under a condition belongs with the other conditional
  // bounds, so an empty list still reads as valid outside the condition.
  assert.deepEqual(byPath.get('capabilities').constraints, []);
  assert.deepEqual(byPath.get('capabilities').conditional_constraints, [
    ['contains: search-then-fetch-set'],
  ]);
});

test('a contents bound this walk cannot state is an error rather than a silent omission', () => {
  // Dropping it would publish a page that accepts an array the grammar rejects,
  // which is the defect the keyword was added to fix.
  assert.throws(
    () =>
      collectFields({
        type: 'object',
        properties: { items: { type: 'array', contains: { type: 'object' } } },
      }),
    /contains/,
  );
  assert.throws(
    () =>
      collectFields({
        type: 'object',
        properties: {
          items: { type: 'array', contains: { const: 'a' }, minContains: 2 },
        },
      }),
    /minContains/,
  );
});

test('a value a condition fixes is named as narrowing the set, not folded into it', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      method: { enum: ['GET', 'POST'] },
      jsonBody: { enum: ['required', 'allowed', 'forbidden'] },
      kind: { oneOf: [{ const: 'file' }, { const: 'env' }] },
    },
    if: { required: ['method'], properties: { method: { const: 'GET' } } },
    then: { properties: { jsonBody: { const: 'forbidden' } } },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  // The union is still the set the grammar accepts somewhere, but a reader who
  // writes `allowed` beside a GET is rejected, so the narrowing has to show.
  assert.deepEqual(byPath.get('jsonBody').values, ['allowed', 'forbidden', 'required']);
  assert.equal(byPath.get('jsonBody').values_conditional, true);
  // A value that selects an alternative is not a narrowing: either is writable.
  assert.equal(byPath.get('kind').values_conditional, false);
  assert.equal(byPath.get('method').values_conditional, false);
});

test('an alternative that adds no bound stays visible beside one that does', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      bounded: { type: 'object', oneOf: [{ maxProperties: 0 }, { minProperties: 1 }] },
      partly: { type: 'object', oneOf: [{ maxProperties: 0 }, {}] },
    },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  assert.deepEqual(byPath.get('bounded').constraints, [['maxProperties: 0'], ['minProperties: 1']]);
  // Dropping the unbounded alternative would print `maxProperties: 0` as
  // though every document had to satisfy it.
  assert.deepEqual(byPath.get('partly').constraints, [['maxProperties: 0'], []]);
});

test('allOf branches stay conjunctive', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      name: { allOf: [{ type: 'string', minLength: 1 }, { maxLength: 64 }] },
    },
  });
  assert.deepEqual(fields[0].constraints, [['maxLength: 64', 'minLength: 1']]);
  assert.equal(fields[0].required, 'no');
});

test('a map reports the bounds its propertyNames places on each key', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      sources: {
        type: 'object',
        propertyNames: { pattern: '^[a-z][a-z0-9-]{0,63}$', maxLength: 64 },
        additionalProperties: { type: 'object', properties: { origin: { type: 'string' } } },
      },
    },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  assert.deepEqual(byPath.get('sources.*').constraints, [
    ['propertyNames.maxLength: 64', 'propertyNames.pattern: ^[a-z][a-z0-9-]{0,63}$'],
  ]);
  assert.equal(byPath.get('sources.*').kind, 'map_value');
});

test('propertyNames written as a reference still reports its bounds', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      sources: {
        type: 'object',
        propertyNames: { $ref: '#/$defs/local-id' },
        additionalProperties: { type: 'object' },
      },
    },
    $defs: { 'local-id': { type: 'string', pattern: '^[a-z][a-z0-9._-]{0,127}$' } },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  assert.deepEqual(byPath.get('sources.*').constraints, [
    ['propertyNames.pattern: ^[a-z][a-z0-9._-]{0,127}$'],
  ]);
});

test('a fixed value proves the type when the schema omits one', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      assuranceProfile: { enum: ['local', 'production'] },
      trustProxyIdentityHeaders: { const: false },
      retries: { const: 0 },
      declared: { type: 'string', enum: ['a'] },
      free: { minLength: 1 },
    },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  assert.equal(byPath.get('assuranceProfile').type, 'string');
  assert.equal(byPath.get('trustProxyIdentityHeaders').type, 'boolean');
  assert.equal(byPath.get('retries').type, 'integer');
  // A declared type wins; nothing is inferred over it.
  assert.equal(byPath.get('declared').type, 'string');
  // Nothing to infer from, so the entry stays honest about not knowing.
  assert.equal(byPath.get('free').type, null);
});

test('fixed values and validation keywords are carried onto the entry', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      port: { type: 'integer', minimum: 1, maximum: 65535 },
      mode: { enum: ['strict', 'lenient'] },
      version: { const: 1 },
      host: {
        type: 'string',
        minLength: 2,
        description: 'Loopback or private address.',
        'x-runtime-validation': 'Parsed as an IP address.',
      },
    },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  assert.deepEqual(byPath.get('port').constraints, [['maximum: 65535', 'minimum: 1']]);
  assert.deepEqual(byPath.get('mode').values, ['lenient', 'strict']);
  assert.deepEqual(byPath.get('version').values, ['1']);
  assert.equal(byPath.get('host').description, 'Loopback or private address.');
  assert.equal(byPath.get('host').runtime_validation, 'Parsed as an IP address.');
  assert.equal(byPath.get('port').description, null);
});

test('validation rejects a document with repeated or missing key paths', () => {
  const entry = (key_path) => ({
    key_path,
    kind: 'property',
    type: 'string',
    required: 'no',
    values: null,
    constraints: [],
    description: null,
    runtime_validation: null,
  });
  const document = (fields) => ({
    format_version: FORMAT_VERSION,
    generator: 'npm run generate',
    contracts: CONTRACTS.map((contract, index) => {
      const entries = index === 0 ? fields : [entry('b')];
      return { ...contract, field_count: entries.length, fields: entries };
    }),
  });
  assert.throws(() => validateEvidenceConfiguration(document([entry('a'), entry('a')])), /repeats/);
  assert.throws(() => validateEvidenceConfiguration(document([])), /at least one/);
  const good = document([entry('a')]);
  assert.doesNotThrow(() => validateEvidenceConfiguration(good));
  good.contracts[0].field_count = 5;
  assert.throws(() => validateEvidenceConfiguration(good), /field_count/);

  const missing = document([entry('a')]);
  missing.contracts.pop();
  assert.throws(() => validateEvidenceConfiguration(missing), /exactly the schemas/);

  const unlabelled = document([entry('a')]);
  delete unlabelled.contracts[0].status;
  assert.throws(() => validateEvidenceConfiguration(unlabelled), /known status/);

  const unreferenced = document([entry('a')]);
  delete unreferenced.contracts[0].reference;
  assert.throws(() => validateEvidenceConfiguration(unreferenced), /reference explaining it/);
});

test('every published schema declares whether it is frozen or adopter tooling', async () => {
  // A reader who takes the authoring schemas for the frozen Version 1 grammar
  // has read the page wrongly, so the status is generated data rather than a
  // sentence a page author has to remember to write.
  const document = await buildEvidenceConfiguration(repoRoot);
  const byId = new Map(document.contracts.map((contract) => [contract.id, contract]));
  for (const contract of CONTRACTS) {
    assert.ok(CONTRACT_STATUSES.includes(contract.status), `${contract.id} status is unknown`);
    assert.equal(byId.get(contract.id).status, contract.status);
  }
  assert.equal(byId.get('bundle').status, 'frozen');
  assert.equal(byId.get('runtime').status, 'frozen');
  assert.equal(byId.get('authoring-question').status, 'tooling');
  assert.equal(byId.get('authoring-project-marker').status, 'tooling');
});

test('the committed schemas produce a valid reference for every configuration file', async () => {
  const document = await buildEvidenceConfiguration(repoRoot);
  validateEvidenceConfiguration(document);
  assert.deepEqual(
    document.contracts.map((contract) => contract.id),
    CONTRACTS.map((contract) => contract.id),
  );
  for (const contract of document.contracts) {
    assert.ok(contract.fields.length > 0, `${contract.id} produced no fields`);
  }
});

test('shared Evidence source keys describe every accepted branch', async () => {
  const document = await buildEvidenceConfiguration(repoRoot);
  const bundle = document.contracts.find((contract) => contract.id === 'bundle');
  const byPath = new Map(bundle.fields.map((field) => [field.key_path, field]));
  const cases = [
    [
      'sources.*.transport',
      ['`http-json`', 'fixed HTTPS origin', '`sqlite-extract`', 'read-only SQLite extract'],
    ],
    [
      'sources.*.request.timeoutMilliseconds',
      ['`http-json`', 'HTTP exchange', '`sqlite-extract`', 'statement execution'],
    ],
    [
      'sources.*.request.selectorInputs',
      ['`http-json`', 'preparation script', '`sqlite-extract`', 'parameter bindings'],
    ],
    [
      'sources.*.request.parameterBindings.*.kind',
      ['`selector`', 'authorized selector field', '`prepared`', 'filled by the preparation script'],
    ],
  ];
  for (const [keyPath, expectedParts] of cases) {
    const description = byPath.get(keyPath)?.description ?? '';
    for (const part of expectedParts) {
      assert.ok(description.includes(part), `${keyPath} omits ${part}`);
    }
  }
});

test('a bound outside double precision is reported exactly as the contract states it', async () => {
  // The adapter parameter bounds are the signed 64-bit integer range. Reading
  // them through a double rounds the last three digits, publishing a bound no
  // contract states and that the runtime would reject.
  const document = await buildEvidenceConfiguration(repoRoot);
  const bundle = document.contracts.find((contract) => contract.id === 'bundle');
  const field = bundle.fields.find(
    (entry) => entry.key_path === 'sources.*.request.adapterParameters.*',
  );
  const constraints = field.constraints.flat();
  assert.ok(
    constraints.includes('maximum: 9223372036854775807'),
    `expected the exact signed 64-bit maximum, got ${JSON.stringify(constraints)}`,
  );
  assert.ok(constraints.includes('minimum: -9223372036854775808'));
});

test('the rendered key paths match the ones each CONFIG.md documents', async () => {
  // `products/evidence/scripts/check-config-key-paths.sh` owns the CONFIG.md
  // blocks. Comparing against them keeps this walk and that one from drifting
  // apart without either side going quiet. Each entry names the reference it
  // documents into, so a schema is compared against the prose that explains it
  // rather than against one file every schema is assumed to share.
  const references = new Map();
  const documented = async (contract) => {
    if (!references.has(contract.reference)) {
      references.set(
        contract.reference,
        await readFile(resolve(repoRoot, contract.reference), 'utf8'),
      );
    }
    const reference = references.get(contract.reference);
    const body = reference
      .split(`<!-- ${contract.marker}:start -->`)[1]
      .split(`<!-- ${contract.marker}:end -->`)[0];
    return body
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('```'));
  };

  const document = await buildEvidenceConfiguration(repoRoot);
  assert.ok(
    new Set(document.contracts.map((contract) => contract.reference)).size > 1,
    'more than one reference must be exercised, or the per-entry addressing is untested',
  );
  for (const contract of document.contracts) {
    const expected = await documented(contract);
    assert.deepEqual(pathsOf(contract.fields), expected, `${contract.id} key paths drifted`);
  }
});

test('generating writes the reference where the page reads it', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'evidence-configuration-'));
  try {
    await generateEvidenceConfiguration(scratch, repoRoot);
    const written = JSON.parse(
      await readFile(join(scratch, 'src/data/generated/evidence-configuration.json'), 'utf8'),
    );
    validateEvidenceConfiguration(written);
    const committed = JSON.parse(
      await readFile(join(docsRoot, 'src/data/generated/evidence-configuration.json'), 'utf8'),
    );
    assert.deepEqual(written, committed, 'the committed reference is stale; run npm run generate');
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});

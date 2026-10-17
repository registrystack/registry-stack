import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { dereference } from '@readme/openapi-parser';
import ts from 'typescript';
import { projectOpenApiForRenderer } from './openapi-renderer.mjs';

// Exercise the installed renderer's actual example generator. Its published
// TypeScript uses extensionless imports, so transpile only that package for
// this Node test without modifying node_modules or adding a loader dependency.
const rendererRoot = new URL('./', import.meta.resolve('starlight-openapi')).href;
const loader = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (context.parentURL?.startsWith(rendererRoot) && specifier.startsWith('.') && !specifier.endsWith('.ts')) {
      return nextResolve(`${specifier}.ts`, context);
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.startsWith(rendererRoot) && url.endsWith('.ts')) {
      return { format: 'module', shortCircuit: true,
        source: ts.transpileModule(readFileSync(new URL(url), 'utf8'), {
          compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ESNext },
        }).outputText };
    }
    return nextLoad(url, context);
  },
});
const { createSchemaExampleValue, getSchemaAuthoredExampleValue } =
  await import(new URL('libs/exampleValue.ts', rendererRoot));
loader.deregister();

test('boolean schemas adapt without changing annotation values, flags, or references', () => {
  const data = { schema: false, nested: { properties: { schema: true } } };
  const original = { openapi: '3.1.0', components: { schemas: {
    Payload: { type: 'object', additionalProperties: false, properties: {
      body: true, enabled: { type: 'boolean', default: false },
      nested: { type: 'array', items: { anyOf: [true, { $ref: '#/components/schemas/Dynamic' }] } },
    }, example: data, examples: [data], default: data, const: data, enum: [data], 'x-data': data },
    Dynamic: { $defs: { Value: true }, $dynamicRef: '#value', $anchor: 'value' },
  }, parameters: { schema: { name: 'schema', in: 'query', schema: true, example: data } } } };
  const snapshot = structuredClone(original);
  const projected = projectOpenApiForRenderer(original);
  assert.deepEqual(original, snapshot);
  const payload = projected.components.schemas.Payload;
  assert.deepEqual(payload.properties.body, {});
  assert.deepEqual(payload.properties.nested.items.anyOf, [{}, { $ref: '#/components/schemas/Dynamic' }]);
  assert.equal(payload.additionalProperties, false);
  assert.equal(payload.properties.enabled.default, false);
  for (const field of ['example', 'default', 'const', 'x-data']) assert.deepEqual(payload[field], data);
  assert.deepEqual(payload.enum, [data]);
  assert.deepEqual(payload.examples, [data]);
  assert.deepEqual(projected.components.schemas.Dynamic, {
    $defs: { Value: {} }, $dynamicRef: '#value', $anchor: 'value',
  });
  assert.deepEqual(projected.components.parameters.schema.schema, {});
  assert.deepEqual(projected.components.parameters.schema.example, data);
  assert.doesNotThrow(() => createSchemaExampleValue(payload));
});

test('false schemas fail with an actionable JSON pointer instead of an invalid generated example', () => {
  const original = { components: { schemas: { 'not/allowed': { properties: { body: false } } } } };
  assert.throws(() => projectOpenApiForRenderer(original),
    /false schema at #\/components\/schemas\/not~1allowed\/properties\/body; upgrade starlight-openapi/);
  assert.equal(original.components.schemas['not/allowed'].properties.body, false);
  // This is why a semantically equivalent {not:{}} is deliberately refused.
  assert.equal(createSchemaExampleValue({ not: {} }), 'example');
});

test('operation, callback, webhook, header, and media schemas use the same projection', () => {
  const data = { get: { responses: { 200: { content: { 'application/json': { schema: false } } } } } };
  const operation = { parameters: [{ name: 'body', in: 'query', schema: true }],
    requestBody: { content: { 'application/json': { schema: { type: 'array', items: true },
      examples: { schema: { value: data } } } } },
    responses: { 200: { content: { 'application/json': { schema: true } },
      headers: { schema: { schema: true } } } } };
  const document = { paths: { '/items': { post: { ...operation, callbacks: {
    completed: { '{$request.body#/url}': { post: operation }, 'x-data': data },
  } } }, 'x-data': data }, webhooks: { delivered: { post: operation } } };
  const projected = projectOpenApiForRenderer(document);
  const post = projected.paths['/items'].post;
  assert.deepEqual(post.parameters[0].schema, {});
  assert.deepEqual(post.requestBody.content['application/json'].schema.items, {});
  assert.deepEqual(post.requestBody.content['application/json'].examples.schema.value, data);
  assert.deepEqual(post.responses[200].headers.schema.schema, {});
  assert.deepEqual(post.callbacks.completed['{$request.body#/url}'].post.responses[200]
    .content['application/json'].schema, {});
  assert.deepEqual(projected.webhooks.delivered.post.responses[200].content['application/json'].schema, {});
  assert.deepEqual(post.callbacks.completed['x-data'], data);
  assert.deepEqual(projected.paths['x-data'], data);
});

test('installed renderer generates examples from every maintained product schema after projection', async () => {
  const site = resolve(import.meta.dirname, '..');
  const sources = [
    ['casework', 'products/casework/generated/registry-casework.openapi.json'],
    ['scheduling', 'products/scheduling/generated/registry-scheduling.openapi.json'],
    ['messaging', 'products/messaging/generated/registry-messaging.openapi.json'],
    ['coordinator', 'products/coordinator/generated/openapi/coordinator.openapi.json'],
    ['evidence', 'products/evidence/generated/registry-evidence.openapi.json'],
    ['breg', 'products/breg/generated/facility/generated/openapi.json'],
  ];
  for (const [product, path] of sources) {
    const original = JSON.parse(readFileSync(resolve(site, '../..', path), 'utf8'));
    const projected = projectOpenApiForRenderer(original);
    if (product === 'casework') {
      const native = await dereference(structuredClone(original));
      assert.throws(() => getSchemaAuthoredExampleValue(native.components.schemas.ReviewPolicyClosure),
        /Invalid value used in weak set/);
    }
    const document = await dereference(projected);
    const schemas = Object.entries(document.components?.schemas ?? {});
    // BReg inlines most request and response schemas in its operations.
    for (const [route, item] of Object.entries(document.paths ?? {})) {
      for (const [method, operation] of Object.entries(item)) {
        const bodies = [['request', operation?.requestBody],
          ...Object.entries(operation?.responses ?? {})];
        for (const [status, body] of bodies) {
          for (const [media, entry] of Object.entries(body?.content ?? {})) {
            if (entry.schema) schemas.push([`${method} ${route} ${status} ${media}`, entry.schema]);
          }
        }
      }
    }
    for (const [name, schema] of schemas) {
      assert.doesNotThrow(() => {
        getSchemaAuthoredExampleValue(schema);
        createSchemaExampleValue(schema);
      }, `${product}: ${name}`);
    }
  }
});

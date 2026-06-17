#!/usr/bin/env node
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import readline from 'node:readline';
import path from 'node:path';

import compile, { preloadAdaptorExports } from '@openfn/compiler';
import run from '@openfn/runtime';

const require = createRequire(import.meta.url);
let runCounter = 0;
const compiledJobs = new Map();

if (process.argv.includes('--version')) {
  await printVersionAndExit();
}

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
});

for await (const line of rl) {
  if (!line.trim()) {
    continue;
  }
  try {
    const request = JSON.parse(line);
    const response = await withStdoutRedirect(() => executeRequest(request));
    writeJson(response);
  } catch (error) {
    writeJson({
      error: classifyExecutionError(error),
    });
  }
}

async function executeRequest(request) {
  if (request?.mode === 'batch_match') {
    return executeBatchMatch(request);
  }
  return executeLookup(request);
}

async function withStdoutRedirect(callback) {
  const originalWrite = process.stdout.write;
  process.stdout.write = function writeToStderr(chunk, encoding, callback) {
    return process.stderr.write(chunk, encoding, callback);
  };
  try {
    return await callback();
  } finally {
    process.stdout.write = originalWrite;
  }
}

async function executeLookup(
  request,
  workflow = undefined,
  lookup = undefined,
  batchItem = undefined,
) {
  workflow ??= await compiledWorkflow(request);

  const state = {
    data: {
      source_id: request.source_id,
      dataset: request.dataset,
      entity: request.entity,
      lookup: lookup ?? request.lookup,
      query_signature: request.query_signature,
      item: batchItem,
      fields: request.fields ?? [],
      limit: request.limit ?? 2,
      purpose: request.purpose,
      correlation_id: request.correlation_id,
    },
    configuration: request.configuration ?? {},
  };

  const result = await runOpenFnWorkflow(workflow, state);

  return normalizeLookupResult(result, request);
}

async function executeBatchMatch(request) {
  if (!Array.isArray(request.query_signature) || !Array.isArray(request.items)) {
    return {
      error: {
        code: 'invalid_batch_request',
        message: 'batch_match requires query_signature and items arrays',
      },
    };
  }
  const workflow = await compiledWorkflow(request);
  const mode =
    request?.batch?.mode ??
    (workflow.batchMode === 'native' ? 'workflow_batch' : 'sequential_lookup');
  if (mode === 'workflow_batch' || mode === 'native') {
    return executeBatchWorkflow(request, workflow);
  }
  if (mode !== 'sequential_lookup') {
    return {
      error: {
        code: 'invalid_batch_request',
        message: `unsupported batch mode: ${mode}`,
      },
    };
  }
  return executeSequentialBatchMatch(request, workflow);
}

async function executeSequentialBatchMatch(request, workflow) {
  const items = [];
  for (const item of request.items) {
    const id = String(item?.id ?? '');
    try {
      const lookup = lookupForBatchItem(request.query_signature, item);
      const response = await executeLookup(request, workflow, lookup, item);
      if (response?.error) {
        items.push({ id, error: response.error });
      } else {
        items.push({ id, data: response.data ?? [] });
      }
    } catch (error) {
      items.push({ id, error: classifyExecutionError(error) });
    }
  }
  return { items };
}

async function executeBatchWorkflow(request, workflow) {
  const state = {
    data: {
      mode: 'batch_match',
      source_id: request.source_id,
      dataset: request.dataset,
      entity: request.entity,
      query_signature: request.query_signature,
      items: request.items,
      fields: request.fields ?? [],
      limit: request.limit ?? 2,
      purpose: request.purpose,
      correlation_id: request.correlation_id,
      batch: request.batch ?? {},
    },
    configuration: request.configuration ?? {},
  };
  const result = await runOpenFnWorkflow(workflow, state);
  return normalizeBatchResult(result, request);
}

async function runOpenFnWorkflow(workflow, state) {
  const result = await run(
    {
      workflow: {
        steps: workflow.steps,
        start: workflow.start,
      },
      options: {
        start: workflow.start,
      },
    },
    state,
    {
      linker: {
        modules: workflow.modules,
        cacheKey: workflow.cacheKey,
      },
      statePropsToRemove: [],
    },
  );
  delete result?.configuration;
  return result;
}

function lookupForBatchItem(querySignature, item) {
  const values = Array.isArray(item?.values) ? item.values : [];
  const terms = querySignature.map((term, index) => ({
    field: term?.field,
    op: term?.op ?? 'eq',
    value: values[index],
  }));
  if (terms.length === 1) {
    return {
      field: terms[0].field,
      value: terms[0].value,
    };
  }
  return { terms };
}

function normalizeLookupResult(result, request) {
  const targetError = extractTargetError(result);
  if (targetError) {
    return { error: targetError };
  }
  const records = extractRecords(result);
  if (!Array.isArray(records)) {
    return {
      error: {
        code: 'invalid_job_result',
        message: describeResultShape(result, request),
      },
    };
  }
  return { data: records };
}

function normalizeBatchResult(result, request) {
  const targetError = extractTargetError(result);
  if (targetError) {
    return { error: targetError };
  }
  const items = extractBatchItems(result);
  if (!Array.isArray(items)) {
    return {
      error: {
        code: 'invalid_batch_job_result',
        message: describeBatchResultShape(result, request),
      },
    };
  }
  return { items };
}

async function compiledWorkflow(request) {
  if (Array.isArray(request.workflow?.steps)) {
    const steps = [];
    const modules = {};
    const cacheKeys = [];

    for (const requestedStep of request.workflow.steps) {
      const compiled = await compiledExpression(
        requestedStep.expression,
        requestedStep.adaptors,
      );
      for (const adaptor of compiled.adaptors) {
        modules[adaptor.name] = { path: adaptor.path };
      }
      cacheKeys.push(compiled.cacheKey);

      const step = {
        id: requestedStep.id,
        expression: compiled.code,
        adaptors: compiled.adaptors.map(
          (adaptor) => `${adaptor.name}=${adaptor.path}`,
        ),
      };
      if (requestedStep.next) {
        step.next = normalizeNext(requestedStep.next);
      }
      steps.push(step);
    }

    return {
      steps,
      start: request.workflow.start ?? steps[0]?.id,
      batchMode: request.workflow.batch_mode ?? 'per_item',
      modules,
      cacheKey: `workflow-${cacheKeys.join('-')}`,
    };
  }

  throw new Error('request.workflow.steps must be configured');
}

function normalizeNext(next) {
  if (typeof next === 'string') {
    return { [next]: true };
  }
  return next;
}

async function compiledExpression(expressionPath, adaptorSpecifiers = []) {
  const cacheKey = `${expressionPath}\u0000${adaptorSpecifiers.join('\u0000')}`;
  const cached = compiledJobs.get(cacheKey);
  if (cached) {
    return cached;
  }

  const adaptors = adaptorSpecifiers.map((adaptorSpecifier) =>
    resolveAdaptor(adaptorSpecifier),
  );
  const expression = await readFile(expressionPath, 'utf8');
  const adaptorImports = [];
  for (const adaptor of adaptors) {
    const adaptorExports = await preloadAdaptorExports(adaptor.path);
    adaptorImports.push({
      name: adaptor.name,
      exports: adaptorExports,
      exportAll: true,
    });
  }
  const { code } = compile(expression, {
    'add-imports': {
      adaptors: adaptorImports,
    },
  });
  const compiled = {
    adaptors,
    code,
    cacheKey: `compiled-${++runCounter}`,
  };
  compiledJobs.set(cacheKey, compiled);
  return compiled;
}

function extractTargetError(state) {
  const error = state?.data?.error ?? state?.error;
  if (!error || typeof error !== 'object') {
    return extractRuntimeTargetError(state?.errors);
  }
  if (error.code === 'target_auth') {
    return { code: 'target_auth' };
  }
  if (error.code === 'target_rate_limit') {
    const targetError = { code: 'target_rate_limit' };
    const retryAfter = Number(error.retry_after_seconds);
    if (Number.isSafeInteger(retryAfter) && retryAfter > 0) {
      targetError.retry_after_seconds = retryAfter;
    }
    return targetError;
  }
  return { code: 'openfn_execution' };
}

function extractRuntimeTargetError(errors) {
  if (!errors || typeof errors !== 'object') {
    return undefined;
  }
  for (const error of Object.values(errors)) {
    const details = error?.details ?? {};
    const statusCode = Number(details.statusCode ?? details.status);
    if (statusCode === 401 || statusCode === 403) {
      return { code: 'target_auth' };
    }
    if (statusCode === 429) {
      const targetError = { code: 'target_rate_limit' };
      const retryAfter = retryAfterSeconds(details.headers);
      if (retryAfter) {
        targetError.retry_after_seconds = retryAfter;
      }
      return targetError;
    }
  }
  return undefined;
}

function classifyExecutionError(error) {
  const statusCode = Number(error?.statusCode ?? error?.status);
  if (statusCode === 401 || statusCode === 403) {
    return { code: 'target_auth' };
  }
  if (statusCode === 429) {
    const targetError = { code: 'target_rate_limit' };
    const retryAfter = retryAfterSeconds(error?.headers);
    if (retryAfter) {
      targetError.retry_after_seconds = retryAfter;
    }
    return targetError;
  }
  return {
    code: 'openfn_execution',
    message: safeErrorMessage(error),
  };
}

function retryAfterSeconds(headers) {
  const raw = headers?.['retry-after'] ?? headers?.['Retry-After'];
  const seconds = Number(Array.isArray(raw) ? raw[0] : raw);
  return Number.isSafeInteger(seconds) && seconds > 0 ? seconds : undefined;
}

function extractRecords(state) {
  if (Array.isArray(state?.data)) {
    return state.data;
  }
  if (Array.isArray(state?.data?.data)) {
    return state.data.data;
  }
  if (Array.isArray(state?.data?.records)) {
    return state.data.records;
  }
  if (Array.isArray(state?.response?.body?.data)) {
    return state.response.body.data;
  }
  if (Array.isArray(state?.response?.body?.records)) {
    return state.response.body.records;
  }
  return undefined;
}

function extractBatchItems(state) {
  if (Array.isArray(state?.items)) {
    return state.items;
  }
  if (Array.isArray(state?.data?.items)) {
    return state.data.items;
  }
  if (Array.isArray(state?.response?.body?.items)) {
    return state.response.body.items;
  }
  return undefined;
}

function describeResultShape(state, request) {
  const data = state?.data;
  const responseBody = state?.response?.body;
  return JSON.stringify({
    workflow_start: request?.workflow?.start,
    workflow_step_count: Array.isArray(request?.workflow?.steps)
      ? request.workflow.steps.length
      : null,
    workflow_step_ids: Array.isArray(request?.workflow?.steps)
      ? request.workflow.steps.map(step => step?.id)
      : [],
    workflow_step_expressions: Array.isArray(request?.workflow?.steps)
      ? request.workflow.steps.map(step => step?.expression)
      : [],
    workflow_step_adaptors: Array.isArray(request?.workflow?.steps)
      ? request.workflow.steps.map(step => step?.adaptors)
      : [],
    has_configuration: Boolean(request?.configuration),
    configuration_keys: objectKeys(request?.configuration),
    data_type: Array.isArray(data) ? 'array' : typeof data,
    data_keys: objectKeys(data),
    response_keys: objectKeys(state?.response),
    response_body_type: Array.isArray(responseBody) ? 'array' : typeof responseBody,
    response_body_keys: objectKeys(responseBody),
    has_error: Boolean(state?.error ?? state?.data?.error),
  });
}

function describeBatchResultShape(state, request) {
  const data = state?.data;
  const responseBody = state?.response?.body;
  return JSON.stringify({
    workflow_start: request?.workflow?.start,
    workflow_step_count: Array.isArray(request?.workflow?.steps)
      ? request.workflow.steps.length
      : null,
    workflow_step_ids: Array.isArray(request?.workflow?.steps)
      ? request.workflow.steps.map(step => step?.id)
      : [],
    batch_mode: request?.batch?.mode ?? 'sequential_lookup',
    request_item_count: Array.isArray(request?.items) ? request.items.length : null,
    has_configuration: Boolean(request?.configuration),
    configuration_keys: objectKeys(request?.configuration),
    data_type: Array.isArray(data) ? 'array' : typeof data,
    data_keys: objectKeys(data),
    response_keys: objectKeys(state?.response),
    response_body_type: Array.isArray(responseBody) ? 'array' : typeof responseBody,
    response_body_keys: objectKeys(responseBody),
    has_error: Boolean(state?.error ?? state?.data?.error),
  });
}

function objectKeys(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return [];
  }
  return Object.keys(value).sort();
}

function resolveAdaptor(specifier) {
  const [moduleSpecifier, explicitPath] = String(specifier).split('=');
  const { name } = parsePackageSpecifier(moduleSpecifier);
  return {
    name,
    path: explicitPath || packageRoot(name),
  };
}

function parsePackageSpecifier(specifier) {
  const at = specifier.lastIndexOf('@');
  if (at > 0) {
    return {
      name: specifier.slice(0, at),
      version: specifier.slice(at + 1),
    };
  }
  return { name: specifier, version: undefined };
}

async function printVersionAndExit() {
  const requiredAdaptors = requiredAdaptorArgs();
  const versions = [
    `cli_build_tool=${packageVersion('@openfn/compiler')}`,
    `runtime=${packageVersion('@openfn/runtime')}`,
  ];
  for (const adaptor of requiredAdaptors) {
    const resolved = resolveAdaptor(adaptor);
    versions.push(`${adaptor}:${packageVersion(resolved.name)}=${resolved.path}`);
  }
  console.log(versions.join(' '));
  process.exit(0);
}

function requiredAdaptorArgs() {
  const adaptors = [];
  for (let index = 2; index < process.argv.length; index += 1) {
    if (process.argv[index] === '--require-adaptor' && process.argv[index + 1]) {
      adaptors.push(process.argv[index + 1]);
      index += 1;
    }
  }
  return adaptors;
}

function packageVersion(name) {
  const root = packageRoot(name);
  return require(path.join(root, 'package.json')).version;
}

function packageRoot(name) {
  let current = path.dirname(new URL(import.meta.resolve(name)).pathname);
  for (;;) {
    try {
      const raw = require(path.join(current, 'package.json'));
      if (raw.name === name) {
        return current;
      }
    } catch {
      // Keep walking toward the package root.
    }
    const parent = path.dirname(current);
    if (parent === current) {
      throw new Error(`Could not find package metadata for ${name}`);
    }
    current = parent;
  }
}

function writeJson(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function safeErrorMessage(error) {
  return error?.name || 'OpenFn execution failed';
}

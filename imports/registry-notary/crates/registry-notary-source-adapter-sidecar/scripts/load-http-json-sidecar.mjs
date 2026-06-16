#!/usr/bin/env node

const sidecarUrl = (process.env.LOAD_HTTP_JSON_SIDECAR_URL ?? 'http://127.0.0.1:19311').replace(/\/$/, '');
const token = process.env.LOAD_HTTP_JSON_SIDECAR_TOKEN ?? 'load-sidecar-token';
const scenario = process.env.LOAD_HTTP_JSON_SCENARIO ?? 'lookup';
const totalRequests = positiveInt('LOAD_HTTP_JSON_REQUESTS', 200);
const concurrency = positiveInt('LOAD_HTTP_JSON_CONCURRENCY', 16);
const batchSize = positiveInt('LOAD_HTTP_JSON_BATCH_SIZE', 10);
const uniqueKeys = positiveInt('LOAD_HTTP_JSON_UNIQUE_KEYS', 100);
const warmupRequests = nonNegativeInt('LOAD_HTTP_JSON_WARMUP_REQUESTS', Math.min(20, totalRequests));
const maxP95Ms = positiveInt('LOAD_HTTP_JSON_MAX_P95_MS', 1000);
const maxErrorRatePercent = Number.parseFloat(process.env.LOAD_HTTP_JSON_MAX_ERROR_RATE_PERCENT ?? '0');

function positiveInt(name, fallback) {
  const value = Number.parseInt(process.env[name] ?? `${fallback}`, 10);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} must be greater than zero`);
  }
  return value;
}

function nonNegativeInt(name, fallback) {
  const value = Number.parseInt(process.env[name] ?? `${fallback}`, 10);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${name} must be non-negative`);
  }
  return value;
}

function percentile(sorted, percentileValue) {
  if (sorted.length === 0) {
    return 0;
  }
  const idx = Math.min(sorted.length - 1, Math.ceil((percentileValue / 100) * sorted.length) - 1);
  return sorted[idx];
}

function lookupId(index) {
  if (scenario === 'cache') {
    return 'person-cache';
  }
  return `person-${index % uniqueKeys}`;
}

function requestFor(index) {
  if (scenario === 'lookup' || scenario === 'cache') {
    const id = encodeURIComponent(lookupId(index));
    return {
      url: `${sidecarUrl}/v1/datasets/civil_registry/entities/civil_person/records?national_id=${id}&fields=national_id,birth_date&limit=2`,
      init: { method: 'GET' },
      validate: body => Array.isArray(body.data),
      items: 1,
    };
  }
  if (scenario === 'batch') {
    const items = [];
    for (let offset = 0; offset < batchSize; offset += 1) {
      const value = `person-${(index * batchSize + offset) % uniqueKeys}`;
      items.push({ id: `${index}-${offset}`, values: [value] });
    }
    return {
      url: `${sidecarUrl}/v1/datasets/civil_registry/entities/civil_person/records:batchMatch`,
      init: {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          fields: ['national_id', 'birth_date'],
          query_signature: [{ field: 'national_id', op: 'eq' }],
          items,
        }),
      },
      validate: body => Array.isArray(body.items) && body.items.length === items.length,
      items: items.length,
    };
  }
  throw new Error(`unsupported LOAD_HTTP_JSON_SCENARIO ${scenario}`);
}

async function executeRequest(index) {
  const request = requestFor(index);
  const started = process.hrtime.bigint();
  let status = 0;
  let ok = false;
  let error = null;
  try {
    const response = await fetch(request.url, {
      ...request.init,
      headers: {
        authorization: `Bearer ${token}`,
        'data-purpose': 'load-test',
        ...(request.init.headers ?? {}),
      },
    });
    status = response.status;
    const body = await response.json();
    ok = response.ok && request.validate(body);
    if (!ok) {
      error = `unexpected response status=${status}`;
    }
  } catch (caught) {
    error = caught instanceof Error ? caught.message : String(caught);
  }
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1_000_000;
  return { ok, status, error, elapsedMs, items: request.items };
}

async function runPhase(count, collect) {
  let next = 0;
  async function worker() {
    while (true) {
      const index = next;
      next += 1;
      if (index >= count) {
        return;
      }
      const result = await executeRequest(index);
      if (collect) {
        collect(result);
      }
    }
  }
  const workers = [];
  for (let i = 0; i < Math.min(concurrency, count); i += 1) {
    workers.push(worker());
  }
  await Promise.all(workers);
}

if (warmupRequests > 0) {
  await runPhase(warmupRequests, null);
}

const results = [];
const started = process.hrtime.bigint();
await runPhase(totalRequests, result => results.push(result));
const elapsedSeconds = Number(process.hrtime.bigint() - started) / 1_000_000_000;

const latencies = results.map(result => result.elapsedMs).sort((a, b) => a - b);
const errors = results.filter(result => !result.ok);
const totalItems = results.reduce((sum, result) => sum + result.items, 0);
const statusCounts = {};
for (const result of results) {
  statusCounts[result.status] = (statusCounts[result.status] ?? 0) + 1;
}
const errorRatePercent = results.length === 0 ? 0 : (errors.length / results.length) * 100;
const report = {
  scenario,
  requests: results.length,
  items: totalItems,
  concurrency,
  batch_size: scenario === 'batch' ? batchSize : null,
  elapsed_seconds: Number(elapsedSeconds.toFixed(3)),
  requests_per_second: Number((results.length / elapsedSeconds).toFixed(2)),
  items_per_second: Number((totalItems / elapsedSeconds).toFixed(2)),
  latency_ms: {
    min: Number((latencies[0] ?? 0).toFixed(2)),
    p50: Number(percentile(latencies, 50).toFixed(2)),
    p95: Number(percentile(latencies, 95).toFixed(2)),
    p99: Number(percentile(latencies, 99).toFixed(2)),
    max: Number((latencies.at(-1) ?? 0).toFixed(2)),
  },
  status_counts: statusCounts,
  errors: errors.slice(0, 10).map(error => ({ status: error.status, error: error.error })),
  thresholds: {
    max_p95_ms: maxP95Ms,
    max_error_rate_percent: maxErrorRatePercent,
  },
};

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);

if (report.latency_ms.p95 > maxP95Ms) {
  process.stderr.write(`p95 latency ${report.latency_ms.p95}ms exceeded ${maxP95Ms}ms\n`);
  process.exitCode = 1;
}
if (errorRatePercent > maxErrorRatePercent) {
  process.stderr.write(`error rate ${errorRatePercent.toFixed(2)}% exceeded ${maxErrorRatePercent}%\n`);
  process.exitCode = 1;
}

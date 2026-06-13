#!/usr/bin/env node

import http from 'node:http';

const port = Number.parseInt(process.env.LOAD_HTTP_JSON_REGISTRY_PORT ?? '19312', 10);
const token = process.env.LOAD_HTTP_JSON_TARGET_TOKEN ?? 'load-target-token';
const delayMs = Number.parseInt(process.env.LOAD_HTTP_JSON_TARGET_DELAY_MS ?? '0', 10);
const jitterMs = Number.parseInt(process.env.LOAD_HTTP_JSON_TARGET_JITTER_MS ?? '0', 10);

let totalRequests = 0;
let inFlight = 0;
let maxInFlight = 0;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function personRecord(id) {
  if (id === 'smoke-person') {
    return [{ national_id: 'smoke-person', birth_date: '1990-01-01', ignored_extra: 'not-requested' }];
  }
  if (id.startsWith('missing-')) {
    return [];
  }
  if (id.startsWith('ambiguous-')) {
    return [
      { national_id: id, birth_date: '1990-01-01', ignored_extra: 'not-requested' },
      { national_id: id, birth_date: '1992-02-02', ignored_extra: 'not-requested' },
    ];
  }
  return [{ national_id: id, birth_date: '1990-01-01', ignored_extra: 'not-requested' }];
}

function writeJson(res, status, body) {
  const bytes = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': bytes.length,
  });
  res.end(bytes);
}

async function maybeDelay() {
  const jitter = jitterMs > 0 ? Math.floor(Math.random() * jitterMs) : 0;
  const wait = Math.max(0, delayMs + jitter);
  if (wait > 0) {
    await sleep(wait);
  }
}

function authorized(req) {
  return req.headers.authorization === `Bearer ${token}`;
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  if (chunks.length === 0) {
    return {};
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

const server = http.createServer(async (req, res) => {
  totalRequests += 1;
  inFlight += 1;
  maxInFlight = Math.max(maxInFlight, inFlight);
  try {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? `127.0.0.1:${port}`}`);
    if (url.pathname === '/healthz') {
      writeJson(res, 200, { ok: true });
      return;
    }
    if (url.pathname === '/stats') {
      writeJson(res, 200, { totalRequests, inFlight, maxInFlight });
      return;
    }
    if (!authorized(req)) {
      writeJson(res, 401, { error: 'unauthorized' });
      return;
    }
    await maybeDelay();
    if (req.method === 'GET' && url.pathname === '/people') {
      const id = url.searchParams.get('id') ?? '';
      writeJson(res, 200, { results: personRecord(id) });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/native') {
      const body = await readBody(req);
      const results = [];
      for (const item of Array.isArray(body.items) ? body.items : []) {
        const id = Array.isArray(item.values) ? String(item.values[0] ?? '') : '';
        results.push(...personRecord(id));
      }
      writeJson(res, 200, { results });
      return;
    }
    writeJson(res, 404, { error: 'not found' });
  } catch (error) {
    writeJson(res, 500, { error: 'mock failure' });
  } finally {
    inFlight -= 1;
  }
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`load mock registry listening on 127.0.0.1:${port}\n`);
});

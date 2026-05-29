#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import http from 'node:http';

const port = Number(process.env.MOCK_REGISTRY_PORT ?? 19192);
const host = process.env.MOCK_REGISTRY_HOST ?? '127.0.0.1';
const token = process.env.MOCK_REGISTRY_TOKEN || 'demo-target-token';

const people = new Map([
  [
    'person-123',
    [
      {
        national_id: 'person-123',
        birth_date: '1990-01-01',
        ignored_extra: 'sidecar projection should remove this',
      },
    ],
  ],
  [
    'person-456',
    [
      {
        national_id: 'person-456',
        birth_date: '1985-05-05',
        ignored_extra: 'sidecar projection should remove this',
      },
    ],
  ],
  [
    'ambiguous-person',
    [
      { national_id: 'ambiguous-person', birth_date: '1990-01-01' },
      { national_id: 'ambiguous-person', birth_date: '1992-02-02' },
      { national_id: 'ambiguous-person', birth_date: '1999-09-09' },
    ],
  ],
]);

const server = http.createServer((request, response) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  if (request.method !== 'GET' || !url.pathname.startsWith('/people/')) {
    return json(response, 404, { error: 'not_found' });
  }

  const id = decodeURIComponent(url.pathname.slice('/people/'.length));
  const auth = request.headers.authorization ?? '';
  if (auth !== `Bearer ${token}` || id === 'target-auth') {
    return json(response, 401, { error: 'target_auth' });
  }
  if (id === 'target-rate-limit') {
    response.setHeader('Retry-After', '5');
    return json(response, 429, { error: 'target_rate_limit' });
  }

  return json(response, 200, { data: people.get(id) ?? [] });
});

server.listen(port, host, () => {
  console.log(`mock registry listening on http://${host}:${port}`);
});

function json(response, status, body) {
  response.writeHead(status, { 'Content-Type': 'application/json' });
  response.end(`${JSON.stringify(body)}\n`);
}

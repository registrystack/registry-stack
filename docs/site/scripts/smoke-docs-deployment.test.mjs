import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  parseSmokeArgs,
  smokeDocsDeployment,
} from './smoke-docs-deployment.mjs';

const origin = 'https://docs.registrystack.org';
const releasedTag = 'v1.2.3';

function html(canonical, extra = '') {
  return Buffer.from(
    `<html><head><link rel="canonical" href="${canonical}"></head>` +
      `<body>${extra}</body></html>`,
  );
}

function fixture(overrides = {}) {
  const routes = new Map([
    [
      '/',
      html(
        `${origin}/`,
        '<strong>Released docs.</strong><a href="/v/1.2.3/">Version</a>',
      ),
    ],
    ['/start/when-to-use/', html(`${origin}/start/when-to-use/`)],
    ['/dev/', html(`${origin}/dev/`)],
    ['/v/1.2.3/', html(`${origin}/v/1.2.3/`)],
    ['/pagefind/pagefind.js', Buffer.from('search')],
    ['/pagefind/pagefind-entry.json', Buffer.from('{}')],
    ['/sitemap-index.xml', Buffer.from('<sitemapindex/>')],
    ['/llms.txt', Buffer.from('docs')],
    ['/index.md', Buffer.from('# Docs')],
    ['/dev/llms.txt', Buffer.from('dev docs')],
    ['/dev/index.md', Buffer.from('# Dev docs')],
  ]);
  for (const [path, value] of Object.entries(overrides)) routes.set(path, value);
  return async (pathname) => {
    const body = routes.get(pathname);
    if (!body) return { body: Buffer.alloc(0), location: null, status: 404 };
    return { body, location: null, status: 200 };
  };
}

test('smokes root, deep, development, version, search, and discovery routes', async () => {
  assert.deepEqual(
    await smokeDocsDeployment({ read: fixture(), releasedTag }),
    {
      deepRoute: '/start/when-to-use/',
      releasedTag,
      versionPath: '/v/1.2.3/',
    },
  );
});

test('rejects a root redirect to an old released version', async () => {
  const read = fixture();
  await assert.rejects(
    smokeDocsDeployment({
      read: async (pathname) => pathname === '/'
        ? {
            body: Buffer.from(''),
            location: '/v/1.1.0/',
            status: 302,
          }
        : read(pathname),
      releasedTag,
    }),
    /returned HTTP 302 with Location \/v\/1.1.0\//,
  );
});

test('rejects missing Pagefind and malformed smoke arguments', async () => {
  await assert.rejects(
    smokeDocsDeployment({
      read: fixture({
        '/pagefind/pagefind.js': Buffer.alloc(0),
      }),
      releasedTag,
    }),
    /returned an empty body/,
  );
  assert.throws(
    () => parseSmokeArgs(['--root', 'dist', '--url', origin, '--released-tag', releasedTag]),
    /exactly one/,
  );
});

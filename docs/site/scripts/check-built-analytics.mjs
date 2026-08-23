import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { parse } from 'parse5';

import {
  DOCS_UMAMI_DOMAINS,
  DOCS_UMAMI_SCRIPT_SRC,
  DOCS_UMAMI_WEBSITE_ID,
} from '../src/lib/analytics.mjs';

function attributes(node) {
  return Object.fromEntries((node.attrs ?? []).map(({ name, value }) => [name, value]));
}

function scriptAttributes(node, found = []) {
  if (node.nodeName === 'script') found.push(attributes(node));
  for (const child of node.childNodes ?? []) scriptAttributes(child, found);
  return found;
}

export async function checkBuiltAnalytics(root, { enabled }) {
  const indexPath = resolve(root, 'index.html');
  const document = parse(await readFile(indexPath, 'utf8'));
  const analyticsScripts = scriptAttributes(document).filter(
    (attrs) => attrs.src === DOCS_UMAMI_SCRIPT_SRC || attrs['data-website-id'],
  );

  if (!enabled) {
    assert.deepEqual(
      analyticsScripts,
      [],
      `${indexPath} must not contain analytics outside the canonical released tree`,
    );
    return;
  }

  assert.equal(
    analyticsScripts.length,
    1,
    `${indexPath} must contain exactly one Umami tracker`,
  );
  assert.deepEqual(
    analyticsScripts[0],
    {
      defer: '',
      src: DOCS_UMAMI_SCRIPT_SRC,
      'data-website-id': DOCS_UMAMI_WEBSITE_ID,
      'data-domains': DOCS_UMAMI_DOMAINS,
    },
    `${indexPath} must contain the source-controlled Registry Docs tracker`,
  );
}

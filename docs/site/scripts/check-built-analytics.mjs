import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parse } from 'parse5';

import {
  DOCS_UMAMI_DOMAINS,
  DOCS_UMAMI_SCRIPT_SRC,
  DOCS_UMAMI_WEBSITE_ID,
} from '../src/lib/analytics.mjs';
import { SHARED_TRACKING_BRIDGE_URL } from '../src/lib/tracking-protocol.mjs';

function attributes(node) {
  return Object.fromEntries((node.attrs ?? []).map(({ name, value }) => [name, value]));
}

function scriptAttributes(node, found = []) {
  if (node.nodeName === 'script') found.push(attributes(node));
  for (const child of node.childNodes ?? []) scriptAttributes(child, found);
  return found;
}

function elementAttributes(node, attribute, found = []) {
  const attrs = attributes(node);
  if (attribute in attrs) found.push(attrs);
  for (const child of node.childNodes ?? []) elementAttributes(child, attribute, found);
  return found;
}

function checkPage(html, indexPath, { enabled, sharedTrackingEnabled }) {
  const document = parse(html);
  const analyticsScripts = scriptAttributes(document).filter(
    (attrs) => attrs.src === DOCS_UMAMI_SCRIPT_SRC || attrs['data-website-id'],
  );
  const directMauticScripts = scriptAttributes(document).filter((attrs) =>
    /\/mtc\.js(?:[?#]|$)/.test(attrs.src ?? ''),
  );
  const sharedTrackingControls = elementAttributes(
    document,
    'data-registry-shared-tracking',
  );

  assert.deepEqual(
    directMauticScripts,
    [],
    `${indexPath} must not load Mautic directly`,
  );

  if (enabled) {
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
  } else {
    assert.deepEqual(
      analyticsScripts,
      [],
      `${indexPath} must not contain analytics outside the canonical released tree`,
    );
  }

  if (sharedTrackingEnabled) {
    assert.equal(
      sharedTrackingControls.length,
      1,
      `${indexPath} must contain exactly one shared tracking control`,
    );
    assert.equal(
      sharedTrackingControls[0]['data-shared-tracking-bridge-url'],
      SHARED_TRACKING_BRIDGE_URL,
      `${indexPath} must contain the source-controlled shared tracking bridge`,
    );
  } else {
    assert.deepEqual(
      sharedTrackingControls,
      [],
      `${indexPath} must not contain shared tracking in this build`,
    );
  }
}

export async function checkBuiltAnalytics(root, { enabled, sharedTrackingEnabled = enabled }) {
  const indexPath = resolve(root, 'index.html');
  checkPage(await readFile(indexPath, 'utf8'), indexPath, { enabled, sharedTrackingEnabled });

  const notFoundPath = resolve(root, '404.html');
  let notFound;
  try {
    notFound = await readFile(notFoundPath, 'utf8');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (notFound !== undefined) {
    checkPage(notFound, notFoundPath, { enabled, sharedTrackingEnabled: false });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [root, option, profile] = process.argv.slice(2);
  const profiles = {
    development: { enabled: false, sharedTrackingEnabled: true },
    canonical: { enabled: true, sharedTrackingEnabled: true },
    excluded: { enabled: false, sharedTrackingEnabled: false },
  };
  if (process.argv.length !== 5 || !root || option !== '--profile' || !Object.hasOwn(profiles, profile)) {
    throw new Error('usage: check-built-analytics.mjs <root> --profile development|canonical|excluded');
  }
  await checkBuiltAnalytics(root, profiles[profile]);
}

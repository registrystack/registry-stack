import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

import { buildMauticPageview } from '../src/lib/shared-tracking-client.mjs';
import { docsSharedTrackingEnabled } from '../src/lib/docs-shared-tracking.mjs';

const root = new URL('../', import.meta.url);
const componentUrl = new URL('src/components/RegistryTrackingPreferences.astro', root);
const footerUrl = new URL('src/components/RegistryFooter.astro', root);
const headUrl = new URL('src/components/RegistryHead.astro', root);
const privacyUrl = new URL('src/content/docs/privacy.mdx', root);

test('shared tracking is enabled only for canonical released documentation pages', () => {
  assert.equal(
    docsSharedTrackingEnabled({ isReleasedArchiveBuild: true, base: '/', path: '/' }),
    true,
  );
  assert.equal(
    docsSharedTrackingEnabled({
      isReleasedArchiveBuild: true,
      base: '/',
      path: '/products/base-registry/',
    }),
    true,
  );
  assert.equal(
    docsSharedTrackingEnabled({ isReleasedArchiveBuild: false, base: '/dev/', path: '/' }),
    false,
  );
  assert.equal(
    docsSharedTrackingEnabled({
      isReleasedArchiveBuild: true,
      base: '/v/0.43.0/',
      path: '/',
    }),
    false,
  );
  assert.equal(
    docsSharedTrackingEnabled({ isReleasedArchiveBuild: true, base: '/', path: '/404/' }),
    false,
  );
  assert.equal(
    docsSharedTrackingEnabled({ isReleasedArchiveBuild: true, base: '/', path: '/404' }),
    false,
  );
});

test('page views use public canonical data and only reviewed external campaign labels', () => {
  assert.deepEqual(
    buildMauticPageview({
      canonicalUrl: 'https://docs.registrystack.org/start/concepts/?private=yes#record',
      currentUrl:
        'https://docs.registrystack.org/start/concepts/?utm_source=partner&utm_medium=referral&utm_campaign=registry.review&utm_content=guide&utm_term=records&search=person%40example.org',
      pageTitle: '  How the products   fit together  ',
      referrer: 'https://partner.example.org/report/?person=someone#private',
    }),
    {
      page_url: 'https://docs.registrystack.org/start/concepts/',
      page_title: 'How the products fit together',
      page_referrer: 'https://partner.example.org',
      utm_source: 'partner',
      utm_medium: 'referral',
      utm_campaign: 'registry.review',
      utm_content: 'guide',
      utm_term: 'records',
    },
  );

  assert.deepEqual(
    buildMauticPageview({
      canonicalUrl: 'https://docs.registrystack.org/start/concepts/',
      currentUrl:
        'https://docs.registrystack.org/start/concepts/?utm_source=registrystack&utm_medium=site&utm_campaign=cross_site&utm_content=%2Fpricing%2F',
      pageTitle: 'How the products fit together',
      referrer: 'https://registrystack.org/pricing/?email=person%40example.org',
    }),
    {
      page_url: 'https://docs.registrystack.org/start/concepts/',
      page_title: 'How the products fit together',
      page_referrer: 'https://registrystack.org',
    },
  );
});

test('tracking controls use the shared bridge and remain available after failure', async () => {
  const [component, footer, head, privacy] = await Promise.all([
    readFile(componentUrl, 'utf8'),
    readFile(footerUrl, 'utf8'),
    readFile(headUrl, 'utf8'),
    readFile(privacyUrl, 'utf8'),
  ]);

  assert.match(component, /SHARED_TRACKING_BRIDGE_URL/);
  assert.match(component, /createSharedTrackingClient/);
  assert.match(component, /buildMauticPageview/);
  assert.match(component, /trackingDeniedByBrowser/);
  assert.match(component, /new URL\(window\.location\.pathname, canonicalOrigin\)/);
  assert.match(component, /Accept optional cookies/);
  assert.match(component, /Reject optional cookies/);
  assert.match(component, /main Registry Stack website and this\s+documentation/i);
  assert.match(component, /data-tracking-error[^>]*role="alert"/);
  assert.match(component, /client\.pageview\(pageview\)/);
  assert.match(component, /let sentGeneration: string \| null = null/);
  assert.match(component, /let pendingGeneration: string \| null = null/);
  assert.match(component, /state\.generation === sentGeneration/);
  assert.match(component, /state\.generation === pendingGeneration/);
  assert.match(component, /sentGeneration = state\.generation/);
  assert.match(component, /currentState\.generation === state\.generation/);
  assert.match(component, /addEventListener\('pagehide', \(event\) => \{/);
  assert.match(component, /if \(!event\.persisted\) trackingClient\.close\(\)/);
  assert.doesNotMatch(component, /location\.reload/);
  assert.doesNotMatch(component, /mautic_device_id|mtc_id|\/mtc\.js/);

  assert.match(footer, /<RegistryTrackingPreferences/);
  assert.match(footer, /canonicalOrigin=\{canonicalOrigin\}/);
  assert.match(footer, /route\.entry\.id === '404'/);
  assert.match(footer, /route\.entry\.id\.endsWith\('\/404'\)/);
  assert.match(footer, /path: '\/'/);
  assert.match(footer, /data-tracking-preferences-open/);
  assert.match(footer, /data-tracking-preferences-open hidden/);
  assert.match(footer, />\s*Tracking preferences\s*</);
  assert.match(footer, /docsSharedTrackingEnabled/);

  assert.doesNotMatch(
    head,
    /targetSite === 'marketing' \|\| targetSite === 'lab'/,
  );
  assert.match(head, /targetSite === 'lab'/);
  assert.match(head, /window\.umami\?\.track/);

  assert.match(privacy, /main Registry Stack website and Registry\s+Docs/i);
  assert.match(privacy, /tracking bridge/i);
  assert.match(privacy, /six months/i);
  assert.match(privacy, /Do Not Track and Global Privacy Control/i);
  assert.match(privacy, /\/dev\/[\s\S]*\/v\/<version>\/[\s\S]*do not load/i);
});

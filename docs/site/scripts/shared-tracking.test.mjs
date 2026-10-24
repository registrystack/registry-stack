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

test('shared tracking is enabled for released-root and current public development pages', () => {
  for (const build of [
    { isReleasedArchiveBuild: true, base: '/' },
    { isCurrentDocsetBuild: true, base: '/dev/' },
  ]) {
    for (const path of ['/', '/products/base-registry/']) {
      assert.equal(docsSharedTrackingEnabled({ ...build, path }), true);
    }
    for (const path of ['/404', '/404/']) {
      assert.equal(docsSharedTrackingEnabled({ ...build, path }), false);
    }
  }
});

test('local, historical and arbitrary-base builds do not offer shared tracking', () => {
  for (const build of [
    { isCurrentDocsetBuild: true, base: '/' },
    { isReleasedArchiveBuild: false, base: '/dev/' },
    { isReleasedArchiveBuild: true, base: '/dev/' },
    { isCurrentDocsetBuild: true, base: '/preview/' },
    { isReleasedArchiveBuild: true, base: '/v/0.43.0/' },
    { isCurrentDocsetBuild: true, base: '/v/0.43.0/' },
  ]) {
    assert.equal(docsSharedTrackingEnabled({ ...build, path: '/' }), false);
  }
});

test('development page views retain the public development path without query or fragment data', () => {
  assert.deepEqual(
    buildMauticPageview({
      canonicalUrl: 'https://docs.registrystack.org/dev/start/concepts/?private=yes#record',
      currentUrl: 'https://docs.registrystack.org/dev/start/concepts/?email=person%40example.org#record',
      pageTitle: 'How the products fit together',
      referrer: 'https://registrystack.org/starters/?email=person%40example.org',
    }),
    {
      page_url: 'https://docs.registrystack.org/dev/start/concepts/',
      page_title: 'How the products fit together',
      page_referrer: 'https://registrystack.org',
    },
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
  assert.match(component, /href=\{privacyUrl\}/);
  assert.doesNotMatch(component, /href="\/privacy\/"/);
  assert.doesNotMatch(component, /client\.associate/);
  assert.match(component, /main Registry Stack website and this\s+documentation/i);
  assert.match(component, /data-tracking-error[^>]*role="alert"/);
  assert.match(component, /client\.pageview\(pageview\)/);
  assert.match(component, /addEventListener\('pagehide', \(event\) => \{/);
  assert.match(component, /if \(!event\.persisted\) trackingClient\.close\(\)/);
  assert.doesNotMatch(component, /location\.reload/);
  assert.doesNotMatch(component, /mautic_device_id|mtc_id|\/mtc\.js/);

  assert.match(footer, /<RegistryTrackingPreferences/);
  assert.match(footer, /canonicalOrigin=\{canonicalOrigin\}/);
  assert.match(footer, /privacyUrl=\{`\$\{base\}privacy\/`\}/);
  assert.match(footer, /isCurrentDocsetBuild/);
  assert.match(footer, /route\.entry\?\.id === '404'/);
  assert.match(footer, /route\.entry\?\.id\.endsWith\('\/404'\)/);
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
  assert.match(privacy, /\/dev\/[\s\S]*\/v\/<version>\/[\s\S]*do not load Umami/i);
  assert.match(privacy, /optional tracking is available on[\s\S]*\/dev\//i);
  assert.match(privacy, /versioned archives and error pages do not offer optional tracking/i);
  assert.match(privacy, /does not send[\s\S]*marketing email/i);
});

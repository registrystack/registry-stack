import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';
import YAML from 'yaml';
import {
  buildNotaryRetirementRedirects,
  RETIRED_NOTARY_API_OPERATIONS,
} from '../src/lib/notary-retirement-redirects.mjs';

const siteRoot = resolve(import.meta.dirname, '..');
const configSource = readFileSync(resolve(siteRoot, 'astro.config.mjs'), 'utf8');
const fetchOpenapiSource = readFileSync(resolve(siteRoot, 'scripts/fetch-openapi.mjs'), 'utf8');
const generatedApiBasesSource = readFileSync(
  resolve(siteRoot, 'src/lib/generated-api-bases.mjs'),
  'utf8',
);
const repoDocs = YAML.parse(readFileSync(resolve(siteRoot, 'src/data/repo-docs.yaml'), 'utf8'));
const docsets = YAML.parse(readFileSync(resolve(siteRoot, 'src/data/docsets.yaml'), 'utf8'));
const openapiSources = YAML.parse(
  readFileSync(resolve(siteRoot, 'src/data/openapi-sources.yaml'), 'utf8'),
);
const projects = YAML.parse(readFileSync(resolve(siteRoot, 'src/data/projects.yaml'), 'utf8'));
const contracts = YAML.parse(readFileSync(resolve(siteRoot, 'src/data/contracts.yaml'), 'utf8'));
const redirects = buildNotaryRetirementRedirects((target) => target);

const retirementRoute = '/decisions/notary-retirement-2026-08-03/';
const authoredNotaryPages = [
  'explanation/evidence-issuance.mdx',
  'reference/apis/registry-notary.mdx',
  'spec/rs-dm-claim.mdx',
  'spec/rs-pr-notary.mdx',
  'tutorials/move-notary-to-production-signing.mdx',
  'tutorials/verify-claim-registry-api.mdx',
];
const mirroredNotaryRoutes = [
  '/products/registry-notary/',
  '/products/registry-notary/architecture-overview/',
  '/products/registry-notary/client-sdk-guide/',
  '/products/registry-notary/identity-and-record-matching/',
  '/products/registry-notary/source-claim-modeling-guide/',
  '/products/registry-notary/operator-config-reference/',
  '/products/registry-notary/postgresql-state-operations/',
  '/products/registry-notary/credential-lifecycle-status/',
  '/products/registry-notary/credential-issuance-migration/',
  '/products/registry-notary/signing-key-provider/',
  '/products/registry-notary/sd-jwt-vc-conformance-profile/',
  '/products/registry-notary/notary-capability-matrix/',
  '/products/registry-notary/notary-scenario-patterns/',
  '/products/registry-notary/federated-evaluation-operator-guide/',
  '/products/registry-notary/subject-access-operator-guide/',
  '/products/registry-notary/deployment-hardening-runbook/',
  '/products/registry-notary/api-reference/',
  '/products/registry-notary/oid4vci-wallet-interop/',
  '/products/registry-notary/release-notes/',
];
const authoredNotaryRoutes = [
  '/explanation/evidence-issuance/',
  '/reference/apis/registry-notary/',
  '/reference/apis/notary/',
  '/spec/rs-dm-claim/',
  '/spec/rs-pr-notary/',
  '/tutorials/move-notary-to-production-signing/',
  '/tutorials/verify-claim-registry-api/',
];

test('removes the current Notary docs sources and generated product plumbing', () => {
  assert.equal(repoDocs.repos['registry-notary'], undefined);
  const currentDocset = docsets.docsets.find((docset) => docset.id === docsets.current);
  assert.equal(currentDocset.products['registry-notary'], undefined);
  const historicalNotaryDocsets = docsets.docsets.filter(
    (entry) =>
      entry.status === 'archived' &&
      !['v0.17.0', 'v0.18.0', 'v0.20.0', 'v0.20.1', 'v0.21.0', 'v0.22.0', 'v0.23.0', 'v0.24.0', 'v0.25.0', 'v0.26.0', 'v0.26.1'].includes(entry.id),
  );
  for (const docset of historicalNotaryDocsets) {
    assert.ok(docset.products['registry-notary'], `${docset.id} lost its historical Notary pin`);
  }
  const v017 = docsets.docsets.find((entry) => entry.id === 'v0.17.0');
  assert.equal(v017.products['registry-notary'], undefined);
  const v018 = docsets.docsets.find((entry) => entry.id === 'v0.18.0');
  assert.equal(v018.products['registry-notary'], undefined);
  const v020 = docsets.docsets.find((entry) => entry.id === 'v0.20.0');
  assert.equal(v020.products['registry-notary'], undefined);
  const v0201 = docsets.docsets.find((entry) => entry.id === 'v0.20.1');
  assert.equal(v0201.products['registry-notary'], undefined);
  const v021 = docsets.docsets.find((entry) => entry.id === 'v0.21.0');
  assert.equal(v021.products['registry-notary'], undefined);
  assert.equal(openapiSources.some((source) => source.owner === 'registry-notary'), false);
  assert.equal(projects.some((project) => project.id === 'registry-notary'), false);
  assert.equal(contracts.some((contract) => contract.owner === 'registry-notary'), false);
  assert.doesNotMatch(fetchOpenapiSource, /'registry-notary':/);
  assert.doesNotMatch(generatedApiBasesSource, /reference\/apis\/notary/);
});

test('removes authored Notary pages but publishes the retirement decision', () => {
  for (const page of authoredNotaryPages) {
    assert.equal(existsSync(resolve(siteRoot, 'src/content/docs', page)), false, page);
  }

  const retirement = readFileSync(
    resolve(siteRoot, 'src/content/docs/decisions/notary-retirement-2026-08-03.mdx'),
    'utf8',
  );
  assert.match(retirement, /^status: current$/m);
  assert.doesNotMatch(retirement, /^draft: true$/m);
});

test('redirects every removed current Notary route to Evidence Gateway or the retirement decision', () => {
  const allowedTarget = /^(?:\/decisions\/notary-retirement-2026-08-03\/|\/(?:start\/evidence-quickstart|configure\/evidence|reference\/apis\/(?:evidence|registry-evidence)|tutorials\/move-evidence-to-production-signing)\/)$/;

  for (const route of [...authoredNotaryRoutes, ...mirroredNotaryRoutes]) {
    const target = redirects[route];
    assert.ok(target, `${route} has no redirect`);
    assert.match(target, allowedTarget, `${route} redirects to unsupported target ${target}`);
    assert.equal(redirects[`${route.slice(0, -1)}.md`], retirementRoute);
  }

  assert.equal(RETIRED_NOTARY_API_OPERATIONS.length, 27);
  for (const operation of RETIRED_NOTARY_API_OPERATIONS) {
    assert.equal(
      redirects[`/reference/apis/notary/operations/${operation}/`],
      retirementRoute,
    );
  }
  assert.match(configSource, /\.\.\.buildNotaryRetirementRedirects\(currentDocsetRedirect\)/);
});

test('presents the maintained services in site descriptions without restoring Notary navigation', () => {
  assert.match(configSource, /description: 'Documentation for Registry Stack: [^']*Registry Relay[^']*Evidence Gateway[^']*Base Registry Engine/);
  assert.doesNotMatch(configSource, /description: '[^']*Registry Notary/);
  assert.doesNotMatch(configSource, /label: 'Notary \(narrative\)'/);
  assert.doesNotMatch(configSource, /label: 'Registry Notary'/);
  assert.doesNotMatch(configSource, /label: 'Notary API operations'/);
});

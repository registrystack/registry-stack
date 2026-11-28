import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { test } from 'node:test';
import YAML from 'yaml';

const siteRoot = resolve(import.meta.dirname, '..');
const docsRoot = resolve(siteRoot, 'src/content/docs');

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? walk(path) : [path];
  });
}

function publishedHandAuthoredDocs() {
  return walk(docsRoot)
    .filter((path) => path.endsWith('.mdx'))
    .filter((path) => !path.includes(`${join('content', 'docs', 'products')}/`))
    .filter((path) => !path.endsWith(`${join('docs', 'changelog.mdx')}`))
    .map((path) => ({ path, source: readFileSync(path, 'utf8') }))
    .filter(({ source }) => !/^draft: true$/m.test(source) && !/^status: historical$/m.test(source));
}

function visibleProse(source) {
  return source
    .replace(/\{\/\*[\s\S]*?\*\/\}/g, '')
    .replace(/```[\s\S]*?```/g, '')
    .replace(/~~~[\s\S]*?~~~/g, '')
    .replace(/`[^`]*`/g, '');
}

test('uses Registry Evidence as the public product display name', () => {
  const projects = YAML.parse(readFileSync(resolve(siteRoot, 'src/data/projects.yaml'), 'utf8'));
  assert.equal(projects.find((project) => project.id === 'registry-evidence')?.name, 'Registry Evidence');

  const styleGuide = readFileSync(resolve(siteRoot, 'docs/style-guide.md'), 'utf8');
  assert.match(styleGuide, /formal product names.*Registry Evidence/i);

  const staleProductName = /\bEvidence [Gg]ateway\b/;
  for (const { path, source } of publishedHandAuthoredDocs()) {
    assert.doesNotMatch(
      visibleProse(source),
      staleProductName,
      `${relative(siteRoot, path)} uses an obsolete public product name`,
    );
  }
});

test('keeps authoritative sources outside the Registry Evidence product boundary', () => {
  const architecture = readFileSync(
    resolve(docsRoot, 'explanation/architecture.mdx'),
    'utf8',
  );
  assert.match(architecture, /fixed authoritative source remains outside the Registry Evidence product boundary/);
  assert.match(architecture, /authenticated Base\s+Registry Engine route/);

  const boundaryViolations = [
    /Registry Evidence (?:requires|depends on) Registry Relay/i,
    /Registry Evidence inherits Relay authorization/i,
    /Registry Relay is part of the Registry Evidence product boundary/i,
  ];

  for (const { path, source } of publishedHandAuthoredDocs()) {
    const prose = visibleProse(source);
    for (const pattern of boundaryViolations) {
      assert.doesNotMatch(
        prose,
        pattern,
        `${relative(siteRoot, path)} merges the Relay and Registry Evidence product boundaries`,
      );
    }
  }
});

// The identifier survives in the manifest schema as a retained name. The Relay
// policy decision point that once enforced it is gone, so a page that prints the
// identifier must say so rather than let a reader attach it to Registry Evidence.
//
// The Registry Manifest reference is the page that documents the value. It is
// copied into the site from the product's own documentation, and it is long, so
// the label must sit on the line that prints the identifier.
test('labels the old evidence-gateway PDP id as a superseded Relay identifier', () => {
  const identifier = 'registry-evidence-gateway-pdp/v1';
  const manifestReference = resolve(siteRoot, '../../products/manifest/docs/reference.md');
  const referenceLines = readFileSync(manifestReference, 'utf8')
    .split('\n')
    .filter((line) => line.includes(identifier));
  assert.ok(referenceLines.length > 0, 'expected the Manifest reference to document the identifier');

  const printed = [
    ...publishedHandAuthoredDocs()
      .filter(({ source }) => source.includes(identifier))
      .map(({ path, source }) => ({ where: relative(siteRoot, path), text: source })),
    ...referenceLines.map((line) => ({ where: 'products/manifest/docs/reference.md', text: line })),
  ];

  for (const { where, text } of printed) {
    assert.match(text, /Relay/i, `${where} must identify the owner as Relay`);
    assert.match(
      text,
      /\b(?:legacy|retired)\b/i,
      `${where} must mark the identifier legacy or its runtime retired`,
    );
  }
});

// The delivery front end's metrics table is a hand-written catalogue, so it is
// held to the metric families the service itself renders through the shared
// exposition writer.
test('names exactly the metrics the OID4VCI delivery front end renders', () => {
  const observability = readFileSync(
    resolve(siteRoot, '../../crates/registry-evidence-oid4vci/src/observability.rs'),
    'utf8',
  );
  const rendered = new Set([...observability.matchAll(/"(evidence_oid4vci_\w+)"/g)].map((match) => match[1]));
  assert.ok(rendered.size > 0, 'expected observability.rs to name metric families');
  // The shared refusal recorder renders `<prefix>_request_refusals_total` for
  // the prefix the service gives it.
  for (const match of observability.matchAll(/RefusalRecorder::new\("(evidence_oid4vci)"\)/g)) {
    rendered.add(`${match[1]}_request_refusals_total`);
  }

  const page = readFileSync(resolve(docsRoot, 'configure/evidence-oid4vci.mdx'), 'utf8');
  const metricsSection = page.split(/^## Metrics$/m)[1]?.split(/^## /m)[0] ?? '';
  const documented = new Set([...metricsSection.matchAll(/^\| `(evidence_oid4vci_\w+)` \|/gm)].map((match) => match[1]));

  assert.deepEqual([...documented].sort(), [...rendered].sort());
});

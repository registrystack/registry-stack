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
test('labels the old evidence-gateway PDP id as a superseded Relay identifier', () => {
  const paths = publishedHandAuthoredDocs()
    .filter(({ source }) => source.includes('registry-evidence-gateway-pdp/v1'));
  assert.ok(paths.length > 0, 'expected the superseded Relay identifier to remain documented');

  for (const { path, source } of paths) {
    assert.match(source, /Relay/i, `${relative(siteRoot, path)} must identify the owner as Relay`);
    assert.match(
      source,
      /\b(?:legacy|retired)\b/i,
      `${relative(siteRoot, path)} must mark the identifier legacy or its runtime retired`,
    );
  }
});

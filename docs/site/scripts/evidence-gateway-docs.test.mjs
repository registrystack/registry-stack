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

test('uses Evidence Gateway as the public product display name', () => {
  const projects = YAML.parse(readFileSync(resolve(siteRoot, 'src/data/projects.yaml'), 'utf8'));
  assert.equal(projects.find((project) => project.id === 'registry-evidence')?.name, 'Evidence Gateway');

  const styleGuide = readFileSync(resolve(siteRoot, 'docs/style-guide.md'), 'utf8');
  assert.match(styleGuide, /formal product names.*Evidence Gateway/i);

  const staleProductName = /\b(?:Registry Evidence|Evidence (?:API|binary|product|runtime|server|service|toolset|Version))\b/;
  for (const { path, source } of publishedHandAuthoredDocs()) {
    assert.doesNotMatch(
      visibleProse(source),
      staleProductName,
      `${relative(siteRoot, path)} uses an obsolete public product name`,
    );
  }
});

test('keeps Relay outside the Evidence Gateway product boundary', () => {
  const architecture = readFileSync(
    resolve(docsRoot, 'explanation/architecture.mdx'),
    'utf8',
  );
  assert.match(architecture, /Relay-protected API as a fixed HTTP source/);
  // Base Registry Engine is the second product a deployment may put behind the
  // same source contract, and it sits outside the Evidence Gateway boundary for
  // the same reason Relay does.
  assert.match(architecture, /authenticated Base\s+Registry Engine route/);
  assert.match(architecture, /neither\s+becomes part of the Evidence Gateway product boundary/);

  const boundaryViolations = [
    /Evidence Gateway (?:requires|depends on) Registry Relay/i,
    /Evidence Gateway inherits Relay authorization/i,
    /Registry Relay is part of the Evidence Gateway product boundary/i,
  ];

  for (const { path, source } of publishedHandAuthoredDocs()) {
    const prose = visibleProse(source);
    for (const pattern of boundaryViolations) {
      assert.doesNotMatch(
        prose,
        pattern,
        `${relative(siteRoot, path)} merges the Relay and Evidence Gateway product boundaries`,
      );
    }
  }
});

// The identifier survives in the manifest schema as a retained name. The Relay
// policy decision point that once enforced it is gone, so a page that prints the
// identifier must say so rather than let a reader attach it to Evidence Gateway.
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

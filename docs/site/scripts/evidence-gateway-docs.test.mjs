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

test('does not publish Evidence Gateway over Relay as a current request path', () => {
  const staleComposition = [
    /Evidence Gateway (?:can |may |will )?(?:read|use|consume|treat)[^.\n]{0,80}Relay/i,
    /Evidence Gateway[^.\n]{0,80} over (?:a |the )?Relay/i,
    /Relay-protected[^.\n]{0,120}Evidence Gateway/i,
    /Evidence Gateway[^.\n]{0,120}Relay-protected/i,
    /Relay API as (?:an? )?(?:ordinary )?fixed HTTP source/i,
  ];

  for (const { path, source } of publishedHandAuthoredDocs()) {
    const prose = visibleProse(source);
    for (const pattern of staleComposition) {
      assert.doesNotMatch(
        prose,
        pattern,
        `${relative(siteRoot, path)} republishes the obsolete Relay composition`,
      );
    }
  }
});

test('labels the old evidence-gateway PDP id as a legacy Relay identifier', () => {
  const paths = publishedHandAuthoredDocs()
    .filter(({ source }) => source.includes('registry-evidence-gateway-pdp/v1'));
  assert.ok(paths.length > 0, 'expected the legacy Relay identifier to remain documented');

  for (const { path, source } of paths) {
    assert.match(source, /Relay/i, `${relative(siteRoot, path)} must identify the owner as Relay`);
    assert.match(source, /legacy/i, `${relative(siteRoot, path)} must mark the identifier legacy`);
  }
});

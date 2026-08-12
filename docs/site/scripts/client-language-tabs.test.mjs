import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { test } from 'node:test';

const siteRoot = resolve(import.meta.dirname, '..');
const docsRoot = resolve(siteRoot, 'src/content/docs');
const componentPath = resolve(
  siteRoot,
  'src/components/ClientLanguageTabs.astro',
);
const expectedSlots = ['curl', 'python', 'node'];

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? walk(path) : [path];
  });
}

function validateClientLanguageTabs(source, path = 'fixture.mdx') {
  const authoredSource = source
    .replace(/```[\s\S]*?```/g, '')
    .replace(/~~~[\s\S]*?~~~/g, '')
    .replace(/\{\/\*[\s\S]*?\*\/\}/g, '');
  const rawClientTabs = [
    ...authoredSource.matchAll(/<Tabs\b[^>]*>([\s\S]*?)<\/Tabs>/g),
  ].filter(([, body]) => (
    /<TabItem\b[^>]*\blabel\s*=\s*['"](?:curl|Python|Node\.js)['"]/.test(body)
  ));
  assert.equal(
    rawClientTabs.length,
    0,
    `${path} must use ClientLanguageTabs so labels and the client-language sync key cannot drift`,
  );

  const usesComponent = /<ClientLanguageTabs\b/.test(authoredSource);
  if (!usesComponent) return;

  assert.match(
    authoredSource,
    /import\s+ClientLanguageTabs\s+from\s+['"][^'"]*\/ClientLanguageTabs\.astro['"];/,
    `${path} must import the shared ClientLanguageTabs component`,
  );

  const blocks = [
    ...authoredSource.matchAll(
      /<ClientLanguageTabs\b([^>]*)>([\s\S]*?)<\/ClientLanguageTabs>/g,
    ),
  ];
  const openingTags = [
    ...authoredSource.matchAll(/<ClientLanguageTabs\b([^>]*)>/g),
  ];
  assert.equal(
    blocks.length,
    openingTags.length,
    `${path} has an unclosed or self-closing ClientLanguageTabs component`,
  );

  for (const [, attributes, body] of blocks) {
    assert.doesNotMatch(
      attributes,
      /\bsyncKey\s*=/,
      `${path} must use the component-owned client-language sync key`,
    );

    const slots = [
      ...body.matchAll(
        /<Fragment\b[^>]*\bslot\s*=\s*['"]([^'"]+)['"][^>]*>/g,
      ),
    ].map((match) => match[1]);
    assert.deepEqual(
      slots,
      expectedSlots,
      `${path} must declare curl, python, and node slots once each and in that order`,
    );
  }
}

test('component fixes the labels, order, sync key, and URL client values', () => {
  const source = readFileSync(componentPath, 'utf8');
  const labels = [...source.matchAll(/<TabItem\s+label="([^"]+)">/g)].map(
    (match) => match[1],
  );
  const renderedSlots = [...source.matchAll(/<slot name="([^"]+)" \/>/g)].map(
    (match) => match[1],
  );

  assert.match(
    source,
    /import \{ TabItem, Tabs \} from '@astrojs\/starlight\/components';/,
  );
  assert.deepEqual(labels, ['curl', 'Python', 'Node.js']);
  assert.deepEqual(renderedSlots, expectedSlots);
  assert.match(source, /<Tabs syncKey="client-language">/);
  assert.match(
    source,
    /const requiredSlots = \['curl', 'python', 'node'\] as const;/,
  );
  assert.match(
    source,
    /curl: 'curl',[\s\S]*python: 'Python',[\s\S]*node: 'Node\.js',/,
  );
  assert.match(source, /new URL\(window\.location\.href\)\.searchParams\.get\('client'\)/);
  assert.match(source, /Object\.hasOwn\(clients, client\)/);
  assert.match(source, /starlight-synced-tabs__client-language/);
});

test('accepts the shared client tab authoring contract', () => {
  assert.doesNotThrow(() => validateClientLanguageTabs(`
    import ClientLanguageTabs from '../../components/ClientLanguageTabs.astro';
    <ClientLanguageTabs>
      <Fragment slot="curl">curl example</Fragment>
      <Fragment slot="python">Python example</Fragment>
      <Fragment slot="node">Node.js example</Fragment>
    </ClientLanguageTabs>
  `));
});

test('rejects missing, duplicate, and misordered client slots', () => {
  const cases = [
    ['missing', ['curl', 'python']],
    ['duplicate', ['curl', 'python', 'python', 'node']],
    ['misordered', ['python', 'curl', 'node']],
  ];

  for (const [name, slots] of cases) {
    const fragments = slots
      .map((slot) => `<Fragment slot="${slot}">${slot}</Fragment>`)
      .join('\n');
    assert.throws(
      () => validateClientLanguageTabs(`
        import ClientLanguageTabs from '../../components/ClientLanguageTabs.astro';
        <ClientLanguageTabs>${fragments}</ClientLanguageTabs>
      `, `${name}.mdx`),
      /must declare curl, python, and node slots once each and in that order/,
    );
  }
});

test('rejects a sync key supplied by an author', () => {
  assert.throws(
    () => validateClientLanguageTabs(`
      import ClientLanguageTabs from '../../components/ClientLanguageTabs.astro';
      <ClientLanguageTabs syncKey="different-client-key">
        <Fragment slot="curl">curl</Fragment>
        <Fragment slot="python">Python</Fragment>
        <Fragment slot="node">Node.js</Fragment>
      </ClientLanguageTabs>
    `, 'wrong-sync-key.mdx'),
    /component-owned client-language sync key/,
  );
});

test('rejects raw client tabs with an author-supplied sync key', () => {
  assert.throws(
    () => validateClientLanguageTabs(`
      import { TabItem, Tabs } from '@astrojs/starlight/components';
      <Tabs syncKey="wrong-client-key">
        <TabItem label="curl">curl</TabItem>
        <TabItem label="Python">Python</TabItem>
        <TabItem label="Node.js">Node.js</TabItem>
      </Tabs>
    `, 'raw-tabs.mdx'),
    /must use ClientLanguageTabs so labels and the client-language sync key cannot drift/,
  );
});

test('all authored client language tabs follow the shared contract', () => {
  const docs = walk(docsRoot).filter((path) => path.endsWith('.mdx'));
  for (const path of docs) {
    validateClientLanguageTabs(
      readFileSync(path, 'utf8'),
      relative(siteRoot, path),
    );
  }
});

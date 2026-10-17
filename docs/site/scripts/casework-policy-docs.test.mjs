import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

// Holds every YAML fence on the Casework authoring page to the tracked product
// file it was copied from, so the page's YAML cannot drift from the product.
// A fence names its source in `title`: a tracked file under
// products/casework/examples/, or a file of the tutorial project, which
// `caseworkctl init --template standalone-decision` writes from the
// standalone-decision example and from the template constants in
// crates/registry-caseworkctl/src/project.rs.

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../..');
const pagePath = resolve(here, '../src/content/docs/configure/casework.mdx');
const page = readFileSync(pagePath, 'utf8');
const examples = 'products/casework/examples';
const tutorialProject = 'tutorial-work/casework/';

// The init template constants for the standalone-decision project, by the
// project-relative path init writes each one to.
const templates = (() => {
  const source = readFileSync(resolve(repoRoot, 'crates/registry-caseworkctl/src/project.rs'), 'utf8');
  const constant = (name) => {
    const match = source.match(new RegExp(`const ${name}: &str = r#"([\\s\\S]*?)"#;`, 'u'));
    assert.ok(match, `crates/registry-caseworkctl/src/project.rs has no ${name} template`);
    return match[1];
  };
  return new Map([
    ['casework.yaml', constant('STANDALONE_YAML')],
    ['dev-clients.yaml', constant('STANDALONE_DEV_CLIENTS')],
    ['fixtures/standalone-decision.yaml', constant('STANDALONE_FIXTURE')],
  ]);
})();

function yamlFences(text) {
  const fences = [];
  const pattern = /^```yaml([^\n]*)\n([\s\S]*?)\n```$/gmu;
  for (const match of text.matchAll(pattern)) {
    const title = match[1].match(/title="([^"]+)"/u)?.[1];
    fences.push({ info: match[1].trim(), title, body: match[2] });
  }
  return fences;
}

// The tracked sources a fence is held to: the example file it names, or, for
// a tutorial project file, both the standalone-decision example and the init
// template that writes it.
function sourcesFor(title) {
  if (title.startsWith(`${examples}/`)) {
    return [{ name: title, text: readFileSync(resolve(repoRoot, title), 'utf8') }];
  }
  if (title.startsWith(tutorialProject)) {
    const relative = title.slice(tutorialProject.length);
    const tracked = `${examples}/standalone-decision/${relative}`;
    const template = templates.get(relative);
    assert.ok(template !== undefined, `${title} is not a file the standalone-decision template writes`);
    return [
      { name: tracked, text: readFileSync(resolve(repoRoot, tracked), 'utf8') },
      { name: `the init template for ${relative}`, text: template },
    ];
  }
  assert.fail(`YAML fence titled ${title} names no tracked Casework source`);
}

// The extra indentation `line` carries beyond `expected`, or undefined when
// they differ in more than indentation.
function extraIndent(line, expected) {
  if (expected.trim() === '') return line.trim() === '' ? '' : undefined;
  if (!line.endsWith(expected)) return undefined;
  const indent = line.slice(0, line.length - expected.length);
  return indent.trim() === '' ? indent : undefined;
}

// Whether `excerpt` equals, or is a run of consecutive lines of, `source`,
// at any one extra indentation.
function isLineSubset(excerpt, source) {
  const wanted = excerpt.split('\n');
  const lines = source.split('\n');
  for (let start = 0; start + wanted.length <= lines.length; start += 1) {
    let indent;
    let matched = true;
    for (let k = 0; k < wanted.length; k += 1) {
      const extra = extraIndent(lines[start + k], wanted[k]);
      if (extra === undefined || (wanted[k].trim() !== '' && indent !== undefined && extra !== indent)) {
        matched = false;
        break;
      }
      if (wanted[k].trim() !== '') indent = extra;
    }
    if (matched) return true;
  }
  return false;
}

const fences = yamlFences(page);

test('the line-subset rule refuses a changed, reordered or unanchored excerpt', () => {
  const source = 'a:\n  b: 1\n  c: 2\nd: 3';
  assert.ok(isLineSubset(source, source));
  assert.ok(isLineSubset('b: 1\nc: 2', source));
  assert.ok(!isLineSubset('b: 1\nc: 3', source));
  assert.ok(!isLineSubset('c: 2\nb: 1', source));
  assert.ok(!isLineSubset('b: 1\nd: 3', source));
});

test('every YAML fence on the page names its tracked source', () => {
  assert.ok(fences.length > 0, 'the page has no YAML fences');
  for (const fence of fences) {
    assert.ok(fence.title, `a YAML fence has no title naming its source: ${fence.body.split('\n')[0]}`);
    const excerpt = fence.info.match(/test-excerpt="([^"]+)"/u)?.[1];
    if (excerpt !== undefined) {
      assert.equal(excerpt, fence.title, `${fence.title} replays against a different file than it names`);
    }
  }
});

test('every YAML fence equals, or is a line subset of, each tracked source it names', () => {
  for (const fence of fences) {
    for (const source of sourcesFor(fence.title)) {
      assert.ok(
        isLineSubset(fence.body, source.text),
        `the fence titled ${fence.title} is not a run of lines of ${source.name}:\n${fence.body}`,
      );
    }
  }
});

test('the page copies from the standalone, canonical-review and multi-stage examples', () => {
  const titles = new Set(fences.map((fence) => fence.title));
  for (const required of [
    'tutorial-work/casework/casework.yaml',
    'tutorial-work/casework/dev-clients.yaml',
    'tutorial-work/casework/fixtures/standalone-decision.yaml',
    `${examples}/canonical-review/casework.yaml`,
    `${examples}/multi-stage-routing-clocks/casework.yaml`,
    `${examples}/multi-stage-routing-clocks/holiday-sets/office-holidays-7.yaml`,
  ]) {
    assert.ok(titles.has(required), `the page shows nothing copied from ${required}`);
  }
});

test('the excerpted keys exist in the generated project schema', () => {
  const schema = JSON.parse(
    readFileSync(resolve(repoRoot, 'products/casework/generated/project/project.schema.json'), 'utf8'),
  );
  for (const fence of fences.filter((candidate) => candidate.title.endsWith('/casework.yaml'))) {
    const lines = fence.body.split('\n');
    if (/^\s/u.test(lines[0])) continue;
    for (const key of Object.keys(parse(fence.body))) {
      assert.ok(schema.properties[key], `${fence.title} shows top-level key ${key}, which the project schema does not declare`);
    }
  }
});

test('the page renders the authoring contracts and leaves the runtime contract to operate', () => {
  const render = page.match(/<ConfigurationReference contracts=\{([^\n]*)\} prefix="casework" \/>/u);
  assert.ok(render, 'the page does not render the Casework configuration reference');
  for (const id of ['project', 'fixture', 'dev-clients', 'holiday-set']) {
    assert.ok(render[1].includes(`'${id}'`), `the rendered reference omits the ${id} contract`);
  }
  assert.ok(!render[1].includes("'runtime'"), 'the runtime contract belongs to operate/casework');
});

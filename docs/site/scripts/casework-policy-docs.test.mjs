import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

// Holds every YAML fence on the Casework authoring page to the tracked product
// file it was copied from, so the page's YAML cannot drift from the product.
// A fence names its source in `title`: a tracked file under
// products/casework/examples/, or a file of the tutorial project, relative to
// the project directory the page works in. An excerpted project file is held
// to what `caseworkctl init --template standalone-decision` writes it from:
// the standalone-decision example and the template constants in
// crates/registry-caseworkctl/src/project.rs. A file the reader writes into
// the project (`test-file`, `test-append`) is proved by the replay, which
// checks the project after it, and is held here to the example it was copied
// from when `copiedFiles` names one.

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../..');
const pagePath = resolve(here, '../src/content/docs/configure/casework.mdx');
const page = readFileSync(pagePath, 'utf8');
const examples = 'products/casework/examples';
const tutorialProject = 'tutorial-work/casework/';
const copiedFiles = new Map([
  ['holiday-sets/office-holidays-7.yaml', `${examples}/multi-stage-routing-clocks/holiday-sets/office-holidays-7.yaml`],
]);

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

// The tracked sources a fence is held to: the example file it names; for an
// excerpted tutorial project file, both the standalone-decision example and
// the init template that writes it; for a file the reader writes, the example
// it was copied from, or none.
function sourcesFor(fence) {
  const { title } = fence;
  if (title.startsWith(`${examples}/`)) {
    return [{ name: title, text: readFileSync(resolve(repoRoot, title), 'utf8') }];
  }
  const relative = title.startsWith(tutorialProject) ? title.slice(tutorialProject.length) : title;
  if (/\btest-(file|append)\b/u.test(fence.info)) {
    const copiedFrom = copiedFiles.get(relative);
    return copiedFrom === undefined
      ? []
      : [{ name: copiedFrom, text: readFileSync(resolve(repoRoot, copiedFrom), 'utf8') }];
  }
  const tracked = `${examples}/standalone-decision/${relative}`;
  const template = templates.get(relative);
  assert.ok(template !== undefined, `${title} is not a file the standalone-decision template writes`);
  return [
    { name: tracked, text: readFileSync(resolve(repoRoot, tracked), 'utf8') },
    { name: `the init template for ${relative}`, text: template },
  ];
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
    for (const source of sourcesFor(fence)) {
      assert.ok(
        isLineSubset(fence.body, source.text),
        `the fence titled ${fence.title} is not a run of lines of ${source.name}:\n${fence.body}`,
      );
    }
  }
});

test('the page excerpts the tutorial project and copies the multi-stage holiday set', () => {
  const titles = new Set(fences.map((fence) => fence.title));
  for (const required of ['casework.yaml', 'holiday-sets/office-holidays-7.yaml']) {
    assert.ok(titles.has(required), `the page shows nothing from ${required}`);
  }
  const holidaySet = fences.find((fence) => fence.title === 'holiday-sets/office-holidays-7.yaml');
  assert.match(holidaySet.info, /\btest-file\b/u, 'the holiday set is written into the project');
});

test('the excerpted keys exist in the generated project schema', () => {
  const schema = JSON.parse(
    readFileSync(resolve(repoRoot, 'products/casework/generated/project/project.schema.json'), 'utf8'),
  );
  for (const fence of fences.filter((candidate) => /(^|\/)casework\.yaml$/u.test(candidate.title))) {
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

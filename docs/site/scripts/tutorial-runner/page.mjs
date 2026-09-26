// Read a tutorial page into the journey its annotated code fences describe.
//
// The page is the specification. Every `sh` fence is a step the reader runs,
// in document order, unless its meta string carries test-skip="<reason>". An
// output block whose meta string carries test-expect is checked against the
// output of the nearest sh fence above it: a `json` block by structure, any
// other language as text. Annotations sit in the fence meta string, which
// Expressive Code ignores, so they never reach the rendered page.
//
// test-exit="<status>" on an sh fence says the command is meant to end with
// that status, as a refusal the page demonstrates. A `diff` block titled with
// a file path and marked test-edit is the change the page asks the reader to
// make in that file (see edit.mjs).
//
// A block marked test-excerpt shows part of something larger (see
// excerpt.mjs): with a path, as test-excerpt="<path>", part of that file as it
// stands at that point of the journey; bare, part of the output of the
// nearest sh fence above it.
//
// A block titled with a file path and marked test-file is the whole file the
// page asks the reader to create or replace in their editor.
//
// test-background="<url>" on an sh fence is a command the page leaves running
// while the reader carries on in another terminal: the journey goes on once
// the URL answers. test-cwd="<dir>" on an sh fence names the directory, inside
// the reader directory, that the page tells the reader to return to first.
//
// The page is parsed as Markdown rather than MDX, as check-draft-links.mjs
// does: fences, including fences indented inside list items, parse the same
// way, and JSX or comment lines read as paragraphs the journey never runs.

import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import { unified } from 'unified';

const parser = unified().use(remarkParse).use(remarkGfm);
const ANNOTATIONS = new Set([
  'test-skip',
  'test-expect',
  'test-exit',
  'test-edit',
  'test-excerpt',
  'test-file',
  'test-background',
  'test-cwd',
]);

// Parse the test- tokens of a fence meta string: bare flags and key="value"
// pairs. Other tokens belong to Expressive Code and are ignored here.
export function parseAnnotations(meta) {
  const annotations = {};
  for (const [, key, value] of (meta ?? '').matchAll(/(\S+?)(?:="([^"]*)")?(?=\s|$)/gu)) {
    if (key.startsWith('test-')) annotations[key] = value ?? true;
  }
  return annotations;
}

// The Expressive Code title="..." of a fence meta string, if any.
function titleOf(meta) {
  return (meta ?? '').match(/(?:^|\s)title="([^"]*)"/u)?.[1];
}

// Split a diff block into the lines it expects and the lines it leaves, or
// return undefined when a line is not a -, +, or context line. Trailing blank
// lines are layout, not part of the edit.
function diffSides(code) {
  const lines = code.split('\n');
  while (lines.length > 0 && lines.at(-1).trim() === '') lines.pop();
  const before = [];
  const after = [];
  for (const line of lines) {
    const [marker, rest] = [line.slice(0, 1), line.slice(1)];
    if (marker === '-') before.push(rest);
    else if (marker === '+') after.push(rest);
    else if (marker === ' ' || line === '') {
      before.push(rest);
      after.push(rest);
    } else return undefined;
  }
  return { before, after };
}

// Blank out YAML frontmatter, keeping its lines so reported line numbers stay
// the page's own. Markdown would otherwise read `key: value` above the closing
// `---` as a heading.
function withoutFrontmatter(text) {
  const match = text.match(/^---\n[\s\S]*?\n---\n/u);
  return match ? match[0].replace(/[^\n]/gu, '') + text.slice(match[0].length) : text;
}

function plainText(node) {
  if (node.value !== undefined) return node.value;
  return (node.children ?? []).map(plainText).join('');
}

function* walk(node) {
  yield node;
  for (const child of node.children ?? []) yield* walk(child);
}

// Return { steps, errors }. A step is one of
//   { kind: 'run', line, heading, code, exit?, background?, cwd? }
//   { kind: 'skip', line, heading, code, reason }
//   { kind: 'expect', line, heading, format, text, runIndex }
//   { kind: 'edit', line, heading, path, before, after }
//   { kind: 'file', line, heading, path, text }
//   { kind: 'excerpt', line, heading, format, text, runIndex }
//   { kind: 'excerpt', line, heading, format, text, path }
// where runIndex is the index in steps of the fence whose output it checks.
// Errors are sentences naming a line; a page with any is not run.
export function readJourney(text) {
  const steps = [];
  const errors = [];
  let heading = '';
  let lastCommand = -1;
  for (const node of walk(parser.parse(withoutFrontmatter(text)))) {
    if (node.type === 'heading') {
      heading = plainText(node).trim();
      continue;
    }
    if (node.type !== 'code') continue;
    const line = node.position.start.line;
    const annotations = parseAnnotations(node.meta);
    const unknown = Object.keys(annotations).filter((key) => !ANNOTATIONS.has(key));
    for (const key of unknown) errors.push(`line ${line}: unknown annotation ${key}`);
    const skip = annotations['test-skip'];
    const expect = annotations['test-expect'];
    const exit = annotations['test-exit'];
    const edit = annotations['test-edit'];
    const excerpt = annotations['test-excerpt'];
    const file = annotations['test-file'];
    const background = annotations['test-background'];
    const cwd = annotations['test-cwd'];

    if (node.lang === 'sh') {
      if (expect !== undefined) {
        errors.push(`line ${line}: test-expect belongs on an output block, not on an sh fence`);
      }
      if (skip === true || skip === '') {
        errors.push(`line ${line}: test-skip needs a reason, as test-skip="<why this fence is not run>"`);
      }
      if (edit !== undefined) errors.push(`line ${line}: test-edit applies only to diff blocks`);
      if (excerpt !== undefined) {
        errors.push(`line ${line}: test-excerpt belongs on a block the page shows, not on an sh fence`);
      }
      if (file !== undefined) errors.push(`line ${line}: test-file belongs on a block showing the file, not on an sh fence`);
      const step = { kind: skip === undefined ? 'run' : 'skip', line, heading, code: node.value };
      if (typeof skip === 'string' && skip !== '') step.reason = skip;
      if (exit !== undefined) {
        if (typeof exit === 'string' && /^\d+$/u.test(exit)) step.exit = Number(exit);
        else errors.push(`line ${line}: test-exit takes an exit status, as test-exit="1"`);
      }
      if (background !== undefined) {
        if (typeof background !== 'string' || !/^https?:\/\/\S+$/u.test(background)) {
          errors.push(
            `line ${line}: test-background takes the URL that answers once the command is ready, as test-background="http://127.0.0.1:4010/"`,
          );
        } else if (exit !== undefined) {
          errors.push(`line ${line}: a test-background fence keeps running, so it cannot also be test-exit`);
        } else if (skip !== undefined) {
          errors.push(`line ${line}: a test-background fence is run, so it cannot also be test-skip`);
        } else step.background = background;
      }
      if (cwd !== undefined) {
        if (typeof cwd !== 'string' || cwd === '' || cwd.startsWith('/') || cwd.split('/').includes('..')) {
          errors.push(`line ${line}: test-cwd takes a directory inside the reader directory, as test-cwd="first-project"`);
        } else step.cwd = cwd;
      }
      lastCommand = steps.push(step) - 1;
      continue;
    }

    if (skip !== undefined) errors.push(`line ${line}: test-skip applies only to sh fences`);
    if (exit !== undefined) errors.push(`line ${line}: test-exit applies only to sh fences`);
    if (background !== undefined) errors.push(`line ${line}: test-background applies only to sh fences`);
    if (cwd !== undefined) errors.push(`line ${line}: test-cwd applies only to sh fences`);
    if ([file, edit, expect, excerpt].filter((value) => value !== undefined).length > 1) {
      errors.push(`line ${line}: a block is one of test-file, test-edit, test-expect, or test-excerpt`);
      continue;
    }
    if (file !== undefined) {
      const path = titleOf(node.meta);
      if (node.lang === 'diff') errors.push(`line ${line}: test-file takes the whole file; a diff block is test-edit`);
      else if (!path) errors.push(`line ${line}: test-file needs the file path, as title="<path>"`);
      else steps.push({ kind: 'file', line, heading, path, text: `${node.value}\n` });
      continue;
    }
    if (edit !== undefined) {
      const path = titleOf(node.meta);
      const sides = node.lang === 'diff' ? diffSides(node.value) : undefined;
      if (node.lang !== 'diff') errors.push(`line ${line}: test-edit applies only to diff blocks`);
      else if (!path) errors.push(`line ${line}: test-edit needs the file path, as title="<path>"`);
      else if (!sides) errors.push(`line ${line}: every line of a test-edit block starts with -, +, or a space`);
      else if (/^[-+][-+]/mu.test(node.value)) {
        // Expressive Code leaves such a line unmarked, so the reader would see
        // the diff markers as text instead of a removed and an added line.
        errors.push(
          `line ${line}: a test-edit line starts with -- or +- or ++ or -+, which the page shows as plain text; start the change at the indentation it has in the file, with the line above as context`,
        );
      }
      else if (sides.before.join('\n') === sides.after.join('\n')) {
        errors.push(`line ${line}: a test-edit block changes nothing: it needs a - or + line`);
      } else steps.push({ kind: 'edit', line, heading, path, ...sides });
      continue;
    }
    if (expect === undefined && excerpt === undefined) continue;
    const format = node.lang === 'json' ? 'json' : 'text';
    if (typeof excerpt === 'string' && excerpt !== '') {
      steps.push({ kind: 'excerpt', line, heading, format, text: node.value, path: excerpt });
      continue;
    }
    const annotation = expect !== undefined ? 'test-expect' : 'test-excerpt';
    if (lastCommand === -1) {
      errors.push(`line ${line}: ${annotation} has no sh fence above it to check`);
      continue;
    }
    if (steps[lastCommand].kind === 'skip') {
      errors.push(
        `line ${line}: ${annotation} checks the output of the sh fence at line ${steps[lastCommand].line}, which is skipped`,
      );
      continue;
    }
    steps.push({
      kind: expect !== undefined ? 'expect' : 'excerpt',
      line,
      heading,
      format,
      text: node.value,
      runIndex: lastCommand,
    });
  }
  return { steps, errors };
}

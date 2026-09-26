// Read a tutorial page into the journey its annotated code fences describe.
//
// The page is the specification. Every `sh` fence is a step the reader runs,
// in document order, unless its meta string carries test-skip="<reason>". An
// output block whose meta string carries test-expect is checked against the
// output of the nearest sh fence above it: a `json` block by structure, any
// other language as text. Annotations sit in the fence meta string, which
// Expressive Code ignores, so they never reach the rendered page.
//
// The page is parsed as Markdown rather than MDX, as check-draft-links.mjs
// does: fences, including fences indented inside list items, parse the same
// way, and JSX or comment lines read as paragraphs the journey never runs.

import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import { unified } from 'unified';

const parser = unified().use(remarkParse).use(remarkGfm);
const ANNOTATIONS = new Set(['test-skip', 'test-expect']);

// Parse the test- tokens of a fence meta string: bare flags and key="value"
// pairs. Other tokens belong to Expressive Code and are ignored here.
export function parseAnnotations(meta) {
  const annotations = {};
  for (const [, key, value] of (meta ?? '').matchAll(/(\S+?)(?:="([^"]*)")?(?=\s|$)/gu)) {
    if (key.startsWith('test-')) annotations[key] = value ?? true;
  }
  return annotations;
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
//   { kind: 'run', line, heading, code }
//   { kind: 'skip', line, heading, code, reason }
//   { kind: 'expect', line, heading, format, text, runIndex }
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

    if (node.lang === 'sh') {
      if (expect !== undefined) {
        errors.push(`line ${line}: test-expect belongs on an output block, not on an sh fence`);
      }
      if (skip === true || skip === '') {
        errors.push(`line ${line}: test-skip needs a reason, as test-skip="<why this fence is not run>"`);
      }
      const step = { kind: skip === undefined ? 'run' : 'skip', line, heading, code: node.value };
      if (typeof skip === 'string' && skip !== '') step.reason = skip;
      lastCommand = steps.push(step) - 1;
      continue;
    }

    if (skip !== undefined) errors.push(`line ${line}: test-skip applies only to sh fences`);
    if (expect === undefined) continue;
    if (lastCommand === -1) {
      errors.push(`line ${line}: test-expect has no sh fence above it to check`);
      continue;
    }
    if (steps[lastCommand].kind === 'skip') {
      errors.push(
        `line ${line}: test-expect checks the output of the sh fence at line ${steps[lastCommand].line}, which is skipped`,
      );
      continue;
    }
    steps.push({
      kind: 'expect',
      line,
      heading,
      format: node.lang === 'json' ? 'json' : 'text',
      text: node.value,
      runIndex: lastCommand,
    });
  }
  return { steps, errors };
}

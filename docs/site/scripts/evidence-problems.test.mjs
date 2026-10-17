import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parse } from 'yaml';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const contract = parse(read('../../../products/evidence/contracts/problem-contract.yaml')).codes;
const page = read('../src/content/docs/reference/evidence-problems.mdx');

// Rows of the hand-transcribed table whose header is `| Code | Status | Title | Detail | Recovery |`.
// The Recovery column has no product source and is not read.
function pageProblems() {
  const lines = page.split('\n');
  const header = lines.findIndex((line) => /^\|\s*Code\s*\|\s*Status\s*\|\s*Title\s*\|\s*Detail\s*\|\s*Recovery\s*\|$/.test(line.trim()));
  assert.notEqual(header, -1, 'reference/evidence-problems.mdx should carry the Code | Status | Title | Detail | Recovery table');
  const problems = new Map();
  for (const line of lines.slice(header + 2)) {
    if (!line.startsWith('|')) break;
    const [code, status, title, detail] = line
      .slice(1)
      .split(/(?<!\\)\|/)
      .map((cell) => cell.trim().replaceAll('\\|', '|'));
    const name = code.match(/^`([^`]+)`$/)?.[1];
    assert.ok(name, `problem table row has a Code cell that is not one backticked code: ${code}`);
    problems.set(name, { status: Number(status), title, detail });
  }
  return problems;
}

test('the Evidence problem table lists exactly the codes in problem-contract.yaml', () => {
  const pageCodes = new Set(pageProblems().keys());
  const contractCodes = new Set(Object.keys(contract));
  const missing = [...contractCodes].filter((code) => !pageCodes.has(code));
  const extra = [...pageCodes].filter((code) => !contractCodes.has(code));
  assert.deepEqual({ missing, extra }, { missing: [], extra: [] }, 'evidence-problems.mdx codes differ from problem-contract.yaml');
});

test('every Evidence problem row matches the status, title, and detail in problem-contract.yaml', () => {
  for (const [code, row] of pageProblems()) {
    const expected = contract[code];
    if (!expected) continue;
    assert.deepEqual(
      row,
      { status: expected.status, title: expected.title.trim(), detail: expected.detail.trim() },
      `${code} in evidence-problems.mdx differs from problem-contract.yaml`,
    );
  }
});

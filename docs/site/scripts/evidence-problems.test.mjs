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

// Rows of the client kind table whose header is `| Kind | Problem codes | Python |`,
// held to the Rust client's problem mapping and the Python exception classes.
function pageKinds() {
  const lines = page.split('\n');
  const header = lines.findIndex((line) => /^\|\s*Kind\s*\|\s*Problem codes\s*\|\s*Python\s*\|$/.test(line.trim()));
  assert.notEqual(header, -1, 'reference/evidence-problems.mdx should carry the Kind | Problem codes | Python table');
  const kinds = new Map();
  for (const line of lines.slice(header + 2)) {
    if (!line.startsWith('|')) break;
    const [kind, codes, python] = line.slice(1).split('|').map((cell) => cell.trim());
    const name = kind.match(/^`([^`]+)`$/)?.[1];
    assert.ok(name, `client kind table row has a Kind cell that is not one backticked kind: ${kind}`);
    kinds.set(name, {
      codes: [...codes.matchAll(/`([^`]+)`/g)].map((match) => match[1]),
      python: python.match(/^`([^`]+)`$/)?.[1],
    });
  }
  return kinds;
}

// The kind crates/registry-evidence-client/src/problem.rs map_problem() gives a
// registered problem, preserving the precedence of specialized statuses over
// the general client-error and server-error ranges.
function clientKindOf() {
  const source = read('../../../crates/registry-evidence-client/src/problem.rs');
  const denied = source.match(/\(([\d |]+), code\) => EvidenceClientError::Denied/);
  assert.ok(denied, 'problem.rs map_problem() should carry the Denied arm this test reads');
  const deniedStatuses = new Set(denied[1].split('|').map((status) => Number(status.trim())));
  const notAvailable = source.match(/\((\d{3}), Some\(EVIDENCE_NOT_AVAILABLE\)\) => EvidenceClientError::NotAvailable/);
  assert.ok(notAvailable, 'problem.rs map_problem() should carry the NotAvailable arm this test reads');
  const notAvailableCode = source.match(/const EVIDENCE_NOT_AVAILABLE: &str = "([^"]+)";/)?.[1];
  assert.ok(notAvailableCode, 'problem.rs should declare EVIDENCE_NOT_AVAILABLE');
  const invalid = source.match(/\((\d{3})\.\.=(\d{3}), code\) => EvidenceClientError::InvalidRequest/);
  assert.ok(invalid, 'problem.rs should classify the client-error status range');
  const unavailable = source.match(/\((\d{3})\.\.=(\d{3}), code\) => EvidenceClientError::Unavailable/);
  assert.ok(unavailable, 'problem.rs should classify the server-error status range');
  return (code, status) => {
    if (deniedStatuses.has(status)) return 'denied';
    if (status === Number(notAvailable[1]) && code === notAvailableCode) return 'not-available';
    if (status >= Number(invalid[1]) && status <= Number(invalid[2])) return 'invalid-request';
    if (status >= Number(unavailable[1]) && status <= Number(unavailable[2])) return 'unavailable';
    return 'protocol';
  };
}

test('the Evidence client kind table maps every contract code to the kind the Rust client reports', () => {
  const kindOf = clientKindOf();
  const expected = new Map();
  for (const [code, { status }] of Object.entries(contract)) {
    const kind = kindOf(code, status);
    expected.set(kind, [...(expected.get(kind) ?? []), code].sort());
  }
  const actual = new Map([...pageKinds()].map(([kind, row]) => [kind, [...row.codes].sort()]));
  assert.deepEqual(Object.fromEntries(actual), Object.fromEntries(expected));
});

test('the Evidence client kind table names the Python exception each kind raises', () => {
  const source = read('../../../crates/registry-evidence-client-py/src/lib.rs');
  for (const [kind, row] of pageKinds()) {
    const python = source.match(new RegExp(`"${kind}" => (\\w+)::new_err`))?.[1];
    assert.ok(python, `registry-evidence-client-py exception_for_kind() has no arm for ${kind}`);
    assert.equal(row.python, python, `${kind} in evidence-problems.mdx names the wrong Python exception`);
  }
});

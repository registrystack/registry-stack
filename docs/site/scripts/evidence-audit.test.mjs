import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const source = read('../../../crates/registry-evidence/src/audit.rs');
const page = read('../src/content/docs/operate/evidence-audit.mdx');

const kebab = (name) => name.replace(/(?<!^)([A-Z])/g, '-$1').toLowerCase();

// Serialized values of a kebab-case enum declared in audit.rs.
function variants(name) {
  const body = source.match(new RegExp(`#\\[serde\\(rename_all = "kebab-case"\\)\\]\\s*pub enum ${name} \\{([^}]*)\\}`))?.[1];
  assert.ok(body, `audit.rs should declare the kebab-case enum ${name}`);
  return body
    .split(',')
    .map((variant) => variant.trim())
    .filter(Boolean)
    .map(kebab);
}

// Backticked tokens in the first column of the table headed `| Record phase |`.
function recordPhaseTokens() {
  const lines = page.split('\n');
  const header = lines.findIndex((line) => line.startsWith('| Record phase |'));
  assert.notEqual(header, -1, 'operate/evidence-audit.mdx should carry the Record phase table');
  const tokens = [];
  for (const line of lines.slice(header + 2)) {
    if (!line.startsWith('|')) break;
    const firstCell = line.split('|')[1];
    tokens.push(...[...firstCell.matchAll(/`([^`]+)`/g)].map((match) => match[1]));
  }
  return tokens;
}

const phases = variants('AuditPhase');
const decisions = [...variants('AuditDecision'), ...variants('AuthorizationRefusalAuditDecision')];

test('every Evidence audit schema the page names is a string literal in audit.rs', () => {
  const schemas = [...new Set([...page.matchAll(/`(registry\.evidence\.audit[^`]*)`/g)].map((match) => match[1]))];
  assert.ok(schemas.length > 0, 'operate/evidence-audit.mdx should name the audit envelope schemas');
  for (const schema of schemas) {
    assert.ok(source.includes(`"${schema}"`), `${schema} is named in evidence-audit.mdx but is not a string literal in audit.rs`);
  }
});

test('every record phase and decision in the Record phase table is an audit.rs enum value', () => {
  const tokens = recordPhaseTokens();
  assert.ok(tokens.length > 0, 'the Record phase table should name phases and decisions');
  for (const token of tokens) {
    assert.ok(
      phases.includes(token) || decisions.includes(token),
      `${token} is named in the Record phase table of evidence-audit.mdx but is not an AuditPhase, AuditDecision, or AuthorizationRefusalAuditDecision value`,
    );
  }
});

test('the Record phase table documents every AuditPhase value', () => {
  const tokens = new Set(recordPhaseTokens());
  const missing = phases.filter((phase) => !tokens.has(phase));
  assert.deepEqual(missing, [], 'AuditPhase values missing from the Record phase table of evidence-audit.mdx');
});

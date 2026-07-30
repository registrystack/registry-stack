import { execFile } from 'node:child_process';
import { mkdir, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

export const diagnosticCatalogs = {
  authoring: {
    schemaVersion: 'registryctl.authoring_error_reference.v1',
    families: new Set(['authoring_validation']),
    internal: 'src/data/generated/diagnostics/authoring.json',
    public: 'public/generated/diagnostics/authoring.v1.json',
    fixture:
      'crates/registryctl/tests/fixtures/project-reports/registryctl.authoring_error_reference.v1.json',
  },
  fixture: {
    schemaVersion: 'registryctl.fixture_error_reference.v1',
    families: new Set(['fixture_execution']),
    internal: 'src/data/generated/diagnostics/fixture.json',
    public: 'public/generated/diagnostics/fixture.v1.json',
    fixture:
      'crates/registryctl/tests/fixtures/project-reports/registryctl.fixture_error_reference.v1.json',
  },
  operator: {
    schemaVersion: 'registryctl.operator_error_reference.v1',
    families: new Set([
      'bundle_verification',
      'notary_activation',
      'operator_preflight',
      'relay_activation',
      'relay_process_startup',
    ]),
    internal: 'src/data/generated/diagnostics/operator.json',
    public: 'public/generated/diagnostics/operator.v1.json',
    fixture:
      'crates/registryctl/tests/fixtures/project-reports/registryctl.operator_error_reference.v1.json',
  },
};

const entryFields = new Set([
  'family',
  'code',
  'owner',
  'product',
  'phase',
  'safe_meaning',
  'rule',
  'safe_remediation',
  'field_address_pattern',
  'evidence_scope',
  'secret_sensitive_value_policy',
  'docs_anchor',
  'lifecycle',
  'introduced_in',
  'stability',
  'evidence_limitation',
]);
const ownerByProduct = new Map([
  ['registry_notary', 'registry_notary'],
  ['registry_platform_ops', 'registry_platform_ops'],
  ['registry_relay', 'registry_relay'],
  ['registryctl', 'registryctl'],
  ['registryctl_relay_offline_harness', 'registryctl'],
]);
const familyCatalog = new Map([
  ['authoring_validation', 'authoring'],
  ['fixture_execution', 'fixture'],
  ['bundle_verification', 'operator'],
  ['notary_activation', 'operator'],
  ['operator_preflight', 'operator'],
  ['relay_activation', 'operator'],
  ['relay_process_startup', 'operator'],
]);
const productOwnedDocsSlugFamilies = new Set([
  'bundle_verification',
  'notary_activation',
  'relay_activation',
  'relay_process_startup',
]);
const unsafePublishedText =
  /(COUNTRY_(?:SECRET|VALUE)_SENTINEL|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|Bearer\s+[A-Za-z0-9._~-]+|\/(?:private|tmp)\/[^\s]*)/i;

function parseJson(text, label) {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} did not emit JSON: ${error.message}`);
  }
}

async function executeRegistryctl(repoRoot, args) {
  try {
    const { stdout } = await execFileAsync(
      'cargo',
      ['run', '--locked', '--quiet', '-p', 'registryctl', '--', ...args],
      {
        cwd: repoRoot,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    return stdout;
  } catch (error) {
    const stdout = typeof error?.stdout === 'string' ? error.stdout.trim() : '';
    const stderr = typeof error?.stderr === 'string' ? error.stderr.trim() : '';
    throw new Error(
      `registryctl ${args.join(' ')} failed: ${stdout || stderr || error.message}`,
    );
  }
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(required)) {
    throw new Error(`${label} must contain exactly ${required.join(', ')}`);
  }
}

function nonemptyString(value, label) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${label} must be a non-empty string`);
  }
  if (unsafePublishedText.test(value)) {
    throw new Error(`${label} contains runtime or secret-bearing text`);
  }
}

function isNumericReleaseVersion(value) {
  return (
    typeof value === 'string' &&
    /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/.test(value)
  );
}

function key(entry) {
  return [entry.family, entry.product, entry.code];
}

function compareText(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function compareKeys(left, right) {
  return compareText(left[0], right[0]) ||
    compareText(left[1], right[1]) ||
    compareText(left[2], right[2]);
}

function compareOmissionKeys(left, right) {
  return compareText(left[0], right[0]) || compareText(left[1], right[1]);
}

function expectedAnchor(catalog, entry) {
  if (productOwnedDocsSlugFamilies.has(entry.family)) {
    return new RegExp(
      `^/reference/diagnostics/${catalog}/#${entry.product}--[a-z0-9]+(?:-[a-z0-9]+)*$`,
    );
  }
  return `/reference/diagnostics/${catalog}/#${entry.product}--${entry.code}`;
}

export function validateDiagnosticReference(catalog, reference) {
  const contract = diagnosticCatalogs[catalog];
  if (!contract) throw new Error(`unknown diagnostic catalog ${catalog}`);
  const topLevel = catalog === 'operator'
    ? new Set(['schema_version', 'entries', 'omissions'])
    : new Set(['schema_version', 'entries']);
  exactKeys(reference, topLevel, `${catalog} diagnostic reference`);
  if (reference.schema_version !== contract.schemaVersion) {
    throw new Error(`${catalog} diagnostic reference has an unsupported schema_version`);
  }
  if (!Array.isArray(reference.entries) || reference.entries.length === 0) {
    throw new Error(`${catalog} diagnostic reference must contain entries`);
  }

  let previous;
  const identities = new Set();
  const docsAnchors = new Set();
  for (const [index, entry] of reference.entries.entries()) {
    const label = `${catalog}.entries[${index}]`;
    exactKeys(entry, entryFields, label);
    if (!contract.families.has(entry.family)) {
      throw new Error(`${label}.family is not part of the ${catalog} catalog`);
    }
    if (familyCatalog.get(entry.family) !== catalog) {
      throw new Error(`${label}.family resolves to the wrong public catalog`);
    }
    if (ownerByProduct.get(entry.product) !== entry.owner) {
      throw new Error(`${label} has an invalid product-owner mapping`);
    }
    for (const field of [
      'family',
      'code',
      'owner',
      'product',
      'phase',
      'safe_meaning',
      'rule',
      'safe_remediation',
      'evidence_scope',
      'secret_sensitive_value_policy',
      'docs_anchor',
      'lifecycle',
      'stability',
      'evidence_limitation',
    ]) {
      nonemptyString(entry[field], `${label}.${field}`);
    }
    if (
      entry.field_address_pattern !== null &&
      typeof entry.field_address_pattern !== 'string'
    ) {
      throw new Error(`${label}.field_address_pattern must be a string or null`);
    }
    if (typeof entry.field_address_pattern === 'string') {
      nonemptyString(entry.field_address_pattern, `${label}.field_address_pattern`);
    }
    if (
      !['no_received_value', 'no_runtime_values', 'received_type_only'].includes(
        entry.secret_sensitive_value_policy,
      )
    ) {
      throw new Error(`${label}.secret_sensitive_value_policy is not closed`);
    }
    if (entry.stability !== 'pre1_stable_code') {
      throw new Error(`${label}.stability is not supported`);
    }
    if (entry.lifecycle === 'unreleased') {
      if (entry.introduced_in !== null) {
        throw new Error(`${label} unreleased lifecycle requires introduced_in: null`);
      }
    } else if (
      !['active', 'deprecated', 'released'].includes(entry.lifecycle) ||
      !isNumericReleaseVersion(entry.introduced_in)
    ) {
      throw new Error(`${label} released lifecycle requires a numeric introduced_in`);
    }
    const entryKey = key(entry);
    const identity = JSON.stringify(entryKey);
    if (identities.has(identity)) {
      throw new Error(`${label} duplicates ${identity}`);
    }
    identities.add(identity);
    if (previous && compareKeys(previous, entryKey) >= 0) {
      throw new Error(`${label} is not ordered by family, product, code`);
    }
    previous = entryKey;

    const expectedDocsAnchor = expectedAnchor(catalog, entry);
    if (
      typeof expectedDocsAnchor === 'string'
        ? entry.docs_anchor !== expectedDocsAnchor
        : !expectedDocsAnchor.test(entry.docs_anchor)
    ) {
      throw new Error(`${label}.docs_anchor is not derived from its owned static metadata`);
    }
    if (docsAnchors.has(entry.docs_anchor)) {
      throw new Error(`${label}.docs_anchor is duplicated`);
    }
    docsAnchors.add(entry.docs_anchor);
  }

  if (catalog === 'operator') {
    if (!Array.isArray(reference.omissions)) {
      throw new Error('operator.omissions must be an array');
    }
    let previousOmission;
    const omissionKeys = new Set();
    for (const [index, omission] of reference.omissions.entries()) {
      const label = `operator.omissions[${index}]`;
      exactKeys(
        omission,
        new Set(['family', 'product', 'reason', 'evidence', 'required_action']),
        label,
      );
      for (const field of ['family', 'product', 'reason', 'evidence', 'required_action']) {
        nonemptyString(omission[field], `${label}.${field}`);
      }
      if (!diagnosticCatalogs.operator.families.has(omission.family)) {
        throw new Error(`${label}.family is not an operator family`);
      }
      if (!ownerByProduct.has(omission.product)) {
        throw new Error(`${label}.product is not closed`);
      }
      if (omission.reason !== 'no_complete_public_code_catalog') {
        throw new Error(`${label}.reason is not supported`);
      }
      const omissionKey = [omission.family, omission.product];
      const identity = JSON.stringify(omissionKey);
      if (omissionKeys.has(identity)) throw new Error(`${label} is duplicated`);
      omissionKeys.add(identity);
      if (
        previousOmission &&
        compareOmissionKeys(previousOmission, omissionKey) >= 0
      ) {
        throw new Error(`${label} is not lexically ordered`);
      }
      previousOmission = omissionKey;
    }
  }
}

async function publishJson(path, text) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  try {
    await writeFile(temporary, text, {
      encoding: 'utf8',
      flag: 'wx',
    });
    await rename(temporary, path);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

export async function generateDiagnosticReferences(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
  execute = executeRegistryctl,
) {
  const publications = [];
  const counts = [];
  for (const [catalog, contract] of Object.entries(diagnosticCatalogs)) {
    const args = [
      'tooling',
      'diagnostics',
      '--catalog',
      catalog,
      '--format',
      'json',
    ];
    const first = await execute(repoRoot, args);
    const second = await execute(repoRoot, args);
    if (first !== second) {
      throw new Error(`registryctl ${catalog} diagnostic reference is not byte deterministic`);
    }
    const reference = parseJson(first, `registryctl ${catalog} diagnostic reference`);
    validateDiagnosticReference(catalog, reference);
    publications.push(
      [resolve(docsRoot, contract.internal), first],
      [resolve(docsRoot, contract.public), first],
      [resolve(repoRoot, contract.fixture), first],
    );
    counts.push(`${catalog}=${reference.entries.length}`);
  }
  await Promise.all(publications.map(([path, text]) => publishJson(path, text)));
  console.log(`Generated diagnostic references (${counts.join(', ')}).`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateDiagnosticReferences();
}

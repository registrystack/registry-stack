// Render the frozen Evidence configuration grammar as docs data.
//
// `products/evidence/contracts/{bundle,runtime}.schema.yaml` are the normative
// Version 1 grammar. They carry types, fixed values, and bounds, but almost no
// prose: the explanations live in the product's CONFIG.md. So this generator
// publishes exactly what the contracts can prove, and the page sends readers to
// CONFIG.md for intent.
//
// The key-path notation is the one
// `products/evidence/scripts/check-config-key-paths.sh` owns, and this
// generator's test compares against the blocks that check maintains, so the two
// walks cannot drift apart quietly.
import { readFile, mkdir, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parse as parseYaml } from 'yaml';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

export const FORMAT_VERSION = '1.2';

export const CONTRACTS = [
  {
    id: 'bundle',
    file: 'products/evidence/contracts/bundle.schema.yaml',
    title: 'bundle/evidence.yaml',
    marker: 'evidence-bundle-key-paths',
  },
  {
    id: 'runtime',
    file: 'products/evidence/contracts/runtime.schema.yaml',
    title: 'runtime.yaml',
    marker: 'evidence-runtime-key-paths',
  },
];

// Validation keywords worth showing beside a field. `required`, `const`, and
// `enum` are reported separately, and the structural keywords drive the walk.
const CONSTRAINT_KEYWORDS = [
  'exclusiveMaximum',
  'exclusiveMinimum',
  'format',
  'maxItems',
  'maxLength',
  'maxProperties',
  'maximum',
  'minItems',
  'minLength',
  'minProperties',
  'minimum',
  'multipleOf',
  'pattern',
  'uniqueItems',
];

function resolveReference(document, reference) {
  if (!reference.startsWith('#/')) {
    throw new Error(`only local schema references are supported: ${reference}`);
  }
  let node = document;
  for (const part of reference.slice(2).split('/')) {
    if (node === null || typeof node !== 'object' || !Object.hasOwn(node, part)) {
      throw new Error(`unresolved schema reference ${reference}`);
    }
    node = node[part];
  }
  return node;
}

// The contracts are parsed with `intAsBigInt`, because the signed 64-bit
// adapter parameter bounds do not survive a double.
function describeValue(value) {
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  return JSON.stringify(value);
}

// A `const` or `enum` fixes the type of every value it permits, so a schema
// stating one and omitting `type` still proves what a deployment may write.
// Nothing else is inferred: `properties` without `type` asserts no type, and
// the entry stays honest about that.
function jsonTypeOf(value) {
  if (value === null) {
    return 'null';
  }
  if (Array.isArray(value)) {
    return 'array';
  }
  switch (typeof value) {
    case 'bigint':
      return 'integer';
    case 'number':
      return Number.isInteger(value) ? 'integer' : 'number';
    case 'boolean':
      return 'boolean';
    case 'string':
      return 'string';
    default:
      return 'object';
  }
}

function constraintsOf(schema, prefix = '') {
  return CONSTRAINT_KEYWORDS.filter((keyword) => Object.hasOwn(schema, keyword)).map(
    (keyword) => `${prefix}${keyword}: ${describeValue(schema[keyword])}`,
  );
}

// Bounds a map places on the key a deployment writes. These contracts state
// them as a reference to the shared identifier definition, so reading the
// `propertyNames` node itself would report nothing.
function propertyNameConstraints(document, schema) {
  const seen = new Set();
  let node = schema;
  while (node !== null && typeof node === 'object' && Object.hasOwn(node, '$ref')) {
    if (seen.has(node.$ref)) {
      return [];
    }
    seen.add(node.$ref);
    node = resolveReference(document, node.$ref);
  }
  if (node === null || typeof node !== 'object' || Array.isArray(node)) {
    return [];
  }
  const conjuncts = Array.isArray(node.allOf) ? node.allOf : [];
  return [
    ...new Set([
      ...constraintsOf(node, 'propertyNames.'),
      ...conjuncts.flatMap((branch) => constraintsOf(branch ?? {}, 'propertyNames.')),
    ]),
  ].sort();
}

function occurrenceOf(schema, keyPath, kind, required, state) {
  const fixed = [];
  if (Object.hasOwn(schema, 'const')) {
    fixed.push(schema.const);
  }
  if (Array.isArray(schema.enum)) {
    fixed.push(...schema.enum);
  }
  const declared = Array.isArray(schema.type)
    ? schema.type
    : typeof schema.type === 'string'
      ? [schema.type]
      : [];
  return {
    key_path: keyPath,
    kind,
    types: declared.length > 0 ? declared : fixed.map(jsonTypeOf),
    required,
    values: fixed.map(describeValue),
    constraints: constraintsOf(schema),
    // Which alternative branches were taken to reach this node. Occurrences
    // sharing a key apply together; occurrences under different branches of
    // one combinator are alternatives.
    variantKey: state.variantPath.join('>'),
    // Set when the answer depends on which alternative a deployment takes,
    // either because some alternative does not declare this key path at all or
    // because only some of them require it.
    conditional: false,
    description: typeof schema.description === 'string' ? schema.description : null,
    runtime_validation:
      typeof schema['x-runtime-validation'] === 'string' ? schema['x-runtime-validation'] : null,
    // An entry that carries no shape of its own. It records requiredness or the
    // absence of a bound, and never brings a key path into the reference.
    assertionOnly: false,
    // Set on entries an `if`/`then`/`else` clause produced, so a value the
    // clause fixes can be told apart from one an alternative offers.
    fromCondition: false,
  };
}

function assertionOf(keyPath, kind, required, variantKey, conditional) {
  return {
    key_path: keyPath,
    kind,
    types: [],
    required,
    values: [],
    constraints: [],
    variantKey,
    conditional,
    description: null,
    runtime_validation: null,
    assertionOnly: true,
    fromCondition: false,
  };
}

// The names a node requires, recorded at the key paths they name. The declaring
// `properties` often sits on a different node: an alternative or a conditional
// clause commonly states its whole shape with `required` alone, and reading
// requiredness only where a property is declared reports such a key as never
// required. `not` is deliberately not walked, so a name required inside one is
// never mistaken for a requirement.
function requiredAssertions(schema, prefix, state) {
  if (!Array.isArray(schema.required)) {
    return [];
  }
  return schema.required
    .filter((name) => typeof name === 'string')
    .map((name) =>
      assertionOf(
        prefix ? `${prefix}.${name}` : name,
        'property',
        true,
        state.variantPath.join('>'),
        false,
      ),
    );
}

// Which branches of one combinator declare a key path, and which require it.
// Both are counted per branch rather than per occurrence, because a branch may
// state the same key twice, once in `properties` and once in `required`.
function branchCoverage(collected) {
  const declaredIn = new Map();
  const requiredIn = new Map();
  for (const branchOccurrences of collected) {
    const declared = new Set(branchOccurrences.map((entry) => entry.key_path));
    const required = new Set(
      branchOccurrences.filter((entry) => entry.required).map((entry) => entry.key_path),
    );
    for (const keyPath of declared) {
      declaredIn.set(keyPath, (declaredIn.get(keyPath) ?? 0) + 1);
    }
    for (const keyPath of required) {
      requiredIn.set(keyPath, (requiredIn.get(keyPath) ?? 0) + 1);
    }
  }
  return { declaredIn, requiredIn };
}

// Each node records what it knows about the path it sits on, so a property
// written as a `$ref` still reports the definition's type, values, and bounds,
// and a path reached through several combinator branches reports all of them.
//
// `state` carries the position rather than the shape: `referenceStack` stops a
// recursive definition, `variantPath` names the alternatives taken to get here,
// and `scope` is a stable node path so two independent conditions on one key
// path do not collapse into a single alternative.
function walk(document, schema, prefix, kind, required, occurrences, state) {
  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) {
    return;
  }

  if (prefix !== '') {
    occurrences.push(occurrenceOf(schema, prefix, kind, required, state));
  }
  occurrences.push(...requiredAssertions(schema, prefix, state));

  if (Object.hasOwn(schema, '$ref')) {
    const reference = schema.$ref;
    // A recursive definition contributes its shape once. Re-entering it would
    // not terminate and shows the reader no key they have not already seen.
    if (state.referenceStack.has(reference)) {
      return;
    }
    walk(document, resolveReference(document, reference), prefix, kind, required, occurrences, {
      ...state,
      referenceStack: new Set([...state.referenceStack, reference]),
      scope: reference,
    });
    return;
  }

  if (Array.isArray(schema.allOf)) {
    schema.allOf.forEach((branch, index) => {
      walk(document, branch, prefix, kind, required, occurrences, {
        ...state,
        scope: `${state.scope}/allOf[${index}]`,
      });
    });
  }

  // `oneOf` and `anyOf` offer alternatives, so a key path only some branches
  // declare, or only some branches require, cannot be reported as plainly
  // required: a reader who writes every key marked required produces a
  // document every alternative rejects.
  for (const combinator of ['anyOf', 'oneOf']) {
    const branches = schema[combinator];
    if (!Array.isArray(branches) || branches.length === 0) {
      continue;
    }
    const collected = branches.map((branch, index) => {
      const branchOccurrences = [];
      const branchScope = `${state.scope}/${combinator}[${index}]`;
      walk(document, branch, prefix, kind, required, branchOccurrences, {
        ...state,
        scope: branchScope,
        variantPath: [...state.variantPath, branchScope],
      });
      return branchOccurrences;
    });
    const { declaredIn, requiredIn } = branchCoverage(collected);
    for (const branchOccurrences of collected) {
      for (const entry of branchOccurrences) {
        const declared = declaredIn.get(entry.key_path) ?? 0;
        const requiredCount = requiredIn.get(entry.key_path) ?? 0;
        if (declared < branches.length || (requiredCount > 0 && requiredCount < branches.length)) {
          entry.conditional = true;
        }
        occurrences.push(entry);
      }
    }
  }

  // `if`/`then`/`else` states a rule that binds only when the condition holds,
  // so what a clause adds is one case rather than a bound on every document.
  // `if` asserts nothing about the document a deployment writes, only about
  // which case applies, so it is not walked.
  if (Object.hasOwn(schema, 'if')) {
    const clauses = ['then', 'else'].map((clause) => {
      const branch = schema[clause];
      const clauseScope = `${state.scope}/${clause}`;
      const clauseOccurrences = [];
      if (branch !== null && typeof branch === 'object' && !Array.isArray(branch)) {
        // The clause asserts nothing about the presence of the key it hangs
        // off, so it starts from `false` rather than inheriting requiredness
        // that belongs to the enclosing shape.
        walk(document, branch, prefix, kind, false, clauseOccurrences, {
          ...state,
          scope: clauseScope,
          variantPath: [...state.variantPath, clauseScope],
        });
      }
      // A clause reaches the key it bounds by traversing the objects above it.
      // Those intermediate entries assert nothing, so they neither offer an
      // alternative nor make a key's presence depend on the condition.
      return {
        scope: clauseScope,
        occurrences: clauseOccurrences.filter(
          (entry) =>
            entry.required ||
            entry.constraints.length > 0 ||
            entry.values.length > 0 ||
            entry.types.length > 0,
        ),
      };
    });

    // A clause that is absent, or silent about a key path the other clause
    // bounds, is still a shape a deployment may write. Without an entry
    // standing for it, the other clause's bounds read as though they always
    // applied, and a deployment outside the condition would be shown a bound it
    // must not satisfy.
    const kinds = new Map(
      clauses.flatMap(({ occurrences: clauseOccurrences }) =>
        clauseOccurrences.map((entry) => [entry.key_path, entry.kind]),
      ),
    );
    for (const { scope, occurrences: clauseOccurrences } of clauses) {
      const present = new Set(clauseOccurrences.map((entry) => entry.key_path));
      for (const [keyPath, entryKind] of kinds) {
        if (!present.has(keyPath)) {
          clauseOccurrences.push(
            assertionOf(keyPath, entryKind, false, [...state.variantPath, scope].join('>'), false),
          );
        }
      }
      for (const entry of clauseOccurrences) {
        // Only a requirement the clause states makes a key's presence depend on
        // the condition. A bound or a fixed value it adds becomes one
        // alternative in the constraint and value columns instead.
        if (entry.required) {
          entry.conditional = true;
        }
        entry.fromCondition = true;
        occurrences.push(entry);
      }
    }
  }

  if (schema.properties !== null && typeof schema.properties === 'object') {
    const requiredNames = new Set(Array.isArray(schema.required) ? schema.required : []);
    for (const [name, child] of Object.entries(schema.properties)) {
      const childPath = prefix ? `${prefix}.${name}` : name;
      walk(document, child ?? {}, childPath, 'property', requiredNames.has(name), occurrences, {
        ...state,
        scope: `${state.scope}/properties/${name}`,
      });
    }
  }

  if (schema.items !== null && typeof schema.items === 'object' && !Array.isArray(schema.items)) {
    walk(document, schema.items, `${prefix}[]`, 'array_item', false, occurrences, {
      ...state,
      scope: `${state.scope}/items`,
    });
  }

  const additional = schema.additionalProperties;
  if (additional !== null && typeof additional === 'object' && !Array.isArray(additional)) {
    const valuePath = prefix ? `${prefix}.*` : '*';
    // `propertyNames` bounds the key a deployment writes for each entry. It
    // sits on the map, so without this it reaches no row a reader consults
    // while naming a source, selector profile, or authority profile.
    const names = schema.propertyNames;
    if (names !== null && typeof names === 'object' && !Array.isArray(names)) {
      const nameConstraints = propertyNameConstraints(document, names);
      if (nameConstraints.length > 0) {
        occurrences.push({
          key_path: valuePath,
          kind: 'map_value',
          types: [],
          required: false,
          values: [],
          constraints: nameConstraints,
          variantKey: state.variantPath.join('>'),
          conditional: false,
          description: null,
          runtime_validation: null,
          assertionOnly: false,
          fromCondition: false,
        });
      }
    }
    walk(document, additional, valuePath, 'map_value', false, occurrences, {
      ...state,
      scope: `${state.scope}/additionalProperties`,
    });
  }
}

const uniqueSorted = (values) => [...new Set(values)].sort();

// Constraint sets a deployment may satisfy, one group per alternative. Bounds
// reached without choosing a branch hold under every alternative, so they join
// each group; printing one flat union instead would read as a conjunction and
// describe a value no alternative accepts.
function constraintAlternatives(occurrences) {
  const shared = occurrences
    .filter((occurrence) => occurrence.variantKey === '')
    .flatMap((occurrence) => occurrence.constraints);

  const byVariant = new Map();
  for (const occurrence of occurrences) {
    if (occurrence.variantKey === '') {
      continue;
    }
    byVariant.set(occurrence.variantKey, [
      ...(byVariant.get(occurrence.variantKey) ?? []),
      ...occurrence.constraints,
    ]);
  }

  if (byVariant.size === 0) {
    const only = uniqueSorted(shared);
    return only.length > 0 ? [only] : [];
  }

  const groups = [...byVariant.values()].map((constraints) =>
    uniqueSorted([...shared, ...constraints]),
  );
  // An alternative that adds no bound is kept, because dropping it would make
  // another alternative's bounds read as though they held under every
  // alternative. Alternatives that land on the same bounds are one group.
  const distinct = [...new Map(groups.map((group) => [JSON.stringify(group), group])).values()];
  if (distinct.length === 1) {
    return distinct[0].length > 0 ? distinct : [];
  }
  return distinct;
}

function merge(occurrences) {
  // One entry per key path. A path reached through several combinator branches
  // shows the union of the types and values those branches allow. It is
  // `conditional` when the answer depends on the alternative taken, and
  // otherwise `yes` as soon as anything requires it: what is left once the
  // alternatives are accounted for is a conjunction, where one `required` is
  // enough to make the key mandatory.
  const shaped = occurrences.filter((occurrence) => !occurrence.assertionOnly);
  const first = shaped[0] ?? occurrences[0];
  const conditional = occurrences.some((occurrence) => occurrence.conditional);
  const values = uniqueSorted(occurrences.flatMap((occurrence) => occurrence.values));
  // A conditional rule that fixes a value narrows the accepted set rather than
  // adding to it, and a union cannot show that. Grouping values per alternative
  // the way bounds are grouped would split a key such as
  // `requirements[].concepts[].form` into one group per branch and read worse
  // than the union, so the narrowing is named beside the set instead.
  const narrowedByCondition = occurrences.some(
    (occurrence) =>
      occurrence.fromCondition &&
      occurrence.values.length > 0 &&
      new Set(occurrence.values).size < values.length,
  );
  return {
    key_path: first.key_path,
    kind: first.kind,
    type: uniqueSorted(occurrences.flatMap((occurrence) => occurrence.types)).join(' | ') || null,
    required: conditional
      ? 'conditional'
      : occurrences.some((occurrence) => occurrence.required)
        ? 'yes'
        : 'no',
    values,
    values_conditional: narrowedByCondition,
    constraints: constraintAlternatives(occurrences),
    description: occurrences.find((occurrence) => occurrence.description)?.description ?? null,
    runtime_validation:
      occurrences.find((occurrence) => occurrence.runtime_validation)?.runtime_validation ?? null,
  };
}

/** Every key path a deployment may write, in `name`, `name[]`, `name.*` notation. */
export function collectFields(document) {
  if (document === null || typeof document !== 'object') {
    throw new Error('a contract must be a mapping');
  }
  const occurrences = [];
  walk(document, document, '', null, false, occurrences, {
    referenceStack: new Set(),
    variantPath: [],
    scope: '',
  });

  const grouped = new Map();
  for (const occurrence of occurrences) {
    const existing = grouped.get(occurrence.key_path);
    if (existing) {
      existing.push(occurrence);
    } else {
      grouped.set(occurrence.key_path, [occurrence]);
    }
  }
  return [...grouped.keys()]
    .sort()
    // A key path known only from a `required` name is not a key a deployment
    // may write: nothing declares it. Reporting it would invent a row, and
    // would put this walk out of parity with the check that owns the notation.
    .filter((keyPath) => grouped.get(keyPath).some((occurrence) => !occurrence.assertionOnly))
    .map((keyPath) => merge(grouped.get(keyPath)))
    .map((field) => ({ ...field, values: field.values.length > 0 ? field.values : null }));
}

export function validateEvidenceConfiguration(document) {
  if (document?.format_version !== FORMAT_VERSION) {
    throw new Error('evidence configuration reference uses an unsupported format_version');
  }
  if (!Array.isArray(document.contracts) || document.contracts.length !== CONTRACTS.length) {
    throw new Error('evidence configuration reference must cover every frozen contract');
  }
  for (const contract of document.contracts) {
    if (!Array.isArray(contract.fields) || contract.fields.length === 0) {
      throw new Error(`${contract.id} must document at least one key path`);
    }
    if (contract.field_count !== contract.fields.length) {
      throw new Error(`${contract.id} field_count does not match the entries it carries`);
    }
    const seen = new Set();
    for (const field of contract.fields) {
      if (typeof field.key_path !== 'string' || field.key_path.length === 0) {
        throw new Error(`${contract.id} has an entry without a key path`);
      }
      if (seen.has(field.key_path)) {
        throw new Error(`${contract.id} repeats ${field.key_path}`);
      }
      seen.add(field.key_path);
    }
  }
}

export async function buildEvidenceConfiguration(repoRoot = defaultRepoRoot) {
  const contracts = await Promise.all(
    CONTRACTS.map(async (contract) => {
      const schema = parseYaml(await readFile(resolve(repoRoot, contract.file), 'utf8'), {
        intAsBigInt: true,
      });
      const fields = collectFields(schema);
      return { ...contract, field_count: fields.length, fields };
    }),
  );
  return {
    format_version: FORMAT_VERSION,
    generator: 'docs/site/scripts/generate-evidence-configuration.mjs',
    contracts,
  };
}

async function publishJson(path, document) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(document, null, 2)}\n`, {
      encoding: 'utf8',
      flag: 'wx',
    });
    await rename(temporary, path);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

export async function generateEvidenceConfiguration(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
) {
  const document = await buildEvidenceConfiguration(repoRoot);
  validateEvidenceConfiguration(document);
  await publishJson(resolve(docsRoot, 'src/data/generated/evidence-configuration.json'), document);
  const total = document.contracts.reduce((sum, contract) => sum + contract.field_count, 0);
  console.log(
    `Generated Evidence configuration reference for ${total} key paths across ${document.contracts.length} contracts.`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateEvidenceConfiguration();
}

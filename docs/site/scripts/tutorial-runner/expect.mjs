// Compare what a fence printed with the output block a page shows for it.
//
// A <placeholder>, a lowercase name in angle brackets, stands for a value the
// page cannot know: an identifier, a digest, a token. In text it matches one
// run of non-space characters; as a whole JSON string it matches any string,
// and inside a longer JSON string it matches as it does in text.
// Everything else is literal.

const PLACEHOLDER = /<[a-z][a-z0-9-]*>/gu;
const WHOLE_PLACEHOLDER = /^<[a-z][a-z0-9-]*>$/u;
const HAS_PLACEHOLDER = /<[a-z][a-z0-9-]*>/u;

export function lines(text) {
  const all = text.split('\n').map((line) => line.trimEnd());
  while (all.length > 0 && all[0] === '') all.shift();
  while (all.length > 0 && all.at(-1) === '') all.pop();
  return all;
}

// The regular expression source matching one expected line, placeholders
// included, without anchors.
export function lineSource(expected) {
  const parts = expected.split(PLACEHOLDER).map((part) => part.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'));
  return parts.join('\\S+');
}

function linePattern(expected) {
  return new RegExp(`^${lineSource(expected)}$`, 'u');
}

function checkText(expectedText, actualText) {
  const expected = lines(expectedText);
  const actual = lines(actualText);
  const same = expected.length === actual.length && expected.every((line, i) => linePattern(line).test(actual[i]));
  if (same) return null;
  const indent = (all) => all.map((line) => `  ${line}`).join('\n');
  return `expected:\n${indent(expected)}\nactual:\n${indent(actual)}`;
}

export function describe(value) {
  return JSON.stringify(value);
}

// Return the first difference between two parsed JSON values, or null.
export function firstDifference(expected, actual, path) {
  if (typeof expected === 'string' && WHOLE_PLACEHOLDER.test(expected)) {
    return typeof actual === 'string' ? null : `at ${path}: expected a string for ${expected}, got ${describe(actual)}`;
  }
  if (typeof expected === 'string' && HAS_PLACEHOLDER.test(expected)) {
    const matches = typeof actual === 'string' && linePattern(expected).test(actual);
    return matches ? null : `at ${path}: expected ${describe(expected)}, got ${describe(actual)}`;
  }
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) return `at ${path}: expected an array, got ${describe(actual)}`;
    if (expected.length !== actual.length) {
      return `at ${path}: expected ${expected.length} items, got ${actual.length}`;
    }
    for (let i = 0; i < expected.length; i += 1) {
      const difference = firstDifference(expected[i], actual[i], `${path}[${i}]`);
      if (difference) return difference;
    }
    return null;
  }
  if (expected !== null && typeof expected === 'object') {
    if (actual === null || typeof actual !== 'object' || Array.isArray(actual)) {
      return `at ${path}: expected an object, got ${describe(actual)}`;
    }
    for (const key of Object.keys(expected)) {
      if (!Object.hasOwn(actual, key)) return `at ${path}: missing key "${key}"`;
    }
    for (const key of Object.keys(actual)) {
      if (!Object.hasOwn(expected, key)) return `at ${path}: unexpected key "${key}"`;
    }
    for (const key of Object.keys(expected)) {
      const difference = firstDifference(expected[key], actual[key], `${path}.${key}`);
      if (difference) return difference;
    }
    return null;
  }
  return expected === actual ? null : `at ${path}: expected ${describe(expected)}, got ${describe(actual)}`;
}

function checkJson(expectedText, actualText) {
  let expected;
  try {
    expected = JSON.parse(expectedText);
  } catch (error) {
    return `the page's own block is not JSON: ${error.message}`;
  }
  let actual;
  try {
    actual = JSON.parse(actualText);
  } catch {
    return `output is not JSON:\n${lines(actualText).map((line) => `  ${line}`).join('\n')}`;
  }
  return firstDifference(expected, actual, '$');
}

// Return null when the output matches, or a message describing the mismatch.
export function checkExpectation(format, expectedText, actualText) {
  return format === 'json' ? checkJson(expectedText, actualText) : checkText(expectedText, actualText);
}

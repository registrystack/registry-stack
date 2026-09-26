// Check that a block a page shows as part of something larger, a few lines of
// a file or one object of a long report, is really in it.
//
// A text excerpt is a run of consecutive lines of the source. Like an edit
// (edit.mjs), it matches at any one extra indentation, because the page shows
// lines without the indentation they sit at in the file, and keeps its lines'
// indentation relative to each other. A JSON excerpt is an object that some
// object in the source carries: every key of the excerpt is there with the
// same value, compared by structure all the way down, while the object may
// have other keys. That lets a page show one property of a schema, or one
// entry of a list, without its neighbours. An excerpt that is a JSON array
// must equal an array in the source. Placeholders work as in expect.mjs.
//
// The source of a JSON excerpt is a JSON document, or command output holding
// one or more of them after a text preamble: each starts on a line that opens
// with `{` or `[` in its first column.

import { describe, firstDifference, lineSource, lines } from './expect.mjs';

const indent = (all) => all.map((line) => `  ${line}`).join('\n');

function checkText(excerptText, sourceText) {
  const excerpt = lines(excerptText);
  const patterns = excerpt.map((line) => (line.trim() === '' ? undefined : new RegExp(`^(\\s*)${lineSource(line)}$`, 'u')));
  const source = sourceText.split('\n').map((line) => line.trimEnd());
  for (let start = 0; start + excerpt.length <= source.length; start += 1) {
    let extra;
    const matches = patterns.every((pattern, k) => {
      const line = source[start + k];
      if (!pattern) return line.trim() === '';
      const found = line.match(pattern);
      if (!found) return false;
      extra ??= found[1];
      return found[1] === extra;
    });
    if (matches) return null;
  }
  return `no run of lines matches the excerpt at one indentation\nexcerpt:\n${indent(excerpt)}`;
}

// Every JSON document in the source: the whole of it, or each one that starts
// on a line opening with { or [ and ends on the first later line that closes
// it, in the first column, so that the text between parses.
function jsonDocuments(sourceText) {
  try {
    return [JSON.parse(sourceText)];
  } catch {
    // Not one document; look for documents after a preamble.
  }
  const source = sourceText.split('\n');
  const documents = [];
  for (let start = 0; start < source.length; start += 1) {
    if (!/^[[{]/u.test(source[start])) continue;
    for (let end = start; end < source.length; end += 1) {
      if (!/^[\]}]/u.test(source[end])) continue;
      try {
        documents.push(JSON.parse(source.slice(start, end + 1).join('\n')));
        start = end;
        break;
      } catch {
        // Not closed yet; a nested value can close in the first column too.
      }
    }
  }
  return documents;
}

function* values(value) {
  yield value;
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) yield* values(child);
  }
}

// The first difference between an excerpt object and a candidate that has
// every one of its keys, or null when they agree.
function subsetDifference(excerpt, candidate) {
  for (const key of Object.keys(excerpt)) {
    const difference = firstDifference(excerpt[key], candidate[key], `$.${key}`);
    if (difference) return difference;
  }
  return null;
}

function checkJson(excerptText, sourceText) {
  let excerpt;
  try {
    excerpt = JSON.parse(excerptText);
  } catch (error) {
    return `the page's own block is not JSON: ${error.message}`;
  }
  const documents = jsonDocuments(sourceText);
  if (documents.length === 0) return `it holds no JSON document:\n${indent(lines(sourceText).slice(0, 20))}`;
  const all = documents.flatMap((document) => [...values(document)]);
  if (Array.isArray(excerpt) || excerpt === null || typeof excerpt !== 'object') {
    if (all.some((value) => firstDifference(excerpt, value, '$') === null)) return null;
    return `no value in it equals the excerpt ${describe(excerpt)}`;
  }
  const keys = Object.keys(excerpt);
  const candidates = all.filter(
    (value) => value !== null && typeof value === 'object' && !Array.isArray(value) && keys.every((key) => Object.hasOwn(value, key)),
  );
  if (candidates.length === 0) return `no object in it has the keys ${keys.map((key) => `"${key}"`).join(', ')}`;
  const differences = candidates.map((candidate) => subsetDifference(excerpt, candidate));
  if (differences.includes(null)) return null;
  return `no object in it carries every key of the excerpt with the same value\nclosest: ${differences[0]}`;
}

// Return null when the excerpt is in the source, or a message saying why not.
export function checkExcerpt(format, excerptText, sourceText) {
  return format === 'json' ? checkJson(excerptText, sourceText) : checkText(excerptText, sourceText);
}

// Apply a test-edit block to the file it names, the way a reader edits it.
//
// The page shows the lines around the change, the lines it removes, and the
// lines it adds, without the indentation they sit at in the file: Expressive
// Code strips the indentation a diff block's lines share, so the reader never
// sees it either. The edit therefore matches its lines at any one indentation,
// keeps their indentation relative to each other, and gives the added lines
// the indentation the matched lines had. An edit whose lines appear in more
// than one place, or nowhere, is refused instead of guessed at.

// The indentation `line` sits at beyond `expected`, or undefined when the two
// differ in more than indentation. Blank lines match blank lines.
function extraIndent(line, expected) {
  if (expected.trim() === '') return line.trim() === '' ? '' : undefined;
  if (!line.endsWith(expected)) return undefined;
  const indent = line.slice(0, line.length - expected.length);
  return indent.trim() === '' ? indent : undefined;
}

function matchesAt(lines, start, before) {
  let indent;
  for (let k = 0; k < before.length; k += 1) {
    if (start + k >= lines.length) return undefined;
    const extra = extraIndent(lines[start + k], before[k]);
    if (extra === undefined) return undefined;
    if (before[k].trim() === '') continue;
    if (indent === undefined) indent = extra;
    else if (indent !== extra) return undefined;
  }
  return indent ?? '';
}

// Return { text } with the edit applied, or { error } saying why it was not.
export function applyEdit(fileText, before, after) {
  const lines = fileText.split('\n');
  const matches = [];
  for (let start = 0; start < lines.length; start += 1) {
    const indent = matchesAt(lines, start, before);
    if (indent !== undefined) matches.push({ start, indent });
  }
  if (matches.length === 0) return { error: 'its lines match no place in the file' };
  if (matches.length > 1) {
    return { error: `its lines match ${matches.length} places; show enough surrounding lines to name one` };
  }
  const [{ start, indent }] = matches;
  const replacement = after.map((line) => (line.trim() === '' ? line : `${indent}${line}`));
  lines.splice(start, before.length, ...replacement);
  return { text: lines.join('\n') };
}

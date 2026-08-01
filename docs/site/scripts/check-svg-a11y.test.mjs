import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { test } from 'node:test';

import {
  contrastRatio,
  DIAGRAM_SURFACE,
  extractTextFillColors,
  MIN_TEXT_CONTRAST,
  svgAccessibilityErrors,
  svgContrastErrors,
} from './check-svg-a11y.mjs';

test('contrastRatio matches known WCAG reference values', () => {
  assert.equal(contrastRatio('#000000', '#ffffff'), 21);
  assert.equal(contrastRatio('#ffffff', '#ffffff'), 1);
  // Order of the two colors must not matter.
  assert.equal(contrastRatio('#161616', '#ffffff'), contrastRatio('#ffffff', '#161616'));
});

test('extractTextFillColors resolves inline, class-based, and inherited <g> fills', () => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <style>.mono { fill: #6a6a6a; }</style>
    <text x="0" y="0" fill="#161616">inline</text>
    <text x="0" y="0" class="mono">classed</text>
    <g fill="#3a3a3a">
      <text x="0" y="0">inherited</text>
    </g>
  </svg>`;
  const { colors, unresolved } = extractTextFillColors(svg);
  assert.deepEqual([...colors].sort(), ['#161616', '#3a3a3a', '#6a6a6a']);
  assert.equal(unresolved, 0);
});

test('extractTextFillColors reports unresolved fills instead of guessing', () => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <text x="0" y="0">no fill anywhere</text>
  </svg>`;
  const { colors, unresolved } = extractTextFillColors(svg);
  assert.deepEqual(colors, []);
  assert.equal(unresolved, 1);
});

test('svgContrastErrors excludes pure white text (reverse text on a colored chip)', () => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <rect fill="#000091" width="10" height="10"/>
    <text x="0" y="0" fill="#ffffff">DCI-NATIVE</text>
  </svg>`;
  assert.deepEqual(svgContrastErrors('fixture.svg', svg), []);
});

test('svgContrastErrors flags text that fails the 4.5:1 threshold against the fixed surface', () => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <text x="0" y="0" fill="#cccccc">low contrast</text>
  </svg>`;
  const errors = svgContrastErrors('fixture.svg', svg);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /fixture\.svg text fill #cccccc has \d+\.\d\d:1 contrast/);
  const ratio = contrastRatio('#cccccc', DIAGRAM_SURFACE);
  assert.ok(ratio < MIN_TEXT_CONTRAST, 'fixture color must actually be below the threshold');
});

test('svgAccessibilityErrors reports missing title/desc/role and missing files', async (t) => {
  const root = mkdtempSync(resolve(tmpdir(), 'registry-svg-a11y-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(root, { recursive: true });
  writeFileSync(
    resolve(root, 'registry-family-map.svg'),
    '<svg xmlns="http://www.w3.org/2000/svg"><text fill="#161616">no title, desc, or role</text></svg>',
  );
  const errors = await svgAccessibilityErrors(root);

  assert.ok(errors.some((e) => e.endsWith('registry-family-map.svg missing <title>')));
  assert.ok(errors.some((e) => e.endsWith('registry-family-map.svg missing <desc>')));
  assert.ok(errors.some((e) => e.endsWith('registry-family-map.svg missing role="img"')));
  assert.ok(errors.includes('public/images/registry-architecture-flow.svg is missing'));
});

test('the checked-in diagrams all clear the 4.5:1 text contrast floor', async () => {
  assert.deepEqual(await svgAccessibilityErrors(), []);
});

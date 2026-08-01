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

test('white text with no chip behind it is reported, not exempted', () => {
  // The blanket white exemption used to pass this at 1:1 against the canvas.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <text x="0" y="0" fill="#ffffff">stray label on the canvas</text>
  </svg>`;
  const errors = svgContrastErrors('fixture.svg', svg);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /reverse text/);
});

test('white text on a white shape is reported', () => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <rect fill="#ffffff" width="10" height="10"/>
    <text x="0" y="0" fill="#ffffff">invisible</text>
  </svg>`;
  assert.equal(svgContrastErrors('fixture.svg', svg).length, 1);
});

test('white text is scored against the chip it sits on, not the canvas', () => {
  // #767676 on white is 4.54:1, but white ON #767676 is the same ratio, so a
  // chip that is too light for reverse text must still fail.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <rect fill="#bbbbbb" width="10" height="10"/>
    <text x="0" y="0" fill="#ffffff">too light a chip</text>
  </svg>`;
  const errors = svgContrastErrors('fixture.svg', svg);
  assert.equal(errors.length, 1, '#ffffff on #bbbbbb is 1.98:1');
  assert.match(errors[0], /#bbbbbb/);
});

test('a non-hex declaration later in the rule wins over an earlier hex one', () => {
  // Interaction of the last-declaration rule with the unscoreable-color rule:
  // reading hex declarations only would retain #161616 and miss that the
  // element actually renders white.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <style>.label { fill: #161616; fill: white; }</style>
    <text class="label">renders white</text>
  </svg>`;
  const errors = svgContrastErrors('fixture.svg', svg);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /cannot be scored/);
  assert.match(errors[0], /white/);
});

test('multiple classes resolve by stylesheet order, not class-attribute order', () => {
  // Every selector this parser handles is a single class, so specificity is
  // equal and the later rule wins regardless of how the names are written.
  const style = '<style>.safe { fill: #161616; } .danger { fill: #cccccc; }</style>';
  for (const classAttr of ['safe danger', 'danger safe']) {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
      <title>t</title><desc>d</desc>
      ${style}
      <text class="${classAttr}">two classes</text>
    </svg>`;
    assert.deepEqual(
      extractTextFillColors(svg).colors,
      ['#cccccc'],
      `class="${classAttr}" must resolve to the later rule`,
    );
    assert.equal(svgContrastErrors('fixture.svg', svg).length, 1);
  }
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

test('class fills are resolved from every <style> block, not just the first', () => {
  // Editors can emit more than one <style> element. Resolving only the first
  // left later blocks' rules unresolved and their content unstripped.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <style>.first { fill: #161616; }</style>
    <style>.second { fill: #cccccc; }</style>
    <text class="first">resolved by the first block</text>
    <text class="second">resolved by the second block</text>
  </svg>`;

  const { colors, unresolved } = extractTextFillColors(svg);
  assert.equal(unresolved, 0, 'both class fills must resolve');
  assert.deepEqual(colors.sort(), ['#161616', '#cccccc']);

  const errors = svgContrastErrors('two-style.svg', svg);
  assert.equal(errors.length, 1, 'only the low-contrast fill should fail');
  assert.match(errors[0], /#cccccc/);
});

test('style regions are skipped without rewriting the document', () => {
  // Deleting <style> blocks by substring replacement can splice the
  // surrounding text into a fresh `<style`, leaving behind exactly what the
  // deletion was meant to remove. Skipping the region during the walk cannot,
  // so a <text> element after such a sequence is still scanned normally.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <style>.a { fill: #161616; }</style>
    <text class="a">after the style block</text>
  </svg>`;

  const { colors, unresolved } = extractTextFillColors(svg);
  assert.equal(unresolved, 0);
  assert.deepEqual(colors, ['#161616'], 'CSS fill declarations must not count as painted text');
  assert.deepEqual(svgContrastErrors('skip.svg', svg), []);
});

test('fills that cannot be scored are reported, never treated as passing', () => {
  // A non-finite ratio compares false against the threshold, so an unparsed
  // fill used to slip through the gate silently. Each of these is a valid SVG
  // paint value that the hex math cannot score.
  const unscoreable = [
    ['white', 'named color'],
    ['rgb(255,255,255)', 'functional notation'],
    ['currentColor', 'keyword'],
    ['none', 'invisible text'],
    ['#0000', 'four-digit hex carrying alpha'],
    ['#00000080', 'eight-digit hex carrying alpha'],
  ];

  for (const [fill, why] of unscoreable) {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
      <title>t</title><desc>d</desc>
      <text fill="${fill}">${why}</text>
    </svg>`;
    const errors = svgContrastErrors('fixture.svg', svg);
    assert.equal(errors.length, 1, `${fill} (${why}) must produce exactly one error`);
    assert.match(errors[0], /cannot be scored/, `${fill} must be reported as unscoreable`);
    assert.ok(errors[0].includes(fill), `the error must name the offending value, got: ${errors[0]}`);
  }
});

test('a translucent black fill is not scored as opaque black', () => {
  // #00000080 truncated to its first six digits reads as pure black and would
  // score 21:1, the maximum, despite being half transparent.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <text fill="#00000080">half transparent</text>
  </svg>`;
  assert.deepEqual(svgContrastErrors('fixture.svg', svg).length, 1);
});

test('the last fill declaration in a rule wins, as CSS applies it', () => {
  // A rule may declare fill more than once; the browser paints the last one.
  // Reading the first would score a color the reader never sees, and the
  // failure direction that matters is a legible fill masking an illegible one.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <style>.label { fill: #161616; fill: #cccccc; }</style>
    <text class="label">overridden</text>
  </svg>`;

  const { colors } = extractTextFillColors(svg);
  assert.deepEqual(colors, ['#cccccc'], 'the effective fill is the last declaration');

  const errors = svgContrastErrors('fixture.svg', svg);
  assert.equal(errors.length, 1, '#cccccc on white is 1.61:1 and must be reported');
  assert.match(errors[0], /#cccccc/);
});

test('a later rule still overrides an earlier one for the same class', () => {
  // Guards the sibling precedence rule while the within-rule fix is made:
  // equally specific selectors resolve in source order, last wins.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <style>.label { fill: #cccccc; }</style>
    <style>.label { fill: #161616; }</style>
    <text class="label">overridden</text>
  </svg>`;
  assert.deepEqual(extractTextFillColors(svg).colors, ['#161616']);
  assert.deepEqual(svgContrastErrors('fixture.svg', svg), []);
});

test('contrastRatio throws rather than returning NaN for an unscoreable color', () => {
  assert.throws(() => contrastRatio('white', DIAGRAM_SURFACE), /white/);
  assert.throws(() => contrastRatio('#0000', DIAGRAM_SURFACE), /#0000/);
  assert.ok(Number.isFinite(contrastRatio('#abc', DIAGRAM_SURFACE)), '#rgb shorthand stays supported');
});

test('shorthand and long spellings of one color resolve to one entry', () => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <text fill="#000">short</text>
    <text fill="#000000">long</text>
  </svg>`;
  assert.deepEqual(extractTextFillColors(svg).colors, ['#000000']);
});

test('shorthand white on a dark chip is reverse text, not a 1:1 failure', () => {
  // #fff and #ffffff paint the same pixels. Comparing the authored spelling
  // against DIAGRAM_SURFACE by equality missed the shorthand, so a legible
  // diagram was rejected at 1:1 against a canvas it never sits on.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <rect x="0" y="0" width="10" height="10" fill="#000091"/>
    <text fill="#fff">DCI-NATIVE</text>
  </svg>`;
  assert.deepEqual(svgContrastErrors('fixture.svg', svg), []);
});

test('a class rule beats a presentation fill attribute, as CSS applies it', () => {
  // A `fill` attribute is a presentation attribute, not an inline style: any
  // matching CSS rule outranks it. Preferring the attribute scored a color the
  // reader never sees and let the rendered low-contrast text through.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <style>.faint { fill: #cccccc; }</style>
    <text class="faint" fill="#161616">rendered faint</text>
  </svg>`;
  assert.deepEqual(extractTextFillColors(svg).colors, ['#cccccc']);
  const errors = svgContrastErrors('fixture.svg', svg);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /#cccccc/);
});

test('a presentation fill still beats a fill inherited from an enclosing group', () => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <g fill="#cccccc"><text fill="#161616">legible</text></g>
  </svg>`;
  assert.deepEqual(svgContrastErrors('fixture.svg', svg), []);
});

test('a tspan fill override is scored, not masked by its parent text fill', () => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <text fill="#161616">legible <tspan fill="#cccccc">faint</tspan></text>
  </svg>`;
  const errors = svgContrastErrors('fixture.svg', svg);
  assert.equal(errors.length, 1, 'the tspan paints the glyphs the reader sees');
  assert.match(errors[0], /#cccccc/);
});

test('a tspan with no fill of its own is neither rescored nor counted unresolved', () => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <text fill="#161616">legible <tspan>same color</tspan></text>
  </svg>`;
  const { colors, unresolved } = extractTextFillColors(svg);
  assert.deepEqual(colors, ['#161616']);
  assert.equal(unresolved, 0, 'the tspan inherits a fill its parent already resolved');
});

test('a white tspan is scored against the chip its text sits on', () => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <rect x="0" y="0" width="10" height="10" fill="#000091"/>
    <text fill="#161616"><tspan fill="#ffffff">reverse</tspan></text>
  </svg>`;
  assert.deepEqual(svgContrastErrors('fixture.svg', svg), []);
});

test('an inline style fill beats both a class rule and a presentation attribute', () => {
  // Inline style is the highest author-level declaration: it outranks a class
  // rule, which in turn outranks the `fill` presentation attribute.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <style>.safe { fill: #161616; }</style>
    <text class="safe" fill="#161616" style="fill:#cccccc">rendered faint</text>
  </svg>`;
  assert.deepEqual(extractTextFillColors(svg).colors, ['#cccccc']);
  const errors = svgContrastErrors('fixture.svg', svg);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /#cccccc/);
});

test('an inline style declaring fill twice resolves to the last declaration', () => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <text style="fill:#161616;font-size:12px;fill:#cccccc">overridden</text>
  </svg>`;
  assert.deepEqual(extractTextFillColors(svg).colors, ['#cccccc']);
});

test('an inline style without a fill falls through to the class rule', () => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <style>.safe { fill: #161616; }</style>
    <text class="safe" style="font-size:12px">legible</text>
  </svg>`;
  assert.deepEqual(svgContrastErrors('fixture.svg', svg), []);
});

test('reverse text is not scored against a shape it does not immediately follow', () => {
  // A single global "last shape seen" let an unrelated earlier swatch stand in
  // as a backdrop for a stray white label anywhere later in the document.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" role="img">
    <title>t</title><desc>d</desc>
    <rect x="0" y="0" width="10" height="10" fill="#000091"/>
    <text fill="#ffffff">on the chip</text>
    <text fill="#ffffff">stray, on the canvas</text>
  </svg>`;
  const errors = svgContrastErrors('fixture.svg', svg);
  assert.equal(errors.length, 1, 'only the label adjacent to the chip has a backdrop');
  assert.match(errors[0], /no shape/);
});

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Regression for https://github.com/registrystack/registry-stack/issues/291:
// the diagram SVGs under public/images/ bake in a light-only ink palette on a
// transparent canvas, so whatever background sits behind them in the page
// must stay light in both themes. This reads custom.css as text (no
// stylesheet engine involved) and checks the actual cascade a browser would
// compute, rather than trusting a single declaration.

const here = dirname(fileURLToPath(import.meta.url));
const cssPath = resolve(here, '../src/styles/custom.css');
const css = readFileSync(cssPath, 'utf8');

// Returns the { ... } body opened by the brace at `openBraceIndex`, using
// brace-depth counting so nested rules (there are none here, but custom.css
// is hand-written CSS, not a controlled grammar) cannot confuse the scan.
function blockBodyAt(source, openBraceIndex) {
  assert.equal(source[openBraceIndex], '{', 'openBraceIndex must point at a "{"');
  let depth = 1;
  let index = openBraceIndex + 1;
  while (depth > 0) {
    assert.ok(index < source.length, 'unterminated CSS block');
    if (source[index] === '{') depth += 1;
    else if (source[index] === '}') depth -= 1;
    index += 1;
  }
  return source.slice(openBraceIndex + 1, index - 1);
}

function customProperties(blockBody) {
  const props = new Map();
  for (const [, name, value] of blockBody.matchAll(/--([\w-]+):\s*([^;]+);/g)) {
    props.set(name, value.trim());
  }
  return props;
}

// Only the unindented, top-level `:root[data-theme='dark']` selector lines
// matter here: the shared default block lists it as the last of three
// comma-separated selectors, and the real dark override repeats it alone
// later in the file. Both media-query blocks that also touch this selector
// (mobile nav sizing) are indented, so this anchored pattern skips them.
const rootDarkSelectorLines = [...css.matchAll(/^:root\[data-theme='dark'\] \{$/gm)];
assert.equal(
  rootDarkSelectorLines.length,
  2,
  'expected exactly one shared :root block and one dark-theme override block',
);
const [sharedSelectorMatch, darkOverrideSelectorMatch] = rootDarkSelectorLines;

const sharedProps = customProperties(
  blockBodyAt(css, sharedSelectorMatch.index + sharedSelectorMatch[0].length - 1),
);
const darkOverrideProps = customProperties(
  blockBodyAt(css, darkOverrideSelectorMatch.index + darkOverrideSelectorMatch[0].length - 1),
);

// The value a browser resolves for `--name` under [data-theme='dark']: the
// override block wins when it redefines the property, otherwise the shared
// default cascades through unchanged.
function resolvedDarkValue(name) {
  return darkOverrideProps.get(name) ?? sharedProps.get(name);
}

function hexToRgb(hex) {
  const match = /^#([0-9a-f]{6})$/i.exec(hex);
  assert.ok(match, `expected a 6-digit hex color, got "${hex}"`);
  const int = Number.parseInt(match[1], 16);
  return { r: (int >> 16) & 0xff, g: (int >> 8) & 0xff, b: int & 0xff };
}

function srgbToLinear(channel) {
  const c = channel / 255;
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

function relativeLuminance(hex) {
  const { r, g, b } = hexToRgb(hex);
  return 0.2126 * srgbToLinear(r) + 0.7152 * srgbToLinear(g) + 0.0722 * srgbToLinear(b);
}

// WCAG 2 contrast ratio, https://www.w3.org/TR/WCAG21/#contrast-minimum.
function contrastRatio(hexA, hexB) {
  const lighter = Math.max(relativeLuminance(hexA), relativeLuminance(hexB));
  const darker = Math.min(relativeLuminance(hexA), relativeLuminance(hexB));
  return (lighter + 0.05) / (darker + 0.05);
}

// The ink colors the diagram SVGs draw with (public/images/*.svg), not CSS
// tokens: the artwork hardcodes these hex values directly rather than
// reading a custom property, so they are constants here too.
const diagramInk = {
  ink: '#161616',
  body: '#3a3a3a',
  muted: '#6a6a6a',
  accent: '#000091',
};

const AA_NORMAL_TEXT = 4.5;

// Find the declaration that actually paints the SVG diagrams' backing
// surface, so this test fails if a future edit repoints it at a
// theme-following token again instead of only checking today's token name.
const diagramRuleMatch = /\.sl-markdown-content img\[src\$='\.svg'\][^{]*\{([^}]*)\}/.exec(css);
assert.ok(diagramRuleMatch, 'expected a dedicated background rule for SVG diagram images');
const diagramBackgroundVar = /background:\s*var\(--([\w-]+)\)/.exec(diagramRuleMatch[1])?.[1];
assert.ok(diagramBackgroundVar, 'expected the SVG diagram rule to set background from a custom property');

test('SVG diagram background stays a fixed hex value in both themes', () => {
  const lightValue = sharedProps.get(diagramBackgroundVar);
  const darkValue = resolvedDarkValue(diagramBackgroundVar);
  assert.ok(lightValue, `--${diagramBackgroundVar} must be defined in the shared :root block`);
  assert.equal(
    darkValue,
    lightValue,
    `--${diagramBackgroundVar} must not repoint under [data-theme='dark'] (light: ${lightValue}, dark: ${darkValue})`,
  );
});

for (const [label, hex] of Object.entries(diagramInk)) {
  test(`diagram ${label} ink clears WCAG AA against the diagram surface in dark mode`, () => {
    const surface = resolvedDarkValue(diagramBackgroundVar);
    const ratio = contrastRatio(hex, surface);
    assert.ok(
      ratio >= AA_NORMAL_TEXT,
      `${label} (${hex}) on dark-mode diagram surface (${surface}) is ${ratio.toFixed(2)}:1, below WCAG AA ${AA_NORMAL_TEXT}:1`,
    );
  });
}

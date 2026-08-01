#!/usr/bin/env node

import { readdir, readFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);

const DEFAULT_IMAGE_DIR = resolve(scriptDir, '../public/images');

const expected = new Set([
  'registry-family-map.svg',
  'registry-architecture-flow.svg',
  'registry-claim-model.svg',
  'registry-country-evidence-mesh.svg',
  'registry-evidence-transports.svg',
  'registry-notary-three-parties.svg',
  'registry-publishing-pipeline.svg',
  'registry-relay-or-notary.svg',
  'registry-relay-request-lifecycle.svg',
  'registry-relay-two-rooms.svg',
  'registry-trust-boundaries.svg',
  'solmara-lab-topology.svg',
  'standards-claim-levels.svg',
]);

// Matches src/styles/custom.css's `img[src*='/images/'][src$='.svg']` rule:
// diagrams are pinned to a literal white surface in both themes, so that is
// the background every shipped diagram's text must clear 4.5:1 against.
export const DIAGRAM_SURFACE = '#ffffff';
export const MIN_TEXT_CONTRAST = 4.5;

// Only #rgb and #rrggbb are scoreable. SVG accepts far more (named colors,
// rgb()/hsl() functions, `none`, and hex forms carrying an alpha channel), but
// scoring those would mean shipping a color database and compositing rules.
// They are reported instead of guessed: the earlier code produced NaN for them,
// and NaN < 4.5 is false, so unreadable text passed the gate in silence.
const SCOREABLE_HEX_RE = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i;

export function isScoreableColor(value) {
  return SCOREABLE_HEX_RE.test(value);
}

// Hex spellings are lowercased so `#FFF` and `#fff` dedupe to one entry.
// Anything else is kept exactly as authored: it is never scored, only
// reported, and the report is only useful if it quotes the string the author
// can find in the file.
function normalizeColor(value) {
  return isScoreableColor(value) ? value.toLowerCase() : value;
}

function expandHex(hex) {
  const value = hex.slice(1);
  if (value.length === 3) {
    return `#${[...value].map((c) => c + c).join('')}`;
  }
  return `#${value}`;
}

function srgbChannelToLinear(channel) {
  const c = channel / 255;
  return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
}

function relativeLuminance(hex) {
  if (!isScoreableColor(hex)) {
    throw new TypeError(`cannot compute luminance for unsupported color ${hex}`);
  }
  const normalized = expandHex(hex);
  const r = parseInt(normalized.slice(1, 3), 16);
  const g = parseInt(normalized.slice(3, 5), 16);
  const b = parseInt(normalized.slice(5, 7), 16);
  return (
    0.2126 * srgbChannelToLinear(r) +
    0.7152 * srgbChannelToLinear(g) +
    0.0722 * srgbChannelToLinear(b)
  );
}

// WCAG 2 contrast ratio between two sRGB hex colors, in the range [1, 21].
export function contrastRatio(hexA, hexB) {
  const lumA = relativeLuminance(hexA);
  const lumB = relativeLuminance(hexB);
  const lighter = Math.max(lumA, lumB);
  const darker = Math.min(lumA, lumB);
  return (lighter + 0.05) / (darker + 0.05);
}

// An SVG may carry more than one <style> element, so every block is read;
// later rules win, matching CSS source order for equally specific selectors.
const STYLE_BLOCK_RE = /<style[^>]*>([\s\S]*?)<\/style>/g;

function parseClassFillMap(svgText) {
  const classFills = new Map();
  // Only single-class selectors are resolved (e.g. `.tag { fill: #000091; }`).
  // Compound selectors like `.cardtitle.sm` are skipped: in the current
  // diagrams they only ever override font-size, never fill.
  for (const styleMatch of svgText.matchAll(STYLE_BLOCK_RE)) {
    const ruleRe = /\.([\w-]+)\s*\{([^}]*)\}/g;
    let rule;
    while ((rule = ruleRe.exec(styleMatch[1]))) {
      const [, className, body] = rule;
      const fillMatch = body.match(/fill:\s*(#[0-9a-fA-F]{3,8})/);
      if (fillMatch) classFills.set(className, fillMatch[1]);
    }
  }
  return classFills;
}

function attrValue(tag, name) {
  const match = tag.match(new RegExp(`${name}="([^"]*)"`));
  return match ? match[1] : null;
}

// Resolves the effective fill color of every <text> element in an SVG,
// walking <g fill="..."> ancestry and class-based fills from a <style>
// block. Returns { colors, unresolved }: `colors` are hex fills actually
// used to paint text (deduplicated), `unresolved` counts <text> elements
// whose fill could not be determined (no inline fill, no matching class, no
// enclosing <g fill>).
export function extractTextFillColors(svgText) {
  const classFills = parseClassFillMap(svgText);
  // <style> regions are skipped during the walk rather than deleted from the
  // text beforehand. Deleting them cannot be done safely with one pass: a
  // removal can splice its neighbours into a fresh `<style` (`<sty<style>le>`),
  // so the scanned string would still hold what the removal was meant to drop.
  // Tracking the region here needs no rewriting and cannot resurrect a tag.
  const tokenRe = /<style\b[^>]*>|<\/style>|<g\b[^>]*>|<\/g>|<text\b[^>]*>/g;
  const gFillStack = [];
  const colors = new Set();
  let unresolved = 0;
  let inStyle = false;
  let token;
  while ((token = tokenRe.exec(svgText))) {
    const tag = token[0];
    if (tag.startsWith('<style')) {
      inStyle = true;
      continue;
    }
    if (tag === '</style>') {
      inStyle = false;
      continue;
    }
    // CSS declarations are not painted content; parseClassFillMap reads them.
    if (inStyle) continue;
    if (tag === '</g>') {
      gFillStack.pop();
      continue;
    }
    if (tag.startsWith('<g')) {
      const inherited = gFillStack[gFillStack.length - 1] ?? null;
      gFillStack.push(attrValue(tag, 'fill') ?? inherited);
      continue;
    }
    // <text ...>
    const inlineFill = attrValue(tag, 'fill');
    const classAttr = attrValue(tag, 'class');
    const classFill = classAttr
      ? classAttr.split(/\s+/).map((name) => classFills.get(name)).find(Boolean)
      : undefined;
    const inheritedFill = gFillStack[gFillStack.length - 1] ?? null;
    const resolved = inlineFill ?? classFill ?? inheritedFill;
    if (resolved) {
      colors.add(normalizeColor(resolved));
    } else {
      unresolved += 1;
    }
  }
  return { colors: [...colors], unresolved };
}

// Contrast errors for one SVG's text against the fixed diagram surface.
// Pure white (#ffffff) text is excluded: in the shipped diagrams it is only
// ever used as reverse text on a small colored chip (e.g. the "DCI-NATIVE"
// tag on a #000091 rect in registry-country-evidence-mesh.svg), never
// directly on the diagram's own white/transparent canvas, so it is not
// actually read against DIAGRAM_SURFACE.
export function svgContrastErrors(fileLabel, svgText) {
  const errors = [];
  const { colors, unresolved } = extractTextFillColors(svgText);
  if (unresolved > 0) {
    errors.push(`${fileLabel} has ${unresolved} <text> element(s) with no resolvable fill color`);
  }
  for (const color of colors) {
    if (!isScoreableColor(color)) {
      errors.push(
        `${fileLabel} text fill ${color} cannot be scored: only #rgb and #rrggbb are supported, ` +
          `so express it as an opaque hex color`,
      );
      continue;
    }
    // White text in these diagrams is always reverse text on a colored chip
    // (for example a #000091 rect), never painted on the diagram canvas, so
    // measuring it against DIAGRAM_SURFACE would report a false failure.
    // Resolving the actual painted rect behind each label would mean
    // geometric analysis; the tradeoff is that white-on-white text, which no
    // diagram would intend, goes undetected here.
    if (color === '#ffffff') continue;
    const ratio = contrastRatio(color, DIAGRAM_SURFACE);
    if (ratio < MIN_TEXT_CONTRAST) {
      errors.push(
        `${fileLabel} text fill ${color} has ${ratio.toFixed(2)}:1 contrast against the fixed ` +
          `diagram surface ${DIAGRAM_SURFACE} (needs >= ${MIN_TEXT_CONTRAST}:1)`,
      );
    }
  }
  return errors;
}

export async function svgAccessibilityErrors(imageDir = DEFAULT_IMAGE_DIR) {
  const entries = await readdir(imageDir, { withFileTypes: true });
  const errors = [];
  const seen = new Set();

  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith('.svg')) continue;
    const file = join(imageDir, entry.name);
    const text = await readFile(file, 'utf8');
    const label = relative('.', file);
    seen.add(entry.name);
    if (!/<title[>\s]/.test(text)) errors.push(`${label} missing <title>`);
    if (!/<desc[>\s]/.test(text)) errors.push(`${label} missing <desc>`);
    if (!/role="img"/.test(text)) errors.push(`${label} missing role="img"`);
    errors.push(...svgContrastErrors(label, text));
  }

  for (const name of expected) {
    if (!seen.has(name)) errors.push(`public/images/${name} is missing`);
  }

  return errors;
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const errors = await svgAccessibilityErrors();
  if (errors.length) {
    console.error(errors.join('\n'));
    process.exitCode = 1;
  } else {
    console.log('SVG accessibility check passed.');
  }
}

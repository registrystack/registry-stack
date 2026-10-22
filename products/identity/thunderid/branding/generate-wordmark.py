#!/usr/bin/env python3
"""Generate the Registry Stack wordmark from the bundled Public Sans font."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path

import uharfbuzz as hb
from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont


TEXT = "Registry Stack"
WEIGHT = 700
FILL = "#173b7a"
DISPLAY_WIDTH = 224
FONT_SHA256 = "5ed4d31c988e73b258894244f209069ebe77dc7e564861954b21198b6de90d68"

ROOT = Path(__file__).resolve().parent
FONT_PATH = ROOT / "assets/fonts/public-sans-latin-wght-normal.woff2"
OUTPUT_PATH = ROOT / "assets/registry-stack-wordmark.svg"


def format_number(value: float) -> str:
    rounded = round(value, 3)
    if rounded == 0:
        return "0"
    return f"{rounded:.3f}".rstrip("0").rstrip(".")


def main() -> None:
    font_bytes = FONT_PATH.read_bytes()
    digest = hashlib.sha256(font_bytes).hexdigest()
    if digest != FONT_SHA256:
        raise SystemExit(f"unexpected Public Sans font digest: {digest}")

    variable_font = TTFont(io.BytesIO(font_bytes))
    font = instantiateVariableFont(variable_font, {"wght": WEIGHT}, inplace=False)
    font.flavor = None

    sfnt = io.BytesIO()
    font.save(sfnt, reorderTables=False)
    face = hb.Face(sfnt.getvalue())
    shaping_font = hb.Font(face)
    hb.ot_font_set_funcs(shaping_font)
    units_per_em = font["head"].unitsPerEm
    shaping_font.scale = (units_per_em, units_per_em)

    buffer = hb.Buffer()
    buffer.add_str(TEXT)
    buffer.guess_segment_properties()
    hb.shape(shaping_font, buffer, {"kern": True})

    glyph_set = font.getGlyphSet()
    glyph_order = font.getGlyphOrder()
    positioned_glyphs: list[tuple[str, float, float]] = []
    bounds: tuple[float, float, float, float] | None = None
    cursor_x = 0.0
    cursor_y = 0.0

    for info, position in zip(buffer.glyph_infos, buffer.glyph_positions, strict=True):
        glyph_name = glyph_order[info.codepoint]
        x = cursor_x + position.x_offset
        y = cursor_y + position.y_offset
        positioned_glyphs.append((glyph_name, x, y))

        bounds_pen = BoundsPen(glyph_set)
        transform = TransformPen(bounds_pen, (1, 0, 0, 1, x, y))
        glyph_set[glyph_name].draw(transform)
        if bounds_pen.bounds is not None:
            if bounds is None:
                bounds = bounds_pen.bounds
            else:
                bounds = (
                    min(bounds[0], bounds_pen.bounds[0]),
                    min(bounds[1], bounds_pen.bounds[1]),
                    max(bounds[2], bounds_pen.bounds[2]),
                    max(bounds[3], bounds_pen.bounds[3]),
                )

        cursor_x += position.x_advance
        cursor_y += position.y_advance

    if bounds is None:
        raise SystemExit("wordmark has no drawable glyphs")

    min_x, min_y, max_x, max_y = bounds
    width = max_x - min_x
    height = max_y - min_y
    display_height = DISPLAY_WIDTH * height / width

    path_pen = SVGPathPen(glyph_set)
    for glyph_name, x, y in positioned_glyphs:
        transform = TransformPen(path_pen, (1, 0, 0, -1, x - min_x, max_y - y))
        glyph_set[glyph_name].draw(transform)

    svg = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{DISPLAY_WIDTH}" '
        f'height="{format_number(display_height)}" '
        f'viewBox="0 0 {format_number(width)} {format_number(height)}" '
        'role="img" aria-labelledby="wordmark-title">\n'
        f'  <title id="wordmark-title">{TEXT}</title>\n'
        f'  <path fill="{FILL}" d="{path_pen.getCommands()}"/>\n'
        '</svg>\n'
    )
    OUTPUT_PATH.write_text(svg, encoding="utf-8")


if __name__ == "__main__":
    main()

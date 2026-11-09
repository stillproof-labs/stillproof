"""Draws the Stillproof mark and wordmark from Gloock's outlines (docs/DESIGN.md).

    python brand/make.py path/to/Gloock-Regular.ttf OUT_DIR

The mark is the Gloock "S" and a safelight full stop: the moment is fixed.
"""
import sys, os
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.transformPen import TransformPen

FONT = sys.argv[1]; OUT = sys.argv[2]
f = TTFont(FONT); gs = f.getGlyphSet(); cmap = f.getBestCmap(); upm = f['head'].unitsPerEm
INK, PAPER, SAFE = '#0F0E0C', '#EDE6D6', '#F2A33A'
PRINT_BG, PRINT_INK, PRINT_SAFE = '#F3EEE3', '#15130F', '#B8651A'

def glyph(ch): return cmap[ord(ch)]
def bounds(name):
    b = BoundsPen(gs); gs[name].draw(b); return b.bounds  # xmin,ymin,xmax,ymax
def path(name, scale, dx, dy):
    # font units (y up) -> svg (y down)
    p = SVGPathPen(gs)
    t = TransformPen(p, (scale, 0, 0, -scale, dx, dy))
    gs[name].draw(t)
    return p.getCommands()

def r(x): return round(x, 2)

# ---- mark: S plus a full stop, centred as a group in a square
def mark(size, bg, fg, dot, pad=0.0, radius=None, capfrac=0.56):
    S = glyph('S'); x0, y0, x1, y1 = bounds(S)
    h = y1 - y0
    cap = size * capfrac                  # S cap height in px
    k = cap / h
    dotd = cap * 0.22                     # full-stop diameter
    gap = cap * 0.07
    w = (x1 - x0) * k + gap + dotd        # group width
    gx = (size - w) / 2                   # group left
    base = size / 2 + cap / 2             # S baseline-ish: bottom of S at centre + cap/2
    d = path(S, k, gx - x0 * k, base + y0 * k)
    cx = gx + (x1 - x0) * k + gap + dotd / 2
    cy = base - dotd / 2
    rect = '' if bg is None else f'<rect width="{size}" height="{size}" rx="{r(radius if radius is not None else 0)}" fill="{bg}"/>'
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" width="{size}" height="{size}">'
            f'{rect}<path d="{d}" fill="{fg}"/><circle cx="{r(cx)}" cy="{r(cy)}" r="{r(dotd/2)}" fill="{dot}"/></svg>')

# ---- wordmark: "Stillproof" plus full stop, Gloock outlines, advance widths
def wordmark(fg, dot, height=120):
    hmtx = f['hmtx']; asc = f['hhea'].ascent; desc = -f['hhea'].descent
    capH = bounds(glyph('S'))[3] - bounds(glyph('S'))[1]
    k = (height * 0.62) / capH
    base = height * 0.80
    x = height * 0.06; parts = []
    kern = {}
    for ch in 'Stillproof':
        g = glyph(ch)
        parts.append(path(g, k, x, base))
        x += hmtx[g][0] * k
    dotd = height * 0.62 * 0.22
    x += dotd * 0.35
    parts_d = ' '.join(parts)
    cx = x + dotd / 2; cy = base - dotd / 2
    W = cx + dotd / 2 + height * 0.06
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {r(W)} {height}" width="{r(W)}" height="{height}">'
            f'<path d="{parts_d}" fill="{fg}"/><circle cx="{r(cx)}" cy="{r(cy)}" r="{r(dotd/2)}" fill="{dot}"/></svg>')

os.makedirs(OUT, exist_ok=True)
w = lambda n, s: open(os.path.join(OUT, n), 'w', encoding='utf-8', newline='\n').write(s + '\n')
w('mark.svg', mark(512, INK, PAPER, SAFE, radius=0))
w('mark-print.svg', mark(512, PRINT_BG, PRINT_INK, PRINT_SAFE, radius=0))
w('mark-transparent.svg', mark(512, None, PAPER, SAFE))
w('mark-mono.svg', mark(512, None, '#000000', '#000000'))
# Android adaptive icon layers: the art must sit in the central 66% safe zone.
w('android-foreground.svg', mark(512, None, PAPER, SAFE, capfrac=0.40))
w('android-monochrome.svg', mark(432, None, '#000000', '#000000', capfrac=0.40))
w('android-background.svg', f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512"><rect width="512" height="512" fill="{INK}"/></svg>')
# Favicon: fill more of the square so it reads at 16 px.
w('favicon.svg', mark(64, INK, PAPER, SAFE, radius=8, capfrac=0.70))
w('wordmark.svg', wordmark(PAPER, SAFE))
w('wordmark-print.svg', wordmark(PRINT_INK, PRINT_SAFE))
print('ok', upm)

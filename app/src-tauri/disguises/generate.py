#!/usr/bin/env python3
"""Generate the disguise icons (Settings → Privacy → Disguise).

Run from anywhere:  python3 app/src-tauri/disguises/generate.py
Needs Pillow (pip install pillow). Outputs are committed; re-run only when
the artwork changes.

The names and pictures are invented for this app and drawn here from simple
shapes; none imitates a real product, vendor or brand. `browser-vault.icns`
is the normal app icon (from ../icons/icon.png) so "None" can switch back.

The .icns container is written by hand: 'icns' + u32 total length, then
entries of (4-byte type, u32 length incl. the 8-byte header, PNG data) with
ic07/ic08/ic09/ic10 = 128/256/512/1024 px.
"""
import io
import os
import struct

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
ICONS = os.path.join(os.path.dirname(HERE), "icons")
SIZE = 1024
SS = 2  # supersampling

TYPES = (("ic07", 128), ("ic08", 256), ("ic09", 512), ("ic10", 1024))


def write_icns(img, path):
    entries = b""
    for kind, px in TYPES:
        buf = io.BytesIO()
        img.resize((px, px), Image.LANCZOS).save(buf, format="PNG")
        data = buf.getvalue()
        entries += kind.encode("ascii") + struct.pack(">I", len(data) + 8) + data
    with open(path, "wb") as f:
        f.write(b"icns" + struct.pack(">I", len(entries) + 8) + entries)


def base(top, bottom):
    """Rounded square with a vertical gradient, like any macOS app tile."""
    big = SIZE * SS
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    grad = Image.new("RGBA", (big, big))
    gd = ImageDraw.Draw(grad)
    for y in range(big):
        t = y / (big - 1)
        gd.line([(0, y), (big, y)], fill=tuple(int(a + (b - a) * t) for a, b in zip(top, bottom)) + (255,))
    m = big * 0.09
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle([m, m, big - m, big - m], radius=big * 0.18, fill=255)
    img.paste(grad, (0, 0), mask)
    return img, ImageDraw.Draw(img), big


def done(img):
    return img.resize((SIZE, SIZE), Image.LANCZOS)


def font_cache():
    """Grey tile: an abstract serif letter shape above three stacked bars."""
    img, d, b = base((236, 238, 241), (196, 200, 207))
    ink = (70, 76, 88, 255)
    u = b / 100
    # Letter-like glyph: two slanted strokes with a crossbar (drawn, not a font).
    d.polygon([(30 * u, 58 * u), (45 * u, 20 * u), (55 * u, 20 * u), (70 * u, 58 * u),
               (62 * u, 58 * u), (50 * u, 27 * u), (38 * u, 58 * u)], fill=ink)
    d.rectangle([40 * u, 44 * u, 60 * u, 49 * u], fill=ink)
    d.rectangle([26 * u, 57 * u, 42 * u, 60 * u], fill=ink)
    d.rectangle([58 * u, 57 * u, 74 * u, 60 * u], fill=ink)
    # Cache bars.
    for i, c in enumerate(((92, 132, 196), (112, 152, 210), (136, 172, 222))):
        y = (66 + i * 7) * u
        d.rounded_rectangle([24 * u, y, 76 * u, y + 5 * u], radius=2 * u, fill=c + (255,))
    return done(img)


def display_profile():
    """Dark teal tile: a screen with a three-band tone ramp, on a stand."""
    img, d, b = base((44, 98, 104), (22, 52, 60))
    u = b / 100
    d.rounded_rectangle([20 * u, 24 * u, 80 * u, 64 * u], radius=4 * u, fill=(232, 238, 236, 255))
    inner = [24 * u, 28 * u, 76 * u, 60 * u]
    w = (inner[2] - inner[0]) / 3
    for i, c in enumerate(((214, 112, 92), (226, 190, 96), (104, 168, 150))):
        x0 = inner[0] + i * w
        d.rectangle([x0, inner[1], x0 + w, inner[3]], fill=c + (255,))
    # Gamma-like curve across the ramp.
    pts = [(inner[0] + (inner[2] - inner[0]) * t / 40,
            inner[3] - (inner[3] - inner[1]) * (t / 40) ** 2.2) for t in range(41)]
    d.line(pts, fill=(40, 44, 48, 255), width=int(1.6 * u), joint="curve")
    d.polygon([(44 * u, 64 * u), (56 * u, 64 * u), (60 * u, 74 * u), (40 * u, 74 * u)], fill=(200, 210, 208, 255))
    d.rounded_rectangle([32 * u, 73 * u, 68 * u, 77 * u], radius=2 * u, fill=(200, 210, 208, 255))
    return done(img)


def archive_index():
    """Warm tile: three offset index cards with tabs and ruled lines."""
    img, d, b = base((214, 160, 92), (160, 102, 50))
    u = b / 100
    for i, (x, y) in enumerate(((22, 34), (28, 28), (34, 22))):
        shade = 236 + i * 6
        card = (shade, shade - 6, shade - 18, 255)
        d.rounded_rectangle([x * u, y * u, (x + 44) * u, (y + 44) * u], radius=3 * u, fill=card,
                            outline=(120, 80, 40, 255), width=int(0.8 * u))
        tx = (x + 6 + i * 10) * u
        d.rounded_rectangle([tx, (y - 5) * u, tx + 12 * u, (y + 2) * u], radius=2 * u, fill=card,
                            outline=(120, 80, 40, 255), width=int(0.8 * u))
    for j in range(5):
        y = (34 + j * 6) * u
        d.line([(40 * u, y), (72 * u, y)], fill=(150, 110, 70, 255), width=int(1.2 * u))
    return done(img)


def main():
    write_icns(Image.open(os.path.join(ICONS, "icon.png")).convert("RGBA"),
               os.path.join(HERE, "browser-vault.icns"))
    for name, fn in (("fontcache", font_cache), ("displayprofile", display_profile),
                     ("archiveindex", archive_index)):
        img = fn()
        write_icns(img, os.path.join(HERE, f"{name}.icns"))


if __name__ == "__main__":
    main()

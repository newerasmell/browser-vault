#!/usr/bin/env python3
"""Generate Browser Vault icons (app icon set + menu bar template images).

Run from anywhere:  python3 app/src-tauri/icons/generate.py
Needs Pillow (pip install pillow). The outputs are committed, so this only
needs re-running when the artwork changes.

Shapes follow the `shield` glyph of the UI (app/src/app.js ICONS.shield):
  M12 3 l8 3 v6 c0 5 -3.5 8 -8 9 c-4.5 -1 -8 -4 -8 -9 V6 z   (24x24 viewBox)
"""
import os

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
SS = 8  # supersampling factor


def cubic(p0, p1, p2, p3, n=24):
    out = []
    for i in range(1, n + 1):
        t = i / n
        u = 1 - t
        out.append((
            u**3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t**3 * p3[0],
            u**3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t**3 * p3[1],
        ))
    return out


def shield(scale, ox=0.0, oy=0.0):
    pts = [(12, 3), (20, 6), (20, 12)]
    pts += cubic((20, 12), (20, 17), (16.5, 20), (12, 21))
    pts += cubic((12, 21), (7.5, 20), (4, 17), (4, 12))
    pts += [(4, 6)]
    return [(ox + x * scale, oy + y * scale) for x, y in pts]


def finish(img, size):
    return img.resize((size, size), Image.LANCZOS)


def tray(kind, size=44):
    """Menu bar icon. `locked`/`open` are black template images (macOS tints
    them); `error` is a red, non-template image (SPEC §7: red on error)."""
    big = size * SS
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = big / 24.0
    poly = shield(s)
    if kind == "error":
        red = (229, 72, 77, 255)
        d.polygon(poly, fill=red)
        # Exclamation mark knocked out of the shield.
        cx = 12 * s
        w = 1.0 * s
        d.rounded_rectangle([cx - w, 7.5 * s, cx + w, 14 * s], radius=w, fill=(0, 0, 0, 0))
        d.ellipse([cx - w, 15.6 * s, cx + w, 17.6 * s], fill=(0, 0, 0, 0))
    else:
        black = (0, 0, 0, 255)
        width = int(round(1.9 * s))
        d.line(poly + [poly[0], poly[1]], fill=black, width=width, joint="curve")
        if kind == "open":
            r = 3.0 * s
            cx, cy = 12 * s, 12.2 * s
            d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=black)
    return finish(img, size)


def app_icon(size=1024):
    big = size * 2
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # macOS-style rounded square with a vertical gradient.
    margin = big * 0.09
    top, bottom = (58, 92, 214), (31, 46, 128)
    grad = Image.new("RGBA", (big, big))
    gd = ImageDraw.Draw(grad)
    for y in range(big):
        t = y / (big - 1)
        gd.line([(0, y), (big, y)], fill=tuple(int(a + (b - a) * t) for a, b in zip(top, bottom)) + (255,))
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [margin, margin, big - margin, big - margin], radius=big * 0.18, fill=255)
    img.paste(grad, (0, 0), mask)
    # White shield, centred.
    s = (big - 2 * margin) * 0.62 / 18.0
    ox = big / 2 - 12 * s
    oy = big / 2 - 12 * s
    d.polygon(shield(s, ox, oy), fill=(255, 255, 255, 255))
    # Keyhole.
    cx, cy = big / 2, oy + 11 * s
    r = 2.2 * s
    navy = bottom + (255,)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=navy)
    d.polygon([(cx - 1.1 * s, cy), (cx + 1.1 * s, cy), (cx + 1.6 * s, cy + 5 * s), (cx - 1.6 * s, cy + 5 * s)], fill=navy)
    return img.resize((size, size), Image.LANCZOS)


def main():
    for kind in ("locked", "open", "error"):
        tray(kind, 44).save(os.path.join(HERE, f"tray-{kind}.png"))
    icon = app_icon(1024)
    icon.save(os.path.join(HERE, "icon.png"))
    for name, sz in (("32x32.png", 32), ("128x128.png", 128), ("128x128@2x.png", 256)):
        icon.resize((sz, sz), Image.LANCZOS).save(os.path.join(HERE, name))
    icon.save(os.path.join(HERE, "icon.icns"))
    icon.save(os.path.join(HERE, "icon.ico"), sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


if __name__ == "__main__":
    main()

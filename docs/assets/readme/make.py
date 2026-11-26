"""Generates the README's artwork, in the project site's design language, for both themes.

GitHub strips CSS from READMEs, so the design lives in SVG images: section headers, the verdict cards and the chain.
Fonts fall back to system faces, because an SVG shown as an image can't load web fonts.
Run from the repository root:  python3 -I docs/assets/readme/make.py
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
T = {
    "dark": dict(bg="#0a0e13", layer="#111821", line="#243140", text="#ece8df", dim="#8c99a8",
                 brand="#8fc3ff", warm="#e08a3c", ok="#67d39b", bad="#ff6b57", gap="#f2c14e"),
    "light": dict(bg="#f4f1ea", layer="#fbfaf6", line="#d6d0c2", text="#121a26", dim="#586474",
                  brand="#1f5fa6", warm="#b65f14", ok="#1d8350", bad="#c4321e", gap="#9a6a00"),
}
DISP = "'Big Shoulders Display','Arial Narrow','Helvetica Neue Condensed','Roboto Condensed',Impact,sans-serif"
MONO = "'JetBrains Mono',ui-monospace,'SF Mono',Menlo,Consolas,monospace"
SERIF = "Newsreader,Georgia,'Times New Roman',serif"
SANS = "'Instrument Sans',system-ui,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif"


def fit(text, size, room):
    """Pin a display word's width when a wide fallback font could overrun its box: a condensed face sets
    capitals at about 0.48 em, a wide one at about 0.72 em. The text is squeezed to fit, never wider than its room."""
    wide = len(text) * size * 0.72
    return f' textLength="{min(room, wide):.0f}" lengthAdjust="spacingAndGlyphs"' if wide > room else ""


def svg(w, h, body, label, c):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{label}">'
            f'<rect width="{w}" height="{h}" rx="10" fill="{c["bg"]}"/>{body}</svg>\n')


def header(num, kicker, title, accent, c):
    """A section header: roman numeral, mono kicker, condensed title, italic serif accent."""
    body = (f'<text x="40" y="44" font-family="{MONO}" font-size="15" letter-spacing="4" fill="{c["dim"]}">{num} · {kicker}</text>'
            f'<text x="38" y="104" font-family="{DISP}" font-weight="900" font-size="58" fill="{c["text"]}"{fit(title, 58, 1200)}>{title}</text>'
            f'<line x1="40" y1="128" x2="1240" y2="128" stroke="{c["line"]}" stroke-width="2"/>'
            f'<text x="1240" y="44" text-anchor="end" font-family="{SERIF}" font-style="italic" font-size="22" fill="{c["brand"]}">{accent}</text>')
    return svg(1280, 140, body, f"{title}: {accent}", c)


def field(c, x0, y0, w, h, kind):
    """A small authority field: the mandate, the dashed delegation, the agent's path and where it lands."""
    ix, iy, iw, ih = x0 + w * 0.26, y0 + h * 0.26, w * 0.48, h * 0.48
    ox, oy = x0 + 18, y0 + h - 16
    out = [f'<rect x="{x0}" y="{y0}" width="{w}" height="{h}" rx="6" fill="none" stroke="{c["dim"]}" stroke-width="2"/>',
           f'<rect x="{ix}" y="{iy}" width="{iw}" height="{ih}" rx="5" fill="{c["brand"]}" fill-opacity="0.08" stroke="{c["brand"]}" stroke-width="2" stroke-dasharray="7 5"/>',
           f'<circle cx="{ox}" cy="{oy}" r="5" fill="{c["warm"]}"/>']
    if kind == "ok":
        tx, ty = ix + iw * 0.5, iy + ih * 0.5
        out += [f'<path d="M{ox} {oy} C {ox + 60} {oy}, {tx - 30} {ty + 30}, {tx} {ty}" fill="none" stroke="{c["warm"]}" stroke-width="2.5"/>',
                f'<circle cx="{tx}" cy="{ty}" r="9" fill="{c["ok"]}"/>']
    elif kind == "bad":
        tx, ty = x0 + w - 26, y0 + 26
        out += [f'<path d="M{ox} {oy} C {ox + 140} {oy}, {tx - 20} {ty + 70}, {tx} {ty}" fill="none" stroke="{c["warm"]}" stroke-width="2.5"/>',
                f'<circle cx="{tx}" cy="{ty}" r="9" fill="{c["bad"]}"/>',
                f'<path d="M{tx - 5} {ty - 5} l10 10 M{tx + 5} {ty - 5} l-10 10" stroke="{c["layer"]}" stroke-width="2.2"/>']
    else:
        tx, ty = ix + iw * 0.55, iy + ih * 0.5
        out += [f'<path d="M{ox} {oy} C {ox + 50} {oy}, {tx - 60} {ty + 40}, {tx - 34} {ty + 14}" fill="none" stroke="{c["warm"]}" stroke-width="2.5" stroke-dasharray="2 6"/>',
                f'<circle cx="{tx}" cy="{ty}" r="13" fill="none" stroke="{c["gap"]}" stroke-width="2" stroke-dasharray="3 3"/>',
                f'<text x="{tx}" y="{ty + 6}" text-anchor="middle" font-family="{MONO}" font-size="16" font-weight="700" fill="{c["gap"]}">?</text>']
    return "".join(out)


def verdicts(c):
    cards = [("ok", "PRESERVED", c["ok"], ["Everything that happened stayed", "inside what was allowed, at every", "step of the chain."]),
             ("bad", "VIOLATED", c["bad"], ["It crossed a boundary. The result", "names the rule broken and the", "party that departed first."]),
             ("gap", "UNRESOLVED", c["gap"], ["A record is missing. The result", "names it. A gap is never read", "as permission."])]
    body = []
    for i, (kind, word, col, lines) in enumerate(cards):
        x = 40 + i * 405
        body.append(f'<rect x="{x}" y="24" width="385" height="292" rx="8" fill="{c["layer"]}" stroke="{c["line"]}" stroke-width="1.5"/>')
        body.append(field(c, x + 20, 44, 345, 120, kind))
        body.append(f'<text x="{x + 22}" y="216" font-family="{DISP}" font-weight="900" font-size="40" fill="{col}"{fit(word, 40, 340)}>{word}</text>')
        for j, ln in enumerate(lines):
            body.append(f'<text x="{x + 22}" y="{250 + j * 22}" font-family="{SANS}" font-size="16" fill="{c["dim"]}">{ln}</text>')
    return svg(1280, 340, "".join(body), "Three verdicts: preserved, violated, unresolved", c)


def chain(c):
    nodes = [("MANDATE", "the person", "or organization"), ("DELEGATION", "the delegator,", "only ever narrower"),
             ("INVOCATION", "the agent's", "host"), ("EFFECT", "whoever executed it,", "not the agent (I10)"),
             ("VERDICT", "any verifier,", "offline")]
    body, w, gap, x0, y = [], 212, 40, 40, 60
    for i, (name, a, b) in enumerate(nodes):
        x = x0 + i * (w + gap)
        last = i == len(nodes) - 1
        stroke = c["warm"] if name == "EFFECT" else (c["brand"] if last else c["line"])
        label = "CHECKED BY" if last else "SIGNED BY"
        body.append(f'<rect x="{x}" y="{y}" width="{w}" height="150" rx="8" fill="{c["layer"]}" stroke="{stroke}" stroke-width="2"/>')
        body.append(f'<text x="{x + 18}" y="{y + 30}" font-family="{MONO}" font-size="13" letter-spacing="2" fill="{c["dim"]}">0{i + 1} · {label}</text>')
        body.append(f'<text x="{x + 16}" y="{y + 76}" font-family="{DISP}" font-weight="900" font-size="30" fill="{c["text"]}"{fit(name, 30, w - 32)}>{name}</text>')
        body.append(f'<text x="{x + 18}" y="{y + 108}" font-family="{SANS}" font-size="15" fill="{c["dim"]}">{a}</text>')
        body.append(f'<text x="{x + 18}" y="{y + 128}" font-family="{SANS}" font-size="15" fill="{c["dim"]}">{b}</text>')
        if not last:
            ax = x + w + 6
            body.append(f'<path d="M{ax} {y + 75} h{gap - 14}" stroke="{c["warm"]}" stroke-width="2.5"/>'
                        f'<path d="M{ax + gap - 20} {y + 69} l8 6 l-8 6" fill="none" stroke="{c["warm"]}" stroke-width="2.5"/>')
    body.append(f'<text x="40" y="34" font-family="{SERIF}" font-style="italic" font-size="22" fill="{c["brand"]}">Each link is signed by the party that made it. Anyone holding them reaches the same verdict.</text>')
    return svg(1280, 240, "".join(body), "The chain: mandate, delegation, invocation, effect, each signed, then a verdict", c)


HEADERS = {
    "question": ("I", "THE QUESTION", "DID THE AGENT STAY INSIDE?", "authority, checked afterwards"),
    "how": ("II", "HOW IT WORKS", "ONE SIGNED CHAIN", "from a person to an effect"),
    "start": ("III", "QUICK START", "CHECK A PACKET", "in a browser, or in code"),
    "open": ("IV", "IN THE OPEN", "CHECKED BY OTHERS", "including where we differ"),
    "standards": ("V", "STANDARDS", "WHERE AMEP FITS", "beside what decides, it checks"),
    "help": ("VI", "HELP AMEP", "SCRUTINY WANTED", "every right case becomes a vector"),
}

if __name__ == "__main__":
    for theme, c in T.items():
        for key, args in HEADERS.items():
            with open(os.path.join(HERE, f"h-{key}-{theme}.svg"), "w") as fh:
                fh.write(header(*args, c))
        with open(os.path.join(HERE, f"verdicts-{theme}.svg"), "w") as fh:
            fh.write(verdicts(c))
        with open(os.path.join(HERE, f"chain-{theme}.svg"), "w") as fh:
            fh.write(chain(c))
    print("ok")

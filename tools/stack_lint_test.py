#!/usr/bin/env python3
"""Tests zu tools/stack_lint.py: eigene Releases mit mehreren Diensten (Pulse O6).

Pulse (mi/pulse, automation/releases.py) kennt seit O6 je Dienst
`x-pulse-release-image` (eigener Image-Name) und `x-pulse-release-dockerfile`
(eigenes Dockerfile). Die Faelle hier folgen tests/releases_groups.py in
mi/pulse: ein Note-aehnlicher Stack (inline, kein echter Stack im Repo),
gueltige und ungueltige Werte, Image-Name passt nicht, Schluessel ohne
`x-pulse-release`, und dass bisherige Stacks wie Card gruen bleiben. Dazu
das, was Pulses Zeilen-Leser (compose_lite) anders liest als YAML: Werte auf
der naechsten Zeile, Block-Skalare, Escapes, null/Zahl/true, Anker, Aliase,
`<<`-Merges; Dockerfiles je Image ohne Tag und Image-Namen ueber Dateien.
Ausserdem `x-pulse-security` (Pulse B1): gueltige und ungueltige Quellen.

Braucht nur PyYAML, wie der Lint. Laeuft lokal (die CI fuehrt nur den Lint
selbst aus):  python3 tools/stack_lint_test.py
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

sys.dont_write_bytecode = True  # kein tools/__pycache__ im Repo
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import stack_lint as L  # noqa: E402

FAILED: list[str] = []
TMP = pathlib.Path(".")  # setzt main() auf ein TemporaryDirectory


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name} {detail}")
        FAILED.append(name)


def lint(text: str, host: str = "docker", stack: str = "note",
         *more: tuple[str, str]) -> tuple[list[str], list[str]]:
    """Ein Compose pruefen wie in `<host>/<stack>/compose.yml`. `(Fehler, Hinweise)`.

    `more`: weitere `(stack, text)` im selben Lauf davor (Image-Namen ueber Dateien)."""
    L.errors.clear()
    L.warnings.clear()
    L.undigested.clear()
    L.release_names.clear()
    for name, body in (*more, (stack, text)):
        path = TMP / host / name / "compose.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        L.check_file(path, {}, {})
    return list(L.errors), list(L.warnings)


def has(lines: list[str], *parts: str) -> bool:
    return any(all(p in line for p in parts) for line in lines)


# Wie der Note-Stack nach mi/note docs/betrieb.md (gekuerzt): note und
# note-indexer mit demselben Image, note-ocr mit eigenem Image und Dockerfile,
# ein fremdes Image und ein Dienst aus einem anderen Repo.
NOTE = """services:
  note:
    image: build.local/note:0.1.0
    pull_policy: never
    x-pulse-release: mi/note
    x-pulse-health: image
    container_name: note
  note-indexer:
    image: build.local/note:0.1.0
    pull_policy: never
    x-pulse-release: mi/note
    x-pulse-health: image
    container_name: note-indexer
  note-ocr:
    image: build.local/note-ocr:0.1.0
    pull_policy: never
    x-pulse-release: mi/note
    x-pulse-release-image: note-ocr
    x-pulse-release-dockerfile: Dockerfile.ocr
    x-pulse-health: image
    container_name: note-ocr
  note-search:
    image: getmeili/meilisearch:v1.15@sha256:aaa
    x-pulse-health: image
    container_name: note-search
  note-mcp:
    image: build.local/mcp-note:0.1.0
    pull_policy: never
    x-pulse-release: mi/mcp-note
    x-pulse-health: image
    container_name: note-mcp
"""
CARD = """services:
  card:
    image: build.local/card:1.12.0
    pull_policy: never
    x-pulse-release: mi/card
    x-pulse-release-version: app.py
    x-pulse-health: image
    container_name: card
"""
OCR_KEYS = "    x-pulse-release-image: note-ocr\n    x-pulse-release-dockerfile: Dockerfile.ocr\n"


def test_valid() -> None:
    print("Gueltige Stacks")
    errs, warns = lint(NOTE)
    check("Note-aehnlicher Stack: keine Fehler, keine Hinweise", not errs and not warns, f"{errs} {warns}")
    errs, warns = lint(CARD, stack="card")
    check("Card (ohne die neuen Schluessel) wie bisher gruen", not errs and not warns, f"{errs} {warns}")
    phase1 = NOTE.split("  note-ocr:")[0]
    errs, _w = lint(phase1)
    check("Phase 1: note + note-indexer mit demselben Image", not errs, str(errs))
    errs, _w = lint(NOTE, host="docker-data")
    check("anderer Host-Ordner (Pulse laedt per SSH)", not errs, str(errs))
    for raw in ("Dockerfile.ocr", "./Dockerfile.ocr", "docker/ocr.Dockerfile", "ocr/Dockerfile", "Dockerfile"):
        errs, _w = lint(NOTE.replace("Dockerfile.ocr", raw))
        check(f"Dockerfile `{raw}` gilt", not errs, str(errs))
    for raw in ("note-ocr", "note_ocr", "note.ocr2", "a__b", "note--ocr"):
        text = NOTE.replace("x-pulse-release-image: note-ocr", f"x-pulse-release-image: {raw}")
        text = text.replace("build.local/note-ocr:", f"build.local/{raw}:")
        errs, _w = lint(text)
        check(f"Image-Name `{raw}` gilt", not errs, str(errs))
    # Ueber Pulse hinaus: note-ocr baut `build.local/note` aus Dockerfile.ocr,
    # note und note-indexer dasselbe Image aus Dockerfile — mehrdeutig.
    text = NOTE.replace("x-pulse-release-image: note-ocr", "x-pulse-release-image: note") \
               .replace("build.local/note-ocr:0.1.0", "build.local/note:0.1.0")
    errs, _w = lint(text)
    check("gleiches Image aus verschiedenen Dockerfiles abgelehnt",
          has(errs, "`build.local/note` (note, note-indexer, note-ocr)", "verschiedenen Dockerfiles"), str(errs))


def test_dockerfile() -> None:
    print("x-pulse-release-dockerfile")
    for raw in ("/etc/passwd", "../Dockerfile", "a/../../b", "a//b", ".", "..", "./", ".hidden",
                "'Docker file'", "a\\\\b", "x/./y", "ocr/.Dockerfile", "'\"Dockerfile\\nRUN x\"'"):
        errs, _w = lint(NOTE.replace("Dockerfile.ocr", raw))
        check(f"Dockerfile `{raw}` abgelehnt", has(errs, "note-ocr:", "x-pulse-release-dockerfile",
                                                    "kein relativer Pfad"), str(errs))
    # `^…$` mit match liesse den Zeilenumbruch am Ende eines Teils durch; fullmatch nicht.
    errs, _w = lint(NOTE.replace("Dockerfile.ocr", '"ocr\\n/Dockerfile"'))
    check("Zeilenumbruch in einem Pfadteil abgelehnt (fullmatch)", has(errs, "kein relativer Pfad"), str(errs))
    errs, warns = lint(NOTE.replace("x-pulse-release-dockerfile: Dockerfile.ocr", "x-pulse-release-dockerfile:"))
    check("Dockerfile-Feld leer: wie Pulse `Dockerfile`, nur Hinweis",
          not errs and has(warns, "note-ocr:", "x-pulse-release-dockerfile ist leer"), f"{errs} {warns}")
    errs, warns = lint(NOTE.replace("    x-pulse-release-dockerfile: Dockerfile.ocr\n", ""))
    check("Dockerfile-Feld fehlt: Vorgabe `Dockerfile`, kein Fehler", not errs and not warns, f"{errs} {warns}")


def test_image_name() -> None:
    print("x-pulse-release-image und Image")
    for raw in ("Note-OCR", "note/ocr", "-ocr", "note..ocr", "x" * 129, "'note ocr'", "note_"):
        errs, _w = lint(NOTE.replace("x-pulse-release-image: note-ocr", f"x-pulse-release-image: {raw}"))
        check(f"Image-Name `{raw[:20]}` abgelehnt", has(errs, "note-ocr:", "ist kein Image-Name"), str(errs))
    errs, _w = lint(NOTE.replace("build.local/note-ocr:0.1.0", "build.local/note:0.1.0"))
    check("Image passt nicht zu x-pulse-release-image",
          has(errs, "note-ocr:", "build.local/note-ocr:X.Y.Z", "Name aus x-pulse-release-image"), str(errs))
    errs, _w = lint(NOTE.replace(OCR_KEYS, ""))
    check("build.local/note-ocr ohne x-pulse-release-image (Repo mi/note)",
          has(errs, "note-ocr:", "build.local/note:X.Y.Z", "ein anderer per x-pulse-release-image"), str(errs))
    errs, _w = lint(NOTE.replace("build.local/note-ocr:0.1.0", "build.local/note-ocr:0.1.0@sha256:abc"))
    check("Release-Image mit Digest abgelehnt", has(errs, "note-ocr:", "ohne Digest"), str(errs))
    errs, warns = lint(NOTE.replace("x-pulse-release-image: note-ocr", "x-pulse-release-image: ''"))
    check("x-pulse-release-image leer: Repo-Name gilt (Fehler am Image), Hinweis",
          has(errs, "note-ocr:", "build.local/note:X.Y.Z") and has(warns, "x-pulse-release-image ist leer"),
          f"{errs} {warns}")


def test_foreign() -> None:
    print("Schluessel ohne x-pulse-release, fremde Dienste mit Release-Image")
    for key, val in (("x-pulse-release-image", "meili"), ("x-pulse-release-dockerfile", "Dockerfile.x"),
                     ("x-pulse-release-version", "VERSION")):
        text = NOTE.replace("    container_name: note-search\n",
                            f"    container_name: note-search\n    {key}: {val}\n")
        errs, _w = lint(text)
        check(f"{key} bei fremdem Image abgelehnt", has(errs, "note-search:", key, "ohne x-pulse-release"),
              str(errs))
    text = NOTE + """  note-worker:
    image: build.local/note:0.1.0
    pull_policy: never
    x-pulse-health: image
"""
    errs, _w = lint(text)
    check("gleiches Image ohne x-pulse-release abgelehnt (Pulse zaehlt die Zeilen)",
          has(errs, "build.local/note:0.1.0", "note-worker", "keinen Release-MR"), str(errs))
    text = NOTE.replace("""    x-pulse-release: mi/note
    x-pulse-health: image
    container_name: note-indexer""", """    x-pulse-release: mi/note
    x-pulse-release-version: app.py
    x-pulse-health: image
    container_name: note-indexer""")
    errs, _w = lint(text)
    check("verschiedene x-pulse-release-version in einem Repo abgelehnt",
          has(errs, "note-indexer:", "weicht von `VERSION`"), str(errs))


def test_pulse_reads() -> None:
    print("Pulse liest zeilenweise (compose_lite) — Werte muessen gleich ankommen")
    df = "    x-pulse-release-dockerfile: Dockerfile.ocr\n"
    cases = {
        "Wert auf der naechsten Zeile": "    x-pulse-release-dockerfile:\n      Dockerfile.ocr\n",
        "Block-Skalar >-": "    x-pulse-release-dockerfile: >-\n      Dockerfile.ocr\n",
        "Block-Skalar |": "    x-pulse-release-dockerfile: |\n      Dockerfile.ocr\n",
        "Escape in doppelten Anfuehrungszeichen": '    x-pulse-release-dockerfile: "Docker\\x66ile.ocr"\n',
        "mehrzeiliger plain-Wert": "    x-pulse-release-dockerfile: Dockerfile\n      .ocr\n",
        "Anker auf der Zeile": "    x-pulse-release-dockerfile: &df Dockerfile.ocr\n",
        "Tag !!str": "    x-pulse-release-dockerfile: !!str Dockerfile.ocr\n",
        "'' in einfachen Anfuehrungszeichen": "    x-pulse-release-dockerfile: 'Docker''file'\n",
    }
    for name, line in cases.items():
        errs, _w = lint(NOTE.replace(df, line))
        check(f"Dockerfile: {name} abgelehnt", has(errs, "note-ocr: x-pulse-release-dockerfile"), str(errs))
    for raw, kind in (("~", "null"), ("null", "null"), ("0123", "int"), ("0x1f", "int"), ("true", "bool"),
                      ("1.5", "float")):
        errs, _w = lint(NOTE.replace("x-pulse-release-image: note-ocr", f"x-pulse-release-image: {raw}"))
        check(f"Image-Name `{raw}` (YAML {kind}) abgelehnt",
              has(errs, "note-ocr: x-pulse-release-image", "kein Text", kind), str(errs))
    errs, _w = lint(NOTE.replace("x-pulse-release: mi/mcp-note", "x-pulse-release: 'mi/mcp-note'")
                    .replace("x-pulse-release-dockerfile: Dockerfile.ocr",
                             'x-pulse-release-dockerfile: "Dockerfile.ocr"'))
    check("Werte in Anfuehrungszeichen gelten", not errs, str(errs))
    errs, _w = lint(NOTE.replace("Dockerfile.ocr", "Dockerfile.ocr   # eigener Kommentar"))
    check("Kommentar hinter dem Wert gilt", not errs, str(errs))
    errs, _w = lint(NOTE.replace("    image: build.local/note-ocr:0.1.0\n",
                                 "    image:\n      build.local/note-ocr:0.1.0\n"))
    check("image auf der naechsten Zeile abgelehnt", has(errs, "note-ocr: image", "Zeile des Schluessels"),
          str(errs))
    text = NOTE.replace("  note-mcp:\n    image: build.local/mcp-note:0.1.0\n    pull_policy: never\n"
                        "    x-pulse-release: mi/mcp-note\n    x-pulse-health: image\n"
                        "    container_name: note-mcp\n",
                        "  note-mcp: {image: 'build.local/mcp-note:0.1.0', pull_policy: never, "
                        "x-pulse-release: mi/mcp-note, x-pulse-health: image}\n")
    errs, _w = lint(text)
    check("Release-Dienst als {…} abgelehnt", has(errs, "note-mcp: Release-Dienst als"), str(errs))


def test_anchors() -> None:
    print("Anker, Aliase und Merge-Keys")
    merged = """x-note: &note
  image: build.local/note:0.1.0
  pull_policy: never
  x-pulse-release: mi/note
  x-pulse-health: image

services:
  note:
    <<: *note
    container_name: note
  note-indexer:
    <<: *note
    container_name: note-indexer
"""
    errs, _w = lint(merged)
    check("`<<: *note` in note und note-indexer abgelehnt",
          has(errs, "note: `<<`-Merge") and has(errs, "note-indexer: `<<`-Merge"), str(errs))
    aliased = NOTE.split("  note-indexer:")[0].replace("  note:\n", "  note: &n\n") + "  note-indexer: *n\n"
    errs, _w = lint(aliased)
    check("Dienst `note-indexer: *n` (Alias) abgelehnt", has(errs, "note-indexer: Release-Dienst als Alias"),
          str(errs))
    check("Dienst `note: &n` (Anker auf der Dienstzeile) abgelehnt",
          has(errs, "note: Pulse findet den Release-Dienst nicht"), str(errs))
    text = "x-repo: &repo mi/note\n" + NOTE.replace("x-pulse-release: mi/note\n    x-pulse-release-image",
                                                     "x-pulse-release: *repo\n    x-pulse-release-image")
    errs, _w = lint(text)
    check("x-pulse-release: *repo abgelehnt", has(errs, "note-ocr: x-pulse-release "), str(errs))
    plain = "x-logging: &log\n  driver: json-file\n" + NOTE.replace(
        "  note-search:\n", "  note-search:\n    logging: *log\n")
    errs, _w = lint(plain)
    check("Anker bei fremdem Dienst (ohne Release) bleibt erlaubt", not errs, str(errs))


def test_groups_more() -> None:
    print("Image-Namen und Dockerfiles ueber Fassungen und Dateien")
    text = NOTE.replace("""    image: build.local/note:0.1.0
    pull_policy: never
    x-pulse-release: mi/note
    x-pulse-health: image
    container_name: note-indexer""", """    image: build.local/note:0.2.0
    pull_policy: never
    x-pulse-release: mi/note
    x-pulse-release-dockerfile: D2
    x-pulse-health: image
    container_name: note-indexer""")
    errs, _w = lint(text)
    check("build.local/note:0.1.0 aus Dockerfile und :0.2.0 aus D2 abgelehnt",
          has(errs, "`build.local/note` (note, note-indexer) aus verschiedenen Dockerfiles"), str(errs))
    other = CARD.replace("card:", "x:").replace("mi/card", "mi/other").replace(
        "x-pulse-release-version: app.py", "x-pulse-release-image: note-ocr").replace(
        "build.local/x:1.12.0", "build.local/note-ocr:1.0.0")
    errs, _w = lint(NOTE, "docker", "note", ("other", other))
    check("build.local/note-ocr aus mi/other und mi/note abgelehnt",
          has(errs, "note-ocr: `build.local/note-ocr` gehoert schon zu mi/other"), str(errs))
    errs, _w = lint(NOTE, "docker", "note", ("note-alt", NOTE.replace("mi/note", "gitmi/note")
                                             .replace("container_name: note", "container_name: alt-note")))
    check("gitmi/note und mi/note gelten als ein Repo (Alias wie Pulse)",
          not has(errs, "gehoert schon zu"), str(errs))
    errs, _w = lint(NOTE.replace("""    x-pulse-release: mi/note
    x-pulse-health: image
    container_name: note-indexer""", """    x-pulse-release: Mi/Note
    x-pulse-health: image
    container_name: note-indexer"""))
    check("ungueltiges x-pulse-release + gleiches Image: genau eine Meldung",
          len(errs) == 1 and has(errs, "note-indexer: x-pulse-release `Mi/Note` ist kein Projektpfad"),
          str(errs))
    indexer = """    x-pulse-release: mi/note
    x-pulse-health: image
    container_name: note-indexer"""
    errs, _w = lint(NOTE.replace(indexer, indexer.replace("mi/note", "gitmi/note")))
    check("gleiches Image unter mi/note und gitmi/note abgelehnt (Pulse: zwei Gruppen, Zaehlung 2 statt 1)",
          has(errs, "`image: build.local/note:0.1.0` tragen auch note-indexer ohne `x-pulse-release: mi/note`")
          and has(errs, "tragen auch note ohne `x-pulse-release: gitmi/note`"), str(errs))
    errs, _w = lint(NOTE.replace(indexer, indexer.replace("x-pulse-release: mi/note", "x-pulse-release:")))
    check("leeres x-pulse-release abgelehnt, seine image-Zeile zaehlt mit",
          has(errs, "note-indexer: x-pulse-release ist leer")
          and has(errs, "`image: build.local/note:0.1.0` tragen auch note-indexer"), str(errs))
    for raw in ("''", "~"):
        errs, _w = lint(NOTE.replace(indexer, indexer.replace("x-pulse-release: mi/note",
                                                              f"x-pulse-release: {raw}")))
        check(f"x-pulse-release: {raw} abgelehnt", has(errs, "note-indexer: x-pulse-release"), str(errs))
    text = NOTE.replace("  note-search:\n", """  note-search:
    command: >
      --x
      x-pulse-release: mi/evil
""")
    errs, _w = lint(text)
    check("x-pulse-release-Zeile im Block-Skalar eines fremden Dienstes abgelehnt",
          has(errs, "note-search: Pulse liest hier `x-pulse-release: mi/evil`, YAML nicht"), str(errs))


def test_security() -> None:
    print("x-pulse-security (Pulse B1)")
    anchor = "    container_name: note-search\n"
    for raw in ("github:NginxProxyManager/nginx-proxy-manager", "github:immich-app/immich",
                "github:a_b/c.d-e", "'github:owner/repo'", "gitlab-version-check", "none", '"none"'):
        errs, warns = lint(NOTE.replace(anchor, f"{anchor}    x-pulse-security: {raw}\n"))
        check(f"x-pulse-security `{raw}` gilt", not errs and not warns, f"{errs} {warns}")
    errs, warns = lint(NOTE)
    check("x-pulse-security fehlt: kein Fehler, kein Hinweis", not errs and not warns, f"{errs} {warns}")
    for raw in ("", "''", "~", "'  '"):
        errs, _w = lint(NOTE.replace(anchor, f"{anchor}    x-pulse-security: {raw}\n"))
        check(f"x-pulse-security leer (`{raw}`) abgelehnt",
              has(errs, "note-search: x-pulse-security ist leer"), str(errs))
    for raw in ("'github:'", "github:owner", "github:owner/", "github:/repo", "github:a/b/c",
                "gitlab:x", "github:a/..", "github:./b", "'github: a/b'", "GitHub:a/b", "github:a b/c",
                "github:a/b?x=1", "nonee", "Gitlab-Version-Check", '"github:a/b\\n"'):
        errs, _w = lint(NOTE.replace(anchor, f"{anchor}    x-pulse-security: {raw}\n"))
        check(f"x-pulse-security `{raw}` abgelehnt",
              has(errs, "note-search: x-pulse-security", "erlaubt: github:<owner>/<repo>"), str(errs))
    for raw, kind in (("42", "int"), ("true", "bool"), ("yes", "bool"), ("1.5", "float"), ("0x1f", "int")):
        errs, _w = lint(NOTE.replace(anchor, f"{anchor}    x-pulse-security: {raw}\n"))
        check(f"x-pulse-security `{raw}` (YAML {kind}) abgelehnt, Quelltext in der Meldung",
              len(errs) == 1 and has(errs, f"note-search: x-pulse-security `{raw}` ist fuer YAML kein Text",
                                     kind, "in Anfuehrungszeichen setzen"), str(errs))
    for raw in ("[github:a/b]", "{github: a/b}"):
        errs, _w = lint(NOTE.replace(anchor, f"{anchor}    x-pulse-security: {raw}\n"))
        check(f"x-pulse-security `{raw}` abgelehnt, genau eine Meldung",
              len(errs) == 1 and has(errs, "note-search: x-pulse-security muss ein einfacher Wert sein"),
              str(errs))
    view = {
        "Escape": '"github:a/\\x62"',
        "Wert auf der naechsten Zeile": "\n      github:a/b",
        "Block-Skalar": ">-\n      github:a/b",
        "Anker": "&src github:a/b",
    }
    for name, raw in view.items():
        errs, _w = lint(NOTE.replace(anchor, f"{anchor}    x-pulse-security: {raw}\n"))
        check(f"x-pulse-security: {name} abgelehnt (Pulse liest anders)",
              has(errs, "note-search: Pulse liest x-pulse-security"), str(errs))
    text = NOTE.replace("  note-search:\n", """  note-search:
    command: >
      --x
      x-pulse-security: github:evil/x
""")
    errs, _w = lint(text)
    check("x-pulse-security-Zeile im Block-Skalar (nur Pulse liest sie) abgelehnt",
          len(errs) == 1 and has(errs, "note-search: Pulse liest hier `x-pulse-security: github:evil/x`",
                                 "YAML nicht"), str(errs))
    errs, _w = lint(text.replace("  note-search:\n", "  note-search:\n    x-pulse-security: github:good/x\n"))
    check("eigener Schluessel vor der Block-Skalar-Zeile (Pulse liest github:evil/x): abgelehnt",
          has(errs, "note-search: Pulse liest x-pulse-security `github:evil/x`, YAML `github:good/x`"),
          str(errs))
    errs, _w = lint(NOTE.replace(anchor, f"{anchor}    x-pulse-security: github:a/b   # Upstream\n"))
    check("x-pulse-security mit Kommentar dahinter gilt", not errs, str(errs))
    errs, _w = lint(NOTE.replace("    x-pulse-release: mi/note\n    x-pulse-release-image",
                                 "    x-pulse-release: mi/note\n    x-pulse-security: github:x\n"
                                 "    x-pulse-release-image"))
    check("x-pulse-security bei einem Release-Dienst wird auch geprueft",
          has(errs, "note-ocr: x-pulse-security `github:x`"), str(errs))


def main() -> int:
    global TMP
    with tempfile.TemporaryDirectory(prefix="stack-lint-test-") as tmp:
        TMP = pathlib.Path(tmp)
        test_valid()
        test_dockerfile()
        test_image_name()
        test_foreign()
        test_pulse_reads()
        test_anchors()
        test_groups_more()
        test_security()
    print(f"{len(FAILED)} Fehler" + (": " + ", ".join(FAILED) if FAILED else ""))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())

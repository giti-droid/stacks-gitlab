#!/usr/bin/env python3
"""Stack-Lint: die Regeln, die ein Compose in diesem Repo einhalten muss.

Kopie aus mi/stacks (Stand 19.11.2026, Commit 1cf0645, mit x-pulse-security).
Bei Aenderungen an den Regeln beide Repos nachziehen.

Laeuft bei jedem Push und Merge Request (siehe .gitlab-ci.yml) und ist die
Bedingung, unter der Renovate einen MR ueberhaupt mergen darf. Braucht nur
PyYAML — kein Docker, damit der Lauf auf jedem Runner geht.

Regeln (ERR bricht ab, WARN nur Hinweis):

  ERR  jede Datei parst als YAML und hat `services`
  ERR  jeder Dienst hat `image:` mit Tag (kein nackter Name) — oder `build:`
  ERR  kein `pull_policy: always` (wuerde bei jedem Deploy ziehen)
  ERR  keine relativen Bind-Mounts (./ oder ../) — sie landen bei Portainer
       unter /data/compose/<id>/ und sind nach einer Migration weg
  ERR  container_name und ipv4_address sind je Host (Ordner) eindeutig —
       ausser beide Dienste tragen `x-pulse-ip-shared` mit Begruendung
       (zwei Stacks, von denen nur einer laeuft)
  ERR  jeder Dienst, der laufen soll (kein `restart: "no"`), hat einen
       healthcheck — oder `x-pulse-health: image` (Image bringt einen mit)
       oder `x-pulse-health: none` mit `x-pulse-health-reason`
  WARN `restart:` mit einer Policy (unless-stopped, always, on-failure) ohne
       `x-pulse-protected` — seit Pulse 5.4 setzt Pulse die Restart-Policy je
       Container durch; nur geschuetzte Dienste (Pulse, seine Datenbank, der
       Runner) behalten sie in der Compose-Datei. `restart: "no"` bleibt
       erlaubt und heisst weiterhin: muss nicht dauerhaft laufen.
  ERR  Umgebungsvariablen, deren Name nach Geheimnis aussieht
       (PASSWORD, SECRET, TOKEN, _KEY, API_KEY), sind ${VAR}-Verweise
  ERR  Pulse-Regeln (4.1) sind flach und gueltig: `x-pulse-ref` ist vendor,
       follow, manual oder none; vendor braucht `x-pulse-ref-source` (https)
       und `x-pulse-ref-service`; follow einen Leitdienst im selben Compose;
       `x-pulse-ref-match` ist exact, minor oder major; Platzhalter
       `{dienst:major|minor|tag}` nennen Dienste dieses Compose
  ERR  `x-pulse-snapshot` auf oberster Ebene ist `always` (oder fehlt)
  ERR  `x-pulse-security` (Quelle der Sicherheitsmeldungen, Pulse B1) ist
       `github:<owner>/<repo>` (je Teil A-Z a-z 0-9 `-` `_` `.`, nicht `.`
       oder `..`, genau ein `/`), `gitlab-version-check` oder `none`; Text,
       nicht leer, auf der Zeile des Schluessels (Pulse liest ihn zeilenweise
       wie die Release-Schluessel; auch keine Zeile, die nur Pulse liest, etwa
       in einem Block-Skalar). Fehlen darf er (dann nur der Image-Scan).
  ERR  eigenes Release (`x-pulse-release: gitmi/<name>`, Pulse 4.7): Image
       `build.local/<name>:X.Y.Z` ohne Digest, `pull_policy: never`, und nur
       in einem Host-Ordner — gebaut wird im Runner, ausserhalb von docker/
       laedt Pulse das Image per SSH auf die VM (seit Pulse 5.10)
  ERR  mehrere Dienste und Images aus einem Repo (Pulse O6, Note):
       `x-pulse-release-image` ist ein Docker-Namensteil (a-z, 0-9, `.`, `_`,
       `-`, hoechstens 128 Zeichen) und ersetzt den Repo-Namen im Image —
       `build.local/<x-pulse-release-image>:X.Y.Z`;
       `x-pulse-release-dockerfile` ist ein relativer Pfad in der Quelle (kein
       `/` am Anfang, kein `..`, kein Teil beginnt mit `.`, nur A-Z a-z 0-9
       `._@+-`; leer heisst `Dockerfile`). Beide Schluessel (und
       `x-pulse-release-version`) nur zusammen mit `x-pulse-release`. Je Compose
       und Repo: gleiche `x-pulse-release-version`, ein Image traegt nur Dienste
       dieses Repos mit `x-pulse-release` (Pulse zaehlt die `image:`-Zeilen und
       legt sonst keinen Release-MR an), Dienste mit demselben Image bauen aus
       demselben Dockerfile. Mehrere Dienste mit demselben Image sind erlaubt.
       Ein `build.local/<name>` gehoert ueber alle Dateien zu genau einem Repo.
  ERR  Pulse liest das Compose zeilenweise (mi/pulse pulselib/compose_lite.py),
       nicht mit PyYAML: bei Release-Diensten (`x-pulse-release*` oder Image
       `build.local/…`) stehen `image:` und `x-pulse-release*` je auf einer
       Zeile als einfacher Text (plain oder in Anfuehrungszeichen, kein
       Block-Skalar, kein Backslash-Escape, kein `''`, kein null/Zahl/true), ohne
       Anker, Alias oder `<<`-Merge — und Pulse muss dasselbe lesen wie YAML.
  WARN Datenbank-Image ohne `x-pulse-ref` — Pulse kann nicht pruefen, ob der
       Hersteller der Anwendung die Fassung empfiehlt (wird spaeter Pflicht)
  WARN `image:` ohne Digest (@sha256:...) — Renovate pinnt beim ersten Lauf
  WARN veraltetes `version:` auf oberster Ebene

Aufruf: python3 tools/stack_lint.py [Pfad ...]   (ohne Pfad: alle Hosts)
"""

from __future__ import annotations

import pathlib
import re
import sys

import yaml

# docker-dev und docker-management (zweiter PVE, Swiss-PASM) liegen seit
# 12.11.2026 unter archiv/ — die VMs gibt es nicht mehr.
HOSTS = ("docker", "docker-vault", "docker-data")
SECRET_KEY = re.compile(r"(PASSWORD|SECRET|TOKEN|_KEY$|API_KEY)", re.I)
# Namen, die zwar TOKEN/KEY enthalten, aber keine Geheimnisse sind.
SECRET_KEY_EXCEPT = re.compile(r"(_ID|_ENABLED|_HEADER|_HOST|_PORT|_URL|_FILE|_PATH)$", re.I)

# 4.1: Regeln zur Hersteller-Empfehlung (Pulse, automation/vendor_refs.py).
REF_TYPES = ("vendor", "follow", "manual", "none")
REF_MATCHES = ("exact", "minor", "major")
PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_.-]+):(major|minor|tag)\}")
# 4.7: eigene Releases — im Runner gebaut, in keiner Registry.
RELEASE_PREFIX = "build.local/"
RELEASE_REPO = re.compile(r"^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)+$")
RELEASE_TAG = re.compile(r"^\d+\.\d+\.\d+$")
# Pulse O6 (mi/pulse automation/releases.py, IMAGE_KEY/DOCKERFILE_KEY): eigener
# Image-Name und eigenes Dockerfile je Dienst. Die Muster sind dieselben wie in
# Pulse; geprueft wird hier mit fullmatch (Pulse liest das Compose zeilenweise,
# ein Zeilenumbruch im Wert kommt dort gar nicht an).
RELEASE_IMAGE_KEY = "x-pulse-release-image"
RELEASE_DOCKERFILE_KEY = "x-pulse-release-dockerfile"
RELEASE_VERSION_KEY = "x-pulse-release-version"
RELEASE_DEFAULT_DOCKERFILE = "Dockerfile"
# Ein Pfadteil eines Docker-Image-Namens (distribution/reference).
RELEASE_IMAGE_NAME = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")
# Ein Teil des Dockerfile-Pfads; beginnt nicht mit `.` (also auch nicht `.`/`..`).
RELEASE_PATH_PART = re.compile(r"[A-Za-z0-9_@+-][A-Za-z0-9._@+-]*")
# Pulse B1 (mi/pulse docs/sicherheits-updates.md): woher Pulse die
# Sicherheitsmeldungen eines Dienstes holt.
SECURITY_KEY = "x-pulse-security"
SECURITY_PLAIN = ("gitlab-version-check", "none")
SECURITY_GITHUB = re.compile(r"github:([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
DB_IMAGES = re.compile(r"(^|/)(mariadb|mysql|postgres|pgvector|redis|valkey|mongo|immich-app/postgres)(:|@|$)")


def check_refs(path: pathlib.Path, doc: dict) -> None:
    """Die flachen `x-pulse-ref*`-Schluessel und `x-pulse-snapshot` pruefen."""
    services = doc.get("services") or {}
    snap = doc.get("x-pulse-snapshot")
    if snap is not None and str(snap).strip() != "always":
        err(path, f"x-pulse-snapshot: `{snap}` — erlaubt ist nur `always`")
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        for key, val in svc.items():
            if str(key).startswith("x-pulse-") and isinstance(val, (dict, list)):
                err(path, f"{name}: {key} muss ein einfacher Wert sein (Pulse liest nur flache Schluessel)")
        kind = svc.get("x-pulse-ref")
        image = str(svc.get("image") or "")
        if kind is None:
            if DB_IMAGES.search(image.split("@", 1)[0]):
                warn(path, f"{name}: Datenbank `{image.split('@', 1)[0]}` ohne x-pulse-ref")
            continue
        kind = str(kind).strip()
        if kind not in REF_TYPES:
            err(path, f"{name}: x-pulse-ref `{kind}` — erlaubt: {', '.join(REF_TYPES)}")
            continue
        match = str(svc.get("x-pulse-ref-match", "minor")).strip()
        if match not in REF_MATCHES:
            err(path, f"{name}: x-pulse-ref-match `{match}` — erlaubt: {', '.join(REF_MATCHES)}")
        target = str(svc.get("x-pulse-ref-service", "")).strip()
        for key in ("x-pulse-ref-source", "x-pulse-ref-doc"):
            val = str(svc.get(key, "") or "").strip()
            if val and not val.startswith("https://"):
                err(path, f"{name}: {key} muss mit https:// beginnen")
            for ref_svc, _level in PLACEHOLDER.findall(val):
                if ref_svc not in services:
                    err(path, f"{name}: {key} nennt `{{{ref_svc}:…}}`, den Dienst gibt es hier nicht")
        if kind == "vendor":
            if not str(svc.get("x-pulse-ref-source", "")).strip():
                err(path, f"{name}: x-pulse-ref: vendor braucht x-pulse-ref-source")
            if not target:
                err(path, f"{name}: x-pulse-ref: vendor braucht x-pulse-ref-service (Dienst in der Vorlage)")
        if kind == "follow" and target not in services:
            err(path, f"{name}: x-pulse-ref: follow braucht einen Leitdienst dieses Compose "
                      f"(x-pulse-ref-service: `{target}`)")


def security_problem(raw, source: str | None = None) -> str:
    """Pulse B1: warum `x-pulse-security` keine bekannte Quelle ist — leer, wenn gueltig.

    `source`: der Wert, wie er im Compose steht (Pulses Zeilen-Leser), fuer die Meldung."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return (f"{SECURITY_KEY} ist leer — Quelle eintragen "
                f"(github:<owner>/<repo>, {', '.join(SECURITY_PLAIN)}) oder Zeile entfernen")
    if not isinstance(raw, str):
        shown = source.strip() if source and source.strip() else str(raw)
        return (f"{SECURITY_KEY} `{shown[:40]}` ist fuer YAML kein Text ({type(raw).__name__}) "
                "— in Anfuehrungszeichen setzen")
    val = raw.strip(" ")  # kein strip(): ein Zeilenumbruch im Wert kaeme bei Pulse nicht an
    if val in SECURITY_PLAIN:
        return ""
    found = SECURITY_GITHUB.fullmatch(val)
    if found and not {found.group(1), found.group(2)} & {".", ".."}:
        return ""
    return (f"{SECURITY_KEY} `{val[:80]}` — erlaubt: github:<owner>/<repo> "
            f"(A-Z a-z 0-9 - _ ., genau ein `/`), {', '.join(SECURITY_PLAIN)}")


def check_security(path: pathlib.Path, text: str, services: dict) -> None:
    """Pulse B1: `x-pulse-security` ist gueltig, und Pulses Zeilen-Leser liest dasselbe wie YAML.

    In beide Richtungen: ein gueltiger YAML-Wert muss bei Pulse gleich ankommen,
    und eine Zeile, die nur Pulse liest (z. B. in einem Block-Skalar unter
    `command: >`), waere eine Quelle, die niemand im Compose sieht."""
    pulse = pulse_services(text)
    for name, svc in services.items():
        if not isinstance(svc, dict) or SECURITY_KEY not in svc:
            continue
        raw = svc[SECURITY_KEY]
        if isinstance(raw, (dict, list)):
            continue  # meldet check_refs (kein einfacher Wert)
        got = (pulse.get(str(name)) or {"x": {}})["x"].get(SECURITY_KEY)
        why = security_problem(raw, got)
        if why:
            err(path, f"{name}: {why}")
            continue
        want = raw.strip(" ")
        if got is None or got.strip(" ") != want:
            err(path, f"{name}: Pulse liest {SECURITY_KEY} `{got}`, YAML `{want}` — den Wert als Text "
                      "auf die Zeile des Schluessels schreiben (ohne Anker, Escape, Block-Skalar)")
    # Gegenrichtung wie bei x-pulse-release (check_pulse_view).
    for name, seen_by_pulse in pulse.items():
        if SECURITY_KEY not in seen_by_pulse["x"]:
            continue
        svc = services.get(name)
        if isinstance(svc, dict) and SECURITY_KEY in svc:
            continue
        err(path, f"{name}: Pulse liest hier `{SECURITY_KEY}: {seen_by_pulse['x'][SECURITY_KEY][:60]}`, "
                  "YAML nicht — die Zeile steht z. B. in einem Block-Skalar; Pulse hielte den Dienst "
                  "gegen diese Quelle")


def split_image(ref: str) -> tuple[str, str | None, str | None]:
    """'host:5050/a/b:tag@sha256:...' -> (name, tag, digest)."""
    name, _, digest = ref.partition("@")
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        base, _, tag = name.rpartition(":")
        return base, tag, digest or None
    return name, None, digest or None

errors: list[str] = []
warnings: list[str] = []
undigested: list[str] = []
# O6: `build.local/<name>` → (Repo, Fundstelle) ueber alle Dateien eines Laufs.
release_names: dict[str, tuple[str, str]] = {}
# Namensraum-Alias wie Pulse (`PULSE_GITLAB_NAMESPACE_ALIASES`, Vorgabe `gitmi=mi`,
# mi/pulse pulselib/gitlab_paths.py `same_project`): gitmi/x und mi/x sind ein Projekt.
NAMESPACE_ALIASES = (("gitmi", "mi"),)


def same_project(a: str, b: str) -> bool:
    def norm(path: str) -> str:
        text = path.strip().strip("/").lower()
        text = text[:-4] if text.endswith(".git") else text
        for old, new in NAMESPACE_ALIASES:
            if text.startswith(old + "/"):
                text = new + text[len(old):]
        return text
    return norm(a) == norm(b)


def err(path: pathlib.Path, msg: str) -> None:
    errors.append(f"{path}: {msg}")


def warn(path: pathlib.Path, msg: str) -> None:
    warnings.append(f"{path}: {msg}")


def release_dockerfile(raw) -> tuple[str, str]:
    """O6: `x-pulse-release-dockerfile` wie Pulse (`dockerfile_path`). `(Pfad, Fehler)`.

    Leer heisst `Dockerfile`, ein fuehrendes `./` faellt weg."""
    text = str(raw or "").strip()
    if not text:
        return RELEASE_DEFAULT_DOCKERFILE, ""
    rel = text[2:] if text.startswith("./") else text
    if text.startswith("/") or not rel or not all(RELEASE_PATH_PART.fullmatch(p) for p in rel.split("/")):
        return "", (f"{RELEASE_DOCKERFILE_KEY} `{text[:80]}` ist kein relativer Pfad in der Quelle "
                    "(kein `/` am Anfang, kein `..`, kein Teil mit `.` vorne, nur A-Z a-z 0-9 . _ @ + -)")
    return rel, ""


def check_release(path: pathlib.Path, where: str, svc: dict, repo: str) -> dict | None:
    """4.7: ein eigenes Release — so, wie Pulse es bauen und tauschen kann.

    Gibt den Dienst fuer die Pruefung je Repo (`check_release_groups`) zurueck,
    `None` bei einem ungueltigen Projektpfad."""
    if not RELEASE_REPO.match(repo):
        err(path, f"{where}: x-pulse-release `{repo}` ist kein Projektpfad (gitmi/<name>)")
        return None
    # O6: der Image-Name kommt aus x-pulse-release-image, sonst aus dem Repo.
    own_name = str(svc.get(RELEASE_IMAGE_KEY) or "").strip()
    if RELEASE_IMAGE_KEY in svc and not own_name:
        warn(path, f"{where}: {RELEASE_IMAGE_KEY} ist leer — es gilt der Repo-Name; Zeile entfernen")
    name_ok = not own_name or (len(own_name) <= 128 and RELEASE_IMAGE_NAME.fullmatch(own_name))
    if not name_ok:
        err(path, f"{where}: {RELEASE_IMAGE_KEY} `{own_name[:80]}` ist kein Image-Name "
                  "(a-z, 0-9, . _ -, hoechstens 128 Zeichen) — Pulse baut den Dienst dann nicht")
    name = own_name or repo.rsplit("/", 1)[-1]
    dockerfile, why = release_dockerfile(svc.get(RELEASE_DOCKERFILE_KEY))
    if why:
        err(path, f"{where}: {why} — Pulse baut den Dienst dann nicht")
    elif RELEASE_DOCKERFILE_KEY in svc and not str(svc.get(RELEASE_DOCKERFILE_KEY) or "").strip():
        warn(path, f"{where}: {RELEASE_DOCKERFILE_KEY} ist leer — es gilt `Dockerfile`; Zeile entfernen")
    image = str(svc.get("image") or "")
    base, tag, digest = split_image(image)
    if name_ok and (base != RELEASE_PREFIX + name or not tag or not RELEASE_TAG.match(tag) or digest):
        hint = (f" (Name aus {RELEASE_IMAGE_KEY})" if own_name else
                f" (Name aus x-pulse-release; ein anderer per {RELEASE_IMAGE_KEY})"
                if base.startswith(RELEASE_PREFIX) and base != RELEASE_PREFIX + name else "")
        err(path, f"{where}: eigenes Release braucht `image: {RELEASE_PREFIX}{name}:X.Y.Z` "
                  f"(ohne Digest){hint}, steht `{image}`")
    if name_ok:
        prev_repo, prev_where = release_names.setdefault(name, (repo, f"{path}: {where}"))
        if not same_project(prev_repo, repo):
            err(path, f"{where}: `{RELEASE_PREFIX}{name}` gehoert schon zu {prev_repo} ({prev_where}) — "
                      f"ein Image-Name, ein Repo; anderen Namen per {RELEASE_IMAGE_KEY}")
    if str(svc.get("pull_policy", "")).lower() != "never":
        err(path, f"{where}: eigenes Release braucht `pull_policy: never` — das Image ist in keiner Registry")
    if "build" in svc:
        err(path, f"{where}: eigenes Release ohne `build:` — gebaut wird im Runner")
    # Pulse 5.10: gebaut wird immer im Runner (docker/); fuer die anderen
    # Host-Ordner laedt Pulse das Image per SSH auf die VM ihres Portainers.
    if path.parent.parent.name not in HOSTS:
        err(path, f"{where}: eigenes Release nur in einem Host-Ordner ({', '.join(HOSTS)})")
    # Wie Pulse: leer heisst `VERSION`.
    ver = str(svc.get(RELEASE_VERSION_KEY) or "VERSION").strip()
    if not ver or ".." in ver or ver.startswith("/"):
        err(path, f"{where}: {RELEASE_VERSION_KEY} `{ver}` ist kein Dateiname")
    return {"service": where, "repo": repo, "image": image, "version": ver,
            "dockerfile": dockerfile or RELEASE_DEFAULT_DOCKERFILE}


def invalid_release(svc: dict) -> bool:
    """Ein nicht leeres, aber ungueltiges x-pulse-release (eigene Meldung in check_release)."""
    repo = str(svc.get("x-pulse-release") or "").strip()
    return bool(repo) and not RELEASE_REPO.match(repo)


def check_release_groups(path: pathlib.Path, services: dict, released: list[dict]) -> None:
    """O6: die Dienste eines Compose je Repo — Pulse macht daraus einen Release-MR.

    Wie Pulse (`release_groups`, `run_step`, `with_image` mit `count`): gleiche
    `x-pulse-release-version`; jede `image:`-Zeile eines Release-Images gehoert
    zu einem Dienst dieses Repos mit `x-pulse-release`, sonst legt Pulse keinen
    MR an (der fremde Dienst bliebe still auf der alten Fassung). Dazu, ueber
    Pulse hinaus: ein Image wird aus einem Dockerfile gebaut — Dienste mit
    demselben Image und verschiedenen Dockerfiles waeren mehrdeutig."""
    groups: dict[str, list[dict]] = {}
    for item in released:
        groups.setdefault(item["repo"], []).append(item)
    for repo, group in groups.items():
        first = group[0]
        for item in group[1:]:
            if item["version"] != first["version"]:
                err(path, f"{item['service']}: {RELEASE_VERSION_KEY} `{item['version']}` weicht von "
                          f"`{first['version']}` ({first['service']}) ab — Dienste aus {repo} gehen nur "
                          "gemeinsam auf eine Fassung")
        by_image: dict[str, list[dict]] = {}
        for item in group:
            if item["image"]:
                by_image.setdefault(item["image"], []).append(item)
        for image, items in by_image.items():
            # Pulse zaehlt jede `image:`-Zeile, auch die anderer Gruppen (Repo-String
            # woertlich: gitmi/note ist hier eine andere Gruppe als mi/note) und die
            # von Diensten mit leerem x-pulse-release. Aus nimmt der Lint nur Dienste
            # mit ungueltigem, nicht leerem x-pulse-release — sie haben ihre Meldung.
            mine = {i["service"] for i in items}
            others = [str(n) for n, s in services.items()
                      if isinstance(s, dict) and str(s.get("image") or "") == image
                      and str(n) not in mine and not invalid_release(s)]
            if others:
                err(path, f"`image: {image}` tragen auch {', '.join(others)} ohne `x-pulse-release: {repo}` "
                          "— Pulse legt dann keinen Release-MR an; dort x-pulse-release setzen oder ein "
                          "eigenes Image")
        # Ein Image (ohne Tag) wird aus genau einem Dockerfile gebaut.
        by_name: dict[str, list[dict]] = {}
        for item in group:
            if item["image"]:
                by_name.setdefault(split_image(item["image"])[0], []).append(item)
        for base, items in by_name.items():
            files = sorted({i["dockerfile"] for i in items})
            if len(files) > 1:
                err(path, f"`{base}` ({', '.join(i['service'] for i in items)}) aus verschiedenen "
                          f"Dockerfiles ({', '.join(files)}) — ein Image, ein {RELEASE_DOCKERFILE_KEY}")


# --------------------------------------------------------------------------- #
# Was Pulse liest (O6): Pulse nimmt nicht PyYAML, sondern einen Zeilen-Leser
# (mi/pulse pulselib/compose_lite.py). Fuer Release-Dienste muss er dasselbe
# lesen wie YAML — sonst baut Pulse still aus dem falschen Dockerfile oder
# findet den Dienst gar nicht. Die drei Funktionen unten sind eine Abschrift
# von `_strip_comment`, `_unquote` und `parse_compose` (Stand mi/pulse 90221d2),
# beschraenkt auf `image` und die `x-pulse-*`-Schluessel.
# --------------------------------------------------------------------------- #

YAML_STR = "tag:yaml.org,2002:str"
YAML_MERGE = "tag:yaml.org,2002:merge"


def _pulse_strip_comment(line: str) -> str:
    out, quote = [], None
    for i, ch in enumerate(line):
        if quote:
            out.append(ch)
            if ch == quote and line[i - 1: i] != "\\":
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (not out or out[-1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _pulse_unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def pulse_services(text: str) -> dict[str, dict]:
    """`{dienst: {"image": …, "x": {schluessel: wert}}}` so, wie Pulse das Compose liest."""
    services: dict[str, dict] = {}
    in_services, svc_indent, current, block, block_indent = False, None, None, None, None
    for raw in (text or "").splitlines():
        if not raw.strip():
            continue
        line = _pulse_strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if indent == 0:
            in_services = body.split(":", 1)[0].strip() in ("services",)
            svc_indent = current = block = None
            continue
        if not in_services:
            continue
        if svc_indent is None:
            svc_indent = indent
        if indent == svc_indent and body.endswith(":"):
            current = _pulse_unquote(body[:-1])
            services[current] = {"image": None, "x": {}}
            block = block_indent = None
            continue
        if current is None:
            continue
        if block and indent > (block_indent or 0):
            continue
        block = block_indent = None
        if body in ("labels:", "environment:"):
            block, block_indent = body[:-1], indent
            continue
        if ":" in body:
            key, _, value = body.partition(":")
            key, value = _pulse_unquote(key), _pulse_unquote(value)
            if key == "image":
                services[current]["image"] = value or None
            if key.startswith("x-pulse-"):
                services[current]["x"][key] = value
    return services


def _pulse_line_value(text: str, line_no: int) -> str:
    """Der Wert einer `schluessel: wert`-Zeile, wie Pulse ihn liest."""
    lines = text.splitlines()
    body = _pulse_strip_comment(lines[line_no]).strip() if line_no < len(lines) else ""
    return _pulse_unquote(body.partition(":")[2])


def scalar_problem(text: str, key_node, val_node) -> str:
    """Warum Pulse den Wert anders liest als YAML — leer, wenn beide gleich lesen."""
    if not isinstance(val_node, yaml.ScalarNode):
        return "ist kein einfacher Wert"
    line = key_node.start_mark.line
    source = text[val_node.start_mark.index:val_node.end_mark.index]
    if val_node.style in ("|", ">"):
        return "ist ein Block-Skalar (`|`/`>`) — Pulse liest nur die Zeile des Schluessels, also leer"
    if val_node.start_mark.line != line or val_node.end_mark.line != line:
        return "steht nicht ganz auf der Zeile des Schluessels — Pulse liest nur diese Zeile"
    empty_plain = val_node.style is None and val_node.value == "" and not source.strip()
    if val_node.tag != YAML_STR and not empty_plain:
        return (f"`{source.strip()[:40]}` ist fuer YAML kein Text ({val_node.tag.rsplit(':', 1)[-1]}) "
                "— in Anfuehrungszeichen setzen")
    if val_node.style == '"' and "\\" in source:
        return "enthaelt `\\` in doppelten Anfuehrungszeichen — Pulse liest Escapes woertlich"
    if val_node.style == "'" and "''" in source[1:-1]:
        return "enthaelt `''` in einfachen Anfuehrungszeichen — Pulse liest es woertlich"
    pulse = _pulse_line_value(text, line)
    if pulse != val_node.value:
        return f"Pulse liest `{pulse[:60]}`, YAML `{val_node.value[:60]}` (Anker, Alias, Tag?)"
    return ""


def release_related(svc) -> bool:
    if not isinstance(svc, dict):
        return False
    return (any(str(k).startswith("x-pulse-release") for k in svc)
            or split_image(str(svc.get("image") or ""))[0].startswith(RELEASE_PREFIX))


def check_pulse_view(path: pathlib.Path, text: str, services: dict) -> None:
    """O6: Release-Dienste so schreiben, dass Pulses Zeilen-Leser dasselbe liest wie YAML."""
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return
    svc_map = None
    if isinstance(root, yaml.MappingNode):
        for key_node, val_node in root.value:
            if isinstance(key_node, yaml.ScalarNode) and key_node.value == "services":
                svc_map = val_node
    if not isinstance(svc_map, yaml.MappingNode):
        return
    pulse = pulse_services(text)
    seen: dict[int, str] = {}
    for key_node, val_node in svc_map.value:
        name = str(key_node.value)
        svc = services.get(name)
        if not release_related(svc):
            continue
        prev = seen.setdefault(id(val_node), name)
        if prev != name:
            err(path, f"{name}: Release-Dienst als Alias von {prev} — Pulse liest Anker und Aliase "
                      "nicht; den Dienst ausschreiben")
            continue
        if not isinstance(val_node, yaml.MappingNode) or val_node.flow_style:
            err(path, f"{name}: Release-Dienst als `{{…}}` auf einer Zeile — Pulse liest nur "
                      "eingerueckte Zeilen `schluessel: wert`")
            continue
        bad = False
        for k, v in val_node.value:
            if k.tag == YAML_MERGE or k.value == "<<":
                err(path, f"{name}: `<<`-Merge in einem Release-Dienst — Pulse liest Anker und Merges "
                          "nicht und saehe Image bzw. x-pulse-release nicht; Schluessel ausschreiben")
                bad = True
        for k, v in val_node.value:
            key = str(k.value)
            if key != "image" and not key.startswith("x-pulse-release"):
                continue
            if key.startswith("x-pulse-") and not isinstance(v, yaml.ScalarNode):
                continue  # meldet check_refs
            why = scalar_problem(text, k, v)
            if why:
                err(path, f"{name}: {key} {why}")
                bad = True
        if bad:
            continue
        # Gesamtvergleich: findet Pulse den Dienst mit denselben Werten?
        seen_by_pulse = pulse.get(name)
        if seen_by_pulse is None:
            err(path, f"{name}: Pulse findet den Release-Dienst nicht — die Zeile `{name}:` muss allein "
                      "stehen (ohne Anker oder Wert)")
            continue
        want_image = str(svc.get("image") or "") or None
        if seen_by_pulse["image"] != want_image:
            err(path, f"{name}: Pulse liest image `{seen_by_pulse['image']}`, YAML `{want_image}`")
        keys = {k for k in svc if str(k).startswith("x-pulse-release")} | \
               {k for k in seen_by_pulse["x"] if k.startswith("x-pulse-release")}
        for key in sorted(keys):
            want = None if key not in svc else "" if svc[key] is None else str(svc[key])
            got = seen_by_pulse["x"].get(key)
            if got != want:
                err(path, f"{name}: Pulse liest {key} `{got}`, YAML `{want}`")
    # Umgekehrt: Dienste, die nur Pulses Zeilen-Leser fuer Release-Dienste haelt
    # (z. B. eine Zeile `x-pulse-release: …` in einem Block-Skalar unter `command: >`).
    for name, seen_by_pulse in pulse.items():
        repo = str(seen_by_pulse["x"].get("x-pulse-release") or "").strip()
        if not repo or release_related(services.get(name)):
            continue
        err(path, f"{name}: Pulse liest hier `x-pulse-release: {repo[:60]}`, YAML nicht — die Zeile steht "
                  "z. B. in einem Block-Skalar; Pulse wuerde den Dienst als eigenes Release behandeln")


def env_items(env) -> list[tuple[str, str]]:
    """environment als Liste (KEY=VAL) oder Mapping -> [(key, val)]."""
    out = []
    if isinstance(env, dict):
        for k, v in env.items():
            out.append((str(k), "" if v is None else str(v)))
    elif isinstance(env, list):
        for item in env:
            s = str(item)
            k, _, v = s.partition("=")
            out.append((k, v))
    return out


def check_file(path: pathlib.Path, seen_names: dict, seen_ips: dict) -> None:
    text = path.read_text(encoding="utf-8")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        err(path, f"kein gueltiges YAML: {exc}")
        return
    if not isinstance(doc, dict) or not isinstance(doc.get("services"), dict):
        err(path, "kein `services:`-Block")
        return
    if "version" in doc:
        warn(path, "`version:` ist veraltet und wird von Compose ignoriert")
    check_refs(path, doc)
    check_security(path, text, doc["services"])

    released: list[dict] = []
    for svc_name, svc in doc["services"].items():
        if not isinstance(svc, dict):
            err(path, f"{svc_name}: Dienst ist kein Mapping")
            continue
        where = f"{svc_name}"

        image = svc.get("image")
        release = svc.get("x-pulse-release")
        if "x-pulse-release" in svc and not str(release or "").strip():
            # Pulse: `repo = str(x.get(RELEASE_KEY) or "").strip()`, leer → kein Release.
            err(path, f"{where}: x-pulse-release ist leer — Pulse uebergeht den Dienst still "
                      "(kein Bau, kein Release-MR); Repo eintragen oder Zeile entfernen")
        elif release is not None:
            item = check_release(path, where, svc, str(release).strip())
            if item:
                released.append(item)
        else:
            # O6: ohne x-pulse-release liest Pulse die Release-Schluessel nicht.
            for key in (RELEASE_IMAGE_KEY, RELEASE_DOCKERFILE_KEY, RELEASE_VERSION_KEY):
                if key in svc:
                    err(path, f"{where}: {key} ohne x-pulse-release — Pulse liest ihn nur bei einem "
                              "eigenen Release; Zeile entfernen oder x-pulse-release setzen")
        if image is None and "build" not in svc:
            err(path, f"{where}: weder image: noch build:")
        elif image is not None and release is not None:
            pass
        elif image is not None:
            _name, tag, digest = split_image(str(image))
            if not tag:
                err(path, f"{where}: image `{image}` ohne Tag")
            elif not digest and "build" not in svc:
                undigested.append(f"{path.parent.parent.name}/{path.parent.name}:{svc_name}")

        if str(svc.get("pull_policy", "")).lower() == "always":
            err(path, f"{where}: pull_policy: always ist nicht erlaubt")

        for vol in svc.get("volumes") or []:
            src = vol.get("source", "") if isinstance(vol, dict) else str(vol).split(":", 1)[0]
            if src.startswith("./") or src.startswith("../") or src == ".":
                err(path, f"{where}: relativer Bind-Mount `{src}`")

        cname = svc.get("container_name")
        if cname:
            prev = seen_names.setdefault(cname, path)
            if prev != path:
                err(path, f"{where}: container_name `{cname}` schon in {prev}")

        nets = svc.get("networks")
        shared = str(svc.get("x-pulse-ip-shared", "")).strip()
        if isinstance(nets, dict):
            for net, cfg in nets.items():
                ip = (cfg or {}).get("ipv4_address") if isinstance(cfg, dict) else None
                if ip:
                    prev_path, prev_shared = seen_ips.setdefault(ip, (path, bool(shared)))
                    if prev_path != path and not (shared and prev_shared):
                        err(path, f"{where}: ipv4_address {ip} schon in {prev_path}")

        restart = str(svc.get("restart", "")).strip().strip('"').lower()
        # Pulse 5.4: ohne restart-Zeile gilt der Dienst als laufend — die
        # Policy setzt Pulse. Nur `restart: "no"` heisst "muss nicht laufen".
        must_run = restart != "no"
        if restart not in ("", "no") and not str(svc.get("x-pulse-protected", "")).strip():
            warn(path, f"{where}: restart: {restart} — seit Pulse 5.4 setzt Pulse die Restart-Policy; "
                       "Zeile entfernen oder x-pulse-protected mit Grund")
        health = svc.get("x-pulse-health")
        if must_run and "healthcheck" not in svc:
            if health == "image":
                pass
            elif health == "none":
                if not str(svc.get("x-pulse-health-reason", "")).strip():
                    err(path, f"{where}: x-pulse-health: none braucht x-pulse-health-reason")
            else:
                err(path, f"{where}: laeuft dauerhaft, aber ohne healthcheck "
                          "(oder x-pulse-health: image|none)")
        if "healthcheck" in svc and health:
            warn(path, f"{where}: healthcheck und x-pulse-health zugleich — eines reicht")

        for key, val in env_items(svc.get("environment")):
            if SECRET_KEY.search(key) and not SECRET_KEY_EXCEPT.search(key):
                if val and "${" not in val:
                    err(path, f"{where}: {key} steht im Klartext — als ${{VAR}} auslagern")

    check_release_groups(path, doc["services"], released)
    check_pulse_view(path, text, doc["services"])


def main(argv: list[str]) -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    if argv:
        files = [pathlib.Path(a) for a in argv]
    else:
        files = sorted(p for h in HOSTS for p in (root / h).glob("*/compose.y*ml"))
    if not files:
        print("keine Compose-Dateien gefunden")
        return 1

    per_host: dict[str, tuple[dict, dict]] = {}
    for path in files:
        host = path.parent.parent.name
        names, ips = per_host.setdefault(host, ({}, {}))
        check_file(path, names, ips)

    if undigested:
        warnings.append(f"{len(undigested)} Image(s) ohne Digest — Renovate pinnt sie beim ersten Lauf: "
                        + ", ".join(undigested))
    for w in warnings:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERR   {e}")
    print(f"{len(files)} Datei(en), {len(errors)} Fehler, {len(warnings)} Hinweise")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

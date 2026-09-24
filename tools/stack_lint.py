#!/usr/bin/env python3
"""Stack-Lint: die Regeln, die ein Compose in diesem Repo einhalten muss.

Kopie aus gitmi/stacks (Stand 24.09.2026). Bei Aenderungen an den Regeln
beide Repos nachziehen.

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
  ERR  jeder Dienst, der laufen soll (restart != "no"), hat einen
       healthcheck — oder `x-pulse-health: image` (Image bringt einen mit)
       oder `x-pulse-health: none` mit `x-pulse-health-reason`
  ERR  Umgebungsvariablen, deren Name nach Geheimnis aussieht
       (PASSWORD, SECRET, TOKEN, _KEY, API_KEY), sind ${VAR}-Verweise
  ERR  Pulse-Regeln (4.1) sind flach und gueltig: `x-pulse-ref` ist vendor,
       follow, manual oder none; vendor braucht `x-pulse-ref-source` (https)
       und `x-pulse-ref-service`; follow einen Leitdienst im selben Compose;
       `x-pulse-ref-match` ist exact, minor oder major; Platzhalter
       `{dienst:major|minor|tag}` nennen Dienste dieses Compose
  ERR  `x-pulse-snapshot` auf oberster Ebene ist `always` (oder fehlt)
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

HOSTS = ("docker", "docker-vault", "docker-data")
SECRET_KEY = re.compile(r"(PASSWORD|SECRET|TOKEN|_KEY$|API_KEY)", re.I)
# Namen, die zwar TOKEN/KEY enthalten, aber keine Geheimnisse sind.
SECRET_KEY_EXCEPT = re.compile(r"(_ID|_ENABLED|_HEADER|_HOST|_PORT|_URL|_FILE|_PATH)$", re.I)

# 4.1: Regeln zur Hersteller-Empfehlung (Pulse, automation/vendor_refs.py).
REF_TYPES = ("vendor", "follow", "manual", "none")
REF_MATCHES = ("exact", "minor", "major")
PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_.-]+):(major|minor|tag)\}")
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


def err(path: pathlib.Path, msg: str) -> None:
    errors.append(f"{path}: {msg}")


def warn(path: pathlib.Path, msg: str) -> None:
    warnings.append(f"{path}: {msg}")


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
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        err(path, f"kein gueltiges YAML: {exc}")
        return
    if not isinstance(doc, dict) or not isinstance(doc.get("services"), dict):
        err(path, "kein `services:`-Block")
        return
    if "version" in doc:
        warn(path, "`version:` ist veraltet und wird von Compose ignoriert")
    check_refs(path, doc)

    for svc_name, svc in doc["services"].items():
        if not isinstance(svc, dict):
            err(path, f"{svc_name}: Dienst ist kein Mapping")
            continue
        where = f"{svc_name}"

        image = svc.get("image")
        if image is None and "build" not in svc:
            err(path, f"{where}: weder image: noch build:")
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
        must_run = restart not in ("no", "")
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

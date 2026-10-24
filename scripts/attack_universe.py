"""Pin, refresh and version-check the MITRE ATT&CK Enterprise universe the battery maps against.

The pinned universe is ``src/ildottore/shared/data/attack-enterprise-<version>.json``: the
tactics of the Enterprise matrix in matrix order, every **current** technique and sub-technique
with its name and the tactics it sits under, and every **retired** ID (revoked or deprecated)
with what replaced it. It is derived from the official STIX 2.1 bundle in
``mitre-attack/attack-stix-data``, found through that repository's collection index, the same
two sources the Feedly *Map ATT&CK Techniques* skill checks at run time. Il Dottore pins
instead of fetching: a coverage figure has to be reproducible from the repository alone, and a
run must never need the network for a denominator.

Three subcommands, standard library only:

* ``check``: fetch the collection index and say whether a newer Enterprise release than the
  pinned one exists (exit 1 when it does). Cheap (33 KB); for a scheduled job.
* ``refresh``: fetch the index, resolve the newest release (or ``--version X.Y``), download its
  bundle, derive the compact universe, write it beside the old one and print what changed:
  tactics added, removed or renamed; techniques added, removed, renamed or re-homed; IDs newly
  retired, and which shipped specs declare them. The old file is removed only when the new one
  is written, so the two never coexist in a wheel.
* ``diff``: print the same change report between two pinned files, nothing fetched.

``--index PATH`` and ``--bundle PATH`` read local copies instead of fetching (offline, and how
the first pin was made: the bundle is 55 MB, keep it out of the repository). A bundle read from
disk is still checked against the index entry's URL and the SHA-256 recorded in the pin.

Usage::

    python -I scripts/attack_universe.py check
    python -I scripts/attack_universe.py refresh [--version 20.0] [--index I.json --bundle B.json]
    python -I scripts/attack_universe.py diff OLD.json NEW.json

The version string a Navigator layer carries (``versions.attack``) is the major version
(``"20"``), which is what the Navigator itself writes; the pin keeps the full ``20.0``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
COLLECTION = "Enterprise ATT&CK"
DOMAIN = "enterprise"
DATA_DIR = Path(__file__).resolve().parent.parent / "src" / "ildottore" / "shared" / "data"
FILE_RE = re.compile(r"^attack-enterprise-(\d+\.\d+)\.json$")
_BATTERY = Path(__file__).resolve().parent.parent / "src" / "ildottore" / "battery" / "attacks"


#: Upper bound on one download. The v20.0 Enterprise bundle is about 45 MB; a response past
#: this is refused rather than read whole (a redirect gone wrong, a mirror that is not MITRE).
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024


def _get(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "ildottore-attack-universe"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as response:  # noqa: S310
        raw: bytes = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(raw) > MAX_DOWNLOAD_BYTES:
        raise SystemExit(f"refusing {url}: larger than {MAX_DOWNLOAD_BYTES} bytes")
    return raw


def _vtuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split(".") if p.isdigit())


def _ext_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return str(ref["external_id"])
    return None


def load_index(path: Path | None) -> dict[str, Any]:
    raw = path.read_bytes() if path is not None else _get(INDEX_URL)
    index: dict[str, Any] = json.loads(raw)
    return index


def resolve(index: dict[str, Any], version: str | None) -> dict[str, Any]:
    """The index entry of the Enterprise release ``version`` (newest when ``None``)."""

    collection = next(c for c in index["collections"] if c["name"] == COLLECTION)
    versions = collection["versions"]
    if version is not None:
        matches = [v for v in versions if v["version"] == version]
        if not matches:
            known = ", ".join(v["version"] for v in versions[:6])
            raise SystemExit(
                f"{COLLECTION} {version} is not in the collection index; newest: {known}"
            )
        return dict(matches[0])
    # ``2-beta`` style pre-releases carry a non-numeric part; they never win.
    return dict(max(versions, key=lambda v: _vtuple(str(v["version"]))))


def derive(
    bundle: dict[str, Any], entry: dict[str, Any], *, sha256: str, index_modified: str
) -> dict[str, Any]:
    """The compact universe: tactics in matrix order, current techniques, retired IDs."""

    objects = bundle["objects"]
    by_stix_id = {o["id"]: o for o in objects}
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix")
    tactics = []
    for ref in matrix["tactic_refs"]:
        tactic = by_stix_id[ref]
        tactics.append(
            {
                "id": _ext_id(tactic),
                "shortname": tactic["x_mitre_shortname"],
                "name": tactic["name"],
            }
        )
    replaced_by: dict[str, str] = {}
    for rel in objects:
        if rel["type"] == "relationship" and rel["relationship_type"] == "revoked-by":
            source = _ext_id(by_stix_id[rel["source_ref"]])
            target = _ext_id(by_stix_id[rel["target_ref"]])
            if source and target:
                replaced_by[source] = target
    techniques: dict[str, dict[str, Any]] = {}
    retired: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj["type"] != "attack-pattern":
            continue
        tid = _ext_id(obj)
        if tid is None:
            continue
        if obj.get("revoked"):
            retired[tid] = {
                "name": obj["name"],
                "status": "revoked",
                "replaced_by": replaced_by.get(tid),
            }
        elif obj.get("x_mitre_deprecated"):
            retired[tid] = {
                "name": obj["name"],
                "status": "deprecated",
                "replaced_by": replaced_by.get(tid),
            }
        else:
            techniques[tid] = {
                "name": obj["name"],
                "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
                "subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            }
    return {
        "domain": DOMAIN,
        "version": entry["version"],
        "modified": entry["modified"],
        "source": {
            "index_url": INDEX_URL,
            "index_modified": index_modified,
            "bundle_url": entry["url"],
            "bundle_sha256": sha256,
        },
        "generated_by": "scripts/attack_universe.py",
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
        "retired": dict(sorted(retired.items())),
    }


def _pinned_files() -> list[Path]:
    return sorted(p for p in DATA_DIR.glob("attack-enterprise-*.json") if FILE_RE.match(p.name))


def _shipped_declarations() -> dict[str, list[str]]:
    """``technique id -> spec ids`` for every ``mitre_attack`` entry in the shipped battery.

    Read by a regular expression on purpose: this script runs with ``-I`` and without the
    package installed, and a YAML parser is not in the standard library.
    """

    declared: dict[str, list[str]] = {}
    pattern = re.compile(r"^\s*-\s*id:\s*\"?(T\d{4}(?:\.\d{3})?)\"?", re.MULTILINE)
    for spec_file in sorted(_BATTERY.glob("*.yaml")):
        text = spec_file.read_text(encoding="utf-8")
        head = text.split("\nmitre_attack:", 1)
        if len(head) != 2:
            continue
        block = head[1].split("\nnist_ai_rmf:", 1)[0]
        for match in pattern.finditer(block):
            declared.setdefault(match.group(1), []).append(spec_file.stem)
    return declared


def change_report(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """What moved between two pins, in the terms a spec author has to act on."""

    lines = [f"{COLLECTION}: {old['version']} -> {new['version']} (modified {new['modified']})"]
    old_tactics = {t["id"]: t for t in old["tactics"]}
    new_tactics = {t["id"]: t for t in new["tactics"]}
    for tid in sorted(set(new_tactics) - set(old_tactics)):
        lines.append(f"  tactic added:   {tid} {new_tactics[tid]['name']}")
    for tid in sorted(set(old_tactics) - set(new_tactics)):
        lines.append(f"  tactic removed: {tid} {old_tactics[tid]['name']}")
    for tid in sorted(set(old_tactics) & set(new_tactics)):
        if old_tactics[tid]["name"] != new_tactics[tid]["name"]:
            lines.append(
                f"  tactic renamed: {tid} {old_tactics[tid]['name']!r} "
                f"-> {new_tactics[tid]['name']!r}"
            )
    old_t, new_t = old["techniques"], new["techniques"]
    added = sorted(set(new_t) - set(old_t))
    removed = sorted(set(old_t) - set(new_t))
    lines.append(
        f"  techniques: {len(old_t)} -> {len(new_t)} ({len(added)} added, {len(removed)} gone)"
    )
    for tid in added:
        lines.append(
            f"    added:    {tid} {new_t[tid]['name']} [{', '.join(new_t[tid]['tactics'])}]"
        )
    declared = _shipped_declarations()
    for tid in removed:
        fate = new["retired"].get(tid)
        where = (
            f"{fate['status']}, replaced by {fate['replaced_by'] or 'nothing'}"
            if fate
            else "absent from the bundle"
        )
        users = f"; DECLARED BY {', '.join(declared[tid])}" if tid in declared else ""
        lines.append(f"    gone:     {tid} {old_t[tid]['name']} ({where}){users}")
    for tid in sorted(set(old_t) & set(new_t)):
        before, after = old_t[tid], new_t[tid]
        if before["name"] != after["name"]:
            lines.append(f"    renamed:  {tid} {before['name']!r} -> {after['name']!r}")
        if before["tactics"] != after["tactics"]:
            lines.append(
                f"    re-homed: {tid} [{', '.join(before['tactics'])}] "
                f"-> [{', '.join(after['tactics'])}]"
            )
    stale = sorted(tid for tid in declared if tid not in new_t)
    if stale:
        lines.append("  shipped specs now declare an ID that is not current:")
        lines.extend(f"    {tid}: {', '.join(declared[tid])}" for tid in stale)
    else:
        lines.append("  every ID the shipped specs declare is current in the new pin")
    return lines


def cmd_check(args: argparse.Namespace) -> int:
    index = load_index(args.index)
    newest = resolve(index, None)
    pins = _pinned_files()
    pinned = FILE_RE.match(pins[-1].name).group(1) if pins else None  # type: ignore[union-attr]
    print(
        f"pinned: {pinned or 'nothing'}; newest in the collection index: {newest['version']} "
        f"(modified {newest['modified']})"
    )
    if pinned is None or _vtuple(newest["version"]) > _vtuple(pinned):
        print("a newer release exists: run `refresh`, read the change report, re-map what moved")
        return 1
    print("the pin is current")
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    index = load_index(args.index)
    entry = resolve(index, args.version)
    if args.bundle is not None:
        raw = Path(args.bundle).read_bytes()
    else:
        print(f"downloading {entry['url']} (about 55 MB)", file=sys.stderr)
        raw = _get(entry["url"])
    sha256 = hashlib.sha256(raw).hexdigest()
    bundle = json.loads(raw)
    collection = next(o for o in bundle["objects"] if o["type"] == "x-mitre-collection")
    if collection["x_mitre_version"] != entry["version"]:
        raise SystemExit(
            f"the bundle says it is {collection['x_mitre_version']}, the index entry says "
            f"{entry['version']}: not pinning a bundle that disagrees with its index"
        )
    new = derive(bundle, entry, sha256=sha256, index_modified=index["modified"])
    target = DATA_DIR / f"attack-enterprise-{entry['version']}.json"
    old_files = [p for p in _pinned_files() if p != target]
    if old_files:
        old = json.loads(old_files[-1].read_text(encoding="utf-8"))
        print("\n".join(change_report(old, new)))
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(new, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    for stale in old_files:
        stale.unlink()
    print(
        f"wrote {target} ({len(new['techniques'])} current techniques, "
        f"{len(new['retired'])} retired, {len(new['tactics'])} tactics)"
    )
    if old_files:
        print(
            "now update ATTACK_VERSION in src/ildottore/shared/attack.py "
            "and the figures in the docs"
        )
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    old = json.loads(Path(args.old).read_text(encoding="utf-8"))
    new = json.loads(Path(args.new).read_text(encoding="utf-8"))
    print("\n".join(change_report(old, new)))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="is there a newer Enterprise release than the pin?")
    check.add_argument("--index", type=Path, help="a local copy of the collection index")
    check.set_defaults(func=cmd_check)
    refresh = sub.add_parser("refresh", help="download a release and re-pin the universe")
    refresh.add_argument("--version", help="pin this release instead of the newest")
    refresh.add_argument("--index", type=Path, help="a local copy of the collection index")
    refresh.add_argument("--bundle", type=Path, help="a local copy of the STIX bundle")
    refresh.set_defaults(func=cmd_refresh)
    diff = sub.add_parser("diff", help="change report between two pinned files")
    diff.add_argument("old")
    diff.add_argument("new")
    diff.set_defaults(func=cmd_diff)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())

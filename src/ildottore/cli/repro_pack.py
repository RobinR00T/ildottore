"""``dottore replay RUN_ID --pack DIR`` - one reproduction pack per failing finding (u12 A-111).

A pack is what an operator hands the owner of the target: a directory per failing finding with
the hash-verified evidence of each of its attempts, copied byte for byte, a ``finding.json`` that
says what was found under which tool and rules, a ``README.md`` that says how to reproduce it and
what to read, and a ``SHA256SUMS`` over all of it.

Read-only on the run: it reads the evidence tree and the run store after :func:`replay_checked`
has verified one against the other, and sends nothing. The README quotes the request the attempt
sent (the spec's attack, as stored, redacted) and the verdict; the reply, text a target wrote,
stays in the attempt file.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any

from ildottore.redactor import visible_controls
from ildottore.shared.digest import spec_digest
from ildottore.shared.enums import CONTROL, VerdictStatus
from ildottore.shared.models import AttackSpec, Attempt
from ildottore.store import ReplayResult, SqliteRunStore
from ildottore.store import paths as evidence_paths

__all__ = ["PACK_FORMAT", "PackError", "write_packs"]

#: Bumped when ``finding.json`` changes shape.
PACK_FORMAT = 1

_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


class PackError(ValueError):
    """The packs cannot be written as asked (no run record, a used directory, an unknown id)."""


def write_packs(
    result: ReplayResult,
    store: SqliteRunStore,
    evidence_root: Path,
    out: Path,
    specs: Mapping[str, AttackSpec],
    *,
    only: Collection[str] = (),
) -> list[Path]:
    """Write one pack per failing finding of ``result``'s run under ``out``; return their paths.

    ``only`` keeps the findings of those spec ids, each of which must have failed in the run.
    ``specs`` is the battery the operator reads now: a spec whose digest still matches the one the
    run recorded lends its name, OWASP code and CWE to the pack, any other is named as changed.
    ``out`` must not exist or be an empty directory: a pack never overwrites one.
    """

    run_id = result.run_id
    if not store.knows_run(run_id):
        raise PackError(f"the run store has no record of run {run_id!r}: a pack needs its findings")
    failing = [f for f in store.list_findings(run_id) if f["status"] == VerdictStatus.FAIL.value]
    wanted = set(only)
    unknown = sorted(wanted - {f["spec_id"] for f in failing})
    if unknown:
        raise PackError(f"no failing finding of {', '.join(unknown)} in run {run_id!r}")
    if wanted:
        failing = [f for f in failing if f["spec_id"] in wanted]
    if not failing:
        return []
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise PackError(f"{out} exists and is not an empty directory: a pack never overwrites")
    names = [_UNSAFE_NAME.sub("_", f["finding_id"]) for f in failing]
    if len(set(names)) != len(names):
        raise PackError("two findings of this run map to one directory name")

    verified = dict(zip(result.attempt_hashes, result.attempts, strict=True))
    context = store.get_run_context(run_id) or {}
    recorded = store.get_run_spec_digests(run_id) or {}
    run_row = store.get_run(run_id) or {}
    written = []
    for finding, name in zip(failing, names, strict=True):
        pack = out / name
        (pack / "attempts").mkdir(parents=True)
        refs = sorted(json.loads(finding["evidence_refs_json"]), key=lambda r: r["attempt_id"])
        evidence = []
        for ref in refs:
            digest = evidence_paths.validate_sha256(ref["sha256"])
            attempt = verified.get(digest)
            if attempt is None:  # check_manifest refuses this first; a pack never trusts a ref
                raise PackError(f"evidence {digest} of {finding['finding_id']} is not verified")
            source = evidence_paths.attempt_path(evidence_root, run_id, digest)
            (pack / "attempts" / f"{digest}.json").write_bytes(source.read_bytes())
            evidence.append((digest, attempt))
        spec, spec_note = _spec_for(finding["spec_id"], specs, recorded)
        document = _finding_document(finding, run_row, context, recorded, spec, evidence)
        (pack / "finding.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        (pack / "README.md").write_text(_readme(document, spec, spec_note, evidence))
        _write_sums(pack)
        written.append(pack)
    return written


def _spec_for(
    spec_id: str, specs: Mapping[str, AttackSpec], recorded: Mapping[str, str]
) -> tuple[AttackSpec | None, str | None]:
    """The spec to describe the finding with, or why there is none."""

    spec = specs.get(spec_id)
    if spec is None:
        return None, f"{spec_id} is not in the specs read now, so the pack names no spec detail"
    if recorded.get(spec_id) != spec_digest(spec):
        return None, (
            f"{spec_id} has changed since the run (its digest differs from the one recorded), "
            "so the pack names no spec detail"
        )
    return spec, None


def _finding_document(
    finding: Mapping[str, Any],
    run_row: Mapping[str, Any],
    context: Mapping[str, Any],
    recorded: Mapping[str, str],
    spec: AttackSpec | None,
    evidence: list[tuple[str, Attempt]],
) -> dict[str, Any]:
    trials = [a for _, a in evidence if a.mutation != CONTROL]
    return {
        "pack_format": PACK_FORMAT,
        "run_id": finding["run_id"],
        "finding_id": finding["finding_id"],
        "spec_id": finding["spec_id"],
        "target_id": run_row.get("target_id"),
        "status": finding["status"],
        "severity": finding["severity"],
        "reproducibility": finding["repro"],
        "attempts": len({a.attempt_id for a in trials}),
        "failed": len({a.attempt_id for a in trials if _status(a) == VerdictStatus.FAIL.value}),
        "runs": context.get("runs"),
        "tool_version": context.get("tool_version"),
        "judging_rules": context.get("judging_rules"),
        "judging_digest": context.get("judging_digest"),
        "spec_digest": recorded.get(finding["spec_id"]),
        "spec": None
        if spec is None
        else {"name": spec.name, "owasp": spec.owasp, "cwe": list(spec.cwe or [])},
        "evidence": [
            {
                "attempt_id": a.attempt_id,
                "mutation": a.mutation,
                "status": _status(a),
                "file": f"attempts/{digest}.json",
            }
            for digest, a in evidence
        ],
    }


def _status(attempt: Attempt) -> str | None:
    return attempt.verdict.status.value if attempt.verdict is not None else None


def _readme(
    document: Mapping[str, Any],
    spec: AttackSpec | None,
    spec_note: str | None,
    evidence: list[tuple[str, Attempt]],
) -> str:
    spec_id = document["spec_id"]
    lines = [
        f"# {visible_controls(document['finding_id'])}: reproduction pack",
        "",
        f"* **Run:** `{document['run_id']}`, Il Dottore {document['tool_version']}, judging rules "
        f"{document['judging_rules']}",
        f"* **Target:** `{visible_controls(str(document['target_id']))}`",
        f"* **Status:** {document['status']}, severity {document['severity']}, "
        f"{document['failed']} of {document['attempts']} attempts failed "
        f"(reproducibility {document['reproducibility']})",
    ]
    if spec is not None:
        cwe = ", ".join(spec.cwe or []) or "no CWE"
        lines += [
            f"* **Spec:** `{spec_id}`, {spec.name} (OWASP {spec.owasp}, {cwe})",
            "",
            *_visible_lines(spec.description.strip()),
        ]
    else:
        lines.append(f"* **Spec:** `{spec_id}` ({spec_note})")
    lines += [
        "",
        "## Reproduce it",
        "",
        "With Il Dottore, against a target file and a scope that authorize the same endpoint:",
        "",
        "```bash",
        f"dottore run -t <target.yaml> --scope <scope.yaml> --spec {spec_id} "
        f"--runs {document['runs']}",
        "```",
        "",
        "By hand: send the `request` of a failing attempt below. A value written "
        "`«REDACTED:<kind>:<hash>»` was masked when the evidence was stored (a secret, PII or a "
        "planted canary); a run with Il Dottore plants a fresh canary and checks for it.",
        "",
        "Before raising it, read the reply in each attempt file (`response.text`, "
        "`response.tool_calls`) against the verdict, as the manual's \"Confirming a finding by "
        'hand, family by family" says. Check the pack with `shasum -a 256 -c SHA256SUMS`; each '
        "attempt file is named by the SHA-256 of its content.",
        "",
        "## Attempts",
    ]
    shown: dict[str, str] = {}
    for digest, attempt in evidence:
        lines += ["", f"### `{visible_controls(attempt.attempt_id)}`: {_status(attempt)}", ""]
        lines.append(f"* **File:** `attempts/{digest}.json`")
        lines.append(f"* **Mutation:** `{visible_controls(attempt.mutation)}`")
        if attempt.verdict is not None:
            reasoning = visible_controls(attempt.verdict.reasoning)
            lines.append(f"* **Verdict:** {attempt.verdict.evaluator_type}, {reasoning}")
        if _status(attempt) == VerdictStatus.FAIL.value:
            request = attempt.request.model_dump(mode="json", exclude_none=True)
            request.pop("metadata", None)
            body = json.dumps(request, indent=2, ensure_ascii=False)
            if body in shown:
                lines += ["", f"Request sent: the same as `{shown[body]}`."]
                continue
            shown[body] = visible_controls(attempt.attempt_id)
            lines += ["", "Request sent:", ""]
            lines += _fenced(body, "json")
    return "\n".join(lines) + "\n"


def _fenced(text: str, info: str) -> list[str]:
    """``text`` in a code fence longer than any backtick run inside it."""

    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}{info}", *_visible_lines(text), fence]


def _visible_lines(text: str) -> list[str]:
    """Each line of ``text`` with the characters a terminal or a viewer acts on written out."""

    return [visible_controls(line) for line in text.splitlines()]


def _write_sums(pack: Path) -> None:
    files = sorted(p for p in pack.rglob("*") if p.is_file())
    sums = "".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(pack).as_posix()}\n"
        for p in files
    )
    (pack / "SHA256SUMS").write_text(sums)

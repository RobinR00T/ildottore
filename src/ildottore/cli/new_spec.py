"""``dottore new-spec`` - scaffold a new attack spec + empty fixtures (contract §5.5).

Produces a schema-shaped starter YAML the author fills in ("write a spec == write an
NSE script", ``docs/09 §1``). It emits **text** (or writes it to an operator-chosen
path); it never writes into the built-in battery (``src/ildottore/battery``, u13-owned,
contract §8). The scaffold is valid enough to lint after the author supplies real content.
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path

import yaml

from ildottore.cli.key_shape import key_shape
from ildottore.shared.enums import Category

__all__ = ["scaffold_spec", "write_scaffold"]

_CATEGORY_OWASP = {
    Category.PROMPT_INJECTION: "LLM01",
    Category.JAILBREAK: "LLM01",
    Category.DATA_LEAKAGE: "LLM02",
    Category.OUTPUT_SECURITY: "LLM05",
    Category.AGENT_TOOL_ABUSE: "LLM06",
    Category.RAG_SECURITY: "LLM08",
    Category.AVAILABILITY_COST: "LLM10",
}


def scaffold_spec(spec_id: str, *, family: str, category: str = "prompt_injection") -> str:
    """Return a schema-shaped starter spec YAML for ``spec_id``.

    ``family`` seeds the ``tags`` and the name; ``category`` picks a sensible default
    OWASP mapping. The author replaces the ``TODO`` placeholders and the fixtures with
    real vulnerable/hardened responses (which ``dottore lint`` then proves detect).
    """

    try:
        cat = Category(category)
    except ValueError as exc:
        raise ValueError(
            f"unknown category {category!r}; expected one of: "
            f"{', '.join(c.value for c in Category)}"
        ) from exc
    _check_id(spec_id)
    _check_family(family)
    owasp = _CATEGORY_OWASP.get(cat, "LLM01")
    name = _scalar(f"TODO short human name for {family}")
    return f"""id: {spec_id}
spec_version: "1.0"
name: {name}
category: {cat.value}
owasp: {owasp}
mitre_atlas:
  tactic: TODO
nist_ai_rmf: "TODO"
# iopc:                # Nova IoPC mapping; the shipped battery requires it (docs/15)
#   techniques: []
#   impacts: []
# aisvs: []            # optional: OWASP AISVS IDs a FAIL is evidence against (CONTRIBUTING)
# mitre_attack:        # optional: ATT&CK techniques the target is OBSERVED performing (docs/17)
#   techniques:
#     - id: T1699
#       occurrence: observed   # or capability-only (listed, never counted)
severity: medium
target_type: chatbot
requires: []
description: >
  TODO describe what this spec validates and what secure behaviour looks like.
attack:
  user_prompt: >
    TODO the attack carrier prompt.
mutations: [identity]
expected_secure_behavior:
  - TODO what a secure target does
evaluators:
  - type: refusal
scoring:
  impact: 2
  exploitability: 2
  confidence_threshold: 0.75
fixtures:
  vulnerable:
    response: >
      TODO a response that demonstrates the target was exploited.
    expect_verdict: fail
  hardened:
    response: >
      TODO a response that demonstrates the target stayed secure.
    expect_verdict: pass
tags: [{_scalar(family)}]
"""


#: A family written as it is: a word YAML reads back as the same text in a flow list.
_PLAIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_PLAIN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]*")


def _check_id(spec_id: str) -> None:
    """The schema's own id shape: the id becomes a file name (`--id ../evil` wrote outside --out,
    audit 2026-10-03, low), and `--stdout` printed a scaffold with any id, which lint then refused
    (u12 A-82)."""

    if not re.fullmatch(r"[A-Z]+(-[A-Z0-9]+)+", spec_id):
        raise ValueError(
            f"invalid spec id {spec_id!r}: use the schema's shape, uppercase segments joined by "
            "'-' (e.g. PI-XYZ-001)"
        )


def _check_family(family: str) -> None:
    """Refuse a ``--family`` the scaffold cannot carry (u12 A-82, CLI audit L10).

    It was written raw into the YAML, so a control character made a file ``lint`` then refused,
    and one holding ``: `` or ``]`` a file that did not parse. A control or format character
    (Unicode categories Cc and Cf, a line break and U+202E included) is refused, never echoed;
    any other text is written as a YAML string (:func:`_scalar`).
    """

    if not family.strip():
        raise ValueError("--family is empty; give the spec family, a word such as jailbreak")
    if any(unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") for ch in family):
        raise ValueError(
            "--family holds a control or format character (a line break, an escape, a "
            "direction override); give the spec family as plain text"
        )
    # A value shaped like a key is a credential pasted into the wrong flag, not a family: the
    # scaffold would print it whole (the rerun of the audit's M7 fuzz). Shaped like a key, not
    # merely what the redactor masks: its phone rule refused `CVE-2021-44228` (round-2 audit, L4).
    shape = key_shape(family)
    if shape is not None:
        raise ValueError(
            f"--family is {shape}, the shape of a key (not shown); give the spec family, a word "
            "such as jailbreak"
        )


def _scalar(text: str) -> str:
    """``text`` as YAML reads it back: plain when it is a plain word that reads back as itself,
    else double-quoted.

    JSON's double-quoted string is a YAML double-quoted scalar, so ``json.dumps`` writes one that
    reads back as written, with ``:``, ``#``, ``,``, ``]`` and quotes inside. A plain word is
    checked by reading it back, in a flow list as ``tags`` writes it: YAML 1.1 reads ``yes``,
    ``on``, ``null``, ``123`` and ``1.0`` as a boolean, a null or a number, not as the text.
    """

    shaped = _PLAIN.fullmatch(text) or (" " in text and _PLAIN_NAME.fullmatch(text))
    if shaped and yaml.safe_load(f"[{text}]") == [text]:
        return text
    return json.dumps(text, ensure_ascii=False)


def write_scaffold(
    out_dir: Path,
    spec_id: str,
    *,
    family: str,
    category: str = "prompt_injection",
) -> Path:
    """Write the scaffold to ``out_dir/<spec_id>.yaml`` and return the path.

    Refuses to overwrite an existing file (a scaffold never clobbers real work) and
    never targets the built-in battery - the operator chooses ``out_dir``.
    """

    # Built before anything is created: a refused --family or --category left an empty --out.
    text = scaffold_spec(spec_id, family=family, category=category)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{spec_id}.yaml"
    if path.exists():
        raise FileExistsError(f"{path} already exists; refusing to overwrite")
    path.write_text(text, encoding="utf-8")
    return path

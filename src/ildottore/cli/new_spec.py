"""``dottore new-spec`` - scaffold a new attack spec + empty fixtures (contract §5.5).

Produces a schema-shaped starter YAML the author fills in ("write a spec == write an
NSE script", ``docs/09 §1``). It emits **text** (or writes it to an operator-chosen
path); it never writes into the repo ``specs/`` tree (u13-owned, contract §8). The
scaffold is valid enough to lint after the author supplies real content.
"""

from __future__ import annotations

from pathlib import Path

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
    owasp = _CATEGORY_OWASP.get(cat, "LLM01")
    return f"""id: {spec_id}
spec_version: "1.0"
name: TODO short human name for {family}
category: {cat.value}
owasp: {owasp}
mitre_atlas:
  tactic: TODO
nist_ai_rmf: "TODO"
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
tags: [{family}]
"""


def write_scaffold(
    out_dir: Path,
    spec_id: str,
    *,
    family: str,
    category: str = "prompt_injection",
) -> Path:
    """Write the scaffold to ``out_dir/<spec_id>.yaml`` and return the path.

    Refuses to overwrite an existing file (a scaffold never clobbers real work) and
    never targets the repo ``specs/`` tree - the operator chooses ``out_dir``.
    """

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{spec_id}.yaml"
    if path.exists():
        raise FileExistsError(f"{path} already exists; refusing to overwrite")
    path.write_text(scaffold_spec(spec_id, family=family, category=category), encoding="utf-8")
    return path

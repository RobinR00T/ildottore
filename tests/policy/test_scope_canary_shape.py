"""An identity canary a reply can hold by chance is refused where it is declared (u08 A-85, item 1).

``authz_leak`` reads an identity's canary in another identity's reply as that identity's data
received, a confirmed Critical, and the scope took any text as a canary: ``ACME``, ``tenant-b``,
``ZZ-1``, ``invoice ready`` and ``12345678`` each failed ``DL-XTENANT-001`` through the CLI on
``7d01521f`` on a reply that merely said them (exit 2). ``load_scope`` refuses such a canary, so
every reader of the file stops before anything is sent, and the message never quotes it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ildottore.policy.errors import ScopeError
from ildottore.policy.scope import (
    MIN_CANARY_BITS,
    MIN_CANARY_CHARS,
    MIN_SINGLE_CLASS_CHARS,
    load_scope,
    weak_canary,
)


def _scope(tmp_path: Path, canary: str, *, name: str = "tenant-two", target: str = "acme") -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(
        'version: "1.0"\ntargets:\n'
        f"  - id: {target}\n    base_url: https://api.example.test\n    identities:\n"
        "      - name: tenant-a\n        auth_ref: env://KEY_A\n"
        f"      - name: {name}\n        auth_ref: env://KEY_B\n"
        f"        canary: {json.dumps(canary)}\n",
        encoding="utf-8",
    )
    return path


_LABEL = "holds, or is part of, an identity's name or the target id"
_ONE_CLASS = "and is shorter than 16 characters, so it reads as a word, a name or a number"
_REGULAR = "too few or too repeated to be a random token"


@pytest.mark.parametrize(
    ("canary", "why"),
    [
        ("ACME", "shorter than 8 characters"),
        ("ZZ-1", "shorter than 8 characters"),
        ("B-42", "shorter than 8 characters"),
        ("invoice ready", "holds a space"),
        ("tenant\tb2-x9", "holds a space"),
        ("tenant-b", f"holds only letters {_ONE_CLASS}"),
        ("Confidential", f"holds only letters {_ONE_CLASS}"),
        ("12345678", f"holds only digits {_ONE_CLASS}"),
        ("2026-10-16", f"holds only digits {_ONE_CLASS}"),
        ("COVID-19", _REGULAR),
        ("canary-1", _REGULAR),
        ("password1", _REGULAR),
        ("4111111111111111", _REGULAR),  # sixteen digits, one of them different
        ("abababababababab", _REGULAR),
    ],
)
def test_a_canary_ordinary_text_can_hold_is_refused(tmp_path: Path, canary: str, why: str) -> None:
    with pytest.raises(ScopeError) as caught:
        load_scope(_scope(tmp_path, canary))
    message = str(caught.value)
    assert why in message
    assert "identity 'tenant-two'" in message
    assert canary not in message  # the marker the target must not learn is never quoted


@pytest.mark.parametrize(
    ("canary", "name", "target"),
    [
        ("tenant-b2", "tenant-b2", "acme"),  # the identity's own name
        ("TENANT-B2", "tenant-b2", "acme"),  # in any case
        ("prod-2026", "tenant-two", "acme-prod-2026"),  # inside the target id
        ("tenant-a1", "tenant-two", "acme"),  # another identity's name, whole
        ("tenant-two-2026", "tenant-two", "acme"),  # a name inside the canary (audit LOW 4)
        ("acme-7f3a91c2e5d4", "tenant-two", "acme"),  # the target id inside the canary
    ],
)
def test_a_canary_that_holds_or_is_part_of_a_name_or_the_target_id_is_refused(
    tmp_path: Path, canary: str, name: str, target: str
) -> None:
    path = _scope(tmp_path, canary, name=name, target=target)
    if canary == "tenant-a1":
        path.write_text(path.read_text().replace("name: tenant-a\n", "name: tenant-a1\n"))
    with pytest.raises(ScopeError, match=_LABEL):
        load_scope(path)


@pytest.mark.parametrize(
    "canary",
    [
        "CANARY-B-7f3a91c2",
        "TENANT-B-CANARY-42",  # the names here are tenant-a and tenant-two
        "ZZ-CANARY-7f3a91",
        "ZYNAP_CANARY_ALPHA",  # one class, long and varied enough
        "2914177763170669",  # a random 16-digit number (audit LOW 4)
        "RAMVGNXAQHYOPRHL",  # a random all-letter token (audit LOW 4)
        "CANARY_B_{{run_id}}",
        "{{run_id}}",
    ],
)
def test_a_random_token_or_one_bound_to_the_run_is_accepted(tmp_path: Path, canary: str) -> None:
    scope = load_scope(_scope(tmp_path, canary))
    target = scope.target("acme")
    assert target is not None
    assert target.identities[1].canary == canary


def test_the_rule_is_one_function_the_loader_applies() -> None:
    assert (MIN_CANARY_CHARS, MIN_SINGLE_CLASS_CHARS, MIN_CANARY_BITS) == (8, 16, 36.0)
    assert weak_canary("CANARY-B-7f3a91c2", ["acme", "tenant-a", "tenant-b"]) is None
    assert weak_canary("ACME1234", ["acme1234-prod"]) is not None
    # A label under three characters is not looked for inside a canary: "b" is in most tokens.
    assert weak_canary("CANARY-B-7f3a91c2", ["a", "b"]) is None
    # An identity with no canary is not checked: the runner ignores an empty one.
    assert weak_canary("", []) is not None


def test_no_canary_and_an_empty_one_still_load(tmp_path: Path) -> None:
    path = _scope(tmp_path, "")
    assert load_scope(path).target("acme") is not None
    path.write_text(path.read_text().replace('        canary: ""\n', ""))
    assert load_scope(path).target("acme") is not None


def test_the_templates_commented_tenant_identity_loads(tmp_path: Path) -> None:
    """``specs/scope.example.yaml`` shows a second identity with a canary: uncommented, it loads."""

    # Where the template is: specs/ on this branch, examples/ once the battery moves (A-84).
    repo = Path(__file__).resolve().parents[2]
    template = next(
        path
        for path in (
            repo / "specs" / "scope.example.yaml",
            repo / "examples" / "scope.example.yaml",
        )
        if path.is_file()
    )
    lines = template.read_text(encoding="utf-8").splitlines()
    start = lines.index("      # - name: tenant-b")
    block = [line.replace("# ", "", 1) for line in lines[start : start + 3]]
    text = "\n".join(lines[:start] + block + lines[start + 3 :]) + "\n"
    path = tmp_path / "scope.yaml"
    path.write_text(text, encoding="utf-8")
    target = load_scope(path).target("openai-gpt-x-staging")
    assert target is not None
    assert [i.name for i in target.identities] == ["default", "tenant-b"]
    assert target.identities[1].canary == "CANARY-B-3f9c1e7a5b2d8064"

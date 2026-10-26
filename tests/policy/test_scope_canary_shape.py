"""An identity canary a reply can hold by chance is refused where it is declared (u08 A-85, item 1).

``authz_leak`` reads an identity's canary in another identity's reply as that identity's data
received, a confirmed Critical, and the scope took any text as a canary: ``ACME``, ``tenant-b``,
``ZZ-1``, ``invoice ready`` and ``12345678`` each failed ``DL-XTENANT-001`` through the CLI on
``7d01521f`` on a reply that merely said them (exit 2). ``load_scope`` refuses such a canary, so
every reader of the file stops before anything is sent, and the message never quotes it. The
floor is 16 characters, the length the 36-bit entropy floor lets a random token reach: at 8, the
refusal promised 8 while every 8 to 10 character canary and 46% of random 12-hex ones were refused
(audit of ``bc5ddcb1``, LOW 2). A canary that holds a name or the target id is refused only when
what is left without it falls under the floors (LOW 4).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ildottore.evaluators.base import foldable
from ildottore.policy.errors import ScopeError
from ildottore.policy.scope import (
    MIN_CANARY_BITS,
    MIN_CANARY_CHARS,
    load_scope,
    weak_canary,
)
from ildottore.shared.folding import folded

#: Distinct invisible characters (u08 A-93): the 16 variation selectors, and 15 format
#: characters (U+200B to U+200F, U+202A to U+202E, U+2060 to U+2064): varied as written, so
#: they carry the entropy the floors ask for until they are removed.
_SELECTORS = "".join(map(chr, range(0xFE00, 0xFE10)))
_FORMATS = "".join(
    map(chr, [*range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2060, 0x2065)])
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


_SHORT = "it is shorter than 16 characters"
_PART = "it is part of an identity's name or the target id"
_HOLDS = "it holds an identity's name or the target id, which a reply can name, and what is left"
_REGULAR = "too few or too repeated characters to be a random token"


@pytest.mark.parametrize(
    ("canary", "why"),
    [
        ("ACME", _SHORT),
        ("ZZ-1", _SHORT),
        ("tenant-b", _SHORT),
        ("Confidential", _SHORT),
        ("12345678", _SHORT),
        ("2026-10-16", _SHORT),
        ("COVID-19", _SHORT),
        ("canary-1", _SHORT),
        # Random, but under the floor: refused with the reason the docs state (audit LOW 2).
        ("a7K2p9Qx", _SHORT),
        ("a7K2p9QxZ4", _SHORT),
        ("7f3a91c2", _SHORT),
        ("a7K2p9QxZ4m8R1t", _SHORT),  # fifteen: one under the floor
        ("invoice ready for you", "holds a space"),
        ("tenant\tb2-x9-7f3a91", "holds a space"),
        ("4111111111111111", _REGULAR),  # sixteen digits, one of them different
        ("abababababababab", _REGULAR),
        ("1234123412341234", _REGULAR),  # 32 bits
    ],
)
def test_a_canary_ordinary_text_can_hold_is_refused(tmp_path: Path, canary: str, why: str) -> None:
    with pytest.raises(ScopeError) as caught:
        load_scope(_scope(tmp_path, canary))
    message = str(caught.value)
    assert why in message
    assert "identity 'tenant-two'" in message
    assert canary not in message  # the marker the target must not learn is never quoted
    assert "at least 16 random characters" in message  # the floor the docs state


@pytest.mark.parametrize(
    ("canary", "name", "target", "why"),
    [
        # Part of a name or of the target id, in any case: a reply naming it names the canary.
        ("tenant-b2-production", "tenant-b2-production-eu", "acme", _PART),
        ("TENANT-B2-PRODUCTION", "tenant-b2-production-eu", "acme", _PART),
        ("prod-2026-eu-west", "tenant-two", "acme-prod-2026-eu-west-1", _PART),
        # Holds one, and what is left without it falls under the floors.
        ("tenant-two-2026-10-16", "tenant-two", "acme", _HOLDS),
        ("TENANT-TWO-2026-10-16", "tenant-two", "acme", _HOLDS),
        ("acme-7f3a91c2e5d4", "tenant-two", "acme", _HOLDS),  # the target id
        ("tenant-a-tenant-a-x1", "tenant-two", "acme", _HOLDS),  # another identity's name
    ],
)
def test_a_canary_that_is_part_of_a_name_or_holds_one_with_a_weak_rest_is_refused(
    tmp_path: Path, canary: str, name: str, target: str, why: str
) -> None:
    with pytest.raises(ScopeError, match=why):
        load_scope(_scope(tmp_path, canary, name=name, target=target))


@pytest.mark.parametrize(
    ("canary", "name", "target"),
    [
        # A random canary that holds a label: what is left is a random token (audit LOW 4).
        ("CANARY-TENANT-B-3f9c1e7a5b2d8064", "tenant-b", "acme"),
        ("canary-tenant-b-3F9C1E7A5B2D8064", "tenant-b", "acme"),
        ("TGT-7f3a91c2e5d4b8a6", "tenant-two", "tgt"),
        ("ACME-3f9c1e7a5b2d8064", "tenant-two", "acme"),
    ],
)
def test_a_random_canary_that_holds_a_name_or_the_target_id_is_accepted(
    tmp_path: Path, canary: str, name: str, target: str
) -> None:
    scope = load_scope(_scope(tmp_path, canary, name=name, target=target))
    loaded = scope.target(target)
    assert loaded is not None
    assert loaded.identities[1].canary == canary


@pytest.mark.parametrize(
    "canary",
    [
        "a7K2p9QxZ4m8R1tY",  # sixteen random characters: the floor
        "CANARY-B-7f3a91c2",
        "TENANT-B-CANARY-42",  # the names here are tenant-a and tenant-two
        "ZZ-CANARY-7f3a91",
        "PLANTED_CANARY_ALPHA",  # one class, long and varied enough
        "2914177763170669",  # a random 16-digit number (audit LOW 4 of round 1)
        "RAMVGNXAQHYOPRHL",  # a random all-letter token (audit LOW 4 of round 1)
        "CANARY_B_{{run_id}}",
        "{{run_id}}",
    ],
)
def test_a_random_token_or_one_bound_to_the_run_is_accepted(tmp_path: Path, canary: str) -> None:
    scope = load_scope(_scope(tmp_path, canary))
    target = scope.target("acme")
    assert target is not None
    assert target.identities[1].canary == canary


@pytest.mark.parametrize(
    "canary",
    [
        "invoice-2026-0001",
        "admin@example.com",
        "2026-10-16T12:00",
        "v1.2.3-beta.4-rc1",
        "Internationalization",
    ],
)
def test_the_check_catches_obvious_shapes_only(tmp_path: Path, canary: str) -> None:
    """A structured id, an address, a timestamp, a version or a long word passes (LOW 3).

    The docs say so and recommend a random canary: a per-tenant sequential id can be another
    tenant's id too, and in its reply it is a confirmed crossing.
    """

    target = load_scope(_scope(tmp_path, canary)).target("acme")
    assert target is not None


def test_the_rule_is_one_function_the_loader_applies() -> None:
    assert (MIN_CANARY_CHARS, MIN_CANARY_BITS) == (16, 36.0)
    assert weak_canary("CANARY-B-7f3a91c2", ["acme", "tenant-a", "tenant-b"]) is None
    assert weak_canary("ACME1234-PROD-EU", ["acme1234-prod-eu-west"]) is not None
    # The longest label is taken out first, so a label inside another leaves nothing of it.
    assert weak_canary("tenant-b-west-7f3a91", ["tenant-b", "tenant-b-west"]) is not None
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
    """``examples/scope.example.yaml`` shows a second identity with a canary: uncommented, it
    loads."""

    # Where the template is: examples/ since the battery moved (u12 A-84), specs/ before it.
    repo = Path(__file__).resolve().parents[2]
    template = next(
        path
        for path in (
            repo / "examples" / "scope.example.yaml",
            repo / "specs" / "scope.example.yaml",
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


@pytest.mark.parametrize(
    "other",
    [
        "CANARY-B-3F9C1E7A5B2D8064",
        "canary-b-3f9c1e7a5b2d8064",
        "CANARY-B-3f9c1e7a​5b2d8064",
        "CANARY-B-3f9c1e7a5b2d8064⁠",
        "CANARY-B-3f9c1e7a\ufe0f5b2d8064",
        "CANARY-B-\u31643f9c1e7a5b2d8064",
    ],
    ids=[
        "upper",
        "lower",
        "zero-width-space",
        "word-joiner",
        "variation-selector",
        "hangul-filler",
    ],
)
def test_two_canaries_that_fold_alike_are_refused(tmp_path: Path, other: str) -> None:
    """``authz_leak`` reads a canary case-folded, invisible characters removed (u08 A-87): two that
    differ only there are one canary to it, and each owner's own would read as the other's leak.
    The canary is not quoted."""

    path = tmp_path / "scope.yaml"
    path.write_text(
        'version: "1.0"\ntargets:\n'
        "  - id: acme\n    base_url: https://api.example.test\n    identities:\n"
        "      - name: tenant-a\n        auth_ref: env://KEY_A\n"
        f"        canary: {json.dumps(other)}\n"
        "      - name: tenant-two\n        auth_ref: env://KEY_B\n"
        '        canary: "CANARY-B-3f9c1e7a5b2d8064"\n',
        encoding="utf-8",
    )
    with pytest.raises(ScopeError) as refused:
        load_scope(path)
    assert "differs from it only in letter case or invisible characters" in str(refused.value)
    assert "3f9c1e7a5b2d8064" not in str(refused.value).casefold()


_HIDDEN = "once its invisible characters are removed, as authz_leak reads it"


@pytest.mark.parametrize(
    ("canary", "why"),
    [
        ("ab" + _SELECTORS, _SHORT),
        ("ab" + _FORMATS, _SHORT),
        ("CANARY" + _FORMATS[:10], _SHORT),
        (
            "ab\u034f\u3164\u115f\u1160\u17b4\u17b5\u180b\u180c\u180d\u180e\u180f\uffa0\u061c\u00ad",
            _SHORT,
        ),
        (_SELECTORS, _SHORT),
        ("abcdabcd" + _SELECTORS[:4] + "abcdabcd", _REGULAR),
        ("AaBbCcDdAaBbCcDd", _REGULAR),
    ],
    ids=[
        "variation-selectors",
        "format-characters",
        "word-joiners",
        "grapheme-joiner-hangul-filler",
        "only-invisible",
        "regular-once-unpadded",
        "regular-once-case-folded",
    ],
)
def test_the_floors_measure_the_canary_as_it_is_read(tmp_path: Path, canary: str, why: str) -> None:
    """u08 A-93 (L3 of the A-92 audit): ``authz_leak`` and ``secret_leakage`` read a canary of the
    floors folded (``shared.folding.folded``), so the floors measure that form. On ``65203f18``
    they measured it as written: ``ab`` and the 16 variation selectors (or, before A-92 too, 15
    distinct format characters) passed, and every reply holding ``ab`` read as the identity's data
    received, a confirmed Critical. The canary is not quoted."""

    with pytest.raises(ScopeError) as refused:
        load_scope(_scope(tmp_path, canary))
    message = str(refused.value)
    assert why in message
    if folded(canary) != canary.casefold():
        assert _HIDDEN in message
    assert repr(canary) not in message and canary not in message
    assert weak_canary(canary, []) is not None


def test_a_canary_with_no_invisible_character_reads_as_before() -> None:
    """The reason names the invisible characters only when there were some to remove."""

    why = weak_canary("abcdabcdabcdabcd", [])
    assert why is not None and _REGULAR in why and _HIDDEN not in why
    assert weak_canary("CANARY-B-3f9c1e7a5b2d8064", ["acme", "tenant-a", "tenant-b"]) is None


def test_a_label_is_looked_for_in_the_canary_as_it_is_read() -> None:
    """A name split inside the canary by invisible characters is still that name."""

    canary = "tenant\u200b-b-\u200c\u200d\u2060\u2061\u2062" + "2026-10-16"
    assert weak_canary(canary.replace("\u200b", ""), ["tenant-b"]) is not None
    why = weak_canary(canary, ["tenant-b"])
    assert why is not None and why.startswith(_HOLDS)


@pytest.mark.parametrize(
    "canary",
    ["Straßenbahnhöfe", "Fußballstadions", "\ufb03" * 16, "ΐΰﬀﬁﬂﬃﬄﬅ"],
    ids=["sharp-s-15", "sharp-s-15-b", "ligature-repeated", "expanding-8"],
)
def test_case_folding_that_lengthens_a_canary_does_not_let_it_pass(canary: str) -> None:
    """Pre-merge audit of A-93, MEDIUM 1: ``ß`` folds to ``ss`` and ``ﬃ`` to ``ffi``, so measured
    folded alone a 15-character word reached 16 and a repeated ligature 44 bits. The floors hold
    for the visible form too, so each stays refused, as on ``65203f18``."""

    assert weak_canary(canary, []) is not None
    assert not foldable(canary)


def test_a_label_with_an_invisible_character_is_looked_for_as_it_is_read(tmp_path: Path) -> None:
    """Pre-merge audit of A-93, LOW 3: the labels are folded as the canary is, so an identity
    named with a zero-width space inside still names the canary that holds it."""

    with pytest.raises(ScopeError) as refused:
        load_scope(_scope(tmp_path, "tenant-b-2026-10-16-x", name="tenant\u200b-b"))
    assert _HOLDS in str(refused.value)
    assert weak_canary("tenant-b-2026-10-16-x", ["tenant\u200b-b"]) is not None


def test_a_label_short_only_once_folded_is_still_taken_out() -> None:
    """Delta audit of A-93, LOW 1: a name of three characters as written, one of them invisible, is
    two as read; it is still taken out of the canary, so what is left is measured, as on
    ``65203f18``."""

    canary = "ab\u200b" * 6 + "cdefghij"
    why = weak_canary(canary, ["tgt", "ab\u200b"])
    assert why is not None and why.startswith(_HOLDS)


def test_an_identity_canary_holding_a_spec_placeholder_is_refused(tmp_path: Path) -> None:
    """Only a spec's canary binds ``{{canary_prefix}}`` and ``{{canary_body}}`` (u08 A-100): the
    runner reads an identity's with ``{{run_id}}`` alone bound, so either would stay as text."""

    with pytest.raises(
        ScopeError, match=r"holds \{\{canary_prefix\}\}, \{\{canary_body\}\}, which only a spec's"
    ):
        load_scope(_scope(tmp_path, "{{canary_prefix}}{{canary_body}}"))
    with pytest.raises(ScopeError, match=r"holds \{\{canary_body\}\}, which only a spec's"):
        load_scope(_scope(tmp_path, "ORCHID-{{canary_body}}"))

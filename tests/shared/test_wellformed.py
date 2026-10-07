"""``shared.wellformed``: a lone surrogate reads as U+FFFD, everything else is kept (A-47)."""

from __future__ import annotations

import json
import time

import pytest

from ildottore.shared.wellformed import REPLACEMENT, well_formed_json, well_formed_text

_HIGH = chr(0xD800)
_LOW = chr(0xDC00)
_R = REPLACEMENT
_EMOJI = chr(0x1F600)
#: The two halves of U+1F600 as separate code points, as a CESU-8 body decodes.
_HALVES = chr(0xD83D) + chr(0xDE00)


def test_the_replacement_is_u_fffd() -> None:
    assert ord(REPLACEMENT) == 0xFFFD


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a" + _HIGH + "b", "a" + _R + "b"),
        ("a" + _LOW + "b", "a" + _R + "b"),
        (_HIGH + _HIGH, _R + _R),
        (_LOW + _HIGH, _R + _R),
        ("ab" + _HIGH, "ab" + _R),
        (_LOW + "ab", _R + "ab"),
        (_HALVES, _EMOJI),
        ("x" + _HALVES + _HIGH, "x" + _EMOJI + _R),
        (_HIGH + _EMOJI, _R + _EMOJI),
        (_HIGH + _HALVES, _R + _EMOJI),
    ],
    ids=[
        "lone-high",
        "lone-low",
        "two-highs",
        "low-then-high",
        "high-at-end",
        "low-at-start",
        "halves-joined",
        "halves-then-lone",
        "lone-before-astral",
        "lone-before-halves",
    ],
)
def test_a_lone_surrogate_reads_as_the_replacement(text: str, expected: str) -> None:
    out = well_formed_text(text)
    assert out == expected
    out.encode("utf-8")


@pytest.mark.parametrize(
    "text",
    ["", "plain", "caf" + chr(0xE9), _EMOJI, _R, "a" + chr(0) + "b", chr(0xFFFF), chr(0x10FFFF)],
)
def test_a_text_with_no_surrogate_is_returned_as_it_is(text: str) -> None:
    assert well_formed_text(text) is text


def test_a_parsed_reply_is_copied_with_every_string_well_formed() -> None:
    value = {
        "id": "c" + _HIGH,
        "n": 3,
        "x": 1.5,
        "flag": True,
        "none": None,
        "choices": [{"message": {"content": "hi" + _LOW, "tool_calls": [{"name": _HIGH}]}}],
        "nested": [["a", [_HIGH, {"k": [_LOW]}]]],
    }
    out = well_formed_json(value)
    assert out == {
        "id": "c" + _R,
        "n": 3,
        "x": 1.5,
        "flag": True,
        "none": None,
        "choices": [{"message": {"content": "hi" + _R, "tool_calls": [{"name": _R}]}}],
        "nested": [["a", [_R, {"k": [_R]}]]],
    }
    json.dumps(out, ensure_ascii=False).encode("utf-8")
    assert value["id"] == "c" + _HIGH  # the input is not changed


def test_a_parsed_reply_keeps_its_order() -> None:
    value = {"b" + _HIGH: 1, "a": 2, "c": [3, "x" + _LOW, 4]}
    out = well_formed_json(value)
    assert list(out) == ["b" + _R, "a", "c"]
    assert out["c"] == [3, "x" + _R, 4]


@pytest.mark.parametrize("scalar", ["s", 1, 1.0, True, None])
def test_a_scalar_at_the_top_is_returned(scalar: object) -> None:
    assert well_formed_json(scalar) == scalar


def test_two_keys_that_read_the_same_keep_both_values() -> None:
    """``{"to<D800>": a, "to<DC00>": b}`` both read ``to<FFFD>``: a plain copy dropped ``a``,
    and a forbidden argument value could leave what the evaluators read."""

    value = {"to" + _HIGH: "first", "to" + _LOW: "evil@example.test", "to" + _HIGH + _HIGH: "x"}
    out = well_formed_json(value)
    assert sorted(out.values()) == ["evil@example.test", "first", "x"]
    assert out["to" + _R] == "first"
    assert out["to" + _R + ", #2"] == "evil@example.test"
    assert out["to" + _R + _R] == "x"


def test_a_well_formed_key_keeps_its_name_against_a_replaced_one() -> None:
    """A key the target wrote with U+FFFD itself is not renamed because a lone surrogate
    elsewhere reads the same: the replaced one moves, wherever it comes in the object."""

    for value in ({"k" + _HIGH: 1, "k" + _R: 2}, {"k" + _R: 2, "k" + _HIGH: 1}):
        out = well_formed_json(value)
        assert out["k" + _R] == 2
        assert out["k" + _R + ", #2"] == 1


def test_a_replaced_key_skips_a_suffixed_name_already_written() -> None:
    value = {"k" + _R + ", #2": "taken", "k" + _R: "plain", "k" + _HIGH: "a", "k" + _LOW: "b"}
    out = well_formed_json(value)
    assert out["k" + _R + ", #2"] == "taken"
    assert out["k" + _R] == "plain"
    assert {out["k" + _R + ", #3"], out["k" + _R + ", #4"]} == {"a", "b"}
    assert len(out) == 4


def test_many_colliding_keys_stay_linear() -> None:
    """Each base counts on from its last number, so n keys landing on one name cost n steps,
    not n squared: 20,000 keys take milliseconds, and some 2 x 10^8 steps if each one searched
    from ``, #2`` again. The bound is loose because sessions in parallel load the machine."""

    halves = [chr(0xD800 + i) for i in range(200)]
    value = {
        "k" + a + b: n for n, (a, b) in enumerate((a, b) for a in halves[:100] for b in halves)
    }
    assert len(value) == 20_000
    start = time.perf_counter()
    out = well_formed_json(value)
    elapsed = time.perf_counter() - start
    assert sorted(out.values()) == list(range(20_000))
    assert elapsed < 15.0


def test_a_value_nested_past_the_recursion_limit_is_walked() -> None:
    """``json.loads`` builds tens of thousands of levels; the walk keeps no Python stack."""

    depth = 50_000
    value = json.loads("[" * depth + json.dumps("x") + "]" * depth)
    inner = value
    for _ in range(depth - 1):
        inner = inner[0]
    inner[0] = "x" + _HIGH
    out = well_formed_json(value)
    for _ in range(depth):
        out = out[0]
    assert out == "x" + _R


def test_a_reply_with_no_surrogate_is_returned_as_it_is() -> None:
    """The same object, not a copy: copying every reply tripled the peak memory of a 4 MiB body
    of small containers, surrogate or not (pre-commit audit)."""

    value = {"items": [{"t": "abcdefgh", "n": i, "f": [1.5, None, True]} for i in range(10_000)]}
    assert well_formed_json(value) is value
    assert well_formed_json([[], {}, [[{"k": "v"}]]]) == [[], {}, [[{"k": "v"}]]]


@pytest.mark.parametrize(
    "value",
    [
        {"a": [{"k" + _HIGH: 1}]},
        [[[[{"x": [0, "y" + _LOW]}]]]],
        {"a": 1, "b": [None, True, 2.5, {"c": {"d" + _HIGH: {}}}]},
    ],
    ids=["key-in-a-list", "value-deep-in-lists", "key-after-scalars"],
)
def test_a_surrogate_anywhere_is_found(value: object) -> None:
    out = well_formed_json(value)
    assert out is not value
    json.dumps(out, ensure_ascii=False).encode("utf-8")

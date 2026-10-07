"""``shared.wellformed``: a lone surrogate reads as U+FFFD, everything else is kept (A-47)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
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


def test_a_parsed_reply_is_made_well_formed_in_place() -> None:
    value = {
        "id": "c" + _HIGH,
        "n": 3,
        "x": 1.5,
        "flag": True,
        "none": None,
        "choices": [{"message": {"content": "hi" + _LOW, "tool_calls": [{"name": _HIGH}]}}],
        "nested": [["a", [_HIGH, {"k": [_LOW]}]]],
    }
    choices = value["choices"]
    out = well_formed_json(value)
    assert out is value
    assert out["choices"] is choices
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


_PEAK = """
import json, resource, sys
from ildottore.shared.wellformed import well_formed_json
raw = sys.argv[1] * int(sys.argv[3]) + sys.argv[2] + sys.argv[4] * int(sys.argv[3])
base = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
value = json.loads(raw)
parsed = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
well_formed_json(value)
walked = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(parsed - base, walked - parsed)
"""


@pytest.mark.parametrize(
    ("opening", "closing"), [("[", "]"), ('{"a":', "}")], ids=["lists", "dicts"]
)
def test_a_deep_reply_with_no_surrogate_costs_little_past_its_parse(
    opening: str, closing: str
) -> None:
    """A generator per level made a clean reply nested 115,000 levels cost four times main's
    peak memory, a chain over each dict's items two thirds more (pre-merge audit): the scan
    keeps one plain iterator per level. Peak memory is measured in a fresh process, so the
    machine's load does not change it."""

    depth = "100000"
    out = subprocess.run(  # noqa: S603 - our own interpreter, a fixed snippet
        [sys.executable, "-c", _PEAK, opening, "0", depth, closing],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    parse, walk = map(int, out.stdout.split())
    assert walk < parse / 2, (parse, walk)


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
    """The same object, unchanged: copying every reply tripled the peak memory of a 4 MiB body
    of small containers, surrogate or not (pre-commit audit)."""

    value: dict[str, object] = {
        "items": [{"t": "abcdefgh", "n": i, "f": [1.5, None, True]} for i in range(10_000)]
    }
    value["z"], value["a"] = 1, 2
    before = json.dumps(value)  # order sensitive, unlike ==
    assert well_formed_json(value) is value
    assert json.dumps(value) == before
    assert well_formed_json([[], {}, [[{"k": "v"}]]]) == [[], {}, [[{"k": "v"}]]]


def test_one_surrogate_copies_nothing() -> None:
    """Copying a reply that holds a surrogate gave a target the same tripled peak for three
    bytes (delta audit): every container stays the object it was, a dict refilled in place."""

    big = [[i, {"v": str(i)}] for i in range(1_000)]
    keyed = {"k" + _HIGH: 1, "j": 2}
    plain = {"z": 1, "a": 2}
    value = {"big": big, "keyed": keyed, "plain": plain, "s": "x" + _HIGH}
    out = well_formed_json(value)
    assert out is value
    assert out["big"] is big and out["big"][7] is big[7] and out["big"][7][1] is big[7][1]
    assert out["keyed"] is keyed and list(keyed) == ["k" + _R, "j"]
    assert out["plain"] is plain and list(plain) == ["z", "a"]
    assert out["s"] == "x" + _R


def test_a_renamed_key_repeated_in_many_dicts_stays_one_string() -> None:
    """``json.loads`` keeps one copy of a key every dict repeats; renaming it once per dict
    multiplied a long key's memory by the number of dicts (pre-merge audit)."""

    key = "a" * 1_000 + _HIGH
    value = json.loads(json.dumps([{key: i} for i in range(3)]))
    well_formed_json(value)
    names = [next(iter(d)) for d in value]
    assert names[0] == "a" * 1_000 + _R
    assert names[0] is names[1] is names[2]


@pytest.mark.parametrize(
    "value",
    [
        {"a": [{"k" + _HIGH: 1}]},
        [[[[{"x": [0, "y" + _LOW]}]]]],
        {"a": 1, "b": [None, True, 2.5, {"c": {"d" + _HIGH: {}}}]},
        {"a": [], "b": {}, "c": "x" + _HIGH},
        [[] for _ in range(2_000)] + ["x" + _HIGH],
        {**{f"k{i}": [] for i in range(2_000)}, "last": "x" + _LOW},
        [{f"k{i}": i} for i in range(2_000)] + [{"z" + _HIGH: 0}],
    ],
    ids=[
        "key-in-a-list",
        "value-deep-in-lists",
        "key-after-scalars",
        "after-sibling-containers",
        "after-many-list-items",
        "after-many-dict-entries",
        "key-after-many-dicts",
    ],
)
def test_a_surrogate_anywhere_is_found(value: object) -> None:
    """Wherever it sits, after sibling containers or thousands of entries included (a walk that
    stopped early passed the first three cases: delta audit)."""

    out = well_formed_json(value)
    json.dumps(out, ensure_ascii=False).encode("utf-8")

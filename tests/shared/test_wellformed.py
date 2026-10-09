"""``shared.wellformed``: a lone surrogate reads as U+FFFD, everything else is kept (A-47)."""

from __future__ import annotations

import json
import time
import tracemalloc
from collections.abc import Callable

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
        ("a" + chr(0xDBFF) + "b", "a" + _R + "b"),
        ("a" + chr(0xDFFF) + "b", "a" + _R + "b"),
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
        "last-high",
        "last-low",
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


def test_a_string_at_the_top_is_made_well_formed() -> None:
    """A reply that is one JSON string has no list or dict to set it in: it is returned fixed."""

    assert well_formed_json("a" + _HIGH) == "a" + _R


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


def _colliding(n: int) -> dict[str, int]:
    """``n`` keys that all read ``k`` plus two U+FFFD once replaced."""

    halves = [chr(0xD800 + i) for i in range(200)]
    pairs = ((a, b) for a in halves for b in halves)
    return {"k" + a + b: index for index, (a, b) in zip(range(n), pairs, strict=False)}


def _cpu_seconds(n: int) -> float:
    best = float("inf")
    for _ in range(3):
        value = _colliding(n)
        start = time.process_time()
        well_formed_json(value)
        best = min(best, time.process_time() - start)
    return best


def test_many_colliding_keys_stay_linear() -> None:
    """Each base counts on from its last number, so n keys landing on one name cost n steps,
    not n squared. Four times the keys cost about four times the CPU, and sixteen times if each
    key searched from ``, #2`` again; a bound on the clock let that pass on a quiet machine
    (pre-merge mutants). CPU time, best of three, is what other sessions' load moves least."""

    value = _colliding(20_000)
    out = well_formed_json(value)
    assert sorted(out.values()) == list(range(20_000))
    ratio = _cpu_seconds(20_000) / _cpu_seconds(5_000)
    assert ratio < 8, ratio


def _walk_memory(build: Callable[[], object]) -> tuple[int, int]:
    """Bytes the value ``build`` makes takes, and the most the walk over it allocates.

    ``tracemalloc`` counts this process's allocations only. Peak RSS in a child process did not
    work: ``ru_maxrss`` is a high-water mark kept across fork and exec, so a child of a large
    pytest process started at its parent's peak and measured nothing.
    """

    tracing = tracemalloc.is_tracing()
    if not tracing:
        tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        value = build()
        after = tracemalloc.get_traced_memory()[0]
        tracemalloc.reset_peak()
        well_formed_json(value)
        walk = tracemalloc.get_traced_memory()[1] - after
    finally:
        if not tracing:
            tracemalloc.stop()
    return after - before, walk


def _nested(kind: str, depth: int, leaf: Callable[[int], object] | None = None) -> object:
    """``depth`` levels of one-item lists or ``{"a": ...}`` dicts, or of pairs when ``leaf``
    gives a string to put beside each level."""

    value: object = 0
    for level in range(depth):
        if leaf is None:
            value = [value] if kind == "lists" else {"a": value}
        else:
            text = leaf(level)
            value = [text, value] if kind == "lists" else {"s": text, "d": value}
    return value


@pytest.mark.parametrize("kind", ["lists", "dicts"])
def test_a_deep_reply_with_no_surrogate_keeps_one_small_iterator_per_level(kind: str) -> None:
    """A generator per level made a clean reply nested 115,000 levels cost four times main's
    peak memory, a chain over each dict's items two thirds more (pre-merge audit): the scan
    keeps one plain iterator per level, some 56 bytes for a list and 80 for a dict, where those
    two cost about 690 and 240, and a fix walk with no scan first about 210 to 260. The nesting
    is built in Python, since ``json.loads`` stops near 1,000 levels on 3.11, the CI's version."""

    depth = 100_000
    _built, walk = _walk_memory(lambda: _nested(kind, depth))
    assert walk < 160 * depth, walk


@pytest.mark.parametrize("kind", ["lists", "dicts"])
def test_a_replaced_string_is_let_go_before_the_levels_below(kind: str) -> None:
    """Each level's iterator held the pair it last gave, and with it the string just replaced,
    until the levels below were fixed: 64 nested pairs of 64 KiB strings with a half kept all 64
    old strings alive (the walk took as much again as the strings, against a twentieth when each
    is let go; final delta audit). The strings are two bytes a character, so a replaced one is
    no larger."""

    built, walk = _walk_memory(
        lambda: _nested(kind, 64, lambda level: chr(0x101 + level) * 32_768 + _HIGH)
    )
    assert walk < built / 2, (built, walk)


def test_a_value_nested_past_the_recursion_limit_is_walked() -> None:
    """Nested far past any interpreter's recursion limit, built in Python so every supported
    version runs it (``json.loads`` builds 116,000 levels on 3.14, about 1,000 on 3.11)."""

    depth = 200_000
    value: object = "x" + _HIGH
    for _ in range(depth):
        value = [value]
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


def test_a_suffix_stays_in_the_dict_where_the_names_collided() -> None:
    """Sharing a suffixed name across dicts must not carry the suffix into a dict where the
    name is free."""

    value = [{"k" + _HIGH: 0, "k" + _LOW: 1}, {"k" + _LOW: 2}]
    well_formed_json(value)
    assert list(value[0]) == ["k" + _R, "k" + _R + ", #2"]
    assert list(value[1]) == ["k" + _R]


def test_a_suffixed_name_repeated_in_many_dicts_stays_one_string() -> None:
    """A suffixed name rebuilt for every dict cost four times the parse's peak on a body of
    dicts with colliding long keys (final delta audit)."""

    key = "a" * 1_000
    value = [{key + _HIGH: 0, key + _LOW: 1} for _ in range(3)]
    well_formed_json(value)
    suffixed = [list(d)[1] for d in value]
    assert suffixed[0] == "a" * 1_000 + _R + ", #2"
    assert suffixed[0] is suffixed[1] is suffixed[2]


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

"""JSON from a target parsed with its nesting bounded (``shared.nesting``, 2026-10-07)."""

from __future__ import annotations

import json

import pytest

from ildottore.shared import nesting
from ildottore.shared.nesting import MAX_DEPTH, NestedTooDeeply, bounded_loads, text_depth
from ildottore.shared.toolcalls import call_arguments


def _nested(levels: int) -> str:
    return "[" * levels + "]" * levels


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("null", 0),
        ('"[[["', 0),
        ("{}", 1),
        ("[[]]", 2),
        ('{"a": [{"b": 1}], "c": 2}', 3),
        ('[1, [2, [3]], {"x": {}}]', 3),
        # Brackets inside a string, an escaped quote and an escaped backslash are not structure.
        ('["[[[", "a\\"[[[", "b\\\\", {"c": "]]]"}]', 2),
        # An unterminated string runs to the end: its brackets are not structure either.
        ('["abc' + "[" * 500, 1),
    ],
)
def test_depth_is_read_from_the_brackets_outside_strings(text: str, expected: int) -> None:
    assert text_depth(text) == expected
    if expected and not text.endswith("["):
        assert text_depth(text) == _parsed_depth(json.loads(text))


def _parsed_depth(value: object) -> int:
    if isinstance(value, dict):
        return 1 + max((_parsed_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_parsed_depth(v) for v in value), default=0)
    return 0


def test_a_document_within_the_limit_parses_as_json_would() -> None:
    document = {"a": [1, {"b": "[[[["}], "c": None}
    text = json.dumps(document)
    assert bounded_loads(text) == document
    assert bounded_loads(text.encode()) == document  # bytes, as a body is read
    assert bounded_loads(text.encode("utf-16")) == document  # decoded as json.loads decodes
    assert bounded_loads(_nested(MAX_DEPTH)) == json.loads(_nested(MAX_DEPTH))
    # Many brackets, shallow: the measure runs and lets it through.
    wide = "[" + ",".join(["[]"] * 1000) + "]"
    assert bounded_loads(wide) == json.loads(wide)


@pytest.mark.parametrize("levels", [MAX_DEPTH + 1, 300, 200_000])
def test_a_document_past_the_limit_is_refused_as_bad_json(levels: int) -> None:
    """200,000 levels overflow the parser's stack; the others parse. Neither is parsed now."""

    with pytest.raises(NestedTooDeeply, match=f"nested more than {MAX_DEPTH} levels deep"):
        bounded_loads(_nested(levels))
    assert issubclass(NestedTooDeeply, ValueError)  # every `except ValueError` still holds


def test_objects_alone_count_as_much_as_arrays() -> None:
    deep = '{"a":' * (MAX_DEPTH + 1) + "1" + "}" * (MAX_DEPTH + 1)
    with pytest.raises(NestedTooDeeply):
        bounded_loads(deep)
    within = '{"a":' * MAX_DEPTH + "1" + "}" * MAX_DEPTH
    assert bounded_loads(within) == json.loads(within)


@pytest.mark.parametrize("levels", [MAX_DEPTH + 1, 20_000, 200_000])
def test_unbalanced_brackets_past_the_limit_are_not_json_on_every_python(levels: int) -> None:
    """The parser decided before: 20,000 unclosed ``[`` were "not JSON" on 3.14 (it reached the
    end) and a stack overflow on 3.12, so CI and a laptop disagreed (pre-commit audit, F2). Now
    they are not JSON everywhere, without being parsed."""

    for text in ("[" * levels, '{"choices": ' + "[" * levels + "1, 2", _nested(levels) + "]"):
        with pytest.raises(ValueError, match="do not balance") as caught:
            bounded_loads(text)
        assert not isinstance(caught.value, NestedTooDeeply)


def test_balanced_brackets_past_the_limit_are_too_deep_even_around_bad_json() -> None:
    with pytest.raises(NestedTooDeeply):
        bounded_loads("[" * (MAX_DEPTH + 1) + "x" + "]" * (MAX_DEPTH + 1))


def test_malformed_json_within_the_limit_is_still_the_parser_error() -> None:
    with pytest.raises(json.JSONDecodeError):
        bounded_loads("{not json")
    with pytest.raises(json.JSONDecodeError):
        bounded_loads("[" * MAX_DEPTH)
    with pytest.raises(json.JSONDecodeError):  # an unterminated string, not a deep one
        bounded_loads('["abc' + "[" * 500)


def test_depth_is_never_negative_and_a_repeated_key_only_over_counts() -> None:
    assert text_depth("]]][") == 0  # never above where it started
    assert text_depth("}") == 0
    # A key written twice keeps the last value: the text is deeper than what parses from it.
    assert text_depth('{"a": [[[1]]], "a": 1}') == 4
    assert bounded_loads('{"a": [[[1]]], "a": 1}') == {"a": 1}


def test_a_lone_surrogate_in_bytes_reads_as_json_loads_reads_it() -> None:
    raw = b'["' + "\ud800".encode("utf-8", "surrogatepass") + b'"]'
    assert bounded_loads(raw) == json.loads(raw)


_ADVERSARIAL = """\
import resource, sys, time
from ildottore.shared.nesting import bounded_loads
BS, Q = chr(92), chr(34)
n = 2_000_000
base = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
worst = 0.0
for tail in (BS, BS + chr(10), Q + "]" * 101):
    text = "[" * 101 + Q + (BS + Q) * n + tail
    start = time.perf_counter()
    try:
        bounded_loads(text)
    except ValueError:
        pass
    worst = max(worst, time.perf_counter() - start)
grown = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - base
print(worst, grown // (1024 * 1024 if sys.platform == "darwin" else 1024))
"""


def test_a_hostile_four_megabyte_string_is_measured_in_linear_time_and_memory() -> None:
    """A string that never closes and ends in a backslash made the string pattern fail and
    ``re.sub`` retry it from every escaped quote: 38 s for 160 KB, hours for 4 MiB (delta
    audit). Without ``DOTALL`` a backslash before a newline did the same; without possessive
    quantifiers each escape kept a backtracking mark, 241 MB for 4 MiB. In a subprocess, so a
    regression times out here instead of hanging the suite, and its memory is its own."""

    import subprocess
    import sys
    from pathlib import Path

    src = Path(nesting.__file__).resolve().parents[2]
    try:
        done = subprocess.run(  # noqa: S603 - our own interpreter, a fixed snippet
            [sys.executable, "-c", _ADVERSARIAL],
            capture_output=True,
            text=True,
            timeout=60,
            env={"PYTHONPATH": str(src), "PYTHONDONTWRITEBYTECODE": "1"},
            check=True,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("measuring 4 MiB of escaped quotes did not finish in 60 s")
    worst, grown_mb = done.stdout.split()
    assert float(worst) < 5.0, f"{worst} s for one 4 MiB text"
    assert int(grown_mb) < 120, f"{grown_mb} MB grown measuring 4 MiB"


def test_a_parser_overflow_the_measure_missed_is_still_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The backstop: whatever gets past the measure, a RecursionError never escapes."""

    def overflow(_text: str) -> object:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(nesting.json, "loads", overflow)
    with pytest.raises(NestedTooDeeply):
        bounded_loads("[1]")


@pytest.mark.parametrize("levels", [300, 200_000])
def test_tool_call_arguments_nested_too_deeply_read_as_no_arguments(levels: int) -> None:
    """A call from a fixture or a store: a live reply this deep is refused by its adapter."""

    call = {"function": {"name": "f", "arguments": '{"a":' + _nested(levels) + "}"}}
    assert call_arguments(call) == {}

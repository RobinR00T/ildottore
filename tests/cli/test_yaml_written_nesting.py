"""A YAML file written deeper than the depth limit is refused where it crosses, as it is composed.

The depth limit (100 levels, ``safe_yaml.MAX_DEPTH``) was measured only once the whole document
was composed (``safe_yaml.check_expanded``). PyYAML's pure-Python scanner keeps one possible simple
key per open flow level and walks them all on every token, so a token costs in proportion to the
levels open around it: a 198 KB list of chains of ``[`` 320 deep was refused ("document is nested
too deeply at line 1, column 101") only after composing all of it, 3 to 7 times what the same
number of flat texts takes (pre-commit audit of the construction-cost fix, 2026-10-07). A list or a
map written at level 101, inside 100 written ones, is now refused before it is composed, with the
same message and, mostly, the same position (clause A-52, u01). Since A-58 a document nests at
most 20 levels in flow style, so the shapes here reach level 101 in block style, or in block style
with 20 flow levels inside (``tests/cli/test_yaml_flow_nesting.py`` has the flow limit and the
scanner's cost).
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from typing import Any

import pytest
import yaml

from ildottore import safe_yaml
from ildottore.registry.schema import SafeLoadError, safe_load_yaml

#: The limit as the manual and contract u01 state it, pinned here rather than read from the code.
LIMIT = 100
#: The flow limit (A-58): flow shapes here stay within it.
FLOW = 20
TOO_DEEP = "document is nested too deeply"
LOADERS = [safe_yaml.safe_load, safe_load_yaml]


def under_maps(levels: int) -> str:
    """Block mappings ``levels`` deep, up to ``k: `` on line ``levels``: what follows is the value
    of the mapping at level ``levels``, written from column ``2 * levels + 2``."""

    return "".join("  " * i + "k:\n" for i in range(levels - 1)) + "  " * (levels - 1) + "k: "


def block_map(levels: int, leaf: str = "v") -> str:
    """Block mappings ``levels`` deep: the mapping at level ``n`` starts on line ``n``."""

    return "".join("  " * i + "k:\n" for i in range(levels)) + "  " * levels + leaf + "\n"


#: Block mappings this deep, then ``FLOW`` flow levels: the last of those opens level 101.
BLOCKS = LIMIT + 1 - FLOW
#: Each collection written exactly one level past the limit: the text up to the first entry of the
#: collection at level 101, included, the text after it, and where that collection starts (line,
#: column, from 1). A block mapping at level ``n`` starts at its first key, on line ``n``; a block
#: sequence at level ``n`` at column ``2 * n - 1``; the flow shapes start on line ``BLOCKS``.
CROSSING: dict[str, tuple[str, str, tuple[int, int]]] = {
    "flow sequences": (
        under_maps(BLOCKS) + "[" * FLOW + "a",
        "]" * FLOW + "\n",
        (BLOCKS, 2 * BLOCKS + 2 + FLOW - 1),
    ),
    "flow mappings": (
        under_maps(BLOCKS) + "{a: " * FLOW + "b",
        "}" * FLOW + "\n",
        (BLOCKS, 2 * BLOCKS + 2 + 4 * (FLOW - 1)),
    ),
    "block mappings": (block_map(LIMIT + 1), "", (LIMIT + 1, 2 * LIMIT + 1)),
    "block sequences": ("- " * (LIMIT + 1) + "x\n", "", (1, 2 * LIMIT + 1)),
}
#: Continuation lines of a flow collection inside block mappings, indented past them.
_PAD = " " * (2 * BLOCKS)
#: More entries of that collection, on the lines below its first, the last one starting with a
#: character no token can start: only composing the collection reaches it.
FURTHER = {
    "flow sequences": "".join(f",\n{_PAD}z{i}" for i in range(5)) + f",\n{_PAD}@",
    "flow mappings": "".join(f",\n{_PAD}z{i}: 1" for i in range(5)) + f",\n{_PAD}@: 1",
    "block mappings": "".join("  " * LIMIT + f"z{i}: 1\n" for i in range(5))
    + "  " * LIMIT
    + "@: 1\n",
    "block sequences": "".join("  " * LIMIT + f"- z{i}\n" for i in range(5))
    + "  " * LIMIT
    + "- @\n",
}


def problem_mark(text: str) -> tuple[int, int]:
    """Where ``safe_yaml.safe_load`` refuses ``text`` as too deep, as line and column from 1."""

    with pytest.raises(yaml.YAMLError) as caught:
        safe_yaml.safe_load(text)
    assert caught.value.problem == TOO_DEEP, caught.value  # type: ignore[attr-defined]
    mark = caught.value.problem_mark  # type: ignore[attr-defined]
    return mark.line + 1, mark.column + 1


def measured_after_composing(text: str) -> tuple[int, int]:
    """Where ``check_expanded`` refuses ``text`` once PyYAML has composed all of it, as before."""

    loader = yaml.SafeLoader(text)
    try:
        node = loader.get_single_node()  # type: ignore[no-untyped-call,unused-ignore]
    finally:
        loader.dispose()  # type: ignore[no-untyped-call,unused-ignore]
    assert node is not None
    with pytest.raises(yaml.YAMLError) as caught:
        safe_yaml.check_expanded(node)
    mark = caught.value.problem_mark  # type: ignore[attr-defined]
    return mark.line + 1, mark.column + 1


# --- the loaders -----------------------------------------------------------------------------


@pytest.mark.parametrize("shape", list(CROSSING))
@pytest.mark.parametrize("load", LOADERS)
def test_composition_stops_where_a_collection_opens_past_the_limit(
    load: Callable[[str], Any], shape: str
) -> None:
    """A character no token can start, in the collection at level 101 and lines below its start,
    is never reached: on the base it was, and the file was refused for it instead (``found
    character '@' that cannot start any token``). A refusal made once that collection is composed
    would reach it too."""

    head, tail, (line, column) = CROSSING[shape]

    with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
        load(head + FURTHER[shape] + tail)

    assert TOO_DEEP in str(caught.value), caught.value
    assert f"line {line}, column {column}" in str(caught.value), caught.value


@pytest.mark.parametrize("shape", list(CROSSING))
def test_the_position_is_the_one_measured_after_composing(shape: str) -> None:
    """For one branch, the refusal is where ``check_expanded`` put it with the document whole."""

    head, tail, where = CROSSING[shape]

    assert problem_mark(head + tail) == where == measured_after_composing(head + tail)


def test_with_several_branches_the_first_one_written_past_the_limit_is_named() -> None:
    """The document is not composed past it, so a deeper branch written later is never seen;
    ``check_expanded`` names the deepest branch, which only a whole document shows."""

    first = "- " + "- " * LIMIT + "x\n"  # an item of the root list, then lists to level 101
    deeper = "- " + "- " * (LIMIT + 50) + "x\n"
    text = first + deeper

    assert problem_mark(text) == (1, 2 * LIMIT + 1)
    assert measured_after_composing(text) == (2, 2 * LIMIT + 1)


def test_an_empty_list_past_the_limit_is_named_where_it_starts() -> None:
    """``k: []`` in the map at level 100: ``check_expanded`` names the first node of the deepest
    level, the key ``k`` (an empty list is as deep as a text); the list is what opens level 101."""

    text = block_map(LIMIT - 1, leaf="k: []")

    assert problem_mark(text) == (LIMIT, 2 * (LIMIT - 1) + 4)
    assert measured_after_composing(text) == (LIMIT, 2 * (LIMIT - 1) + 1)


@pytest.mark.parametrize(
    "text",
    [
        "- " * LIMIT + "a\n",  # a text
        "- &a x\n- " + "- " * (LIMIT - 1) + "*a\n",  # an alias
        block_map(LIMIT),  # the key and the value of the map at level 100
    ],
)
def test_a_leaf_written_past_the_limit_is_measured_after_composing_as_before(text: str) -> None:
    """A text or an alias opens no level, so the scanner pays what it pays at the limit: it is
    left to ``check_expanded``, which names it where it named it before (an alias at its anchor,
    on line 1; the map's key before its value)."""

    assert problem_mark(text) == measured_after_composing(text)


@pytest.mark.parametrize("load", LOADERS)
def test_a_document_written_at_the_limit_loads_as_before(load: Callable[[str], Any]) -> None:
    """Every shape at exactly the limit, siblings included (the count goes back down after each
    chain), builds the value plain PyYAML builds."""

    at_limit = [
        "- " * (LIMIT - 1) + "[]",
        "- " * (LIMIT - 1) + "a",
        under_maps(LIMIT - FLOW - 1) + "[" * FLOW + "a" + "]" * FLOW + "\n",
        under_maps(LIMIT - FLOW - 1) + "{a: " * FLOW + "b" + "}" * FLOW + "\n",
        block_map(LIMIT - 1),
        "".join("- " + "- " * (LIMIT - 2) + "a\n" for _ in range(50)),
        "".join("  " * i + "k:\n" for i in range(LIMIT - FLOW - 2))
        + "".join(
            "  " * (LIMIT - FLOW - 2) + f"s{i}: " + "[" * FLOW + "a" + "]" * FLOW + "\n"
            for i in range(9)
        ),
    ]

    for text in at_limit:
        assert load(text) == yaml.safe_load(text), text[:40]


@pytest.mark.parametrize("load", LOADERS)
def test_the_limit_written_past_first_is_the_one_reported(
    load: Callable[[str], Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Composition stops at the first of the two: the nodes written past the size cap, or a list or
    a map written past the depth limit. On the base a file written deep was composed on until its
    nodes passed the cap, and was reported as too large."""

    monkeypatch.setattr(safe_yaml, "MAX_NODES", 1_000)
    texts = "x, " * 1_200
    deep_first = "- " * LIMIT + "[" + texts + "]"
    large_first = "[" + texts + "[" * FLOW + "]" * FLOW + "]"

    with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
        load(deep_first)
    assert TOO_DEEP in str(caught.value), caught.value
    assert f"line 1, column {2 * LIMIT + 1}" in str(caught.value), caught.value
    with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
        load(large_first)
    assert "document is too large" in str(caught.value), caught.value


@pytest.mark.parametrize("load", LOADERS)
def test_a_list_past_the_limit_comes_before_the_count_its_parents_end_would_cross(
    load: Callable[[str], Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A list or a map is counted once it is composed, so the order reported is the order the
    checks are made, not the order written: 999 texts, then lists 100 deep, whose ends would take
    the count past a cap of 1,000, are refused at the list that opens level 101 (pre-merge audit;
    before A-52, too large at that list, once its text and its end were counted)."""

    monkeypatch.setattr(safe_yaml, "MAX_NODES", 1_000)
    text = "- x\n" * 999 + "- " + "- " * LIMIT + "y\n"

    with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
        load(text)

    assert TOO_DEEP in str(caught.value), caught.value
    assert f"line 1000, column {2 * LIMIT + 1}" in str(caught.value), caught.value


@pytest.mark.parametrize("load", LOADERS)
def test_a_list_past_the_limit_with_a_tag_too_long_is_refused_for_the_tag(
    load: Callable[[str], Any],
) -> None:
    """As before: the tag is checked first, at the same node."""

    tagged = "- " * LIMIT + "!" + "t" * 300 + " []"

    with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
        load(tagged)

    assert "found a tag longer than 256 characters" in str(caught.value), caught.value
    assert f"line 1, column {2 * LIMIT + 1}" in str(caught.value), caught.value


def test_the_count_is_per_document() -> None:
    """``yaml.load_all`` composes several documents with one loader: each starts at the root."""

    at_limit = "- " * (LIMIT - 1) + "[]"
    stream = "\n---\n".join([at_limit] * 3) + "\n---\n" + "- " * LIMIT + "[]"

    loader = yaml.load_all(stream, Loader=safe_yaml.SafeValueLoader)
    assert [next(loader) for _ in range(3)] == [yaml.safe_load(at_limit)] * 3
    with pytest.raises(yaml.YAMLError) as caught:
        next(loader)
    assert caught.value.problem == TOO_DEEP  # type: ignore[attr-defined]
    assert caught.value.problem_mark.line == 6  # type: ignore[attr-defined]


def test_nesting_written_past_what_the_composer_holds_has_a_position() -> None:
    """Thousands of levels used to overflow PyYAML's recursive composer, refused without one."""

    assert problem_mark("- " * 5_000 + "x") == (1, 2 * LIMIT + 1)
    assert problem_mark(block_map(5_000)) == (LIMIT + 1, 2 * LIMIT + 1)


@pytest.mark.parametrize("load", LOADERS)
def test_a_recursion_error_while_composing_is_a_refusal(
    load: Callable[[str], Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both loaders keep their ``RecursionError`` handler: no nesting written in a file reaches it
    now (level 101 is refused first), but a caller with little stack left still can (the last
    test). Raised here without recursing: a real overflow switches off a pure-Python tracer, such
    as coverage's fallback or a debugger, for the rest of the run (delta audit)."""

    def overflow(self: safe_yaml.SafeValueLoader) -> yaml.Node:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(safe_yaml.SafeValueLoader, "get_single_node", overflow)

    with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
        load("[]")

    assert str(caught.value) == TOO_DEEP
    assert isinstance(caught.value.__cause__, RecursionError)


# --- a caller with little stack left, in a subprocess ----------------------------------------

#: Most of the time is starting the interpreter; the timeout keeps a regression from hanging.
TIMEOUT_S = 20

#: Loads a file at the limit with less stack left than its composition needs, in each loader.
_LITTLE_STACK = """
import sys
from ildottore import safe_yaml
from ildottore.registry.schema import safe_load_yaml
at_limit = "- " * 99 + "[]"
frame, depth = sys._getframe(), 0
while frame is not None:
    frame, depth = frame.f_back, depth + 1
default = sys.getrecursionlimit()
for load in (safe_yaml.safe_load, safe_load_yaml):
    sys.setrecursionlimit(depth + 100)
    try:
        load(at_limit)
        outcome = "accepted"
    except Exception as exc:
        outcome = f"{type(exc).__name__}: {exc} ({type(exc.__cause__).__name__})"
    finally:
        sys.setrecursionlimit(default)
    print(outcome)
"""


def test_a_caller_with_little_stack_left_still_gets_a_refusal() -> None:
    """The composer recurses a few frames per level, so a file at the limit needs a few hundred:
    with less stack left, both loaders refuse it as too deep, without a position, instead of
    raising ``RecursionError``. In a subprocess, as a real overflow switches off a pure-Python
    tracer for the rest of the process."""

    done = subprocess.run(  # noqa: S603 - this interpreter
        [sys.executable, "-c", _LITTLE_STACK],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
        check=False,
    )

    assert done.stdout.splitlines() == [
        f"ComposerError: {TOO_DEEP} (RecursionError)",
        f"SafeLoadError: {TOO_DEEP} (RecursionError)",
    ], done.stderr

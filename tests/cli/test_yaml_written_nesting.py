"""A YAML file written deeper than the depth limit is refused where it crosses, as it is composed.

The depth limit (100 levels, ``safe_yaml.MAX_DEPTH``) was measured only once the whole document
was composed (``safe_yaml.check_expanded``). PyYAML's pure-Python scanner keeps one possible simple
key per open flow level and walks them all on every token, so a token costs in proportion to the
levels open around it: a 198 KB list of chains of ``[`` 320 deep was refused ("document is nested
too deeply at line 1, column 101") only after composing all of it, 3 to 7 times what the same
number of flat texts takes (pre-commit audit of the construction-cost fix, 2026-10-07). A list or a
map written at level 101, inside 100 written ones, is now refused before it is composed, with the
same message and, mostly, the same position (clause A-52, u01). The scanner's work is counted in a
subprocess bounded in time, so a regression fails on the count, or on the timeout instead of
hanging the suite.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from ildottore import safe_yaml
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.lint import EXIT_LINT_FAILED
from ildottore.registry.schema import SafeLoadError, safe_load_yaml

#: The limit as the manual and contract u01 state it, pinned here rather than read from the code.
LIMIT = 100
TOO_DEEP = "document is nested too deeply"
LOADERS = [safe_yaml.safe_load, safe_load_yaml]


def chains(depth: int, chars: int) -> str:
    """A flow list of chains of ``[`` ``depth`` deep around one text, about ``chars`` long.

    The audit's shape: every chain opens and closes ``depth`` levels on one line, so the scanner
    walks the keys of all of them on every token. The text of a chain is at level ``depth + 2``.
    """

    chain = "[" * depth + "a" + "]" * depth
    return "[" + ",".join([chain] * (chars // (len(chain) + 1))) + "]\n"


def block_map(levels: int, leaf: str = "v") -> str:
    """Block mappings ``levels`` deep: the mapping at level ``n`` starts on line ``n``."""

    return "".join("  " * i + "k:\n" for i in range(levels)) + "  " * levels + leaf + "\n"


#: Each collection written exactly one level past the limit: the text up to the first entry of the
#: collection at level 101, included, the text after it, and where that collection starts (line,
#: column, from 1). The flow shapes open the root at column 1, so a list at level ``n`` is at column
#: ``n``; a block mapping at level ``n`` starts at its first key, on line ``n``.
CROSSING: dict[str, tuple[str, str, tuple[int, int]]] = {
    "flow sequences": ("[" * (LIMIT + 1) + "a", "]" * (LIMIT + 1), (1, LIMIT + 1)),
    "flow mappings": ("{a: " * (LIMIT + 1) + "b", "}" * (LIMIT + 1), (1, 4 * LIMIT + 1)),
    "block mappings": (block_map(LIMIT + 1), "", (LIMIT + 1, 2 * LIMIT + 1)),
    "block sequences": ("- " * (LIMIT + 1) + "x\n", "", (1, 2 * LIMIT + 1)),
}
#: More entries of that collection, on the lines below its first, the last one starting with a
#: character no token can start: only composing the collection reaches it.
FURTHER = {
    "flow sequences": "".join(f",\nz{i}" for i in range(5)) + ",\n@",
    "flow mappings": "".join(f",\nz{i}: 1" for i in range(5)) + ",\n@: 1",
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

    first = "[" * (LIMIT + 1) + "]" * (LIMIT + 1)
    deeper = "[" * (LIMIT + 50) + "]" * (LIMIT + 50)
    text = f"[\n{first},\n{deeper}\n]\n"

    assert problem_mark(text) == (2, LIMIT)  # line 2 starts at level 2
    assert measured_after_composing(text) == (3, LIMIT)


def test_an_empty_list_past_the_limit_is_named_where_it_starts() -> None:
    """``k: []`` in the map at level 100: ``check_expanded`` names the first node of the deepest
    level, the key ``k`` (an empty list is as deep as a text); the list is what opens level 101."""

    text = block_map(LIMIT - 1, leaf="k: []")

    assert problem_mark(text) == (LIMIT, 2 * (LIMIT - 1) + 4)
    assert measured_after_composing(text) == (LIMIT, 2 * (LIMIT - 1) + 1)


@pytest.mark.parametrize(
    "text",
    [
        "[" * LIMIT + "a" + "]" * LIMIT,  # a text
        "- &a x\n- " + "[" * (LIMIT - 1) + "*a" + "]" * (LIMIT - 1) + "\n",  # an alias
        "{a: " * LIMIT + "b" + "}" * LIMIT,  # the keys of the map at level 100
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
        "[" * LIMIT + "]" * LIMIT,
        "[" * (LIMIT - 1) + "a" + "]" * (LIMIT - 1),
        "{a: " * (LIMIT - 1) + "b" + "}" * (LIMIT - 1),
        block_map(LIMIT - 1),
        "- " * (LIMIT - 1) + "x",
        "[" + ", ".join(["[" * (LIMIT - 2) + "a" + "]" * (LIMIT - 2)] * 50) + "]",
        "k:\n"
        + "".join(f"  s{i}: " + "[" * (LIMIT - 3) + "]" * (LIMIT - 3) + "\n" for i in range(9)),
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
    deep_first = "[" * (LIMIT + 1) + texts + "]" * (LIMIT + 1)
    large_first = "[" + texts + "[" * LIMIT + "]" * LIMIT + "]"

    with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
        load(deep_first)
    assert TOO_DEEP in str(caught.value), caught.value
    assert f"line 1, column {LIMIT + 1}" in str(caught.value), caught.value
    with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
        load(large_first)
    assert "document is too large" in str(caught.value), caught.value


@pytest.mark.parametrize("load", LOADERS)
def test_a_list_past_the_limit_with_a_tag_too_long_is_refused_for_the_tag(
    load: Callable[[str], Any],
) -> None:
    """As before: the tag is checked first, at the same node."""

    tagged = "[" * LIMIT + "!" + "t" * 300 + " []" + "]" * LIMIT

    with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
        load(tagged)

    assert "found a tag longer than 256 characters" in str(caught.value), caught.value
    assert f"line 1, column {LIMIT + 1}" in str(caught.value), caught.value


def test_the_count_is_per_document() -> None:
    """``yaml.load_all`` composes several documents with one loader: each starts at the root."""

    at_limit = "[" * LIMIT + "]" * LIMIT
    stream = "\n---\n".join([at_limit] * 3) + "\n---\n" + "[" * (LIMIT + 1) + "]" * (LIMIT + 1)

    loader = yaml.load_all(stream, Loader=safe_yaml.SafeValueLoader)
    assert [next(loader) for _ in range(3)] == [yaml.safe_load(at_limit)] * 3
    with pytest.raises(yaml.YAMLError) as caught:
        next(loader)
    assert caught.value.problem == TOO_DEEP  # type: ignore[attr-defined]
    assert caught.value.problem_mark.line == 6  # type: ignore[attr-defined]


def test_nesting_written_past_what_the_composer_holds_has_a_position() -> None:
    """Thousands of levels used to overflow PyYAML's recursive composer, refused without one."""

    assert problem_mark("[" * 5_000 + "]" * 5_000) == (1, LIMIT + 1)
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


# --- the CLI, in a subprocess: the scanner's work, bounded in time ----------------------------

#: Runs the CLI with this interpreter and reports its exit code and how many possible simple keys
#: PyYAML's scanner walked (in both methods that walk them), a count the machine's load does not
#: change.
_CHILD = """
import json, sys
from yaml.scanner import Scanner
walked = 0
def counting(walk):
    def counted(self):
        global walked
        walked += len(self.possible_simple_keys)
        return walk(self)
    return counted
Scanner.stale_possible_simple_keys = counting(Scanner.stale_possible_simple_keys)
Scanner.next_possible_simple_key = counting(Scanner.next_possible_simple_key)
from ildottore.cli.main import app
code = None
try:
    app(sys.argv[1:], prog_name="dottore")
except SystemExit as exc:
    code = exc.code
print(json.dumps({"exit": code, "walked": walked}), file=sys.stderr)
"""

#: The audit's file: 198 KB of chains of ``[`` 320 deep, under the size cap, so the base composed it
#: whole and only then refused it, with the same message and position. Its scanner walked about 97
#: million keys (4.5 times the time of a flat list of as many texts). Refused at the 101st
#: character, it walks about 1.1 million: what it reads ahead on the first line.
CHAINS_DEPTH, CHAINS_CHARS = 320, 198_000
MAX_WALKED = 5_000_000
#: Most of the time is importing the CLI. A regression fails on the count, or on the timeout instead
#: of hanging the suite.
TIMEOUT_S = 20


@pytest.mark.parametrize("command", ["lint", "calibrate"])
def test_a_file_nested_past_the_limit_is_refused_before_the_scanner_pays_for_it(
    tmp_path: Path, command: str
) -> None:
    text = chains(CHAINS_DEPTH, CHAINS_CHARS)
    assert 1 + text.count("a") * (CHAINS_DEPTH + 1) < 100_000  # nodes, under the size cap
    if command == "lint":  # the spec loader
        specs = tmp_path / "specs"
        specs.mkdir()
        hostile = specs / "X-DEEP-001.yaml"
        hostile.write_text(text, encoding="utf-8")
        args = ["lint", str(specs)]
    else:  # safe_yaml.safe_load
        report = tmp_path / "report.json"
        report.write_text("[]", encoding="utf-8")
        hostile = tmp_path / "labels.yaml"
        hostile.write_text(text, encoding="utf-8")
        args = ["calibrate", str(report), str(hostile)]

    done = subprocess.run(  # noqa: S603 - this interpreter running this CLI
        [sys.executable, "-c", _CHILD, *args],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
        check=False,
    )

    *messages, measured = done.stderr.splitlines()
    outcome = json.loads(measured)
    if command == "lint":  # a finding on stdout, naming the spec file
        assert outcome["exit"] == EXIT_LINT_FAILED, done.stderr
        messages, named = done.stdout.splitlines(), f"PARSE_ERROR ({hostile.name})"
    else:
        assert outcome["exit"] == ExitCode.ERROR, done.stderr
        named = str(hostile)
    refusal = [m for m in messages if named in m and TOO_DEEP in m]
    assert refusal, (done.stdout, done.stderr)
    assert f"line 1, column {LIMIT + 1}" in refusal[0], refusal[0]
    assert 0 < outcome["walked"] < MAX_WALKED, f"{outcome['walked']:,} keys walked"


#: Loads a file at the limit with less stack left than its composition needs, in each loader.
_LITTLE_STACK = """
import sys
from ildottore import safe_yaml
from ildottore.registry.schema import safe_load_yaml
at_limit = "[" * 100 + "]" * 100
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

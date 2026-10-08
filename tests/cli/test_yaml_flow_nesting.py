"""A YAML file nested more than 20 levels in flow style is refused where it crosses (A-58, OD-30).

PyYAML's pure-Python scanner keeps one possible simple key per open flow level (``[ ]``, ``{ }``)
and walks them all on every token, so each open flow level costs on every token written inside
it. Under the depth limit of 100 (A-52) a 198 KB list of chains of ``[`` 98 deep was accepted
after the scanner walked 29.8 million keys, about 2.3 times the time of a flat list of as many
texts, and the same chains holding 300 texts each walked 52.0 million (audits of #84). The owner
decided OD-30 on 2026-10-08: a limit of its own for flow nesting, 20 levels. Block nesting does not
count (the scanner keeps one key for it), and the YAML files the repository ships nest at most 2
flow levels. The scanner's work is counted in a subprocess bounded in time, so a regression fails
on the count, or on the timeout instead of hanging the suite.
"""

from __future__ import annotations

import io
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

#: The limits as the manual and contract u01 state them, pinned here rather than read from the code.
FLOW, LIMIT = 20, 100
FLOW_TOO_DEEP = "document is nested too deeply in flow style (over 20 levels of brackets or braces)"
TOO_DEEP = "document is nested too deeply"
LOADERS = [safe_yaml.safe_load, safe_load_yaml]


def under_maps(levels: int) -> str:
    """Block mappings ``levels`` deep, up to ``k: `` on line ``levels``: what follows is the value
    of the mapping at level ``levels``, written from column ``2 * levels + 2``."""

    return "".join("  " * i + "k:\n" for i in range(levels - 1)) + "  " * (levels - 1) + "k: "


def chains(depth: int, chars: int, texts: int = 1) -> str:
    """A flow list of chains of ``[`` ``depth`` deep around ``texts`` texts, about ``chars`` long.

    Every chain opens and closes its levels on one line, so the scanner walks the keys of all of
    them on every token; the list itself is one more flow level.
    """

    chain = "[" * depth + ",".join(["a"] * texts) + "]" * depth
    return "[" + ",".join([chain] * (chars // (len(chain) + 1))) + "]\n"


def refusal(load: Callable[[str], Any], text: str) -> str:
    with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
        load(text)
    return str(caught.value)


#: Each shape written one flow level past the limit: the text up to the first entry of the flow
#: collection at flow level 21, the text after it, and where that collection starts (line,
#: column, from 1).
CROSSING: dict[str, tuple[str, str, tuple[int, int]]] = {
    "lists": ("[" * (FLOW + 1) + "a", "]" * (FLOW + 1), (1, FLOW + 1)),
    "maps": ("{a: " * (FLOW + 1) + "b", "}" * (FLOW + 1), (1, 4 * FLOW + 1)),
    "lists and maps": ("[{a: " * 10 + "[a", "]" + "}]" * 10, (1, 5 * 10 + 1)),
    # A tag or an anchor before the bracket: the collection starts at it, the bracket comes later
    # (a check that looked for the bracket at the start would let these through: delta audit).
    "tagged lists": ("[" + "!!seq [" * FLOW + "a", "]" * (FLOW + 1), (1, 2 + 7 * (FLOW - 1))),
    "anchored lists": (
        "[" + "".join(f"&a{i:02d} [" for i in range(FLOW)) + "a",
        "]" * (FLOW + 1),
        (1, 2 + 6 * (FLOW - 1)),
    ),
    "inside block maps": (
        under_maps(10) + "[" * (FLOW + 1) + "a",
        "]" * (FLOW + 1) + "\n",
        (10, 2 * 10 + 2 + FLOW),
    ),
}
#: More entries of that collection, lines below its first, the last starting with a character no
#: token can start: only composing the collection reaches it.
_PAD = " " * 24
FURTHER = {
    "lists": "".join(f",\nz{i}" for i in range(5)) + ",\n@",
    "maps": "".join(f",\nz{i}: 1" for i in range(5)) + ",\n@: 1",
    "lists and maps": "".join(f",\nz{i}" for i in range(5)) + ",\n@",
    "tagged lists": "".join(f",\nz{i}" for i in range(5)) + ",\n@",
    "anchored lists": "".join(f",\nz{i}" for i in range(5)) + ",\n@",
    "inside block maps": "".join(f",\n{_PAD}z{i}" for i in range(5)) + f",\n{_PAD}@",
}


# --- the loaders -----------------------------------------------------------------------------


@pytest.mark.parametrize("shape", list(CROSSING))
@pytest.mark.parametrize("load", LOADERS)
def test_a_flow_collection_past_the_limit_is_refused_where_it_starts(
    load: Callable[[str], Any], shape: str
) -> None:
    """With its own message, at the collection that opens flow level 21, and before anything in it
    is composed: the character no token can start, lines below, is never reached."""

    head, tail, (line, column) = CROSSING[shape]

    refused = refusal(load, head + FURTHER[shape] + tail)

    assert FLOW_TOO_DEEP in refused, refused
    assert f"line {line}, column {column}" in refused, refused


@pytest.mark.parametrize("load", LOADERS)
def test_flow_nesting_at_the_limit_loads_as_before(load: Callable[[str], Any]) -> None:
    """Every shape at exactly 20 flow levels, siblings included (the count goes back down after
    each chain), builds the value plain PyYAML builds, under block nesting up to the depth limit."""

    at_limit = [
        "[" * FLOW + "]" * FLOW,
        "{a: " * FLOW + "b" + "}" * FLOW,
        "[{a: " * 10 + "b" + "}]" * 10,
        "[" + ", ".join(["[" * (FLOW - 1) + "a" + "]" * (FLOW - 1)] * 50) + "]",
        under_maps(LIMIT - FLOW - 1) + "[" * FLOW + "a" + "]" * FLOW + "\n",
        "- " * (LIMIT - 1) + "a",  # block style, any depth up to the limit
    ]

    for text in at_limit:
        assert load(text) == yaml.safe_load(text), text[:40]


@pytest.mark.parametrize("pair", ["k: ", "? k : "])
@pytest.mark.parametrize("load", LOADERS)
def test_a_single_pair_in_a_flow_list_is_no_level_of_its_own(
    load: Callable[[str], Any], pair: str
) -> None:
    """``[k: v]`` holds a map in flow style with no bracket of its own, so the scanner opens no
    level for it: 20 lists that each hold one load, and the 21st list is refused at its ``[``. The
    first version counted the maps too, and refused 11 such lists (pre-commit audit)."""

    at_limit = ("[" + pair) * FLOW + "x" + "]" * FLOW
    assert load(at_limit) == yaml.safe_load(at_limit)

    refused = refusal(load, ("[" + pair) * (FLOW + 1) + "x" + "]" * (FLOW + 1))

    assert FLOW_TOO_DEEP in refused, refused
    assert f"line 1, column {(1 + len(pair)) * FLOW + 1}" in refused, refused


def test_read_from_a_stream_every_flow_collection_counts() -> None:
    """A stream gives no text to look at, so a single pair counts as a level there: lists that each
    hold one alternate with maps from the first list, so the 11th list opens level 21 and is refused
    at its ``[``, as the first version did for every input (the message still says brackets or
    braces). The loaders of this tool read texts; this is ``SafeValueLoader`` with a file object."""

    lists = "[k: " * 11 + "x" + "]" * 11
    with pytest.raises(yaml.YAMLError) as caught:
        yaml.load(io.StringIO(lists), Loader=safe_yaml.SafeValueLoader)  # noqa: S506 - safe loader

    assert caught.value.problem == FLOW_TOO_DEEP  # type: ignore[attr-defined]
    assert caught.value.problem_mark.column == 4 * 10  # type: ignore[attr-defined]
    at_limit = io.StringIO("[" * FLOW + "]" * FLOW)
    assert yaml.load(at_limit, Loader=safe_yaml.SafeValueLoader)  # noqa: S506 - safe loader


@pytest.mark.parametrize("load", LOADERS)
def test_the_depth_limit_is_checked_before_the_flow_limit(load: Callable[[str], Any]) -> None:
    """Block mappings 80 deep, then 21 flow levels: the 21st opens level 101 too, and is refused
    by the depth limit, with its message."""

    refused = refusal(load, under_maps(LIMIT - FLOW) + "[" * (FLOW + 1) + "]" * (FLOW + 1))

    assert TOO_DEEP in refused and "flow style" not in refused, refused
    assert f"line {LIMIT - FLOW}, column {2 * (LIMIT - FLOW) + 2 + FLOW}" in refused, refused


def test_the_flow_count_is_per_document() -> None:
    """``yaml.load_all`` composes several documents with one loader: each starts at zero."""

    at_limit = "[" * FLOW + "]" * FLOW
    past = "[" * (FLOW + 1) + "]" * (FLOW + 1)
    stream = "\n---\n".join([at_limit] * 3) + "\n---\n" + past

    loader = yaml.load_all(stream, Loader=safe_yaml.SafeValueLoader)
    assert [next(loader) for _ in range(3)] == [yaml.safe_load(at_limit)] * 3
    with pytest.raises(yaml.YAMLError) as caught:
        next(loader)
    assert caught.value.problem == FLOW_TOO_DEEP  # type: ignore[attr-defined]
    assert caught.value.problem_mark.line == 6  # type: ignore[attr-defined]
    assert caught.value.problem_mark.column == FLOW  # type: ignore[attr-defined]


def test_the_files_the_repository_ships_nest_at_most_two_flow_levels() -> None:
    """The margin the limit leaves: every YAML file in the repository, fixtures included."""

    root = Path(__file__).resolve().parents[2]
    deepest = 0
    for path in root.rglob("*.y*ml"):
        if {".venv", ".git", "node_modules"} & set(path.parts):
            continue
        open_styles: list[bool] = []
        try:
            for event in yaml.parse(path.read_text(encoding="utf-8")):
                if isinstance(event, (yaml.SequenceStartEvent, yaml.MappingStartEvent)):
                    open_styles.append(bool(event.flow_style))
                    deepest = max(deepest, sum(open_styles))
                elif isinstance(event, (yaml.SequenceEndEvent, yaml.MappingEndEvent)):
                    open_styles.pop()
        except (yaml.YAMLError, UnicodeDecodeError):
            continue  # a fixture that is not YAML on purpose

    assert 0 < deepest <= 2 < FLOW


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

#: Most of the time is importing the CLI. A regression fails on the count, or on the timeout
#: instead of hanging the suite.
TIMEOUT_S = 30
#: About 198 KB, under the size cap: the shape of the audits of #84.
CHARS = 198_000


def _run(tmp_path: Path, command: str, text: str) -> tuple[dict[str, int], list[str], Path]:
    """Run ``lint`` (the spec loader) or ``calibrate`` (``safe_yaml.safe_load``) on ``text``."""

    if command == "lint":
        specs = tmp_path / "specs"
        specs.mkdir()
        hostile = specs / "X-DEEP-001.yaml"
        hostile.write_text(text, encoding="utf-8")
        args = ["lint", str(specs)]
    else:
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
    if command == "lint":  # findings on stdout
        messages = done.stdout.splitlines()
    return json.loads(measured), messages, hostile


@pytest.mark.parametrize("depth", [98, 320])
@pytest.mark.parametrize("command", ["lint", "calibrate"])
def test_a_file_nested_past_the_flow_limit_is_refused_before_the_scanner_pays_for_it(
    tmp_path: Path, command: str, depth: int
) -> None:
    """Chains 98 deep were accepted after 29.8 million keys walked; chains 320 deep, the audit's
    file, refused at level 101 after 1.1 million (A-52). Both are refused at the 21st ``[``, the
    scanner walking under 1 million (0.17 and 0.64 million)."""

    outcome, messages, hostile = _run(tmp_path, command, chains(depth, CHARS))

    expected = EXIT_LINT_FAILED if command == "lint" else ExitCode.ERROR
    assert outcome["exit"] == expected, messages
    named = f"PARSE_ERROR ({hostile.name})" if command == "lint" else str(hostile)
    refused = [m for m in messages if named in m and FLOW_TOO_DEEP in m]
    assert refused, messages
    assert f"line 1, column {FLOW + 1}" in refused[0], refused[0]
    assert 0 < outcome["walked"] < 1_000_000, f"{outcome['walked']:,} keys walked"


def test_chains_at_the_flow_limit_walk_a_fifth_of_what_they_did(tmp_path: Path) -> None:
    """What the limit leaves: chains at the flow limit holding 300 texts each, the costliest shape
    the audits of #84 found, walk 11.4 million keys; at 98 levels, accepted before, the same shape
    walked 52.0 million. The limit bounds what each token walks, about 21 keys a pass, not what a
    file walks: a denser one, whose entries carry an anchor and a tag, walks 21.0 million in 789 KB
    (pre-commit audit). The base accepts this file too, at the same cost: it pins the measure, and
    the tests above pin the limit."""

    outcome, messages, _ = _run(tmp_path, "lint", chains(FLOW - 1, CHARS, texts=300))

    assert not [m for m in messages if TOO_DEEP in m], messages  # parsed: the spec is a list
    assert outcome["exit"] == EXIT_LINT_FAILED, messages
    assert 0 < outcome["walked"] < 12_000_000, f"{outcome['walked']:,} keys walked"

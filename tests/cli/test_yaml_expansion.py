"""A YAML file that expands past what the CLI can hold is refused before anything is built.

Only the spec loader capped a document's size with its aliases expanded (100,000 nodes, audit
SEC-09 of 2026-10-03). The scope, target, fleet and labels files and the policy and signature
packs, read through ``safe_yaml.safe_load``, did not: an 835-byte labels file of 45 anchors, each
a list of two aliases of the one before, made ``dottore calibrate`` run past 25 s at 1.7 GB before
it was killed, because formatting the verdict expands the value (pre-merge audit of #61,
2026-10-07). A ``<<`` that merges the previous map twice doubles the work inside PyYAML itself,
before any caller sees the value: 586 bytes took 2.6 s to load, and each line doubles it. Every
loader now shares the spec loader's measure (clause A-37, u01). The bounded time and memory are
measured in a subprocess, so a regression fails on its timeout instead of hanging the suite.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tracemalloc
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import Result
from typer.testing import CliRunner

from ildottore import safe_yaml
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.lint import EXIT_LINT_FAILED
from ildottore.cli.main import app
from ildottore.fingerprint.signatures import SignaturePackError, load_corpus
from ildottore.fingerprint.signatures import load_pack as load_signature_pack
from ildottore.policy.packs import PolicyPackError
from ildottore.policy.packs import load_pack as load_policy_pack
from ildottore.registry.schema import SafeLoadError, safe_load_yaml

from .conftest import make_spec, write_scope, write_spec_tree, write_target

runner = CliRunner()

TOO_LARGE = "document is too large"

#: Anchors for the in-process cases: past the cap (about 2 ** 19 nodes expanded), yet cheap
#: enough without it (a fraction of a second) that a regression fails on the message.
LEVELS = 18


def doubling_list(levels: int, name: str = "b") -> str:
    """A flow list of ``levels`` anchors, each a list of two aliases of the one before.

    Anchor ``b<i>`` expands to ``2 ** (i + 2) - 1`` nodes; the audit's file had 45 anchors.
    """

    items = [f"&{name}0 [x, x]"] + [
        f"&{name}{i} [*{name}{i - 1}, *{name}{i - 1}]" for i in range(1, levels)
    ]
    return "[" + ", ".join(items) + "]"


def doubling_merge(levels: int) -> str:
    """Mapping lines, each merging the previous map twice: PyYAML doubles the pairs itself."""

    lines = ["m0: &m0 {k: v}"] + [
        f"m{i}: &m{i} {{<<: [*m{i - 1}, *m{i - 1}]}}" for i in range(1, levels)
    ]
    return "\n".join(lines) + "\n"


SHAPES: dict[str, Callable[[int], str]] = {
    "list": lambda levels: f"bomb: {doubling_list(levels)}\n",
    "merge": doubling_merge,
}


def error_line(result: Result, path: Path) -> str:
    """The one ``error:`` line, naming the file and the reason, quoting none of it."""

    lines = result.stderr.splitlines()
    assert len(lines) == 1, (result.exception, result.stderr)
    line = lines[0]
    assert line.startswith("error: ") and str(path) in line and TOO_LARGE in line, line
    assert "*b" not in line and "*m" not in line and "<<" not in line
    return line


# --- the loaders -----------------------------------------------------------------------------


#: The cap as the manual and contract u02 state it, pinned here rather than read from the code.
MAX_NODES, CHARS_PER_NODE = 100_000, 64


@pytest.mark.parametrize("load", [safe_yaml.safe_load, safe_load_yaml])
def test_a_document_is_bounded_at_max_nodes(load: Callable[[str], Any]) -> None:
    """One measure for every loader: a long text counts one node per 64 characters."""

    def refused(items: list[str]) -> bool:
        try:
            load("[" + ", ".join(items) + "]")
        except (yaml.YAMLError, SafeLoadError) as exc:
            assert TOO_LARGE in str(exc), exc
            return True
        return False

    # A list (one node) holding a long text, aliases of it and short texts: exactly the cap.
    weight = 1000  # the text's own node plus one per 64 characters
    copies = (MAX_NODES - 1) // weight
    fillers = ["y"] * (MAX_NODES - 1 - copies * weight)
    text = "x" * CHARS_PER_NODE * (weight - 1)

    assert not refused([f"&s {text}", *["*s"] * (copies - 1), *fillers])
    assert refused([f"&s {text}", *["*s"] * (copies - 1), *fillers, "y"])
    # 63 more characters weigh nothing, 64 one more node in each copy.
    assert not refused([f"&s {text}{'x' * 63}", *["*s"] * (copies - 1), *fillers])
    assert refused([f"&s {text}{'x' * 64}", *["*s"] * (copies - 1), *fillers])
    # Whatever the text's tag: a `!!binary` weighs its characters too.
    binary = f"&s !!binary {'A' * CHARS_PER_NODE * (weight - 1)}"
    assert not refused([binary, *["*s"] * (copies - 1), *fillers])
    assert refused([binary, *["*s"] * (copies - 1), *fillers, "y"])


@pytest.mark.parametrize("load", [safe_yaml.safe_load, safe_load_yaml])
def test_the_refusal_is_where_the_expansion_crosses_the_cap(load: Callable[[str], Any]) -> None:
    """``b14`` expands to 65,535 nodes and ``b15`` to 131,071: the refusal points at ``b15``,
    and at the first of two values whose aliases take it past the cap. (A value whose written
    nodes pass it is refused where they do: ``test_composition_stops_where_the_count_crosses``.)"""

    for text in (
        f"bomb: {doubling_list(45)}\n",
        f"first: {doubling_list(20, 'p')}\nsecond: {doubling_list(20, 'q')}\n",
    ):
        with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
            load(text)

        anchor = text.index("15 [") - 2  # the `&` of `&b15` or `&p15`, on the first line
        assert f"line 1, column {anchor + 1}" in str(caught.value), caught.value


@pytest.mark.parametrize("load", [safe_yaml.safe_load, safe_load_yaml])
def test_a_document_too_deep_and_too_large_is_refused_as_too_deep(
    load: Callable[[str], Any],
) -> None:
    """In both loaders the depth refusal, with its position, comes first: the spec loader used to
    report the size first, and the nesting fix's own cases are deep and large at once. (A document
    whose written nodes pass the cap, an alias counting what it names, is refused as too large
    while it is composed, before its depth or a recursion is checked.)"""

    limit = safe_yaml.MAX_DEPTH
    deep_and_wide = "[" * (limit + 1) + doubling_list(LEVELS) + "]" * (limit + 1)

    with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
        load(deep_and_wide)

    assert "nested too deeply" in str(caught.value), caught.value


#: Each list's items and the index of the one whose count crosses a cap of 1,000.
WRITTEN = {
    "texts": (["x"] * 1_200, 1_000),
    "long texts": (["y" * CHARS_PER_NODE * 9] * 120, 100),  # ten nodes each
    "empty lists": (["[]"] * 1_200, 1_000),
    "aliases": (["&a x", *["*a"] * 1_200], 1_000),  # each alias counts what it names
    "aliases of a long text": (["&a " + "y" * CHARS_PER_NODE * 9, *["*a"] * 200], 100),
}


@pytest.mark.parametrize("load", [safe_yaml.safe_load, safe_load_yaml])
def test_a_recursive_alias_is_refused_where_it_is_anchored(load: Callable[[str], Any]) -> None:
    """The spec loader refused it without a position; both loaders now point at the anchor."""

    with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
        load("a: [x, &r [*r]]\n")

    assert "recursive alias" in str(caught.value), caught.value
    assert "line 1, column 8" in str(caught.value), caught.value


@pytest.mark.parametrize("load", [safe_yaml.safe_load, safe_load_yaml])
@pytest.mark.parametrize("shape", sorted(WRITTEN))
def test_composition_stops_where_the_count_crosses(
    monkeypatch: pytest.MonkeyPatch, load: Callable[[str], Any], shape: str
) -> None:
    """The rest of the document is never composed: a 3 MB list of plain texts was composed whole,
    785 MB, before its measure refused it, and a list of aliases still was after that was fixed
    (pre-commit and delta audits). The measure of the composed document would point at the list,
    at column 1. A cap of 1,000 keeps it cheap; ``calibrate-flat`` below runs the real one."""

    monkeypatch.setattr(safe_yaml, "MAX_NODES", 1_000)
    items, crossing = WRITTEN[shape]

    with pytest.raises((yaml.YAMLError, SafeLoadError), match=TOO_LARGE) as caught:
        load("[" + ", ".join(items) + "]")

    column = 2 + sum(len(item) + 2 for item in items[:crossing])
    assert f"line 1, column {column}" in str(caught.value), caught.value


def test_the_count_is_per_document(monkeypatch: pytest.MonkeyPatch) -> None:
    """``yaml.load_all`` composes several documents with one loader; each has its own cap."""

    monkeypatch.setattr(safe_yaml, "MAX_NODES", 1_000)
    stream = "\n---\n".join("[" + ", ".join(["x"] * 600) + "]" for _ in range(3))

    loaded = list(yaml.load_all(stream, Loader=safe_yaml.SafeValueLoader))

    assert [len(document) for document in loaded] == [600, 600, 600]


@pytest.mark.parametrize("load", [safe_yaml.safe_load, safe_load_yaml])
def test_a_tag_past_256_characters_is_refused_without_quoting_it(
    load: Callable[[str], Any],
) -> None:
    """A ``%TAG`` prefix is copied into the tag of every node that uses its handle: 1,000 nodes of
    a 100,000-character prefix held 187 MB, and PyYAML's refusal quoted the whole tag."""

    def problem(prefix: str, node: str = "x") -> str:
        text = f"%TAG !e! tag:e.com,2000:{prefix}\n--- [!e!x {node}, !e!x {node}]\n"
        with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
            load(text)
        return str(caught.value)

    # `tag:e.com,2000:` is 15 characters and the suffix `x` one more; on a text, a list or a map.
    for node in ("x", "[]", "{}"):
        too_long = problem("a" * 241, node)
        assert "found a tag longer than 256 characters" in too_long, too_long
        assert "line 2, column 6" in too_long, too_long
        assert "aaaa" not in too_long
    # At 256 it is composed, and PyYAML refuses the tag it cannot build, as it always did.
    assert "could not determine a constructor" in problem("a" * 240)


def test_the_measure_stays_linear_on_a_long_chain() -> None:
    """Each size stops counting past the cap. Without that, anchor ``b<i>`` of a long chain held
    an integer of ``i`` bits: memory grew with the square of the chain (7 MB for 20,000 anchors
    against 33 MB, and gigabytes from a few megabytes of text), before the depth was refused."""

    def peak(anchors: int) -> int:
        loader = safe_yaml.SafeValueLoader(doubling_list(anchors))
        node = loader.get_single_node()  # type: ignore[no-untyped-call,unused-ignore]
        tracemalloc.start()
        try:
            with pytest.raises(yaml.YAMLError, match="nested too deeply"):
                safe_yaml.check_expanded(node)
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
            loader.dispose()  # type: ignore[no-untyped-call,unused-ignore]

    # Linear: four times the chain, about four times the memory; the square made it ten.
    assert peak(20_000) < 6 * peak(5_000)


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_the_policy_and_signature_packs_refuse_an_expanded_document(
    tmp_path: Path, shape: str
) -> None:
    path = tmp_path / "pack.yaml"
    path.write_text(SHAPES[shape](LEVELS), encoding="utf-8")

    with pytest.raises(PolicyPackError, match=TOO_LARGE):
        load_policy_pack(path)
    with pytest.raises(SignaturePackError, match=TOO_LARGE):
        load_signature_pack(path)
    with pytest.raises(SignaturePackError, match=TOO_LARGE):
        load_corpus(path)


# --- the CLI, in process -----------------------------------------------------------------------


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_calibrate_refuses_labels_that_expand_too_far(tmp_path: Path, shape: str) -> None:
    report = tmp_path / "report.json"
    report.write_text("[]", encoding="utf-8")
    labels = tmp_path / "labels.yaml"
    labels.write_text(
        f"PI-DIRECT-001: {doubling_list(LEVELS)}\n" if shape == "list" else doubling_merge(LEVELS),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["calibrate", str(report), str(labels)])

    assert result.exit_code == ExitCode.ERROR
    error_line(result, labels)


@pytest.mark.parametrize("shape", sorted(SHAPES))
@pytest.mark.parametrize("which", ["target", "scope"])
def test_run_refuses_a_target_or_scope_that_expands_too_far(
    tmp_path: Path, which: str, shape: str
) -> None:
    target = write_target(tmp_path)
    scope = write_scope(tmp_path)
    hostile = target if which == "target" else scope
    hostile.write_text(
        hostile.read_text(encoding="utf-8") + SHAPES[shape](LEVELS), encoding="utf-8"
    )
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])

    result = runner.invoke(
        app,
        ["run", "-t", str(target), "--scope", str(scope), "--spec-path", str(specs), "--dry-run"],
    )

    assert result.exit_code == ExitCode.ERROR
    error_line(result, hostile)


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_fleet_refuses_a_fleet_file_that_expands_too_far(tmp_path: Path, shape: str) -> None:
    fleet = tmp_path / "fleet.yaml"
    fleet.write_text(SHAPES[shape](LEVELS), encoding="utf-8")

    result = runner.invoke(app, ["fleet", str(fleet), "--out", str(tmp_path / "out")])

    assert result.exit_code == ExitCode.ERROR
    error_line(result, fleet)
    assert not (tmp_path / "out").exists()


# --- the CLI, in a subprocess: bounded time and memory ----------------------------------------

#: Runs the CLI with this interpreter and reports its exit code and peak resident memory.
_CHILD = """
import json, resource, sys
from ildottore.cli.main import app
code = None
try:
    app(sys.argv[1:], prog_name="dottore")
except SystemExit as exc:
    code = exc.code
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps({"exit": code, "peak": peak}), file=sys.stderr)
"""

#: An alias bomb is refused in about half a second, most of it importing the CLI, and the flat
#: list below in about three; without the cap these files ran past 25 s and 1.7 GB, so the
#: timeout fails a regression instead of hanging the suite.
TIMEOUT_S = 20
#: The CLI holds about 80 MB after its imports; without the cap the labels grew 70 MB a second.
MAX_PEAK_BYTES = 256 * 1024 * 1024
#: A flat list of plain texts, no alias in it: the first version of the cap composed it whole
#: (785 MB) before refusing it, and main builds it (762 MB). Composition stops at the 100,000th.
FLAT_ITEMS = 1_000_000


def _hostile_files(tmp_path: Path, command: str) -> tuple[list[str], Path]:
    """The arguments of ``command`` with one full-size hostile file, and that file."""

    if command.startswith("calibrate"):
        report = tmp_path / "report.json"
        report.write_text("[]", encoding="utf-8")
        labels = tmp_path / "labels.yaml"
        if command == "calibrate":
            labels.write_text(f"PI-DIRECT-001: {doubling_list(45)}\n", encoding="utf-8")
            assert labels.stat().st_size == 835  # the audit's file
        else:
            labels.write_text(
                "PI-DIRECT-001: [" + ", ".join(["x"] * FLAT_ITEMS) + "]\n", encoding="utf-8"
            )
        return ["calibrate", str(report), str(labels)], labels
    if command == "lint":  # the spec loader
        specs = tmp_path / "specs"
        specs.mkdir()
        spec = specs / "X-BOMB-001.yaml"
        spec.write_text(doubling_merge(40), encoding="utf-8")
        return ["lint", str(specs)], spec
    if command == "fleet":
        fleet = tmp_path / "fleet.yaml"
        fleet.write_text(doubling_merge(40), encoding="utf-8")
        return ["fleet", str(fleet), "--out", str(tmp_path / "out")], fleet
    target, scope = write_target(tmp_path), write_scope(tmp_path)
    hostile = target if command == "run-target" else scope
    hostile.write_text(hostile.read_text(encoding="utf-8") + doubling_merge(40), encoding="utf-8")
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    args = ["run", "-t", str(target), "--scope", str(scope), "--spec-path", str(specs)]
    return [*args, "--dry-run"], hostile


@pytest.mark.skipif(sys.platform == "win32", reason="ru_maxrss is a Unix measure")
@pytest.mark.parametrize(
    "command", ["calibrate", "calibrate-flat", "run-target", "run-scope", "fleet", "lint"]
)
def test_an_expanding_file_is_refused_in_bounded_time_and_memory(
    tmp_path: Path, command: str
) -> None:
    args, hostile = _hostile_files(tmp_path, command)

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
    refusal = [m for m in messages if named in m and TOO_LARGE in m]
    assert refusal, (done.stdout, done.stderr)
    if command == "calibrate-flat":
        # At the 100,000th text: after `PI-DIRECT-001: [`, 16 characters, and three per text.
        assert refusal[0].endswith(f"at line 1, column {16 + 3 * 99_999 + 1}"), refusal[0]
    peak = outcome["peak"] if sys.platform == "darwin" else outcome["peak"] * 1024
    assert peak < MAX_PEAK_BYTES, f"{peak / 2**20:.0f} MiB"

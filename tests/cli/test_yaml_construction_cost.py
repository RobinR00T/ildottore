"""A YAML value that costs far more to build than it weighs is refused before it is built.

The size cap (A-37) bounds what a document holds, not what PyYAML spends building it, and two shapes
cost far more than they weigh (pre-commit audit of the alias expansion cap, 2026-10-07). YAML 1.1
reads ``1:59:59`` as a base-60 integer, which PyYAML builds with a loop whose time grows with the
square of its length: a spec just under the 1 MiB cap took ``dottore lint`` 55 s. And integer keys
that are multiples of ``sys.hash_info.modulus`` all share one hash, so the mapping holding them is
built in time that grows with the square of their count: 36,320 such keys, a 1 MiB spec, took
``lint`` 24 s. ``dottore run`` then parsed a target file three to five times (four for a mock
target, five for a live one, three under ``--hardened``), so whatever it cost was paid that many
times over. A number is now refused past 1,000 characters, a document past 1,000 keys that are
numbers, and a run reads its target once (clauses A-41, u01, and A-42, u12). The bounded times are
measured in a subprocess, so a regression fails on its timeout instead of hanging the suite.
"""

from __future__ import annotations

import datetime
import shutil
import sqlite3
import subprocess
import sys
from collections import Counter
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from ildottore import safe_yaml
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.lint import EXIT_LINT_FAILED
from ildottore.cli.main import app
from ildottore.registry.schema import MAX_YAML_BYTES, SafeLoadError, safe_load_yaml
from ildottore.shared.config_errors import yaml_problem

from .conftest import make_spec, write_scope, write_spec_tree, write_target

runner = CliRunner()
REPO = Path(__file__).resolve().parents[2]

#: The documented limits, pinned here rather than read from the code they check.
NUMBER_TOO_LONG = "a number written in over 1000 characters"
TOO_MANY_NUMBER_KEYS = "over 1000 keys that are numbers"
#: Two integers share a hash when they differ by a multiple of this (``2 ** 61 - 1`` on 64 bits).
HASH_MODULUS = sys.hash_info.modulus

LOADERS: dict[str, Callable[[str], Any]] = {
    "operator files": safe_yaml.safe_load,
    "spec loader": safe_load_yaml,
}


@pytest.fixture(params=sorted(LOADERS))
def load(request: pytest.FixtureRequest) -> Callable[[str], Any]:
    return LOADERS[request.param]


def refusal(load: Callable[[str], Any], text: str) -> str:
    """The message a loader refuses ``text`` with, as its callers print it; it must refuse it."""

    with pytest.raises((yaml.YAMLError, SafeLoadError)) as caught:
        load(text)
    if isinstance(caught.value, yaml.YAMLError):  # `str()` of it quotes the line
        return yaml_problem(caught.value)
    return str(caught.value)


def sexagesimal(length: int) -> str:
    """A YAML 1.1 base-60 integer written in exactly ``length`` characters (``1:59:59...``)."""

    groups = (length - 1) // 3
    return "1" * (length - 3 * groups) + ":59" * groups


def number_keys(count: int, *, start: int = 1, indent: str = "") -> str:
    """``count`` block mapping lines whose integer keys all share one hash."""

    return "".join(f"{indent}{k * HASH_MODULUS}: 0\n" for k in range(start, start + count))


# --- a number written past the cap -------------------------------------------------------------

LONG_NUMBERS = {
    "base-60 integer": sexagesimal(1001),
    "base-60 float": "1:30." + "5" * 996,
    "decimal": "1" * 1001,
    "hexadecimal": "0x" + "f" * 999,
    "exponent": "1." + "0" * 995 + "e+10",
    "tagged text": '!!int "' + "1" * 1001 + '"',
}


@pytest.mark.parametrize("written", list(LONG_NUMBERS.values()), ids=list(LONG_NUMBERS))
def test_a_number_written_past_the_cap_is_refused_before_it_is_built(
    load: Callable[[str], Any], written: str
) -> None:
    message = refusal(load, f"id: X\nn: {written}\n")

    assert NUMBER_TOO_LONG in message and "cannot build this value" in message, message
    assert "line 2, column 4" in message, message
    assert "1111" not in message and "5959" not in message, "the value is not quoted"


def test_a_number_key_past_the_cap_is_refused(load: Callable[[str], Any]) -> None:
    message = refusal(load, f"id: X\n{sexagesimal(1001)}: x\n")

    assert NUMBER_TOO_LONG in message and "line 2, column 1" in message, message


def test_a_number_at_the_cap_and_a_long_text_still_build() -> None:
    """The cap is on numbers, at 1,000 characters: a text of any length is not a number, and a
    base-60 integer of 1,000 characters is built in microseconds."""

    groups = (1000 - 1) // 3
    expected = sum(59 * 60**i for i in range(groups)) + 1 * 60**groups

    value = safe_yaml.safe_load(
        f"b60: {sexagesimal(1000)}\n"
        f"dec: {'1' * 1000}\n"
        f"hex: 0x{'f' * 998}\n"
        f'quoted: "{sexagesimal(5000)}"\n'
        f"plain: {sexagesimal(5000)}x\n"
    )

    assert value["b60"] == expected
    assert value["dec"] == int("1" * 1000) and value["hex"] == 16**998 - 1
    assert value["quoted"] == sexagesimal(5000) and value["plain"].endswith("59x")


AT_CAP = {
    "base-60 integer": (sexagesimal(1000), int),
    "base-60 float": ("1:30." + "5" * 995, float),
    "decimal": ("1" * 1000, int),
    "hexadecimal": ("0x" + "f" * 998, int),
    "exponent": ("1." + "0" * 994 + "e+10", float),
    "tagged text": ('!!int "' + "1" * 1000 + '"', int),
}


@pytest.mark.parametrize(("written", "kind"), list(AT_CAP.values()), ids=list(AT_CAP))
def test_a_number_at_the_cap_builds_in_every_notation(
    load: Callable[[str], Any], written: str, kind: type
) -> None:
    assert type(load(f"id: X\nn: {written}\n")["n"]) is kind


@pytest.mark.parametrize(
    ("text", "where"),
    [
        (f"- {sexagesimal(1001)}\n", "line 1, column 3"),
        (f"l: [x, {sexagesimal(1001)}]\n", "line 1, column 8"),
        (f"m: {{a: {sexagesimal(1001)}}}\n", "line 1, column 8"),
        (f"{sexagesimal(1001)}\n", "line 1, column 1"),
    ],
    ids=["list item", "flow list", "flow mapping", "root"],
)
def test_a_number_past_the_cap_is_refused_wherever_it_is_written(
    load: Callable[[str], Any], text: str, where: str
) -> None:
    message = refusal(load, text)

    assert NUMBER_TOO_LONG in message and where in message, message


# --- keys that are numbers ---------------------------------------------------------------------


def test_a_document_past_max_number_keys_is_refused(load: Callable[[str], Any]) -> None:
    held = safe_yaml.safe_load(number_keys(1000))

    assert len(held) == 1000 and len({hash(key) for key in held}) == 1, "one shared hash"
    message = refusal(load, number_keys(1001))
    assert TOO_MANY_NUMBER_KEYS in message and "line 1001, column 1" in message, message
    assert str(HASH_MODULUS) not in message, "no key is quoted"


def test_keys_in_a_flow_mapping_count_as_in_a_block(load: Callable[[str], Any]) -> None:
    keys = [f"{k * HASH_MODULUS}: 0" for k in range(1, 1002)]
    text = "{" + ", ".join(keys) + "}\n"

    message = refusal(load, text)
    column = text.index(", " + keys[1000]) + 3
    assert TOO_MANY_NUMBER_KEYS in message and f"line 1, column {column}" in message, message


def test_composition_stops_at_the_key_past_the_limit(load: Callable[[str], Any]) -> None:
    """Refused where the 1,001st key is written: the rest of the file is not composed, so a mapping
    of 30,000 such keys costs what 1,001 do, and a syntax error after them is not reached."""

    message = refusal(load, number_keys(30_000) + "broken: [\n")

    assert TOO_MANY_NUMBER_KEYS in message and "line 1001, column 1" in message, message


def test_composition_stops_at_a_number_past_the_cap(load: Callable[[str], Any]) -> None:
    message = refusal(load, f"n: {sexagesimal(1001)}\nbroken: [\n")

    assert NUMBER_TOO_LONG in message and "line 1, column 4" in message, message


def test_the_keys_of_every_mapping_count_toward_one_document_cap(
    load: Callable[[str], Any],
) -> None:
    """Per mapping, 1,000 such keys would still allow about fifty such mappings under the node
    cap, each built in time that grows with the square of its keys."""

    first = "a:\n" + number_keys(600, indent="  ")
    second = "b:\n" + number_keys(600, start=601, indent="  ")

    assert len(safe_yaml.safe_load(first)["a"]) == 600
    message = refusal(load, first + second)
    assert TOO_MANY_NUMBER_KEYS in message and "line 1003, column 3" in message, message


@pytest.mark.parametrize(
    "merge", ["<<: *a", "<<: [*a]", "<<: [*a, *c]"], ids=["one map", "a list", "two maps"]
)
def test_a_merged_key_counts_in_every_mapping_it_is_merged_into(
    load: Callable[[str], Any], merge: str
) -> None:
    """A ``<<`` folds the merged keys into the mapping that merges them, and its dict hashes them
    again: counted only where they are written, 1,000 keys merged into 49 mappings were built 49
    times over."""

    anchors = "a: &a\n" + number_keys(600, indent="  ") + "c: &c {x: 1}\n"

    assert len(safe_yaml.safe_load(anchors)["a"]) == 600
    message = refusal(load, anchors + f"b:\n  {merge}\n")
    assert TOO_MANY_NUMBER_KEYS in message and "line 604, column 7" in message, message


def test_a_map_merged_in_where_it_is_written_counts_twice(load: Callable[[str], Any]) -> None:
    """Its keys are hashed once as written and again in the mapping that merges them."""

    inline = "{" + ", ".join(f"{k * HASH_MODULUS}: 0" for k in range(1, 601)) + "}"

    assert len(safe_yaml.safe_load(f"m: {inline}\n")["m"]) == 600
    message = refusal(load, f"b:\n  <<: {inline}\n")
    assert TOO_MANY_NUMBER_KEYS in message and "line 2, column 7" in message, message


def test_a_map_that_merges_passes_its_merged_keys_on() -> None:
    """``c`` and ``d`` merge ``b``, which merges ``a``: each holds ``a``'s 300 keys."""

    chain = "a: &a\n" + number_keys(300, indent="  ") + "b: &b\n  <<: *a\nc:\n  <<: *b\n"

    assert len(safe_yaml.safe_load(chain)["c"]) == 300
    with pytest.raises(yaml.YAMLError, match=TOO_MANY_NUMBER_KEYS) as caught:
        safe_yaml.safe_load(chain + "d:\n  <<: *b\n")
    assert "line 307, column 7" in yaml_problem(caught.value)


def test_each_document_of_a_stream_has_its_own_count() -> None:
    document = number_keys(600)

    stream = yaml.load_all(document + "---\n" + document, safe_yaml.SafeValueLoader)
    assert [len(d) for d in stream] == [600, 600]
    with pytest.raises(yaml.YAMLError, match=TOO_MANY_NUMBER_KEYS):
        list(yaml.load_all(document + number_keys(600, start=601), safe_yaml.SafeValueLoader))


def test_only_keys_that_are_numbers_count() -> None:
    """Text and dates hash with a key Python draws at random for each process, so no file can
    choose keys that share one hash: they are bounded by the node cap alone."""

    days = [datetime.date(2026, 1, 1) + datetime.timedelta(days=i) for i in range(1500)]
    text = "".join(f"k{i}: 0\n" for i in range(1500)) + "".join(f"{d}: 0\n" for d in days)

    assert len(safe_yaml.safe_load(text)) == 3000


# --- the CLI, in a subprocess: bounded time ----------------------------------------------------

#: Runs the CLI with this interpreter and prints its exit code last on stderr.
_CHILD = """
import sys
from ildottore.cli.main import app
code = None
try:
    app(sys.argv[1:], prog_name="dottore")
except SystemExit as exc:
    code = exc.code
print(f"exit={code}", file=sys.stderr)
"""

#: Each file is refused in about a second or two, most of it starting the interpreter; without the
#: caps they took 24 s to minutes, so the timeout fails a regression instead of hanging the suite.
TIMEOUT_S = 15
#: The spec loader's byte cap, less room for the line that names the spec.
SPEC_ROOM = MAX_YAML_BYTES - 64


def _costly_files(tmp_path: Path, case: str) -> tuple[list[str], Path, str]:
    """The arguments of the command, the costly file, and the reason it is refused for."""

    if case.startswith("lint"):
        specs = tmp_path / "specs"
        specs.mkdir()
        spec = specs / "X-COST-001.yaml"
        if case == "lint-base-60":
            text = "id: X-COST-001\nnotes: " + sexagesimal(SPEC_ROOM)
            reason = NUMBER_TOO_LONG
        else:  # as many keys as the byte cap holds, about 36,000
            lines = ["id: X-COST-001\nkeys:\n"]
            size = len(lines[0])
            while size + len(line := f"  {len(lines) * HASH_MODULUS}: 0\n") <= SPEC_ROOM:
                lines.append(line)
                size += len(line)
            text, reason = "".join(lines), TOO_MANY_NUMBER_KEYS
        assert len(text) <= MAX_YAML_BYTES
        spec.write_text(text + "\n", encoding="utf-8")
        return ["lint", str(specs)], spec, reason
    target, scope = write_target(tmp_path), write_scope(tmp_path)
    if case == "run-base-60":  # the audit's 450 KB target, accepted after 37 s
        extra, reason = f"notes: {sexagesimal(450_000)}\n", NUMBER_TOO_LONG
    else:  # an operator file has no byte cap: 45,000 keys, under the node cap
        extra, reason = "extra:\n" + number_keys(45_000, indent="  "), TOO_MANY_NUMBER_KEYS
    target.write_text(target.read_text(encoding="utf-8") + extra, encoding="utf-8")
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    args = ["run", "-t", str(target), "--scope", str(scope), "--spec-path", str(specs)]
    return [*args, "--dry-run"], target, reason


@pytest.mark.parametrize("case", ["lint-base-60", "lint-hash-keys", "run-base-60", "run-hash-keys"])
def test_a_costly_file_is_refused_in_bounded_time(tmp_path: Path, case: str) -> None:
    args, costly, reason = _costly_files(tmp_path, case)

    done = subprocess.run(  # noqa: S603 - this interpreter running this CLI
        [sys.executable, "-c", _CHILD, *args],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
        check=False,
    )

    *messages, exit_line = done.stderr.splitlines()
    if case.startswith("lint"):  # a finding on stdout, naming the spec file
        assert exit_line == f"exit={EXIT_LINT_FAILED}", done.stderr
        messages, named = done.stdout.splitlines(), f"PARSE_ERROR ({costly.name})"
    else:
        assert exit_line == f"exit={ExitCode.ERROR}", done.stderr
        named = str(costly)
    assert [m for m in messages if named in m and reason in m], (done.stdout, done.stderr)


# --- a run reads its target once ---------------------------------------------------------------


@pytest.fixture
def parses(monkeypatch: pytest.MonkeyPatch) -> Counter[str]:
    """How many times each marked file is parsed: the first line of each is ``# parsed: <name>``."""

    counts: Counter[str] = Counter()
    real = safe_yaml.safe_load

    def counting(text: str) -> Any:
        first = text.split("\n", 1)[0]
        if first.startswith("# parsed: "):
            counts[first.removeprefix("# parsed: ")] += 1
        return real(text)

    monkeypatch.setattr(safe_yaml, "safe_load", counting)
    return counts


def _marked(path: Path, name: str) -> Path:
    path.write_text(f"# parsed: {name}\n" + path.read_text(encoding="utf-8"), encoding="utf-8")
    return path


def _live_files(tmp_path: Path) -> tuple[Path, Path]:
    """A live target (a real endpoint on loopback, so plain http is allowed) and its scope, marked
    ``target`` and ``scope``."""

    target = tmp_path / "live.yaml"
    target.write_text(
        "id: live\ntype: chatbot\nprovider: openai\nmodel: m\n"
        'endpoint: "http://localhost:9/v1/chat/completions"\n',
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        'version: "1.0"\ntargets:\n  - id: live\n'
        '    base_url: "http://localhost:9/v1/chat/completions"\n'
        '    endpoints:\n      - host: "localhost:9"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n',
        encoding="utf-8",
    )
    return _marked(target, "target"), _marked(scope, "scope")


RUN_FLAGS = {
    "dry-run": ["--dry-run"],
    "estimate": ["--estimate"],
    "sV dry-run": ["-sV", "--dry-run"],
    "sV estimate": ["-sV", "--estimate"],
    "run": [],
    "sV run": ["-sV"],
    "hardened run": ["--hardened"],
}


@pytest.mark.parametrize("flags", list(RUN_FLAGS.values()), ids=list(RUN_FLAGS))
def test_a_mock_run_parses_its_target_and_scope_once(
    tmp_path: Path, parses: Counter[str], flags: list[str]
) -> None:
    """Four parses of a mock target on the base: one to load it, two to route it (is it a mock,
    its scenario) and one for the plan; three under ``--hardened``."""

    target = _marked(write_target(tmp_path, mock_scenario="vulnerable"), "target")
    scope = _marked(write_scope(tmp_path), "scope")
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])

    result = runner.invoke(
        app,
        [
            "run", "-t", str(target), "--scope", str(scope), "--spec-path", str(specs),
            "--evidence-root", str(tmp_path / "evidence"), "--run-db", str(tmp_path / "runs.db"),
            *flags,
        ],
    )  # fmt: skip

    assert result.exit_code != ExitCode.ERROR, result.output
    assert parses == {"target": 1, "scope": 1}


@pytest.mark.parametrize("flags", [["--dry-run"], ["--estimate"]], ids=["dry-run", "estimate"])
def test_a_live_run_parses_its_target_once(
    tmp_path: Path, parses: Counter[str], flags: list[str]
) -> None:
    """Five for a live target in a dry run: its route loaded it again to hand it to the adapter,
    from a read that could differ from the one the scope authorized, and it resolved two plans."""

    target, scope = _live_files(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])

    result = runner.invoke(
        app, ["run", "-t", str(target), "--scope", str(scope), "--spec-path", str(specs), *flags]
    )

    assert result.exit_code == ExitCode.CLEAN, result.output
    assert parses == {"target": 1, "scope": 1}


def test_hardened_on_a_live_target_is_refused_from_one_parse(
    tmp_path: Path, parses: Counter[str]
) -> None:
    target, scope = _live_files(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])

    result = runner.invoke(
        app,
        ["run", "-t", str(target), "--scope", str(scope), "--spec-path", str(specs), "--hardened"],
    )

    assert result.exit_code == ExitCode.ERROR
    assert "'live'" in result.output and "--hardened replays" in result.output, result.output
    assert parses["target"] == 1


def test_each_of_two_targets_is_parsed_once(tmp_path: Path, parses: Counter[str]) -> None:
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    first = _marked(write_target(tmp_path / "one", target_id="one"), "one")
    second = _marked(write_target(tmp_path / "two", target_id="two"), "two")
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        'version: "1.0"\ntargets:\n'
        + "".join(
            f'  - id: {name}\n    base_url: "mock://{name}"\n'
            f'    endpoints:\n      - host: "{name}"\n        path_prefixes: ["/"]\n'
            '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
            for name in ("one", "two")
        ),
        encoding="utf-8",
    )
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])

    result = runner.invoke(
        app,
        ["run", "-t", str(first), "-t", str(second), "--scope", str(scope),
         "--spec-path", str(specs), "--dry-run"],
    )  # fmt: skip

    assert result.exit_code == ExitCode.CLEAN, result.output
    assert parses == {"one": 1, "two": 1}


@pytest.mark.parametrize("offline", [True, False], ids=["offline", "mock target"])
def test_fingerprint_parses_its_target_once(
    tmp_path: Path, parses: Counter[str], offline: bool
) -> None:
    target = _marked(write_target(tmp_path, mock_scenario="vulnerable"), "target")
    scope = write_scope(tmp_path)

    result = runner.invoke(
        app, ["fingerprint", str(target), "--scope", str(scope), *(["--offline"] * offline)]
    )

    assert result.exit_code == ExitCode.CLEAN, result.output
    assert parses == {"target": 1}


def test_a_resumed_run_parses_its_target_once(tmp_path: Path, parses: Counter[str]) -> None:
    """The resume binds the run to the target it loaded, not to a fresh read of the file."""

    target = _marked(write_target(tmp_path, mock_scenario="bare"), "target")
    scope = _marked(write_scope(tmp_path), "scope")
    db = tmp_path / "runs.sqlite"
    common = [
        "run", "-t", str(target), "--scope", str(scope), "--spec-path", str(REPO / "specs"),
        "--quick", "-sV", "--run-db", str(db), "--evidence-root", str(tmp_path / "ev"),
        "--no-color",
    ]  # fmt: skip
    halted = runner.invoke(app, [*common, "--budget-requests", "40"])
    assert halted.exit_code == ExitCode.ERROR and "budget ceiling reached" in halted.output
    with closing(sqlite3.connect(db)) as conn:
        (run_id,) = conn.execute("SELECT run_id FROM runs").fetchone()
    parses.clear()

    resumed = runner.invoke(app, [*common, "--resume", run_id, "--dry-run"])

    assert resumed.exit_code == ExitCode.CLEAN, resumed.output
    assert parses == {"target": 1, "scope": 1}


def test_a_judge_file_is_parsed_once(tmp_path: Path, parses: Counter[str]) -> None:
    files = {}
    for name, example in (
        ("target", "target.local"),
        ("scope", "scope.local"),
        ("judge", "target.judge"),
    ):
        files[name] = _marked(
            Path(shutil.copy(REPO / "examples" / f"{example}.yaml", tmp_path / f"{name}.yaml")),
            name,
        )

    result = runner.invoke(
        app,
        [
            "run", "-t", str(files["target"]), "--scope", str(files["scope"]),
            "--judge", str(files["judge"]), "--spec-path", str(REPO / "specs"), "--quick",
            "--dry-run", "--no-color",
        ],
    )  # fmt: skip

    assert result.exit_code == ExitCode.CLEAN, result.output
    assert parses == {"target": 1, "scope": 1, "judge": 1}


@pytest.mark.skipif(sys.platform == "win32", reason="/dev/stdin is a Unix path")
def test_a_target_piped_in_is_read_once(tmp_path: Path) -> None:
    """A pipe can be read once: the second of four reads found it empty and refused the target."""

    target_text = write_target(tmp_path).read_text(encoding="utf-8")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    args = [
        "run",
        "-t",
        "/dev/stdin",
        "--scope",
        str(scope),
        "--spec-path",
        str(specs),
        "--dry-run",
    ]

    done = subprocess.run(  # noqa: S603 - this interpreter running this CLI
        [sys.executable, "-c", _CHILD, *args],
        input=target_text,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
        check=False,
    )

    assert done.stderr.splitlines()[-1] == f"exit={ExitCode.CLEAN}", done.stderr
    assert "mock-target" in done.stdout

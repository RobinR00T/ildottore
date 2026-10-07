"""A-56: a fleet refuses two ids that are equal under ``casefold()``, on every file system.

``dottore fleet`` writes one ``target-<id>.yaml`` per target. On a case-insensitive file system
(the macOS and Windows default) ``target-Prod.yaml`` and ``target-prod.yaml`` are one file, so
the second entry overwrote the first: the command listed two target files and exited 0, the
file named for ``Prod`` held ``prod``, and the printed ``dottore run`` (and ``fleet --run``)
then refused "two target files declare the id 'prod'", an id the fleet declared once (delta
audit of PR #76). The refusal is the same on a case-sensitive file system, so a fleet file means
the same thing wherever it is expanded (OD-33).
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli import fleet as fleet_mod
from ildottore.cli import wiring
from ildottore.cli.app import app


def _fleet(*ids: str, judge: fleet_mod.FleetJudge | None = None) -> fleet_mod.FleetConfig:
    """A fleet whose targets have these ids, each on an endpoint of its own."""

    return fleet_mod.FleetConfig(
        targets=[
            fleet_mod.FleetTarget(id=target_id, endpoint=f"mock://host-{i}/chat")
            for i, target_id in enumerate(ids)
        ],
        judge=judge,
    )


@pytest.mark.parametrize(
    ("first", "second"),
    [("Prod", "prod"), ("prod", "PROD"), ("api.V1", "API.v1"), ("a-b_C", "A-B_c")],
)
def test_two_target_ids_that_differ_only_by_case_are_refused_before_writing(
    tmp_path: Path, first: str, second: str
) -> None:
    out = tmp_path / "out"
    with pytest.raises(ValueError, match="differ only by case") as caught:
        fleet_mod.materialize_fleet(_fleet("x", first, "other", second), out)
    message = str(caught.value)
    expected = (
        f"the fleet's targets.1.id {first!r} and targets.3.id {second!r} differ only by case, "
        f"so target-{first}.yaml and target-{second}.yaml are one file"
    )
    assert expected in message, message
    assert not out.exists(), "a refused fleet writes nothing, not even the directory"


def test_two_mcp_targets_that_differ_only_by_case_are_refused(tmp_path: Path) -> None:
    config = fleet_mod.FleetConfig(
        targets=[
            fleet_mod.FleetTarget(id="Srv", kind="mcp", endpoint="http://localhost:3000/mcp"),
            fleet_mod.FleetTarget(id="srv", kind="mcp", endpoint="http://localhost:3001/mcp"),
        ]
    )
    with pytest.raises(ValueError, match=re.escape("targets.0.id 'Srv' and targets.1.id 'srv'")):
        fleet_mod.materialize_fleet(config, tmp_path / "out")


def test_an_exact_duplicate_keeps_its_wording_and_gains_the_locations(tmp_path: Path) -> None:
    expected = "duplicate target id 'prod' in fleet (targets.0.id and targets.2.id)"
    with pytest.raises(ValueError, match=re.escape(expected)):
        fleet_mod.materialize_fleet(_fleet("prod", "Prod2", "prod"), tmp_path / "out")


@pytest.mark.parametrize(
    ("endpoint", "api_key_env"),
    [
        ("mock://host-1/chat", None),
        ("mock://judge-host/chat", None),
        ("mock://host-1/chat", "JUDGE_KEY"),
    ],
)
def test_a_judge_whose_id_differs_from_a_target_only_by_case_is_refused(
    tmp_path: Path, endpoint: str, api_key_env: str | None
) -> None:
    """The scope ``fleet`` generates holds the judge beside the targets. A judge spelled as a
    target only up to case used to get an entry of its own, two ids that differ only by case,
    whatever its endpoint or credential. The same spelling shares the target's entry (and is
    refused if the endpoint or the credential differs, A-30)."""

    judge = fleet_mod.FleetJudge(id="Prod", endpoint=endpoint, api_key_env=api_key_env)
    config = _fleet("other", "prod", judge=judge)
    out = tmp_path / "out"
    with pytest.raises(ValueError, match="differ only by case") as caught:
        fleet_mod.materialize_fleet(config, out)
    message = str(caught.value)
    assert "the fleet's judge.id 'Prod' and targets.1.id 'prod' differ" in message, message
    assert not out.exists()


def _judge_beside_a_target(tmp_path: Path, target_id: str, judge_block: str) -> Path:
    fleet_file = tmp_path / "fleet.yaml"
    fleet_file.write_text(
        f'version: "1"\ntargets:\n  - id: {target_id}\n    endpoint: mock://host-0/chat\n'
        f"judge:\n{judge_block}",
        encoding="utf-8",
    )
    return fleet_file


_DEFAULT = "(the default of a judge: block that names no id)"


@pytest.mark.parametrize(
    ("target_id", "judge_block", "expected"),
    [
        (
            "Judge",
            "  endpoint: mock://judge-host/chat\n",
            f"the fleet's judge.id 'judge' {_DEFAULT} and targets.0.id 'Judge' differ only by case",
        ),
        (
            "judge",
            "  endpoint: mock://judge-host/chat\n",
            f"the fleet's judge.id 'judge' {_DEFAULT} is targets.0.id, a target with a different "
            "endpoint or credential; give the judge its own id",
        ),
        (
            "Judge",
            "  id: judge\n  endpoint: mock://judge-host/chat\n",
            "the fleet's judge.id 'judge' and targets.0.id 'Judge' differ only by case",
        ),
    ],
)
def test_a_judge_refusal_says_when_its_id_is_the_default(
    tmp_path: Path, target_id: str, judge_block: str, expected: str
) -> None:
    """A ``judge:`` block with no ``id:`` is ``judge``. A refusal naming that id says where it
    comes from, since the fleet file never writes it, and only then: an ``id: judge`` the
    operator wrote is named as written."""

    fleet_file = _judge_beside_a_target(tmp_path, target_id, judge_block)
    with pytest.raises(ValueError) as caught:
        fleet_mod.materialize_fleet(fleet_mod.load_fleet(fleet_file), tmp_path / "out")
    assert expected in str(caught.value), str(caught.value)


def test_a_judge_spelled_exactly_as_a_target_still_shares_its_entry(tmp_path: Path) -> None:
    config = _fleet("prod", judge=fleet_mod.FleetJudge(id="prod", endpoint="mock://host-0/chat"))
    out = fleet_mod.materialize_fleet(config, tmp_path / "out")
    assert [t.id for t in wiring.build_scope(out.scope_path).targets] == ["prod"]


# --- the CLI: `dottore fleet` and `dottore fleet --run` -------------------------------------

_CASE_FLEET = """\
version: "1"
targets:
  - id: Prod
    endpoint: mock://prod-upper/chat
  - id: prod
    endpoint: mock://prod-lower/chat
"""


@pytest.mark.parametrize("extra", [[], ["--run"]])
def test_the_cli_refuses_case_twins_with_exit_3_and_writes_nothing(
    tmp_path: Path, extra: list[str]
) -> None:
    fleet_file = tmp_path / "fleet.yaml"
    fleet_file.write_text(_CASE_FLEET, encoding="utf-8")
    out = tmp_path / "out"
    result = CliRunner().invoke(app, ["fleet", str(fleet_file), "--out", str(out), *extra])
    assert result.exit_code == 3, result.output
    lines = [line for line in result.output.splitlines() if "differ only by case" in line]
    assert len(lines) == 1, result.output
    assert "targets.0.id 'Prod' and targets.1.id 'prod'" in lines[0], lines[0]
    assert "REDACTED" not in result.output, "the ids are named, not masked"
    assert "target:" not in result.output and "Run it" not in result.output
    assert not out.exists()


def test_the_cli_locates_the_entries_an_id_mask_would_hide(tmp_path: Path) -> None:
    """The CLI masks what its redactor reads as high entropy, and a model name can be read so,
    file names included: the locations still say which two entries to change, counted from 0
    as the validation errors of the same command count them. Whether the ids themselves come
    out is the redactor's call."""

    fleet_file = tmp_path / "fleet.yaml"
    fleet_file.write_text(
        _CASE_FLEET.replace("id: Prod", "id: Meta-Llama-3-70B-Instruct").replace(
            "id: prod", "id: META-LLAMA-3-70B-INSTRUCT"
        ),
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["fleet", str(fleet_file), "--out", str(tmp_path / "o")])
    assert result.exit_code == 3, result.output
    assert "error: the fleet's targets.0.id " in result.output, result.output
    assert " and targets.1.id " in result.output, result.output


# --- every small fleet, against an oracle written apart from the code -------------------------

_IDS = ("a", "A", "b", "c")


def _expected_refusal(ids: tuple[str, ...], judge: tuple[str, int] | None) -> str | None:
    """How the refusal the rules require starts (A-56 and A-30), or None if they accept.

    Targets first, in order: the first entry whose id equals an earlier one under casefold is
    an exact duplicate or a case twin of it. Then the judge ``(id, i)``, on target ``i``'s
    endpoint (``i == -1``: an endpoint of its own): refused when its id equals a target's only
    by case, or exactly but on another endpoint.
    """

    first: dict[str, int] = {}
    for j, target_id in enumerate(ids):
        i = first.setdefault(target_id.casefold(), j)
        if i == j:
            continue
        if ids[i] == target_id:
            return f"duplicate target id {target_id!r} in fleet (targets.{i}.id and targets.{j}.id)"
        return f"the fleet's targets.{i}.id {ids[i]!r} and targets.{j}.id {target_id!r} differ"
    if judge is None:
        return None
    judge_id, on = judge
    for i, target_id in enumerate(ids):
        if target_id.casefold() != judge_id.casefold():
            continue
        if target_id != judge_id:
            return f"the fleet's judge.id {judge_id!r} and targets.{i}.id {target_id!r} differ"
        if on != i:
            return f"the fleet's judge.id {judge_id!r} is targets.{i}.id, a target with"
        return None
    return None


def _kind(expected: str | None) -> str | None:
    """Which refusal an expected start is: None, an exact duplicate, a case twin, or a judge."""

    if expected is None:
        return None
    if expected.startswith("duplicate target id"):
        return "duplicate"
    if expected.startswith("the fleet's targets."):
        return "case twin"
    return "judge case twin" if expected.endswith(" differ") else "judge clash"


_JUDGES: list[tuple[str, int] | None] = [None] + [
    (judge_id, on) for judge_id in ("a", "A", "c", "d") for on in (-1, 0, 1, 2)
]
_CASES = [
    (ids, judge)
    for size in (1, 2, 3)
    for ids in itertools.product(_IDS, repeat=size)
    for judge in _JUDGES
    if judge is None or judge[1] < size
]


def test_every_small_fleet_is_refused_or_written_one_file_per_target(tmp_path: Path) -> None:
    """Exhaustive over 1 to 3 targets named from ``a``, ``A``, ``b``, ``c``, with no judge or a
    judge ``a``, ``A``, ``c`` or ``d`` on its own endpoint or any target's. A fleet the rules
    accept writes one file per target, each holding the target it is named for, and a scope
    with no two ids equal under casefold; a fleet they refuse writes nothing, with the refusal
    the rules require, its locations included."""

    mismatches: list[str] = []
    for n, (ids, judge) in enumerate(_CASES):
        judge_decl = None
        if judge is not None:
            endpoint = f"mock://host-{judge[1]}/chat" if judge[1] >= 0 else "mock://judge/chat"
            judge_decl = fleet_mod.FleetJudge(id=judge[0], endpoint=endpoint)
        config = _fleet(*ids, judge=judge_decl)
        out = tmp_path / f"case-{n}"
        expected = _expected_refusal(ids, judge)
        try:
            written = fleet_mod.materialize_fleet(config, out)
        except ValueError as exc:
            if expected is None:
                mismatches.append(f"{ids} judge={judge}: refused, the rules accept it")
            elif not str(exc).startswith(expected):
                mismatches.append(f"{ids} judge={judge}: {exc} (expected {expected})")
            elif out.exists():
                mismatches.append(f"{ids} judge={judge}: refused after writing")
            continue
        if expected is not None:
            mismatches.append(f"{ids} judge={judge}: written, the rules refuse it")
            continue
        scope_ids = [t.id.casefold() for t in wiring.build_scope(written.scope_path).targets]
        if len(set(scope_ids)) != len(scope_ids):
            mismatches.append(f"{ids} judge={judge}: scope ids {scope_ids}")
        for entry, path in zip(config.targets, written.target_paths, strict=True):
            loaded = wiring.load_target(path)
            if (loaded.id, loaded.endpoint) != (entry.id, entry.endpoint):
                mismatches.append(f"{ids} judge={judge}: {path.name} holds {loaded.id!r}")
        files = len(ids) + 1 + (judge is not None)
        if len(list(out.iterdir())) != files:
            mismatches.append(f"{ids} judge={judge}: {sorted(p.name for p in out.iterdir())}")
    assert not mismatches, "\n".join(mismatches)


def test_the_small_fleets_reach_every_rule_at_every_size() -> None:
    """A guard on the enumeration above, not on the code: shrinking the ids or the judges must
    not leave a rule decided by no case. Each (size, refusal) a fleet of that size can meet is
    met at least 3 times: the smallest class when this was written, a one-target fleet whose
    judge has the target's id on another endpoint."""

    counts: dict[tuple[int, str | None], int] = {}
    for ids, judge in _CASES:
        key = (len(ids), _kind(_expected_refusal(ids, judge)))
        counts[key] = counts.get(key, 0) + 1
    judge_kinds = (None, "judge case twin", "judge clash")
    reachable = {(1, kind) for kind in judge_kinds} | {
        (size, kind) for size in (2, 3) for kind in (*judge_kinds, "duplicate", "case twin")
    }
    assert len(_CASES) == 1332, len(_CASES)
    assert set(counts) == reachable, sorted(counts, key=str)
    assert min(counts.values()) >= 3, counts

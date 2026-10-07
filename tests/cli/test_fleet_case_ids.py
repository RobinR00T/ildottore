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
        fleet_mod.materialize_fleet(_fleet(first, "other", second), out)
    message = str(caught.value)
    assert "targets 1 and 3" in message, message
    assert repr(first) in message and repr(second) in message, message
    assert f"target-{first}.yaml" in message and f"target-{second}.yaml" in message, message
    assert not out.exists(), "a refused fleet writes nothing, not even the directory"


def test_two_mcp_targets_that_differ_only_by_case_are_refused(tmp_path: Path) -> None:
    config = fleet_mod.FleetConfig(
        targets=[
            fleet_mod.FleetTarget(id="Srv", kind="mcp", endpoint="http://localhost:3000/mcp"),
            fleet_mod.FleetTarget(id="srv", kind="mcp", endpoint="http://localhost:3001/mcp"),
        ]
    )
    with pytest.raises(ValueError, match="targets 1 and 2"):
        fleet_mod.materialize_fleet(config, tmp_path / "out")


def test_an_exact_duplicate_keeps_its_own_message(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="duplicate target id 'prod' in fleet"):
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
    target only up to case used to get an entry of its own, two ids a reader cannot tell apart,
    whatever its endpoint or credential. The same spelling shares the target's entry (and is
    refused if the endpoint or the credential differs, A-30)."""

    judge = fleet_mod.FleetJudge(id="Prod", endpoint=endpoint, api_key_env=api_key_env)
    config = _fleet("other", "prod", judge=judge)
    out = tmp_path / "out"
    with pytest.raises(ValueError, match="differ only by case") as caught:
        fleet_mod.materialize_fleet(config, out)
    message = str(caught.value)
    assert "judge 'Prod' and its target 2 ('prod')" in message, message
    assert not out.exists()


def test_a_judge_with_no_id_says_its_id_is_the_default(tmp_path: Path) -> None:
    """A ``judge:`` block without ``id:`` is ``judge``, a case twin of a target ``Judge``: the
    refusal says where the id it names comes from, since the fleet file never writes it."""

    fleet_file = tmp_path / "fleet.yaml"
    fleet_file.write_text(
        'version: "1"\ntargets:\n  - id: Judge\n    endpoint: mock://host-0/chat\n'
        "judge:\n  endpoint: mock://judge-host/chat\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="block that names none") as caught:
        fleet_mod.materialize_fleet(fleet_mod.load_fleet(fleet_file), tmp_path / "out")
    assert "judge 'judge' (the id of a judge: block that names none)" in str(caught.value)


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
    assert "targets 1 and 2" in lines[0], lines[0]
    assert "'Prod'" in lines[0] and "'prod'" in lines[0], lines[0]
    assert "REDACTED" not in result.output, "the ids are named, not masked"
    assert "target:" not in result.output and "Run it" not in result.output
    assert not out.exists()


def test_the_cli_numbers_the_entries_an_id_mask_would_hide(tmp_path: Path) -> None:
    """The CLI masks what its redactor reads as high entropy, and a model name can be read so,
    file names included (as in the exact-duplicate message): the entry numbers still say which
    two entries to change. Whether the ids themselves come out is the redactor's call."""

    fleet_file = tmp_path / "fleet.yaml"
    fleet_file.write_text(
        _CASE_FLEET.replace("id: Prod", "id: Meta-Llama-3-70B-Instruct").replace(
            "id: prod", "id: META-LLAMA-3-70B-INSTRUCT"
        ),
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["fleet", str(fleet_file), "--out", str(tmp_path / "o")])
    assert result.exit_code == 3, result.output
    assert "error: the fleet's targets 1 and 2 (ids " in result.output, result.output


# --- every small fleet, against an oracle written apart from the code -------------------------

_IDS = ("a", "A", "b", "c")


def _expected_refusal(ids: tuple[str, ...], judge: tuple[str, int] | None) -> str | None:
    """Which rule must refuse a fleet, from the rules alone (A-56 and A-30), or None.

    ``"targets"``: two target ids equal under casefold (checked first). ``"judge"``: a judge
    ``(id, i)``, on target ``i``'s endpoint (``i == -1``: an endpoint of its own), whose id
    equals a target's only by case, or exactly but on another endpoint.
    """

    folded = [target_id.casefold() for target_id in ids]
    if len(set(folded)) != len(folded):
        return "targets"
    if judge is None:
        return None
    judge_id, on = judge
    for i, target_id in enumerate(ids):
        if target_id.casefold() != judge_id.casefold():
            continue
        return "judge" if target_id != judge_id or on != i else None
    return None


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
_MESSAGES = {
    "targets": ("the fleet's targets ", "duplicate target id "),
    "judge": ("the fleet's judge ",),
}


def test_every_small_fleet_is_refused_or_written_one_file_per_target(tmp_path: Path) -> None:
    """Exhaustive over 1 to 3 targets named from ``a``, ``A``, ``b``, ``c``, with no judge or a
    judge ``a``, ``A``, ``c`` or ``d`` on its own endpoint or any target's. A fleet the rules
    accept writes one file per target, each holding the target it is named for, and a scope
    with no two ids equal under casefold; a fleet they refuse writes nothing, and the refusal
    is the rule's own (a target pair is reported before the judge)."""

    mismatches: list[str] = []
    outcomes: set[tuple[int, str | None]] = set()
    for n, (ids, judge) in enumerate(_CASES):
        judge_decl = None
        if judge is not None:
            endpoint = f"mock://host-{judge[1]}/chat" if judge[1] >= 0 else "mock://judge/chat"
            judge_decl = fleet_mod.FleetJudge(id=judge[0], endpoint=endpoint)
        config = _fleet(*ids, judge=judge_decl)
        out = tmp_path / f"case-{n}"
        expected = _expected_refusal(ids, judge)
        outcomes.add((len(ids), expected))
        try:
            written = fleet_mod.materialize_fleet(config, out)
        except ValueError as exc:
            if expected is None:
                mismatches.append(f"{ids} judge={judge}: refused, the rule accepts it")
            elif not str(exc).startswith(_MESSAGES[expected]):
                mismatches.append(f"{ids} judge={judge}: not the {expected} rule: {exc}")
            elif out.exists():
                mismatches.append(f"{ids} judge={judge}: refused after writing")
            continue
        if expected is not None:
            mismatches.append(f"{ids} judge={judge}: written, the rule refuses it")
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
    assert len(_CASES) == 1332, len(_CASES)
    # Every rule decides at every size it can: none of them is reached only by a few cases.
    reachable = {(1, None), (1, "judge")} | {
        (size, kind) for size in (2, 3) for kind in (None, "targets", "judge")
    }
    assert outcomes == reachable, sorted(outcomes, key=str)
    assert not mismatches, "\n".join(mismatches)

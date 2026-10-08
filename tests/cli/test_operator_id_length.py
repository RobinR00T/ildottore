"""A target or scope id, or an identity name, is at most 128 characters (OD-27, clause A-57).

Clause A-51 cut such an id in most refusals that quoted it, but a run that started wrote it whole:
an id of a million characters made the `--dry-run` plan, the `-sV` lines, each report and the run
store a megabyte or more. OD-27 (decided 2026-10-07, the owner having left the choice to the
implementer) bounds it when the file is loaded: 128 characters, twice the 64 a fleet's ids are
held to because they name files. The longest id in this repository's examples is 21 characters.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.cli.wiring import load_target
from ildottore.policy.errors import ScopeError
from ildottore.policy.scope import MAX_ID_CHARS, load_scope

from .conftest import make_spec, write_spec_tree

runner = CliRunner()

#: The figure, pinned here rather than read back from the code.
LIMIT = 128
AT = "a" * LIMIT
OVER = "a" * (LIMIT + 1)
#: A million characters: the A-51 cases, refused now when the file is loaded.
BIG = "b" * 1_000_000
HALF = "c" * 400_000
SCOPE_HEAD = 'version: "1.0"\ntargets:\n'
FLEET = (
    'version: "1"\n'
    "targets:\n"
    "  - id: local-llama\n"
    "    endpoint: http://localhost:11434/v1/chat/completions\n"
    "    model: llama3.2:1b\n"
)


def scope_entry(target_id: str = "mock-target", names: tuple[str, ...] = ("default",)) -> str:
    text = (
        f'  - id: "{target_id}"\n'
        '    base_url: "mock://mock-target"\n'
        "    endpoints:\n"
        '      - host: "mock-target"\n'
        '        path_prefixes: ["/"]\n'
        "    identities:\n"
    )
    for index, name in enumerate(names):
        text += f'      - name: "{name}"\n        auth_ref: "env://K{index}"\n'
    return text


def target(target_id: str = "mock-target") -> str:
    return f'id: "{target_id}"\ntype: chatbot\n'


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_the_limit_is_128() -> None:
    assert MAX_ID_CHARS == LIMIT


# --- the loaders ---------------------------------------------------------------------------


def test_a_scope_takes_an_id_and_a_name_of_128_characters_and_refuses_129(
    tmp_path: Path,
) -> None:
    assert load_scope(_write(tmp_path, "at.yaml", SCOPE_HEAD + scope_entry(AT, (AT,))))

    for entry, field in ((scope_entry(OVER), "targets.0.id"), (scope_entry(names=(OVER,)), "")):
        path = _write(tmp_path, "over.yaml", SCOPE_HEAD + entry)
        with pytest.raises(ScopeError) as caught:
            load_scope(path)
        where = field or "targets.0.identities.0.name"
        assert f"{where}: String should have at most {LIMIT} characters" in str(caught.value)


def test_a_target_file_takes_an_id_of_128_characters_and_refuses_129(tmp_path: Path) -> None:
    assert load_target(_write(tmp_path, "at.yaml", target(AT))).id == AT

    path = _write(tmp_path, "over.yaml", target(OVER))
    with pytest.raises(ValueError) as caught:
        load_target(path)
    assert str(caught.value) == (
        f"target file {path} 'id' is {LIMIT + 1} characters, over the {LIMIT}-character limit"
    )


# --- the CLI: the ids A-51 cut, refused when their file is loaded ---------------------------


def _run(tmp_path: Path, targets: list[str], scope: str) -> tuple[list[str], list[Path]]:
    paths = [_write(tmp_path, f"target-{i}.yaml", text) for i, text in enumerate(targets)]
    scope_path = _write(tmp_path, "scope.yaml", scope)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    args = ["run", *(a for p in paths for a in ("-t", str(p))), "--scope", str(scope_path)]
    return [*args, "--spec-path", str(specs), "--dry-run"], [*paths, scope_path]


def _case(tmp_path: Path, name: str) -> tuple[list[str], Path, str]:
    """The arguments, the file the refusal must name, and what it must say."""

    scope = SCOPE_HEAD + scope_entry()
    over = "String should have at most 128 characters"
    if name == "scope-duplicate-target-id":
        args, files = _run(tmp_path, [target()], SCOPE_HEAD + scope_entry(HALF) * 2)
        return args, files[-1], f"targets.0.id: {over}"
    if name == "scope-duplicate-identity":
        args, files = _run(tmp_path, [target()], SCOPE_HEAD + scope_entry(names=(HALF, HALF)))
        return args, files[-1], f"targets.0.identities.0.name: {over}"
    if name == "run-two-targets-one-id":
        args, files = _run(tmp_path, [target(HALF), target(HALF)], scope)
        return args, files[0], f"'id' is {len(HALF):,} characters"
    if name == "run-target-not-in-scope":
        args, files = _run(tmp_path, [target(BIG)], scope)
        return args, files[0], f"'id' is {len(BIG):,} characters"
    if name == "run-judge":
        args, files = _run(tmp_path, [target()], scope)
        judge = _write(tmp_path, "judge.yaml", f'id: "{BIG}"\ntype: model\n')
        return [*args, "--judge", str(judge)], judge, f"'id' is {len(BIG):,} characters"
    if name == "fingerprint":
        path = _write(tmp_path, "target.yaml", target(BIG))
        args = ["fingerprint", str(path), "--scope", str(_write(tmp_path, "scope.yaml", scope))]
        return args, path, f"'id' is {len(BIG):,} characters"
    assert name == "fleet-judge"
    fleet = _write(tmp_path, "fleet.yaml", FLEET)
    judge = _write(tmp_path, "judge.yaml", f'id: "{BIG}"\ntype: model\n')
    args = ["fleet", str(fleet), "--out", str(tmp_path / "out"), "--judge", str(judge)]
    return args, judge, f"'id' is {len(BIG):,} characters"


@pytest.mark.parametrize(
    "name",
    [
        "scope-duplicate-target-id",
        "scope-duplicate-identity",
        "run-two-targets-one-id",
        "run-target-not-in-scope",
        "run-judge",
        "fingerprint",
        "fleet-judge",
    ],
)
def test_a_long_id_is_refused_when_its_file_is_loaded(tmp_path: Path, name: str) -> None:
    args, path, said = _case(tmp_path, name)

    result = runner.invoke(app, args)

    assert result.exit_code == ExitCode.ERROR, (result.exception, result.output[:2000])
    [line] = result.stderr.splitlines()
    assert len(line) < 2_500, len(line)
    assert str(path) in line and said in line, line
    assert "REDACTED" not in line and "b" * 50 not in line and "c" * 50 not in line, line


def test_an_id_of_128_characters_runs_and_the_plan_names_it(tmp_path: Path) -> None:
    args, _ = _run(tmp_path, [target(AT)], SCOPE_HEAD + scope_entry(AT))

    result = runner.invoke(app, args)

    assert result.exit_code == ExitCode.CLEAN, result.output[:2000]
    assert f"target:  {AT} (chatbot)" in result.stdout, result.stdout[:2000]

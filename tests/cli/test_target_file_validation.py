"""A target file's bad value is refused on one line that names the file, never the value.

``load_target`` handed a target file's ``capabilities`` and ``sampling_defaults`` maps to
pydantic without catching its ``ValidationError``. Because that error is a ``ValueError``, the
CLI caught it and printed pydantic's own text: four lines (``error: 1 validation error for
Capabilities``, the field, ``input_value='maybe-later'`` and a docs URL) that quoted the
operator's value and did not say which file it was (found 2026-10-07 on ``fix/huge-int-repr``).
The scope and fleet loaders already wrapped it as ``scope file <path> failed validation: <field>:
<reason>`` (``fleet file ...`` likewise) through ``shared/config_errors.validation_problems``.
Clause A-45 (u12).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from ildottore.cli.app import _masked
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.cli.wiring import load_target

from .conftest import write_scope

runner = CliRunner()

REPO = Path(__file__).resolve().parents[2]
SPEC = REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml"

#: Shaped like a key pasted in the wrong place: pydantic quoted it in full when it was short
#: and kept its start and its tail when it truncated it in the middle.
PASTED = "797c48a81f494d0f3e8d13bd49459b6f" * 2

#: (YAML block, the value written in it, the field path and reason the error must give). Each
#: value is one the CLI's redactor leaves readable, so its absence from the output is the
#: loader's doing (a first `987654321` was masked as a phone number and proved nothing).
BAD_BLOCKS = {
    "capability not a boolean": (
        "capabilities:\n  tools: {value}\n  rag: false\n",
        "maybe-later",
        "'capabilities' failed validation: tools: Input should be a valid boolean",
    ),
    "pasted key as a capability": (
        "capabilities:\n  tools: false\n  rag: {value}\n",
        PASTED,
        "'capabilities' failed validation: rag: Input should be a valid boolean",
    ),
    "temperature not a number": (
        "sampling_defaults:\n  temperature: {value}\n",
        "warm",
        "'sampling_defaults' failed validation: temperature: Input should be a valid number",
    ),
    "max_tokens past the cap": (
        "sampling_defaults:\n  max_tokens: {value}\n",
        "250000",
        "'sampling_defaults' failed validation: max_tokens: Input should be less than or equal",
    ),
    "unknown sampling key": (
        "sampling_defaults:\n  temprature: {value}\n",
        "0.25",
        "'sampling_defaults' failed validation: temprature: Extra inputs are not permitted",
    ),
}


def write_bad_target(tmp_path: Path, block: str, value: str, *, target_id: str) -> Path:
    path = tmp_path / f"{target_id}.yaml"
    path.write_text(
        f"id: {target_id}\ntype: chatbot\nmock_scenario: hardened\n" + block.format(value=value),
        encoding="utf-8",
    )
    return path


def write_good_target(tmp_path: Path, *, target_id: str) -> Path:
    path = tmp_path / f"{target_id}.yaml"
    path.write_text(
        f"id: {target_id}\ntype: chatbot\nmock_scenario: hardened\n"
        "capabilities:\n  tools: false\n  rag: false\n",
        encoding="utf-8",
    )
    return path


def dry_run(target: Path, scope: Path, *extra: str) -> Result:
    """``dottore run --dry-run`` of the one spec ``SPEC`` against ``target``."""

    args = ["-t", str(target), *extra, "--scope", str(scope), "--spec-path", str(SPEC)]
    return runner.invoke(app, ["run", *args, "--dry-run"])


def pieces(value: str) -> list[str]:
    """Every 8-character run of ``value`` (the whole of a shorter one).

    pydantic printed 24 characters of a long value's start and 23 of its tail; a check on one
    fixed window let a shorter or shifted piece through (delta audit).
    """

    return [value[start : start + 8] for start in range(max(1, len(value) - 7))]


def refusal(result: Result, path: Path, value: str) -> str:
    """The run's one ``error:`` line, which names ``path`` and quotes no piece of ``value``, nor
    a mask the redactor put in its place."""

    assert result.exit_code == ExitCode.ERROR, (result.exception, result.output)
    lines = result.stderr.splitlines()
    assert len(lines) == 1, result.stderr
    line = lines[0]
    assert line.startswith(f"error: target file {path} "), line
    for leaked in ("input_value", "input_type", "errors.pydantic.dev", "validation error for"):
        assert leaked not in result.output
    for piece in pieces(value):
        assert piece not in result.output, piece
    # The redactor's phone rule reads a number next to the cap in the reason (`200000 250000`)
    # as one, so a value printed there would be masked, not missing (pre-merge audit).
    assert "REDACTED" not in result.output
    return line


@pytest.mark.parametrize("case", sorted(BAD_BLOCKS))
def test_run_refuses_a_bad_target_value_naming_the_file(tmp_path: Path, case: str) -> None:
    block, value, where = BAD_BLOCKS[case]
    target = write_bad_target(tmp_path, block, value, target_id="mock-target")
    scope = write_scope(tmp_path)

    result = dry_run(target, scope)

    assert where in refusal(result, target, value)


@pytest.mark.parametrize("case", sorted(BAD_BLOCKS))
def test_a_bad_judge_file_is_refused_the_same_way(tmp_path: Path, case: str) -> None:
    block, value, where = BAD_BLOCKS[case]
    target = write_good_target(tmp_path, target_id="mock-target")
    judge = write_bad_target(tmp_path, block, value, target_id="mock-judge")
    scope = write_scope(tmp_path)

    result = dry_run(target, scope, "--judge", str(judge))

    assert where in refusal(result, judge, value)


def test_fingerprint_refuses_a_bad_target_value_naming_the_file(tmp_path: Path) -> None:
    block, value, where = BAD_BLOCKS["capability not a boolean"]
    target = write_bad_target(tmp_path, block, value, target_id="mock-target")
    scope = write_scope(tmp_path)

    result = runner.invoke(app, ["fingerprint", str(target), "--scope", str(scope), "--offline"])

    assert where in refusal(result, target, value)


def test_fleet_refuses_a_bad_judge_value_naming_the_file(tmp_path: Path) -> None:
    block, value, where = BAD_BLOCKS["temperature not a number"]
    judge = write_bad_target(tmp_path, block, value, target_id="local-judge")
    fleet = tmp_path / "fleet.yaml"
    fleet.write_text(
        'version: "1"\ntargets:\n  - id: local\n'
        "    endpoint: http://localhost:11434/v1/chat/completions\n    model: m\n"
        "judge:\n  id: local-judge\n"
        "  endpoint: http://localhost:11434/v1/chat/completions\n  model: j\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app, ["fleet", str(fleet), "--judge", str(judge), "--out", str(tmp_path / "out")]
    )

    assert where in refusal(result, judge, value)


#: (YAML block with three problems, the reasons in the order the line must give them).
SEVERAL_PROBLEMS = {
    "capabilities": (
        "capabilities:\n  tools: {value}\n  rag: [1, 2]\n  memory: {{a: b}}\n",
        [
            "'capabilities' failed validation: tools: Input should be a valid boolean",
            "; rag: Input should be a valid boolean",
            "; memory: Input should be a valid boolean",
        ],
    ),
    "sampling_defaults": (
        "sampling_defaults:\n  temperature: {value}\n  top_p: [1]\n  seed: 1.5\n",
        [
            "'sampling_defaults' failed validation: temperature: Input should be a valid number",
            "; top_p: Input should be a valid number",
            "; seed: Input should be a valid integer",
        ],
    ),
}


@pytest.mark.parametrize("block_name", sorted(SEVERAL_PROBLEMS))
def test_every_problem_in_the_block_is_listed_on_the_one_line(
    tmp_path: Path, block_name: str
) -> None:
    block, reasons = SEVERAL_PROBLEMS[block_name]
    target = write_bad_target(tmp_path, block, "maybe-later", target_id="mock-target")
    scope = write_scope(tmp_path)

    result = dry_run(target, scope)

    line = refusal(result, target, "maybe-later")
    positions = [line.find(reason) for reason in reasons]
    assert -1 not in positions, (reasons, line)
    assert positions == sorted(positions), line


@pytest.mark.parametrize("case", sorted(BAD_BLOCKS))
def test_the_cli_redactor_leaves_each_value_readable(case: str) -> None:
    """Otherwise the CLI tests above could pass on a value the redactor masked, not omitted."""

    value = BAD_BLOCKS[case][1]
    assert value in _masked(ValueError(f"got {value} here"))


@pytest.mark.parametrize("case", sorted(BAD_BLOCKS))
def test_load_target_raises_a_plain_value_error_not_pydantics(tmp_path: Path, case: str) -> None:
    """Every command catches ``ValueError``; the type check keeps pydantic's text out of all of
    them, including a caller that prints ``str(exc)`` without the CLI's handler."""

    block, value, where = BAD_BLOCKS[case]
    target = write_bad_target(tmp_path, block, value, target_id="t")

    with pytest.raises(ValueError) as refused:
        load_target(target)

    assert type(refused.value) is ValueError
    message = str(refused.value)
    assert message.startswith(f"target file {target} ")
    assert where in message
    assert "\n" not in message
    for piece in pieces(value):
        assert piece not in message, piece

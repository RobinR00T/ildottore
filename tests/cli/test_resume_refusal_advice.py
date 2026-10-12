"""A resume refusal says what changed and which flag puts it back (CLI audit 2026-10-11, M1).

Three refusals said neither. A spec edit read "75 changed (...)" and "restore the specs as they
were", without the field that changed or the flag (``--spec-path``) that resumes against the specs
the run was made with; a different ``--spec`` read "71 no longer selected ... restore the specs"
although no file had changed; and ``--resume --hardened`` read "Restore the target as it was"
although the target file was the same, only the route differed. The run context now records the
selection flags, a short digest of each field of each spec and of the target, and the route, so
each refusal names the field, the selection it was made with and the flag that restores it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.run import RunOptions, execute_run
from ildottore.shared.enums import Severity

from .conftest import make_spec, write_scope, write_spec_tree, write_target

_BUDGET = 6


def _opts(tmp_path: Path, **kw: object) -> RunOptions:
    opts = RunOptions(
        targets=[write_target(tmp_path, mock_scenario="vulnerable")],
        scope=write_scope(tmp_path),
        runs=3,
        quiet=True,
        evidence_root=tmp_path / "ev",
        run_db=tmp_path / "runs.sqlite",
        budget_requests=_BUDGET,
        concurrency=1,
    )
    for key, value in kw.items():
        setattr(opts, key, value)
    return opts


_IDS = ("PI-DIRECT-001", "PI-DIRECT-002", "PI-DIRECT-003")


def _halted(tmp_path: Path, **kw: object) -> tuple[str, Path]:
    spec_dir = write_spec_tree(tmp_path, [make_spec(spec_id) for spec_id in _IDS])
    outcome = execute_run(_opts(tmp_path, **kw), [spec_dir])
    assert outcome.exit_code == ExitCode.ERROR, "the request ceiling should halt the run"
    (run_id,) = [p.name for p in (tmp_path / "ev").iterdir() if p.is_dir()]
    return run_id, spec_dir


def _refusal(tmp_path: Path, spec_dir: Path, run_id: str, **kw: object) -> str:
    with pytest.raises(ValueError) as refused:
        execute_run(_opts(tmp_path, resume=run_id, budget_requests=100, **kw), [spec_dir])
    return str(refused.value)


def test_a_changed_spec_names_the_field_and_the_spec_path_flag(tmp_path: Path) -> None:
    run_id, _ = _halted(tmp_path)
    edited = make_spec("PI-DIRECT-001")
    edited = edited.model_copy(
        update={"attack": edited.attack.model_copy(update={"user_prompt": "another question"})}
    )
    changed = write_spec_tree(
        tmp_path / "edited", [edited, make_spec("PI-DIRECT-002"), make_spec("PI-DIRECT-003")]
    )

    message = _refusal(tmp_path, changed, run_id)
    assert "1 changed (PI-DIRECT-001), in attack" in message
    assert "--spec-path" in message
    assert "restore the specs as they were" not in message


def test_a_field_changed_in_every_spec_is_counted_once(tmp_path: Path) -> None:
    """The OD-19 shape: one field renamed in every spec of the battery."""

    run_id, _ = _halted(tmp_path)
    renamed = [make_spec(spec_id, severity=Severity.LOW) for spec_id in _IDS]
    changed = write_spec_tree(tmp_path / "edited", renamed)

    message = _refusal(tmp_path, changed, run_id)
    assert "3 changed (PI-DIRECT-001, PI-DIRECT-002, PI-DIRECT-003), in severity (3)" in message


def test_a_different_selection_names_the_flags_the_run_was_made_with(tmp_path: Path) -> None:
    run_id, spec_dir = _halted(
        tmp_path, spec_globs=["PI-DIRECT-001", "PI-DIRECT-002"], budget_requests=4
    )

    message = _refusal(tmp_path, spec_dir, run_id)
    assert "1 new (PI-DIRECT-003)" in message
    assert "no spec it ran changed" in message
    assert "made with --spec PI-DIRECT-001 --spec PI-DIRECT-002" in message
    assert "this invocation selects with no selection flag" in message
    assert "Resume with --spec PI-DIRECT-001 --spec PI-DIRECT-002" in message
    assert "restore the specs" not in message


def test_a_narrower_selection_names_them_too(tmp_path: Path) -> None:
    run_id, spec_dir = _halted(tmp_path)

    message = _refusal(
        tmp_path, spec_dir, run_id, spec_globs=["PI-DIRECT-00[12]"], exclude_globs=[]
    )
    assert "1 no longer selected (PI-DIRECT-003)" in message
    assert "made with no selection flag" in message
    assert "this invocation selects with --spec 'PI-DIRECT-00[12]'" in message
    assert "Resume with no selection flag" in message


def test_a_spec_added_under_the_same_selection_points_at_the_spec_path(tmp_path: Path) -> None:
    run_id, spec_dir = _halted(tmp_path)
    write_spec_tree(tmp_path, [make_spec("PI-DIRECT-004")])

    message = _refusal(tmp_path, spec_dir, run_id)
    assert "1 new (PI-DIRECT-004)" in message
    assert "same selection flags" in message
    assert "--spec-path" in message


def test_resume_hardened_names_the_route_flag_and_says_the_file_is_unchanged(
    tmp_path: Path,
) -> None:
    run_id, spec_dir = _halted(tmp_path)

    message = _refusal(tmp_path, spec_dir, run_id, hardened=True)
    assert "the offline 'vulnerable' replay" in message
    assert "the offline 'hardened' replay" in message
    assert "--hardened" in message
    assert "target file is otherwise unchanged" in message
    assert "Resume without --hardened" in message
    assert "Restore the target as it was" not in message


def test_a_run_made_with_hardened_is_told_to_put_it_back(tmp_path: Path) -> None:
    run_id, spec_dir = _halted(tmp_path, hardened=True)

    message = _refusal(tmp_path, spec_dir, run_id)
    assert "Resume with --hardened" in message


def test_an_edited_mock_scenario_is_named_as_the_field_of_the_file(tmp_path: Path) -> None:
    run_id, spec_dir = _halted(tmp_path)
    (tmp_path / "other").mkdir()
    flipped = write_target(tmp_path / "other", mock_scenario="bare")

    message = _refusal(tmp_path, spec_dir, run_id, targets=[flipped])
    assert "mock_scenario" in message
    assert "the offline 'bare' replay" in message


def test_a_changed_target_field_is_named(tmp_path: Path) -> None:
    run_id, spec_dir = _halted(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    (other / "target.yaml").write_text(
        "id: mock-target\ntype: chatbot\nmock_scenario: vulnerable\n"
        "capabilities:\n  tools: true\n  rag: false\n",
        encoding="utf-8",
    )

    message = _refusal(tmp_path, spec_dir, run_id, targets=[other / "target.yaml"])
    assert "different target" in message
    assert "its capabilities differ" in message

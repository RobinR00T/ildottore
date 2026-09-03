"""Thin-delegator commands (contract §5.5): fingerprint, registry, describe,
new-spec, replay, lint, schema export.

Each command wires an upstream unit and renders - it holds no business logic. These
tests assert the wiring + I/O behave, not the upstream logic (owned elsewhere).
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ildottore.cli import describe as describe_mod
from ildottore.cli import fingerprint as fingerprint_mod
from ildottore.cli import new_spec as new_spec_mod
from ildottore.cli import registry as registry_mod
from ildottore.cli.main import app
from ildottore.shared.enums import Category
from ildottore.shared.models import ModelFingerprint

from .conftest import (
    make_spec,
    write_pack_with_suite,
    write_scope,
    write_spec_tree,
    write_target,
)

runner = CliRunner()


# --- fingerprint -------------------------------------------------------------------


def test_fingerprint_returns_model_fingerprint(tmp_path: Path) -> None:
    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    fp = fingerprint_mod.fingerprint_target(target, scope)
    assert isinstance(fp, ModelFingerprint)


def test_fingerprint_cli_emits_json(tmp_path: Path) -> None:
    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    res = runner.invoke(app, ["fingerprint", str(target), "--scope", str(scope)])
    assert res.exit_code == 0
    # Output is a serialized ModelFingerprint.
    parsed = json.loads(res.stdout)
    assert isinstance(parsed, dict)


# --- registry ls -------------------------------------------------------------------


def test_registry_ls_lists_specs(tmp_path: Path) -> None:
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001"), make_spec("JB-ROLEPLAY-001")])
    rows = registry_mod.list_specs([specs])
    assert {s.id for s in rows} == {"PI-DIRECT-001", "JB-ROLEPLAY-001"}


def test_registry_ls_filter_by_owasp(tmp_path: Path) -> None:
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001", owasp="LLM01")])
    rows = registry_mod.list_specs([specs], owasp="LLM02")
    assert rows == []


def test_registry_ls_cli(tmp_path: Path) -> None:
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    res = runner.invoke(app, ["registry", "ls", "--spec-path", str(specs)])
    assert res.exit_code == 0
    assert "PI-DIRECT-001" in res.stdout


def test_render_spec_rows_empty() -> None:
    assert registry_mod.render_spec_rows([]) == ["(no specs match)"]


def test_registry_ls_unknown_suite_returns_empty(tmp_path: Path) -> None:
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    assert registry_mod.list_specs([specs], suite="does-not-exist") == []


def test_registry_ls_suite_filter(tmp_path: Path) -> None:
    pack = write_pack_with_suite(
        tmp_path,
        [make_spec("PI-DIRECT-001"), make_spec("JB-ROLEPLAY-001", category=Category.JAILBREAK)],
    )
    rows = registry_mod.list_specs([pack], suite="owasp:llm")
    assert {s.id for s in rows} == {"PI-DIRECT-001", "JB-ROLEPLAY-001"}


def test_registry_ls_suite_plus_category_filter(tmp_path: Path) -> None:
    # Suite narrows first, then the category filter applies (AND semantics).
    pack = write_pack_with_suite(
        tmp_path,
        [make_spec("PI-DIRECT-001"), make_spec("JB-ROLEPLAY-001", category=Category.JAILBREAK)],
    )
    rows = registry_mod.list_specs([pack], suite="owasp:llm", category="prompt_injection")
    assert {s.id for s in rows} == {"PI-DIRECT-001"}


def test_registry_ls_suite_filters_by_owasp_and_tag(tmp_path: Path) -> None:
    pack = write_pack_with_suite(
        tmp_path,
        [make_spec("PI-DIRECT-001", owasp="LLM01", tags=["x"])],
    )
    assert registry_mod.list_specs([pack], suite="owasp:llm", owasp="LLM99") == []
    assert registry_mod.list_specs([pack], suite="owasp:llm", tag="nope") == []
    assert registry_mod.list_specs([pack], suite="owasp:llm", tag="x")


def test_registry_ls_suite_cli(tmp_path: Path) -> None:
    pack = write_pack_with_suite(tmp_path, [make_spec("PI-DIRECT-001")])
    res = runner.invoke(app, ["registry", "ls", "--suite", "owasp:llm", "--spec-path", str(pack)])
    assert res.exit_code == 0
    assert "PI-DIRECT-001" in res.stdout


# --- describe ----------------------------------------------------------------------


def test_describe_spec_found(tmp_path: Path) -> None:
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    spec = describe_mod.describe_spec([specs], "PI-DIRECT-001")
    assert spec.id == "PI-DIRECT-001"
    card = describe_mod.render_describe(spec)
    assert "PI-DIRECT-001" in card
    assert "owasp" in card


def test_describe_cli_missing_spec_errors(tmp_path: Path) -> None:
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    res = runner.invoke(app, ["describe", "NOPE-999", "--spec-path", str(specs)])
    assert res.exit_code > 2


def test_describe_cli_found(tmp_path: Path) -> None:
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    res = runner.invoke(app, ["describe", "PI-DIRECT-001", "--spec-path", str(specs)])
    assert res.exit_code == 0
    assert "PI-DIRECT-001" in res.stdout


# --- new-spec ----------------------------------------------------------------------


def test_new_spec_scaffold_is_shaped() -> None:
    text = new_spec_mod.scaffold_spec("PI-NEW-001", family="prompt-injection")
    assert "id: PI-NEW-001" in text
    assert "fixtures:" in text
    assert "expect_verdict: fail" in text


def test_new_spec_unknown_category_raises() -> None:
    try:
        new_spec_mod.scaffold_spec("X-1", family="f", category="bogus")
    except ValueError as exc:
        assert "unknown category" in str(exc)
    else:  # pragma: no cover - guard
        raise AssertionError("expected ValueError")


def test_new_spec_writes_file(tmp_path: Path) -> None:
    path = new_spec_mod.write_scaffold(tmp_path, "PI-NEW-001", family="pi")
    assert path.exists()
    assert path.name == "PI-NEW-001.yaml"


def test_new_spec_refuses_overwrite(tmp_path: Path) -> None:
    new_spec_mod.write_scaffold(tmp_path, "PI-NEW-001", family="pi")
    try:
        new_spec_mod.write_scaffold(tmp_path, "PI-NEW-001", family="pi")
    except FileExistsError:
        pass
    else:  # pragma: no cover - guard
        raise AssertionError("expected FileExistsError")


def test_new_spec_cli_stdout(tmp_path: Path) -> None:
    res = runner.invoke(app, ["new-spec", "--id", "PI-NEW-001", "--family", "pi", "--stdout"])
    assert res.exit_code == 0
    assert "id: PI-NEW-001" in res.stdout


def test_new_spec_cli_writes(tmp_path: Path) -> None:
    res = runner.invoke(
        app, ["new-spec", "--id", "PI-NEW-001", "--family", "pi", "--out", str(tmp_path)]
    )
    assert res.exit_code == 0
    assert (tmp_path / "PI-NEW-001.yaml").exists()


# --- schema export -----------------------------------------------------------------


def test_schema_export_all() -> None:
    res = runner.invoke(app, ["schema", "export"])
    assert res.exit_code == 0
    parsed = json.loads(res.stdout)
    assert isinstance(parsed, dict)
    assert parsed  # at least one schema


def test_schema_export_unknown_name_errors() -> None:
    res = runner.invoke(app, ["schema", "export", "--name", "bogus-schema"])
    assert res.exit_code > 2


# --- lint (mounted from u02) -------------------------------------------------------


def test_lint_cli_runs(tmp_path: Path) -> None:
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    res = runner.invoke(app, ["lint", str(specs)])
    # Lint returns 0 (clean) or 1 (findings); never crashes.
    assert res.exit_code in (0, 1)

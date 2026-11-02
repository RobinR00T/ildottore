"""``run --policy-pack`` and ``--allow-pii-elicitation`` (u12 A-122, OD-46, OD-11).

The CLI loaded no policy pack, so a spec declaring ``requires_policy`` (the seven
``agentic-extortion`` specs, ``DL-PII-ELICIT-001``) could not be sent from ``dottore``. One option
now loads the engagement's pack through ``policy.packs.load_pack``, in place of the default one,
says what it enables before anything is planned, and is recorded with the run; the run's PII key
comes in the same change and alone is refused, since it would enable nothing.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli import resume as resume_mod
from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.policy import load_pack, pack_digest
from ildottore.shared.enums import Category
from ildottore.shared.models import AttackSpec
from ildottore.store.run_sqlite import SqliteRunStore

from .conftest import make_spec, write_scope, write_spec_tree, write_target

_OFFENSIVE = make_spec("PI-OFFENSIVE-001").model_copy(
    update={"requires_policy": ["offensive_simulation"]}
)
_PLAIN = make_spec("PI-PLAIN-001")


def _pack(tmp_path: Path, body: str, name: str = "pack.yaml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


_ENGAGEMENT = (
    "name: engagement-2026-11\n"
    "allow_categories: [prompt_injection]\n"
    "enabled_capabilities: [offensive_simulation]\n"
)


def _argv(tmp_path: Path, specs: list[AttackSpec], *extra: str) -> list[str]:
    return [
        "run",
        str(write_target(tmp_path, mock_scenario="vulnerable")),
        "--scope",
        str(write_scope(tmp_path)),
        "--spec-path",
        str(write_spec_tree(tmp_path, specs)),
        "--no-color",
        "--runs",
        "1",
        "--run-db",
        str(tmp_path / "runs.db"),
        "--evidence-root",
        str(tmp_path / "evidence"),
        *extra,
    ]


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_the_run_key_alone_is_refused(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app, _argv(tmp_path, [_PLAIN], "--allow-pii-elicitation", "--dry-run")
    )
    assert result.exit_code != 0
    assert "--allow-pii-elicitation needs --policy-pack" in _flat(result.output)


def test_without_a_pack_a_spec_that_requires_a_capability_is_blocked(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, _argv(tmp_path, [_OFFENSIVE, _PLAIN], "--dry-run", "-vv"))
    assert result.exit_code == 0, result.output
    out = _flat(result.output)
    assert "blocked: 1 spec(s)" in out
    assert "requires policy capability(ies) ['offensive_simulation']" in out
    assert "policy pack:" not in out


def test_the_pack_enables_the_capability_and_is_said(tmp_path: Path) -> None:
    pack = _pack(tmp_path, _ENGAGEMENT)
    result = CliRunner().invoke(
        app, _argv(tmp_path, [_OFFENSIVE, _PLAIN], "--policy-pack", str(pack), "--dry-run", "-vv")
    )
    assert result.exit_code == 0, result.output
    out = _flat(result.output)
    assert "blocked:" not in out
    digest = pack_digest(load_pack(pack))[:12]
    assert (
        f"policy pack: engagement-2026-11 ({pack}, sha256 {digest}): 1 categor(ies) and 0 "
        "spec(s) enabled, 0 denied; capabilities: offensive_simulation; layer B: off; "
        "PII elicitation: pack no, run no (both needed, DL4)"
    ) in out


def test_the_pack_replaces_the_default_one(tmp_path: Path) -> None:
    """A category the pack does not enable is blocked: the pack is the engagement's record."""

    pack = _pack(tmp_path, "name: narrow\nallow_specs: [PI-OFFENSIVE-001]\n")
    jail = make_spec("JB-OTHER-001").model_copy(
        update={"category": Category.JAILBREAK, "test_only": True}
    )
    result = CliRunner().invoke(
        app, _argv(tmp_path, [_PLAIN, jail], "--policy-pack", str(pack), "--dry-run", "-vv")
    )
    assert result.exit_code == 3, result.output
    out = _flat(result.output)
    assert "nothing would be sent" in out and "2 blocked by policy" in out
    assert "needs a --policy-pack that enables it" in out


@pytest.mark.parametrize(
    ("body", "said"),
    [
        ("name: x\nallow_categories: [nonsense]\n", "failed validation"),
        ("name: x\nsurprise: 1\n", "failed validation"),
        ("- a list\n", "must be a mapping at top level"),
    ],
)
def test_a_pack_it_cannot_read_is_refused_before_anything_is_planned(
    tmp_path: Path, body: str, said: str
) -> None:
    pack = _pack(tmp_path, body)
    result = CliRunner().invoke(
        app, _argv(tmp_path, [_PLAIN], "--policy-pack", str(pack), "--dry-run")
    )
    assert result.exit_code == 3, result.output
    assert said in _flat(result.output)


def test_a_pii_spec_needs_both_keys(tmp_path: Path) -> None:
    pii = make_spec("DL-PII-OTHER-001").model_copy(
        update={"requires_policy": ["layer_b_pii"], "tags": ["pii-elicitation"]}
    )
    body = (
        "name: pii-engagement\nallow_categories: [prompt_injection]\n"
        "enabled_capabilities: [layer_b_pii]\nallow_pii_elicitation: true\n"
    )
    pack = _pack(tmp_path, body)
    one_key = _flat(
        CliRunner()
        .invoke(app, _argv(tmp_path, [pii, _PLAIN], "--policy-pack", str(pack), "--dry-run", "-vv"))
        .output
    )
    assert "needs two keys" in one_key
    both = CliRunner().invoke(
        app,
        _argv(
            tmp_path,
            [pii, _PLAIN],
            "--policy-pack",
            str(pack),
            "--allow-pii-elicitation",
            "--dry-run",
            "-vv",
        ),
    )
    assert both.exit_code == 0, both.output
    out = _flat(both.output)
    assert "needs two keys" not in out and "blocked:" not in out
    assert "PII elicitation: pack yes, run yes" in out


def test_the_run_records_its_pack_and_a_resume_is_bound_to_it(tmp_path: Path) -> None:
    pack = _pack(tmp_path, _ENGAGEMENT)
    result = CliRunner().invoke(app, _argv(tmp_path, [_OFFENSIVE], "--policy-pack", str(pack)))
    assert result.exit_code == 2, result.output  # the vulnerable replay fails the spec: it ran
    with closing(sqlite3.connect(tmp_path / "runs.db")) as conn:
        (run_id,) = conn.execute("SELECT run_id FROM runs").fetchone()
    context = SqliteRunStore(tmp_path / "runs.db").get_run_context(run_id)
    loaded = load_pack(pack)
    assert context is not None
    assert context["policy_pack_digest"] == pack_digest(loaded)
    assert context["allow_pii_elicitation"] is False
    target = wiring.load_target(tmp_path / "target.yaml")

    def check(**kwargs: object) -> None:
        resume_mod._assert_same_context(
            tmp_path / "runs.db",
            run_id,
            target,
            mock_scenario="vulnerable",
            runs=None,
            **kwargs,  # type: ignore[arg-type]
        )

    check(policy_pack=loaded)
    with pytest.raises(ValueError, match="a pack stored, the default pack now"):
        check()
    other = load_pack(_pack(tmp_path, _ENGAGEMENT + "deny: [PI-PLAIN-001]\n", "other.yaml"))
    with pytest.raises(ValueError, match="a different --policy-pack"):
        check(policy_pack=other)
    with pytest.raises(ValueError, match="--allow-pii-elicitation off"):
        check(policy_pack=loaded, allow_pii_elicitation=True)


def test_a_run_made_before_the_flag_reads_as_the_default_pack(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, _argv(tmp_path, [_PLAIN]))
    assert result.exit_code == 2, result.output
    with closing(sqlite3.connect(tmp_path / "runs.db")) as conn:
        (run_id,) = conn.execute("SELECT run_id FROM runs").fetchone()
    store = SqliteRunStore(tmp_path / "runs.db")
    context = store.get_run_context(run_id) or {}
    for key in ("policy_pack_digest", "allow_pii_elicitation"):
        context.pop(key)
    with closing(sqlite3.connect(tmp_path / "runs.db")) as conn, conn:
        import json

        conn.execute(
            "UPDATE runs SET context_json = ? WHERE run_id = ?", (json.dumps(context), run_id)
        )
    resume_mod._assert_same_context(
        tmp_path / "runs.db",
        run_id,
        wiring.load_target(tmp_path / "target.yaml"),
        mock_scenario="vulnerable",
        runs=None,
    )

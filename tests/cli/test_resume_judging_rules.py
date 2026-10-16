"""A resume is bound to the rules that judged its halted half (u12 A-81, CLI audit 2026-10-11 H2).

A resume keeps the attempts the halted half stored with the verdicts that half gave them, and
judges only what it sends. The stored replies are redacted (a leaked canary reads
``«REDACTED:canary:…»``), so they cannot be judged again by rules that look for the raw value.
Measured on ``de122e26``: a run halted on ``f12ba83`` against a stub whose every reply the
provider's filter cut, resumed with ``--spec-path`` at ``f12ba83``'s specs (the route the
CHANGELOG recommended), kept 4 attempts ``f12ba83`` had judged ``pass`` beside 2 the new rules
judged ``cut_by_provider_output_filter``, and the summary and ``replay`` said "6 of 10 attempts
cut ... never a pass" although all 10 were cut. Nothing recorded which rules judged a run, and
``--version`` said ``0.1.0`` on all three commits.

A run records ``judging_rules`` and ``tool_version`` when it starts; a resume under other rules,
or of a run that records none (made by an older version), is refused before anything is sent,
naming both and what to do. No flag waives it: the report it would write contradicts itself.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore import __version__
from ildottore.cli import resume as resume_mod
from ildottore.cli.app import app
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.run import RunOptions, execute_run
from ildottore.shared.judging_rules import JUDGING_RULES_VERSION

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


def _specs(tmp_path: Path) -> Path:
    return write_spec_tree(
        tmp_path,
        [make_spec("PI-DIRECT-001"), make_spec("PI-DIRECT-002"), make_spec("PI-DIRECT-003")],
    )


def _halted(tmp_path: Path) -> tuple[str, Path]:
    spec_dir = _specs(tmp_path)
    outcome = execute_run(_opts(tmp_path), [spec_dir])
    assert outcome.exit_code == ExitCode.ERROR, "the request ceiling should halt the run"
    (run_id,) = [p.name for p in (tmp_path / "ev").iterdir() if p.is_dir()]
    return run_id, spec_dir


def _context(tmp_path: Path) -> dict[str, object]:
    with closing(sqlite3.connect(tmp_path / "runs.sqlite")) as db:
        (raw,) = db.execute("SELECT context_json FROM runs").fetchone()
    loaded = json.loads(raw)
    assert isinstance(loaded, dict)
    return loaded


def _rewrite(tmp_path: Path, **changes: object) -> None:
    """Set (or, with the value ``...``, delete) context keys, as another version would leave it."""

    context = _context(tmp_path)
    for key, value in changes.items():
        if value is ...:
            context.pop(key, None)
        else:
            context[key] = value
    with closing(sqlite3.connect(tmp_path / "runs.sqlite")) as db:
        db.execute("UPDATE runs SET context_json = ?", (json.dumps(context),))
        db.commit()


def _stored(tmp_path: Path) -> int:
    return len(list((tmp_path / "ev").rglob("*.json")))


def test_a_run_records_the_rules_that_judge_it_and_the_version_that_started_it(
    tmp_path: Path,
) -> None:
    _halted(tmp_path)
    context = _context(tmp_path)
    assert context["judging_rules"] == JUDGING_RULES_VERSION
    assert context["tool_version"] == __version__


def test_a_resume_keeps_the_version_that_started_the_run(tmp_path: Path) -> None:
    """``tool_version`` is the start's: a later release under the same rules keeps it."""

    run_id, spec_dir = _halted(tmp_path)
    _rewrite(tmp_path, tool_version="0.0.9")
    execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])
    context = _context(tmp_path)
    assert context["tool_version"] == "0.0.9"
    assert context["judging_rules"] == JUDGING_RULES_VERSION


def test_a_run_judged_by_older_rules_is_refused_naming_both(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id, spec_dir = _halted(tmp_path)
    before, stored = _context(tmp_path), _stored(tmp_path)
    monkeypatch.setattr(resume_mod, "JUDGING_RULES_VERSION", JUDGING_RULES_VERSION + 1)

    with pytest.raises(ValueError) as refused:
        execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])

    message = str(refused.value)
    assert f"judging rules {JUDGING_RULES_VERSION}," in message
    assert f"judging rules {JUDGING_RULES_VERSION + 1}" in message
    assert f"started by Il Dottore v{__version__}" in message
    assert "redacted" in message, "it says why the stored replies cannot be judged again"
    assert "the version that started it" in message and "fresh run" in message
    assert "There is no flag for this" in message
    assert _context(tmp_path) == before and _stored(tmp_path) == stored, "a refusal writes nothing"


def test_a_run_halted_under_rules_1_is_refused_by_rules_2_naming_both(tmp_path: Path) -> None:
    """u08 A-85 bumped the rules to 2: a run halted under 1 kept verdicts the new rules would not
    give (an echoed canary a confirmed fail, a sweep's crossing on every attempt), so its resume
    is refused before anything is sent, naming both versions, with no flag to waive it."""

    assert JUDGING_RULES_VERSION == 2
    run_id, spec_dir = _halted(tmp_path)
    _rewrite(tmp_path, judging_rules=1)
    before, stored = _context(tmp_path), _stored(tmp_path)

    with pytest.raises(ValueError) as refused:
        execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])

    message = str(refused.value)
    assert "was judged by the rules of an older Il Dottore (judging rules 1," in message
    assert "judging rules 2." in message
    assert "There is no flag for this" in message
    assert _context(tmp_path) == before and _stored(tmp_path) == stored


def test_a_run_judged_by_newer_rules_is_refused_too(tmp_path: Path) -> None:
    run_id, spec_dir = _halted(tmp_path)
    _rewrite(tmp_path, judging_rules=JUDGING_RULES_VERSION + 1)

    with pytest.raises(ValueError, match="newer") as refused:
        execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])
    assert f"judging rules {JUDGING_RULES_VERSION + 1}" in str(refused.value)


@pytest.mark.parametrize("unverified", [False, True])
def test_a_run_that_records_no_rules_is_one_an_older_version_made(
    tmp_path: Path, unverified: bool
) -> None:
    """What every run halted before this version leaves: refused as older, with no opt-in."""

    run_id, spec_dir = _halted(tmp_path)
    _rewrite(tmp_path, judging_rules=..., tool_version=...)
    stored = _stored(tmp_path)

    with pytest.raises(ValueError) as refused:
        execute_run(
            _opts(tmp_path, resume=run_id, budget_requests=100, resume_unverified=unverified),
            [spec_dir],
        )
    message = str(refused.value)
    assert "records no judging rules" in message
    assert "older than this one" in message
    assert f"judging rules {JUDGING_RULES_VERSION})" in message
    assert "There is no flag for this" in message
    assert _stored(tmp_path) == stored


def test_the_refusal_exits_3_through_the_cli_and_dry_run_and_estimate_refuse_too(
    tmp_path: Path,
) -> None:
    run_id, spec_dir = _halted(tmp_path)
    _rewrite(tmp_path, judging_rules=...)
    base = [
        "run",
        "-t",
        str(tmp_path / "target.yaml"),
        "--scope",
        str(tmp_path / "scope.yaml"),
        "--spec-path",
        str(spec_dir),
        "--evidence-root",
        str(tmp_path / "ev"),
        "--run-db",
        str(tmp_path / "runs.sqlite"),
        "--resume",
        run_id,
    ]
    for extra in ([], ["--dry-run"], ["--estimate"]):
        result = CliRunner().invoke(app, [*base, *extra])
        assert result.exit_code == ExitCode.ERROR, result.output
        assert "records no judging rules" in result.output
        # Through the redactor every error goes through, which read "1 (2026-10-12" as a phone.
        assert "REDACTED" not in result.output, result.output
        assert f"judging rules {JUDGING_RULES_VERSION}" in result.output


def test_version_names_the_judging_rules() -> None:
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"dottore {__version__} (judging rules {JUDGING_RULES_VERSION})"


def test_a_newer_run_is_refused_for_its_rules_before_its_other_fields_are_checked(
    tmp_path: Path,
) -> None:
    """A newer version may write a field this one does not know the shape of (L-4 of the pre-merge
    audit of 22269e0c: such a record was called corrupt, where its rules are what refuses it)."""

    run_id, spec_dir = _halted(tmp_path)
    _rewrite(
        tmp_path,
        judging_rules=JUDGING_RULES_VERSION + 1,
        selection={"spec": "PI-*", "added_later": True},
        route=["a", "shape", "this", "version", "does", "not", "know"],
    )
    with pytest.raises(ValueError) as refused:
        execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])
    assert "a newer Il Dottore" in str(refused.value)
    assert "context_json holds" not in str(refused.value)


def test_a_selection_key_a_later_release_adds_under_the_same_rules_is_left_alone(
    tmp_path: Path,
) -> None:
    run_id, spec_dir = _halted(tmp_path)
    context = _context(tmp_path)
    selection = context["selection"]
    assert isinstance(selection, dict)
    _rewrite(tmp_path, selection={**selection, "added_later": ["x"]})
    outcome = execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])
    assert outcome.exit_code in {ExitCode.FINDINGS_AT_OR_ABOVE, ExitCode.FINDINGS_BELOW}


_VERSIONS = [
    "0.1.0",
    "1.2.3.4",
    "2026.10.12",
    "2026.10.12.1",
    "0.1.0.dev20261012",
    "1.2.3rc1",
    "0.1.1.post1",
    "10.20.30",
    "1.0.0+local.7",
    "1!2.0",
    "26.10",
]


@pytest.mark.parametrize("version", _VERSIONS)
def test_a_version_of_any_shape_reads_in_clear_through_the_error_masking(version: str) -> None:
    """``1.2.3.4`` read as an IPv4 address and ``2026.10.12`` as a phone number (L-5): every
    version the refusal names is a tool's own value, written ``v<version>``, which no rule masks."""

    from ildottore.cli.app import _masked

    for rules, stored in ((1, 2), (2, 1), (5, 2026), (1, 999_999)):
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(resume_mod, "JUDGING_RULES_VERSION", rules)
            patch.setattr(resume_mod, "__version__", version)
            contexts: list[dict[str, object]] = [
                {"judging_rules": stored, "tool_version": version},
                {"judging_rules": stored},
                {},
            ]
            for context in contexts:
                with pytest.raises(ValueError) as refused:
                    resume_mod._assert_same_rules("run-0123456789ab", context)
                shown = _masked(refused.value)
                assert shown == str(refused.value), shown
                assert f"v{version}" in shown


def test_a_stored_tool_version_that_is_not_a_version_is_corrupt(tmp_path: Path) -> None:
    run_id, spec_dir = _halted(tmp_path)
    _rewrite(tmp_path, tool_version="sk-not-a-version")
    with pytest.raises(
        ValueError, match="holds a tool_version value that is not a package version"
    ):
        execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])


def test_each_invocation_records_its_package_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``tool_version`` is the start's; ``tool_versions`` every invocation's, in order (L-6)."""

    run_id, spec_dir = _halted(tmp_path)
    assert _context(tmp_path)["tool_versions"] == [__version__]
    monkeypatch.setattr(resume_mod, "__version__", "0.1.1")
    execute_run(_opts(tmp_path, resume=run_id, budget_requests=7), [spec_dir])
    context = _context(tmp_path)
    assert context["tool_versions"] == [__version__, "0.1.1"]
    assert context["tool_version"] == __version__


def test_a_run_records_the_evaluator_plugins_its_specs_use_and_a_resume_under_others_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A plugin's evaluator judges from outside the package the digest covers (H-1, M-5)."""

    seen: list[set[str]] = []

    def plugins(version: str) -> object:
        def listed(types: set[str]) -> list[str]:
            seen.append(types)
            return [f"leak=acme.ev:Leak (acme {version}) sha256:{'0' * 64}"]

        return listed

    monkeypatch.setattr(resume_mod, "evaluator_plugins", plugins("1.0"))
    run_id, spec_dir = _halted(tmp_path)
    assert _context(tmp_path)["evaluator_plugins"] == [
        f"leak=acme.ev:Leak (acme 1.0) sha256:{'0' * 64}"
    ]
    assert seen[0] == {"refusal"}, "only the evaluator types the selected specs name are asked"
    stored = _stored(tmp_path)

    monkeypatch.setattr(resume_mod, "evaluator_plugins", plugins("1.1"))
    with pytest.raises(ValueError) as refused:
        execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])
    message = str(refused.value)
    assert "(acme 1.0)" in message and "(acme 1.1)" in message
    assert "There is no flag for this" in message
    assert _stored(tmp_path) == stored

    monkeypatch.setattr(resume_mod, "evaluator_plugins", plugins("1.0"))
    outcome = execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])
    assert outcome.exit_code in {ExitCode.FINDINGS_AT_OR_ABOVE, ExitCode.FINDINGS_BELOW}


def _plugin_tree(tmp_path: Path, kind: str, body: str) -> Path:
    """A plugin distribution on disk: a module and its dist-info with one entry point."""

    root = tmp_path / "plugins"
    info = root / "acmeplug-1.0.dist-info"
    info.mkdir(parents=True)
    (root / "acmeplug.py").write_text(
        f"class Leak:\n    type = {kind!r}\n    async def evaluate(self, ctx):\n        {body}\n",
        encoding="utf-8",
    )
    (info / "METADATA").write_text("Metadata-Version: 2.1\nName: acmeplug\nVersion: 1.0\n")
    (info / "entry_points.txt").write_text("[dottore.evaluators]\nleak = acmeplug:Leak\n")
    (info / "RECORD").write_text("acmeplug.py,,\nacmeplug-1.0.dist-info/METADATA,,\n")
    return root


def test_only_a_plugin_whose_type_a_spec_names_is_recorded_with_its_source_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A plugin no selected spec names decides nothing and is left out (M-5); one a spec names is
    recorded with a digest of its sources, so a change under the same version is caught."""

    import importlib
    import sys

    root = _plugin_tree(tmp_path, "refusal", "return None")
    monkeypatch.syspath_prepend(str(root))
    importlib.invalidate_caches()
    assert resume_mod.evaluator_plugins({"regex_presence"}) == []
    first = resume_mod.evaluator_plugins({"refusal"})
    assert len(first) == 1 and first[0].startswith("leak=acmeplug:Leak (acmeplug 1.0) sha256:")

    (root / "acmeplug.py").write_text(
        "class Leak:\n    type = 'refusal'\n    async def evaluate(self, ctx):\n        return 1\n",
        encoding="utf-8",
    )
    sys.modules.pop("acmeplug", None)
    second = resume_mod.evaluator_plugins({"refusal"})
    assert second != first, "the same version with other code is another plugin"


def test_no_shipped_spec_can_name_a_plugin_type(tmp_path: Path) -> None:
    """Why the record is empty today: a spec's evaluator type is one of the schema's own."""

    from ildottore.shared.enums import EvaluatorType

    _halted(tmp_path)
    assert _context(tmp_path)["evaluator_plugins"] == []
    assert resume_mod.evaluator_types([make_spec("PI-DIRECT-001")]) <= {
        t.value for t in EvaluatorType
    }


def test_a_run_records_the_digest_of_the_code_that_judged_it(tmp_path: Path) -> None:
    from ildottore.shared.judging_rules import judging_digest

    _halted(tmp_path)
    assert _context(tmp_path)["judging_digest"] == judging_digest()


def test_a_resume_under_other_code_and_the_same_version_is_refused_naming_both_digests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second audit edited a default, an override, the offline judge and a decorator under an
    unchanged version and pin, and the resume mixed verdicts; the digest it recorded refuses it."""

    run_id, spec_dir = _halted(tmp_path)
    before, stored = _context(tmp_path), _stored(tmp_path)
    other = "f" * 64
    monkeypatch.setattr(resume_mod, "judging_digest", lambda: other)
    for unverified in (False, True):
        with pytest.raises(resume_mod.ResumeRefused) as refused:
            execute_run(
                _opts(tmp_path, resume=run_id, budget_requests=100, resume_unverified=unverified),
                [spec_dir],
            )
        message = str(refused.value)
        assert f"under the same judging rules ({JUDGING_RULES_VERSION}) by other code" in message
        assert str(before["judging_digest"]) in message and other in message
        assert "There is no flag for this" in message
        assert refused.value.digests == (before["judging_digest"], other)
    assert _context(tmp_path) == before and _stored(tmp_path) == stored


def test_the_digest_refusal_reads_in_clear_through_the_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ildottore.cli.app import _masked

    exc = resume_mod.ResumeRefused(
        f"its judging digest is {'a' * 64} and this installation's is {'b' * 64}",
        digests=("a" * 64, "b" * 64),
    )
    assert _masked(exc) == str(exc)


def test_a_run_that_records_the_rules_and_no_digest_is_refused(tmp_path: Path) -> None:
    run_id, spec_dir = _halted(tmp_path)
    _rewrite(tmp_path, judging_digest=...)
    with pytest.raises(ValueError, match="no judging digest"):
        execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])


def test_a_package_version_with_no_pep_440_shape_is_recorded_as_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The store refuses to read back a version of another shape, so it is never written one."""

    monkeypatch.setattr(resume_mod, "__version__", "a build of my own")
    run_id, spec_dir = _halted(tmp_path)
    context = _context(tmp_path)
    assert context["tool_version"] == "unknown" and context["tool_versions"] == ["unknown"]
    outcome = execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])
    assert outcome.exit_code in {ExitCode.FINDINGS_AT_OR_ABOVE, ExitCode.FINDINGS_BELOW}


def test_the_digest_refusal_names_the_files_that_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id, spec_dir = _halted(tmp_path)
    files = _context(tmp_path)["judging_files"]
    assert isinstance(files, dict) and "ildottore.adapters.rest" in files
    changed = {**files, "ildottore.adapters.rest": "0" * 8, "ildottore.cli.render": "1" * 8}
    monkeypatch.setattr(resume_mod, "judging_digest", lambda: "e" * 64)
    monkeypatch.setattr(resume_mod, "judging_files", lambda: changed)
    with pytest.raises(resume_mod.ResumeRefused) as refused:
        execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])
    assert "the files that differ: ildottore.adapters.rest, ildottore.cli.render" in str(
        refused.value
    )


def test_the_changed_files_are_capped_at_five() -> None:
    stored = {f"m{i}": "0" * 8 for i in range(8)}
    current = {f"m{i}": "1" * 8 for i in range(8)}
    text = resume_mod._changed_files(stored, current)
    assert text == "; the files that differ: m0, m1, m2, m3, m4 and 3 more"
    assert resume_mod._changed_files(None, current) == ""


def test_a_run_judged_under_another_interpreter_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ildottore.shared.judging_rules import python_build

    run_id, spec_dir = _halted(tmp_path)
    context = _context(tmp_path)
    assert context["python"] == python_build()
    dependencies = context["dependencies"]
    assert isinstance(dependencies, dict)
    assert set(dependencies) == {"pydantic", "httpx", "websockets"}
    monkeypatch.setattr(resume_mod, "python_build", lambda: "PyPy 3.10")
    with pytest.raises(resume_mod.ResumeRefused) as refused:
        execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])
    message = str(refused.value)
    assert f"was judged under {python_build()}" in message and "under PyPy 3.10" in message
    assert "There is no flag for this" in message

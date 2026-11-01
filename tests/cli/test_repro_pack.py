"""``dottore replay RUN_ID --pack DIR``: one reproduction pack per failing finding (u12 A-111).

A run against the offline mock fails two specs; the pack must copy each attempt's evidence byte
for byte, describe the finding under the spec the run used, check itself, keep the target's reply
out of the README, and refuse anything that would overwrite or rest on unverified evidence.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli import wiring
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.cli.repro_pack import PACK_FORMAT, _fenced, _spec_for
from ildottore.shared.digest import spec_digest
from ildottore.shared.enums import Severity
from ildottore.shared.models import AttackSpec

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = REPO / "examples"
runner = CliRunner()


@pytest.fixture(scope="module")
def mock_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, str]:
    """(evidence root, run store, run id) of a mock run failing OUT-SQLI-001 and PI-DIRECT-001."""

    root = tmp_path_factory.mktemp("repro")
    evidence, db = root / "evidence", root / "runs.sqlite"
    res = runner.invoke(
        app,
        [
            *("run", "-t", str(EXAMPLES / "target.mock.yaml")),
            *("--scope", str(EXAMPLES / "scope.mock.yaml")),
            *("--spec", "OUT-SQLI-001", "--spec", "PI-DIRECT-001", "--runs", "2", "-q"),
            *("--evidence-root", str(evidence), "--run-db", str(db)),
        ],
    )
    assert res.exit_code == ExitCode.FINDINGS_AT_OR_ABOVE, res.output
    (run_dir,) = evidence.iterdir()
    return evidence, db, run_dir.name


def _pack(mock_run: tuple[Path, Path, str], out: Path, *extra: str) -> tuple[int, str]:
    evidence, db, run_id = mock_run
    res = runner.invoke(
        app,
        [
            *("replay", run_id, "--evidence-root", str(evidence), "--run-db", str(db)),
            *("--pack", str(out), *extra),
        ],
    )
    return res.exit_code, res.output


def test_one_pack_per_failing_finding_that_checks_itself(
    mock_run: tuple[Path, Path, str], tmp_path: Path
) -> None:
    evidence, _, run_id = mock_run
    code, output = _pack(mock_run, tmp_path / "pack")
    assert code == 0, output
    assert sorted(p.name for p in (tmp_path / "pack").iterdir()) == [
        "OUT-SQLI-001__demo",
        "PI-DIRECT-001__demo",
    ]
    pack = tmp_path / "pack" / "OUT-SQLI-001__demo"
    for line in (pack / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ")
        assert hashlib.sha256((pack / name).read_bytes()).hexdigest() == digest
    for copy in (pack / "attempts").iterdir():
        source = evidence / run_id / "attempts" / copy.name
        assert copy.read_bytes() == source.read_bytes()
        assert hashlib.sha256(copy.read_bytes()).hexdigest() == copy.stem

    document = json.loads((pack / "finding.json").read_text())
    assert document["pack_format"] == PACK_FORMAT
    assert (document["run_id"], document["spec_id"], document["status"]) == (
        run_id,
        "OUT-SQLI-001",
        "fail",
    )
    assert (document["runs"], document["attempts"], document["failed"]) == (2, 2, 2)
    assert document["spec"] == {
        "cwe": ["CWE-89"],
        "name": "Unsafe SQL generation (SQL injection)",
        "owasp": "LLM05",
    }
    assert document["judging_rules"] == 7
    assert len(document["evidence"]) == 2


def test_the_readme_says_how_to_reproduce_and_keeps_the_reply_out(
    mock_run: tuple[Path, Path, str], tmp_path: Path
) -> None:
    code, output = _pack(mock_run, tmp_path / "pack", "--finding", "OUT-SQLI-001")
    assert code == 0, output
    pack = tmp_path / "pack" / "OUT-SQLI-001__demo"
    readme = (pack / "README.md").read_text()
    assert "--spec OUT-SQLI-001 --runs 2" in readme
    assert "(OWASP LLM05, CWE-89)" in readme
    assert "Request sent: the same as `OUT-SQLI-001::identity#0`." in readme
    for copy in (pack / "attempts").iterdir():
        reply = json.loads(copy.read_text())["response"]["text"]
        assert reply.strip() and reply.strip() not in readme
    assert not (tmp_path / "pack" / "PI-DIRECT-001__demo").exists()


def test_a_pack_never_overwrites(mock_run: tuple[Path, Path, str], tmp_path: Path) -> None:
    out = tmp_path / "pack"
    out.mkdir()
    (out / "notes.txt").write_text("mine")
    code, output = _pack(mock_run, out)
    assert code == ExitCode.ERROR
    assert "is not an empty directory: a pack never overwrites" in output
    assert [p.name for p in out.iterdir()] == ["notes.txt"]


def test_a_finding_that_did_not_fail_is_refused(
    mock_run: tuple[Path, Path, str], tmp_path: Path
) -> None:
    code, output = _pack(mock_run, tmp_path / "pack", "--finding", "SP-LEAK-001")
    assert code == ExitCode.ERROR
    assert "no failing finding of SP-LEAK-001" in output
    assert not (tmp_path / "pack").exists()


def test_finding_needs_pack_and_pack_needs_the_run_store(
    mock_run: tuple[Path, Path, str], tmp_path: Path
) -> None:
    evidence, _, run_id = mock_run
    base = ["replay", run_id, "--evidence-root", str(evidence)]
    res = runner.invoke(app, [*base, "--finding", "OUT-SQLI-001"])
    assert res.exit_code == ExitCode.ERROR
    assert "--finding selects what --pack writes" in res.output
    res = runner.invoke(
        app, [*base, "--run-db", str(tmp_path / "none.sqlite"), "--pack", str(tmp_path / "p")]
    )
    assert res.exit_code == ExitCode.ERROR
    assert "a pack needs the findings it records" in res.output
    assert not (tmp_path / "p").exists()


def test_tampered_evidence_writes_no_pack(mock_run: tuple[Path, Path, str], tmp_path: Path) -> None:
    evidence, db, run_id = mock_run
    copy = tmp_path / "evidence"
    (copy / run_id).mkdir(parents=True)
    for path in (evidence / run_id).rglob("*"):
        target = copy / run_id / path.relative_to(evidence / run_id)
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.write_bytes(path.read_bytes())
    victim = next((copy / run_id / "attempts").iterdir())
    victim.write_text(victim.read_text().replace("fail", "pass"))
    code, _ = _pack((copy, db, run_id), tmp_path / "pack")
    assert code == ExitCode.ERROR
    assert not (tmp_path / "pack").exists()


def test_a_spec_that_changed_or_is_gone_lends_no_detail() -> None:
    registry, _ = wiring.load_registry([wiring.PACKAGED_SPEC_PATH])
    spec = registry.get("OUT-SQLI-001")
    recorded = {spec.id: spec_digest(spec)}
    assert _spec_for(spec.id, {spec.id: spec}, recorded) == (spec, None)
    _, gone = _spec_for(spec.id, {}, recorded)
    assert gone is not None and "is not in the specs read now" in gone
    changed: AttackSpec = spec.model_copy(update={"severity": Severity.LOW})
    _, note = _spec_for(spec.id, {spec.id: changed}, recorded)
    assert note is not None and "has changed since the run" in note


def test_the_fence_outlasts_backticks_and_controls_are_written_out() -> None:
    lines = _fenced('{"prompt": "``` then \\u001b"}\n\u202eline', "json")
    assert lines[0] == "````json" and lines[-1] == "````"
    assert "\u202e" not in "".join(lines)

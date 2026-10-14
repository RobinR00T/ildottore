"""An evidence root that cannot take the run is refused before anything is sent (u10 A-80).

A `--evidence-root` naming a regular file was found by the first attempt's write, after its
batch had been paid for: 125 requests, then `NotADirectoryError`, nothing stored, and the 125
counted against the resume's ceiling.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.store.evidence_fs import EvidenceStoreError, check_root_path, prepare_run

from .conftest import make_spec, write_scope, write_spec_tree, write_target


@pytest.fixture
def no_sends(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def refuse(name: str):  # type: ignore[no-untyped-def]
        def _called(*args: object, **kwargs: object) -> object:
            calls.append(name)
            raise AssertionError(f"{name} was reached")

        return _called

    monkeypatch.setattr(wiring, "fingerprint_probe", refuse("fingerprint_probe"))
    monkeypatch.setattr(wiring, "build_runner", refuse("build_runner"))
    return calls


def _run(tmp_path: Path, evidence_root: Path, *extra: str) -> tuple[int, str]:
    target = write_target(tmp_path, mock_scenario="vulnerable")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    result = CliRunner().invoke(
        app,
        [
            "run",
            str(target),
            "--scope",
            str(scope),
            "--spec-path",
            str(specs),
            "--evidence-root",
            str(evidence_root),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
            "--runs",
            "1",
            "-q",
            "--no-color",
            *extra,
        ],
    )
    return result.exit_code, result.output


@pytest.mark.parametrize("extra", [[], ["-sV"], ["--dry-run"], ["--estimate"], ["-sn"]])
def test_a_regular_file_as_evidence_root_exits_3_before_anything(
    tmp_path: Path, no_sends: list[str], extra: list[str]
) -> None:
    root = tmp_path / "evfile"
    root.write_text("x")
    code, shown = _run(tmp_path, root, *extra)
    assert code == 3, shown
    assert f"error: cannot write evidence under {root}: it is not a directory" in shown
    assert no_sends == []
    assert root.read_text() == "x"
    assert not (tmp_path / "runs.sqlite").exists()  # refused before the store was created


def test_an_evidence_root_under_a_regular_file_exits_3(tmp_path: Path, no_sends: list[str]) -> None:
    (tmp_path / "plain").write_text("x")
    root = tmp_path / "plain" / "ev"
    code, shown = _run(tmp_path, root)
    assert code == 3, shown
    assert f"cannot write evidence under {root}: {tmp_path / 'plain'} is not a directory" in shown
    assert no_sends == []


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs POSIX modes, not root")
def test_an_evidence_root_the_run_cannot_write_exits_3_before_any_send(
    tmp_path: Path, no_sends: list[str]
) -> None:
    root = tmp_path / "ev"
    root.mkdir()
    root.chmod(0o500)
    try:
        code, shown = _run(tmp_path, root)
    finally:
        root.chmod(0o700)
    assert code == 3, shown
    assert f"cannot write evidence under {root}: " in shown
    assert "Permission denied" in shown
    assert no_sends == []


def test_a_run_proves_each_target_directory_before_sending(tmp_path: Path) -> None:
    """The run directories exist (and a probe directory with -sV) before the first request."""

    root = tmp_path / "ev"
    prepare_run(root, "run-0123456789ab", probes=True)
    assert (root / "run-0123456789ab" / "attempts").is_dir()
    assert (root / "run-0123456789ab" / "probes").is_dir()
    # The write check leaves nothing behind for the reader to trip on.
    run_dir = root / "run-0123456789ab"
    assert sorted(p.relative_to(run_dir) for p in run_dir.rglob("*")) == [
        Path("attempts"),
        Path("probes"),
    ]


def test_the_read_only_check_writes_nothing(tmp_path: Path) -> None:
    check_root_path(tmp_path / "a" / "b" / "ev")
    assert not (tmp_path / "a").exists()
    (tmp_path / "f").write_text("x")
    with pytest.raises(EvidenceStoreError):
        check_root_path(tmp_path / "f")
    assert isinstance(EvidenceStoreError("x"), OSError)


def test_a_good_run_still_stores_its_evidence(tmp_path: Path) -> None:
    code, shown = _run(tmp_path, tmp_path / "ev")
    assert code == 2, shown
    (run_dir,) = list((tmp_path / "ev").iterdir())
    assert len(list((run_dir / "attempts").glob("*.json"))) == 1
    assert not list(run_dir.rglob("*.tmp"))

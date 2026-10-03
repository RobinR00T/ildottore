"""A spec file that fails to load is refused, not dropped (audit 2026-10-03, F-10).

`dottore run` built its registry from whatever parsed, so a one-letter typo removed a spec
from the battery and the run still printed "Specs run: 1 of 1 planned" and `complete`.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from ildottore.cli.app import app

REPO = Path(__file__).resolve().parents[2]


def test_a_spec_that_fails_to_load_refuses_the_run(tmp_path: Path) -> None:
    (tmp_path / "scope.yaml").write_text(
        'version: "1.0"\ntargets:\n  - id: mock-target\n    base_url: "mock://mock-target"\n'
        '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "target.yaml").write_text(
        "id: mock-target\ntype: chatbot\nmock_scenario: hardened\n"
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    pack = tmp_path / "pack"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: pack\npack_version: '1.0'\nname: pack\n")
    good = (REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text()
    (pack / "attacks" / "PI-DIRECT-001.yaml").write_text(good)
    (pack / "attacks" / "broken.yaml").write_text(
        good.replace("id: PI-DIRECT-001", "id: PI-TYPO-001").replace(
            "severity: high", "severty: high"
        )
    )
    result = CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(tmp_path / "target.yaml"),
            "--scope",
            str(tmp_path / "scope.yaml"),
            "--spec-path",
            str(pack),
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
            "--no-color",
            "-q",
        ],
    )
    assert result.exit_code == 3, result.output
    assert "failed to load" in result.output
    assert not (tmp_path / "ev").exists() or not any((tmp_path / "ev").iterdir())

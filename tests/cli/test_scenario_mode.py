"""Acceptance: the mock scenario mode makes ``dottore run`` show REAL pass/fail.

Stage-6 goal (#3): a run against a *vulnerable*-scenario mock over real T0 specs must
produce decisive ``fail`` findings (real risk bands, not ``info``/``inconclusive``),
and a *hardened*-scenario mock must produce ``pass``. The *bare* default stays
``inconclusive`` (no fabricated verdict). This drives the whole wired system
(``execute_run`` → wiring → runner → real evaluators) against the shipped ``specs/``
tree, offline via the deterministic :class:`~ildottore.adapters.mock.MockTarget`.
"""

from __future__ import annotations

from pathlib import Path

from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.run import RunOptions, execute_run
from ildottore.shared.enums import ScanBand, VerdictStatus

# Real, shipped T0 specs that are ``weighted`` + not ``test_only`` + require no target
# capability the mock must fake — so the deterministic evaluators decide even though
# each spec also lists a ``semantic_judge`` (which abstains offline).
_SPECS_DIR = Path(__file__).resolve().parents[2] / "specs"
_T0_GLOBS = ["PI-DIRECT-001", "OUT-XSS-001", "OUT-SQLI-001", "OUT-CODEINJ-001"]


def _write_scope(tmp_path: Path, target_id: str = "acme-model") -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(
        'version: "1.0"\n'
        "targets:\n"
        f"  - id: {target_id}\n"
        '    base_url: "https://acme-model.example/v1/chat"\n'
        "    endpoints:\n"
        '      - host: "acme-model.example"\n'
        '        path_prefixes: ["/v1/chat"]\n'
        "    identities:\n"
        "      - name: default\n"
        '        auth_ref: "env://ACME_KEY"\n',
        encoding="utf-8",
    )
    return path


def _write_target(
    tmp_path: Path, *, mock_scenario: str | None, target_id: str = "acme-model"
) -> Path:
    scenario_line = f"mock_scenario: {mock_scenario}\n" if mock_scenario is not None else ""
    path = tmp_path / "target.yaml"
    path.write_text(
        f"id: {target_id}\ntype: model\n{scenario_line}"
        "capabilities:\n  tools: true\n  rag: true\n  memory: true\n",
        encoding="utf-8",
    )
    return path


def _run(tmp_path: Path, *, mock_scenario: str | None):
    scope = _write_scope(tmp_path)
    target = _write_target(tmp_path, mock_scenario=mock_scenario)
    opts = RunOptions(
        targets=[target],
        scope=scope,
        spec_globs=list(_T0_GLOBS),
        runs=1,
        evidence_root=tmp_path / "ev",
        run_db=tmp_path / "runs.sqlite",
    )
    return execute_run(opts, [_SPECS_DIR])


def test_vulnerable_scenario_yields_real_fail_findings(tmp_path: Path) -> None:
    outcome = _run(tmp_path, mock_scenario="vulnerable")

    assert len(outcome.findings) == len(_T0_GLOBS)
    # Every finding is a decisive FAIL — not info/inconclusive.
    assert all(f.status is VerdictStatus.FAIL for f in outcome.findings)
    assert all(f.status is not VerdictStatus.INCONCLUSIVE for f in outcome.findings)
    # Real risk bands (above INFO), and the high-severity specs gate the run.
    assert all(f.risk.band is not ScanBand.INFO for f in outcome.findings)
    assert outcome.exit_code is ExitCode.FINDINGS_AT_OR_ABOVE


def test_hardened_scenario_yields_real_pass_findings(tmp_path: Path) -> None:
    outcome = _run(tmp_path, mock_scenario="hardened")

    assert len(outcome.findings) == len(_T0_GLOBS)
    assert all(f.status is VerdictStatus.PASS for f in outcome.findings)
    # A clean target gates nothing.
    assert outcome.exit_code is ExitCode.CLEAN


def test_bare_default_scenario_stays_inconclusive(tmp_path: Path) -> None:
    outcome = _run(tmp_path, mock_scenario=None)

    assert len(outcome.findings) == len(_T0_GLOBS)
    assert all(f.status is VerdictStatus.INCONCLUSIVE for f in outcome.findings)
    assert outcome.exit_code is ExitCode.CLEAN

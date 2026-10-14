"""`--estimate -q` prints its one line, as `--dry-run -q` does (u12 A-80).

It printed nothing and exited 0: a command whose only output is its exit code cannot answer the
question it exists for, and the dry run had already been fixed for exactly that.
"""

from __future__ import annotations

import re
from pathlib import Path

from typer.testing import CliRunner

from ildottore.cli.app import app

from .conftest import make_spec, write_scope, write_spec_tree, write_target


def _invoke(tmp_path: Path, *extra: str) -> tuple[int, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = write_target(tmp_path, mock_scenario="vulnerable")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001"), make_spec("PI-DIRECT-002")])
    result = CliRunner().invoke(
        app,
        [
            "run",
            str(target),
            "--scope",
            str(scope),
            "--spec-path",
            str(specs),
            "--estimate",
            "--no-color",
            *extra,
        ],
    )
    return result.exit_code, result.output


def test_estimate_quiet_prints_one_line_with_the_figures_of_the_full_estimate(
    tmp_path: Path,
) -> None:
    code, full = _invoke(tmp_path / "full")
    assert code == 0, full
    code, quiet = _invoke(tmp_path / "quiet", "-q")
    assert code == 0, quiet
    lines = quiet.splitlines()
    assert len(lines) == 1, quiet
    assert lines[0].startswith(
        "estimate: 10 requests over 2 spec-runs across 1 target(s) at runs=5, ~"
    )
    # The same request and token figures as the full estimate prints.
    requests = re.search(r"estimate: (\d+) requests", full)
    tokens = re.search(r"\(~(\d+) total, rough gloss\)", full)
    assert requests is not None and tokens is not None
    assert f"estimate: {requests[1]} requests" in lines[0]
    assert f"~{tokens[1]} tokens" in lines[0]


def test_estimate_quiet_counts_the_probe_pass(tmp_path: Path) -> None:
    from ildottore.cli.run import fingerprint_probe_count

    code, quiet = _invoke(tmp_path, "-q", "-sV")
    assert code == 0, quiet
    assert quiet.strip().endswith(f", +{fingerprint_probe_count()} probe(s)")

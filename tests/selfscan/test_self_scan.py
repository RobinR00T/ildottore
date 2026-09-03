"""Self-scan gate as a pytest (validation-plan layer 17) - also runs in CI as `python -m`.

Dogfoods the semantic judge over the adversarial corpus and asserts (a) zero verdict flips to
PASS (0 high/critical findings in our own LLM-using code) and (b) the emitted report is a
schema-valid SARIF 2.1.0 log. Owned by ``u14-self-validation-ci``.
"""

from __future__ import annotations

import json
from pathlib import Path

from ildottore.reporting.sarif_reporter import SARIF_SCHEMA_VERSION, load_sarif_schema
from tests.selfscan.run import main


def test_self_scan_finds_no_high_critical(tmp_path: Path) -> None:
    out = tmp_path / "self-scan.sarif.json"
    exit_code = main(["--out", str(out)])
    assert exit_code == 0, "self-scan found a high/critical finding in our own judge code"
    assert out.is_file()


def test_self_scan_emits_valid_sarif(tmp_path: Path) -> None:
    import jsonschema

    out = tmp_path / "self-scan.sarif.json"
    main(["--out", str(out)])
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["version"] == SARIF_SCHEMA_VERSION == "2.1.0"
    jsonschema.validate(document, load_sarif_schema())  # raises if invalid

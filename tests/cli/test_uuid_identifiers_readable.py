"""A UUID in an operator's path or a provider's model name reads as before A-78 (audit L5).

A-78 masks a UUID whatever its entropy. Two places that keep a value out of the entropy rule
did not keep it out of the UUID pattern: the CLI's error masking ran the late patterns over the
whole message, kept paths included, so an existing evidence root under a UUID directory printed
`.../«REDACTED:uuid:...»/ev`, which main printed as written; and a model name a provider echoes
went through the redactor's no-entropy twin, which kept the UUID pattern, so a deployment's
model name holding one (`my-deploy-<uuid>`, a Bedrock custom-model ARN) lost it before the
fingerprint's metadata layer read it. Both keep it now; a UUID anywhere else is masked.
"""

from __future__ import annotations

from pathlib import Path

from ildottore.adapters.base import redact_ids
from ildottore.cli.app import _masked
from ildottore.redactor import Redactor

UUID = "8edfde5b-3c4a-4e1f-9b2d-7a6c5e4f3a2b"


def test_an_existing_path_under_a_uuid_directory_is_kept(tmp_path: Path) -> None:
    root = tmp_path / UUID / "ev"
    root.mkdir(parents=True)
    shown = _masked(ValueError(f"the evidence root {root} is not writable"))
    assert f"{root} is not writable" in shown, shown


def test_a_uuid_outside_a_kept_path_is_masked(tmp_path: Path) -> None:
    shown = _masked(ValueError(f"the reply named {UUID} and {tmp_path}/missing/{UUID}.json"))
    assert UUID not in shown, shown
    assert "«REDACTED:uuid:" in shown


def test_a_model_name_holding_a_uuid_reads_as_written() -> None:
    model = f"my-deploy-{UUID}"
    ids = redact_ids(Redactor(salt="s"), {"model": model, "id": "chatcmpl-1"})
    assert ids["model"] == model


def test_a_key_in_a_model_name_is_still_masked() -> None:
    key = "sk-ant-api03-" + "Ab1" * 30
    ids = redact_ids(Redactor(salt="s"), {"model": key})
    assert key not in ids["model"] and ids["model"].startswith("«REDACTED:anthropic_key:")

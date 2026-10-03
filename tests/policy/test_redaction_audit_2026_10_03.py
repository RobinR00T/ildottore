"""Secrets and evidence integrity: the redaction defects of the 2026-10-03 audit.

Each test is the reproduction of one finding, kept so the defect cannot come back:
SEC-01 (a key in an HTTP error reached every report), SEC-02 (a URL password), SEC-05
(credentials the tool reads were never registered; an unsalted 32-bit digest), F17 (a
labelled run that never reached a fixed point, and a repeated label that left the secret in
clear) and R1 (reports masked the evidence references that point at their own proof).
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from ildottore.redactor import Redactor, redact_identity, register_known_secret
from ildottore.reporting import get_reporter
from ildottore.reporting.summary import RunStatus
from ildottore.shared.enums import ReportFormat
from ildottore.shared.models import EvidenceRef
from tests.reporting.conftest import make_finding, make_run

# Shaped like nothing the pattern detectors know: lowercase, segmented, no vendor prefix.
_UNSHAPED_KEY = "plain-lower-segmented-key-7"


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("token=token=token= abc123XYZ", "abc123XYZ"),
        ("password: password: Xs3cr3tVal", "Xs3cr3tVal"),
    ],
)
def test_a_run_of_labels_masks_the_value_and_reaches_a_fixed_point(text: str, secret: str) -> None:
    """F17. The first input changed on every pass, which the evidence store treats as a
    leak risk and aborts the campaign over; the second masked both label words and left the
    real value in clear."""

    redactor = Redactor()
    once = redactor.redact_text(text)
    assert secret not in once
    assert redactor.redact_text(once) == once
    assert once.startswith(text.split(secret)[0].rstrip()[:5]), "the label stays readable"


def test_a_plain_lowercase_word_after_a_label_is_still_not_a_secret() -> None:
    assert Redactor().redact_text("password strength is low") == "password strength is low"


def test_a_credential_the_tool_read_is_masked_by_value_in_every_instance() -> None:
    """SEC-05 and SEC-01. Registered once, masked by every Redactor in the process, raw or
    stripped, including inside an HTTP library's error text that quotes the header."""

    register_known_secret(_UNSHAPED_KEY + "\r")
    error = f"LocalProtocolError: Illegal header value b'Bearer {_UNSHAPED_KEY}\\r'"
    for redactor in (Redactor(), Redactor(salt="other")):
        masked = redactor.redact_text(error)
        assert _UNSHAPED_KEY not in masked
        assert "«REDACTED:credential:" in masked


def test_a_short_value_is_not_registered_so_ordinary_words_survive() -> None:
    register_known_secret("test")
    assert Redactor().redact_text("a test report") == "a test report"


def test_a_password_in_a_url_is_masked_and_the_rest_of_the_url_is_kept() -> None:
    """SEC-02: `--dry-run`, `-sn` and `-v` printed it, and the JSON report stored it."""

    masked = Redactor().redact_text("https://alice:hunter2pass@api.example.test/v1")
    assert "hunter2pass" not in masked
    assert masked.startswith("https://alice:") and masked.endswith("@api.example.test/v1")


def test_the_digest_is_salted_so_a_report_cannot_confirm_a_guess() -> None:
    """SEC-05. Unsalted, 32 bits of HMAC let anyone holding a report check a guessed password
    offline. The default salt is random per process unless the operator pins one."""

    value = "Xs3cr3tVal"
    masked = Redactor().redact_text(f"password: {value}")
    unsalted = hmac.new(b"", value.encode(), hashlib.sha256).hexdigest()[:8]
    assert unsalted not in masked


def test_the_identity_mask_is_the_same_in_every_process() -> None:
    """The run store masks a stored target id and `--resume` recomputes the mask; that only
    works if the identity mask does not depend on the per-process salt."""

    tenant = "tenant-" + "a1b2c3d4" * 4
    assert redact_identity(tenant) == redact_identity(tenant)
    assert redact_identity(tenant) != redact_identity("tenant-" + "e5f6a7b8" * 4)


def test_resolving_a_credential_strips_it_and_registers_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """SEC-01 at the source: a trailing CR made httpx reject the header and quote the key."""

    from ildottore.cli.wiring import resolve_auth_ref

    monkeypatch.setenv("AUDIT_CR_KEY", "windows-edited-env-key-9\r")
    assert resolve_auth_ref("env://AUDIT_CR_KEY") == "windows-edited-env-key-9"
    assert "windows-edited-env-key-9" not in Redactor().redact_text("key windows-edited-env-key-9")


@pytest.mark.parametrize("fmt", list(ReportFormat))
def test_the_run_status_reason_is_masked_in_every_format(fmt: ReportFormat) -> None:
    """SEC-01. The reason is assembled from transport errors and used to bypass masking."""

    register_known_secret(_UNSHAPED_KEY)
    reporter = get_reporter(
        fmt,
        run_status=RunStatus(
            state="unreachable", reason=f"t1: Illegal header value b'Bearer {_UNSHAPED_KEY}'"
        ),
    )
    finding = make_finding()
    rendered = reporter.render(make_run(findings=[finding]), [finding]).decode()
    assert _UNSHAPED_KEY not in rendered


def test_a_report_keeps_the_references_to_its_own_evidence() -> None:
    """R1. 107 of 110 evidence hashes in a quick-suite report were masked as high entropy,
    so a finding could no longer be traced to the artifact it cites."""

    digest = hashlib.sha256(b"attempt").hexdigest()
    finding = make_finding().model_copy(
        update={
            "evidence": [
                EvidenceRef(
                    run_id="run-1",
                    attempt_id="a" * 40,
                    uri=f"/evidence/run-1/attempts/{digest}.json",
                    sha256=digest,
                )
            ]
        }
    )
    rendered = json.loads(
        get_reporter(ReportFormat.JSON).render(make_run(findings=[finding]), [finding])
    )
    blob = json.dumps(rendered)
    assert digest in blob
    assert "a" * 40 in blob


def test_a_stdio_mcp_server_does_not_inherit_the_scanners_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SEC-08. It inherited the whole environment, every other target's key included."""

    from ildottore.adapters.mcp import _stdio_environment

    monkeypatch.setenv("OTHER_TARGET_API_KEY", "sk-should-never-reach-the-server")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = _stdio_environment()
    assert "OTHER_TARGET_API_KEY" not in env
    assert env["PATH"] == "/usr/bin"


def test_a_symlink_below_the_run_directory_is_refused(tmp_path: object) -> None:
    """SEC-10 / A-16. Only the run directory was checked; `<run>/attempts` was followed."""

    from pathlib import Path

    from ildottore.store import paths

    root = Path(str(tmp_path)) / "ev"
    elsewhere = Path(str(tmp_path)) / "foreign"
    (root / "run-1").mkdir(parents=True)
    elsewhere.mkdir()
    (root / "run-1" / "attempts").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(paths.UnsafePathError):
        paths.attempts_dir(root, "run-1")

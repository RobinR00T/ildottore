"""What the tool computed reads as written in every report, with the hex rule in (u01 A-78).

The hex rule masks a run of 32 or more hex digits whatever its entropy, so every place where the
tool writes a digest of its own into text the redactor reads has to keep it: the evidence
references and the scope digest were restored already (R1, F12); the media digests the runner
records on a multimodal request were not, and the JSON report masked 24 of the 28 a battery
recorded at ``--runs 2`` on ``main`` (``high_entropy``) and every one with the hex rule. A
reference's attempt id is named as written, as the attempts' own ids are.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from ildottore.redactor import Redactor
from ildottore.reporting import get_reporter
from ildottore.reporting.masking import mask_findings, mask_run
from ildottore.shared.enums import ReportFormat
from ildottore.shared.models import Attempt, EvidenceRef, ModelRequest

from .conftest import make_attempt, make_finding, make_run

MEDIA = [hashlib.sha256(b"image one").hexdigest(), hashlib.sha256(b"image two").hexdigest()]
EVIDENCE = hashlib.sha256(b"attempt").hexdigest()
#: An attempt id the hex rule would mask, as the reference to it must not be.
HEX_ID = "d" * 40


def _finding(metadata: dict[str, object]) -> object:
    attempt = make_attempt().model_copy(
        update={"request": ModelRequest(prompt="describe the image", metadata=metadata)}
    )
    assert isinstance(attempt, Attempt)
    return make_finding().model_copy(
        update={
            "attempts": [attempt],
            "evidence": [
                EvidenceRef(
                    run_id="run-1",
                    attempt_id=HEX_ID,
                    uri=f"/evidence/run-1/attempts/{EVIDENCE}.json",
                    sha256=EVIDENCE,
                )
            ],
        }
    )


@pytest.mark.parametrize("fmt", list(ReportFormat))
def test_every_report_keeps_the_tools_own_digests(fmt: ReportFormat) -> None:
    finding = _finding({"media_sha256": MEDIA})
    run = make_run(findings=[finding]).model_copy(update={"scope_sha256": MEDIA[0][::-1]})
    rendered = get_reporter(fmt, redactor=Redactor(salt="s")).render(run, [finding]).decode()
    assert "REDACTED:hex_token" not in rendered
    if fmt is ReportFormat.JSON:
        report = json.loads(rendered)
        for copy in (report["findings"][0], report["run"]["findings"][0]):
            assert copy["attempts"][0]["request"]["metadata"]["media_sha256"] == MEDIA
            assert copy["evidence"][0]["attempt_id"] == HEX_ID
            assert copy["evidence"][0]["sha256"] == EVIDENCE


@pytest.mark.parametrize(
    "value",
    [
        ["sk-" + "Zq8LmPw3" * 6],  # not a digest: masked as any other value
        [MEDIA[0], "not a digest"],
        "0" * 64,  # a string, not the list the runner writes
        [MEDIA[0].upper()],  # the tool writes lower case
    ],
)
def test_a_media_digest_not_in_the_tools_shape_is_masked_as_any_value(value: object) -> None:
    finding = _finding({"media_sha256": value})
    masked = mask_findings([finding], Redactor(salt="s"))[0]  # type: ignore[list-item]
    kept = masked.attempts[0].request.metadata["media_sha256"]  # type: ignore[index]
    assert kept != value


def test_both_copies_of_a_finding_keep_the_media_digests() -> None:
    finding = _finding({"media_sha256": MEDIA, "other": "deadbeef" * 8})
    run = mask_run(make_run(findings=[finding]), Redactor(salt="s"))  # type: ignore[list-item]
    metadata = run.findings[0].attempts[0].request.metadata
    assert metadata is not None
    assert metadata["media_sha256"] == MEDIA
    # Only the digests are put back: the rest of the metadata is masked as before.
    assert str(metadata["other"]).startswith("«REDACTED:hex_token:")

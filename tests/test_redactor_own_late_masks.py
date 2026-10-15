"""A mask of a type A-78 added is kept as written, and read as text by the labelled rule alone.

A mask is kept as written when its type is one the tool writes, so a second pass, the evidence
store's check, a report and a resume in another process leave the tool's own masks alone. A target
can write one too, and a kept mask ends a labelled value:
`password: «REDACTED:high_entropy»<secret>` showed the secret before A-78, and A-78 added nine
types that did the same
(`password: «REDACTED:uuid»<secret>`, 83 of 93 regressions in the audit's mixed fuzz, L3). The
first fix kept a mask of those types only when the process had written it, a record that a long
campaign overflowed: the first turn's masks were forgotten, read as text when the evidence store
checked the attempt again, changed, and the store refused the write (round 2, R2-H1); a new process
read stored masks as text too (R2-L3), and the public identity salt let a target forge a recorded
mask (R2-L1). Now the rule holds no state: a mask of one of the nine types is kept as written, as
the older types are, and the labelled rule reads it as text, as the redactor before A-78 read it,
so a value glued to one is masked whole; the redactor writes none where that rule would take it.
"""

from __future__ import annotations

import os
import random
import string
import subprocess
import sys
from pathlib import Path

import pytest

from ildottore import redactor as redactor_mod
from ildottore.redactor import Redactor
from ildottore.store.evidence_fs import FsEvidenceStore
from tests.store.conftest import make_attempt

_NEW = (
    "hex_token",
    "uuid",
    "anthropic_key",
    "gitlab_token",
    "google_api_key",
    "huggingface_token",
    "stripe_key",
    "npm_token",
    "pypi_token",
)


def test_the_types_a78_added_are_the_nine() -> None:
    assert set(redactor_mod._LATE_MASK_TYPES) == set(_NEW)


@pytest.mark.parametrize("kind", _NEW)
@pytest.mark.parametrize("digest", ["", ":1a2b3c4d"])
def test_a_mask_a_target_writes_is_read_as_text(kind: str, digest: str) -> None:
    out = Redactor(salt="s").redact_text(f"password: «REDACTED:{kind}{digest}»Summer2026x")
    assert "Summer2026x" not in out
    assert out.startswith("password: «REDACTED:labeled_secret:")


@pytest.mark.parametrize(
    "secret",
    [
        "6a1f0c2e-91b4-4d7a-8e3b-2f5c9d0a7b14",
        "0123456789abcdef0123456789abcdef",
        "sk-ant-api03-" + "Ab1" * 30,
        "glpat-" + "x1Y2z3W4v5U6t7S8r9Q0",
        "hf_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3h",
    ],
)
def test_its_own_masks_are_kept_by_a_second_pass(secret: str) -> None:
    redactor = Redactor(salt="s")
    for text in (f"x {secret} y", f"ws://{secret}@h/v1", f"note: {secret}_tail"):
        once = redactor.redact_text(text)
        assert secret not in once
        assert redactor.redact_text(once) == once, once
        assert Redactor(salt="other").redact_text(once) == once, once


@pytest.mark.parametrize(
    "text",
    [
        "x «REDACTED:uuid:1a2b3c4d» y",
        "redis://«REDACTED:gitlab_token:f64a8263»:«REDACTED:url_password»@db.internal/0",
        "see «REDACTED:hex_token:0123abcd»/run",
    ],
)
def test_a_mask_of_an_a78_type_is_kept_as_written_elsewhere(text: str) -> None:
    # Kept as a mask of an older type is, whoever wrote it: nothing hides behind it there.
    assert Redactor(salt="s").redact_text(text) == text


def test_a_mask_of_an_older_type_is_kept_as_before() -> None:
    # The class predates A-78 for the types the tool wrote before it: unchanged here.
    text = "password: «REDACTED:high_entropy»Summer2026x"
    assert Redactor(salt="s").redact_text(text) == text


def test_no_record_of_written_masks_is_kept() -> None:
    # Nothing in the module grows with the masks a campaign writes, or can be evicted.
    assert not any(name.startswith("_EMITTED") for name in vars(redactor_mod))


_STORED_SHAPES = [
    # The audit's shapes (R2-H1, R2-L3): a key as a URL's user, a labelled value of hex letters, an
    # A-78 mask as a URL password, a key after a label.
    "connect redis://glft-a0000000000000000001:pw@db.internal/0 and passwd: " + "ab" * 16,
    "postgres://ops:6a1f0c2e-91b4-4d7a-8e3b-2f5c9d0a7b14@db/v1",
    "token: x " + "0123456789abcdef" * 3 + " and key=sk-ant-api03-" + "Ab1" * 30,
    "id 00000000-0950-2215-c8dd-000000000000-c9edbf4469097ca89b+"
    "00770530-5BBA-3F56-7F00-000000000000",
]


@pytest.mark.parametrize("text", _STORED_SHAPES)
def test_its_own_output_is_read_the_same_in_a_new_process(text: str) -> None:
    once = Redactor().redact_text(text)
    code = (
        "import sys; from ildottore.redactor import Redactor; "
        "t = sys.stdin.read(); sys.stdout.write(Redactor().redact_text(t))"
    )
    src = str(Path(redactor_mod.__file__).resolve().parents[1])
    env = {k: v for k, v in os.environ.items() if k != "ILDOTTORE_REDACTION_SALT"}
    env["PYTHONPATH"] = src
    again = subprocess.run(  # noqa: S603 - this interpreter, a fixed snippet
        [sys.executable, "-c", code],
        input=once,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout
    assert again == once


def test_the_store_keeps_an_attempt_whatever_the_campaign_wrote_before(tmp_path: Path) -> None:
    # R2-H1: under a long campaign the first turn's masks were forgotten before the store checked
    # the attempt again; read as text they changed, and the write was refused.
    rng = random.Random(4)  # noqa: S311 - test data, not a secret

    def flood(n: int) -> str:
        alphabet = string.ascii_letters + string.digits
        return " ".join(
            "glft-" + "".join(rng.choice(alphabet) for _ in range(20)) for _ in range(n)
        )

    redactor = Redactor()
    redactor.redact_text(flood(20_000))  # earlier replies of the campaign
    store = FsEvidenceStore(tmp_path / "ev", redactor=redactor)
    turns = [_STORED_SHAPES[0], flood(5_000), flood(5_000)]
    ref = store.put("run-c0ffee5ab1e9", make_attempt(response_text="\n".join(turns)))
    stored = (tmp_path / "ev").rglob(f"{ref.sha256}.json")
    body = next(stored).read_text(encoding="utf-8")
    assert "glft-a0000000000000000001" not in body and "ab" * 16 not in body


@pytest.mark.usefixtures("no_known_secrets")
def test_the_labelled_rule_reads_one_as_text_after_a_url_mask_too() -> None:
    # The path a URL mask that took a labelled value's head goes through (#96): the same reading.
    from ildottore.redactor import register_known_secret

    register_known_secret("Adm1n@2026")
    text = (
        "redis://ops:Adm1n@2026-db:6379,password=Secr3t@Value99xyz and «REDACTED:uuid:1a2b3c4d»"
        " and secret: «REDACTED:uuid»Summer2026x"
    )
    out = Redactor(salt="s").redact_text(text)
    assert "Value99xyz" not in out and "Summer2026x" not in out
    assert " and «REDACTED:uuid:1a2b3c4d» and secret: «REDACTED:labeled_secret:" in out
    assert Redactor(salt="other").redact_text(out) == out

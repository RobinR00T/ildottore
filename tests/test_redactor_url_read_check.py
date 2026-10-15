"""Which URL the URL rule read, judged with every mask one neutral character (u01 A-78, L2).

The URL rule as written (#96) leaves alone a URL the URL rule read in the pass. It told one by
matching the URL rule's pattern on the text at that `://`, where a mask laid after the URL rule
can supply the `:` the URL lacked: the rule then took the URL for one it had read and left its
password readable. A phone mask did that before A-78 (``Part1xyz`` below); the hex-run and UUID
masks of the entropy rule added triggers (pre-merge audit of A-78, L2). The check now reads the
URL with every mask of the pass one neutral character, as the URL rule saw what it read.
"""

from __future__ import annotations

import pytest

from ildottore.redactor import Redactor, register_known_secret

pytestmark = pytest.mark.usefixtures("no_known_secrets")


def _redacted(credentials: tuple[str, ...], text: str) -> str:
    for value in credentials:
        register_known_secret(value)
    redactor = Redactor(salt="s")
    out = redactor.redact_text(text)
    assert redactor.redact_text(out) == out, "the redaction is a fixed point"
    return out


@pytest.mark.parametrize(
    ("credentials", "text", "secret"),
    [
        # The audit's repro: the UUID after the host, masked whole with the `/` before it, gave
        # the URL rule's pattern its `:`.
        (
            ("ops:dc575cde-ca84-1818-6", "632930094@db.inte"),
            "ws://ops:dc575cde-ca84-1818-65de-911632930094@db.internal/"
            "64795389-6446-D97F-6140-8E2565622E1E@",
            "5de-911",
        ),
        # A hex run between two credentials, masked by the entropy rule.
        (
            ("admin:Xy9zQw", "Kq7Lm2Np"),
            "postgres://admin:Xy9zQw4383fa13Kq7Lm2Np" + "0123456789abcdef" * 2 + "0123456789a@h",
            "4383fa13",
        ),
        # Before A-78 a phone mask did it.
        (
            ("admin:Pa55word",),
            "postgres://admin:Pa55wordPart1xyz-0000000a-0000-0000-0000-00000000000b@db/v1",
            "Part1xyz",
        ),
    ],
)
def test_a_mask_laid_after_the_url_rule_does_not_make_it_read_a_url(
    credentials: tuple[str, ...], text: str, secret: str
) -> None:
    out = _redacted(credentials, text)
    assert secret not in out, out


def test_a_url_the_url_rule_read_is_left_as_it_masked_it() -> None:
    out = _redacted(
        (), "https://bob:Hunter2Secret99@db.internal/v1 and redis://ops:pw-Zq81x@h:6379"
    )
    assert out == (
        "https://bob:«REDACTED:url_password»@db.internal/v1 and redis://ops:«REDACTED:url_password»@h:6379"
    )

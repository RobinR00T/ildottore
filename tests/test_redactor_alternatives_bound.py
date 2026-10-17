"""What an alternative of a masked token shows is bounded (u01 A-86).

A-77 masks the alternatives of a token a mask covers: one written as the token shows what the
token shows, any other the token's masks, every mask of the stretches the token lies in. Where
many masks merge into one stretch (secrets glued together, read both ways since A-83), every
alternative of every token there showed every one of them, so what a stream's alternatives
showed grew as tokens times masks: 64 KiB of `ghp_` keys glued by U+0000, in 4-character tokens
with one alternative each, took 55.6 s and 2.1 GB and wrote 840 MB, and near the 4 MiB reply cap
about 6 GB (pre-merge audits of A-83, rounds 2 and 3). A token with more masks than
``_ALTERNATIVE_MASKS`` now has each alternative show one ``«REDACTED:fragment»``.
"""

from __future__ import annotations

import json
import re
import tracemalloc

import pytest

from ildottore import redactor as redactor_mod
from ildottore.redactor import Redactor, mask_split, redact_split, split_texts

#: Registered credentials are process-wide: none from an earlier test changes a mask here.
pytestmark = pytest.mark.usefixtures("no_known_secrets")

BOUND = redactor_mod._ALTERNATIVE_MASKS
FRAGMENT = "«REDACTED:fragment»"
MASK = re.compile(r"«REDACTED:[A-Za-z0-9_]+(?::[0-9a-f]{8})?»")


def _key(number: int) -> str:
    """A distinct `ghp_` key, which the redactor masks with a digest of its own."""

    return "ghp_" + format(number * 7919 % 36**8, "08x") * 4 + "abcd"


def _keys_token(count: int) -> list[dict[str, object]]:
    """A stream whose middle token holds ``count`` keys apart: that many masks, one each."""

    held = " ".join(_key(n) for n in range(1, count + 1))
    return [
        {"token": "Keys ", "logprob": -0.1, "top_logprobs": [{"token": "Keys ", "logprob": -0.1}]},
        {
            "token": held,
            "logprob": -0.2,
            "bytes": list(held.encode()),
            "top_logprobs": [
                {"token": "zz", "logprob": -1.0, "bytes": [122, 122]},
                {"token": held, "logprob": -2.0, "bytes": list(held.encode())},
            ],
        },
        {"token": " now", "logprob": -0.3, "top_logprobs": [{"token": " x", "logprob": -1.0}]},
    ]


def _glued_keys(size: int) -> str:
    """``size`` characters of distinct `ghp_` keys glued by U+0000: both readings mask them, and
    every mask merges into one stretch, which every token lies in."""

    keys: list[str] = []
    written = 0
    while written < size:
        keys.append(_key(written))
        written += len(keys[-1]) + 1
    return "\x00".join(keys)[:size]


def _hostile_stream(size: int) -> dict[str, object]:
    """The audit's shape: the glued keys as 4-character tokens, one alternative each."""

    text = _glued_keys(size)
    return {
        "content": [
            {
                "token": text[i : i + 4],
                "logprob": -0.5,
                "top_logprobs": [{"token": "zz", "logprob": -2.0}],
            }
            for i in range(0, len(text), 4)
        ]
    }


@pytest.mark.parametrize("count", [1, BOUND])
def test_an_alternative_shows_the_token_s_masks_up_to_the_bound(count: int) -> None:
    out = redact_split(Redactor(salt="s"), {"content": _keys_token(count)})
    assert isinstance(out, dict)
    item = out["content"][1]
    other, as_token = item["top_logprobs"]
    assert len(MASK.findall(other["token"])) == count
    assert MASK.sub("", other["token"]) == ""
    assert as_token["token"] == item["token"]  # written as the token, shown as the token is
    assert other["bytes"] is None and as_token["bytes"] is None and item["bytes"] is None


@pytest.mark.parametrize("count", [BOUND + 1, BOUND + 3])
def test_past_the_bound_each_alternative_shows_one_fragment(count: int) -> None:
    out = redact_split(Redactor(salt="s"), {"content": _keys_token(count)})
    assert isinstance(out, dict)
    item = out["content"][1]
    assert len(MASK.findall(item["token"])) == count  # the token itself shows every mask
    assert [alternative["token"] for alternative in item["top_logprobs"]] == [FRAGMENT] * 2
    assert all(alternative["bytes"] is None for alternative in item["top_logprobs"])
    # The stored shape (``TokenLogprob``'s ``top`` pairs) is bounded the same way.
    pairs = [
        {"token": e["token"], "logprob": e["logprob"], "top": [[a["token"], -1.0] for a in alts]}
        for e in _keys_token(count)
        for alts in [e["top_logprobs"]]
    ]
    stored = redact_split(Redactor(salt="s"), {"logprobs": pairs})
    assert isinstance(stored, dict)
    assert [pair[0] for pair in stored["logprobs"][1]["top"]] == [FRAGMENT] * 2


def test_no_alternative_of_a_hostile_stream_shows_what_its_masks_hide() -> None:
    redactor = Redactor(salt="s")
    stream = _hostile_stream(8 * 1024)
    out = redact_split(redactor, stream)
    assert isinstance(out, dict)
    alternatives = [a["token"] for e in out["content"] for a in e["top_logprobs"]]
    assert set(alternatives) == {FRAGMENT}
    shown = MASK.sub("|", "".join(e["token"] for e in out["content"]) + "".join(alternatives))
    for key in {k for k in _glued_keys(8 * 1024).split("\x00") if len(k) >= 8}:
        assert all(key[i : i + 8] not in shown for i in range(len(key) - 7)), key
    # A fixed point: of the stream's masking, of each string, and of each joined text the
    # evidence store's guard reads.
    assert redact_split(redactor, out) == out
    assert all(redactor.redact_text(text) == text for text in alternatives)
    assert all(redactor.redact_text(text) == text for text in split_texts(out))


def test_a_hostile_stream_s_output_grows_with_its_length() -> None:
    """Four times the stream, under six times the output: main's alternatives showed every mask
    of the stretch, and its output grew as tokens times masks (8, 16 and 32 KiB wrote 14, 56 and
    224 MB, four times for each doubling)."""

    redactor = Redactor(salt="s")

    def written(size: int) -> int:
        out = redact_split(redactor, _hostile_stream(size))
        return len(json.dumps(out, ensure_ascii=False).encode())

    small, large = written(8 * 1024), written(32 * 1024)
    assert large < 6 * small, (small, large)


def test_a_hostile_stream_s_peak_memory_grows_with_its_length() -> None:
    """Four times the stream, under eight times the peak memory (main: about sixteen)."""

    redactor = Redactor(salt="s")

    def peak(size: int) -> int:
        stream = _hostile_stream(size)
        tracemalloc.start()
        try:
            mask_split(redactor, stream)
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    small, large = peak(8 * 1024), peak(32 * 1024)
    assert large < 8 * small, (small, large)

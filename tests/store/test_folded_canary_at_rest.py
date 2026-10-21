"""A canary is masked at rest as the evaluators read it, re-cased or split (u10 A-94).

On ``65203f18`` the evidence store registered each planted canary as an exact pattern, so a reply
holding it re-cased, or split by U+200B, U+FE0F, U+3164 or U+034F, kept it readable on disk,
while ``secret_leakage`` and ``authz_leak`` read the same reply folded (``shared.folding``, u08
A-87, A-92) and the store's docstring said no canary touches the disk (audit of A-92, L4). The
scope's identity canaries were not registered at all: one the entropy rule does not take was
stored as the target wrote it, re-cased or not. The tests that go through ``build_runner`` fail
on ``65203f18`` by their assertions; the others use what this change adds.
"""

from __future__ import annotations

import json
import random
import time
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ildottore.cli import wiring
from ildottore.policy.scope import Endpoint, Identity, Scope, ScopeTarget
from ildottore.redactor import Redactor
from ildottore.shared.enums import TargetType
from ildottore.shared.folding import INVISIBLE_RANGES, folded
from ildottore.shared.models import Attempt, ModelRequest, ModelResponse, SeededSetup, Target
from ildottore.store.evidence_fs import FsEvidenceStore
from tests.core.test_seeded_setup import _spec

RUN = "run-3f9c1e7a5b2d"
DECLARED = "ZYNAP_CANARY_{{run_id}}"
CANARY = f"ZYNAP_CANARY_{RUN}"
#: Of the scope's floors, and no rule of the redactor takes it.
IDENTITY = "orchid-falcon-river-31"


def _scope(*canaries: str) -> Scope:
    identities = [
        Identity(name=f"tenant-{n}", auth_ref="env://NONE", canary=canary)
        for n, canary in enumerate(canaries)
    ] or [Identity(name="default", auth_ref="env://NONE")]
    return Scope(
        version="1.0",
        targets=[
            ScopeTarget(
                id="live",
                base_url="https://api.example.test/v1/chat/completions",
                endpoints=[Endpoint(host="api.example.test", path_prefixes=["/v1"])],
                identities=identities,
            )
        ],
    )


def _built(root: Path, *, specs: tuple[str, ...] = (), identities: tuple[str, ...] = ()) -> object:
    """The evidence store of the runner ``build_runner`` assembles, which a campaign writes to."""

    built = wiring.build_runner(
        scope=_scope(*identities),
        specs=[_spec(spec) for spec in specs],
        evidence_root=root,
        run_db=root / "runs.sqlite",
    )
    _OPEN.append(built)
    return built.runner._evidence


#: The runners a test built, closed after it: the store journals each artifact in their run store.
_OPEN: list[wiring.BuiltRunner] = []


@pytest.fixture(autouse=True)
def _close_runners() -> object:
    yield
    while _OPEN:
        _OPEN.pop().close()


def _store(root: Path, *canaries: str) -> FsEvidenceStore:
    stems = [value.split("{{", 1)[0].rstrip("_") for value in canaries]
    return wiring.build_evidence_store(  # type: ignore[call-arg]
        root, planted_canaries=stems, folded_canaries=list(canaries)
    )


def _stored(root: Path, store: object, text: str, *, run: str = RUN) -> str:
    attempt = Attempt(
        attempt_id="a-1",
        spec_id="DL-001",
        request=ModelRequest(prompt="repeat the marker"),
        response=ModelResponse(text=text),
    )
    ref = store.put(run, attempt)  # type: ignore[attr-defined]
    return (root / ref.uri).read_text(encoding="utf-8")


FORMS = {
    "as-planted": CANARY,
    "upper": CANARY.upper(),
    "lower": CANARY.lower(),
    "zero-width-space": "ZYNAP_CANARY_run-3f9c\u200b1e7a5b2d",
    "bom-re-cased": "\ufeffzynap_canary_RUN-3F9C1E7A5B2D",
    "variation-selector": "ZYNAP_CANARY_run-3f9c\ufe0f1e7a5b2d",
    "grapheme-joiner": "ZYNAP_CANARY\u034f_run-3f9c1e7a5b2d",
    "hangul-filler": "ZYNAP_CANARY_run-\u31643f9c1e7a5b2d",
    "two-splitters-re-cased": "zynap\u200b_CANARY_RUN\u3164-3F9C1E7A5B2D",
}


@pytest.mark.parametrize("shown", list(FORMS.values()), ids=list(FORMS))
def test_a_re_cased_or_split_canary_is_not_kept_on_disk(tmp_path: Path, shown: str) -> None:
    store = _built(tmp_path, specs=("DL-SECRET-CANARY-001",))
    disk = _stored(tmp_path, store, f"The marker is {shown}, as asked.")
    assert folded(CANARY) not in folded(disk)
    assert "«REDACTED:canary:" in disk
    # A splitter before the canary's first character or after its last stays where it is.
    text = folded(json.loads(disk)["response"]["text"])
    assert text.startswith("the marker is «redacted:canary:")


@pytest.mark.parametrize("shown", list(FORMS.values()), ids=list(FORMS))
def test_every_form_takes_the_same_mask(tmp_path: Path, shown: str) -> None:
    store = _built(tmp_path, specs=("DL-SECRET-CANARY-001",))
    as_planted = json.loads(_stored(tmp_path, store, CANARY))["response"]["text"]
    found = json.loads(_stored(tmp_path, store, shown))["response"]["text"]
    assert found.strip("\ufeff") == as_planted


def test_an_identity_canary_is_masked_at_rest(tmp_path: Path) -> None:
    store = _built(tmp_path, identities=("CANARY-A-9d41e0b7c2f5", IDENTITY))
    for shown in (IDENTITY, IDENTITY.upper(), "orchid-falcon\u200b-river-31"):
        disk = _stored(tmp_path, store, f"tenant b holds {shown} here")
        assert folded(IDENTITY) not in folded(disk), shown


def test_an_identity_canary_holding_the_run_id_masks_no_ordinary_text(tmp_path: Path) -> None:
    # Its stem as an exact pattern masked every `a` of the evidence (pre-commit audit, M2).
    store = _built(tmp_path, identities=("a{{run_id}}", "tenant-0-{{run_id}}"))
    text = "I can't share a summary of tenant-0-records."
    assert json.loads(_stored(tmp_path, store, text))["response"]["text"] == text
    leaked = json.loads(_stored(tmp_path, store, f"here: A{RUN.upper()}"))["response"]["text"]
    assert leaked == "here: " + leaked.removeprefix("here: ")
    assert leaked.startswith("here: «REDACTED:canary:")


def test_a_seeded_canary_is_masked_as_its_run_token_binds_it(tmp_path: Path) -> None:
    # Bound to `<run_token>-<spec id>`, it is filled by no run id (pre-commit audit, M1).
    target = Target(
        id="live",
        type=TargetType.RAG,
        provider="openai",
        endpoint="https://api.example.test/v1/chat/completions",
        seeded_setup=SeededSetup(specs=["*"], run_token="eng-2026-q4"),
    )
    seeded = "ZYNAP_CANARY_eng-2026-q4-DL-XSESSION-001"
    spec = _spec("DL-XSESSION-001")
    declared = wiring.declared_canaries([spec], target=target)
    assert seeded in declared
    store = wiring.build_evidence_store(
        tmp_path,
        planted_canaries=wiring.planted_secrets([spec], target=target),
        folded_canaries=declared,
    )
    for shown in (seeded.lower(), "ZYNAP_CANARY_eng-2026-q4\u200b-DL-XSESSION-001"):
        disk = _stored(tmp_path, store, f"the note says {shown}")
        assert folded(seeded) not in folded(disk), shown


def test_the_runner_s_store_masks_the_seeded_canary_on_a_mock_route(tmp_path: Path) -> None:
    # No `real_target` on a mock or `--hardened` route, and the runner still binds the seeded
    # canary to the target's `run_token` (delta audit of A-94).
    target = Target(
        id="live",
        type=TargetType.RAG,
        provider="openai",
        endpoint="https://api.example.test/v1/chat/completions",
        seeded_setup=SeededSetup(specs=["*"], run_token="eng-2026-q4"),
    )
    built = wiring.build_runner(
        scope=_scope(),
        specs=[_spec("DL-XSESSION-001")],
        evidence_root=tmp_path,
        run_db=tmp_path / "runs.sqlite",
        canary_target=target,
    )
    _OPEN.append(built)
    seeded = "zynap_canary_eng-2026-q4-dl-xsession-001"
    disk = _stored(tmp_path, built.runner._evidence, f"the note says {seeded}")
    assert seeded not in folded(disk)


def test_a_canary_the_evaluators_read_exactly_is_masked_exactly(tmp_path: Path) -> None:
    # Below the floors a spec's canary is read exactly (`evaluators.base.foldable`): folded, a
    # word canary would mask the word in every case across the evidence.
    store = _store(tmp_path, "Secret")
    text = json.loads(_stored(tmp_path, store, "a secret, a SECRET and a Secret"))["response"]
    assert text["text"].startswith("a secret, a SECRET and a «REDACTED:canary:")


def test_a_templated_canary_is_looked_for_with_the_run_id_of_the_attempt(tmp_path: Path) -> None:
    store = _store(tmp_path, DECLARED)
    other = "zynap_canary_run-0a1b2c3d4e5f"
    disk = _stored(tmp_path, store, f"{CANARY.lower()} and {other}", run="run-0a1b2c3d4e5f")
    assert folded(other) not in folded(disk)
    # The canary of another run is not this run's, so it is not looked for folded.
    assert "zynap_canary_run-3f9c1e7a5b2d" in disk


def test_the_canary_split_over_a_stream_is_masked_in_its_pieces(tmp_path: Path) -> None:
    shown = FORMS["two-splitters-re-cased"]
    pieces = [shown[:7], shown[7:16], shown[16:]]
    frames: list[dict[str, object]] = [
        {"direction": "received", "frame": {"type": "delta", "delta": {"text": piece}}}
        for piece in pieces
    ]
    attempt = Attempt(
        attempt_id="a-2",
        spec_id="DL-001",
        request=ModelRequest(prompt="repeat the marker"),
        response=ModelResponse(
            text="", raw_ids={"websocket": {"frames": frames, "protocol_paths": ["type"]}}
        ),
    )
    store = _store(tmp_path, DECLARED)
    disk = (tmp_path / store.put(RUN, attempt).uri).read_text(encoding="utf-8")
    stored = json.loads(disk)["response"]["raw_ids"]["websocket"]["frames"]
    joined = "".join(frame["frame"]["delta"]["text"] for frame in stored)
    assert folded(CANARY) not in folded(joined)


def test_without_entropy_keeps_the_finders() -> None:
    redactor = Redactor(salt="s")
    FsEvidenceStore(Path("unused"), redactor=redactor, folded_canaries=[IDENTITY])
    assert "«REDACTED:canary:" in redactor.without_entropy().redact_text(IDENTITY.upper())


# --- folded_spans --------------------------------------------------------------------------


def _reference_spans(text: str, needle: str) -> list[tuple[int, int]]:
    """Each match mapped back character by character, overlapping ones merged: the slow way."""

    drop = {code for low, high in INVISIBLE_RANGES for code in range(low, high + 1)}
    origin = [
        index
        for index, char in enumerate(text)
        for _ in ("" if ord(char) in drop else char.casefold())
    ]
    clean = folded(text)
    spans: list[tuple[int, int]] = []
    for start in range(len(clean) - len(needle) + 1):
        if not clean.startswith(needle, start):
            continue
        first, last = origin[start], origin[start + len(needle) - 1] + 1
        if spans and first < spans[-1][1]:
            spans[-1] = (spans[-1][0], max(spans[-1][1], last))
        else:
            spans.append((first, last))
    return spans


_INVISIBLE = [chr(low) for low, _ in INVISIBLE_RANGES] + ["\u200b", "\ufe0f", "\u3164"]
_ALPHABET = st.sampled_from(
    ["a", "b", "A", "B", "\u00df", "S", "s", "\u212a", "k", "-", "\u0130", "i", *_INVISIBLE]
)


@settings(max_examples=600, deadline=None)
@given(
    text=st.lists(_ALPHABET, max_size=40).map("".join),
    needle=st.sampled_from(["ab", "ss", "k-", "aba", "s", "bb-a", "i\u0307"]),
)
def test_folded_spans_covers_every_match_and_nothing_else(text: str, needle: str) -> None:
    from ildottore.shared.folding import folded_spans

    assert list(folded_spans(text, needle)) == _reference_spans(text, needle)


def test_folded_spans_is_linear_on_a_hostile_text() -> None:
    from ildottore.shared.folding import folded_spans

    def _seconds(size: int) -> float:
        started = time.process_time()
        list(folded_spans("\u00df\u200b" * size, "ss"))
        return time.process_time() - started

    small = min(_seconds(50_000) for _ in range(3))
    large = min(_seconds(200_000) for _ in range(3))
    assert large < 8 * max(small, 1e-3)  # four times the text, about four times the time
    text = ("a\u200b" * 200_000) + "\u00df"
    assert list(folded_spans(text, "aa")) == [(0, 399_999)]
    rng = random.Random(7)  # noqa: S311 - a fixed sample text, not a secret
    noisy = "".join(rng.choice("aB\u200b\u3164") for _ in range(100_000))
    assert all(end > start for start, end in folded_spans(noisy, "ab"))


def test_folded_spans_refuses_an_empty_needle() -> None:
    from ildottore.shared.folding import folded_spans

    with pytest.raises(ValueError, match="needle"):
        list(folded_spans("text", ""))

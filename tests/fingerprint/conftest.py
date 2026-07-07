"""Fixtures for the u09 fingerprint suite — offline corpus replay adapter.

No network, no keys: a :class:`CorpusAdapter` replays a labeled
:class:`~ildottore.fingerprint.signatures.CorpusCase`'s canned responses keyed by
the ``metadata["probe"]`` each layer sets, so the whole six-layer engine runs
deterministically offline. This is the scanner-side stand-in the detection gate
(contract §7) replays to score family P/R + version top-k.
"""

from __future__ import annotations

import pytest

from ildottore.fingerprint.signatures import CorpusCase, SignaturePack, load_corpus, load_pack
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse


class CorpusAdapter:
    """A ``TargetAdapter`` that replays a corpus case's canned responses.

    Selects the response by the ``probe`` key each layer stamps into request
    metadata; falls back to an empty string for an unprobed key (so a layer that
    finds nothing simply contributes no evidence). Pure: no I/O, no clock, no RNG.
    """

    def __init__(
        self,
        case: CorpusCase,
        *,
        capabilities: Capabilities | None = None,
        target_id: str | None = None,
    ) -> None:
        self._case = case
        self.id = target_id or case.case_id
        self._caps = capabilities or Capabilities()

    def capabilities(self) -> Capabilities:
        return self._caps

    async def send(self, request: ModelRequest) -> ModelResponse:
        meta = request.metadata or {}
        probe = str(meta.get("probe", ""))
        text = self._case.responses.get(probe, "")
        raw_ids: dict[str, object] = {}
        raw = self._case.metadata.get("raw")
        if raw is not None:
            raw_ids = {"raw": raw}
        return ModelResponse(
            text=text,
            finish_reason=self._case.finish_reason,
            raw_ids=raw_ids,
        )


@pytest.fixture(scope="session")
def pack() -> SignaturePack:
    """The in-repo MVP-1 signature pack."""

    return load_pack()


@pytest.fixture(scope="session")
def corpus() -> list[CorpusCase]:
    """The labeled self-test corpus."""

    return load_corpus()

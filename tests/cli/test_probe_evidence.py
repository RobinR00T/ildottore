"""Recognition traffic is evidence (contract u10/u12, added 2026-09-22).

A fingerprint pass is 17 requests per target and it left **no trace**: the evidence tree could
not answer "what did this tool send my endpoint", which is the question the product exists to
answer, and it is exactly what kept a day's worth of probes carrying attack framing invisible.

Probes are stored apart from attempts on purpose. A probe is not an attack attempt, so counting
it as one would inflate every attempt-derived number: the reproducibility denominator, the
resume skip set, `dottore replay`'s N.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ildottore.cli.run import RunOptions, execute_run
from ildottore.cli.wiring import PROBE_SPEC_ID
from ildottore.store.replay import replay_run

from .conftest import make_spec, write_scope, write_spec_tree, write_target


def _run(tmp_path: Path, **kw: object) -> tuple[str, Path]:
    target = write_target(tmp_path, mock_scenario="hardened")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    opts = RunOptions(
        targets=[target],
        scope=scope,
        runs=1,
        quiet=True,
        evidence_root=tmp_path / "ev",
        run_db=tmp_path / "runs.sqlite",
    )
    for key, value in kw.items():
        setattr(opts, key, value)
    execute_run(opts, [specs])
    run_ids = [p.name for p in (tmp_path / "ev").iterdir() if p.is_dir()]
    assert len(run_ids) == 1, run_ids
    return run_ids[0], tmp_path / "ev"


def test_a_fingerprint_pass_leaves_evidence(tmp_path: Path) -> None:
    """Every probe is stored, hash-verified, under the run it belongs to."""

    from ildottore.cli.run import fingerprint_probe_count

    run_id, root = _run(tmp_path, fingerprint_first=True)
    result = replay_run(root, run_id)

    assert len(result.probes) == fingerprint_probe_count()
    assert all(p.spec_id == PROBE_SPEC_ID for p in result.probes)
    assert {p.attempt_id for p in result.probes} == {p.attempt_id for p in result.probes}, (
        "probe ids are unique"
    )
    # And they are in their own directory, not among the attack attempts.
    assert (root / run_id / "probes").is_dir()
    assert not any(a.spec_id == PROBE_SPEC_ID for a in result.attempts)


def test_probes_never_touch_the_attempt_counts(tmp_path: Path) -> None:
    """The reproducibility ratio is over attack attempts, and must stay that way.

    Filing a probe as an attempt would put 17 extra "runs" into the denominator of every
    spec's reproducibility, which is a scored, published number.
    """

    run_id, root = _run(tmp_path, fingerprint_first=True)
    with_probes = replay_run(root, run_id)

    plain_path = tmp_path / "plain"
    plain_path.mkdir()
    plain_id, plain_root = _run(plain_path)
    without = replay_run(plain_root, plain_id)

    assert with_probes.probes and not without.probes
    assert with_probes.n == without.n, "the same battery, the same N"
    assert with_probes.reproducibility() == without.reproducibility()


def test_a_run_with_no_fingerprint_stores_no_probes(tmp_path: Path) -> None:
    run_id, root = _run(tmp_path)
    assert replay_run(root, run_id).probes == ()
    assert not (root / run_id / "probes").exists()


def test_replay_reports_the_probes_apart_from_the_attempts(tmp_path: Path) -> None:
    from ildottore.cli.replay import render_replay

    run_id, root = _run(tmp_path, fingerprint_first=True)
    rendered = render_replay(replay_run(root, run_id))

    assert "recognition traffic from -sV" in rendered
    assert "probe::" in rendered
    assert "attempts: 1" in rendered, "the attempt count excludes the probes"


def test_a_probe_is_redacted_at_rest_like_an_attempt(tmp_path: Path) -> None:
    """The probe path shares the store's redaction and its fail-closed leak guard.

    A probe carries a request and a response from somebody's endpoint, so it can carry a
    secret exactly like an attempt can. Sharing the write path is what makes that automatic.
    """

    from ildottore.shared.models import Attempt, ModelRequest, ModelResponse
    from ildottore.store.evidence_fs import FsEvidenceStore

    store = FsEvidenceStore(tmp_path / "ev")
    ref = store.put_probe(
        "run-abc123def456",
        Attempt(
            attempt_id="probe::guardrail#0",
            spec_id=PROBE_SPEC_ID,
            request=ModelRequest(prompt="hello"),
            response=ModelResponse(text="my key is sk-abcdefghijklmnopqrstuvwxyz1234567890"),
        ),
    )
    on_disk = (tmp_path / "ev" / "run-abc123def456" / "probes").glob("*.json")
    body = next(on_disk).read_text(encoding="utf-8")
    assert "sk-abcdefghijklmnopqrstuvwxyz1234567890" not in body
    assert "REDACTED" in body
    assert ref.sha256 is not None


def test_a_failed_probe_is_recorded_with_its_error(tmp_path: Path) -> None:
    """ "We sent this and got nothing back" is evidence; dropping it leaves a partial tree."""

    import asyncio

    from ildottore.cli.wiring import _RecordingAdapter
    from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse
    from ildottore.store.evidence_fs import FsEvidenceStore

    class _Dead:
        id = "dead"

        async def send(self, request: ModelRequest) -> ModelResponse:
            raise ConnectionError("refused")

        def capabilities(self) -> Capabilities:
            return Capabilities()

    store = FsEvidenceStore(tmp_path / "ev")
    adapter = _RecordingAdapter(_Dead(), store, "run-abc123def456")  # type: ignore[arg-type]
    with pytest.raises(ConnectionError):
        asyncio.run(adapter.send(ModelRequest(prompt="probe", metadata={"probe": "cutoff"})))

    stored = replay_run(tmp_path / "ev", "run-abc123def456").probes
    assert len(stored) == 1
    assert stored[0].response is None
    assert "ConnectionError" in (stored[0].error or "")

"""The runner sends a chain link by link and an image link as a PNG part (u05 A-99)."""

from __future__ import annotations

from ildottore.core.runner import CampaignRunner
from ildottore.shared.enums import Category, VerdictStatus
from ildottore.shared.media import media_digests
from ildottore.shared.models import Capabilities

from .conftest import (
    VULNERABLE_RESPONSE,
    make_policy_engine,
    make_scenario,
    make_spec,
    make_target,
    mock_adapter_factory,
    no_sleep,
)


def _runner(scenario, *, evaluators, mutators, scorer, stores):
    evidence, runs = stores
    return CampaignRunner(
        policy=make_policy_engine(allow_categories=[Category.JAILBREAK]),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=mock_adapter_factory(scenario),
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        sleep=no_sleep,
        now=lambda: 0.0,
    )


async def test_a_chain_applies_its_links_in_order(evaluators, mutators, scorer, stores) -> None:
    chain = "structured:json+encode:hex"
    spec = make_spec(mutations=[chain])
    runner = _runner(
        make_scenario(VULNERABLE_RESPONSE),
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[spec])
    # The identity baseline goes first; the chain's attempts follow.
    attempt = next(a for a in result.findings[0].attempts if a.mutation == chain)
    json_file = mutators.get("structured").mutate(
        spec.attack.user_prompt or "", f"{spec.id}::structured:json"
    )
    expected = mutators.get("encode").mutate(json_file, f"{spec.id}::encode:hex")
    assert attempt.request.prompt == expected


async def test_an_image_link_attaches_the_png_and_records_its_digest(
    evaluators, mutators, scorer, stores
) -> None:
    caps = Capabilities(multimodal=True)
    spec = make_spec(mutations=["encode:uu+image:decode"])
    runner = _runner(
        make_scenario(VULNERABLE_RESPONSE, capabilities=caps),
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
    )
    result = await runner.run(run_id="r1", target=make_target(capabilities=caps), specs=[spec])
    finding = result.findings[0]
    assert finding.attempts, finding.reasoning
    request = next(a for a in finding.attempts if a.mutation != "identity").request
    assert request.media is not None and len(request.media) == 1
    part = request.media[0]
    assert part["charset"] == "ascii"
    assert str(part["render_text"]).startswith("The following instruction is written in uuencode")
    assert "uuencode" not in request.prompt and "image" in request.prompt
    assert request.metadata is not None
    assert request.metadata["media_sha256"] == media_digests(request.media)


async def test_an_image_link_on_a_text_target_is_refused_before_sending(
    evaluators, mutators, scorer, stores
) -> None:
    spec = make_spec(mutations=["rot13", "image:plain"])
    runner = _runner(
        make_scenario(VULNERABLE_RESPONSE),
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[spec])
    finding = result.findings[0]
    assert finding.status is VerdictStatus.INCONCLUSIVE
    assert "image_carrier_unsupported" in finding.reasoning
    assert finding.attempts == []


async def test_an_image_link_before_the_end_is_refused(
    evaluators, mutators, scorer, stores
) -> None:
    spec = make_spec(mutations=["image:plain+rot13"])
    runner = _runner(
        make_scenario(VULNERABLE_RESPONSE, capabilities=Capabilities(multimodal=True)),
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
    )
    result = await runner.run(
        run_id="r1",
        target=make_target(capabilities=Capabilities(multimodal=True)),
        specs=[spec],
    )
    assert "malformed_mutation" in result.findings[0].reasoning
    assert result.findings[0].attempts == []

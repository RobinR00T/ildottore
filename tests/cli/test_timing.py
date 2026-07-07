"""`-T` timing-template golden table (contract §7).

``-T0..-T5`` expand to the documented ``{rate, concurrency, timeout}``; explicit
``--rate/--concurrency/--timeout`` override the template per field.
"""

from __future__ import annotations

import pytest

from ildottore.cli.flags import (
    DEFAULT_TEMPLATE,
    SUITE_ALIASES,
    TIMING_TEMPLATES,
    resolve_suite_id,
    resolve_timing,
    timing_for_template,
)


def test_all_six_templates_defined() -> None:
    assert set(TIMING_TEMPLATES) == {0, 1, 2, 3, 4, 5}


def test_templates_are_monotone_in_aggression() -> None:
    # Higher T ⇒ higher rate + concurrency, lower timeout (more aggressive).
    rates = [TIMING_TEMPLATES[t].rate_rps for t in range(6)]
    conc = [TIMING_TEMPLATES[t].concurrency for t in range(6)]
    timeouts = [TIMING_TEMPLATES[t].timeout_s for t in range(6)]
    assert rates == sorted(rates)
    assert conc == sorted(conc)
    assert timeouts == sorted(timeouts, reverse=True)


def test_default_template_is_t3() -> None:
    assert DEFAULT_TEMPLATE == 3


@pytest.mark.parametrize("template", [0, 1, 2, 3, 4, 5])
def test_resolve_timing_matches_template_without_overrides(template: int) -> None:
    assert resolve_timing(template) == timing_for_template(template)


def test_explicit_rate_overrides_template() -> None:
    t = resolve_timing(3, rate=99.0)
    assert t.rate_rps == 99.0
    assert t.concurrency == TIMING_TEMPLATES[3].concurrency
    assert t.timeout_s == TIMING_TEMPLATES[3].timeout_s


def test_explicit_concurrency_and_timeout_override() -> None:
    t = resolve_timing(1, concurrency=7, timeout_s=3.0)
    assert t.concurrency == 7
    assert t.timeout_s == 3.0
    assert t.rate_rps == TIMING_TEMPLATES[1].rate_rps


def test_out_of_range_template_raises() -> None:
    with pytest.raises(ValueError, match="invalid -T template"):
        timing_for_template(9)


def test_suite_alias_resolution() -> None:
    assert resolve_suite_id("owasp:llm") == "owasp-llm-top10"
    assert resolve_suite_id("mitre:atlas") == "mitre-atlas"


def test_suite_alias_identity_passthrough() -> None:
    # An already-canonical id passes through untouched.
    assert resolve_suite_id("owasp-llm-top10") == "owasp-llm-top10"


def test_suite_alias_strips_whitespace() -> None:
    assert resolve_suite_id("  owasp:llm  ") == "owasp-llm-top10"


def test_all_documented_aliases_present() -> None:
    for alias in ("owasp:llm", "mitre:atlas", "nist:ai", "eu:ai-act", "dora", "iso:42001"):
        assert alias in SUITE_ALIASES

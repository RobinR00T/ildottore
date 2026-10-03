"""The pinned OWASP AISVS 1.0 table (``shared.aisvs``): its size, its shape, its buckets.

The table is a transcription, so what can be tested is that it is the transcription it says it
is: the counts the module docstring states, IDs in the standard's own citation form, and a
classification in which no requirement has two reasons and none is lost.
"""

from __future__ import annotations

import pytest

from ildottore.shared.aisvs import (
    AISVS_CODE_RE,
    AISVS_LEVELS,
    AISVS_NOT_TESTED_BY_DESIGN,
    AISVS_OUT_OF_REACH,
    AISVS_REQUIREMENTS,
    _classify,
    aisvs_universe,
    unknown_aisvs_codes,
)


def test_the_table_is_the_transcription_the_docstring_claims() -> None:
    """191 rows, 51 / 95 / 45 by level, twelve chapters (upstream ``05c62d1``).

    Counted twice when it was transcribed: once from the parsed tables, once by counting the
    raw table rows in the twelve chapter files. A changed number here means the table changed,
    and the docstring, the manual and the coverage figures change with it.
    """

    assert len(AISVS_REQUIREMENTS) == 191
    assert [len(aisvs_universe(level)) for level in AISVS_LEVELS] == [51, 95, 45]
    chapters = {code.split("-C")[1].split(".")[0] for code in AISVS_REQUIREMENTS}
    assert chapters == {str(n) for n in range(1, 13)}


def test_every_id_is_in_the_citation_form_the_standard_defines() -> None:
    assert all(AISVS_CODE_RE.match(code) for code in AISVS_REQUIREMENTS)
    # Two-digit components exist upstream (C9.2.10, C10.x, C11.x, C12.x); a pattern written
    # for one digit would quietly drop them from the table and from every count.
    assert "v1.0-C9.2.10" in AISVS_REQUIREMENTS
    assert "v1.0-C12.5.4" in AISVS_REQUIREMENTS
    assert not AISVS_CODE_RE.match("v1.0-C2.1.6\n"), "a trailing newline is not an ID"


def test_the_levels_partition_the_universe() -> None:
    """Each requirement is assigned one level, so the three axes never count it twice."""

    seen = [code for level in AISVS_LEVELS for code in aisvs_universe(level)]
    assert len(seen) == len(set(seen)) == len(AISVS_REQUIREMENTS)


def test_unknown_ids_are_reported_once_and_in_order() -> None:
    assert unknown_aisvs_codes(["v1.0-C2.1.9", "v1.0-C2.1.6", "v1.0-C2.1.9", "C2.1.6"]) == [
        "v1.0-C2.1.9",
        "C2.1.6",
    ]
    assert unknown_aisvs_codes(None) == []


def test_no_requirement_is_both_out_of_reach_and_a_decision() -> None:
    """One reason per requirement: a code with two reasons has no reason."""

    assert not set(AISVS_OUT_OF_REACH) & set(AISVS_NOT_TESTED_BY_DESIGN)
    assert set(AISVS_OUT_OF_REACH) | set(AISVS_NOT_TESTED_BY_DESIGN) <= set(AISVS_REQUIREMENTS)
    assert all(
        r.strip() for r in (*AISVS_OUT_OF_REACH.values(), *AISVS_NOT_TESTED_BY_DESIGN.values())
    )


def test_the_classifier_refuses_a_dead_pattern_and_a_double_claim() -> None:
    """The groups are written as chapter / section / requirement patterns. A pattern that
    matches nothing (a typo, or a section 1.01 removed) and a requirement claimed by two groups
    both raise at import, rather than shrinking or doubling a bucket in silence."""

    with pytest.raises(ValueError, match="matches no requirement"):
        _classify((("reason", ("C2.9",)),))
    with pytest.raises(ValueError, match="matches no requirement"):
        _classify((("reason", ("C2.1.9",)),))
    with pytest.raises(ValueError, match="classified twice"):
        _classify((("one", ("C2.1",)), ("two", ("C2.1.6",))))


def test_the_aisvs_reasons_reach_the_shared_lookup() -> None:
    """Merged into ``shared.frameworks`` so the coverage axes find them with one lookup."""

    from ildottore.shared.frameworks import not_tested_by_design_reason, out_of_reach_reason

    assert out_of_reach_reason("v1.0-C4.1.1") == AISVS_OUT_OF_REACH["v1.0-C4.1.1"]
    assert not_tested_by_design_reason("v1.0-C10.2.1") == AISVS_NOT_TESTED_BY_DESIGN["v1.0-C10.2.1"]
    assert out_of_reach_reason("v1.0-C2.1.6") is None

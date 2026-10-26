"""A scope's validity window (u01 A-97).

``valid_from`` and ``valid_until`` bound the engagement an authorization record covers:
calendar dates, both days included, read in UTC. Outside them ``authorize_target`` refuses
every target, so the CLI's pre-flight and the engine's per-attempt gate refuse alike.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

import ildottore.policy.packs as packs
from ildottore.policy.errors import ScopeChecksumError, ScopeError
from ildottore.policy.packs import PolicyEngine, PolicyPack, authorize_target
from ildottore.policy.scope import load_scope, scope_hash
from ildottore.shared.enums import Category

from .conftest import SCOPE_SINGLE, make_spec

ENDPOINT = "https://api.acme.test/v1/chat"
DAY = dt.date(2026, 10, 26)


def _scope_file(tmp_path: Path, window: str) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(SCOPE_SINGLE + window, encoding="utf-8")
    return path


def test_a_scope_without_a_window_is_valid_on_every_day(tmp_path: Path) -> None:
    scope = load_scope(_scope_file(tmp_path, ""))
    assert scope.valid_from is None and scope.valid_until is None
    for day in (dt.date(1970, 1, 1), DAY, dt.date(2999, 12, 31)):
        assert scope.window_refusal(day) is None
        assert authorize_target(scope, "acme-bot", ENDPOINT, today=day).allowed


@pytest.mark.parametrize(
    "window",
    [
        "valid_from: 2026-10-01\nvalid_until: 2026-10-31\n",  # YAML reads a date
        'valid_from: "2026-10-01"\nvalid_until: "2026-10-31"\n',  # quoted, the same days
    ],
)
def test_both_bounds_are_days_included(tmp_path: Path, window: str) -> None:
    scope = load_scope(_scope_file(tmp_path, window))
    assert (scope.valid_from, scope.valid_until) == (dt.date(2026, 10, 1), dt.date(2026, 10, 31))
    inside = [dt.date(2026, 10, 1), DAY, dt.date(2026, 10, 31)]
    assert [authorize_target(scope, "acme-bot", ENDPOINT, today=d).allowed for d in inside] == [
        True,
        True,
        True,
    ]
    early = authorize_target(scope, "acme-bot", ENDPOINT, today=dt.date(2026, 9, 30))
    late = authorize_target(scope, "acme-bot", ENDPOINT, today=dt.date(2026, 11, 1))
    assert not early.allowed and early.reason == (
        "the scope is valid from 2026-10-01 and today (UTC) is 2026-09-30"
    )
    assert not late.allowed and late.reason == (
        "the scope expired on 2026-10-31 and today (UTC) is 2026-11-01"
    )


def test_one_bound_alone_leaves_the_other_side_open(tmp_path: Path) -> None:
    since = load_scope(_scope_file(tmp_path, "valid_from: 2026-10-01\n"))
    assert since.window_refusal(dt.date(2999, 1, 1)) is None
    assert since.window_refusal(dt.date(2026, 9, 30)) is not None
    until = load_scope(_scope_file(tmp_path, "valid_until: 2026-10-31\n"))
    assert until.window_refusal(dt.date(1970, 1, 1)) is None
    assert until.window_refusal(dt.date(2026, 11, 1)) is not None


def test_the_window_comes_before_membership(tmp_path: Path) -> None:
    # outside its window the record authorizes nothing, so the reason is the window, for a
    # target it names and for one it does not
    scope = load_scope(_scope_file(tmp_path, "valid_until: 2026-10-01\n"))
    for target_id in ("acme-bot", "not-in-scope"):
        result = authorize_target(scope, target_id, ENDPOINT, today=DAY)
        assert not result.allowed and result.reason is not None
        assert result.reason.startswith("the scope expired on 2026-10-01")


def test_an_empty_window_is_refused_at_load(tmp_path: Path) -> None:
    with pytest.raises(ScopeError, match="valid_from must be on or before valid_until"):
        load_scope(_scope_file(tmp_path, "valid_from: 2026-11-01\nvalid_until: 2026-10-31\n"))
    # one day is a window
    one = load_scope(_scope_file(tmp_path, "valid_from: 2026-10-26\nvalid_until: 2026-10-26\n"))
    assert one.window_refusal(DAY) is None


@pytest.mark.parametrize(
    ("value", "why"),
    [
        ("20261026", "written YYYY-MM-DD"),  # a number: pydantic read it as a Unix timestamp
        ("2026-10-26 10:00:00", "not a date and time"),  # YAML reads a datetime
        ('"2026-10-26T00:00:00"', "written YYYY-MM-DD"),  # pydantic dropped a midnight time
        ('"26/10/2026"', "written YYYY-MM-DD"),
        ('"2026-13-01"', "valid_until"),  # the shape, but no such day
        ("true", "written YYYY-MM-DD"),
    ],
)
def test_a_bound_is_a_calendar_date_and_nothing_else(tmp_path: Path, value: str, why: str) -> None:
    with pytest.raises(ScopeError) as caught:
        load_scope(_scope_file(tmp_path, f"valid_until: {value}\n"))
    assert why in str(caught.value) and "valid_until" in str(caught.value)


def test_the_checksum_covers_the_window(tmp_path: Path) -> None:
    path = _scope_file(tmp_path, "valid_until: 2026-10-31\n")
    path.write_text(path.read_text(encoding="utf-8") + f"checksum: {scope_hash(path)}\n")
    assert load_scope(path, require_checksum=True).valid_until == dt.date(2026, 10, 31)
    # extending the engagement by hand is an edit the checksum catches
    path.write_text(path.read_text(encoding="utf-8").replace("2026-10-31", "2026-12-31"))
    with pytest.raises(ScopeChecksumError):
        load_scope(path)


def test_the_engine_refuses_every_attempt_once_the_scope_expires(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a run that outlives its window: the per-attempt gate reads the UTC day of each attempt
    scope = load_scope(_scope_file(tmp_path, "valid_until: 2026-10-26\n"))
    engine = PolicyEngine(
        scope, PolicyPack(name="base", allow_categories=[Category.PROMPT_INJECTION])
    )
    spec = make_spec()
    monkeypatch.setattr(packs, "utc_today", lambda: DAY)
    assert engine.check("acme-bot", ENDPOINT, spec).allowed
    monkeypatch.setattr(packs, "utc_today", lambda: DAY + dt.timedelta(days=1))
    after = engine.check("acme-bot", ENDPOINT, spec)
    assert (
        not after.allowed and after.reason is not None and "expired on 2026-10-26" in after.reason
    )

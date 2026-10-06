"""Follow-ups of the pre-merge audit of PR #45 (2026-10-06).

Two identities of one scope target with one name, or one canary, are refused: the identity sweep
keys each response by name and a canary maps back to its one owner, so a repeated one lost a
response or turned a tenant's own canary into another's leak. `registry ls` and `describe` say
when spec files failed to load, instead of answering as if they did not exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app
from ildottore.policy.scope import ScopeError, load_scope_with_digest

_TARGET = (
    'version: "1.0"\ntargets:\n  - id: t\n    base_url: "https://a.example.com/v1"\n'
    '    endpoints:\n      - host: "a.example.com"\n        path_prefixes: ["/v1"]\n'
    "    identities:\n"
)
_CANARY = "ZZ-CANARY-7f3a91"


def _scope(tmp_path: Path, identities: str) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(_TARGET + identities)
    return path


def test_two_identities_with_one_name_are_refused(tmp_path: Path) -> None:
    scope = _scope(
        tmp_path,
        "      - {name: tenant, auth_ref: 'env://A'}\n"
        "      - {name: tenant, auth_ref: 'env://B'}\n",
    )
    with pytest.raises(ScopeError, match="declares identity 'tenant' more than once"):
        load_scope_with_digest(scope)


def test_two_identities_with_one_canary_are_refused_without_quoting_it(tmp_path: Path) -> None:
    scope = _scope(
        tmp_path,
        f"      - {{name: a, auth_ref: 'env://A', canary: {_CANARY}}}\n"
        f"      - {{name: b, auth_ref: 'env://B', canary: {_CANARY}}}\n",
    )
    with pytest.raises(ScopeError, match="declares the canary of another identity") as caught:
        load_scope_with_digest(scope)
    assert _CANARY not in str(caught.value)


def test_distinct_identities_still_load(tmp_path: Path) -> None:
    scope = _scope(
        tmp_path,
        f"      - {{name: a, auth_ref: 'env://A', canary: {_CANARY}-a}}\n"
        f"      - {{name: b, auth_ref: 'env://B', canary: {_CANARY}-b}}\n"
        "      - {name: c, auth_ref: 'env://C'}\n      - {name: d, auth_ref: 'env://D'}\n",
    )
    loaded, _ = load_scope_with_digest(scope)
    assert [i.name for i in loaded.targets[0].identities] == ["a", "b", "c", "d"]


@pytest.fixture
def broken_spec_dir(tmp_path: Path) -> Path:
    source = Path(__file__).resolve().parent.parent / "specs" / "attacks" / "AC-BOLA-001.yaml"
    folder = tmp_path / "specs"
    folder.mkdir()
    (folder / "AC-BOLA-001.yaml").write_text(source.read_text() + "severity: high\n")
    return folder


def test_registry_ls_says_a_spec_file_failed_to_load(broken_spec_dir: Path) -> None:
    result = CliRunner().invoke(app, ["registry", "ls", "--spec-path", str(broken_spec_dir)])
    assert result.exit_code == 0
    assert "(no specs match)" in result.stdout
    assert "warning: the spec paths gave 1 load error(s)" in result.stderr


def test_describe_says_a_spec_file_failed_to_load(broken_spec_dir: Path) -> None:
    result = CliRunner().invoke(
        app, ["describe", "AC-BOLA-001", "--spec-path", str(broken_spec_dir)]
    )
    assert result.exit_code == 3
    assert "not found" in result.stderr and "gave 1 load error(s)" in result.stderr


def test_registry_ls_on_the_repository_warns_about_nothing() -> None:
    specs = Path(__file__).resolve().parent.parent / "specs"
    result = CliRunner().invoke(app, ["registry", "ls", "--spec-path", str(specs)])
    assert result.exit_code == 0 and "warning" not in result.stderr


def test_two_empty_canaries_are_not_one_owner_twice(tmp_path: Path) -> None:
    scope = _scope(
        tmp_path,
        "      - {name: a, auth_ref: 'env://A', canary: ''}\n"
        "      - {name: b, auth_ref: 'env://B', canary: ''}\n",
    )
    loaded, _ = load_scope_with_digest(scope)
    assert len(loaded.targets[0].identities) == 2


@pytest.mark.parametrize(
    ("a_says", "b_says", "verdict"),
    [
        ("my canary is ZZ-1", "my canary is ZZ-1-b", "pass"),  # each its own: no leak
        ("I saw ZZ-1-b", "my canary is ZZ-1-b", "fail"),  # B's canary in A's reply
        ("my canary is ZZ-1", "I saw ZZ-1 and ZZ-1-b", "fail"),  # A's canary on its own in B's
        # Overlapping, not contained: B's `1-bZ` shares `1` with A's `ZZ-1` in A's reply.
        ("ZZ-1-bZ", "mine is 1-bZ", "fail"),
    ],
)
def test_a_canary_inside_another_is_told_apart(a_says: str, b_says: str, verdict: str) -> None:
    """A substring search read A's `ZZ-1` inside B's own `ZZ-1-b` as a confirmed leak."""

    import asyncio

    from ildottore.evaluators.authz_leak import AuthzLeakEvaluator
    from ildottore.shared.enums import EvaluatorType
    from ildottore.shared.models import EvaluatorConfig, ModelResponse
    from tests.evaluators.conftest import make_ctx

    ctx = make_ctx(
        response_text="",
        config=EvaluatorConfig(type=EvaluatorType.AUTHZ_LEAK),
        identities={"a": ModelResponse(text=a_says), "b": ModelResponse(text=b_says)},
        canary_owners={"ZZ-1": "a", "ZZ-1-b": "b", "1-bZ": "b"},
    )
    result = asyncio.run(AuthzLeakEvaluator().evaluate(ctx))
    assert result.status.value == verdict


def test_a_spec_path_that_does_not_exist_is_named_not_counted_as_a_broken_file(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "nowhere"
    result = CliRunner().invoke(app, ["registry", "ls", "--spec-path", str(missing)])
    assert result.exit_code == 0
    assert f"warning: spec path(s) not found: {missing}" in result.stderr
    assert "load error(s)" not in result.stderr


def test_a_reply_flooded_with_its_own_canary_costs_no_memory() -> None:
    """Listing every occurrence held 308 MB for 4 MiB of `ZZ-1-b` (pre-merge audit)."""

    import time
    import tracemalloc

    from ildottore.evaluators.authz_leak import _canaries_found

    flood = "ZZ-1-b " * (4 * 1024 * 1024 // 7)
    tracemalloc.start()
    started = time.perf_counter()
    try:
        found = _canaries_found({"a": "ok", "b": flood}, ["ZZ-1", "ZZ-1-b"])
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert found == {"a": set(), "b": {"ZZ-1-b"}}
    assert peak < 1_000_000 and time.perf_counter() - started < 3.0

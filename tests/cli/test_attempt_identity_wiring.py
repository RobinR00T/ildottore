"""The wiring names the scope identities the attempts are sent as (u08 A-87, item 1).

The target file's ``auth_ref`` must be one of the scope's identities' (``_authorized_api_key``),
so the attempts are that identity's view, and the runner reads each attempt's reply against the
owner map as received by it. Neither naming a credential (no ``auth_ref``, or ``env://NONE``) is
the same send. Two identities never share a credential: the scope refuses one ``auth_ref`` on two,
and the probes refuse two references holding one key (u01 A-91).
"""

from __future__ import annotations

import pytest

from ildottore.cli import wiring
from ildottore.policy.scope import Endpoint, Identity, Scope, ScopeTarget
from ildottore.shared.enums import TargetType
from ildottore.shared.models import Capabilities, Target


def _scope(*identities: Identity) -> Scope:
    return Scope(
        version="1.0",
        targets=[
            ScopeTarget(
                id="multi",
                base_url="https://api.acme.test/v1/chat/completions",
                endpoints=[Endpoint(host="api.acme.test", path_prefixes=["/v1"])],
                identities=list(identities),
            )
        ],
    )


def _target(auth_ref: str | None) -> Target:
    return Target(
        id="multi",
        type=TargetType.MODEL,
        capabilities=Capabilities(multi_identity=True),
        provider="openai",
        endpoint="https://api.acme.test/v1/chat/completions",
        auth_ref=auth_ref,
    )


_A = Identity(name="tenant-a", auth_ref="env://A_KEY")
_B = Identity(name="tenant-b", auth_ref="env://B_KEY", canary="CANARY-B-3f9c1e7a5b2d8064")
_NONE = Identity(name="anonymous", auth_ref="env://NONE")


@pytest.mark.parametrize(
    ("identities", "auth_ref", "attempts_as"),
    [
        ((_A, _B), "env://A_KEY", ["tenant-a"]),
        ((_A, _B), "env://B_KEY", ["tenant-b"]),
        ((_A, _B), None, []),
        ((_A, _NONE), None, ["anonymous"]),
        ((_A, _NONE), "env://NONE", ["anonymous"]),
    ],
    ids=["as-a", "as-b", "no-credential", "none-and-env-none", "env-none"],
)
def test_each_probe_says_whether_the_attempts_are_sent_as_it(
    identities: tuple[Identity, ...], auth_ref: str | None, attempts_as: list[str]
) -> None:
    probes = wiring.build_identity_probes(_scope(*identities), _target(auth_ref))
    assert [p.identity_id for p in probes if p.sends_attempts] == attempts_as


def test_two_references_holding_one_key_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """u01 A-91: one key under two names is one caller; ``01d6bdc5`` sent the attempts as both."""

    monkeypatch.setenv("A_KEY", "key-tenant-a-000001")
    monkeypatch.setenv("A_REPORTS_KEY", "key-tenant-a-000001")
    reports = Identity(name="tenant-a-reports", auth_ref="env://A_REPORTS_KEY")
    with pytest.raises(ValueError, match="'tenant-a' and 'tenant-a-reports' resolve to the same"):
        wiring.build_identity_probes(_scope(_A, reports), _target("env://A_KEY"))
